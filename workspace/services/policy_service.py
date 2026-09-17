"""合规策略控制平面（policy component）。

独立于协调端的版本化策略服务，运营侧用它完成 legal-hold / fiscal-retention 规则的
草拟（draft）、金丝雀（canary）、激活（activate）与回滚（rollback）。

核心不变量：
- 修订号单调递增；修订内容（规则集合 + content_hash）一经创建即不可变，
  状态迁移只改变生命周期标记与金丝雀队列，绝不改写规则本体。
- 状态机：DRAFT -> CANARIED -> ACTIVE -> SUPERSEDED；
  rollback 后目标修订进入 ROLLED_BACK（不可再激活，只能重新起草），
  被取代的上一修订恢复为 ACTIVE。
- 激活/回滚支持 expected_version 乐观并发：期望与当前 ACTIVE 修订不一致时
  返回 409 诊断信息，且不产生任何状态变更。
- resolve(subject) 为每个工作流主体给出当前应绑定的不可变修订快照：
  金丝雀队列中的主体命中 CANARIED 修订，其余主体命中 ACTIVE 修订。

仅使用标准库（http.server / sqlite3），与其他容器共享同一镜像。
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from common import iso, now_ms, policy_content_hash

SERVICE_NAME = "policy"
PORT = int(os.environ.get("POLICY_PORT", "9104"))
DB_PATH = os.environ.get("POLICY_DB", "/data/policy.db")
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "dev-internal-token")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "dev-admin-token")
# 系统首次启动即激活一份空规则基线修订（rev 1）：
# 所有存量/新建工作流都绑定到一个具体的、不可变的修订号。

SCHEMA = """
CREATE TABLE IF NOT EXISTS revisions(
  revision INTEGER PRIMARY KEY,
  rules TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  state TEXT NOT NULL,                  -- DRAFT/CANARIED/ACTIVE/SUPERSEDED/ROLLED_BACK
  canary_subjects TEXT NOT NULL DEFAULT '[]',
  note TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  type TEXT NOT NULL,
  revision INTEGER,
  detail TEXT
);
"""

_lock = threading.RLock()
_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
_conn.row_factory = sqlite3.Row
_conn.executescript(SCHEMA)
_conn.commit()


def db():
    return _conn


def _event(etype: str, revision: int | None, detail: dict):
    db().execute(
        "INSERT INTO events(ts, type, revision, detail) VALUES(?,?,?,?)",
        (now_ms(), etype, revision,
         json.dumps(detail, ensure_ascii=False, sort_keys=True)))


def _get_rev(revision: int) -> dict | None:
    r = db().execute("SELECT * FROM revisions WHERE revision=?",
                     (revision,)).fetchone()
    return _hydrate(dict(r)) if r else None


def _hydrate(r: dict) -> dict:
    r["rules"] = json.loads(r["rules"])
    r["canary_subjects"] = json.loads(r["canary_subjects"])
    return r


def _list_revs() -> list[dict]:
    rows = db().execute("SELECT * FROM revisions ORDER BY revision").fetchall()
    return [_hydrate(dict(r)) for r in rows]


def ensure_baseline():
    """首启动植入 rev 1 空规则 ACTIVE 基线（幂等）。"""
    with _lock:
        n = db().execute("SELECT COUNT(*) c FROM revisions").fetchone()["c"]
        if n:
            return
        ts = now_ms()
        rules = []
        db().execute(
            "INSERT INTO revisions(revision, rules, content_hash, state,"
            " canary_subjects, note, created_at, updated_at)"
            " VALUES(1,?,?, 'ACTIVE', '[]', ?, ?, ?)",
            (json.dumps(rules, ensure_ascii=False),
             policy_content_hash(rules),
             "baseline empty policy", ts, ts))
        _event("POLICY_BOOTSTRAP", 1, {"state": "ACTIVE", "rules": 0})
        db().commit()


class Conflict(Exception):
    """期望版本冲突：携带可诊断信息，调用方映射为 409。"""

    def __init__(self, error: str, **extra):
        self.error = error
        self.extra = extra
        super().__init__(error)


# -- 生命周期操作（全部串行化在 _lock 内，保证状态机判定+写入原子） --------
def create_revision(rules: list[dict], note: str | None) -> dict:
    from common import normalize_rules
    norm = normalize_rules(rules)
    ts = now_ms()
    with _lock:
        nxt = (db().execute("SELECT COALESCE(MAX(revision),0)+1 m FROM revisions")
               .fetchone()["m"])
        chash = policy_content_hash(norm)
        db().execute(
            "INSERT INTO revisions(revision, rules, content_hash, state,"
            " canary_subjects, note, created_at, updated_at)"
            " VALUES(?,?,?, 'DRAFT', '[]', ?, ?, ?)",
            (nxt, json.dumps(norm, ensure_ascii=False), chash, note, ts, ts))
        _event("POLICY_DRAFTED", nxt, {"rules": len(norm),
                                       "content_hash": chash, "note": note})
        db().commit()
        return _get_rev(nxt)


def canary_revision(revision: int, subjects: list[str], note: str | None) -> dict:
    subjects = sorted(set(subjects))
    if not subjects:
        raise Conflict("canary requires at least one canary_subjects entry")
    with _lock:
        rev = _get_rev(revision)
        if not rev:
            raise Conflict("revision not found", revision=revision)
        if rev["state"] not in ("DRAFT", "CANARIED"):
            raise Conflict(
                f"revision {revision} cannot canary in state {rev['state']}",
                revision=revision, state=rev["state"])
        merged = sorted(set(rev["canary_subjects"]) | set(subjects))
        db().execute(
            "UPDATE revisions SET state='CANARIED', canary_subjects=?,"
            " updated_at=? WHERE revision=?",
            (json.dumps(merged, ensure_ascii=False), now_ms(), revision))
        _event("POLICY_CANARIED", revision,
               {"canary_subjects": subjects, "cohort_total": len(merged),
                "note": note})
        db().commit()
        return _get_rev(revision)


def _active_revision_row() -> dict | None:
    r = db().execute("SELECT * FROM revisions WHERE state='ACTIVE'").fetchone()
    return dict(r) if r else None


def activate_revision(revision: int, expected_version: int | None) -> dict:
    with _lock:
        cur = _active_revision_row()
        cur_n = cur["revision"] if cur else None
        if expected_version is not None and expected_version != cur_n:
            raise Conflict(
                f"expected active revision {expected_version} but current is {cur_n}",
                expected=expected_version, current=cur_n, requested=revision)
        rev = _get_rev(revision)
        if not rev:
            raise Conflict("revision not found", revision=revision)
        if rev["state"] == "ACTIVE":
            return rev  # 幂等：重复激活同一修订无副作用
        if rev["state"] not in ("DRAFT", "CANARIED"):
            raise Conflict(
                f"revision {revision} cannot activate in state {rev['state']}",
                revision=revision, state=rev["state"])
        ts = now_ms()
        if cur:
            db().execute(
                "UPDATE revisions SET state='SUPERSEDED', updated_at=? WHERE revision=?",
                (ts, cur["revision"]))
        db().execute(
            "UPDATE revisions SET state='ACTIVE', updated_at=? WHERE revision=?",
            (ts, revision))
        _event("POLICY_ACTIVATED", revision,
               {"previous": cur_n, "expected": expected_version})
        db().commit()
        return _get_rev(revision)


def rollback(target: int | None, expected_version: int | None) -> dict:
    """回滚一个 ACTIVE（恢复上一修订）或 CANARIED（仅撤回金丝雀）修订。"""
    with _lock:
        cur = _active_revision_row()
        cur_n = cur["revision"] if cur else None
        if target is None:
            target = cur_n
        rev = _get_rev(target)
        if not rev:
            raise Conflict("revision not found", revision=target)
        # 幂等：同一回滚重放返回首次结果，不产生额外事件/状态变更
        if rev["state"] == "ROLLED_BACK":
            ev = db().execute(
                "SELECT detail FROM events WHERE type='POLICY_ROLLED_BACK'"
                " AND revision=? ORDER BY id DESC LIMIT 1",
                (target,)).fetchone()
            detail = json.loads(ev["detail"]) if ev else {}
            return {"idempotent": True, "rolled_back": target,
                    "restored": detail.get("restored"),
                    "canary_subjects": rev["canary_subjects"]}
        if expected_version is not None and expected_version != cur_n:
            raise Conflict(
                f"expected active revision {expected_version} but current is {cur_n}",
                expected=expected_version, current=cur_n, target=target)
        if rev["state"] not in ("ACTIVE", "CANARIED"):
            raise Conflict(
                f"revision {target} cannot rollback in state {rev['state']}",
                revision=target, state=rev["state"])
        ts = now_ms()
        restored = None
        if rev["state"] == "ACTIVE":
            prev = db().execute(
                "SELECT * FROM revisions WHERE state='SUPERSEDED'"
                " ORDER BY revision DESC LIMIT 1").fetchone()
            if not prev:
                raise Conflict("no previous revision to restore",
                               revision=target)
            restored = prev["revision"]
            db().execute(
                "UPDATE revisions SET state='ACTIVE', updated_at=? WHERE revision=?",
                (ts, restored))
        db().execute(
            "UPDATE revisions SET state='ROLLED_BACK', updated_at=? WHERE revision=?",
            (ts, target))
        _event("POLICY_ROLLED_BACK", target,
               {"restored": restored, "expected": expected_version,
                "canary_subjects": rev["canary_subjects"]})
        db().commit()
        return {"rolled_back": target, "restored": restored,
                "canary_subjects": rev["canary_subjects"]}


def resolve_subject(subject_id: str) -> dict:
    """返回主体应绑定的不可变修订快照（金丝雀优先于全量）。"""
    with _lock:
        rows = db().execute(
            "SELECT * FROM revisions WHERE state IN ('CANARIED','ACTIVE')"
            " ORDER BY revision DESC").fetchall()
        active = None
        for r in rows:
            d = _hydrate(dict(r))
            if d["state"] == "CANARIED" and subject_id in d["canary_subjects"]:
                d["canary"] = True
                return d
            if d["state"] == "ACTIVE" and active is None:
                active = d
        if active:
            active["canary"] = False
            return active
        raise Conflict("no active policy revision")


def list_events() -> list[dict]:
    rows = db().execute(
        "SELECT id, ts, type, revision, detail FROM events ORDER BY id").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["detail"] = json.loads(d["detail"])
        except Exception:
            pass
        out.append(d)
    return out


class Handler(BaseHTTPRequestHandler):
    server_version = f"{SERVICE_NAME}/1.0"

    def log_message(self, fmt, *args):
        print(f"[policy] {fmt % args}")

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n).decode()) if n else {}

    def _auth(self, expected):
        return self.headers.get("Authorization", "") == f"Bearer {expected}"

    def do_GET(self):
        parsed = urlparse(self.path)
        p = parsed.path.rstrip("/") or "/"
        try:
            if p == "/health":
                return self._json(200, {"ok": True, "role": "policy",
                                        "ts": iso()})
            if not self._auth(INTERNAL_TOKEN):
                return self._json(401, {"error": "unauthorized"})
            if p == "/policies/revisions":
                return self._json(200, {"revisions": _list_revs()})
            if p == "/policies/active":
                with _lock:
                    cur = _active_revision_row()
                if not cur:
                    return self._json(409, {"error": "no active revision"})
                return self._json(200, _hydrate(dict(cur)))
            if p == "/policies/events":
                return self._json(200, {"events": list_events()})
            if p == "/policies/resolve":
                q = parse_qs(parsed.query)
                sid = (q.get("subject_id") or [""])[0]
                if not sid:
                    return self._json(400, {"error": "subject_id required"})
                try:
                    return self._json(200, resolve_subject(sid))
                except Conflict as c:
                    return self._json(409, {"error": c.error, **c.extra})
            parts = [x for x in p.split("/") if x]
            if len(parts) == 3 and parts[:2] == ["policies", "revisions"]:
                rev = _get_rev(int(parts[2]))
                return self._json(200 if rev else 404,
                                  rev or {"error": "not found"})
            return self._json(404, {"error": "not found", "path": p})
        except ValueError:
            return self._json(400, {"error": "bad revision id"})
        except Exception as e:
            return self._json(500, {"error": repr(e)})

    def do_POST(self):
        p = urlparse(self.path).path.rstrip("/") or "/"
        try:
            if not self._auth(ADMIN_TOKEN):
                return self._json(401, {"error": "unauthorized"})
            body = self._body()
            if p == "/policies/revisions":
                try:
                    rev = create_revision(body.get("rules", []),
                                          body.get("note"))
                except ValueError as e:
                    return self._json(400, {"error": str(e)})
                return self._json(201, rev)
            parts = [x for x in p.split("/") if x]
            if (len(parts) == 4 and parts[:2] == ["policies", "revisions"]
                    and parts[3] == "canary"):
                try:
                    rev = canary_revision(
                        int(parts[2]),
                        body.get("canary_subjects", []), body.get("note"))
                except Conflict as c:
                    return self._json(409, {"error": c.error, **c.extra})
                return self._json(200, rev)
            if (len(parts) == 4 and parts[:2] == ["policies", "revisions"]
                    and parts[3] == "activate"):
                try:
                    rev = activate_revision(
                        int(parts[2]), body.get("expected_version"))
                except Conflict as c:
                    return self._json(409, {"error": c.error, **c.extra})
                return self._json(200, rev)
            if p == "/policies/rollback":
                try:
                    out = rollback(body.get("target"),
                                   body.get("expected_version"))
                except Conflict as c:
                    return self._json(409, {"error": c.error, **c.extra})
                return self._json(200, out)
            return self._json(404, {"error": "not found", "path": p})
        except ValueError:
            return self._json(400, {"error": "bad revision id"})
        except Exception as e:
            return self._json(500, {"error": repr(e)})


def main():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    ensure_baseline()
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[policy] compliance policy control plane listening on :{PORT}"
          f" db={DB_PATH}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
