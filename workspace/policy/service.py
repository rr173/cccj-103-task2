"""版本化合规策略控制面：HTTP 服务（标准库 ThreadingHTTPServer）。

接口（操作员令牌见 POLICY_ADMIN_TOKEN；读取接口供协调端内部令牌访问）：
  POST /revisions                 起草 DRAFT {rules, canary_subjects?, note?}
  POST /revisions/{v}/canary      DRAFT -> CANARY（expected_version 可选，校验 head）
  POST /revisions/{v}/activate    CANARY -> ACTIVE（expected_version 可选）
  POST /revisions/{v}/withdraw    CANARY -> WITHDRAWN（撤回规则，旧主体续跑）
  POST /revisions/{v}/rollback    历史/任意不可变版本 -> ACTIVE（保留历史证据）
  GET  /revisions/{v}             不可变版本全文（含 content_hash）
  GET  /current                   当前指针 head/active/canaries
  GET  /stream?since=0            版本事件流（协调端做乐观并发版本号的依据）
  GET  /health

乐观并发：`expected_version` 必须等于服务端 head（最新版本号），否则 409 且
原子地不写任何状态（连流事件都不追加）。
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from common import iso, now_ms, policy_content_hash

PORT = int(os.environ.get("POLICY_PORT", "8090"))
DB_PATH = os.environ.get("POLICY_DB", "/data/policy.db")
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "dev-internal-token")
ADMIN_TOKEN = os.environ.get("POLICY_ADMIN_TOKEN",
                            os.environ.get("ADMIN_TOKEN", "dev-admin-token"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS revisions(
  version INTEGER PRIMARY KEY AUTOINCREMENT,
  rules TEXT NOT NULL,                  -- 规范化后的不可变规则集 JSON
  canary_subjects TEXT NOT NULL,        -- JSON list[str]
  note TEXT,
  content_hash TEXT NOT NULL,
  state TEXT NOT NULL,                  -- DRAFT/CANARY/ACTIVE/WITHDRAWN/SUPERSEDED
  based_on INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS stream(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  version INTEGER NOT NULL,
  type TEXT NOT NULL,
  detail TEXT
);
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
"""

VALID_TRANSITIONS = {
    "canary": {"DRAFT": "CANARY"},
    "activate": {"CANARY": "ACTIVE", "DRAFT": "ACTIVE"},
    "withdraw": {"CANARY": "WITHDRAWN", "ACTIVE": "WITHDRAWN"},
}


class PolicyConflict(Exception):
    """乐观并发冲突：调用方持有的版本号落后于 head。"""


class PolicyError(Exception):
    def __init__(self, status: int, code: str, message: str,
                 extra: dict | None = None):
        self.status = status
        self.code = code
        self.message = message
        self.extra = extra or {}
        super().__init__(message)


def normalize_rule(rule: dict) -> dict:
    m = rule.get("match") or {}
    hold = rule.get("hold", "LEGAL_HOLD")
    if rule.get("hold_code"):
        hold = rule["hold_code"]
    if not rule.get("id"):
        raise PolicyError(400, "invalid_rule", "rule.id required")
    if hold not in ("LEGAL_HOLD", "FISCAL_RETENTION"):
        raise PolicyError(400, "invalid_rule",
                          f"hold must be LEGAL_HOLD/FISCAL_RETENTION, got {hold}")
    return {
        "id": rule["id"],
        "hold": hold,
        "reason": rule.get("reason", f"{hold} rule {rule['id']}"),
        "hold_seconds": int(rule.get("hold_seconds", 86400)),
        "match": {
            "service": m.get("service"),
            "record_id": m.get("record_id"),
            "record_prefix": m.get("record_prefix"),
        },
    }


class PolicyStore:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self.lock = threading.RLock()
        if self.head_version() == 0:
            # 虚拟基线 rev0：无规则，ACTIVE。所有工作流默认绑定的不可变修订。
            self.conn.execute(
                "INSERT INTO kv(k,v) VALUES('active','0')")
            self.conn.execute(
                "INSERT INTO stream(ts,version,type,detail) VALUES(?,?,?,?)",
                (now_ms(), 0, "BASELINE", json.dumps({"note": "empty baseline"})))
            self.conn.commit()

    # -- 基础 --------------------------------------------------------------
    def head_version(self) -> int:
        r = self.conn.execute("SELECT COALESCE(MAX(version),0) AS v FROM revisions"
                              ).fetchone()
        return r["v"]

    def active_version(self) -> int:
        r = self.conn.execute("SELECT v FROM kv WHERE k='active'").fetchone()
        return int(r["v"]) if r else 0

    def get(self, version: int) -> dict | None:
        if version == 0:
            return {"version": 0, "rules": [], "canary_subjects": [],
                    "note": "empty baseline", "content_hash": policy_content_hash([], []),
                    "state": "ACTIVE", "based_on": None,
                    "created_at": 0, "updated_at": 0}
        r = self.conn.execute("SELECT * FROM revisions WHERE version=?",
                              (version,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["rules"] = json.loads(d["rules"])
        d["canary_subjects"] = json.loads(d["canary_subjects"])
        return d

    def list_canaries(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM revisions WHERE state='CANARY' ORDER BY version"
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["rules"] = json.loads(d["rules"])
            d["canary_subjects"] = json.loads(d["canary_subjects"])
            out.append(d)
        return out

    def list_watch(self) -> list[dict]:
        """协调端需要持续观察的版本：所有 CANARY 与最近的 SUPERSEDED/WITHDRAWN，
        以便把已缓存版本的状态推进同步过去（否则再也见不到离开 CANARY 集合的版本）。"""
        rows = self.conn.execute(
            "SELECT * FROM revisions WHERE state='CANARY'"
            " OR version IN (SELECT version FROM revisions"
            " WHERE state IN ('SUPERSEDED','WITHDRAWN') ORDER BY version DESC LIMIT 20)"
            " ORDER BY version").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["rules"] = json.loads(d["rules"])
            d["canary_subjects"] = json.loads(d["canary_subjects"])
            out.append(d)
        return out

    def stream_since(self, since: int) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, ts, version, type, detail FROM stream WHERE id>? ORDER BY id",
            (since,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["detail"] = json.loads(d["detail"])
            except Exception:
                pass
            out.append(d)
        return out

    def _append(self, version: int, etype: str, detail: dict):
        self.conn.execute(
            "INSERT INTO stream(ts,version,type,detail) VALUES(?,?,?,?)",
            (now_ms(), version, etype,
             json.dumps(detail, ensure_ascii=False, sort_keys=True)))

    # -- 状态变更（均在锁内、单事务，失败整体回滚） -------------------------
    def create(self, rules: list[dict], canary_subjects: list[str],
               note: str | None) -> dict:
        with self.lock:
            based_on = self.active_version()
            ts = now_ms()
            cur = self.conn.execute(
                "INSERT INTO revisions(rules, canary_subjects, note, content_hash,"
                " state, based_on, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)",
                (json.dumps(rules, ensure_ascii=False, sort_keys=True),
                 json.dumps(sorted(set(canary_subjects))), note,
                 policy_content_hash(rules, canary_subjects),
                 "DRAFT", based_on, ts, ts))
            v = cur.lastrowid
            self._append(v, "REVISION_DRAFTED",
                         {"based_on": based_on, "rule_count": len(rules),
                          "canary_subjects": sorted(set(canary_subjects))})
            self.conn.commit()
            return self.get(v)

    def _check_expected(self, expected: int | None):
        if expected is None:
            return
        # head 包含所有已落库版本（含 DRAFT），保证起草期间的并发也可诊断
        if int(expected) != self.head_version():
            raise PolicyConflict()

    def transition(self, version: int, action: str,
                   expected: int | None) -> dict:
        with self.lock:
            self._check_expected(expected)
            rev = self.get(version)
            if not rev:
                raise PolicyError(404, "unknown_revision",
                                  f"revision {version} not found")
            if action == "rollback":
                # 回退到任意不可变历史版本：当前 ACTIVE 与被回退的 CANARY
                # 都变为 SUPERSEDED，目标变 ACTIVE。历史版本内容永不删除。
                if rev["state"] in ("DRAFT",):
                    raise PolicyError(409, "invalid_state",
                                      "only immutable published revisions can be"
                                      " rollback targets")
                target_state = "ACTIVE"
            else:
                allowed = VALID_TRANSITIONS[action]
                if rev["state"] not in allowed:
                    raise PolicyError(
                        409, "invalid_state",
                        f"cannot {action} revision in state {rev['state']}")
                target_state = allowed[rev["state"]]
            prev_active = self.active_version()
            ts = now_ms()
            if action == "rollback" and version == prev_active \
                    and rev["state"] == "ACTIVE" \
                    and not self.conn.execute(
                        "SELECT 1 FROM revisions WHERE state='CANARY' LIMIT 1"
                    ).fetchone():
                # 幂等回退到当前 ACTIVE 且没有待退役的金丝雀：no-op
                self._append(version, "ROLLBACK_NOOP", {"active": version})
                self.conn.commit()
                return self.get(version)
            if target_state == "ACTIVE":
                if prev_active and prev_active != version:
                    self.conn.execute(
                        "UPDATE revisions SET state='SUPERSEDED', updated_at=?"
                        " WHERE version=?", (ts, prev_active))
                # 回退到历史/基线版本（目标可能是虚拟基线 0）：把所有现存
                # CANARY 一律置为 SUPERSEDED——回退意味着撤销全部在途金丝雀。
                if action == "rollback":
                    self.conn.execute(
                        "UPDATE revisions SET state='SUPERSEDED', updated_at=?"
                        " WHERE state='CANARY'", (ts,))
                self.conn.execute(
                    "UPDATE revisions SET state='ACTIVE', updated_at=? WHERE version=?",
                    (ts, version))
                self.conn.execute(
                    "INSERT INTO kv(k,v) VALUES('active',?)"
                    " ON CONFLICT(k) DO UPDATE SET v=excluded.v", (str(version),))
            else:
                self.conn.execute(
                    "UPDATE revisions SET state=?, updated_at=? WHERE version=?",
                    (target_state, ts, version))
            etype = {
                "canary": "REVISION_CANARIED",
                "activate": "REVISION_ACTIVATED",
                "withdraw": "REVISION_WITHDRAWN",
                "rollback": "REVISION_ROLLED_BACK",
            }[action]
            self._append(version, etype,
                         {"from_active": prev_active if target_state == "ACTIVE"
                          else None, "actor": "operator"})
            self.conn.commit()
            return self.get(version)


store: PolicyStore | None = None


class Handler(BaseHTTPRequestHandler):
    server_version = "PolicyControl/1.0"

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

    def _admin(self) -> bool:
        return self.headers.get("Authorization", "") == f"Bearer {ADMIN_TOKEN}"

    def _internal(self) -> bool:
        h = self.headers.get("Authorization", "")
        return h in (f"Bearer {ADMIN_TOKEN}", f"Bearer {INTERNAL_TOKEN}")

    def do_GET(self):
        u = urlparse(self.path)
        p = u.path.rstrip("/") or "/"
        try:
            if p == "/health":
                return self._json(200, {"ok": True, "role": "policy",
                                        "head": store.head_version(),
                                        "active": store.active_version(),
                                        "ts": iso()})
            parts = [x for x in p.split("/") if x]
            if p == "/current":
                if not self._internal():
                    return self._json(401, {"error": "unauthorized"})
                return self._json(200, self._current())
            if p == "/stream":
                if not self._internal():
                    return self._json(401, {"error": "unauthorized"})
                q = parse_qs(u.query)
                since = int(q.get("since", ["0"])[0])
                evs = store.stream_since(since)
                return self._json(200, {"head": store.head_version(),
                                        "events": evs})
            if len(parts) == 2 and parts[0] == "revisions":
                if not self._internal():
                    return self._json(401, {"error": "unauthorized"})
                rev = store.get(int(parts[1]))
                if not rev:
                    return self._json(404, {"error": "unknown revision"})
                return self._json(200, rev)
            return self._json(404, {"error": "not found", "path": p})
        except PolicyError as e:
            return self._json(e.status, {"error": e.code, "message": e.message})
        except Exception as e:
            return self._json(500, {"error": repr(e)})

    def _current(self) -> dict:
        return {
            "head": store.head_version(),
            "active": store.active_version(),
            "active_revision": store.get(store.active_version()),
            "canaries": store.list_canaries(),
            "watch": store.list_watch(),
        }

    def do_POST(self):
        p = urlparse(self.path).path.rstrip("/") or "/"
        try:
            parts = [x for x in p.split("/") if x]
            if p == "/revisions":
                if not self._admin():
                    return self._json(401, {"error": "unauthorized"})
                body = self._body()
                raw_rules = body.get("rules") or []
                if not isinstance(raw_rules, list):
                    return self._json(400, {"error": "rules must be a list"})
                rules = [normalize_rule(r) for r in raw_rules]
                rev = store.create(rules, body.get("canary_subjects") or [],
                                   body.get("note"))
                return self._json(201, rev)
            if len(parts) == 3 and parts[0] == "revisions" \
                    and parts[2] in ("canary", "activate", "withdraw", "rollback"):
                if not self._admin():
                    return self._json(401, {"error": "unauthorized"})
                body = self._body()
                exp = body.get("expected_version")
                try:
                    rev = store.transition(int(parts[1]), parts[2],
                                           int(exp) if exp is not None else None)
                except PolicyConflict:
                    cur = self._current()
                    return self._json(409, {
                        "error": "version_conflict",
                        "message": f"expected_version {exp} is stale;"
                                   f" server head is {cur['head']},"
                                   f" active is {cur['active']}",
                        "expected_version": int(exp) if exp is not None else None,
                        "server_head": cur["head"],
                        "server_active": cur["active"],
                        "diagnostic": "optimistic concurrency guard: no state changed",
                    })
                code = 200 if parts[2] != "rollback" else 200
                return self._json(code, rev)
            return self._json(404, {"error": "not found", "path": p})
        except PolicyError as e:
            return self._json(e.status, {"error": e.code, "message": e.message,
                                         **e.extra})
        except ValueError:
            return self._json(400, {"error": "revision/version must be int"})
        except Exception as e:
            return self._json(500, {"error": repr(e)})


def main():
    global store
    store = PolicyStore(DB_PATH)
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[policy] compliance policy control plane on :{PORT} db={DB_PATH}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
