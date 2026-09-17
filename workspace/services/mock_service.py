"""业务服务通用实现（orders / billing / profile 共用同一镜像，环境变量区分）。

职责：
- 维护本地业务记录（状态 ACTIVE / RESTRICTED / SEALED / PURGED）。
- 执行协调端两阶段命令：RESTRICT / UNRESTRICT / PURGE，命令按 command_id 幂等。
- 法律/财务保留：RESTRICT 命中保留策略时不擦除，回报 SEALED + hold 元数据；
  保留解除后由协调端续跑 PURGE（同一执行计划）。
- 墓碑账本：协调端下发 + PURGE 原子写入；任何写入路径先查墓碑。
- 副本检疫：迟到副本（binlog/缓存重放、对等同步）命中墓碑 -> 拒绝并隔离，
  数据不会重新回到可用状态。
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from common import (
    canonical,
    hmac_hex,
    iso,
    now_ms,
    seal_rule_for,
    sha256_hex,
    verify_tombstone_token,
    GLOBAL_TOMBSTONE_SECRET,
)

SERVICE_NAME = os.environ.get("SERVICE_NAME", "orders")
PORT = int(os.environ.get("SERVICE_PORT", "9101"))
DB_PATH = os.environ.get("SERVICE_DB", f"/data/{SERVICE_NAME}.db")
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "dev-internal-token")
# 该服务对哪些记录施加法律/财务保留（逗号分隔 record_id 列表）
HOLD_RECORDS = set(filter(None, os.environ.get("HOLD_RECORDS", "").split(",")))
HOLD_CODE = os.environ.get("HOLD_CODE", "LEGAL_HOLD")
HOLD_REASON = os.environ.get("HOLD_REASON", "legal retention")
HOLD_SECONDS = int(os.environ.get("HOLD_SECONDS", "6"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS records(
  record_id TEXT PRIMARY KEY,
  subject_id TEXT NOT NULL,
  kind TEXT,
  payload TEXT,
  status TEXT NOT NULL DEFAULT 'ACTIVE',
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS commands(
  command_id TEXT PRIMARY KEY,
  request_id TEXT, record_id TEXT, op TEXT,
  status TEXT, result TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS holds(
  record_id TEXT PRIMARY KEY,
  code TEXT, reason TEXT, active INTEGER NOT NULL,
  origin TEXT NOT NULL DEFAULT 'LOCAL',  -- LOCAL/POLICY/EXTERNAL
  policy_revision INTEGER,
  created_at INTEGER NOT NULL, releases_at INTEGER
);
CREATE TABLE IF NOT EXISTS tombstones(
  subject_id TEXT PRIMARY KEY,
  request_id TEXT, token TEXT, version INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS quarantine(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  record_id TEXT, subject_id TEXT, source TEXT,
  reason TEXT, payload TEXT, ts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
"""

_lock = threading.RLock()
_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
_conn.row_factory = sqlite3.Row
_conn.executescript(SCHEMA)
_conn.commit()


def db():
    return _conn


def fault_mode() -> str | None:
    r = db().execute("SELECT v FROM kv WHERE k='fault_mode'").fetchone()
    return r["v"] if r else None


def set_fault(on: bool, mode: str):
    with _lock:
        if on:
            db().execute(
                "INSERT INTO kv(k,v) VALUES('fault_mode',?)"
                " ON CONFLICT(k) DO UPDATE SET v=excluded.v", (mode,))
        else:
            db().execute("DELETE FROM kv WHERE k='fault_mode'")
        db().commit()


def result_hash(record_id: str, status: str, extra: dict | None = None) -> str:
    body = {"service": SERVICE_NAME, "record_id": record_id, "status": status}
    if extra:
        body.update(extra)
    return sha256_hex(canonical(body))


def tombstone_exists(subject_id: str) -> dict | None:
    r = db().execute("SELECT * FROM tombstones WHERE subject_id=?",
                     (subject_id,)).fetchone()
    return dict(r) if r else None


def write_tombstone(subject_id: str, request_id: str, token: str, version: int):
    with _lock:
        db().execute(
            "INSERT OR IGNORE INTO tombstones(subject_id, request_id, token, version,"
            " created_at) VALUES(?,?,?,?,?)",
            (subject_id, request_id, token, version, now_ms()))
        db().commit()


def get_hold(record_id: str) -> dict | None:
    r = db().execute("SELECT * FROM holds WHERE record_id=?", (record_id,)).fetchone()
    return dict(r) if r else None


def hold_active(record_id: str) -> dict | None:
    h = get_hold(record_id)
    if h and h["active"]:
        # LOCAL 保留到期自动失效（模拟固定保留期限解除）；
        # POLICY/EXTERNAL 保留只能由协调端显式迁移（RELEASE_HOLD）解除，
        # 绝不允许因时间流逝而自动失效（法律保留不可被定时任务悄悄解除）。
        if h["origin"] == "LOCAL" and h["releases_at"] \
                and now_ms() >= h["releases_at"]:
            with _lock:
                db().execute("UPDATE holds SET active=0 WHERE record_id=?",
                             (record_id,))
                db().commit()
            return None
        return h
    return None


def ensure_hold(record_id: str):
    """记录被冻结且配置了本地保留策略时，建立保留（封存而非擦除）。"""
    if record_id not in HOLD_RECORDS:
        return None
    existing = get_hold(record_id)
    if existing:
        return existing if existing["active"] else None
    ts = now_ms()
    with _lock:
        db().execute(
            "INSERT INTO holds(record_id, code, reason, active, origin,"
            " policy_revision, created_at, releases_at)"
            " VALUES(?,?,?,1,'LOCAL',NULL,?,?)",
            (record_id, HOLD_CODE, HOLD_REASON, ts, ts + HOLD_SECONDS * 1000))
        db().commit()
    return get_hold(record_id)


def ensure_external_hold(record_id: str, code: str, reason: str):
    """管理面注入的"外部认证保留"：任何 PURGE/RELEASE 都不得解除（终态封存）。"""
    ts = now_ms()
    with _lock:
        db().execute(
            "INSERT INTO holds(record_id, code, reason, active, origin,"
            " policy_revision, created_at, releases_at)"
            " VALUES(?,?,?,1,'EXTERNAL',NULL,?,NULL)"
            " ON CONFLICT(record_id) DO UPDATE SET code=excluded.code,"
            " reason=excluded.reason, active=1, origin='EXTERNAL',"
            " releases_at=NULL",
            (record_id, code, reason, ts))
        db().commit()
    return get_hold(record_id)


def ensure_policy_hold(record_id: str, rule: dict, revision: int):
    """协调端策略迁移（SEAL）下发的策略来源保留。

    同一 record 已有 EXTERNAL/LOCAL 保留时以既有保留为准（不覆盖、不缩短）；
    保留身份可由协调端随后显式 RELEASE_HOLD 解除。
    """
    existing = get_hold(record_id)
    if existing and existing["active"]:
        return existing
    ts = now_ms()
    secs = int(rule.get("retention_seconds", 0))
    releases = ts + secs * 1000 if secs > 0 else None
    with _lock:
        db().execute(
            "INSERT INTO holds(record_id, code, reason, active, origin,"
            " policy_revision, created_at, releases_at)"
            " VALUES(?,?,?,1,'POLICY',?,?,?)"
            " ON CONFLICT(record_id) DO UPDATE SET code=excluded.code,"
            " reason=excluded.reason, active=1, origin='POLICY',"
            " policy_revision=excluded.policy_revision,"
            " releases_at=excluded.releases_at",
            (record_id, rule["hold_code"], rule.get("hold_reason", ""),
             revision, ts, releases))
        db().commit()
    return get_hold(record_id)


def store_command(command_id: str, request_id: str, record_id: str, op: str,
                  status: str, result: dict):
    ts = now_ms()
    with _lock:
        existing = db().execute("SELECT * FROM commands WHERE command_id=?",
                                (command_id,)).fetchone()
        if existing:
            return dict(existing)
        db().execute(
            "INSERT INTO commands(command_id, request_id, record_id, op, status, result,"
            " created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)",
            (command_id, request_id, record_id, op, status,
             json.dumps(result, ensure_ascii=False, sort_keys=True), ts, ts))
        db().commit()
    return {"command_id": command_id, "status": status, "result": result,
            "replayed": False}


def execute_command(payload: dict) -> dict:
    """幂等执行命令。重复 command_id 返回首次结果（安全重试）。"""
    command_id = payload["command_id"]
    request_id = payload.get("request_id")
    record_id = payload.get("record_id")
    op = payload["op"]

    with _lock:
        existing = db().execute("SELECT * FROM commands WHERE command_id=?",
                                (command_id,)).fetchone()
        if existing:
            d = dict(existing)
            d["result"] = json.loads(d["result"])
            d["replayed"] = True
            return d

        rec = db().execute("SELECT * FROM records WHERE record_id=?",
                           (record_id,)).fetchone()
        ts = now_ms()

        # 命令执行前先看墓碑：已确认删除后任何命令都不能让数据复活。
        # PURGE 例外（幂等擦除）；SEAL/RELEASE_HOLD 是策略迁移操作，只在
        # 仍然存在的封存/冻结记录上工作，绝不使数据恢复可用（423 口径不变），
        # 且规则撤回后续跑 PURGE 是同一工作流的既定语义，故同样放行。
        if rec and tombstone_exists(rec["subject_id"]) \
                and op not in ("PURGE", "SEAL", "RELEASE_HOLD"):
            result = {"status": "FAILED",
                      "error": "tombstone blocks resurrected command",
                      "result_hash": result_hash(record_id, "FAILED")}
            return store_command(command_id, request_id, record_id, op,
                                 "FAILED", result)

        if op == "RESTRICT":
            if not rec:
                result = {"status": "FAILED", "error": "record not found",
                          "result_hash": result_hash(record_id, "FAILED")}
                return store_command(command_id, request_id, record_id, op,
                                     "FAILED", result)
            # 服务侧策略：工作流命令携带其不可变策略修订快照；
            # 命中 SEAL 规则时建立策略来源保留（canary 主体与对照主体因此分化）。
            rules = payload.get("rules") or []
            revision = payload.get("policy_revision")
            pr = seal_rule_for(rules, service=SERVICE_NAME,
                               subject_id=rec["subject_id"],
                               record_id=record_id) if rules else None
            if pr:
                ensure_policy_hold(record_id, pr, revision or 0)
            hold = ensure_hold(record_id) or hold_active(record_id)
            if hold:
                db().execute(
                    "UPDATE records SET status='SEALED', updated_at=? WHERE record_id=?",
                    (ts, record_id))
                db().commit()
                result = {
                    "status": "SEALED", "service": SERVICE_NAME,
                    "request_id": request_id, "record_id": record_id,
                    "subject_id": rec["subject_id"],
                    "hold_code": hold["code"], "hold_reason": hold["reason"],
                    "hold_origin": hold["origin"],
                    "hold_releases_at": hold["releases_at"],
                    "policy_revision": revision,
                    "result_hash": result_hash(record_id, "SEALED",
                                               {"hold_code": hold["code"],
                                                "hold_origin": hold["origin"]}),
                    "note": "受保留约束：封存不擦除，解除后续跑原计划",
                }
                return store_command(command_id, request_id, record_id, op,
                                     "SEALED", result)
            db().execute(
                "UPDATE records SET status='RESTRICTED', updated_at=? WHERE record_id=?",
                (ts, record_id))
            db().commit()
            result = {"status": "RESTRICTED", "service": SERVICE_NAME,
                      "request_id": request_id, "record_id": record_id,
                      "subject_id": rec["subject_id"],
                      "policy_revision": revision,
                      "result_hash": result_hash(record_id, "RESTRICTED")}
            return store_command(command_id, request_id, record_id, op,
                                 "RESTRICTED", result)

        if op == "SEAL":
            # 策略迁移显式封存（目标项可能已是 RESTRICTED/SEALED）。
            if not rec:
                result = {"status": "PURGED", "service": SERVICE_NAME,
                          "request_id": request_id, "record_id": record_id,
                          "note": "already purged before migration",
                          "result_hash": result_hash(record_id, "PURGED")}
                return store_command(command_id, request_id, record_id, op,
                                     "PURGED", result)
            rules = payload.get("rules") or []
            revision = payload.get("policy_revision") or 0
            pr = seal_rule_for(rules, service=SERVICE_NAME,
                               subject_id=rec["subject_id"],
                               record_id=record_id)
            if not pr:
                # 修订不命中该记录：迁移幂等，不做任何改动
                result = {"status": rec["status"], "service": SERVICE_NAME,
                          "request_id": request_id, "record_id": record_id,
                          "subject_id": rec["subject_id"],
                          "result_hash": result_hash(record_id, rec["status"]),
                          "note": "no matching seal rule; unchanged"}
                return store_command(command_id, request_id, record_id, op,
                                     rec["status"], result)
            hold = ensure_policy_hold(record_id, pr, revision)
            db().execute(
                "UPDATE records SET status='SEALED', updated_at=? WHERE record_id=?",
                (ts, record_id))
            db().commit()
            result = {
                "status": "SEALED", "service": SERVICE_NAME,
                "request_id": request_id, "record_id": record_id,
                "subject_id": rec["subject_id"],
                "hold_code": hold["code"], "hold_reason": hold["reason"],
                "hold_origin": hold["origin"],
                "hold_releases_at": hold["releases_at"],
                "result_hash": result_hash(record_id, "SEALED",
                                           {"hold_code": hold["code"],
                                            "policy_revision": revision}),
                "note": "策略迁移：新匹配项先于任何 PURGE 封存"}
            return store_command(command_id, request_id, record_id, op,
                                 "SEALED", result)

        if op == "RELEASE_HOLD":
            # 策略迁移撤回规则：仅解除 POLICY 来源保留；
            # EXTERNAL（外部认证）与 LOCAL 固定保留不得被策略迁移改写。
            if not rec:
                result = {"status": "PURGED", "service": SERVICE_NAME,
                          "request_id": request_id, "record_id": record_id,
                          "note": "already purged",
                          "result_hash": result_hash(record_id, "PURGED")}
                return store_command(command_id, request_id, record_id, op,
                                     "PURGED", result)
            h = hold_active(record_id)
            if h and h["origin"] == "POLICY":
                with _lock:
                    db().execute("UPDATE holds SET active=0 WHERE record_id=?",
                                 (record_id,))
                    db().execute(
                        "UPDATE records SET status='RESTRICTED', updated_at=?"
                        " WHERE record_id=?", (ts, record_id))
                    db().commit()
                result = {
                    "status": "RESTRICTED", "service": SERVICE_NAME,
                    "request_id": request_id, "record_id": record_id,
                    "subject_id": rec["subject_id"],
                    "released_hold_code": h["code"], "hold_origin": "POLICY",
                    "result_hash": result_hash(record_id, "RESTRICTED",
                                               {"released": h["code"]}),
                    "note": "策略撤回：解除封存，续跑同一工作流"}
                return store_command(command_id, request_id, record_id, op,
                                     "RESTRICTED", result)
            if h:
                # 外部认证/本地保留仍然有效：记录保持 SEALED
                db().execute(
                    "UPDATE records SET status='SEALED', updated_at=? WHERE record_id=?",
                    (ts, record_id))
                db().commit()
                result = {
                    "status": "SEALED", "service": SERVICE_NAME,
                    "request_id": request_id, "record_id": record_id,
                    "subject_id": rec["subject_id"],
                    "hold_code": h["code"], "hold_reason": h["reason"],
                    "hold_origin": h["origin"],
                    "hold_releases_at": h["releases_at"],
                    "result_hash": result_hash(record_id, "SEALED",
                                               {"hold_code": h["code"]}),
                    "note": "保留来自外部/本地，策略回滚不得改写"}
                return store_command(command_id, request_id, record_id, op,
                                     "SEALED", result)
            db().execute(
                "UPDATE records SET status='RESTRICTED', updated_at=? WHERE record_id=?",
                (ts, record_id))
            db().commit()
            result = {"status": "RESTRICTED", "service": SERVICE_NAME,
                      "request_id": request_id, "record_id": record_id,
                      "subject_id": rec["subject_id"],
                      "result_hash": result_hash(record_id, "RESTRICTED"),
                      "note": "无活动保留：恢复冻结态，等待 PURGE 闸门"}
            return store_command(command_id, request_id, record_id, op,
                                 "RESTRICTED", result)

        if op == "PURGE":
            if not rec:
                result = {"status": "PURGED", "service": SERVICE_NAME,
                          "request_id": request_id, "record_id": record_id,
                          "note": "already absent (idempotent)",
                          "result_hash": result_hash(record_id, "PURGED")}
                return store_command(command_id, request_id, record_id, op,
                                     "PURGED", result)
            if hold_active(record_id):
                # 约束未解除（含外部认证/本地/策略保留）：拒绝擦除并回报封存事实。
                # HTTP 423（非 4xx 永久失败）+ 幂等命令结果 SEALED：协调端不会把
                # 该条目判为 FAILED，而是经命令状态轮询把它收敛为 SEALED——
                # 这也覆盖"RESTRICT 之后才由外部司法/审计加挂保留"的发现路径。
                h = hold_active(record_id)
                db().execute(
                    "UPDATE records SET status='SEALED', updated_at=? WHERE record_id=?",
                    (ts, record_id))
                db().commit()
                result = {"status": "SEALED", "error": "active hold blocks purge",
                          "service": SERVICE_NAME, "request_id": request_id,
                          "record_id": record_id, "subject_id": rec["subject_id"],
                          "hold_code": h["code"], "hold_reason": h["reason"],
                          "hold_origin": h["origin"],
                          "hold_releases_at": h["releases_at"],
                          "result_hash": result_hash(record_id, "SEALED",
                                                     {"hold_code": h["code"],
                                                      "hold_origin": h["origin"]})}
                out = store_command(command_id, request_id, record_id, op,
                                    "SEALED", result)
                out["http_status"] = 423
                return out
            subject_id = rec["subject_id"]
            token = _mint_tombstone_token(request_id, subject_id)
            # 原子地：擦除业务数据 + 写本地墓碑（关键不变量）
            db().execute(
                "INSERT OR IGNORE INTO tombstones(subject_id, request_id, token, version,"
                " created_at) VALUES(?,?,?,1,?)",
                (subject_id, request_id, token, ts))
            db().execute("DELETE FROM records WHERE record_id=?", (record_id,))
            db().commit()
            result = {"status": "PURGED", "service": SERVICE_NAME,
                      "request_id": request_id, "record_id": record_id,
                      "subject_id": subject_id,
                      "policy_revision": payload.get("policy_revision"),
                      "result_hash": result_hash(record_id, "PURGED",
                                                {"erased_at": ts}),
                      "tombstone_token": token}
            return store_command(command_id, request_id, record_id, op,
                                 "PURGED", result)

        if op == "UNRESTRICT":
            if rec and rec["status"] in ("RESTRICTED",):
                db().execute(
                    "UPDATE records SET status='ACTIVE', updated_at=? WHERE record_id=?",
                    (ts, record_id))
                db().commit()
            status_out = "CANCELLED"
            result = {"status": status_out, "service": SERVICE_NAME,
                      "request_id": request_id, "record_id": record_id,
                      "result_hash": result_hash(record_id, status_out),
                      "note": "saga 局部补偿：解除冻结"}
            return store_command(command_id, request_id, record_id, op,
                                 status_out, result)

        return {"status": "FAILED", "error": f"unknown op {op}", "replayed": False}


def _mint_tombstone_token(request_id: str, subject_id: str) -> str:
    body = canonical({"request_id": request_id, "subject_id": subject_id})
    return f"tomb:{hmac_hex(GLOBAL_TOMBSTONE_SECRET, body)}"


class Handler(BaseHTTPRequestHandler):
    server_version = f"Service-{SERVICE_NAME}/1.0"

    def log_message(self, fmt, *args):
        print(f"[{SERVICE_NAME}] {fmt % args}")

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

    def _auth(self):
        return self.headers.get("Authorization", "") == f"Bearer {INTERNAL_TOKEN}"

    def do_GET(self):
        p = urlparse(self.path).path.rstrip("/") or "/"
        q = urlparse(self.path).query
        try:
            if p == "/health":
                return self._json(200, {"ok": True, "service": SERVICE_NAME,
                                        "ts": iso()})
            if p.startswith("/records/"):
                rid = p.split("/", 2)[2]
                r = db().execute("SELECT * FROM records WHERE record_id=?",
                                 (rid,)).fetchone()
                if not r:
                    return self._json(404, {"error": "not found"})
                r = dict(r)
                code = 200
                if r["status"] == "RESTRICTED":
                    code = 423
                elif r["status"] == "SEALED":
                    code = 423
                return self._json(code, r)
            parts = [x for x in p.split("/") if x]
            if len(parts) == 3 and parts[0] == "internal" \
                    and parts[1] == "commands":
                if not self._auth():
                    return self._json(401, {"error": "unauthorized"})
                r = db().execute("SELECT * FROM commands WHERE command_id=?",
                                 (parts[2],)).fetchone()
                if not r:
                    return self._json(404, {"error": "unknown command"})
                d = dict(r)
                d["result"] = json.loads(d["result"])
                return self._json(200, d["result"])
            if len(parts) == 3 and parts[0] == "internal" and parts[1] == "holds":
                if not self._auth():
                    return self._json(401, {"error": "unauthorized"})
                h = get_hold(parts[2])
                if not h:
                    return self._json(200, {"record_id": parts[2], "active": False})
                active = bool(hold_active(parts[2]))
                return self._json(200, {"record_id": parts[2], "active": active,
                                        "code": h["code"], "reason": h["reason"],
                                        "origin": h["origin"],
                                        "releases_at": h["releases_at"]})
            if p == "/admin/quarantine":
                rows = db().execute(
                    "SELECT id, record_id, subject_id, source, reason, payload, ts"
                    " FROM quarantine ORDER BY id").fetchall()
                return self._json(200, {"quarantine": [dict(r) for r in rows]})
            return self._json(404, {"error": "not found", "path": p})
        except Exception as e:
            return self._json(500, {"error": repr(e)})

    def do_POST(self):
        p = urlparse(self.path).path.rstrip("/") or "/"
        try:
            if p == "/seed":
                body = self._body()
                return self._seed(body)
            if p == "/internal/resolve":
                if not self._auth():
                    return self._json(401, {"error": "unauthorized"})
                body = self._body()
                rows = db().execute(
                    "SELECT record_id, subject_id, kind, status FROM records"
                    " WHERE subject_id=? ORDER BY record_id",
                    (body["subject_id"],)).fetchall()
                return self._json(200, {"service": SERVICE_NAME,
                                        "records": [dict(r) for r in rows]})
            if p == "/internal/commands":
                if not self._auth():
                    return self._json(401, {"error": "unauthorized"})
                payload = self._body()
                # 故障注入：模拟服务长期失联（内部命令 503，健康/查询仍正常）
                if fault_mode() == "commands_503":
                    return self._json(503, {"error": "injected: service unavailable"})
                # 仅 PURGE 失联：用于确定性构造"迁移 vs 迟到 PURGED 回调"竞态
                if fault_mode() == "purge_503" and payload.get("op") == "PURGE":
                    return self._json(503, {"error": "injected: purge unavailable"})
                if fault_mode() == "restrict_409_once" \
                        and payload.get("op") == "RESTRICT":
                    # 一次性永久冲突：只对首次命令 409，之后恢复，
                    # 用于证明协调端不会对"永久失败"做无效重试
                    set_fault(False, "")
                    return self._json(409, {"error": "injected: permanent conflict"})
                if fault_mode() == "restrict_409_permanent" \
                        and payload.get("op") == "RESTRICT":
                    return self._json(409, {"error": "injected: permanent conflict"})
                out = execute_command(payload)
                # PURGE 命中活动保留 -> 命令幂等结果 SEALED 以 423 返回
                # （首次执行与后续幂等重放一致；423 非永久失败，协调端轮询收敛）
                code = out.get("http_status") or (
                    423 if payload.get("op") == "PURGE"
                    and out.get("status") == "SEALED" else 200)
                return self._json(code, out.get("result", out))
            if p == "/internal/tombstones":
                if not self._auth():
                    return self._json(401, {"error": "unauthorized"})
                body = self._body()
                if not verify_tombstone_token(body["request_id"],
                                              body["subject_id"], body["token"]):
                    return self._json(403, {"error": "invalid tombstone token"})
                write_tombstone(body["subject_id"], body["request_id"],
                                body["token"], int(body.get("version", 1)))
                # 反熵：墓碑到达时清除残留的可擦除记录；
                # SEALED 记录受法律/财务保留，墓碑不得越权擦除，
                # 仅继续保证其对业务不可用（423），保留解除后由协调端续跑 PURGE。
                with _lock:
                    rows = db().execute(
                        "SELECT record_id, status FROM records WHERE subject_id=?",
                        (body["subject_id"],)).fetchall()
                    purged = 0
                    for r in rows:
                        if r["status"] == "SEALED":
                            continue
                        db().execute(
                            "INSERT INTO quarantine(record_id, subject_id, source,"
                            " reason, payload, ts) VALUES(?,?,?,?,?,?)",
                            (r["record_id"], body["subject_id"], "anti-entropy",
                             "tombstone arrival purges residual record", None, now_ms()))
                        db().execute("DELETE FROM records WHERE record_id=?",
                                     (r["record_id"],))
                        purged += 1
                    db().commit()
                return self._json(200, {"ok": True, "purged_residual": purged})
            if p == "/admin/fault":
                # 演示/验证用故障注入（生产环境应由管理面鉴权关闭）
                if self.headers.get("Authorization", "") != \
                        f"Bearer {os.environ.get('ADMIN_TOKEN', 'dev-admin-token')}":
                    return self._json(401, {"error": "unauthorized"})
                body = self._body()
                set_fault(bool(body.get("on")), body.get("mode", ""))
                return self._json(200, {"ok": True,
                                        "fault": fault_mode()})
            if p == "/admin/holds":
                # 外部认证保留注入：模拟外部司法/审计封存，任何路径不得改写
                if self.headers.get("Authorization", "") != \
                        f"Bearer {os.environ.get('ADMIN_TOKEN', 'dev-admin-token')}":
                    return self._json(401, {"error": "unauthorized"})
                body = self._body()
                rec = body.get("record_id")
                if not rec:
                    return self._json(400, {"error": "record_id required"})
                h = ensure_external_hold(rec,
                                         body.get("hold_code", "EXTERNAL_CERT"),
                                         body.get("hold_reason",
                                                  "externally certified"))
                r = db().execute("SELECT * FROM records WHERE record_id=?",
                                 (rec,)).fetchone()
                if r:
                    db().execute(
                        "UPDATE records SET status='SEALED', updated_at=?"
                        " WHERE record_id=?", (now_ms(), rec))
                    db().commit()
                return self._json(200, {"ok": True, "hold": {
                    "record_id": rec, "code": h["code"], "origin": h["origin"],
                    "active": bool(h["active"])}})
            if p == "/replica-events":
                body = self._body()
                return self._replica_event(body)
            return self._json(404, {"error": "not found", "path": p})
        except Exception as e:
            return self._json(500, {"error": repr(e)})

    # -- 管理/演示接口 -----------------------------------------------------
    def _seed(self, body: dict):
        ts = now_ms()
        rid = body["record_id"]
        sid = body["subject_id"]
        with _lock:
            # 墓碑优先：已删除主体不得通过"播种/同步"复活
            if tombstone_exists(sid):
                db().execute(
                    "INSERT INTO quarantine(record_id, subject_id, source, reason,"
                    " payload, ts) VALUES(?,?,?,?,?,?)",
                    (rid, sid, "seed", "tombstone blocks re-seed",
                     json.dumps(body, ensure_ascii=False), ts))
                db().commit()
                return self._json(410, {"error": "tombstone: subject deleted",
                                        "quarantined": True})
            db().execute(
                "INSERT INTO records(record_id, subject_id, kind, payload, status,"
                " updated_at) VALUES(?,?,?,?, 'ACTIVE', ?)"
                " ON CONFLICT(record_id) DO UPDATE SET payload=excluded.payload,"
                " updated_at=excluded.updated_at",
                (rid, sid, body.get("kind", "data"),
                 json.dumps(body.get("payload", {}), ensure_ascii=False), ts))
            db().commit()
        return self._json(201, {"ok": True, "service": SERVICE_NAME,
                                "record_id": rid})

    def _replica_event(self, body: dict):
        """迟到副本入口：binlog 重放 / 缓存回填 / 对端同步都走这里。"""
        ts = now_ms()
        rid = body["record_id"]
        sid = body["subject_id"]
        source = body.get("source", "replica")
        with _lock:
            t = tombstone_exists(sid)
            if t:
                db().execute(
                    "INSERT INTO quarantine(record_id, subject_id, source, reason,"
                    " payload, ts) VALUES(?,?,?,?,?,?)",
                    (rid, sid, source,
                     "late replica blocked by tombstone (no resurrection)",
                     json.dumps(body.get("payload", {}), ensure_ascii=False), ts))
                db().commit()
                return self._json(410, {
                    "error": "tombstone blocks late replica",
                    "quarantined": True,
                    "tombstone_request": t["request_id"],
                    "note": "迟到副本已隔离，资料不会重新可用"})
            # 无墓碑：正常应用副本 upsert（仅当协调端尚未确认删除时）
            db().execute(
                "INSERT INTO records(record_id, subject_id, kind, payload, status,"
                " updated_at) VALUES(?,?,?,?,'ACTIVE',?)"
                " ON CONFLICT(record_id) DO UPDATE SET payload=excluded.payload,"
                " updated_at=excluded.updated_at",
                (rid, sid, body.get("kind", "replica"),
                 json.dumps(body.get("payload", {}), ensure_ascii=False), ts))
            db().commit()
        return self._json(201, {"ok": True, "applied": True})


def main():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[{SERVICE_NAME}] listening on :{PORT} db={DB_PATH}"
          f" holds={sorted(HOLD_RECORDS) or 'none'}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
