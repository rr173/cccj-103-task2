"""协调端 HTTP 服务（标准库 ThreadingHTTPServer）。"""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from common import iso, now_ms, verify_signature
from coordinator import policy_client
from coordinator.engine import INTERNAL_TOKEN, POLICY_URL, Engine, load_registry
from coordinator.policy_manager import PolicyConflict
from coordinator.store import Store

ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "dev-admin-token")
DB_PATH = os.environ.get("COORDINATOR_DB", "/data/coordinator.db")
CALLBACK_BASE = os.environ.get("CALLBACK_BASE", "http://127.0.0.1:8080")
LISTEN_PORT = int(os.environ.get("COORDINATOR_PORT", "8080"))

store = Store(DB_PATH)
engine = Engine(store, load_registry(), CALLBACK_BASE)


def _item_view(i: dict) -> dict:
    return {
        "service": i["service"],
        "subject_id": i["subject_id"],
        "record_id": i["record_id"],
        "status": i["status"],
        "attempts": i["attempts"],
        "overdue": bool(i["overdue"]),
        "fatal": bool(i["fatal"]),
        "hold": None if not i["hold_code"] else {
            "code": i["hold_code"], "reason": i["hold_reason"],
            "releases_at": iso(i["hold_releases_at"]) if i["hold_releases_at"] else None,
        },
        "result_hash": i["result_hash"],
        "last_error": i["last_error"],
        "command_id_restrict": i["command_id_restrict"],
        "command_id_purge": i["command_id_purge"],
        "policy_revision": i["policy_revision"],
        "sealed_rule_id": i["sealed_rule_id"],
        "updated_at": iso(i["updated_at"]),
    }


def _request_view(rid: str) -> dict | None:
    req = store.request_view(rid)
    if not req:
        return None
    return {
        "request_id": req["id"],
        "subject_id": req["subject_id"],
        "display_name": req["display_name"],
        "status": req["status"],
        "deadline": iso(req["deadline_ms"]),
        "expired": now_ms() > req["deadline_ms"],
        "cert_version": req["cert_version"],
        "policy_revision": req["policy_revision"],
        "created_at": iso(req["created_at"]),
        "updated_at": iso(req["updated_at"]),
        "items": [_item_view(i) for i in req["items"]],
        "events": req["events"],
        "reports": [
            {"service": r["service"], "command_id": r["command_id"],
             "reported_status": r["reported_status"], "accepted": bool(r["accepted"]),
             "reason": r["reason"], "received_at": iso(r["received_at"])}
            for r in req["reports"]
        ],
        "certificates": [
            {"version": c["version"], "merkle_root": c["merkle_root"],
             "signature": c["signature"], "leaves": c["leaves"],
             "item_count": c["item_count"], "sealed_count": c["sealed_count"],
             "created_at": iso(c["created_at"])}
            for c in req["certificates"]
        ],
    }


def _raw_view(req: dict) -> dict:
    """面向独立验证方的原始证据视图：保留毫秒时间戳与服务回报原文。"""
    import json as _json
    return {
        "request_id": req["id"],
        "subject_id": req["subject_id"],
        "status": req["status"],
        "deadline_ms": req["deadline_ms"],
        "cert_version": req["cert_version"],
        "policy_revision": req["policy_revision"],
        "items": [
            {"service": i["service"], "subject_id": i["subject_id"],
             "record_id": i["record_id"], "status": i["status"],
             "result_hash": i["result_hash"], "hold_code": i["hold_code"],
             "command_id_restrict": i["command_id_restrict"],
             "command_id_purge": i["command_id_purge"],
             "policy_revision": i["policy_revision"],
             "updated_at": i["updated_at"],
             "evidence": _json.loads(i["evidence"]) if i["evidence"] else None}
            for i in req["items"]],
        "certificates": [
            {"version": c["version"], "merkle_root": c["merkle_root"],
             "signature": c["signature"],
             "leaves": c["leaves"], "item_count": c["item_count"],
             "sealed_count": c["sealed_count"], "created_at": c["created_at"]}
            for c in req["certificates"]],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "DeletionCoordinator/1.0"

    def log_message(self, fmt, *args):
        print(f"[coord] {self.address_string()} - {fmt % args}")

    # -- 工具 --------------------------------------------------------------
    def _json(self, code: int, obj: dict | list):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length", 0))
        if not n:
            return {}
        return json.loads(self.rfile.read(n).decode())

    def _auth(self, expected: str) -> bool:
        h = self.headers.get("Authorization", "")
        return h == f"Bearer {expected}"

    # -- 路由 --------------------------------------------------------------
    def do_GET(self):
        p = urlparse(self.path).path.rstrip("/") or "/"
        try:
            if p == "/health":
                return self._json(200, {"ok": True, "role": "coordinator",
                                        "ts": iso()})
            parts = [x for x in p.split("/") if x]
            if len(parts) == 2 and parts[0] == "requests":
                view = _request_view(parts[1])
                return self._json(200 if view else 404, view or {"error": "not found"})
            if len(parts) == 3 and parts[0] == "requests" \
                    and parts[2] == "tombstones":
                if not store.get_request(parts[1]):
                    return self._json(404, {"error": "not found"})
                return self._json(200, {"tombstones": store.list_tombstones(parts[1])})
            if len(parts) == 3 and parts[0] == "requests" \
                    and parts[2] == "verify":
                return self._verify(parts[1])
            if len(parts) == 4 and parts[0] == "internal" \
                    and parts[1] == "requests" and parts[3] == "raw":
                # 第三方验证用原始证据（毫秒时间戳、命令 id、服务回报原文）
                if not self._auth(INTERNAL_TOKEN):
                    return self._json(401, {"error": "unauthorized"})
                req0 = store.request_view(parts[2])
                if not req0:
                    return self._json(404, {"error": "not found"})
                return self._json(200, _raw_view(req0))
            if p == "/policy/revisions":
                if not self._auth(ADMIN_TOKEN):
                    return self._json(401, {"error": "unauthorized"})
                return self._json(200, {"revisions": store.list_policy_revisions()})
            if len(parts) == 3 and parts[:2] == ["policy", "revisions"]:
                if not self._auth(ADMIN_TOKEN):
                    return self._json(401, {"error": "unauthorized"})
                rev = None
                try:
                    rev = engine.policy.get_revision(int(parts[2]))
                except Exception as e:
                    return self._json(502, {"error": repr(e)})
                return self._json(200 if rev else 404, rev or {"error": "not found"})
            if p == "/policy/current":
                if not self._auth(INTERNAL_TOKEN):
                    return self._json(401, {"error": "unauthorized"})
                try:
                    s, b = policy_client.get(f"{POLICY_URL}/current", INTERNAL_TOKEN)
                    return self._json(s, b)
                except policy_client.PolicyUnavailable as e:
                    return self._json(503, {"error": "policy unreachable",
                                            "detail": str(e)})
            if p == "/policy/dry-run":
                if not self._auth(ADMIN_TOKEN):
                    return self._json(401, {"error": "unauthorized"})
                q = parse_qs(urlparse(self.path).query)
                try:
                    rev = int(q["revision"][0])
                    action = q.get("action", ["CANARY"])[0]
                except (KeyError, ValueError):
                    return self._json(400, {"error": "?revision=N&action=... required"})
                try:
                    return self._json(200, engine.policy.dry_run(rev, action))
                except Exception as e:
                    return self._json(502, {"error": repr(e)})
            if p == "/migrations":
                if not self._auth(ADMIN_TOKEN):
                    return self._json(401, {"error": "unauthorized"})
                return self._json(200, {"migrations": engine.policy.list_migrations()})
            if len(parts) == 2 and parts[0] == "migrations":
                if not self._auth(ADMIN_TOKEN):
                    return self._json(401, {"error": "unauthorized"})
                mv = engine.policy.migration_view(parts[1])
                return self._json(200 if mv else 404, mv or {"error": "not found"})
            return self._json(404, {"error": "not found", "path": p})
        except Exception as e:
            return self._json(500, {"error": repr(e)})

    def do_POST(self):
        p = urlparse(self.path).path.rstrip("/") or "/"
        try:
            parts = [x for x in p.split("/") if x]
            if p == "/requests":
                body = self._body()
                if not body.get("subject_id"):
                    return self._json(400, {"error": "subject_id required"})
                req = engine.create_request(body["subject_id"],
                                            body.get("display_name"),
                                            pause_after_resolve=bool(
                                                body.get("pause_after_resolve")))
                return self._json(202, {"request_id": req["id"],
                                        "status": req["status"]})
            if p == "/internal/reports":
                if not self._auth(INTERNAL_TOKEN):
                    return self._json(401, {"error": "unauthorized"})
                result = engine.ingest_report(self._body())
                return self._json(200 if result.get("accepted") else 409, result)
            if len(parts) == 4 and parts[0] == "admin" and parts[1] == "requests" \
                    and parts[3] in ("pause", "resume"):
                if not self._auth(ADMIN_TOKEN):
                    return self._json(401, {"error": "unauthorized"})
                rid = parts[2]
                req = store.get_request(rid)
                if not req:
                    return self._json(404, {"error": "not found"})
                val = 1 if parts[3] == "pause" else 0
                with store.lock:
                    store.conn.execute(
                        "UPDATE requests SET engine_paused=? WHERE id=?", (val, rid))
                    store.event(rid, f"ENGINE_{parts[3].upper()}D", {})
                    store.commit()
                return self._json(200, {"request_id": rid, "engine_paused": bool(val)})
            if p == "/policy/apply":
                return self._apply_revision()
            if p == "/admin/fault":
                if not self._auth(ADMIN_TOKEN):
                    return self._json(401, {"error": "unauthorized"})
                body = self._body()
                mode = body.get("mode", "")
                on = bool(body.get("on", True))
                if mode == "purge_paused":
                    engine.purge_paused = on
                    if not on:
                        # 同时解除所有持久化在迁移行上的“停在某项前”钩子
                        with store.lock:
                            store.conn.execute(
                                "UPDATE migrations SET pause_after_item=NULL"
                                " WHERE status='RUNNING'")
                            store.commit()
                elif mode == "migration_crash":
                    # 下一个迁移 checkpoint 落库后立即崩溃（崩溃恢复场景）
                    engine.policy.crash_after_step = on
                elif mode == "crash":
                    engine.crash_after_tick = True
                    return self._json(202, {"ok": True, "crash_armed": True})
                elif mode == "clear":
                    engine.purge_paused = False
                    engine.crash_after_tick = False
                    engine.policy.crash_after_step = False
                    with store.lock:
                        store.conn.execute(
                            "UPDATE migrations SET pause_after_item=NULL"
                            " WHERE status='RUNNING'")
                        store.commit()
                else:
                    return self._json(400, {"error": f"unknown mode {mode}"})
                return self._json(200, {"ok": True,
                                        "purge_paused": engine.purge_paused,
                                        "migration_crash":
                                            engine.policy.crash_after_step})
            return self._json(404, {"error": "not found", "path": p})
        except Exception as e:
            return self._json(500, {"error": repr(e)})

    def _apply_revision(self):
        if not self._auth(ADMIN_TOKEN):
            return self._json(401, {"error": "unauthorized"})
        body = self._body()
        try:
            rev = int(body["revision"])
        except (KeyError, ValueError, TypeError):
            return self._json(400, {"error": "revision (int) required"})
        action = (body.get("action") or "CANARY").upper()
        if action not in ("CANARY", "ACTIVATE", "WITHDRAW", "ROLLBACK"):
            return self._json(400, {"error": "invalid action"})
        exp = body.get("expected_version")
        try:
            mv = engine.policy.apply_revision(
                rev, action, body.get("idempotency_key"),
                int(exp) if exp is not None else None,
                pause_after_item=body.get("pause_after_item"),
                source_revision=(int(body["source_revision"])
                                 if body.get("source_revision") is not None
                                 else None))
        except PolicyConflict as c:
            # 诊断性 409：迁移行都没写，所有项原子地保持原样
            return self._json(409, {
                "error": "version_conflict",
                "message": str(c), "expected_version": c.expected,
                "server_head": c.head, "server_active": c.active,
                "diagnostic": "optimistic concurrency guard: no items touched"})
        except Exception as e:
            return self._json(502, {"error": repr(e)})
        return self._json(202, mv)

    def _verify(self, rid: str):
        """独立复算入口（测试用 verifier 不依赖该接口，自行复算）。"""
        from common import evidence_leaf, merkle_root, verify_tombstone_token
        view = _request_view(rid)
        if not view or not view["certificates"]:
            return self._json(404, {"error": "no certificate"})
        cert = view["certificates"][-1]
        # 1) 叶子与 Merkle 根
        calc_root = merkle_root([l["hash"] for l in cert["leaves"]])
        root_ok = calc_root == cert["merkle_root"]
        # 2) 协调端签名
        payload = {
            "request_id": rid, "subject_id": view["subject_id"],
            "version": cert["version"], "merkle_root": cert["merkle_root"],
            "issued_at": store.list_certificates(rid)[-1]["created_at"],
            "sealed_count": cert["sealed_count"], "item_count": cert["item_count"],
        }
        sig_ok = verify_signature(payload, cert["signature"])
        # 3) 每项叶子可由其证据复算
        items = {f"{i['service']}:{i['record_id']}": i for i in view["items"]}
        leaf_ok = True
        for leaf in cert["leaves"]:
            it = items.get(leaf["item"])
            if not it:
                leaf_ok = False
                continue
            raw_it = store.get_item(f"{rid}:{it['service']}:{it['record_id']}")
            body = {
                "service": it["service"], "subject_id": it["subject_id"],
                "record_id": it["record_id"], "status": it["status"],
                "result_hash": it["result_hash"],
                "hold_code": it["hold"]["code"] if it["hold"] else None,
                "command_id": it["command_id_purge"] or it["command_id_restrict"],
                "policy_revision": raw_it["policy_revision"],
                "updated_at": raw_it["updated_at"],
            }
            if evidence_leaf(body) != leaf["hash"]:
                leaf_ok = False
        return self._json(200, {"merkle_root_ok": root_ok, "signature_ok": sig_ok,
                                "leaves_ok": leaf_ok,
                                "verified": root_ok and sig_ok and leaf_ok})


def main():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    engine.start()
    httpd = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler)
    print(f"[coord] deletion coordinator listening on :{LISTEN_PORT} db={DB_PATH}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        engine.stop()


if __name__ == "__main__":
    main()
