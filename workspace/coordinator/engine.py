"""删除编排引擎。

核心保证：
1. 删除申请 -> 先并行解析各服务关联身份 -> 生成带期限（deadline/SLA）的执行计划。
2. Saga 两阶段：RESTRICT（可逆冻结/封存）全部成功后才 PURGE（擦除）；
   任一服务永久失败则对已冻结项做局部补偿（UNRESTRICT）并中止，不会半删。
3. 法律保留/财务留存：服务回报 SEALED + hold_code + 解除时间；计划项保持终态
   "封存未擦除"，约束到期后引擎自动续跑原计划（同一 request_id/同一计划），
   约束解除后不需要用户重新申请。
4. 回报可重复/乱序：以 command_id 幂等、以状态序（STATUS_RANK）判定乱序，
   全部落库审计；服务长期失联时按阶段期限标记 overdue，同时轮询补偿回调丢失。
5. 对外确认（CONFIRMED + 证书）后写入全局墓碑（tombstone）并推送到各服务，
   迟到副本在任何服务落地前都会被墓碑拦截，不得把资料带回可用状态。
6. 最终结果可证明：每项服务签名证据 -> 叶子哈希 -> Merkle 根 -> 协调端签名证书，
   验证方仅凭返回字段即可独立复算验证（tests/verifier.py 独立实现验证）。
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid

from . import http_client, policy_client
from .store import SEALED_LIKE, STATUS_RANK, TERMINAL, Store
from common import (
    evidence_leaf,
    iso,
    merkle_root,
    now_ms,
    seal_rule_for,
    sign,
    tombstone_token,
)

# 阶段期限（毫秒）。计划带期限；到期未到终态 -> overdue 告警，但不放弃。
RESTRICT_SLA_MS = int(os.environ.get("RESTRICT_SLA_SECONDS", "30")) * 1000
PURGE_SLA_MS = int(os.environ.get("PURGE_SLA_SECONDS", "30")) * 1000
REQUEST_TTL_MS = int(os.environ.get("REQUEST_TTL_SECONDS", "300")) * 1000
BACKOFF_BASE_MS = int(os.environ.get("BACKOFF_BASE_MS", "400"))
BACKOFF_MAX_MS = int(os.environ.get("BACKOFF_MAX_MS", "5000"))
POLL_AFTER_MS = int(os.environ.get("POLL_AFTER_MS", "1500"))
HOLD_CHECK_MS = int(os.environ.get("HOLD_CHECK_MS", "1000"))
TICK_MS = float(os.environ.get("ENGINE_TICK_MS", "0.3"))

INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "dev-internal-token")

DEFAULT_REGISTRY = [
    {"name": "orders", "base_url": "http://127.0.0.1:9101"},
    {"name": "billing", "base_url": "http://127.0.0.1:9102"},
    {"name": "profile", "base_url": "http://127.0.0.1:9103"},
]


def load_registry() -> list[dict]:
    raw = os.environ.get("SERVICES_JSON")
    if raw:
        reg = json.loads(raw)
    else:
        reg = DEFAULT_REGISTRY
    for s in reg:
        s.setdefault("token", INTERNAL_TOKEN)
    return reg


def backoff_ms(attempt: int) -> int:
    return min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * (2 ** max(0, attempt - 1)))


class Engine:
    def __init__(self, store: Store, registry: list[dict], callback_base: str):
        self.store = store
        self.registry = {s["name"]: s for s in registry}
        self.callback_base = callback_base.rstrip("/")
        self._stop = threading.Event()
        self._pause_after_resolve: set[str] = set()
        # 已应用/在途修订的规则快照缓存：迁移把条目换绑后，RESTRICT 重发需用其修订
        self._rev_rules: dict[int, list[dict]] = {}
        # 崩溃注入：本次运行处理完第 N 个迁移项后在检查点落盘后退出；
        # 重启的进程默认为 0（不持久化），从而从持久检查点恢复完成迁移。
        # 经 POST /admin/policy/crash-after 在运行时武装（仅进程内存）。
        self._crash_after = 0
        self.thread: threading.Thread | None = None

    def set_migration_crash_after(self, n: int):
        self._crash_after = max(0, int(n))

    # -- 生命周期 ----------------------------------------------------------
    def start(self):
        self.thread = threading.Thread(target=self._run, name="engine", daemon=True)
        self.thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as e:  # 引擎循环绝不能因单次异常退出
                print(f"[engine] tick error: {e!r}")
            time.sleep(TICK_MS)

    # -- 申请入口 ----------------------------------------------------------
    def create_request(self, subject_id: str, display_name: str | None = None,
                       pause_after_resolve: bool = False) -> dict:
        rid = f"req_{uuid.uuid4().hex[:16]}"
        ts = now_ms()
        if pause_after_resolve:
            self._pause_after_resolve.add(rid)
        # 每个工作流在创建时绑定一个不可变的策略修订快照：
        # 金丝雀主体命中 CANARIED 修订，其余主体命中 ACTIVE 修订。
        snap = policy_client.resolve_subject(subject_id)
        revision = int(snap["revision"])
        rules = snap.get("rules", [])
        with self.store.lock:
            self.store.conn.execute(
                "INSERT INTO requests(id, subject_id, display_name, status, deadline_ms,"
                " created_at, updated_at, policy_revision)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (rid, subject_id, display_name, "RESOLVING", ts + REQUEST_TTL_MS,
                 ts, ts, revision))
            self.store.put_binding(rid, subject_id, revision, rules,
                                   snap.get("content_hash"),
                                   bool(snap.get("canary")))
            for svc in self.registry:
                iid = f"{rid}:{svc}:PENDING"
                self.store.conn.execute(
                    "INSERT INTO items(id, request_id, service, subject_id, status,"
                    " next_attempt_at, created_at, updated_at, policy_revision,"
                    " policy_version) VALUES(?,?,?,?,?,?,?,?,?,1)",
                    (iid, rid, svc, subject_id, "PENDING", ts, ts, ts, revision))
            self.store.event(rid, "REQUEST_CREATED", {
                "subject_id": subject_id, "display_name": display_name,
                "deadline": iso(ts + REQUEST_TTL_MS),
                "services": list(self.registry),
                "policy_revision": revision, "canary": bool(snap.get("canary"))})
            self.store.commit()
        return self.store.get_request(rid)

    # -- 主循环 ------------------------------------------------------------
    def tick(self):
        # 先恢复/推进在途策略迁移：崩溃重启后仅凭持久登记即可从检查点续跑
        try:
            self._process_migrations()
        except Exception as e:
            print(f"[engine] migration tick error: {e!r}")
        for req in self.store.active_requests():
            rid = req["id"]
            if req["engine_paused"]:
                continue
            with self.store.lock:
                try:
                    self._process_request(rid)
                except Exception as e:
                    # 单请求处理失败不影响其他请求；落审计后下轮重试
                    self.store.event(rid, "TICK_ERROR", {"error": repr(e)})
                    self.store.commit()

    def _process_request(self, rid: str):
        req = self.store.get_request(rid)
        items = self.store.list_items(rid)
        if req["status"] == "RESOLVING":
            self._resolve(rid, items)
            items = self.store.list_items(rid)
            # 计划就绪：已无占位项（占位项 id 形如 <rid>:<service>:PENDING）。
            # 真实项初始也是 PENDING，故必须按 id/record_id 判定而非状态。
            resolved_done = bool(items) and all(
                not i["id"].endswith(":PENDING") for i in items)
            if resolved_done:
                # 验证钩子：解析完成即冻结，计划停在 PENDING，等待注入异常回报
                if rid in self._pause_after_resolve:
                    self.store.conn.execute(
                        "UPDATE requests SET engine_paused=1 WHERE id=?", (rid,))
                    self.store.event(rid, "ENGINE_PAUSED",
                                     {"hook": "pause_after_resolve"})
                    self._pause_after_resolve.discard(rid)
                    self.store.commit()
                    return
                self._set_request_status(rid, "IN_PROGRESS")
                self.store.event(rid, "PLAN_READY", {
                    "deadline": iso(req["deadline_ms"]),
                    "items": [
                        {"service": i["service"], "record_id": i["record_id"],
                         "present": i["status"] != "CANCELLED"}
                        for i in items],
                })
            req = self.store.get_request(rid)

        if req["status"] in ("IN_PROGRESS", "CONFIRMED"):
            items = self.store.list_items(rid)
            self._dispatch_restrict(rid, items)
            items = self.store.list_items(rid)
            self._poll_missing_callbacks(rid, items)
            self._check_sealed_holds(rid, items)
            items = self.store.list_items(rid)
            self._open_purge_gate(rid, items)
            items = self.store.list_items(rid)
            self._dispatch_purge(rid, items)
            items = self.store.list_items(rid)
            self._mark_overdue(rid, items)
            items = self.store.list_items(rid)

            if any(i["status"] == "FAILED" for i in items):
                self._compensate_and_abort(rid, items)
                return

            self._maybe_confirm(rid, self.store.get_request(rid), items)

    # -- 阶段 0：跨服务身份解析 --------------------------------------------
    def _resolve(self, rid: str, items: list[dict]):
        ts = now_ms()
        # 只处理占位项（record_id 尚未确定）；解析成功后该项被真实计划项替换，
        # 必须从本轮待处理集合移除，避免同 tick 重复插入触发唯一约束。
        pending = [i for i in items if i["status"] == "PENDING"
                   and i["record_id"] is None]
        for item in pending:
            svc = self.registry.get(item["service"])
            if not svc:
                continue
            try:
                status, body = http_client.post(
                    f"{svc['base_url']}/internal/resolve",
                    {"subject_id": item["subject_id"]}, svc["token"])
                records = body.get("records", [])
                # 用真实记录替换占位计划项；该服务无关联记录 -> CANCELLED（无需处理）
                self.store.conn.execute(
                    "DELETE FROM items WHERE id=?", (item["id"],))
                if not records:
                    nid = f"{rid}:{item['service']}:NONE"
                    self.store.conn.execute(
                        "INSERT INTO items(id, request_id, service, subject_id, record_id,"
                        " status, next_attempt_at, created_at, updated_at)"
                        " VALUES(?,?,?,?,?,?,?,?,?)",
                        (nid, rid, item["service"], item["subject_id"], None,
                         "CANCELLED", 0, ts, ts))
                    self.store.event(rid, "IDENTITY_RESOLVED",
                                     {"service": item["service"], "records": []})
                else:
                    for rec in records:
                        nid = f"{rid}:{item['service']}:{rec['record_id']}"
                        self.store.conn.execute(
                            "INSERT INTO items(id, request_id, service, subject_id,"
                            " record_id, status, command_id_restrict, next_attempt_at,"
                            " created_at, updated_at, policy_revision, policy_version)"
                            " VALUES(?,?,?,?,?,?,?,?,?,?,?,1)",
                            (nid, rid, item["service"], item["subject_id"],
                             rec["record_id"], "PENDING",
                             f"cmd_{uuid.uuid4().hex[:12]}", ts, ts, ts,
                             item.get("policy_revision", 1)))
                    self.store.event(rid, "IDENTITY_RESOLVED", {
                        "service": item["service"], "records": records})
                # 关键：解析结果立即提交，后续 tick 才能看到真实计划项
                self.store.commit()
            except http_client.ServiceError as e:
                # 解析失败：保留 PENDING 退避重试（身份解析是计划前提）
                self.store.conn.execute(
                    "UPDATE items SET attempts=attempts+1, last_error=?,"
                    " next_attempt_at=? WHERE id=?",
                    (f"resolve failed: {e.body}", ts + backoff_ms(item["attempts"] + 1),
                     item["id"]))
                self.store.event(rid, "RESOLVE_RETRY",
                                 {"service": item["service"], "error": str(e.body)})

    # -- 阶段 1：RESTRICT（可逆冻结；命中保留策略则服务自行 SEALED） --------
    def _dispatch_restrict(self, rid: str, items: list[dict]):
        ts = now_ms()
        for item in items:
            if item["status"] not in ("PENDING", "DISPATCHED", "ERROR"):
                continue
            if item["next_attempt_at"] and ts < item["next_attempt_at"]:
                continue
            svc = self.registry.get(item["service"])
            command_id = item["command_id_restrict"] or f"cmd_{uuid.uuid4().hex[:12]}"
            rules = self._rules_for_revision(item["policy_revision"], rid)
            payload = {
                "command_id": command_id,
                "request_id": rid,
                "subject_id": item["subject_id"],
                "record_id": item["record_id"],
                "op": "RESTRICT",
                "callback_url": f"{self.callback_base}/internal/reports",
                # 命令携带条目所绑定的不可变策略快照：金丝雀/对照主体分流
                "policy_revision": item["policy_revision"],
                "rules": rules,
            }
            try:
                status, body = http_client.post(
                    f"{svc['base_url']}/internal/commands", payload, svc["token"])
                # 服务同步执行：可能直接给出终态（RESTRICTED/SEALED）
                if body.get("status") in ("RESTRICTED", "SEALED"):
                    self._apply_service_result(item, command_id, body)
                else:
                    self._mark_dispatched(item, command_id, "restrict", body)
            except http_client.ServiceError as e:
                self._handle_call_error(item, command_id, "restrict", e)

    # -- 回调丢失的安全补偿：轮询服务侧命令状态（不依赖回调恰好送达） ------
    def _poll_missing_callbacks(self, rid: str, items: list[dict]):
        ts = now_ms()
        for item in items:
            if item["status"] not in ("DISPATCHED", "ERROR"):
                continue
            if not item["active_command_id"]:
                continue
            if ts - item["updated_at"] < POLL_AFTER_MS:
                continue
            svc = self.registry.get(item["service"])
            try:
                _, body = http_client.get(
                    f"{svc['base_url']}/internal/commands/{item['active_command_id']}",
                    svc["token"])
                if body.get("status") in ("RESTRICTED", "SEALED", "PURGED", "FAILED"):
                    self._apply_service_result(item, item["active_command_id"], body,
                                               via="POLL")
            except http_client.ServiceError:
                pass  # 服务失联：退避/overdue 路径负责

    # -- 法律/财务保留：检查封存是否解除，解除后续跑原 PURGE ---------------
    def _check_sealed_holds(self, rid: str, items: list[dict]):
        ts = now_ms()
        for item in items:
            if item["status"] != "SEALED":
                continue
            if ts - item["holds_checked_at"] < HOLD_CHECK_MS:
                continue
            svc = self.registry.get(item["service"])
            try:
                _, body = http_client.get(
                    f"{svc['base_url']}/internal/holds/{item['record_id']}",
                    svc["token"])
                self.store.conn.execute(
                    "UPDATE items SET holds_checked_at=? WHERE id=?", (ts, item["id"]))
                active = body.get("active")
                releases_at = body.get("releases_at")
                origin = body.get("origin")
                # 仅服务侧 LOCAL 固定保留到期自动解除；
                # POLICY 保留必须由显式策略迁移（RELEASE_HOLD）撤回，
                # EXTERNAL（外部认证）保留任何路径都不得解除。
                if not active and origin in (None, "LOCAL"):
                    # 保留解除：同一计划项回到 RESTRICTED，等待 PURGE 闸门
                    self.store.conn.execute(
                        "UPDATE items SET status='RESTRICTED', hold_code=NULL,"
                        " hold_reason=NULL, hold_releases_at=NULL, hold_origin=NULL,"
                        " updated_at=? WHERE id=?",
                        (ts, item["id"]))
                    self.store.event(rid, "HOLD_RELEASED", {
                        "service": item["service"], "record_id": item["record_id"],
                        "origin": origin,
                        "note": "约束解除，自动续跑原计划，无需重新申请"})
                elif releases_at and releases_at != item["hold_releases_at"]:
                    self.store.conn.execute(
                        "UPDATE items SET hold_releases_at=?, updated_at=? WHERE id=?",
                        (releases_at, ts, item["id"]))
            except http_client.ServiceError:
                pass

    # -- PURGE 闸门：所有非空计划项 RESTRICTED/SEALED 后才开放 -------------
    def _open_purge_gate(self, rid: str, items: list[dict]):
        actionable = [i for i in items if i["status"] != "CANCELLED"]
        if not actionable:
            return
        if any(i["status"] in ("PENDING", "DISPATCHED", "ERROR") for i in actionable):
            return
        if not all(i["status"] in SEALED_LIKE for i in actionable):
            return
        ts = now_ms()
        changed = False
        for item in actionable:
            if not item["command_id_purge"]:
                self.store.conn.execute(
                    "UPDATE items SET command_id_purge=?, purge_due_ms=? WHERE id=?",
                    (f"cmd_{uuid.uuid4().hex[:12]}", ts + PURGE_SLA_MS, item["id"]))
                changed = True
        if changed:
            self.store.event(rid, "PURGE_GATE_OPENED",
                             {"note": "全部服务冻结/封存完成，开放擦除阶段"})

    # -- 阶段 2：PURGE（擦除；SEALED 项跳过直到保留解除） ------------------
    def _dispatch_purge(self, rid: str, items: list[dict]):
        ts = now_ms()
        for item in items:
            if item["status"] != "RESTRICTED":
                continue
            if not item["command_id_purge"]:
                continue
            if item["next_attempt_at"] and ts < item["next_attempt_at"]:
                continue
            svc = self.registry.get(item["service"])
            command_id = item["command_id_purge"]
            payload = {
                "command_id": command_id,
                "request_id": rid,
                "subject_id": item["subject_id"],
                "record_id": item["record_id"],
                "op": "PURGE",
                "callback_url": f"{self.callback_base}/internal/reports",
                "policy_revision": item["policy_revision"],
            }
            try:
                status, body = http_client.post(
                    f"{svc['base_url']}/internal/commands", payload, svc["token"])
                if body.get("status") == "PURGED":
                    self._apply_service_result(item, command_id, body)
                else:
                    self._mark_dispatched(item, command_id, "purge", body)
            except http_client.ServiceError as e:
                self._handle_call_error(item, command_id, "purge", e)

    # -- 失联/超时：标记 overdue（可证明地展示，继续重试，不终止） ----------
    def _mark_overdue(self, rid: str, items: list[dict]):
        ts = now_ms()
        for item in items:
            if item["status"] in TERMINAL or item["status"] in SEALED_LIKE \
                    or item["status"] == "CANCELLED":
                continue
            due = (item["purge_due_ms"] if item["command_id_purge"]
                   else item["created_at"] + RESTRICT_SLA_MS)
            if ts > due and not item["overdue_event"]:
                self.store.conn.execute(
                    "UPDATE items SET overdue=1, overdue_event=1 WHERE id=?",
                    (item["id"],))
                self.store.event(rid, "ITEM_OVERDUE", {
                    "service": item["service"], "record_id": item["record_id"],
                    "phase": "PURGE" if item["command_id_purge"] else "RESTRICT",
                    "since": iso(due),
                    "note": "服务长期失联或未回报；继续安全重试与轮询"})

    # -- Saga 补偿与中止 ---------------------------------------------------
    def _compensate_and_abort(self, rid: str, items: list[dict]):
        req = self.store.get_request(rid)
        if req["status"] == "ABORTED":
            return
        ts = now_ms()
        for item in items:
            # 仅补偿可逆阶段（RESTRICTED）；已擦除不可恢复，保留墓碑；
            # SEALED 受法律约束不得解封存；FAILED 项保持 FAILED。
            if item["status"] != "RESTRICTED":
                continue
            svc = self.registry.get(item["service"])
            comp_id = f"cmd_comp_{uuid.uuid4().hex[:10]}"
            payload = {
                "command_id": comp_id, "request_id": rid,
                "subject_id": item["subject_id"], "record_id": item["record_id"],
                "op": "UNRESTRICT",
                "callback_url": f"{self.callback_base}/internal/reports"}
            try:
                _, body = http_client.post(
                    f"{svc['base_url']}/internal/commands", payload, svc["token"])
                final_status = body.get("status", "CANCELLED")
                self.store.conn.execute(
                    "UPDATE items SET status=?, active_command_id=?, updated_at=? WHERE id=?",
                    (final_status if final_status in ("CANCELLED", "RESTRICTED")
                     else "CANCELLED", comp_id, ts, item["id"]))
                self.store.event(rid, "COMPENSATED", {
                    "service": item["service"], "record_id": item["record_id"],
                    "command_id": comp_id, "result": body})
            except http_client.ServiceError as e:
                # 补偿本身也要安全重试：留在 RESTRICTED，下轮继续
                self.store.conn.execute(
                    "UPDATE items SET attempts=attempts+1, last_error=?,"
                    " next_attempt_at=? WHERE id=?",
                    (f"compensate failed: {e.body}",
                     ts + backoff_ms(item["attempts"] + 1), item["id"]))
                self.store.event(rid, "COMPENSATE_RETRY",
                                 {"service": item["service"], "error": str(e.body)})
        # 仍有补偿未完成则下轮继续，不急着 ABORTED
        items2 = self.store.list_items(rid)
        if any(i["status"] == "RESTRICTED" for i in items2):
            self.store.commit()
            return
        self._set_request_status(rid, "ABORTED")
        self.store.event(rid, "REQUEST_ABORTED", {
            "note": "存在永久失败项，已对可逆项完成局部补偿；未对外确认删除"})

    # -- 对外确认 + 可证明结果 + 墓碑传播 ----------------------------------
    def _maybe_confirm(self, rid: str, req: dict, items: list[dict]):
        actionable = [i for i in items if i["status"] != "CANCELLED"]
        if not actionable:
            # 该用户在任何服务都无数据：也给出"空删除"证书
            if req["status"] != "CONFIRMED":
                self._issue_confirmation(rid, req, items)
            return
        # 仅在整体终态时签发/升级证书：
        #  - 全部 PURGED：最终删除证书（sealed_count=0）
        #  - 全部 PURGED/SEALED 且至少一个 SEALED：封存确认证书（带保留信息）
        # 阶段中间态（RESTRICTED/PURGING 等）不得发证书。
        statuses = {i["status"] for i in actionable}
        all_terminal = statuses <= {"PURGED", "SEALED"}
        if not all_terminal:
            return
        has_sealed = "SEALED" in statuses
        already_cert_for_state = False
        if req["cert_version"]:
            last = self.store.list_certificates(rid)[-1]
            already_cert_for_state = (last["sealed_count"] > 0) == has_sealed \
                and req["status"] == "CONFIRMED"
        if not already_cert_for_state:
            self._issue_confirmation(rid, req, items)

    def _issue_confirmation(self, rid: str, req: dict, items: list[dict]):
        ts = now_ms()
        version = (req["cert_version"] or 0) + 1
        leaves = []
        sealed = 0
        for item in sorted(items, key=lambda i: (i["service"], i["record_id"] or "")):
            leaf_body = {
                "service": item["service"],
                "subject_id": item["subject_id"],
                "record_id": item.get("record_id"),
                "status": item["status"],
                "result_hash": item.get("result_hash"),
                "hold_code": item.get("hold_code"),
                # 证据中绑定阶段命令：已进入擦除阶段则用 PURGE 命令，否则 RESTRICT
                "command_id": item.get("command_id_purge")
                             or item.get("command_id_restrict"),
                "updated_at": item["updated_at"],
                # 证据绑定策略修订：证书签发时该项所处的不可变策略版本
                "policy_revision": item.get("policy_revision"),
            }
            # 叶子携带完整规范字段：历史证书在条目后续迁移后仍可独立复验，
            # 而不依赖会变化的当前 items 行。
            leaves.append({"item": f"{item['service']}:{item.get('record_id')}",
                           "status": item["status"],
                           "hash": evidence_leaf(leaf_body),
                           "body": leaf_body})
            if item["status"] == "SEALED":
                sealed += 1
        root = merkle_root([l["hash"] for l in leaves])
        cert_payload = {
            "request_id": rid, "subject_id": req["subject_id"],
            "version": version, "merkle_root": root, "issued_at": ts,
            "sealed_count": sealed, "item_count": len(leaves),
        }
        signature = sign(cert_payload)
        with self.store.lock:
            self.store.conn.execute(
                "INSERT OR REPLACE INTO certificates(request_id, version, merkle_root,"
                " signature, leaves, item_count, sealed_count, created_at)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (rid, version, root, signature, json.dumps(leaves, ensure_ascii=False),
                 len(leaves), sealed, ts))
            self.store.conn.execute(
                "UPDATE requests SET cert_version=?, updated_at=? WHERE id=?",
                (version, ts, rid))
            # 全局墓碑（幂等）。SEALED 项也进入删除确认口径：业务侧同样不可用。
            token = tombstone_token(rid, req["subject_id"])
            self.store.conn.execute(
                "INSERT OR IGNORE INTO tombstones(request_id, subject_id, service,"
                " token, version, pushed, created_at) VALUES(?,?,?,?,?,0,?)",
                (rid, req["subject_id"], "*", token, version, ts))
            for item in items:
                if item["status"] == "CANCELLED":
                    continue
                self.store.conn.execute(
                    "INSERT OR IGNORE INTO tombstones(request_id, subject_id, service,"
                    " token, version, pushed, created_at) VALUES(?,?,?,?,?,0,?)",
                    (rid, req["subject_id"], item["service"], token, version, ts))
            self.store.event(rid, "CERTIFICATE_ISSUED", {
                "version": version, "merkle_root": root[:16],
                "sealed_count": sealed})
            if self.store.get_request(rid)["status"] != "CONFIRMED":
                self.store.conn.execute(
                    "UPDATE requests SET status='CONFIRMED' WHERE id=?", (rid,))
                self.store.event(rid, "REQUEST_CONFIRMED", {
                    "note": "删除已对外确认；全局墓碑生效，迟到副本将被拦截"})
            self.store.commit()
        # 墓碑推送到各服务（失败下轮继续推；服务自身擦除时也已写本地墓碑）
        self._push_tombstones(rid, req["subject_id"], token, version)

    def _push_tombstones(self, rid: str, subject_id: str, token: str, version: int):
        with self.store.lock:
            pending = self.store.conn.execute(
                "SELECT service FROM tombstones WHERE request_id=? AND pushed=0"
                " AND service!='*'", (rid,)).fetchall()
        for row in pending:
            svc_name = row["service"]
            svc = self.registry.get(svc_name)
            if not svc:
                continue
            try:
                http_client.post(f"{svc['base_url']}/internal/tombstones", {
                    "request_id": rid, "subject_id": subject_id,
                    "token": token, "version": version,
                }, svc["token"])
                with self.store.lock:
                    self.store.conn.execute(
                        "UPDATE tombstones SET pushed=1 WHERE request_id=?"
                        " AND service=?", (rid, svc_name))
                    self.store.commit()
            except http_client.ServiceError:
                pass  # 反熵重试：墓碑账本保留 pushed=0

    # -- 回报入口（回调/轮询统一走这里） -----------------------------------
    def ingest_report(self, payload: dict) -> dict:
        rid = payload["request_id"]
        service = payload["service"]
        record_id = payload.get("record_id")
        command_id = payload.get("command_id")
        reported = payload.get("status")
        ts = now_ms()
        req = self.store.get_request(rid)
        if not req:
            return self._record_report(rid, service, record_id, command_id, payload,
                                       False, "unknown request")
        iid = f"{rid}:{service}:{record_id}" if record_id else None
        item = self.store.get_item(iid) if iid else None
        if not item:
            return self._record_report(rid, service, record_id, command_id, payload,
                                       False, "unknown item")
        # 乱序/伪造命令：不属于该计划项当前阶段
        valid_cmds = {item["command_id_restrict"], item["command_id_purge"]}
        if item["active_command_id"]:
            valid_cmds.add(item["active_command_id"])
        valid_cmds.discard(None)
        is_migration_cmd = bool(command_id) and str(command_id).startswith(
            ("cmd_seal_", "cmd_release_"))
        if command_id and command_id not in valid_cmds \
                and not str(command_id).startswith("cmd_comp_") \
                and not is_migration_cmd:
            return self._record_report(rid, service, record_id, command_id, payload,
                                       False, "stale/unknown command_id")
        # 乐观并发（修订围栏）：竞争回调不得把同一条目推进到两个修订之下。
        # 命令携带的 policy_revision 与条目当前绑定不一致时一律拒绝（不改状态）。
        cmd_revision = payload.get("policy_revision")
        if cmd_revision is not None and int(cmd_revision) != \
                int(item.get("policy_revision") or 0):
            return self._record_report(rid, service, record_id, command_id, payload,
                                       False,
                                       f"revision fence: item bound to"
                                       f" rev {item.get('policy_revision')},"
                                       f" callback rev {cmd_revision}")
        # 阶段-状态必须匹配：RESTRICT 阶段命令只能报 RESTRICTED/SEALED/FAILED，
        # PURGE 阶段命令只能报 PURGED/FAILED。用 restrict 命令报 PURGED 属于越级。
        phase_status = {
            item["command_id_restrict"]: {"RESTRICTED", "SEALED", "FAILED"},
            item["command_id_purge"]: {"PURGED", "FAILED"},
        }.get(command_id)
        if str(command_id).startswith("cmd_seal_"):
            phase_status = {"SEALED", "PURGED", "FAILED"}
        elif str(command_id).startswith("cmd_release_"):
            phase_status = {"RESTRICTED", "SEALED", "PURGED", "FAILED"}
        if phase_status and reported not in phase_status:
            return self._record_report(rid, service, record_id, command_id, payload,
                                       False,
                                               f"phase/status mismatch: {command_id[:12]}"
                                               f" cannot report {reported}")
        # 关键护栏：迁移封存后迟到的旧 PURGE 回调不得把 SEALED 推进为 PURGED。
        if item["status"] == "SEALED" and reported == "PURGED":
            return self._record_report(rid, service, record_id, command_id, payload,
                                       False,
                                       "rejected: SEALED item cannot be purged"
                                       " (withdraw/rollback first)")
        # 迁移命令同步执行；其迟到的 FAILED 回调不得把已封存项降为 FAILED
        if item["status"] == "SEALED" and reported == "FAILED" \
                and is_migration_cmd:
            return self._record_report(rid, service, record_id, command_id, payload,
                                       False,
                                       "rejected: late migration FAILED cannot"
                                       " rewrite SEALED history")
        # 终态后重复回报：幂等接受（不改变状态），明确标注 duplicate
        if item["status"] in TERMINAL and reported == item["status"]:
            self._record_report(rid, service, record_id, command_id, payload,
                                True, "duplicate replay (idempotent ack)")
            return {"accepted": True, "duplicate": True, "applied": False}
        # 倒序回报：例如已 PURGING/PURGED 才收到 RESTRICT 成功
        if reported in STATUS_RANK and STATUS_RANK.get(reported, 99) < \
                STATUS_RANK.get(item["status"], 0):
            return self._record_report(rid, service, record_id, command_id, payload,
                                       False, f"out-of-order: {item['status']}<-{reported}")
        # 应用前进
        self._apply_service_result(item, command_id or item["active_command_id"],
                                   payload, via="CALLBACK")
        self._record_report(rid, service, record_id, command_id, payload,
                            True, f"applied -> {reported}")
        return {"accepted": True, "duplicate": False, "applied": True}

    def _apply_service_result(self, item: dict, command_id: str | None, body: dict,
                              via: str = "SYNC"):
        ts = now_ms()
        status = body["status"]
        iid = item["id"]
        rid = item["request_id"]
        with self.store.lock:
            cur = self.store.get_item(iid)
            if not cur:
                return
            # 重复：同状态直接幂等
            if cur["status"] == status:
                self.store.event(rid, "REPORT_DUPLICATE", {
                    "service": item["service"], "record_id": item["record_id"],
                    "status": status, "via": via})
                return
            # 乱序：不倒退
            if status in STATUS_RANK and STATUS_RANK[status] < STATUS_RANK[cur["status"]]:
                self.store.event(rid, "REPORT_OUT_OF_ORDER", {
                    "service": item["service"], "record_id": item["record_id"],
                    "current": cur["status"], "received": status, "via": via})
                return
            fields = ["status=?", "result_hash=?", "evidence=?", "last_error=NULL",
                      "overdue=0", "next_attempt_at=0", "updated_at=?",
                      "report_seq=report_seq+1"]
            vals: list = [status, body.get("result_hash"),
                          json.dumps(body, ensure_ascii=False, sort_keys=True), ts]
            if status == "SEALED":
                fields += ["hold_code=?", "hold_reason=?", "hold_releases_at=?",
                           "hold_origin=?"]
                vals += [body.get("hold_code"), body.get("hold_reason"),
                         body.get("hold_releases_at"),
                         body.get("hold_origin", "POLICY")]
            else:
                # RESTRICTED（保留解除/迁移撤回）：清空封存字段，回到可擦除冻结态
                fields += ["hold_code=NULL", "hold_reason=NULL",
                           "hold_releases_at=NULL", "hold_origin=NULL"]
            if status == "FAILED":
                fields += ["fatal=1"]
            vals.append(iid)
            self.store.conn.execute(
                f"UPDATE items SET {', '.join(fields)} WHERE id=?", vals)
            self.store.event(rid, "ITEM_ADVANCE", {
                "service": item["service"], "record_id": item["record_id"],
                "from": cur["status"], "to": status, "via": via,
                "hold_code": body.get("hold_code"),
                "result_hash": (body.get("result_hash") or "")[:16]})
            self.store.commit()

    def _mark_dispatched(self, item: dict, command_id: str, phase: str, body: dict):
        ts = now_ms()
        with self.store.lock:
            self.store.conn.execute(
                "UPDATE items SET status='DISPATCHED', active_command_id=?,"
                " attempts=attempts+1, last_error=NULL, updated_at=? WHERE id=?",
                (command_id, ts, item["id"]))
            self.store.event(item["request_id"], "COMMAND_DISPATCHED", {
                "service": item["service"], "record_id": item["record_id"],
                "phase": phase, "command_id": command_id,
                "async_status": body.get("status")})
            self.store.commit()

    def _handle_call_error(self, item: dict, command_id: str, phase: str,
                           e: http_client.ServiceError):
        ts = now_ms()
        fatal = e.status in (400, 404, 409)
        with self.store.lock:
            cur = self.store.get_item(item["id"])
            # 封存项的 PURGE 被服务以"保留仍有效"拒绝：保持 SEALED 终态口径，
            # 绝不标记 FAILED；保留解除（迁移 RELEASE / 到期）后闸门会重开。
            if phase == "purge" and cur and cur["status"] == "SEALED":
                self.store.conn.execute(
                    "UPDATE items SET last_error=?, next_attempt_at=0,"
                    " updated_at=? WHERE id=?",
                    (f"purge blocked while sealed: {e.body}", ts, item["id"]))
                self.store.event(item["request_id"], "PURGE_BLOCKED_BY_HOLD", {
                    "service": item["service"], "record_id": item["record_id"],
                    "error": str(e.body)[:200]})
                self.store.commit()
                return
            if fatal:
                self.store.conn.execute(
                    "UPDATE items SET status='FAILED', fatal=1, last_error=?,"
                    " active_command_id=?, updated_at=? WHERE id=?",
                    (f"{phase} fatal: {e.body}", command_id, ts, item["id"]))
                self.store.event(item["request_id"], "ITEM_FAILED", {
                    "service": item["service"], "record_id": item["record_id"],
                    "phase": phase, "error": str(e.body)})
            else:
                nxt = ts + backoff_ms(item["attempts"] + 1)
                self.store.conn.execute(
                    "UPDATE items SET status='ERROR', active_command_id=?,"
                    " attempts=attempts+1, last_error=?, next_attempt_at=?,"
                    " updated_at=? WHERE id=?",
                    (command_id, f"{phase} transient: {e.body}", nxt, ts, item["id"]))
                self.store.event(item["request_id"], "COMMAND_RETRY_SCHEDULED", {
                    "service": item["service"], "phase": phase,
                    "attempt": item["attempts"] + 1, "retry_at": iso(nxt),
                    "error": str(e.body)[:200]})
            self.store.commit()

    def _record_report(self, rid: str, service: str, record_id: str | None,
                       command_id: str | None, payload: dict, accepted: bool,
                       reason: str) -> dict:
        with self.store.lock:
            self.store.conn.execute(
                "INSERT INTO reports(request_id, item_id, service, command_id, attempt,"
                " reported_status, result_hash, hold_code, accepted, reason, received_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (rid, f"{rid}:{service}:{record_id}", service, command_id,
                 payload.get("attempt"), payload.get("status"),
                 payload.get("result_hash"), payload.get("hold_code"),
                 1 if accepted else 0, reason, now_ms()))
            if not accepted:
                self.store.event(rid, "REPORT_REJECTED", {
                    "service": service, "record_id": record_id,
                    "command_id": command_id, "reason": reason})
            self.store.commit()
        return {"accepted": accepted, "reason": reason}

    def _set_request_status(self, rid: str, status: str):
        with self.store.lock:
            self.store.conn.execute(
                "UPDATE requests SET status=?, updated_at=? WHERE id=?",
                (status, now_ms(), rid))
            self.store.commit()

    # =====================================================================
    # 合规策略控制平面：不可变修订绑定 / 干跑 / 幂等可恢复迁移 / 回滚
    # =====================================================================
    def _rules_for_revision(self, revision: int, rid: str | None = None):
        """取得某修订号对应的不可变规则快照（缓存优先，缺失则问策略组件）。"""
        if revision in self._rev_rules:
            return self._rev_rules[revision]
        binding = self.store.get_binding(rid) if rid else None
        if binding and int(binding["revision"]) == int(revision):
            self._rev_rules[revision] = binding["rules"]
            return binding["rules"]
        try:
            rev = policy_client.get_revision(int(revision))
            self._rev_rules[revision] = rev.get("rules", [])
            return rev.get("rules", [])
        except policy_client.PolicyError:
            # 策略组件暂不可达：不编造规则，退化为空（既有 LOCAL 保留仍然生效）
            return []

    @staticmethod
    def _migration_id(revision: int, mode: str, subjects: list[str] | None,
                      expected_version: int | None = None) -> str:
        if subjects is None:
            scope = "ALL"
        else:
            scope = ",".join(sorted(set(subjects)))
        # expected_version 进入幂等键：冲突请求（CONFLICT 行）作为审计保留后，
        # 运营以正确期望版本重试会得到一次全新的评估，而不会被旧冲突行遮蔽。
        exp = "na" if expected_version is None else str(expected_version)
        return f"mig_r{revision}_{mode}_{scope or 'EMPTY'}_exp{exp}"

    def _migration_snapshot(self, revision: int) -> dict:
        rev = policy_client.get_revision(revision)
        if not rev or rev.get("state") not in ("CANARIED", "ACTIVE"):
            raise PolicyApplyError(
                f"revision {revision} is not CANARIED/ACTIVE",
                {"revision": revision, "state": (rev or {}).get("state")})
        return rev

    def _plan_item_action(self, item: dict, rules: list[dict], target: int) -> str:
        """计算单个计划项在目标修订下的动作（纯函数，干跑与迁移共用）。"""
        status = item["status"]
        if status == "CANCELLED":
            return "SKIP"
        # PURGED / FAILED：法律终态，任何迁移不得改写；ABORTED 在请求层排除。
        if status in ("PURGED", "FAILED"):
            return "SKIP"
        # 外部认证封存：任何策略迁移都不得解除或改版本
        if status == "SEALED" and item.get("hold_origin") == "EXTERNAL":
            return "SKIP"
        if status == "PURGING":
            return "WAIT"
        seal = seal_rule_for(rules, service=item["service"],
                             subject_id=item["subject_id"],
                             record_id=item["record_id"])
        if status == "SEALED":
            # 本地固定保留：等待其自身到期续跑，不被策略迁移改写
            if item.get("hold_origin") == "LOCAL":
                return "SKIP"
            # 策略封存：新修订仍要求封存 -> 保持封存并换绑；否则撤回 -> 解封续跑
            return "SEAL" if seal else "RELEASE"
        # RESTRICTED / PENDING / DISPATCHED / ERROR
        if seal:
            return "SEAL"
        return "REBIND"

    def policy_dry_run(self, revision: int, subjects: list[str] | None) -> dict:
        """干跑：报告候选修订将对哪些未完成条目产生变更（不落库、不发命令）。"""
        rev = self._migration_snapshot(revision)
        rules = rev["rules"]
        changes, skipped, waiting = [], [], []
        with self.store.lock:
            rows = self.store.conn.execute(
                "SELECT * FROM requests WHERE status IN ('RESOLVING','IN_PROGRESS','CONFIRMED')"
            ).fetchall()
            for r in rows:
                req = dict(r)
                if subjects is not None and req["subject_id"] not in subjects:
                    continue
                if int(req["policy_revision"]) == revision:
                    continue
                for item in self.store.list_items(req["id"]):
                    if item["record_id"] is None:
                        continue  # 身份解析前的占位项：不属于迁移对象
                    if item["status"] == "CANCELLED":
                        continue
                    action = self._plan_item_action(item, rules, revision)
                    entry = {
                        "request_id": req["id"],
                        "subject_id": req["subject_id"],
                        "service": item["service"],
                        "record_id": item["record_id"],
                        "from_status": item["status"],
                        "bound_revision": item["policy_revision"],
                        "action": action,
                    }
                    if action == "SKIP":
                        skipped.append({**entry,
                                        "reason": self._skip_reason(item)})
                    elif action == "WAIT":
                        waiting.append(entry)
                    else:
                        changes.append(entry)
        return {"revision": revision, "state": rev["state"],
                "content_hash": rev["content_hash"],
                "would_change": len(changes),
                "changes": changes, "waiting": waiting, "skipped": skipped}

    @staticmethod
    def _skip_reason(item: dict) -> str:
        if item["status"] in ("PURGED", "FAILED"):
            return "legal terminal state is immutable"
        if item["status"] == "SEALED" and item.get("hold_origin") == "EXTERNAL":
            return "externally certified history cannot be rewritten"
        if item["status"] == "SEALED" and item.get("hold_origin") == "LOCAL":
            return "local fixed-term hold; resumes on its own release"
        return "no change"

    def apply_policy_revision(self, revision: int, mode: str,
                              subjects: list[str] | None,
                              expected_version: int | None,
                              from_revision: int | None = None) -> dict:
        """登记并（由引擎循环）执行一次策略迁移。

        幂等：同一 (revision, mode, subjects) 重放返回既有登记，不产生额外
        事件/命令/修订号跳动。冲突时所有条目保持原样（仅留一条冲突诊断记录）。

        from_revision 仅 rollback 使用：只把当前绑定在"被撤回修订"上的条目
        迁回恢复修订，其余条目（更早的历史修订）一概不动。
        """
        mid = self._migration_id(revision, mode, subjects, expected_version)
        with self.store.lock:
            existing = self.store.get_migration(mid)
            if existing:
                return {"idempotent": True, **self.store.migration_view(mid)}
            try:
                rev = self._migration_snapshot(revision)
                active = policy_client.get_active()
                active_n = int(active["revision"])
                # 乐观并发：期望版本不符 -> 诊断性 409，原子地不触碰任何条目
                conflict = None
                if expected_version is not None and \
                        int(expected_version) != active_n:
                    conflict = (f"expected active policy version {expected_version}"
                                f" but policy component reports {active_n}")
                elif mode == "canary":
                    cohort = set(rev.get("canary_subjects", []))
                    if rev["state"] != "CANARIED":
                        conflict = (f"revision {revision} is {rev['state']},"
                                    " cannot canary-apply")
                    elif subjects and not set(subjects) <= cohort:
                        conflict = ("canary subjects outside registered cohort:"
                                    f" {sorted(set(subjects or []) - cohort)}")
                if conflict:
                    ts = now_ms()
                    self.store.conn.execute(
                        "INSERT INTO policy_migrations(id, revision, mode,"
                        " expected_version, state, total, done, last_item_id,"
                        " detail, created_at, updated_at)"
                        " VALUES(?,?,?,?, 'CONFLICT', 0, 0, NULL, ?, ?, ?)",
                        (mid, revision, mode, expected_version,
                         json.dumps({"error": conflict, "active": active_n}),
                         ts, ts))
                    self.store.migration_event(mid, "MIGRATION_CONFLICT", {
                        "error": conflict, "expected": expected_version,
                        "actual": active_n})
                    self.store.commit()
                    raise PolicyApplyError(conflict, {
                        "migration_id": mid, "expected": expected_version,
                        "actual": active_n, "revision": revision})
            except policy_client.PolicyError as e:
                raise PolicyApplyError(f"policy component error: {e.body}",
                                       {"revision": revision})

            # 预检 + 计划（同一事务/锁内，冲突后此处绝不执行 => 全部条目不动）
            plan = self._build_plan(revision, mode, subjects, rev["rules"],
                                    from_revision)
            ts = now_ms()
            self.store.conn.execute(
                "INSERT INTO policy_migrations(id, revision, mode, expected_version,"
                " state, total, done, last_item_id, detail, created_at, updated_at)"
                " VALUES(?,?,?,?,'IN_PROGRESS',?,0,NULL,?, ?, ?)",
                (mid, revision, mode, expected_version, len(plan),
                 json.dumps({"crash_fired": 0, "from_revision": from_revision,
                             "requests": sorted({p[0] for p in plan})}),
                 ts, ts))
            for rid0, item, action in plan:
                self.store.conn.execute(
                    "INSERT INTO policy_migration_items(migration_id, item_id,"
                    " request_id, service, record_id, action, state, detail,"
                    " updated_at) VALUES(?,?,?,?,?,?,'PENDING',NULL,?)",
                    (mid, item["id"], rid0, item["service"],
                     item["record_id"], action, ts))
            self.store.migration_event(mid, "MIGRATION_STARTED", {
                "revision": revision, "mode": mode,
                "subjects": subjects, "planned": len(plan),
                "expected_version": expected_version,
                "from_revision": from_revision})
            self.store.commit()
        # 缓存目标修订快照，供恢复后 RESTRICT 重发使用
        self._rev_rules[revision] = rev["rules"]
        # 登记后立即尝试执行（也可由下一 tick 恢复执行；崩溃后纯靠 tick 恢复）
        self._run_migration(mid)
        return self.store.migration_view(mid)

    def _build_plan(self, target: int, mode: str,
                    subjects: list[str] | None, rules: list[dict],
                    from_revision: int | None = None) -> list[tuple]:
        plan: list[tuple] = []
        rows = self.store.conn.execute(
            "SELECT * FROM requests WHERE status IN ('RESOLVING','IN_PROGRESS','CONFIRMED')"
        ).fetchall()
        for r in rows:
            req = dict(r)
            in_scope = subjects is None or req["subject_id"] in subjects
            if not in_scope:
                continue
            for item in self.store.list_items(req["id"]):
                if item["record_id"] is None:
                    continue  # 身份解析前的占位项不迁移
                item_rev = int(item["policy_revision"])
                # 仅迁移条目当前绑定的修订：
                #  canary/activate：低于目标修订的在途条目；
                #  rollback：恰好绑定在被撤回修订上的条目（部分金丝雀也覆盖）。
                if mode == "rollback":
                    if item_rev != int(from_revision):
                        continue
                elif item_rev >= target:
                    continue
                action = self._plan_item_action(item, rules, target)
                if action == "SKIP":
                    continue
                plan.append((req["id"], item, action))
        plan.sort(key=lambda p: p[1]["id"])
        return plan

    def rollback_policy(self, target: int | None,
                        expected_version: int | None) -> dict:
        """回滚策略组件修订，并把受影响在途工作流迁移回恢复的修订。

        ACTIVE 修订回滚 -> 恢复上一 SUPERSEDED 修订；
        仅 CANARIED 的修订撤回 -> 金丝雀队列迁回当前 ACTIVE 修订。
        """
        result = policy_client.rollback(target, expected_version)
        rolled_back = int(result["rolled_back"])
        restored = result.get("restored")
        subjects = result.get("canary_subjects")
        if restored is None:
            # 金丝雀撤回：目标修订 = 当前 ACTIVE
            active = policy_client.get_active()
            restored = int(active["revision"])
            scope = subjects
        else:
            # 被回滚的是 ACTIVE -> 影响全部在途工作流
            scope = None
        view = self.apply_policy_revision(
            int(restored), "rollback", scope, expected_version,
            from_revision=rolled_back)
        view["policy_rollback"] = result
        return view

    # -- 迁移执行（幂等 + 持久检查点恢复 + 乐观并发 CAS） -------------------
    def _process_migrations(self):
        with self.store.lock:
            rows = self.store.conn.execute(
                "SELECT id FROM policy_migrations WHERE state='IN_PROGRESS'"
            ).fetchall()
            ids = [r["id"] for r in rows]
        for mid in ids:
            try:
                self._run_migration(mid)
            except Exception as e:
                with self.store.lock:
                    self.store.migration_event(mid, "MIGRATION_TICK_ERROR",
                                               {"error": repr(e)})
                    self.store.commit()

    def _run_migration(self, mid: str):
        with self.store.lock:
            mig = self.store.get_migration(mid)
            if not mig or mig["state"] != "IN_PROGRESS":
                return
            target = int(mig["revision"])
            try:
                rev = policy_client.get_revision(target)
                rules = rev["rules"]
                self._rev_rules[target] = rules
            except policy_client.PolicyError as e:
                if target in self._rev_rules:
                    rules = self._rev_rules[target]
                else:
                    self.store.migration_event(mid, "MIGRATION_POLICY_UNAVAILABLE",
                                               {"error": str(e.body)})
                    self.store.commit()
                    return
            rows = self.store.list_migration_items(mid)
            checkpoint = mig["last_item_id"]
            applied_this_run = 0
            for mi in rows:
                # 从持久检查点之后恢复：已 DONE/SKIPPED 的行重放为纯空操作
                if mi["state"] in ("DONE", "SKIPPED"):
                    continue
                item = self.store.get_item(mi["item_id"])
                if not item:
                    self._finish_item_row(mid, mi, "SKIPPED",
                                          {"reason": "item gone"})
                    continue
                # 动态状态重算（覆盖 WAIT：PURGING 可能已到终态或回到 RESTRICTED）
                action = self._plan_item_action(item, rules, target)
                if action == "SKIP":
                    self._finish_item_row(mid, mi, "SKIPPED",
                                          {"reason": self._skip_reason(item),
                                           "from": item["status"]})
                    self._advance_checkpoint(mid, mi["item_id"])
                    continue
                if action == "WAIT":
                    continue  # 等擦除中条目自然到终态，下轮再评估
                try:
                    self._execute_item_migration(mid, mi, item, action, target,
                                                 rules)
                except MigrationTransient as e:
                    # 瞬态失败：不推进检查点，下轮以同一幂等命令重试
                    self.store.migration_event(mid, "MIGRATION_ITEM_RETRY", {
                        "item_id": item["id"], "action": action,
                        "error": str(e)})
                    self.store.commit()
                    return
                self._advance_checkpoint(mid, mi["item_id"])
                applied_this_run += 1
                # 崩溃注入：检查点已落盘后退出，重启必须从检查点续跑。
                # 阈值仅存于进程内存（非持久）：重启进程 _crash_after=0，
                # 会凭持久检查点完成剩余项而不会再次崩溃。
                if self._crash_after and applied_this_run >= self._crash_after:
                    self.store.migration_event(mid, "MIGRATION_CRASH_INJECTED",
                                               {"checkpoint": mi["item_id"]})
                    self.store.commit()
                    print(f"[engine] migration crash injection after checkpoint"
                          f" {mi['item_id']}; exiting", flush=True)
                    os._exit(1)
            pending = self.store.conn.execute(
                "SELECT COUNT(*) c FROM policy_migration_items"
                " WHERE migration_id=? AND state='PENDING'", (mid,)).fetchone()
            if pending["c"]:
                self.store.commit()
                return
            self._complete_migration(mid, target, rules)

    def _execute_item_migration(self, mid: str, mi: dict, item: dict,
                                action: str, target: int, rules: list[dict]):
        rid0 = item["request_id"]
        svc = self.registry.get(item["service"])
        ts = now_ms()
        ver = int(item["policy_version"])
        if action == "REBIND":
            fields = ["policy_revision=?", "policy_version=policy_version+1",
                      "updated_at=?"]
            vals = [target, ts]
            if item["status"] in ("DISPATCHED", "ERROR"):
                # 作废旧阶段命令并重置计划：下轮 RESTRICT 用新修订快照重新下发，
                # 旧命令的迟到回调会在修订围栏处被拒绝
                fields += ["status='PENDING'", "active_command_id=NULL",
                           "next_attempt_at=0",
                           "command_id_restrict=?",
                           "attempts=attempts"]
                vals += [f"cmd_{uuid.uuid4().hex[:12]}"]
            cur = self.store.conn.execute(
                f"UPDATE items SET {', '.join(fields)} WHERE id=?"
                " AND policy_version=?", (*vals, item["id"], ver))
            if cur.rowcount == 0:
                raise MigrationTransient(
                    f"cas conflict on {item['id']}: expected version {ver}")
            self.store.event(rid0, "POLICY_REBOUND", {
                "service": item["service"], "record_id": item["record_id"],
                "to_revision": target})
            self.store.migration_event(mid, "MIGRATION_ITEM_APPLIED", {
                "item_id": item["id"], "action": "REBIND",
                "to_revision": target, "from_status": item["status"]})
            self._finish_item_row(mid, mi, "DONE", {"to_revision": target})
            self.store.commit()
            return

        if action == "SEAL":
            command_id = f"cmd_seal_{uuid.uuid4().hex[:12]}"
            payload = {
                "command_id": command_id, "request_id": rid0,
                "subject_id": item["subject_id"], "record_id": item["record_id"],
                "op": "SEAL", "policy_revision": target, "rules": rules,
                "callback_url": f"{self.callback_base}/internal/reports"}
            try:
                _, body = http_client.post(
                    f"{svc['base_url']}/internal/commands", payload,
                    svc["token"])
            except http_client.ServiceError as e:
                if e.status in (503, 0, 500, 502, 504):
                    raise MigrationTransient(str(e.body))
                raise
            out_status = body.get("status")
            if out_status in ("PURGED", "FAILED"):
                # 迟到擦除已在服务侧落地：迁移收敛跳过，绝不重建数据；
                # 服务拒绝封存（如记录状态冲突）：保留原样，记为受保护跳过
                self.store.migration_event(mid, "MIGRATION_ITEM_LOST_RACE"
                    if out_status == "PURGED" else "MIGRATION_ITEM_PRESERVED", {
                    "item_id": item["id"], "outcome": body.get("status"),
                    "error": body.get("error"),
                    "note": "migration seal not applied; item preserved"})
                self._finish_item_row(mid, mi, "SKIPPED",
                                      {"reason": body.get("error")
                                       or "already PURGED",
                                       "outcome": out_status})
                self.store.commit()
                return
            self._cas_advance(item, ver, "SEALED", body, command_id, target,
                              hold_origin=body.get("hold_origin", "POLICY"))
            self.store.event(rid0, "POLICY_SEALED", {
                "service": item["service"], "record_id": item["record_id"],
                "to_revision": target, "hold_code": body.get("hold_code"),
                "note": "新匹配 RESTRICTED 项在任何 PURGE 前完成封存"})
            self.store.migration_event(mid, "MIGRATION_ITEM_APPLIED", {
                "item_id": item["id"], "action": "SEAL",
                "to_revision": target, "command_id": command_id,
                "from_status": item["status"]})
            self._finish_item_row(mid, mi, "DONE", {"to_revision": target,
                                                    "command_id": command_id})
            self.store.commit()
            return

        if action == "RELEASE":
            command_id = f"cmd_release_{uuid.uuid4().hex[:12]}"
            payload = {
                "command_id": command_id, "request_id": rid0,
                "subject_id": item["subject_id"], "record_id": item["record_id"],
                "op": "RELEASE_HOLD", "policy_revision": target,
                "rules": rules,
                "callback_url": f"{self.callback_base}/internal/reports"}
            try:
                _, body = http_client.post(
                    f"{svc['base_url']}/internal/commands", payload,
                    svc["token"])
            except http_client.ServiceError as e:
                if e.status in (503, 0, 500, 502, 504):
                    raise MigrationTransient(str(e.body))
                raise
            out_status = body.get("status")
            if out_status == "PURGED":
                self.store.migration_event(mid, "MIGRATION_ITEM_LOST_RACE", {
                    "item_id": item["id"], "outcome": "already PURGED"})
                self._finish_item_row(mid, mi, "SKIPPED",
                                      {"reason": "already PURGED"})
                self.store.commit()
                return
            if out_status == "SEALED":
                # 服务侧保留并非 POLICY 来源（外部认证/本地）：不得解除，保持封存
                self.store.migration_event(mid, "MIGRATION_ITEM_PRESERVED", {
                    "item_id": item["id"], "hold_origin": body.get("hold_origin"),
                    "note": "non-policy hold preserved; item not rewritten"})
                self._finish_item_row(mid, mi, "SKIPPED", {
                    "reason": f"hold origin {body.get('hold_origin')} preserved"})
                self.store.commit()
                return
            # RESTRICTED：策略撤回，同一工作流解封续跑（无需重新申请）
            self._cas_advance(item, ver, "RESTRICTED", body, command_id, target)
            self.store.event(rid0, "HOLD_WITHDRAWN", {
                "service": item["service"], "record_id": item["record_id"],
                "released_hold": item.get("hold_code"),
                "to_revision": target,
                "note": "规则撤回：同一工作流自动续跑"})
            self.store.migration_event(mid, "MIGRATION_ITEM_APPLIED", {
                "item_id": item["id"], "action": "RELEASE",
                "to_revision": target, "command_id": command_id,
                "from_status": "SEALED"})
            self._finish_item_row(mid, mi, "DONE", {"to_revision": target,
                                                    "command_id": command_id})
            self.store.commit()
            return

    def _cas_advance(self, item: dict, expected_ver: int, status: str,
                     body: dict, command_id: str, target_rev: int,
                     hold_origin: str | None = None):
        """乐观并发推进：版本不匹配时抛错，调用方不提交任何变更。"""
        ts = now_ms()
        sets = ["status=?", "result_hash=?", "evidence=?",
                "policy_revision=?", "policy_version=policy_version+1",
                "active_command_id=?", "updated_at=?"]
        vals = [status, body.get("result_hash"),
                json.dumps(body, ensure_ascii=False, sort_keys=True),
                target_rev, command_id, ts]
        if status == "SEALED":
            sets += ["hold_code=?", "hold_reason=?", "hold_releases_at=?",
                     "hold_origin=?"]
            vals += [body.get("hold_code"), body.get("hold_reason"),
                     body.get("hold_releases_at"),
                     hold_origin or body.get("hold_origin", "POLICY")]
        else:
            sets += ["hold_code=NULL", "hold_reason=NULL",
                     "hold_releases_at=NULL", "hold_origin=NULL",
                     "overdue=0", "next_attempt_at=0",
                     # 撤回解封后续跑原 PURGE：作废旧 purge 命令，
                     # 由 PURGE 闸门用新 command_id 重新开放（回调按命令幂等）
                     "command_id_purge=NULL", "purge_due_ms=0"]
        cur = self.store.conn.execute(
            f"UPDATE items SET {', '.join(sets)} WHERE id=?"
            " AND policy_version=?", (*vals, item["id"], expected_ver))
        if cur.rowcount == 0:
            raise MigrationTransient(
                f"cas conflict on {item['id']}: expected version {expected_ver}")

    def _finish_item_row(self, mid: str, mi: dict, state: str, detail: dict):
        self.store.conn.execute(
            "UPDATE policy_migration_items SET state=?, detail=?, updated_at=?"
            " WHERE migration_id=? AND item_id=?",
            (state, json.dumps(detail, ensure_ascii=False), now_ms(),
             mid, mi["item_id"]))

    def _advance_checkpoint(self, mid: str, item_id: str):
        self.store.conn.execute(
            "UPDATE policy_migrations SET last_item_id=?,"
            " done=(SELECT COUNT(*) FROM policy_migration_items"
            " WHERE migration_id=? AND state IN ('DONE','SKIPPED')),"
            " updated_at=? WHERE id=?",
            (item_id, mid, now_ms(), mid))

    def _complete_migration(self, mid: str, target: int, rules: list[dict]):
        mig = self.store.get_migration(mid)
        affected = sorted({mi["request_id"]
                           for mi in self.store.list_migration_items(mid)
                           if mi["state"] in ("DONE", "SKIPPED")})
        for rid0 in affected:
            req = self.store.get_request(rid0)
            if not req:
                continue
            items = self.store.list_items(rid0)
            revs = [int(i["policy_revision"]) for i in items
                    if i["status"] != "CANCELLED"]
            # 工作流级修订 = 全部存活条目达到的最高公共修订；
            # PURGED/外部封存条目保留旧修订值（历史不可改写），故取最小值。
            req_rev = min(revs) if revs else target
            self.store.conn.execute(
                "UPDATE requests SET policy_revision=?, updated_at=? WHERE id=?",
                (req_rev, now_ms(), rid0))
            binding = self.store.get_binding(rid0)
            if binding:
                # 绑定快照推进到目标修订；旧快照仍由证书/事件中的叶子证据保留
                self.store.put_binding(
                    rid0, req["subject_id"], req_rev,
                    rules if req_rev == target else binding["rules"],
                    None, mig["mode"] == "canary")
        self.store.conn.execute(
            "UPDATE policy_migrations SET state='COMPLETED', updated_at=? WHERE id=?",
            (now_ms(), mid))
        self.store.migration_event(mid, "MIGRATION_COMPLETED", {
            "revision": target, "requests": affected})
        self.store.commit()


class PolicyApplyError(Exception):
    def __init__(self, message: str, detail: dict):
        self.detail = detail
        super().__init__(message)


class MigrationTransient(Exception):
    pass
