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

from . import http_client
from .policy_manager import PolicyConflict, PolicyManager
from .store import SEALED_LIKE, STATUS_RANK, TERMINAL, Store
from common import (
    evidence_leaf,
    iso,
    merkle_root,
    now_ms,
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
POLICY_URL = os.environ.get("POLICY_URL", "http://127.0.0.1:8090")

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
        self.thread: threading.Thread | None = None
        # 版本化合规策略控制面
        self.policy = PolicyManager(store, self.registry, POLICY_URL,
                                    INTERNAL_TOKEN, callback_base)
        self._policy_sync_at = 0.0
        # 确定性故障钩子（仅 admin 注入；生产环境管理面鉴权关闭）
        self.purge_paused = False
        self.crash_after_tick = False
        self._tick_count = 0

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
        # 每个工作流在创建瞬间绑定一个**不可变策略修订**：
        # 金丝雀主体命中 CANARY 修订，对照主体绑定当前 ACTIVE。
        try:
            self.policy.sync_from_control_plane()
        except Exception:
            pass
        bound = self.policy.effective_revision(subject_id)
        bound_rev = bound["version"]
        with self.store.lock:
            self.store.conn.execute(
                "INSERT INTO requests(id, subject_id, display_name, status, deadline_ms,"
                " policy_revision, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)",
                (rid, subject_id, display_name, "RESOLVING", ts + REQUEST_TTL_MS,
                 bound_rev, ts, ts),
            )
            for svc in self.registry:
                iid = f"{rid}:{svc}:PENDING"
                self.store.conn.execute(
                    "INSERT INTO items(id, request_id, service, subject_id, status,"
                    " policy_revision, next_attempt_at, created_at, updated_at)"
                    " VALUES(?,?,?,?,?,?,?,?,?)",
                    (iid, rid, svc, subject_id, "PENDING", bound_rev, ts, ts, ts),
                )
            self.store.event(rid, "REQUEST_CREATED", {
                "subject_id": subject_id, "display_name": display_name,
                "deadline": iso(ts + REQUEST_TTL_MS),
                "services": list(self.registry),
                "policy_revision": bound_rev,
                "policy_state": bound.get("state"),
                "bound_rules": [r["id"] for r in bound.get("rules", [])],
            })
            self.store.commit()
        return self.store.get_request(rid)

    # -- 主循环 ------------------------------------------------------------
    def tick(self):
        # 1) 同步不可变策略修订（控制面失联则继续使用已缓存修订 / 基线 rev0）
        if self._tick_count % 5 == 0:
            try:
                self.policy.sync_from_control_plane()
            except Exception as e:
                print(f"[engine] policy sync error: {e!r}")
        # 2) 续跑所有 RUNNING 迁移（崩溃恢复 / 竞争裁决后继续 / 暂停钩子恢复）
        try:
            self.policy.run_due()
        except Exception as e:
            print(f"[engine] migration resume error: {e!r}")
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
        self._tick_count += 1
        if self.crash_after_tick:
            # 故障注入：模拟协调端在迁移/编排中途崩溃（不提交任何内存态）。
            print("[engine] injected crash firing; exiting process NOW")
            os._exit(77)

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
            # 合规策略强制：项已绑定修订中的规则在 PURGE 前生效
            # （保证“新匹配的 RESTRICTED 项先 SEALED，再谈 PURGE”）。
            self._enforce_policy(rid, items)
            items = self.store.list_items(rid)
            self._open_purge_gate(rid, items)
            items = self.store.list_items(rid)
            if not self.purge_paused:
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
        req = self.store.get_request(rid)
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
                        " status, policy_revision, next_attempt_at, created_at, updated_at)"
                        " VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (nid, rid, item["service"], item["subject_id"], None,
                         "CANCELLED", req["policy_revision"], 0, ts, ts))
                    self.store.event(rid, "IDENTITY_RESOLVED",
                                     {"service": item["service"], "records": []})
                else:
                    for rec in records:
                        nid = f"{rid}:{item['service']}:{rec['record_id']}"
                        self.store.conn.execute(
                            "INSERT INTO items(id, request_id, service, subject_id,"
                            " record_id, status, command_id_restrict, policy_revision,"
                            " next_attempt_at, created_at, updated_at)"
                            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                            (nid, rid, item["service"], item["subject_id"],
                             rec["record_id"], "PENDING",
                             f"cmd_{uuid.uuid4().hex[:12]}",
                             req["policy_revision"], ts, ts, ts))
                    self.store.event(rid, "IDENTITY_RESOLVED", {
                        "service": item["service"], "records": records,
                        "policy_revision": req["policy_revision"]})
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
            payload = {
                "command_id": command_id,
                "request_id": rid,
                "subject_id": item["subject_id"],
                "record_id": item["record_id"],
                "op": "RESTRICT",
                "callback_url": f"{self.callback_base}/internal/reports",
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
                if not active:
                    # 保留解除：同一计划项回到 RESTRICTED，等待 PURGE 闸门
                    self.store.conn.execute(
                        "UPDATE items SET status='RESTRICTED', hold_code=NULL,"
                        " hold_reason=NULL, hold_releases_at=NULL, updated_at=? WHERE id=?",
                        (ts, item["id"]))
                    self.store.event(rid, "HOLD_RELEASED", {
                        "service": item["service"], "record_id": item["record_id"],
                        "note": "约束解除，自动续跑原计划，无需重新申请"})
                elif releases_at and releases_at != item["hold_releases_at"]:
                    self.store.conn.execute(
                        "UPDATE items SET hold_releases_at=?, updated_at=? WHERE id=?",
                        (releases_at, ts, item["id"]))
            except http_client.ServiceError:
                pass

    # -- PURGE 闸门：所有非空计划项 RESTRICTED/SEALED 后才开放 -------------
    def _enforce_policy(self, rid: str, items: list[dict]):
        for item in items:
            # 终态 / CANCELLED / 未解析占位项不强制
            if item["status"] in TERMINAL or item["record_id"] is None:
                continue
            try:
                self.policy.enforce_on_item(item)
            except Exception as e:
                self.store.event(rid, "POLICY_ENFORCE_ERROR", {
                    "service": item["service"], "record_id": item["record_id"],
                    "error": repr(e)})

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
            # 撤回/回退 RELEASE 会清空旧 PURGE 命令：闸门重新开放时签发新命令，
            # 保证“同一工作流续跑”而不是复用已封存期的陈旧 command_id。
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
                # 证据绑定该计划项的不可变策略修订（回滚也不重写历史证书）
                "policy_revision": item.get("policy_revision", 0),
                "updated_at": item["updated_at"],
            }
            leaves.append({"item": f"{item['service']}:{item.get('record_id')}",
                           "status": item["status"],
                           "hash": evidence_leaf(leaf_body)})
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
        if command_id and command_id not in valid_cmds \
                and not str(command_id).startswith("cmd_comp_"):
            return self._record_report(rid, service, record_id, command_id, payload,
                                       False, "stale/unknown command_id")
        # 阶段-状态必须匹配：RESTRICT 阶段命令只能报 RESTRICTED/SEALED/FAILED，
        # PURGE 阶段命令只能报 PURGED/FAILED。用 restrict 命令报 PURGED 属于越级。
        phase_status = {
            item["command_id_restrict"]: {"RESTRICTED", "SEALED", "FAILED"},
            item["command_id_purge"]: {"PURGED", "FAILED"},
        }.get(command_id)
        if phase_status and reported not in phase_status:
            return self._record_report(rid, service, record_id, command_id, payload,
                                       False,
                                               f"phase/status mismatch: {command_id[:8]}"
                                               f" cannot report {reported}")
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
            # 合规保护：已依法 SEALED 的项不得被迟到的 RESTRICTED 同级回报解封。
            # 状态序中两者同级（rank 都是 2），必须显式守门，否则会丢掉封存。
            if cur["status"] == "SEALED" and status == "RESTRICTED":
                self.store.event(rid, "REPORT_REJECTED_AFTER_SEAL", {
                    "service": item["service"], "record_id": item["record_id"],
                    "current": "SEALED", "received": "RESTRICTED",
                    "rule_id": cur["sealed_rule_id"], "via": via})
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
                fields += ["hold_code=?", "hold_reason=?", "hold_releases_at=?"]
                vals += [body.get("hold_code"), body.get("hold_reason"),
                         body.get("hold_releases_at")]
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
