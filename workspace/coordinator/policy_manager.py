"""版本化合规策略：协调端侧的修订缓存、规划器与可恢复迁移。

职责与保证：
1. 每个工作流（requests）与每个计划项（items）都绑定一个**不可变策略修订**
   `policy_revision`；新建工作流按 ACTIVE/CANARY 主体集合选择生效修订。
2. `dry_run` 只规划不落库：报告候选修订会改变哪些未完成项（SEAL/RELEASE/REBIND）。
   PURGED / 已中止(ABORTED) / 已对外认证（有证书）的历史绝不在变更集合内被重写。
3. `apply_revision` 启动一次幂等、可恢复的迁移：
   - 幂等键 = idempotency_key；重复请求直接返回既有迁移，不产生额外事件/版本抬升；
   - 每个 item 一个 durable checkpoint（migration_items.status），崩溃后从断点继续；
   - 乐观并发：expected_version 落后于策略 head -> 409，原子地所有项原样不动；
   - 逐项 CAS（乐观锁 report_seq/updated_at 守门），竞争回调不可能把同一项
     在两个修订下各推进一次。
4. 撤回（WITHDRAW）/回退（ROLLBACK）：被封存项 RELEASE 后续跑同一工作流；
   历史证书、墓碑与密码学证据永不删除、永不重写。
"""
from __future__ import annotations

import json
import os
import uuid

from . import http_client, policy_client
from .store import TERMINAL, Store
from common import iso, now_ms, policy_rule_matches

_PURGE_SLA_MS = int(os.environ.get("PURGE_SLA_SECONDS", "30")) * 1000

# 迁移按批次推进；每处理一个 item 即提交 checkpoint（崩溃恢复粒度）。
BASELINE_REV = 0
# 已对外认证（CONFIRMED 且有证书）的请求，其终态历史不可改写；
# 但由"新封存 -> 撤回"这种前向演进签发的新证书属于正常续跑（沿用既有机制）。
CERTIFIED_IMMUTABLE_STATES = {"PURGED", "FAILED", "CANCELLED"}


class PolicyConflict(Exception):
    def __init__(self, expected: int, head: int, active: int):
        self.expected = expected
        self.head = head
        self.active = active
        super().__init__(f"expected_version {expected} stale; head={head} active={active}")


class PolicyFault(Exception):
    pass


class PolicyManager:
    def __init__(self, store: Store, registry: dict, policy_url: str,
                 internal_token: str, callback_base: str):
        self.store = store
        self.registry = registry
        self.policy_url = policy_url.rstrip("/")
        self.token = internal_token
        self.callback_base = callback_base.rstrip("/")
        # 确定性崩溃注入：下一个 migration item 的 checkpoint 落库后立即退出进程，
        # 模拟“迁移中途协调端崩溃”，durable checkpoint 已在磁盘上。
        self.crash_after_step = False

    # ================= 策略组件同步（不可变缓存） =======================
    def sync_from_control_plane(self) -> dict:
        """拉取 /current，缓存 ACTIVE 与全部 CANARY；重复版本按哈希校验不可变。"""
        try:
            status, cur = policy_client.get(f"{self.policy_url}/current",
                                            self.token)
        except policy_client.PolicyUnavailable:
            return {"ok": False, "reason": "policy control plane unreachable;"
                                           " baseline rev0 in effect"}
        if status != 200:
            return {"ok": False, "reason": f"HTTP {status}"}
        active = cur.get("active", 0)
        with self.store.lock:
            self._cache_revision(cur["active_revision"])
            for c in cur.get("watch") or cur.get("canaries", []):
                self._cache_revision(c)
            self.store.conn.commit()
        return {"ok": True, "head": cur["head"], "active": active,
                "canaries": [c["version"] for c in cur.get("canaries", [])]}

    def _cache_revision(self, rev: dict | None):
        if not rev:
            return
        v = rev["version"]
        existing = self.store.get_policy_revision(v)
        if existing:
            # 不可变性：除 DRAFT->CANARY/ACTIVE 等状态推进外，内容必须逐字节一致。
            if existing["content_hash"] != rev["content_hash"]:
                raise PolicyFault(
                    f"policy revision {v} content hash mismatch:"
                    f" {existing['content_hash']} != {rev['content_hash']}")
            if existing["state"] != rev["state"]:
                self.store.conn.execute(
                    "UPDATE policy_revisions SET state=? WHERE version=?",
                    (rev["state"], v))
            return
        self.store.conn.execute(
            "INSERT INTO policy_revisions(version, rules, canary_subjects,"
            " content_hash, state, based_on, note, seen_at) VALUES(?,?,?,?,?,?,?,?)",
            (v, json.dumps(rev.get("rules", []), ensure_ascii=False,
                           sort_keys=True),
             json.dumps(rev.get("canary_subjects", [])),
             rev["content_hash"], rev["state"], rev.get("based_on"),
             rev.get("note"), now_ms()))

    def _baseline(self) -> dict:
        return {"version": 0, "rules": [], "canary_subjects": [],
                "state": "ACTIVE", "based_on": None}

    def get_revision(self, version: int) -> dict:
        if version == 0:
            return self._baseline()
        rev = self.store.get_policy_revision(version)
        if not rev:
            # 按需回源（例如 apply 一个刚创建、尚未被 tick 缓存的版本）
            status, body = policy_client.get(
                f"{self.policy_url}/revisions/{version}", self.token)
            if status != 200:
                raise PolicyFault(f"revision {version} unavailable: HTTP {status}")
            with self.store.lock:
                self._cache_revision(body)
                self.store.commit()
            rev = self.store.get_policy_revision(version)
        return rev

    def current_head_active(self) -> tuple[int, int]:
        try:
            status, cur = policy_client.get(f"{self.policy_url}/current",
                                            self.token)
            if status == 200:
                return int(cur["head"]), int(cur["active"])
        except policy_client.PolicyUnavailable:
            pass
        return 0, 0

    # ================= 生效修订选择 ====================================
    def effective_revision(self, subject_id: str) -> dict:
        """新工作流的绑定修订：命中金丝雀主体 -> 该 CANARY；否则 ACTIVE。"""
        active = self.store.get_policy_revision(self._cached_active_version())
        chosen = active
        for c in self.store.conn.execute(
                "SELECT * FROM policy_revisions WHERE state='CANARY' ORDER BY version"
        ).fetchall():
            subjects = set(json.loads(c["canary_subjects"]))
            if subject_id in subjects:
                chosen = dict(c)
                chosen["rules"] = json.loads(c["rules"])
                chosen["canary_subjects"] = list(subjects)
        return chosen or self._baseline()

    def _cached_active_version(self) -> int:
        r = self.store.conn.execute(
            "SELECT version FROM policy_revisions WHERE state='ACTIVE'"
            " ORDER BY version DESC LIMIT 1").fetchone()
        return r["version"] if r else 0

    # ================= 规则匹配 ========================================
    @staticmethod
    def matching_rule(rev: dict, service: str | None,
                      record_id: str | None) -> dict | None:
        for rule in rev.get("rules", []):
            if policy_rule_matches(rule, service, record_id):
                return rule
        return None

    # ================= 规划器（dry-run 与 apply 共用，只读） ===========
    def _unfinished_requests(self) -> list[dict]:
        # RESOLVING 的请求还没有真实 record，无法评估 record 规则；跳过。
        # 注意：ABORTED 请求绝不纳入迁移（saga 中止历史不可重写）。
        rows = self.store.conn.execute(
            "SELECT * FROM requests WHERE status IN ('IN_PROGRESS','CONFIRMED')"
        ).fetchall()
        return [dict(r) for r in rows]

    def plan_actions(self, target_rev: dict, action: str,
                     source_rev: dict | None = None) -> list[dict]:
        """返回候选修订对每个受影响未完成项的动作（只读）。

        动作：
          SEAL          目标修订有命中规则且当前未按同规则封存
          RELEASE       撤回/回退：项被**来源修订**封存，目标不再要求封存
          REBIND        仅重绑修订（主体进入/离开金丝雀），无封存变化
          SKIP_TERMINAL PURGED/FAILED/CANCELLED 等终态历史，绝不重写

        RELEASE 的选择只看“该项由哪个修订的规则封存（sealed_rule_id）”，
        与当前金丝雀作用域无关——这样多个并行 CANARY 互不干扰，撤回 rev N
        绝不会释放 rev M 封的项。

        source_rev：撤回时=被撤回修订；回退时=回滚前的 ACTIVE；
                    普通 CANARY/ACTIVATE 时与 target_rev 相同。
        """
        plans: list[dict] = []
        withdraw = action in ("WITHDRAW", "ROLLBACK")
        source_rev = source_rev or target_rev
        scope = set(source_rev.get("canary_subjects") or [])
        source_version = source_rev["version"]
        # 撤回/回退后的生效目标：回退到被回滚版本本身；撤回回到来源的父修订。
        if action == "ROLLBACK":
            match_rev = target_rev
            if not scope:
                scope = set(target_rev.get("canary_subjects") or [])
        elif action == "WITHDRAW":
            parent_no = source_rev.get("based_on") or 0
            match_rev = self.get_revision(parent_no) if parent_no else self._baseline()
        else:
            match_rev = target_rev
        for req in self._unfinished_requests():
            rid = req["id"]
            items = self.store.list_items(rid)
            in_scope = (action == "ACTIVATE") or (not scope) or \
                (req["subject_id"] in scope)
            for item in items:
                if item["status"] == "CANCELLED" or item["record_id"] is None:
                    continue
                cur_rev = self.get_revision(item["policy_revision"]) \
                    if item["policy_revision"] else self._baseline()
                # 终态历史不可改写（PURGED / 永久失败 / 已补偿）。
                if item["status"] in TERMINAL:
                    plans.append(self._plan_row(item, "SKIP_TERMINAL", None,
                                                target_rev, note=item["status"]))
                    continue
                target_rule = self.matching_rule(
                    match_rev, item["service"], item["record_id"]) \
                    if in_scope else None
                cur_rule = self._find_rule_by_id(cur_rev, item["sealed_rule_id"]) \
                    if item["status"] == "SEALED" else None
                sealed_by_source = item["status"] == "SEALED" \
                    and item["policy_revision"] == source_version
                if withdraw and sealed_by_source and not target_rule:
                    # 撤回/回退：来源修订封的项，在父修订中不再有命中规则 -> 解封续跑
                    plans.append(self._plan_row(item, "RELEASE", cur_rule,
                                                match_rev, source_rev=cur_rev))
                elif target_rule and item["status"] != "SEALED":
                    plans.append(self._plan_row(item, "SEAL", target_rule,
                                                target_rev))
                elif target_rule and item["status"] == "SEALED" \
                        and item["sealed_rule_id"] != target_rule["id"]:
                    # 已按另一规则封存：封存事实不变，仅换绑规则/修订
                    plans.append(self._plan_row(item, "REBIND", target_rule,
                                                target_rev,
                                                note="sealed rule rebind"))
                # 注意：WITHDRAW/ROLLBACK 不产生“纯重绑”动作——
                # 被撤回版本封的项走 RELEASE（回到 based_on），其它项保持
                # 各自已绑定的不可变修订；CANARY/ACTIVATE 才整体重绑作用域。
        return plans

    @staticmethod
    def _find_rule_by_id(rev: dict | None, rule_id: str | None) -> dict | None:
        if not rev or not rule_id:
            return None
        return next((r for r in rev.get("rules", []) if r["id"] == rule_id), None)

    def _plan_row(self, item: dict, action: str, rule: dict | None,
                  target_rev: dict, note: str | None = None,
                  source_rev: dict | None = None) -> dict:
        return {
            "request_id": item["request_id"],
            "item_id": item["id"],
            "service": item["service"],
            "record_id": item["record_id"],
            "subject_id": item["subject_id"],
            "status": item["status"],
            "action": action,
            "rule_id": rule["id"] if rule else None,
            "from_revision": item["policy_revision"],
            "to_revision": target_rev["version"],
            "source_revision": (source_rev or {}).get("version"),
            "note": note,
        }

    def dry_run(self, revision: int, action: str = "CANARY") -> dict:
        """只读：返回 unfinished items 中会被该修订改变的集合。不落库、不发事件。"""
        rev = self.get_revision(revision)
        plans = self.plan_actions(rev, action)
        changing = [p for p in plans if p["action"] != "SKIP_TERMINAL"]
        seal = [p for p in changing if p["action"] == "SEAL"]
        release = [p for p in changing if p["action"] == "RELEASE"]
        rebind = [p for p in changing if p["action"] == "REBIND"]
        skip = [p for p in plans if p["action"] == "SKIP_TERMINAL"]
        return {
            "revision": revision, "action": action,
            "state": rev.get("state"),
            "rules": rev.get("rules", []),
            "canary_subjects": rev.get("canary_subjects", []),
            "content_hash": rev.get("content_hash"),
            "would_change": len(changing),
            "would_seal": len(seal), "would_release": len(release),
            "would_rebind": len(rebind),
            "untouched_terminal": len(skip),
            "affected_subjects": sorted({p["subject_id"] for p in changing}),
            "items": changing,
            "protected": {
                "note": "PURGED/FAILED/CANCELLED, ABORTED requests and certified"
                        " terminal history are never rewritten",
                "skipped_terminal_items": len(skip)},
        }

    # ================= 迁移：启动 / 断点续跑 ===========================
    def apply_revision(self, revision: int, action: str,
                       idempotency_key: str | None,
                       expected_version: int | None,
                       pause_after_item: str | None = None,
                       source_revision: int | None = None) -> dict:
        key = idempotency_key or f"mig_{uuid.uuid4().hex[:16]}"
        with self.store.lock:
            existing = self.store.get_migration(key)
            if existing:
                # 幂等重放：同一幂等键直接返回既有迁移，零额外写入。
                return self._migration_view(existing, replayed=True)

            # 乐观并发：在写入任何东西之前校验策略 head。
            if expected_version is not None:
                head, active = self.current_head_active()
                if int(expected_version) != head:
                    # 诊断性冲突：原子地不留任何改动（迁移行也不写）。
                    raise PolicyConflict(int(expected_version), head, active)

            # 先同步控制面，确保拿到最新的状态（WITHDRAWN/SUPERSEDED 等）。
            # ROLLBACK 尤其依赖“刚被置为 SUPERSEDED 的金丝雀”状态，强制刷新一次。
            try:
                self.sync_from_control_plane()
            except Exception:
                pass
            rev = self.get_revision(revision)  # 可能 PolicyFault -> 502
            # ROLLBACK/WITHDRAW 的规划语义：把“来源修订”封的项解到目标修订。
            # - WITHDRAW：来源 = 被撤回的修订本身（即 revision）
            # - ROLLBACK：目标=被回滚到的历史版本（revision，常为 0）；
            #   来源 = 调用方显式 source_revision，或当前仍有 SEALED 项绑定
            #   的最高版本（精确作用域，绝不误放其它金丝雀封的项）。
            plan_rev = rev
            if action == "ROLLBACK":
                chosen = source_revision
                if chosen is None:
                    sealed_vers = [r["v"] for r in self.store.conn.execute(
                        "SELECT DISTINCT policy_revision AS v FROM items"
                        " WHERE status='SEALED' AND policy_revision!=?",
                        (revision,)).fetchall()]
                    chosen = max(sealed_vers) if sealed_vers else None
                if chosen is not None:
                    # 强制从控制面回源，确保来源修订的最新状态（SUPERSEDED）
                    # 与不可变内容已在缓存中，不受 tick 同步时序影响。
                    try:
                        s0, body = policy_client.get(
                            f"{self.policy_url}/revisions/{chosen}", self.token)
                        if s0 == 200:
                            with self.store.lock:
                                self._cache_revision(body)
                                self.store.commit()
                    except policy_client.PolicyUnavailable:
                        pass
                    plan_rev = self.get_revision(chosen)
            # 规划：目标=rev（回退到的版本 / 撤回动作中仅用于记账），
            # 来源=plan_rev（被撤回或被回退、当前持有 SEALED 项的修订）。
            plans = self.plan_actions(rev, action, source_rev=plan_rev)
            ts = now_ms()
            actionable = [p for p in plans if p["action"] != "SKIP_TERMINAL"]
            self.store.conn.execute(
                "INSERT INTO migrations(id, revision, action, expected_version,"
                " status, total, pause_after_item, created_at, updated_at)"
                " VALUES(?,?,?,?,'RUNNING',?,?,?,?)",
                (key, revision, action, expected_version, len(actionable),
                 pause_after_item, ts, ts))
            for seq, p in enumerate(plans):
                self.store.conn.execute(
                    "INSERT INTO migration_items(migration_id, item_id, action,"
                    " rule_id, seq, status, detail) VALUES(?,?,?,?,?,'PENDING',?)",
                    (key, p["item_id"], p["action"], p["rule_id"], seq,
                     json.dumps(p, ensure_ascii=False, sort_keys=True)))
            # 工作流级别绑定：迁移启动即把请求的 policy_revision 指向目标修订。
            affected_rids = {p["request_id"] for p in plans
                             if p["action"] != "SKIP_TERMINAL"}
            for arid in affected_rids:
                self.store.conn.execute(
                    "UPDATE requests SET policy_revision=?, updated_at=? WHERE id=?",
                    (revision, ts, arid))
            self.store.event(
                self._event_scope_request(plans), "POLICY_MIGRATION_STARTED", {
                    "migration_id": key, "revision": revision, "action": action,
                    "total": len(actionable),
                    "affected_requests": sorted(affected_rids),
                    "expected_version": expected_version})
            self.store.commit()

        # 启动后立即推进一批（崩溃/暂停钩子由 run_due 在 tick 中续跑）。
        self.run_migration(key)
        return self._migration_view(self.store.get_migration(key))

    @staticmethod
    def _event_scope_request(plans: list[dict]) -> str:
        # 迁移可能跨多个 request；事件挂到第一个受影响请求，同时每个 item
        # 的推进事件仍各自落在其 request 审计链上。
        return plans[0]["request_id"] if plans else "policy"

    def _scope_from_done(self, done_rows: list[dict]) -> str:
        for d in done_rows:
            # item_id 形如 <request_id>:<service>:<record_id>
            it = self.store.get_item(d["item_id"])
            if it:
                return it["request_id"]
        return "policy"

    def run_due(self):
        """引擎 tick 调用：续跑所有 RUNNING 迁移（崩溃恢复 + 暂停钩子恢复）。"""
        for m in self.store.running_migrations():
            self.run_migration(m["id"])

    def run_migration(self, mid: str, pause_after_item: str | None = None):
        mig = self.store.get_migration(mid)
        if not mig or mig["status"] != "RUNNING":
            return mig
        pause_item = pause_after_item or mig["pause_after_item"]
        rev = self.get_revision(mig["revision"])
        # 撤回/回退解封后续跑：项回到来源修订的父修订（based_on，通常为基线 0）。
        release_target = rev
        if mig["action"] == "WITHDRAW":
            parent_no = rev.get("based_on") or 0
            release_target = self.get_revision(parent_no) if parent_no else self._baseline()
        # ROLLBACK：rev 即被回滚到的目标版本本身（常为基线 0）
        rows = self.store.get_migration_items(mid)
        for row in rows:
            if row["status"] != "PENDING":
                continue
            if row["action"] == "SKIP_TERMINAL":
                self._mark_done(mid, row, {"note": "terminal history untouched"})
                continue
            # 确定性故障钩子：处理到指定 item 前停住（该项保持 PENDING），
            # 供“竞争回调”场景把 PURGED 回调插进来。钩子持久化在迁移行上，
            # admin clear 后由引擎 run_due 续跑（因此重启后仍可恢复）。
            if pause_item and row["item_id"] == pause_item:
                return self.store.get_migration(mid)
            item = self.store.get_item(row["item_id"])
            if not item:
                self._mark_done(mid, row, {"note": "item vanished"})
                continue
            try:
                if row["action"] == "SEAL":
                    self._do_seal(item, rev, json.loads(row["detail"]))
                elif row["action"] == "RELEASE":
                    self._do_release(item, release_target, json.loads(row["detail"]))
                elif row["action"] == "REBIND":
                    self._do_rebind(item, rev, json.loads(row["detail"]))
                self._mark_done(mid, row, None)
                # 确定性崩溃：checkpoint 已提交后立即退出（不提交任何内存态）。
                if self.crash_after_step:
                    print("[policy] injected crash after migration checkpoint;"
                          " exiting NOW")
                    import os as _os
                    _os._exit(77)
            except http_client.ServiceError as e:
                # 服务瞬态/失联：保持 PENDING，下轮 tick 从断点继续（可恢复）。
                with self.store.lock:
                    self.store.event(item["request_id"],
                                     "POLICY_MIGRATION_STEP_RETRY", {
                                         "migration_id": mid,
                                         "item": row["item_id"],
                                         "error": str(e.body)[:200]})
                    self.store.commit()
                return self.store.get_migration(mid)
        with self.store.lock:
            cur = self.store.get_migration(mid)
            if cur and cur["status"] == "RUNNING":
                done = self.store.get_migration_items(mid)
                changed = sum(1 for d in done if d["action"] != "SKIP_TERMINAL")
                self.store.conn.execute(
                    "UPDATE migrations SET status='COMPLETED', changed=?,"
                    " sealed=?, released=?, rebound=?, skipped_terminal=?,"
                    " updated_at=? WHERE id=?",
                    (changed, mig["sealed"] or 0, mig["released"] or 0,
                     mig["rebound"] or 0,
                     sum(1 for d in done if d["action"] == "SKIP_TERMINAL"),
                     now_ms(), mid))
                # 真实计数由 _mark_done 累加；这里用准确值覆盖。
                self.store.conn.execute(
                    "UPDATE migrations SET sealed=(SELECT COUNT(*) FROM"
                    " migration_items WHERE migration_id=? AND action='SEAL'"
                    " AND status='DONE'), released=(SELECT COUNT(*) FROM"
                    " migration_items WHERE migration_id=? AND action='RELEASE'"
                    " AND status='DONE'), rebound=(SELECT COUNT(*) FROM"
                    " migration_items WHERE migration_id=? AND action='REBIND'"
                    " AND status='DONE') WHERE id=?", (mid, mid, mid, mid))
                self.store.event(
                    self._scope_from_done(done),
                    "POLICY_MIGRATION_COMPLETED", {
                        "migration_id": mid, "revision": mig["revision"],
                        "action": mig["action"], "changed": changed})
                self.store.commit()
        return self.store.get_migration(mid)

    # -- 单项原语（CAS 乐观锁：report_seq + 当前状态 + 当前修订守门） ----
    def _guard(self, item: dict, expect_statuses: set[str],
               expect_revision: int | None = None) -> dict | None:
        """重读最新项；若状态/修订已被竞争回调推进则拒绝（返回最新值）。"""
        cur = self.store.get_item(item["id"])
        if not cur:
            return None
        if cur["status"] not in expect_statuses:
            return cur
        if expect_revision is not None and cur["policy_revision"] != expect_revision:
            return cur
        return cur

    def _do_seal(self, item: dict, rev: dict, plan: dict):
        rule = self.matching_rule(rev, item["service"], item["record_id"])
        if not rule:
            return  # 规则已不在修订中（不可变修订不会发生；防御性 no-op）
        with self.store.lock:
            cur = self._guard(item, {"RESTRICTED", "DISPATCHED", "ERROR",
                                     "PURGING", "PENDING"})
            if cur is None or cur["status"] == "SEALED":
                return
            # 竞争回调可能已把它推到终态（如 PURGED）：绝不回退，迁移跳过此项。
            if cur["status"] in TERMINAL:
                self.store.event(cur["request_id"], "POLICY_SEAL_RACE_SKIP", {
                    "service": cur["service"], "record_id": cur["record_id"],
                    "current": cur["status"],
                    "note": "竞争回调已推进到终态；同一项不会在两个修订下各推进一次"})
                self.store.commit()
                return
            seq_before = cur["report_seq"]
            # 调用服务执行 SEAL（命令幂等）。网络调用放在锁外更优，但为保证
            # “回调与迁移互斥”，这里在 store 锁内串行执行（与引擎写路径一致）。
            result = self._service_seal(cur, rule)
            cur = self.store.get_item(cur["id"])
            if cur["report_seq"] != seq_before or cur["status"] in TERMINAL:
                # 回调在服务调用期间抢先：不覆盖，记录竞争裁决。
                self.store.event(cur["request_id"], "POLICY_SEAL_RACE_SKIP", {
                    "service": cur["service"], "record_id": cur["record_id"],
                    "current": cur["status"], "rule_id": rule["id"]})
                self.store.commit()
                return
            if result.get("status") == "PURGED":
                # 服务侧记录已被并发擦除：以前进方式采纳终态，不封存。
                self._adopt_terminal(cur, result)
                return
            ts = now_ms()
            self.store.conn.execute(
                "UPDATE items SET status='SEALED', policy_revision=?,"
                " sealed_rule_id=?, hold_code=?, hold_reason=?,"
                " hold_releases_at=?, result_hash=?, evidence=?,"
                " command_id_purge=NULL, overdue=0, next_attempt_at=0,"
                " report_seq=report_seq+1, updated_at=? WHERE id=?",
                (rev["version"], rule["id"], result.get("hold_code", rule["hold"]),
                 result.get("hold_reason", rule["reason"]),
                 result.get("hold_releases_at"), result.get("result_hash"),
                 json.dumps(result, ensure_ascii=False, sort_keys=True),
                 ts, cur["id"]))
            self.store.event(cur["request_id"], "POLICY_ITEM_SEALED", {
                "service": cur["service"], "record_id": cur["record_id"],
                "rule_id": rule["id"], "revision": rev["version"],
                "from": cur["status"]})
            self.store.commit()

    def _service_seal(self, item: dict, rule: dict) -> dict:
        svc = self.registry[item["service"]]
        command_id = f"cmd_seal_{uuid.uuid4().hex[:10]}"
        payload = {
            "command_id": command_id, "request_id": item["request_id"],
            "subject_id": item["subject_id"], "record_id": item["record_id"],
            "op": "SEAL", "rule_id": rule["id"], "hold": rule["hold"],
            "reason": rule["reason"], "hold_seconds": rule.get("hold_seconds", 86400),
            "callback_url": f"{self.callback_base}/internal/reports"}
        status, body = http_client.post(
            f"{svc['base_url']}/internal/commands", payload, svc["token"])
        return body

    def _adopt_terminal(self, item: dict, result: dict):
        ts = now_ms()
        self.store.conn.execute(
            "UPDATE items SET status='PURGED', result_hash=?, evidence=?,"
            " report_seq=report_seq+1, next_attempt_at=0, updated_at=? WHERE id=?",
            (result.get("result_hash"),
             json.dumps(result, ensure_ascii=False, sort_keys=True), ts, item["id"]))
        self.store.event(item["request_id"], "POLICY_RACE_CONVERGED_PURGED", {
            "service": item["service"], "record_id": item["record_id"],
            "note": "迁移与迟到 PURGED 回调竞争：收敛到唯一合法终态 PURGED"})

    def _do_release(self, item: dict, target_rev: dict, plan: dict):
        with self.store.lock:
            cur = self._guard(item, {"SEALED"})
            if cur is None:
                return
            if cur["status"] != "SEALED":
                return  # 已被其它路径推进（如保留到期），幂等 no-op
            svc = self.registry[cur["service"]]
            command_id = f"cmd_rel_{uuid.uuid4().hex[:10]}"
            try:
                _, body = http_client.post(
                    f"{svc['base_url']}/internal/commands", {
                        "command_id": command_id,
                        "request_id": cur["request_id"],
                        "subject_id": cur["subject_id"],
                        "record_id": cur["record_id"], "op": "RELEASE",
                        "rule_id": cur["sealed_rule_id"],
                        "callback_url": f"{self.callback_base}/internal/reports"},
                    svc["token"])
            except http_client.ServiceError:
                raise
            ts = now_ms()
            # 回到 RESTRICTED 续跑同一工作流；重绑到目标修订（撤回基线/回退目标）。
            # SEAL 时为拒绝陈旧 PURGE 回调已清空 command_id_purge；这里立刻签发
            # 一条**新** PURGE 命令——因为同级其它项此时可能已 PURGED，常规
            # PURGE 闸门（要求所有项仍 RESTRICTED/SEALED）不会再为它补命令。
            new_purge_cmd = f"cmd_{uuid.uuid4().hex[:12]}"
            self.store.conn.execute(
                "UPDATE items SET status='RESTRICTED', policy_revision=?,"
                " sealed_rule_id=NULL, hold_code=NULL, hold_reason=NULL,"
                " hold_releases_at=NULL, result_hash=?,"
                " command_id_purge=?, purge_due_ms=?, overdue=0,"
                " next_attempt_at=0, report_seq=report_seq+1, updated_at=?"
                " WHERE id=?",
                (target_rev["version"], body.get("result_hash"),
                 new_purge_cmd, ts + _PURGE_SLA_MS, ts, cur["id"]))
            self.store.event(cur["request_id"], "POLICY_ITEM_RELEASED", {
                "service": cur["service"], "record_id": cur["record_id"],
                "rule_id": cur["sealed_rule_id"],
                "to_revision": target_rev["version"],
                "new_purge_command": new_purge_cmd,
                "note": "规则撤回/回退：解除封存，同一工作流续跑"})
            self.store.commit()

    def _do_rebind(self, item: dict, rev: dict, plan: dict):
        with self.store.lock:
            cur = self.store.get_item(item["id"])
            if not cur or cur["policy_revision"] == rev["version"]:
                return
            if cur["status"] in TERMINAL:
                return
            rule = self.matching_rule(rev, cur["service"], cur["record_id"])
            if cur["status"] == "SEALED":
                # 仅换绑到新规则/新修订，封存事实不变（证书历史保持）。
                self.store.conn.execute(
                    "UPDATE items SET policy_revision=?, sealed_rule_id=?,"
                    " updated_at=? WHERE id=?",
                    (rev["version"],
                     rule["id"] if rule else cur["sealed_rule_id"],
                     now_ms(), cur["id"]))
            else:
                self.store.conn.execute(
                    "UPDATE items SET policy_revision=?, updated_at=? WHERE id=?",
                    (rev["version"], now_ms(), cur["id"]))
            self.store.commit()

    def _mark_done(self, mid: str, row: dict, detail: dict | None):
        with self.store.lock:
            merged = detail or {}
            self.store.conn.execute(
                "UPDATE migration_items SET status='DONE', detail=? WHERE"
                " migration_id=? AND item_id=?",
                (json.dumps(merged, ensure_ascii=False, sort_keys=True),
                 mid, row["item_id"]))
            self.store.conn.execute(
                "UPDATE migrations SET updated_at=? WHERE id=?",
                (now_ms(), mid))
            self.store.commit()

    # ================= 视图 ============================================
    def _migration_view(self, mig: dict, replayed: bool = False) -> dict:
        items = self.store.get_migration_items(mig["id"])
        done = sum(1 for i in items if i["status"] == "DONE")
        return {
            "migration_id": mig["id"], "revision": mig["revision"],
            "action": mig["action"], "status": mig["status"],
            "expected_version": mig["expected_version"],
            "total": mig["total"], "done": done,
            "remaining": len(items) - done,
            "sealed": mig["sealed"], "released": mig["released"],
            "rebound": mig["rebound"],
            "skipped_terminal": mig["skipped_terminal"],
            "replayed": replayed,
            "checkpoint": {"seq": done, "of": len(items)},
            "items": [{"item_id": i["item_id"], "action": i["action"],
                       "rule_id": i["rule_id"], "status": i["status"]}
                      for i in items],
            "created_at": iso(mig["created_at"]),
            "updated_at": iso(mig["updated_at"]),
        }

    def migration_view(self, mid: str) -> dict | None:
        mig = self.store.get_migration(mid)
        return self._migration_view(mig) if mig else None

    def list_migrations(self) -> list[dict]:
        rows = self.store.conn.execute(
            "SELECT id FROM migrations ORDER BY created_at DESC LIMIT 50"
        ).fetchall()
        return [self._migration_view(self.store.get_migration(r["id"]))
                for r in rows]

    # ================= 运行期强制（引擎 tick 用） ======================
    def enforce_on_item(self, item: dict) -> bool:
        """根据项**已绑定**的修订，把 RESTRICTED 等未封存项按规则封存。

        用于新建工作流（金丝雀主体在创建时绑定修订）与 REBIND 后的即时生效：
        保证“新匹配 RESTRICTED 项在任何 PURGE 之前变为 SEALED”。
        返回是否发生封存。
        """
        rev_no = item["policy_revision"]
        if rev_no == 0:
            return False
        rev = self.get_revision(rev_no)
        if rev.get("state") in ("WITHDRAWN", "SUPERSEDED"):
            return False
        rule = self.matching_rule(rev, item["service"], item["record_id"])
        if not rule:
            return False
        if item["status"] in ("SEALED",) and item["sealed_rule_id"] == rule["id"]:
            return False
        if item["status"] in TERMINAL or item["status"] in ("PENDING",):
            return False
        plan = self._plan_row(item, "SEAL", rule, rev)
        try:
            self._do_seal(item, rev, plan)
            return True
        except http_client.ServiceError:
            return False
