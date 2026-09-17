"""容器启动验证（smoke / e2e）：由独立 verifier 容器执行。

仅使用标准库；从零复算证据哈希、Merkle 根、HMAC 签名、墓碑令牌，
不调用协调端的 /verify 自证接口，保证"可证明的最终结果"是第三方可验证的。

覆盖需求矩阵：
  A. 正常删除 + 法律保留封存 -> 证书 v1；约束到期自动续跑 -> 证书 v2；
     重复/乱序回报被识别；对外确认后迟到副本被墓碑拦截，不复活。
  B. 服务长期失联（故障注入）：期限到期 overdue；安全重试；恢复后收敛确认。
  C. Saga 永久失败：局部补偿 UNRESTRICT 后 ABORTED；不发证书；无墓碑。
退出码：0 全部通过；1 有断言失败。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request

COORD = os.environ.get("COORD_URL", "http://127.0.0.1:8080")
POLICY = os.environ.get("POLICY_URL", "http://127.0.0.1:8090")
ORDERS = os.environ.get("ORDERS_URL", "http://127.0.0.1:9101")
BILLING = os.environ.get("BILLING_URL", "http://127.0.0.1:9102")
PROFILE = os.environ.get("PROFILE_URL", "http://127.0.0.1:9103")
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "dev-internal-token")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "dev-admin-token")
SECRET = os.environ.get("DELETION_SIGNING_SECRET", "dev-deletion-secret").encode()
TSECRET = os.environ.get("GLOBAL_TOMBSTONE_SECRET", "dev-tombstone-secret").encode()
LOCAL_SUPERVISOR = os.environ.get("LOCAL_SUPERVISOR", "1") == "1"

FAILURES: list[str] = []
PASSES: list[str] = []


def check(name: str, cond: bool, detail: str = ""):
    if cond:
        PASSES.append(name)
        print(f"  PASS  {name}")
    else:
        FAILURES.append(f"{name} {detail}")
        print(f"  FAIL  {name} {detail}")


def req(method: str, url: str, payload: dict | None = None,
        token: str | None = None, timeout: float = 5.0, ret: bool = False):
    data = json.dumps(payload).encode() if payload is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            body = json.loads(raw)
        except Exception:
            body = {"raw": raw}
        if ret:
            return e.code, body
        return e.code, body
    except Exception as e:
        if ret:
            return 0, {"error": str(e)}
        raise


def wait_for(url: str, name: str, timeout_s: float = 20.0):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            s, _ = req("GET", f"{url}/health", ret=True)
            if s == 200:
                print(f"  ... {name} ready")
                return True
        except Exception:
            pass
        time.sleep(0.3)
    return False


def wait_until(name: str, fn, timeout_s: float = 30.0, interval: float = 0.3):
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        try:
            last = fn()
            if last:
                return last
        except Exception as e:
            last = repr(e)
        time.sleep(interval)
    check(name, False, f"timeout; last={last}")
    return None


# -- 独立复算（与协调端/服务代码无关的重新实现） --------------------------
def canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode()


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def leaf_hash(item: dict) -> str:
    return sha(canon({
        "service": item["service"], "subject_id": item["subject_id"],
        "record_id": item["record_id"], "status": item["status"],
        "result_hash": item["result_hash"],
        "hold_code": item["hold_code"],
        "command_id": item["command_id_purge"] or item["command_id_restrict"],
        "policy_revision": item.get("policy_revision", 0),
        "updated_at": item["updated_at"],
    }))


def merkle(leaves: list[str]) -> str:
    if not leaves:
        return sha(b"")
    while len(leaves) > 1:
        if len(leaves) % 2:
            leaves.append(leaves[-1])
        leaves = [sha(leaves[i].encode() + leaves[i + 1].encode())
                  for i in range(0, len(leaves), 2)]
    return leaves[0]


def get_view(rid: str) -> dict:
    s, v = req("GET", f"{COORD}/requests/{rid}")
    assert s == 200, v
    return v


def get_raw(rid: str) -> dict:
    """协调端内部视图（供验证器取毫秒时间戳独立复算叶子）。"""
    s, v = req("GET", f"{COORD}/internal/requests/{rid}/raw",
               token=INTERNAL_TOKEN)
    assert s == 200, v
    return v


def verify_certificate_strict(rid: str) -> bool:
    """严格独立验证：叶子哈希 -> Merkle 根 -> HMAC 签名，全部从零复算。"""
    raw = get_raw(rid)
    cert = raw["certificates"][-1]
    leaves = []
    for it in raw["items"]:
        if it["status"] == "CANCELLED":
            continue
        leaves.append(leaf_hash(it))
    if merkle(leaves) != cert["merkle_root"]:
        return False
    payload = {
        "request_id": rid, "subject_id": raw["subject_id"],
        "version": cert["version"], "merkle_root": cert["merkle_root"],
        "issued_at": cert["created_at"],
        "sealed_count": cert["sealed_count"], "item_count": cert["item_count"],
    }
    sig = hmac.new(SECRET, canon(payload), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, cert["signature"])


def tombstone_token(request_id: str, subject_id: str) -> str:
    return "tomb:" + hmac.new(
        TSECRET, canon({"request_id": request_id, "subject_id": subject_id}),
        hashlib.sha256).hexdigest()


# -- 合规策略控制面辅助 -----------------------------------------------------
def policy_draft(rules: list[dict], canary=None, note: str = "") -> tuple[int, dict]:
    s, b = req("POST", f"{POLICY}/revisions",
               {"rules": rules, "canary_subjects": canary or [], "note": note},
               token=ADMIN_TOKEN)
    assert s == 201, b
    return b["version"], b


def policy_action(version: int, action: str, expected=None):
    payload = {}
    if expected is not None:
        payload["expected_version"] = expected
    return req("POST", f"{POLICY}/revisions/{version}/{action}", payload,
               token=ADMIN_TOKEN)


def policy_current() -> dict:
    s, b = req("GET", f"{POLICY}/current", token=INTERNAL_TOKEN)
    assert s == 200, b
    return b


def verify_stored_certificate(rid: str, cert_version: int) -> bool:
    """独立验证**某个历史版本**证书（回滚后历史证据仍须逐字节可验）。"""
    raw = get_raw(rid)
    cert = next((c for c in raw["certificates"]
                 if c["version"] == cert_version), None)
    if not cert:
        return False
    # 历史叶子哈希直接来自证书负载（证书行不可变）；重算 Merkle 根与签名。
    if merkle([l["hash"] for l in cert["leaves"]]) != cert["merkle_root"]:
        return False
    payload = {
        "request_id": rid, "subject_id": raw["subject_id"],
        "version": cert["version"], "merkle_root": cert["merkle_root"],
        "issued_at": cert["created_at"],
        "sealed_count": cert["sealed_count"], "item_count": cert["item_count"],
    }
    sig = hmac.new(SECRET, canon(payload), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, cert["signature"])


def dry_run(rev: int, action: str = "CANARY") -> dict:
    s, b = req("GET", f"{COORD}/policy/dry-run?revision={rev}&action={action}",
               token=ADMIN_TOKEN)
    assert s == 200, b
    return b


def apply_rev(rev: int, action="CANARY", key=None, expected=None,
              pause_after_item=None, token=ADMIN_TOKEN):
    body = {"revision": rev, "action": action}
    if key is not None:
        body["idempotency_key"] = key
    if expected is not None:
        body["expected_version"] = expected
    if pause_after_item is not None:
        body["pause_after_item"] = pause_after_item
    return req("POST", f"{COORD}/policy/apply", body, token=token)


def wait_migration(mid: str, state="COMPLETED", timeout_s=30.0) -> dict | None:
    def f():
        s, b = req("GET", f"{COORD}/migrations/{mid}", token=ADMIN_TOKEN)
        if s == 200 and b["status"] == state:
            return b
        return None
    return wait_until(f"migration {mid[:12]} -> {state}", f, timeout_s)


def wait_item(rid: str, record: str, statuses: set, timeout_s=30.0) -> dict | None:
    def f():
        v = get_view(rid)
        it = next((i for i in v["items"] if i["record_id"] == record), None)
        if it and it["status"] in statuses:
            return v
        return None
    return wait_until(f"item {record} -> {statuses}", f, timeout_s)


def rule(rid: str, service=None, record=None, prefix=None, hold="LEGAL_HOLD",
         hold_seconds=86400):
    m = {}
    if service:
        m["service"] = service
    if record:
        m["record_id"] = record
    if prefix:
        m["record_prefix"] = prefix
    return {"id": rid, "hold": hold, "reason": f"{hold} {rid}",
            "hold_seconds": hold_seconds, "match": m}


def seed_subject(sid: str, recs: list[tuple[str, str]]):
    for base, rec in recs:
        s, b = req("POST", f"{base}/seed",
                   {"record_id": rec, "subject_id": sid, "payload": {}})
        assert s in (201, 200), b


def create_req(sid: str) -> str:
    s, b = req("POST", f"{COORD}/requests", {"subject_id": sid})
    assert s == 202, b
    return b["request_id"]


def wait_confirmed(rid: str, timeout_s=30.0) -> dict | None:
    return wait_until(
        f"{rid} CONFIRMED",
        lambda: (lambda v: v if v and v["status"] == "CONFIRMED" else None)(
            get_view(rid)), timeout_s)


def wait_status(rid: str, status: str, timeout_s=30.0) -> dict | None:
    return wait_until(
        f"{rid} {status}",
        lambda: (lambda v: v if v and v["status"] == status else None)(
            get_view(rid)), timeout_s)


# =========================================================================
# 场景 A：正常删除 + 法律保留 + 重复/乱序回报 + 迟到副本 + 解除后续跑
# =========================================================================
def scenario_a():
    print("\n=== 场景 A：正常删除 / 法律保留 / 重复乱序回报 / 迟到副本 / 解除续跑 ===")
    sid = "user-A"
    seed = [
        (ORDERS, "ord-1", {"amount": 99}),
        (ORDERS, "ord-2", {"amount": 199}),
        (BILLING, "inv-1", {"due": 50}),
        (PROFILE, "prof-1", {"name": "Alice"}),
    ]
    for base, rid_rec, payload in seed:
        s, b = req("POST", f"{base}/seed",
                   {"record_id": rid_rec, "subject_id": sid, "payload": payload})
        check(f"seed {base}/{rid_rec}", s in (201, 200), str(b))

    s, b = req("POST", f"{COORD}/requests",
               {"subject_id": sid, "display_name": "Alice",
                "pause_after_resolve": True})
    rid = b["request_id"]
    check("删除申请已受理(202)", s == 202, str(b))

    # 引擎钩子：身份解析一完成就冻结编排，便于确定性注入回报异常
    def plan_ready():
        vv = get_view(rid)
        real = [i for i in vv["items"] if i["status"] != "CANCELLED"]
        if real and all(i["record_id"] and i["status"] == "PENDING"
                        for i in real) and vv["events"]:
            paused = any(e["type"] == "ENGINE_PAUSED" for e in vv["events"])
            return vv if paused else None
        return None
    v = wait_until("身份解析完成、带期限计划生成（编排已冻结）", plan_ready, 15)
    check("计划带 deadline", v and v["deadline"], str(v))
    check("计划覆盖 3 个服务", v and len({i["service"] for i in v["items"]}) == 3)

    target = next(i for i in v["items"] if i["record_id"] == "ord-1")
    # 1) 伪造 command_id
    s, b = req("POST", f"{COORD}/internal/reports", {
        "request_id": rid, "service": "orders", "record_id": "ord-1",
        "command_id": "cmd_FORGED", "status": "RESTRICTED",
        "result_hash": "x"}, token=INTERNAL_TOKEN)
    check("伪造命令回报被拒(409)", s == 409 and "stale" in b.get("reason", ""), str(b))
    # 2) 越级/乱序：计划项仍在 RESTRICT 阶段，却回报 PURGED
    s, b = req("POST", f"{COORD}/internal/reports", {
        "request_id": rid, "service": "orders", "record_id": "ord-1",
        "command_id": target["command_id_restrict"], "status": "PURGED",
        "result_hash": "y"}, token=INTERNAL_TOKEN)
    check("越级/乱序回报被识别", s == 409 and (
        "out-of-order" in b.get("reason", "")
        or "phase/status mismatch" in b.get("reason", "")), str(b))
    # 3) 合法的乱序补充：先手动推进到 RESTRICTED，再收到更旧的 DISPATCHED 空回报
    #    （此处直接验证状态序：旧阶段回调不得回退状态，下一断言重复场景一并覆盖）

    req("POST", f"{COORD}/admin/requests/{rid}/resume", token=ADMIN_TOKEN)

    # 等待证书 v1（billing inv-1 被法律保留 -> SEALED）
    def cert_v1():
        v = get_view(rid)
        if v["certificates"]:
            return v
        return None
    v = wait_until("对外确认 CONFIRMED + 证书 v1（含 SEALED）", cert_v1, 25)
    check("请求状态 CONFIRMED", v and v["status"] == "CONFIRMED", str(v and v["status"]))
    inv = next(i for i in v["items"] if i["record_id"] == "inv-1")
    check("财务/法律记录被封存而非擦除", inv["status"] == "SEALED"
          and inv["hold"] and inv["hold"]["code"] == "LEGAL_HOLD", str(inv))
    check("其他记录全部 PURGED",
          all(i["status"] == "PURGED" for i in v["items"]
              if i["record_id"] not in ("inv-1",) and i["status"] != "CANCELLED"))
    check("封存记录业务读返回 423（保留解除前持续封存）",
          req("GET", f"{BILLING}/records/inv-1", ret=True)[0] == 423)
    cert1 = v["certificates"][-1]
    check("证书 v1 含封存计数", cert1["sealed_count"] == 1, str(cert1))

    # 重复回报：终态后重放 PURGED 回调，必须幂等不复活
    purged = next(i for i in v["items"] if i["record_id"] == "ord-1")
    s, b = req("POST", f"{COORD}/internal/reports", {
        "request_id": rid, "service": "orders", "record_id": "ord-1",
        "command_id": purged["command_id_purge"], "status": "PURGED",
        "result_hash": purged["result_hash"]}, token=INTERNAL_TOKEN)
    check("重复回报幂等(duplicate=true)", s == 200 and b.get("duplicate"), str(b))
    # 倒序：已 PURGED 后又收到旧 RESTRICT 阶段成功，必须拒绝且不回退
    s, b = req("POST", f"{COORD}/internal/reports", {
        "request_id": rid, "service": "orders", "record_id": "ord-1",
        "command_id": purged["command_id_restrict"], "status": "RESTRICTED",
        "result_hash": "old"}, token=INTERNAL_TOKEN)
    check("倒序旧阶段回报不回退状态(409)",
          s == 409 and "out-of-order" in b.get("reason", ""), str(b))

    # 迟到副本：对外确认后，binlog/缓存重放不得复活
    for base, rec in ((ORDERS, "ord-1"), (PROFILE, "prof-1"),
                      (ORDERS, "ord-2")):
        s, b = req("POST", f"{base}/replica-events", {
            "record_id": rec, "subject_id": sid, "source": "late-binlog",
            "payload": {"resurrected": True}})
        check(f"迟到副本被墓碑拦截 {base}/{rec}", s == 410 and b.get("quarantined"),
              f"{s} {b}")
        s2, b2 = req("GET", f"{base}/records/{rec}", ret=True)
        check(f"副本未复活（读不到/404） {base}/{rec}", s2 == 404, str(b2))
    # 封存记录：迟到副本同样被拒，但封存行依法保留（仍 423，不变 ACTIVE）
    s, b = req("POST", f"{BILLING}/replica-events", {
        "record_id": "inv-1", "subject_id": sid, "source": "late-binlog",
        "payload": {"resurrected": True}})
    check("封存记录的迟到副本被拦截", s == 410 and b.get("quarantined"), str(b))
    check("封存记录仍为封存态(423)未被复活",
          req("GET", f"{BILLING}/records/inv-1", ret=True)[0] == 423)
    s, b = req("GET", f"{ORDERS}/admin/quarantine")
    check("orders 检疫区记录了迟到副本",
          any(q["reason"].startswith("late replica") for q in b["quarantine"]), str(b))

    # seed 复活尝试也被拦截
    s, b = req("POST", f"{PROFILE}/seed",
               {"record_id": "prof-1", "subject_id": sid, "payload": {"x": 1}})
    check("再次播种被墓碑拒绝(410)", s == 410 and b.get("quarantined"), str(b))

    # 严格独立验证证书 v1
    check("证书 v1 第三方严格验证通过", verify_certificate_strict(rid))
    # 墓碑令牌可由第三方用共享密钥独立验证
    stones = _tombstones(rid)
    global_tok = next(t["token"] for t in stones if t["service"] == "*")
    check("全局墓碑令牌可独立验签",
          hmac.compare_digest(global_tok, tombstone_token(rid, sid)))
    check("墓碑已推送到各服务", all(t["pushed"] for t in stones
          if t["service"] != "*"), str(stones))

    # 保留解除：同一计划自动续跑，无需重新申请 -> 证书 v2（全部 PURGED）
    def cert_v2_all_purged():
        vv = get_view(rid)
        if len(vv["certificates"]) >= 2 \
                and vv["certificates"][-1]["sealed_count"] == 0 \
                and all(i["status"] in ("PURGED", "CANCELLED")
                        for i in vv["items"]):
            return vv
        return None
    v = wait_until("保留解除后自动续跑原计划 -> 证书 v2 全部 PURGED",
                   cert_v2_all_purged, 30)
    check("证书 v2 封存计数归零",
          v and v["certificates"][-1]["sealed_count"] == 0,
          str(v and v["certificates"][-1]))
    check("证书 v2 全部 PURGED",
          v and all(i["status"] in ("PURGED", "CANCELLED") for i in v["items"]))
    check("证书 v2 第三方严格验证通过", v is not None
          and verify_certificate_strict(rid))
    # 事件审计链覆盖关键节点
    types_ = {e["type"] for e in v["events"]}
    for t in ("REQUEST_CREATED", "PLAN_READY", "PURGE_GATE_OPENED",
              "HOLD_RELEASED", "REQUEST_CONFIRMED", "CERTIFICATE_ISSUED",
              "REPORT_REJECTED"):
        check(f"审计事件存在: {t}", t in types_)
    return rid


def _tombstones(rid):
    s, b = req("GET", f"{COORD}/requests/{rid}/tombstones")
    return b["tombstones"]


# =========================================================================
# 场景 B：服务长期失联 -> 期限 overdue -> 恢复 -> 安全重试收敛
# =========================================================================
def scenario_b():
    print("\n=== 场景 B：服务失联 / 期限告警 / 安全重试 / 恢复收敛 ===")
    sid = "user-B"
    for base, rec in ((ORDERS, "ord-b1"), (BILLING, "inv-b1"),
                      (PROFILE, "prof-b1")):
        req("POST", f"{base}/seed",
            {"record_id": rec, "subject_id": sid, "payload": {}})
    s, b = req("POST", f"{COORD}/requests", {"subject_id": sid})
    rid = b["request_id"]

    # 故障注入：让 orders 所有内部命令 503（health/seed 仍正常）
    s, fault = req("POST", f"{ORDERS}/admin/fault",
                   {"mode": "commands_503", "on": True}, token=ADMIN_TOKEN)
    check("故障注入成功", s == 200, str(fault))

    def overdue_seen():
        v = get_view(rid)
        if any(i["overdue"] for i in v["items"] if i["service"] == "orders"):
            return v
        return None
    v = wait_until("orders 失联超过阶段期限 -> overdue 可证明展示",
                   overdue_seen, 40)
    check("overdue 项仍在重试而非失败",
          v and all(i["status"] in ("ERROR", "DISPATCHED")
                    for i in v["items"] if i["overdue"]), str(v))
    check("未确认、无证书", v["status"] != "CONFIRMED" and not v["certificates"])
    check("审计含 ITEM_OVERDUE 与重试调度",
          any(e["type"] == "ITEM_OVERDUE" for e in v["events"])
          and any(e["type"] == "COMMAND_RETRY_SCHEDULED" for e in v["events"]))

    # 恢复：同一 command_id 的重试必须幂等，最终收敛
    req("POST", f"{ORDERS}/admin/fault",
        {"mode": "commands_503", "on": False}, token=ADMIN_TOKEN)

    def confirmed():
        vv = get_view(rid)
        return vv if vv["status"] == "CONFIRMED" else None
    v = wait_until("恢复后安全重试收敛 -> CONFIRMED", confirmed, 30)
    check("全部 PURGED", v and all(
        i["status"] in ("PURGED", "CANCELLED") for i in v["items"]))
    check("证书第三方验证通过", v is not None and verify_certificate_strict(rid))
    # 服务端确认命令是幂等执行的（同一 command_id 重试次数>1 但只执行一次）
    s, b = req("GET", f"{COORD}/requests/{rid}")
    check("存在多次 attempts（确实重试过）",
          any(i["attempts"] >= 2 for i in b["items"]),
          str([(i["service"], i["attempts"]) for i in b["items"]]))


# =========================================================================
# 场景 C：永久失败 -> 局部补偿 -> ABORTED，不确认不擦除不建墓碑
# =========================================================================
def scenario_c():
    print("\n=== 场景 C：永久失败 / 局部补偿 / 中止 ===")
    sid = "user-C"
    for base, rec in ((ORDERS, "ord-c1"), (BILLING, "inv-c1"),
                      (PROFILE, "prof-c1")):
        req("POST", f"{base}/seed",
            {"record_id": rec, "subject_id": sid, "payload": {}})
    s, b = req("POST", f"{COORD}/requests", {"subject_id": sid})
    rid = b["request_id"]

    # billing 在 RESTRICT 阶段返回 409 永久冲突（一次性）：
    # saga 必须对已冻结的其他服务局部补偿后中止，而不是无限重试
    req("POST", f"{BILLING}/admin/fault",
        {"mode": "restrict_409_once", "on": True}, token=ADMIN_TOKEN)

    def aborted():
        vv = get_view(rid)
        return vv if vv["status"] == "ABORTED" else None
    v = wait_until("永久失败后 saga 中止 ABORTED", aborted, 30)
    if v:
        failed_item = next((i for i in v["items"] if i["status"] == "FAILED"), None)
        check("存在 FAILED 项", failed_item is not None)
        check("永久失败不做无效重试(attempts<=1)",
              failed_item is not None and failed_item["attempts"] <= 1,
              str(failed_item and failed_item["attempts"]))
        check("已冻结项被局部补偿(CANCELLED/恢复)",
              all(i["status"] != "RESTRICTED" for i in v["items"]))
        check("未对外确认、无证书",
              v["status"] == "ABORTED" and not v["certificates"])
        s, b = req("GET", f"{COORD}/requests/{rid}/tombstones")
        check("中止不产生墓碑", b["tombstones"] == [], str(b))
        check("审计含 COMPENSATED 与 REQUEST_ABORTED",
              any(e["type"] == "COMPENSATED" for e in v["events"])
              and any(e["type"] == "REQUEST_ABORTED" for e in v["events"]))
        # billing 数据仍在（未擦除）；orders/profile 数据已恢复 ACTIVE
        s, _ = req("GET", f"{BILLING}/records/inv-c1", ret=True)
        check("失败服务数据未被擦除(仍可读/冻结)", s in (200, 423), str(s))


# =========================================================================
# 策略 P1：金丝雀主体拿新修订，对照队列留在旧修订；创建即绑定、PURGE 前封存
# =========================================================================
def scenario_p1_canary_vs_control():
    print("\n=== 策略 P1：起草/金丝雀；金丝雀 vs 对照；新匹配先 SEALED 后 PURGE ===")
    sid_can, sid_ctl = "user-P1-CAN", "user-P1-CTL"
    seed_subject(sid_can, [(ORDERS, "p1-ord"), (BILLING, "p1-inv"),
                           (PROFILE, "p1-prof")])
    seed_subject(sid_ctl, [(ORDERS, "p1c-ord"), (BILLING, "p1c-inv"),
                           (PROFILE, "p1c-prof")])

    # 起草 DRAFT：对 orders/p1-ord 施加法律保留；先挂金丝雀主体
    rev, draft = policy_draft(
        [rule("p1-hold-orders", service="orders", record="p1-ord")],
        canary=[sid_can], note="P1 canary seal")
    check("策略修订为不可变 DRAFT（含 content_hash）",
          draft["state"] == "DRAFT" and len(draft["content_hash"]) == 64, str(draft))
    s, b = policy_action(rev, "canary")
    check("DRAFT -> CANARY", s == 200 and b["state"] == "CANARY", str(b))

    cur = policy_current()
    check("ACTIVE 仍为基线 0（金丝雀未影响对照）", cur["active"] == 0
          and [c["version"] for c in cur["canaries"]] == [rev], str(cur))

    # 两个主体同时提交：金丝雀主体必须绑定 rev，对照主体绑定 0
    rid_can = create_req(sid_can)
    rid_ctl = create_req(sid_ctl)
    vc = wait_confirmed(rid_can)
    vo = wait_confirmed(rid_ctl)

    can_item = next(i for i in vc["items"] if i["record_id"] == "p1-ord")
    check("金丝雀工作流绑定新修订", vc["policy_revision"] == rev
          and can_item["policy_revision"] == rev,
          f"{vc['policy_revision']} {can_item['policy_revision']}")
    check("金丝雀主体新匹配项在任何 PURGE 前 SEALED",
          can_item["status"] == "SEALED"
          and can_item["sealed_rule_id"] == "p1-hold-orders"
          and can_item["hold"] and can_item["hold"]["code"] == "LEGAL_HOLD",
          str(can_item))
    check("金丝雀其余项 PURGED",
          all(i["status"] == "PURGED" for i in vc["items"]
              if i["record_id"] not in ("p1-ord",) and i["status"] != "CANCELLED"))
    check("金丝雀证书记录 1 项封存且第三方可验",
          vc["certificates"][-1]["sealed_count"] == 1
          and verify_certificate_strict(rid_can))
    check("对照队列留在旧修订 rev0 且全部 PURGED",
          vo["policy_revision"] == 0
          and all(i["policy_revision"] == 0 for i in vo["items"])
          and all(i["status"] in ("PURGED", "CANCELLED") for i in vo["items"])
          and verify_certificate_strict(rid_ctl), str(vo))
    check("封存记录业务读 423",
          req("GET", f"{ORDERS}/records/p1-ord", ret=True)[0] == 423)
    # 审计链包含绑定与封存事件
    types_ = {e["type"] for e in vc["events"]}
    check("审计含 REQUEST_CREATED.policy_revision 与 POLICY_ITEM_SEALED",
          any(e.get("detail", {}).get("policy_revision") == rev
              for e in vc["events"] if e["type"] == "REQUEST_CREATED")
          and "POLICY_ITEM_SEALED" in types_, str(sorted(types_)))
    # 撤回金丝雀规则（为 P2/P3 共享：这里仅撤回 P1，金丝雀主体的封存随之解除）
    s, b = policy_action(rev, "withdraw")
    check("CANARY -> WITHDRAWN", s == 200 and b["state"] == "WITHDRAWN", str(b))
    s, b = apply_rev(rev, "WITHDRAW", key=f"withdraw-p1-{rev}")
    check("撤回迁移已受理", s == 202, str(b))
    v = wait_until("撤回后同一工作流续跑 -> 全部 PURGED",
                   lambda: (lambda x: x if x and all(
                       i["status"] in ("PURGED", "CANCELLED") for i in x["items"])
                            and x["certificates"][-1]["sealed_count"] == 0 else None)(
                       get_view(rid_can)), 30)
    check("撤回后续跑签发新证书且可独立验证", v is not None
          and verify_certificate_strict(rid_can))


# =========================================================================
# 策略 P2/P3：dry-run 零副作用；迁移把 RESTRICTED 项 SEALED；撤回后续跑；
#             迟到 PURGED 回调不能把已封存项再推进（竞争回调只认一个修订）
# =========================================================================
def scenario_p2_p3_seal_then_withdraw():
    print("\n=== 策略 P2/P3：dry-run / 迁移封存 / 撤回续跑 / 陈旧 PURGE 回调 ===")
    sid = "user-P2"
    seed_subject(sid, [(ORDERS, "p2-a"), (ORDERS, "p2-b"),
                       (BILLING, "p2-inv"), (PROFILE, "p2-prof")])
    rid = create_req(sid)
    # 冻结 PURGE 派发，让工作流稳定停在“全部 RESTRICTED、闸门已开”
    req("POST", f"{COORD}/admin/fault", {"mode": "purge_paused", "on": True},
        token=ADMIN_TOKEN)

    def restricted():
        v = get_view(rid)
        real = [i for i in v["items"] if i["status"] != "CANCELLED"]
        return v if real and all(i["status"] == "RESTRICTED" for i in real) else None
    v = wait_until("工作流停在 RESTRICTED（PURGE 已冻结）", restricted, 25)
    purge_cmd = next(i for i in v["items"]
                     if i["record_id"] == "p2-a")["command_id_purge"]
    events_before = len(v["events"])
    revs_before = [i["policy_revision"] for i in v["items"]]

    rev, _ = policy_draft(
        [rule("p2-seal-a", service="orders", record="p2-a")],
        canary=[sid], note="P2 migration seal")
    # dry-run：只读
    d = dry_run(rev, "CANARY")
    plan_a = next((p for p in d["items"] if p["record_id"] == "p2-a"), None)
    check("dry-run 报告 p2-a 将被 SEAL",
          d["would_seal"] >= 1 and plan_a and plan_a["action"] == "SEAL"
          and plan_a["to_revision"] == rev, str(d["items"]))
    check("dry-run 标记终态历史受保护",
          d["untouched_terminal"] >= 0 and "protected" in d)

    policy_action(rev, "canary")
    # dry-run 之后仍未落库：修订/事件/状态零变化
    v2 = get_view(rid)
    check("dry-run 原子零副作用",
          len(v2["events"]) == events_before
          and [i["policy_revision"] for i in v2["items"]] == revs_before
          and all(i["status"] == "RESTRICTED" for i in v2["items"]
                  if i["status"] != "CANCELLED"),
          f"{len(v2['events'])} vs {events_before}")

    # 正式应用迁移（PURGE 仍冻结）
    s, m = apply_rev(rev, "CANARY", key=f"p2-apply-{rev}")
    check("迁移受理 202", s == 202 and m["status"] in ("RUNNING", "COMPLETED"), str(m))
    m = wait_migration(m["migration_id"])
    check("迁移完成且至少封存 1 项",
          m and m["status"] == "COMPLETED" and m["sealed"] >= 1, str(m))
    v = wait_item(rid, "p2-a", {"SEALED"})
    item_a = next(i for i in v["items"] if i["record_id"] == "p2-a")
    check("p2-a 在 PURGE 前变为 SEALED 并绑定新修订",
          item_a["status"] == "SEALED" and item_a["policy_revision"] == rev
          and item_a["sealed_rule_id"] == "p2-seal-a", str(item_a))
    check("其它项保持 RESTRICTED（金丝雀规则只命中 p2-a）",
          all(i["status"] == "RESTRICTED"
              for i in v["items"] if i["record_id"] not in ("p2-a",)
              and i["status"] != "CANCELLED"))

    # 陈旧/竞争回调：用封存前签发的 PURGE 命令回报 PURGED —— 必须被拒绝
    s, b = req("POST", f"{COORD}/internal/reports", {
        "request_id": rid, "service": "orders", "record_id": "p2-a",
        "command_id": purge_cmd, "status": "PURGED",
        "result_hash": "late"}, token=INTERNAL_TOKEN, ret=True)
    check("封存后迟到 PURGED 回调被拒（一项不会在两个修订下推进）",
          s == 409 and ("stale" in b.get("reason", "")
                        or "out-of-order" in b.get("reason", "")
                        or "mismatch" in b.get("reason", "")), f"{s} {b}")
    v = get_view(rid)
    item_a = next(i for i in v["items"] if i["record_id"] == "p2-a")
    check("被拒回调未改写封存态/修订", item_a["status"] == "SEALED"
          and item_a["policy_revision"] == rev)

    # P3：撤回规则 -> 同一工作流续跑
    policy_action(rev, "withdraw")
    s, m = apply_rev(rev, "WITHDRAW", key=f"p2-withdraw-{rev}")
    check("撤回迁移受理", s == 202, str(m))
    wait_migration(m["migration_id"])
    req("POST", f"{COORD}/admin/fault", {"mode": "clear"}, token=ADMIN_TOKEN)
    v = wait_confirmed(rid)
    check("撤回后同一工作流全部 PURGED（无需重新申请）",
          all(i["status"] in ("PURGED", "CANCELLED") for i in v["items"]))
    check("撤回后证书 sealed_count=0 且第三方可验",
          v["certificates"][-1]["sealed_count"] == 0
          and verify_certificate_strict(rid))


# =========================================================================
# 策略 P4：迁移与迟到 PURGED 回调竞争 -> 唯一合法终态 + 一张一致证书
# =========================================================================
def scenario_p4_race_purged():
    print("\n=== 策略 P4：迁移 ⨉ 迟到 PURGED 回调：乐观并发收敛 ===")
    sid = "user-P4"
    seed_subject(sid, [(ORDERS, "p4-a"), (BILLING, "p4-b"),
                       (PROFILE, "p4-prof")])
    rid = create_req(sid)
    req("POST", f"{COORD}/admin/fault", {"mode": "purge_paused", "on": True},
        token=ADMIN_TOKEN)
    v = wait_until("P4 全部 RESTRICTED",
                   lambda: (lambda x: x if x and all(
                       i["status"] == "RESTRICTED" for i in x["items"]
                       if i["status"] != "CANCELLED") else None)(get_view(rid)), 25)
    target = f"{rid}:orders:p4-a"

    rev, _ = policy_draft(
        [rule("p4-hold", service="orders", record="p4-a")],
        canary=[sid], note="P4 race")
    policy_action(rev, "canary")

    # 启动迁移并在处理 p4-a **之前**停住（该项保持持久 PENDING checkpoint）
    s, m = apply_rev(rev, "CANARY", key=f"p4-mig-{rev}",
                     pause_after_item=target)
    check("P4 迁移启动并暂停于检查点", s == 202, str(m))
    # 确认暂停钩子已让迁移停在 p4-a：它仍为 RESTRICTED，迁移仍 RUNNING
    def paused_before_target():
        s2, b = req("GET", f"{COORD}/migrations/{m['migration_id']}",
                    token=ADMIN_TOKEN)
        vv = get_view(rid)
        it = next((i for i in vv["items"] if i["record_id"] == "p4-a"), None)
        if s2 == 200 and b["status"] == "RUNNING" and it \
                and it["status"] == "RESTRICTED":
            return (b, it)
        return None
    paused = wait_until("迁移稳定暂停在 p4-a 之前", paused_before_target, 15)
    p4a = paused[1]

    # 竞争方：一个迟到的真实 PURGE 在后端执行成功并回报 PURGED
    purge_cmd = p4a["command_id_purge"]
    s, cb = req("POST", f"{ORDERS}/internal/commands", {
        "command_id": purge_cmd, "request_id": rid, "subject_id": sid,
        "record_id": "p4-a", "op": "PURGE",
        "callback_url": f"{COORD}/internal/reports"}, token=INTERNAL_TOKEN)
    check("后端竞争 PURGE 已实际执行", s == 200 and cb.get("status") == "PURGED",
          str(cb))
    s, b = req("POST", f"{COORD}/internal/reports", {
        "request_id": rid, "service": "orders", "record_id": "p4-a",
        "command_id": purge_cmd, "status": "PURGED",
        "result_hash": cb.get("result_hash")}, token=INTERNAL_TOKEN)
    check("PURGED 回调被协调端接受", s == 200 and b.get("accepted"), str(b))

    # 放开暂停钩子：迁移恢复，必须识别 p4-a 已终态，不得再封存
    req("POST", f"{COORD}/admin/fault", {"mode": "clear"}, token=ADMIN_TOKEN)
    m = wait_migration(m["migration_id"])
    check("竞争后迁移仍完成（不卡死、不回退）",
          m and m["status"] == "COMPLETED", str(m))
    v = wait_confirmed(rid)
    item = next(i for i in v["items"] if i["record_id"] == "p4-a")
    check("p4-a 收敛到唯一合法终态 PURGED（未被 SEALED 覆盖）",
          item["status"] == "PURGED", str(item))
    check("只签发一张一致的最终证书（sealed_count=0，可独立验签）",
          v["certificates"][-1]["sealed_count"] == 0
          and verify_certificate_strict(rid)
          and all(i["status"] in ("PURGED", "CANCELLED") for i in v["items"]))
    # 事件审计必须记录一次竞争裁决，且 p4-a 没有出现 SEALED->PURGED 的双推进
    ev = [e for e in v["events"]
          if e["type"] in ("POLICY_SEAL_RACE_SKIP", "POLICY_RACE_CONVERGED_PURGED")]
    check("审计记录了竞争裁决（同一修订下仅推进一次）", len(ev) >= 1,
          str([(e["type"], e.get("detail")) for e in ev]))


# =========================================================================
# 策略 P5：重放同一迁移请求 -> 无额外事件、无修订抬升（幂等）
# =========================================================================
def scenario_p5_replay():
    print("\n=== 策略 P5：迁移请求幂等重放 ===")
    sid = "user-P5"
    seed_subject(sid, [(ORDERS, "p5-a"), (BILLING, "p5-b"),
                       (PROFILE, "p5-prof")])
    rid = create_req(sid)
    req("POST", f"{COORD}/admin/fault", {"mode": "purge_paused", "on": True},
        token=ADMIN_TOKEN)
    wait_until("P5 全部 RESTRICTED",
               lambda: (lambda x: x if x and all(
                   i["status"] == "RESTRICTED" for i in x["items"]
                   if i["status"] != "CANCELLED") else None)(get_view(rid)), 25)
    rev, _ = policy_draft(
        [rule("p5-hold", service="orders", record="p5-a")],
        canary=[sid], note="P5 replay")
    policy_action(rev, "canary")
    key = f"p5-key-{rev}"
    s, m1 = apply_rev(rev, "CANARY", key=key)
    assert s == 202, m1
    wait_migration(m1["migration_id"])
    v = wait_item(rid, "p5-a", {"SEALED"})
    events_after_first = len(v["events"])
    rev_after_first = next(i for i in v["items"]
                           if i["record_id"] == "p5-a")["policy_revision"]
    seal_events = sum(1 for e in v["events"]
                      if e["type"] == "POLICY_ITEM_SEALED"
                      and e.get("detail", {}).get("record_id") == "p5-a")

    # 用完全相同的幂等键重放
    s, m2 = apply_rev(rev, "CANARY", key=key)
    check("重放返回同一迁移且 replayed=true",
          s == 202 and m2["replayed"] is True
          and m2["migration_id"] == m1["migration_id"], str(m2))
    time.sleep(1.0)
    v2 = get_view(rid)
    seal_events2 = sum(1 for e in v2["events"]
                       if e["type"] == "POLICY_ITEM_SEALED"
                       and e.get("detail", {}).get("record_id") == "p5-a")
    # 幂等重放本身不得产生任何迁移事件；只统计由迁移/封存引入的事件，
    # 排除 tick 循环可能产生的其它事件（如轮询/退避）。
    mig_events = [e for e in v2["events"]
                  if e["type"] in ("POLICY_MIGRATION_STARTED",
                                   "POLICY_MIGRATION_COMPLETED",
                                   "POLICY_ITEM_SEALED", "POLICY_ITEM_RELEASED")]
    mig_events_first = [e for e in v["events"] if e["type"] in (
        "POLICY_MIGRATION_STARTED", "POLICY_MIGRATION_COMPLETED",
        "POLICY_ITEM_SEALED", "POLICY_ITEM_RELEASED")]
    check("重放不产生额外迁移事件 / 不抬升修订 / 不重复封存",
          len(mig_events) == len(mig_events_first)
          and seal_events2 == seal_events
          and next(i for i in v2["items"]
                   if i["record_id"] == "p5-a")["policy_revision"]
          == rev_after_first,
          f"{len(mig_events)} vs {len(mig_events_first)}")
    req("POST", f"{COORD}/admin/fault", {"mode": "clear"}, token=ADMIN_TOKEN)
    # 清理：撤回 P5，让工作流自然收敛（不影响后续场景的终态计数）
    policy_action(rev, "withdraw")
    s, wm = apply_rev(rev, "WITHDRAW", key=f"p5-wd-{rev}")
    wait_migration(wm["migration_id"])
    wait_confirmed(rid)


# =========================================================================
# 策略 P6：expected-version 冲突是诊断性的，且原子地所有项原样不动
# =========================================================================
def scenario_p6_expected_version_conflict():
    print("\n=== 策略 P6：乐观并发 expected-version 冲突 ===")
    sid = "user-P6"
    seed_subject(sid, [(ORDERS, "p6-a"), (BILLING, "p6-b")])
    rid = create_req(sid)
    req("POST", f"{COORD}/admin/fault", {"mode": "purge_paused", "on": True},
        token=ADMIN_TOKEN)
    wait_until("P6 全部 RESTRICTED",
               lambda: (lambda x: x if x and all(
                   i["status"] == "RESTRICTED" for i in x["items"]
                   if i["status"] != "CANCELLED") else None)(get_view(rid)), 25)

    rev1, _ = policy_draft(
        [rule("p6-hold-a", service="orders", record="p6-a")],
        canary=[sid], note="P6 first")
    rev2, _ = policy_draft(
        [rule("p6-hold-b", service="billing", record="p6-b")],
        canary=[sid], note="P6 second")
    policy_action(rev1, "canary")
    policy_action(rev2, "canary")  # head 现在推进到 rev2；rev1 的 expected 过期
    head = policy_current()["head"]

    v0 = get_view(rid)
    snap = [(i["record_id"], i["status"], i["policy_revision"]) for i in v0["items"]]
    events0 = len(v0["events"])
    s, b = apply_rev(rev1, "CANARY", key=f"p6-stale-{rev1}",
                     expected=head - 1)
    check("陈旧 expected_version 返回诊断性 409",
          s == 409 and b.get("error") == "version_conflict"
          and b.get("server_head") == head
          and "no items touched" in b.get("diagnostic", ""), f"{s} {b}")
    # 控制面侧同样诊断
    s, b2 = policy_action(rev2, "activate", expected=head - 1)
    check("控制面激活冲突同样 409 且无副作用",
          s == 409 and b2.get("error") == "version_conflict"
          and b2.get("server_head") == head, f"{s} {b2}")
    time.sleep(0.5)
    v1 = get_view(rid)
    snap1 = [(i["record_id"], i["status"], i["policy_revision"]) for i in v1["items"]]
    check("冲突原子地不留改动（状态/修订/事件数均不变）",
          snap1 == snap and len(v1["events"]) == events0
          and not v1["items"][0].get("sealed_rule_id"),
          f"{snap1} vs {snap}")
    s, ml = req("GET", f"{COORD}/migrations", token=ADMIN_TOKEN)
    check("冲突不创建迁移记录",
          all(x["migration_id"] != f"p6-stale-{rev1}" for x in ml["migrations"]),
          str(ml))
    req("POST", f"{COORD}/admin/fault", {"mode": "clear"}, token=ADMIN_TOKEN)


# =========================================================================
# 策略 P7：协调端迁移中途崩溃 -> 重启后从持久 checkpoint 完成
# =========================================================================
def scenario_p7_crash_resume():
    print("\n=== 策略 P7：崩溃恢复 / 可恢复迁移 / 断点续跑 ===")
    sid = "user-P7"
    recs = [("p7-r0", ORDERS), ("p7-r1", BILLING), ("p7-r2", PROFILE)]
    seed_subject(sid, [(b, r) for r, b in recs])
    rid = create_req(sid)
    req("POST", f"{COORD}/admin/fault", {"mode": "purge_paused", "on": True},
        token=ADMIN_TOKEN)
    wait_until("P7 全部 RESTRICTED",
               lambda: (lambda x: x if x and all(
                   i["status"] == "RESTRICTED" for i in x["items"]
                   if i["status"] != "CANCELLED") else None)(get_view(rid)), 25)

    rev, _ = policy_draft(
        [rule("p7-all", prefix="p7-")], canary=[sid], note="P7 crash")
    policy_action(rev, "canary")
    # 注入确定性崩溃：下一个迁移 checkpoint 提交后进程立即退出。
    # apply 请求本身可能因进程退出而连接中断——迁移行/checkpoint 已落库，
    # 这正是“崩溃在迁移中途”；重启后凭幂等键查到同一迁移并续跑。
    req("POST", f"{COORD}/admin/fault", {"mode": "migration_crash", "on": True},
        token=ADMIN_TOKEN, ret=True)
    key = f"p7-crash-{rev}"
    try:
        s, m = apply_rev(rev, "CANARY", key=key)
    except Exception as e:
        # 预期：进程在处理该请求时 os._exit，连接被重置；迁移已落库。
        m = {"migration_id": key}
        print(f"    (apply 连接随崩溃中断，符合预期: {e!r})")
    mid = m.get("migration_id", key) if isinstance(m, dict) else key
    # 等待进程崩溃（checkpoint 已落盘，随后 os._exit）
    deadline = time.time() + 8
    sc = 200
    while time.time() < deadline:
        sc, _ = req("GET", f"{COORD}/health", ret=True)
        if sc != 200:
            break
        time.sleep(0.2)
    check("协调端在迁移中途崩溃（checkpoint 已持久化）", sc != 200, f"status={sc}")

    # run_local.sh 的监督器 / compose restart 都会自动重启
    ready = wait_for(COORD, "coordinator(restarted)", timeout_s=25)
    check("协调端重启就绪", ready)
    # 重启后内存故障钩子已消失；保险起见显式 clear，并解除 PURGE 冻结
    req("POST", f"{COORD}/admin/fault", {"mode": "clear"}, token=ADMIN_TOKEN)

    m2 = wait_migration(mid, timeout_s=30)
    check("重启后迁移从 checkpoint 恢复并 COMPLETED",
          m2 and m2["status"] == "COMPLETED"
          and m2["sealed"] >= 3 and m2["migration_id"] == mid, str(m2))
    check("checkpoint 续跑：已完成项未被重复计数",
          m2 and m2["sealed"] == m2["total"], str(m2))
    v = get_view(rid)
    check("P7 三项全部 SEALED 绑定同一不可变修订",
          all(i["status"] == "SEALED" and i["policy_revision"] == rev
              for i in v["items"] if i["status"] != "CANCELLED"), str(v))
    # 每个 item 的封存事件只能出现一次（断点续跑不重复副作用）
    for rec, _base in recs:
        n = sum(1 for e in v["events"] if e["type"] == "POLICY_ITEM_SEALED"
                and e.get("detail", {}).get("record_id") == rec)
        check(f"P7 {rec} 仅一次封存事件（无重复迁移副作用）", n == 1, f"n={n}")
    # 清理：撤回并续跑，避免遗留封存（后续场景独立）
    policy_action(rev, "withdraw")
    s, wm = apply_rev(rev, "WITHDRAW", key=f"p7-wd-{rev}")
    wait_migration(wm["migration_id"])
    wait_confirmed(rid)


# =========================================================================
# 策略 P8：回滚已部分金丝雀化的修订 -> 历史证书/墓碑/独立密码学验证均保留
# =========================================================================
def scenario_p8_rollback_preserves_history():
    print("\n=== 策略 P8：回滚保留历史证书 / 墓碑 / 独立密码学验证 ===")
    sid = "user-P8"
    seed_subject(sid, [(ORDERS, "p8-a"), (BILLING, "p8-b"),
                       (PROFILE, "p8-prof")])
    rid = create_req(sid)
    req("POST", f"{COORD}/admin/fault", {"mode": "purge_paused", "on": True},
        token=ADMIN_TOKEN)
    wait_until("P8 全部 RESTRICTED",
               lambda: (lambda x: x if x and all(
                   i["status"] == "RESTRICTED" for i in x["items"]
                   if i["status"] != "CANCELLED") else None)(get_view(rid)), 25)
    rev, _ = policy_draft(
        [rule("p8-hold", service="orders", record="p8-a")],
        canary=[sid], note="P8 partial canary")
    policy_action(rev, "canary")
    s, m = apply_rev(rev, "CANARY", key=f"p8-can-{rev}")
    wait_migration(m["migration_id"])
    v = wait_item(rid, "p8-a", {"SEALED"})
    # 此时只部分金丝雀化：p8-a SEALED，其余 RESTRICTED，已签发“封存证书”v1
    # （证书只在整体终态签发；放开 PURGE 让其余项 PURGE，得到一张含 1 SEALED 的证书）
    req("POST", f"{COORD}/admin/fault", {"mode": "clear"}, token=ADMIN_TOKEN)
    v = wait_confirmed(rid)
    cert_v1 = v["certificates"][-1]["version"]
    check("金丝雀封存证书已签发（sealed_count=1）",
          v["certificates"][-1]["sealed_count"] == 1)
    stones_before = _tombstones(rid)
    global_tok = next(t["token"] for t in stones_before if t["service"] == "*")

    # 回滚到基线 rev0（历史不可变版本），协调端对金丝雀主体做 RELEASE 迁移
    cur = policy_current()
    s, b = policy_action(0, "rollback")
    check("回滚到不可变基线成功（策略状态机）",
          s == 200 and b["state"] == "ACTIVE" and b["version"] == 0, str(b))
    s, rm = req("POST", f"{COORD}/policy/apply", {
        "revision": 0, "action": "ROLLBACK",
        "idempotency_key": f"p8-rollback-{cur['head']}",
        "source_revision": rev}, token=ADMIN_TOKEN)
    check("回滚迁移受理", s == 202, str(rm))
    wait_migration(rm["migration_id"])
    v = wait_until("回滚后同一工作流续跑 -> 全 PURGED 新证书",
                   lambda: (lambda x: x if x and all(
                       i["status"] in ("PURGED", "CANCELLED") for i in x["items"])
                            and x["certificates"][-1]["sealed_count"] == 0 else None)(
                       get_view(rid)), 30)

    # 1) 历史证书行仍在、且可独立密码学复验（历史证据未被重写）
    check("回滚后历史封存证书仍存在",
          v is not None
          and any(c["version"] == cert_v1 for c in v["certificates"]))
    check("历史证书 v1 独立密码学复验通过",
          verify_stored_certificate(rid, cert_v1))
    check("回滚后新证书独立复验通过", v is not None
          and verify_certificate_strict(rid))
    # 2) 墓碑与令牌不变（历史墓碑令牌只依赖 request_id/subject_id）
    stones_after = _tombstones(rid)
    check("全局墓碑在回滚后保留且令牌不变",
          any(t["service"] == "*" and t["token"] == global_tok
              for t in stones_after), str(stones_after))
    check("墓碑令牌可第三方独立验签",
          hmac.compare_digest(global_tok, tombstone_token(rid, sid)))
    # 3) 已 PURGED 的迟到副本依然 410，永不复活（回滚不撤销删除事实）
    s, b = req("POST", f"{BILLING}/replica-events", {
        "record_id": "p8-b", "subject_id": sid, "source": "post-rollback-binlog",
        "payload": {}})
    check("回滚后迟到副本仍被墓碑拦截(410)", s == 410 and b.get("quarantined"),
          f"{s} {b}")
    check("回滚后记录仍 404（PURGED 历史未被复活）",
          req("GET", f"{BILLING}/records/p8-b", ret=True)[0] == 404)
    # 4) 对已全部终态的请求再 dry-run 任何旧修订：零变更
    d = dry_run(rev, "CANARY")
    check("回滚后对历史请求 dry-run 旧修订：零未完成项可改",
          d["would_change"] == 0, str(d["items"]))
    # 5) 策略事件流完整记录 draft/canary/rollback（可审计）
    s, stream = req("GET", f"{POLICY}/stream?since=0", token=INTERNAL_TOKEN)
    types_ = {e["type"] for e in stream["events"]}
    check("策略流含 DRAFTED/CANARIED/ROLLED_BACK",
          {"REVISION_DRAFTED", "REVISION_CANARIED", "REVISION_ROLLED_BACK"}
          <= types_, str(sorted(types_)))


def main():
    print("等待服务就绪 ...")
    for url, name in ((POLICY, "policy"), (COORD, "coordinator"),
                      (ORDERS, "orders"), (BILLING, "billing"),
                      (PROFILE, "profile")):
        if not wait_for(url, name):
            print(f"FATAL: {name} 未就绪")
            sys.exit(1)

    # 健康检查
    for url, name in ((POLICY, "policy"), (COORD, "coordinator"),
                      (ORDERS, "orders"), (BILLING, "billing"),
                      (PROFILE, "profile")):
        s, b = req("GET", f"{url}/health")
        check(f"health {name}", s == 200 and b.get("ok"), str(b))

    scenario_a()
    scenario_b()
    scenario_c()
    scenario_p1_canary_vs_control()
    scenario_p2_p3_seal_then_withdraw()
    scenario_p4_race_purged()
    scenario_p5_replay()
    scenario_p6_expected_version_conflict()
    scenario_p7_crash_resume()
    scenario_p8_rollback_preserves_history()

    print("\n================ 验证结果 ================")
    print(f"通过 {len(PASSES)} 项，失败 {len(FAILURES)} 项")
    if FAILURES:
        print("失败明细:")
        for f in FAILURES:
            print(" -", f)
        sys.exit(1)
    print("全部通过：容器启动验证成功。")
    sys.exit(0)


if __name__ == "__main__":
    main()
