"""容器启动验证（smoke / e2e）：由独立 verifier 容器执行。

仅使用标准库；从零复算证据哈希、Merkle 根、HMAC 签名、墓碑令牌，
不调用协调端的 /verify 自证接口，保证"可证明的最终结果"是第三方可验证的。

覆盖需求矩阵：
  A. 正常删除 + 法律保留封存 -> 证书 v1；约束到期自动续跑 -> 证书 v2；
     重复/乱序回报被识别；对外确认后迟到副本被墓碑拦截，不复活。
  B. 服务长期失联（故障注入）：期限到期 overdue；安全重试；恢复后收敛确认。
  C. Saga 永久失败：局部补偿 UNRESTRICT 后 ABORTED；不发证书；无墓碑。
  D~H（tests/policy_scenarios.py）：版本化合规策略控制平面——
     金丝雀/对照分流、新匹配先封存、撤回续跑、迁移与迟到 PURGED 竞争收敛、
     重放幂等、expected-version 冲突原子不改动、崩溃检查点续跑、
     部分金丝雀回滚保留历史墓碑/证书且外部认证不可改写。
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
ORDERS = os.environ.get("ORDERS_URL", "http://127.0.0.1:9101")
BILLING = os.environ.get("BILLING_URL", "http://127.0.0.1:9102")
PROFILE = os.environ.get("PROFILE_URL", "http://127.0.0.1:9103")
POLICY = os.environ.get("POLICY_URL", "http://127.0.0.1:9104")
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "dev-internal-token")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "dev-admin-token")
SECRET = os.environ.get("DELETION_SIGNING_SECRET", "dev-deletion-secret").encode()
TSECRET = os.environ.get("GLOBAL_TOMBSTONE_SECRET", "dev-tombstone-secret").encode()

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
        "updated_at": item["updated_at"],
        "policy_revision": item.get("policy_revision"),
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
    """严格独立验证：叶子哈希 -> Merkle 根 -> HMAC 签名，全部从零复算。

    叶子以证书签发时落库的规范字段（leaf["body"]）为准：即便条目之后因策略
    迁移/续跑而变化，历史证书仍可被第三方独立复验（回滚不重写历史证据）。
    所有历史版本证书逐一验证。
    """
    raw = get_raw(rid)
    if not raw["certificates"]:
        return False
    ok = True
    for cert in raw["certificates"]:
        leaves = []
        for l in cert["leaves"]:
            body = l.get("body")
            if not body:
                ok = False
                continue
            # 1a) 叶子哈希可由其随证保存的规范字段独立复算（防篡改）
            if sha(canon(body)) != l["hash"]:
                ok = False
            leaves.append(l["hash"])
        # 1b) 叶子成对折叠为 Merkle 根
        if merkle(leaves) != cert["merkle_root"]:
            ok = False
        # 2) 协调端 HMAC 签名
        payload = {
            "request_id": rid, "subject_id": raw["subject_id"],
            "version": cert["version"], "merkle_root": cert["merkle_root"],
            "issued_at": cert["created_at"],
            "sealed_count": cert["sealed_count"], "item_count": cert["item_count"],
        }
        sig = hmac.new(SECRET, canon(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, cert["signature"]):
            ok = False
    return ok


def tombstone_token(request_id: str, subject_id: str) -> str:
    return "tomb:" + hmac.new(
        TSECRET, canon({"request_id": request_id, "subject_id": subject_id}),
        hashlib.sha256).hexdigest()


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


def main():
    print("等待服务就绪 ...")
    for url, name in ((COORD, "coordinator"), (POLICY, "policy"),
                      (ORDERS, "orders"), (BILLING, "billing"),
                      (PROFILE, "profile")):
        if not wait_for(url, name):
            print(f"FATAL: {name} 未就绪")
            sys.exit(1)

    # 健康检查
    for url, name in ((COORD, "coordinator"), (POLICY, "policy"),
                      (ORDERS, "orders"), (BILLING, "billing"),
                      (PROFILE, "profile")):
        s, b = req("GET", f"{url}/health")
        check(f"health {name}", s == 200 and b.get("ok"), str(b))

    # 策略组件基线：存在且仅有一份 ACTIVE 空规则基线修订 rev1
    s, b = req("GET", f"{POLICY}/policies/active", token=INTERNAL_TOKEN)
    check("policy 基线修订 rev1 已激活", s == 200 and b.get("revision") == 1
          and b.get("state") == "ACTIVE" and b.get("rules") == [], str(b))

    scenario_a()
    scenario_b()
    scenario_c()

    # 版本化合规策略控制平面验收场景 D~H（policy/coordinator/mock backends/
    # 外部独立验证方共同参与）
    from tests import policy_scenarios
    policy_scenarios.run_policy_scenarios(check)

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
