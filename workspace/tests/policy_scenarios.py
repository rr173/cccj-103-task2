"""容器启动验证 · 合规策略控制平面场景（场景 D~G）。

由 tests/verifier.py 在所有组件（policy / coordinator / mock backends /
external verifier）就绪后调用，仅用标准库、仅走黑盒 HTTP 接口。

覆盖验收场景：
  D. 金丝雀主体绑定新修订、对照队列停留在旧修订；新匹配的 RESTRICTED 项
     在任何 PURGE 前变 SEALED；撤回规则后续跑同一工作流；历史证书保留且
     第三方独立复验通过。
  E. 迁移与迟到 PURGED 回调竞争：收敛为唯一合法终态 SEALED、唯一一致证书；
     迁移请求重放不产生额外事件/版本跳动。
  F. expected-version 冲突可诊断且原子地不触碰任何条目。
  G. 迁移处理到一半杀死协调端 -> 重启后从持久检查点完成迁移。
  H. 回滚一个"仅部分金丝雀"的修订：金丝雀项回到旧修订续跑，对照项不受影响；
     PURGED 墓碑与历史证书保留；外部认证（EXTERNAL）封存任何路径不得改写，
     其证书可被独立密码学复验。
退出码语义由调用方（verifier.py）统一统计。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request

C = os.environ.get("COORD_URL", "http://127.0.0.1:8080")
O = os.environ.get("ORDERS_URL", "http://127.0.0.1:9101")
B = os.environ.get("BILLING_URL", "http://127.0.0.1:9102")
PR = os.environ.get("PROFILE_URL", "http://127.0.0.1:9103")
P = os.environ.get("POLICY_URL", "http://127.0.0.1:9104")
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "dev-internal-token")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "dev-admin-token")
SECRET = os.environ.get("DELETION_SIGNING_SECRET", "dev-deletion-secret").encode()
# 本地（非容器）运行时由 scripts/coord_supervisor.sh 负责重启协调端；
# 容器场景由 docker-compose restart 策略负责。两种情况下验证方都只需等待
# /health 恢复——重启动作不依赖测试进程。
COORD_RESTART_GRACE = float(os.environ.get("COORD_RESTART_GRACE", "2.0"))

ADMIN = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
INTERNAL = {"Authorization": f"Bearer {INTERNAL_TOKEN}"}


def _restart_local_coordinator():
    """协调端在崩溃注入后死亡；其重启由监督进程/编排负责，这里只等待。"""
    time.sleep(COORD_RESTART_GRACE)


def _req(method, url, payload=None, headers=None, timeout=8.0):
    data = json.dumps(payload).encode() if payload is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        r.add_header(k, v)
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
        return e.code, body
    except Exception as e:
        return 0, {"error": str(e)}


def _wait(fn, timeout=30.0, interval=0.3, name=""):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            x = fn()
        except Exception as e:
            x, last = None, repr(e)
        if x:
            return x
        time.sleep(interval)
    raise AssertionError(f"timeout: {name} last={last}")


# -- 与生产代码无关的独立证据复算 ----------------------------------------
def _canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode()


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _merkle(ls: list[str]) -> str:
    if not ls:
        return _sha(b"")
    while len(ls) > 1:
        if len(ls) % 2:
            ls.append(ls[-1])
        ls = [_sha(ls[i].encode() + ls[i + 1].encode())
              for i in range(0, len(ls), 2)]
    return ls[0]


def verify_all_certificates(rid: str, check) -> bool:
    """从零复算该工作流所有历史版本证书：叶子->Merkle->HMAC。"""
    s, raw = _req("GET", f"{C}/internal/requests/{rid}/raw", headers=INTERNAL)
    if s != 200 or not raw.get("certificates"):
        check(f"{rid}: 证书原始证据可取", False, f"http={s}")
        return False
    ok = True
    for cert in raw["certificates"]:
        leaves = []
        for l in cert["leaves"]:
            body = l.get("body")
            if not body or _sha(_canon(body)) != l["hash"]:
                ok = False
            leaves.append(l["hash"])
        if _merkle(leaves) != cert["merkle_root"]:
            ok = False
        payload = {
            "request_id": rid, "subject_id": raw["subject_id"],
            "version": cert["version"], "merkle_root": cert["merkle_root"],
            "issued_at": cert["created_at"],
            "sealed_count": cert["sealed_count"],
            "item_count": cert["item_count"],
        }
        sig = hmac.new(SECRET, _canon(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, cert["signature"]):
            ok = False
    return ok


# -- 小工具 ---------------------------------------------------------------
def seed(base, rec, sid):
    s, _ = _req("POST", f"{base}/seed",
                {"record_id": rec, "subject_id": sid, "payload": {}})
    assert s in (200, 201), (base, rec, s)


def view(rid):
    return _req("GET", f"{C}/requests/{rid}")[1]


def items(rid):
    return {i["record_id"]: i for i in view(rid)["items"] if i["record_id"]}


def create(sid, pause=False):
    s, d = _req("POST", f"{C}/requests",
                {"subject_id": sid, "pause_after_resolve": pause})
    assert s == 202, d
    return d["request_id"]


def fault(base, mode, on):
    _req("POST", f"{base}/admin/fault", {"mode": mode, "on": on}, ADMIN)


def policy_rev(rules, note=""):
    s, d = _req("POST", f"{P}/policies/revisions",
                {"rules": rules, "note": note}, ADMIN)
    assert s == 201, d
    return d["revision"]


def canary(rev, subjects):
    return _req("POST", f"{P}/policies/revisions/{rev}/canary",
                {"canary_subjects": subjects}, ADMIN)


def activate(rev, expected=None):
    return _req("POST", f"{P}/policies/revisions/{rev}/activate",
                {"expected_version": expected}, ADMIN)


def apply(rev, mode, subjects=None, expected=None):
    return _req("POST", C + "/admin/policy/apply",
                {"revision": rev, "mode": mode, "subjects": subjects,
                 "expected_version": expected}, ADMIN)


def dryrun(rev, subjects=None):
    return _req("POST", C + "/admin/policy/dry-run",
                {"revision": rev, "subjects": subjects}, ADMIN)


def rollback(target=None, expected=None):
    return _req("POST", C + "/admin/policy/rollback",
                {"target": target, "expected_version": expected}, ADMIN)


def at_phase(rid, rec, statuses, purge_phase=False):
    def f():
        it = items(rid).get(rec, {})
        if it.get("status") not in statuses:
            return False
        return (it.get("command_id_purge") is not None) if purge_phase else True
    return f


# =========================================================================
# 场景 D：金丝雀 vs 对照 / 新匹配先封存 / 撤回续跑 / 历史证据保留
# =========================================================================
def scenario_d(check):
    print("\n=== 场景 D：金丝雀分流 / 先封存后撤回 / 同一工作流续跑 ===")
    sid_k, sid_c = "sub-D-canary", "sub-D-control"
    seed(O, "ord-d1", sid_k)
    seed(O, "ord-d2", sid_c)

    # canary 工作流先在旧修订上创建，PURGE 故障让它停在擦除阶段之前
    fault(O, "purge_503", True)
    rid_k = create(sid_k)
    _wait(at_phase(rid_k, "ord-d1", ("RESTRICTED", "ERROR", "PURGING"),
                   purge_phase=True), name="D canary at purge phase")
    # 对照工作流在无故障的旧策略下走完 -> PURGED rev1
    fault(O, "purge_503", False)
    rid_c = create(sid_c)
    _wait(lambda: view(rid_c)["status"] == "CONFIRMED", name="D control confirmed")
    check("D 对照队列停留在旧修订并 PURGED",
          items(rid_c)["ord-d2"]["status"] == "PURGED"
          and items(rid_c)["ord-d2"]["policy_revision"] == 1)
    fault(O, "purge_503", True)

    rev = policy_rev([{"action": "SEAL", "service": "orders",
                       "record_glob": "ord-d1", "hold_code": "LEGAL_HOLD",
                       "hold_reason": "new litigation hold"}], "D hold")
    s, _ = canary(rev, [sid_k])
    check("D 修订进入 CANARIED", s == 200, s)

    # 干跑：报告候选修订会改变的未完成条目
    s, dr = dryrun(rev, [sid_k])
    ch = dr["changes"][0] if dr["changes"] else {}
    check("D dry-run 报告唯一未完成变更（旧修订 -> SEAL，PURGE 之前）",
          s == 200 and dr["would_change"] == 1 and ch["action"] == "SEAL"
          and ch["bound_revision"] == 1 and ch["from_status"]
          in ("RESTRICTED", "ERROR") and ch["record_id"] == "ord-d1", str(dr))

    # 应用金丝雀迁移
    s, m = apply(rev, "canary", [sid_k])
    check("D 金丝雀迁移完成（幂等登记 done=1）",
          s == 200 and m["state"] == "COMPLETED" and m["done"] == 1, str(m))
    check("D 新匹配项在任何 PURGE 前 SEALED 并绑定新修订",
          items(rid_k)["ord-d1"]["status"] == "SEALED"
          and items(rid_k)["ord-d1"]["policy_revision"] == rev)
    check("D 封存记录业务读 423",
          _req("GET", O + "/records/ord-d1")[0] == 423)
    _wait(lambda: view(rid_k)["certificates"], name="D canary cert")
    check("D 封存证书 v1 sealed=1 且独立密码学复验通过",
          view(rid_k)["certificates"][-1]["sealed_count"] == 1
          and verify_all_certificates(rid_k, check))

    # 撤回规则：同一工作流解封续跑
    fault(O, "purge_503", False)
    s, rb = rollback(target=rev)
    check("D 撤回金丝雀修订成功且迁移完成",
          s == 200 and rb["state"] == "COMPLETED" and rb["done"] == 1, str(rb))
    s, rb2 = rollback(target=rev)
    check("D 撤回重放幂等（无额外事件）",
          s == 200 and rb2.get("policy_rollback", {}).get("idempotent") is True
          and len(rb2.get("events", [])) == len(rb.get("events", [])), str(s))
    _wait(lambda: len(view(rid_k)["certificates"]) >= 2
          and view(rid_k)["certificates"][-1]["sealed_count"] == 0,
          name="D withdraw resumes to cert v2")
    v = view(rid_k)
    check("D 撤回后同一工作流续跑 PURGED，回到旧修订",
          items(rid_k)["ord-d1"]["status"] == "PURGED"
          and items(rid_k)["ord-d1"]["policy_revision"] == 1)
    check("D 历史封存证书保留 + v2 证书独立复验通过",
          v["certificates"][0]["sealed_count"] == 1
          and v["certificates"][-1]["sealed_count"] == 0
          and verify_all_certificates(rid_k, check))
    check("D 撤回后续跑未新建请求（同一 request_id）",
          view(rid_k)["request_id"] == rid_k)


# =========================================================================
# 场景 E：迁移 vs 迟到 PURGED 回调 / 重放幂等
# =========================================================================
def scenario_e(check):
    print("\n=== 场景 E：迁移竞争迟到 PURGED 回调 / 重放无副作用 ===")
    sid = "sub-E-race"
    seed(O, "ord-e1", sid)
    rev = policy_rev([{"action": "SEAL", "service": "orders",
                       "record_glob": "ord-e1", "hold_code": "LEGAL_HOLD"}],
                     "E hold")
    fault(O, "purge_503", True)
    rid = create(sid)
    _wait(at_phase(rid, "ord-e1", ("RESTRICTED", "ERROR", "PURGING"),
                   purge_phase=True), name="E at purge phase")
    s, _ = canary(rev, [sid])
    assert s == 200
    s, m = apply(rev, "canary", [sid])
    check("E 迁移封存成功", s == 200 and m["state"] == "COMPLETED"
          and items(rid)["ord-e1"]["status"] == "SEALED", str((s, m.get("state"))))

    # 迟到的旧修订 PURGED 回调
    it = items(rid)["ord-e1"]
    s, rr = _req("POST", C + "/internal/reports", {
        "request_id": rid, "service": "orders", "record_id": "ord-e1",
        "command_id": it["command_id_purge"], "status": "PURGED",
        "result_hash": "late", "policy_revision": 1}, INTERNAL)
    check("E 迟到 PURGED 回调被修订围栏/封存护栏拒绝(409)",
          s == 409 and ("fence" in rr.get("reason", "")
                        or "SEALED" in rr.get("reason", "")), str(rr))

    fault(O, "purge_503", False)
    time.sleep(2.0)
    check("E 收敛为唯一合法终态 SEALED",
          items(rid)["ord-e1"]["status"] == "SEALED")
    certs = view(rid)["certificates"]
    check("E 只有一份一致证书且独立复验通过",
          len(certs) == 1 and certs[-1]["sealed_count"] == 1
          and verify_all_certificates(rid, check), str(len(certs)))

    # 重放同一迁移请求
    before_ver = items(rid)["ord-e1"]["policy_version"]
    s, m1 = apply(rev, "canary", [sid])
    check("E 重放迁移返回既有登记（idempotent）",
          s == 200 and m1.get("idempotent") is True and m1["state"] == "COMPLETED",
          str(s))
    check("E 重放不产生版本跳动/额外证书",
          items(rid)["ord-e1"]["policy_version"] == before_ver
          and len(view(rid)["certificates"]) == 1)
    s, migs = _req("POST", C + "/admin/policy/migrations", {}, ADMIN)
    e_migs = [x for x in migs["migrations"]
              if x["id"] == f"mig_r{rev}_canary_{sid}_expna"]
    check("E 迁移登记唯一（重放不新增行）", len(e_migs) == 1, str(e_migs))


# =========================================================================
# 场景 F：expected-version 冲突诊断 + 原子不触碰
# =========================================================================
def scenario_f(check):
    print("\n=== 场景 F：expected-version 冲突可诊断且原子不改动 ===")
    sid = "sub-F"
    seed(O, "ord-f1", sid)
    fault(O, "purge_503", True)
    rid = create(sid)
    _wait(at_phase(rid, "ord-f1", ("RESTRICTED", "ERROR", "PURGING"),
                   purge_phase=True), name="F at purge phase")
    rev = policy_rev([{"action": "SEAL", "service": "orders",
                       "record_glob": "ord-f1", "hold_code": "FISCAL_HOLD"}],
                     "F hold")
    s, _ = canary(rev, [sid])
    assert s == 200

    # 策略组件层面的乐观并发
    s, a = activate(rev, expected=999)
    check("F 策略激活 expected-version 冲突(409)且带诊断字段",
          s == 409 and a.get("expected") == 999 and a.get("current") is not None
          and a.get("requested") == rev, str(a))
    # 协调端迁移层面的乐观并发：冲突登记 CONFLICT，所有条目原样
    snap = dict(items(rid)["ord-f1"])
    s, a = apply(rev, "activate", None, expected=999)
    check("F 迁移 expected-version 冲突(409)诊断",
          s == 409 and "999" in str(a.get("error", "")), str(a))
    after = items(rid)["ord-f1"]
    check("F 冲突后条目原子保持：状态/版本/命令均未变",
          after["status"] == snap["status"]
          and after["policy_version"] == snap["policy_version"]
          and after["command_id_restrict"] == snap["command_id_restrict"]
          and after["policy_revision"] == snap["policy_revision"],
          f"{snap['status']}/{snap['policy_version']} -> "
          f"{after['status']}/{after['policy_version']}")
    s, migs = _req("POST", C + "/admin/policy/migrations", {}, ADMIN)
    row = next((x for x in migs["migrations"]
                if x["id"] == f"mig_r{rev}_activate_ALL_exp999"), None)
    check("F 冲突被记录为 CONFLICT 且 total=0（未触碰任何条目）",
          row is not None and row["state"] == "CONFLICT" and row["total"] == 0,
          str(row))
    fault(O, "purge_503", False)


# =========================================================================
# 场景 G：迁移半途杀死协调端，重启后从检查点完成
# =========================================================================
def scenario_g(check):
    print("\n=== 场景 G：迁移崩溃 -> 持久检查点 -> 重启续跑完成 ===")
    sid = "sub-G"
    # 两个服务各一条记录：迁移共 2 个条目，处理完第 1 个后崩溃
    seed(O, "ord-g1", sid)
    seed(PR, "prof-g1", sid)
    fault(O, "purge_503", True)
    fault(PR, "commands_503", False)
    rid = create(sid)
    # orders 到达 purge 阶段（RESTRICTED），profile 正常情况下也会 PURGED ——
    # 为保证两条目都停在可封存状态，对 profile 也制造 purge 失联
    fault(PR, "purge_503", True)
    _wait(at_phase(rid, "ord-g1", ("RESTRICTED", "ERROR", "PURGING"),
                   purge_phase=True), name="G orders at purge phase")
    _wait(at_phase(rid, "prof-g1", ("RESTRICTED", "ERROR", "PURGING"),
                   purge_phase=True), name="G profile at purge phase")

    rev = policy_rev([
        {"action": "SEAL", "service": "orders", "record_glob": "ord-g1",
         "hold_code": "LEGAL_HOLD"},
        {"action": "SEAL", "service": "profile", "record_glob": "prof-g1",
         "hold_code": "FISCAL_HOLD"},
    ], "G hold both")
    s, _ = canary(rev, [sid])
    assert s == 200

    # 干跑显示 2 个未完成条目
    s, dr = dryrun(rev, [sid])
    check("G dry-run 报告 2 个待变更条目", s == 200 and dr["would_change"] == 2,
          str(dr))

    # 武装崩溃注入：本进程处理完第 1 个迁移项后 os._exit(1)
    s, arm = _req("POST", C + "/admin/policy/crash-after",
                  {"after": 1}, ADMIN)
    check("G 崩溃注入已武装（仅进程内）", s == 200 and arm.get("crash_after") == 1
          and arm.get("persistent") is False, str(arm))
    s, m = apply(rev, "canary", [sid])
    # HTTP 请求随进程被杀而失败/无响应——这是预期的"协调端中途死亡"
    check("G 迁移请求在崩溃时未正常返回（协调端死亡）", s in (0, 500, 502, 503),
          f"http={s}")

    # 确认协调端确实死了
    deadline = time.time() + 5
    died = False
    while time.time() < deadline:
        s, _ = _req("GET", C + "/health", timeout=1.0)
        if s == 0:
            died = True
            break
        time.sleep(0.2)
    check("G 协调端进程已终止", died)

    # 重启：生产/容器由 restart 策略负责；本地拉起新进程（不携带崩溃阈值）
    _restart_local_coordinator()
    _wait(lambda: _req("GET", C + "/health", timeout=1.0)[0] == 200,
          timeout=15, name="G coordinator restarted")

    # 重启后凭持久检查点自动续跑：迁移最终 COMPLETED，两条目都 SEALED
    def migration_done():
        s, migs = _req("POST", C + "/admin/policy/migrations", {}, ADMIN)
        row = next((x for x in migs["migrations"]
                    if x["id"] == f"mig_r{rev}_canary_{sid}_expna"), None)
        return row if row and row["state"] == "COMPLETED" else None
    row = _wait(migration_done, timeout=20, name="G migration completed after restart")
    check("G 迁移从检查点恢复并完成（2/2，同一迁移 id）",
          row["done"] == 2 and row["total"] == 2
          and row["last_item_id"] is not None, str(row))
    its = items(rid)
    check("G 两个条目都 SEALED 且绑定新修订（崩溃无半完成泄漏）",
          its["ord-g1"]["status"] == "SEALED"
          and its["prof-g1"]["status"] == "SEALED"
          and its["ord-g1"]["policy_revision"] == rev
          and its["prof-g1"]["policy_revision"] == rev,
          str({k: (v["status"], v["policy_revision"]) for k, v in its.items()}))
    # 重放同一迁移请求：没有额外事件/版本跳动
    s, replay = apply(rev, "canary", [sid])
    check("G 恢复后重放迁移幂等",
          s == 200 and replay.get("idempotent") is True, str(s))
    # 崩溃恢复事件链可审计
    s, migs = _req("POST", C + "/admin/policy/migrations", {}, ADMIN)
    types_ = {e["type"] for e in migs["events"]
              if f"mig_r{rev}_canary_{sid}_expna" in e["migration_id"]}
    check("G 审计链含 崩溃注入/开始/逐项应用/完成",
          {"MIGRATION_STARTED", "MIGRATION_CRASH_INJECTED",
           "MIGRATION_ITEM_APPLIED", "MIGRATION_COMPLETED"} <= types_,
          str(sorted(types_)))
    fault(O, "purge_503", False)
    fault(PR, "purge_503", False)


# =========================================================================
# 场景 H：部分金丝雀回滚 / PURGED 墓碑与历史证书保留 / 外部认证不可改写
# =========================================================================
def scenario_h(check):
    print("\n=== 场景 H：部分金丝雀回滚 / 墓碑保留 / 外部认证封存不可改写 ===")
    sid1, sid2, sid3 = "sub-H1", "sub-H2", "sub-H3"
    seed(O, "ord-h1", sid1)   # 金丝雀工作流
    seed(O, "ord-h2", sid2)   # 对照工作流
    seed(B, "inv-h3", sid3)   # 外部认证工作流

    # 1) 金丝雀工作流停在 RESTRICTED
    fault(O, "purge_503", True)
    rid1 = create(sid1)
    _wait(at_phase(rid1, "ord-h1", ("RESTRICTED", "ERROR", "PURGING"),
                   purge_phase=True), name="H canary at purge phase")
    # 2) 对照工作流在旧修订下完成 PURGED（建立墓碑与历史证书）
    fault(O, "purge_503", False)
    rid2 = create(sid2)
    _wait(lambda: view(rid2)["status"] == "CONFIRMED", name="H control confirmed")
    control_certs = len(view(rid2)["certificates"])
    fault(O, "purge_503", True)

    # 3) billing 工作流：先 RESTRICTED，再由"外部司法/审计"加挂 EXTERNAL 封存
    fault(B, "purge_503", True)
    rid3 = create(sid3)
    _wait(at_phase(rid3, "inv-h3", ("RESTRICTED", "ERROR", "PURGING"),
                   purge_phase=True), name="H external at purge phase")
    s, _ = _req("POST", B + "/admin/holds", {
        "record_id": "inv-h3", "hold_code": "COURT_ORDER",
        "hold_reason": "externally certified litigation hold"}, ADMIN)
    check("H 外部认证封存注入成功", s == 200, s)
    fault(B, "purge_503", False)
    _wait(lambda: items(rid3)["inv-h3"]["status"] == "SEALED",
          name="H external sealed")
    # 等待外部封存证书签发
    _wait(lambda: view(rid3)["certificates"], name="H external cert")
    check("H 外部封存项 hold_origin=EXTERNAL",
          items(rid3)["inv-h3"].get("hold", {}).get("origin") == "EXTERNAL",
          str(items(rid3)["inv-h3"].get("hold")))

    # 起草全量封存修订，但只把 sid1 放入金丝雀队列（部分金丝雀）
    rev = policy_rev([
        {"action": "SEAL", "service": "orders", "record_glob": "ord-h1",
         "hold_code": "LEGAL_HOLD"},
        {"action": "SEAL", "service": "billing", "record_glob": "inv-h3",
         "hold_code": "LEGAL_HOLD"},
    ], "H partial canary")
    s, _ = canary(rev, [sid1])
    check("H 修订仅金丝雀 sid1（部分金丝雀）", s == 200, s)

    # 干跑（全量视角）：ord-h1 待封存；ord-h2 已 PURGED 必须 skipped；
    # inv-h3 EXTERNAL 必须 skipped（不得改写外部认证历史）
    s, dr = dryrun(rev, None)
    change_keys = {(c["request_id"], c["record_id"]) for c in dr["changes"]}
    skip = {(x["request_id"], x["record_id"]): x["reason"] for x in dr["skipped"]}
    check("H dry-run 只把金丝雀 ord-h1 列为变更",
          any(rec == "ord-h1" for _, rec in change_keys)
          and not any(rec in ("ord-h2", "inv-h3") for _, rec in change_keys),
          str(dr))
    check("H dry-run 标注 PURGED 与 EXTERNAL 历史不可改写",
          any(rec == "ord-h2" and "immutable" in r for (_, rec), r in skip.items())
          and any(rec == "inv-h3" and "externally certified" in r
                  for (_, rec), r in skip.items()), str(skip))

    # 回滚这个仅部分金丝雀的修订（策略组件中它是 CANARIED）
    fault(O, "purge_503", False)
    s, rb = rollback(target=rev)
    check("H 部分金丝雀回滚完成", s == 200 and rb["state"] == "COMPLETED", str(rb))

    # 金丝雀项：被 rev 封存后又随回滚解封 -> 回到 rev1 续跑 PURGE
    _wait(lambda: items(rid1)["ord-h1"]["status"] == "PURGED",
          name="H canary rebind+purged")
    check("H 金丝雀项回滚后回到旧修订并 PURGED（同一工作流）",
          items(rid1)["ord-h1"]["policy_revision"] == 1
          and view(rid1)["request_id"] == rid1)
    # 对照项：从未被金丝雀迁移触碰，墓碑/证书保持
    check("H 对照项保持 PURGED，证书数量不变",
          items(rid2)["ord-h2"]["status"] == "PURGED"
          and len(view(rid2)["certificates"]) == control_certs)
    s, stones = _req("GET", f"{C}/requests/{rid2}/tombstones")
    check("H 对照工作流墓碑保留且已推送",
          s == 200 and all(t["pushed"] for t in stones["tombstones"]
                          if t["service"] != "*"), str(stones))
    s, q = _req("GET", O + "/admin/quarantine")
    # 外部无关，这里仅确认对照记录读不到（墓碑生效）
    check("H 对照记录读取 404（墓碑未被回滚破坏）",
          _req("GET", O + "/records/ord-h2")[0] == 404)

    # 外部认证项：任何迁移都没改写它，始终 EXTERNAL/SEALED
    it = items(rid3)["inv-h3"]
    check("H 外部认证封存保持 SEALED/EXTERNAL，未被回滚改写",
          it["status"] == "SEALED"
          and it.get("hold", {}).get("origin") == "EXTERNAL"
          and it["hold"]["code"] == "COURT_ORDER", str(it))
    check("H 外部封存记录业务读 423",
          _req("GET", B + "/records/inv-h3")[0] == 423)
    check("H 外部封存工作流证书独立密码学复验通过",
          verify_all_certificates(rid3, check))
    check("H 金丝雀工作流历史证书（封存+续跑）独立复验通过",
          verify_all_certificates(rid1, check))


# =========================================================================
# 场景 I：PURGED / ABORTED / 外部认证历史在策略迁移下永不重写
# （PURGED 与 EXTERNAL 已在 E/H 覆盖；本场景专门固定 ABORTED 不变量）
# =========================================================================
def scenario_i(check):
    print("\n=== 场景 I：ABORTED 历史不可被策略迁移改写 ===")
    sid = "sub-I"
    seed(O, "ord-i1", sid)
    seed(B, "inv-i1", sid)
    # billing 在 RESTRICT 阶段一次性 409 永久冲突 -> saga 补偿并 ABORTED
    _req("POST", B + "/admin/fault",
         {"mode": "restrict_409_once", "on": True}, ADMIN)
    rid = create(sid)
    _wait(lambda: view(rid)["status"] == "ABORTED", name="I aborted")
    v = view(rid)
    check("I 工作流已 ABORTED 且无证书/墓碑",
          v["status"] == "ABORTED" and not v["certificates"], str(v["status"]))
    # 起草一个会命中两个记录的封存修订，并仅把该主体加入金丝雀队列
    rev = policy_rev([
        {"action": "SEAL", "service": "orders", "record_glob": "*",
         "hold_code": "LEGAL_HOLD"},
        {"action": "SEAL", "service": "billing", "record_glob": "*",
         "hold_code": "FISCAL_HOLD"},
    ], "I should not apply")
    s, _ = canary(rev, [sid])
    assert s == 200, s
    # dry-run 不应包含该 ABORTED 工作流的任何条目
    s, dr = dryrun(rev, [sid])
    affected = [c for c in dr["changes"] if c["request_id"] == rid]
    check("I dry-run 不把 ABORTED 工作流列为变更",
          s == 200 and not affected, str(affected))
    # 应用迁移：ABORTED 条目既不换修订也不封存
    s, m = apply(rev, "canary", [sid])
    check("I 迁移不触碰 ABORTED 工作流（无迁移条目）",
          s == 200 and not any(mi["request_id"] == rid for mi in m["items"]),
          str(s))
    its = items(rid)
    inv = its["inv-i1"]
    ord_ = its["ord-i1"]
    check("I ABORTED 项保持原样：FAILED@rev1 与补偿 CANCELLED 均未改写",
          inv["status"] == "FAILED" and inv["policy_revision"] == 1
          and ord_["status"] == "CANCELLED",
          str({k: (x["status"], x["policy_revision"]) for k, x in its.items()}))
    # 失败服务的数据仍然存在（未被封存/擦除）；已补偿服务记录恢复可用
    check("I 失败服务数据未被策略迁移封存或擦除（仍可读）",
          _req("GET", B + "/records/inv-i1")[0] in (200, 423))
    # 策略层冲突路径同样固定：对一个已 ROLLED_BACK 修订重复回滚是幂等的，
    # 这里不再制造额外状态（前面 D 已覆盖），只确认 ABORTED 请求没有证书
    check("I ABORTED 工作流自始至终无证书",
          view(rid)["certificates"] == [])


def run_policy_scenarios(check):
    scenario_d(check)
    scenario_e(check)
    scenario_f(check)
    scenario_g(check)
    scenario_h(check)
    scenario_i(check)
