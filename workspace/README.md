# 跨业务服务的数据删除协调能力（GDPR/合规删除编排参考实现）

一套面向**多个业务服务**的数据删除协调（deletion orchestration）参考实现。
用户提出删除后，协调端先解析其在各服务中的关联身份、生成**带期限的执行计划**，
通过 **Saga 两阶段（RESTRICT → PURGE）** 安全执行；对受**法律保留 / 财务留存**
约束的记录只**封存**不擦除，约束解除后**自动续跑原计划**（无需重新申请）；
能容忍服务回报**重复、乱序、长期失联**；对外给出**可第三方独立证明的最终结果**
（Merkle 证据 + 签名证书）；删除一经对外确认，**全局墓碑（tombstone）**保证
任何迟到副本都无法把数据带回可用状态。

**零第三方依赖**：仅使用 Python 3.11 标准库（`http.server` / `sqlite3` /
`hashlib` / `hmac` / `urllib`），容器内无需 `pip install`，开箱即可通过启动验证。

---

## 0. 版本化合规策略控制面（draft → canary → activate → rollback）

除删除编排外，系统内置一套**版本化的合规策略控制面**（`policy/` 组件），
让操作员能够**起草、金丝雀、激活、撤回/回滚**法律保留（LEGAL_HOLD）或
财务留存（FISCAL_RETENTION）规则：

- **不可变修订（revision）**：每个修订的 `{rules, canary_subjects}` 经规范化哈希
  得到 `content_hash`；版本一经落库内容不可变，重复拉取逐字节校验（防篡改）。
- **每个工作流绑定一个不可变修订**：`requests`/`items` 均带 `policy_revision`，
  并写入 Merkle 证据叶子；新建工作流在创建瞬间按“金丝雀主体命中 CANARY、
  否则 ACTIVE”选版本绑定。
- **生命周期**：`DRAFT → CANARY → ACTIVE`，可 `WITHDRAWN`（撤回）/
  `SUPERSEDED`（被取代）/ `ROLLBACK`（回退到任意历史不可变版本）。
  所有状态推进都支持 `expected_version` 乐观并发，冲突返回**诊断性 409 且
  原子地不写任何状态**。
- **dry-run 只读**：`GET /policy/dry-run?revision=N&action=CANARY` 报告候选修订
  会改变哪些未完成项（`would_seal / would_release / would_rebind`、受影响主体、
  受保护的终态项计数），不产生任何副作用。
- **应用修订 = 幂等、可恢复迁移**：
  - 幂等键 `idempotency_key`：重放同一请求返回既有迁移，**零额外事件、零修订抬升**；
  - 每个计划项一个 durable checkpoint（`migration_items.status`），协调端
    **崩溃后从断点续跑**，已完成的封存/解封绝不重复执行；
  - 逐项 CAS 乐观锁（`report_seq`+当前状态+当前修订守门）：**竞争回调不可能把
    同一项在两个修订下各推进一次**；迁移与迟到 PURGED 回调竞争时收敛到唯一合法
    终态与一张一致证书；
  - **PURGED / FAILED / CANCELLED、ABORTED 请求、已对外认证的终态历史永不重写**；
    撤回/回滚只把“由被撤回修订封存”的项解封，同一工作流续跑，历史证书/墓碑/
    独立密码学证据原样保留。

策略相关接口：策略组件 `/revisions`、`/current`、`/stream`（8090 端口）；
协调端 `/policy/dry-run`、`/policy/apply`、`/migrations/*`、`/policy/revisions/*`。

---

## 1. 需求 → 实现对照

| 需求 | 实现 |
|---|---|
| 删除前先解析各服务关联身份 | `POST /requests` 后引擎并行调用各服务 `/internal/resolve`，把占位计划项替换为真实 `(service, record_id)` 列表；无关联记录的服务标记 `CANCELLED` |
| 生成带期限的执行计划 | 计划含 `deadline`（请求 TTL）、`RESTRICT_SLA_SECONDS`、`PURGE_SLA_SECONDS`；计划落库并发 `PLAN_READY` 事件 |
| 法律保留 / 财务留存只能封存 | 服务在 `RESTRICT` 命中保留策略时返回 `SEALED + hold_code + hold_reason + hold_releases_at`，记录状态 `SEALED`，业务读返回 **423 Locked**，绝不擦除 |
| 约束解除后继续原计划，不重新申请 | 引擎周期轮询 `/internal/holds/{id}`；保留到期后同一 `request_id`、同一计划项从 `SEALED→RESTRICTED→PURGED`，签发证书 **v2**，全程审计 |
| 回报可能重复 | 服务侧命令按 `command_id` 幂等；协调端终态后重复回报返回 `duplicate=true` 且不改状态，全部写 `reports` 审计 |
| 回报可能乱序 | 计划项状态机带序（`STATUS_RANK`），倒退回报拒绝；命令按阶段绑定，**越级回报**（如用 RESTRICT 命令报 PURGED）拒绝并记 `REPORT_REJECTED` |
| 服务长期失联 | 瞬态失败指数退避重试（同 `command_id`）；超过阶段期限标记 `overdue`（继续重试，不终止）；额外**轮询**服务侧命令状态补偿回调丢失 |
| 可证明的最终结果 | 每项服务回报 `result_hash` → 叶子哈希 → **Merkle 根** → 协调端 **HMAC-SHA256 签名证书**；`tests/verifier.py` 从零独立复算验证（不调用协调端自证接口） |
| 安全重试与局部补偿 | Saga：全部 RESTRICT/SEALED 成功后 PURGE 闸门才开放；RESTRICT 阶段永久失败 → 对已 `RESTRICTED` 的项下发 `UNRESTRICT` 补偿 → `ABORTED`，不发证书、不建墓碑。补偿失败也安全重试 |
| 删除确认后迟到副本不得复活 | 确认时写**全局墓碑**（带 HMAC 令牌）并推送各服务；服务 PURGE 与本地墓碑原子提交；`/replica-events`（binlog 重放/缓存回填/对端同步）命中墓碑返回 **410** 并进**检疫区**，永不复活；墓碑反熵还会清除残留记录（SEALED 依法保留） |
| 容器启动验证 | `Dockerfile` + `docker-compose.yml` 提供 **policy** / coordinator / orders / billing / profile / **verifier**；verifier 退出码 0 即通过。无 Docker 时 `scripts/run_local.sh` 等价验证（本地由崩溃监督器自动重启协调端） |

---

## 2. 架构

```
                 ┌────────────────────────────────────────────┐
   操作员策略      │        policy 控制面 :8090                  │
 ─draft/canary──▶ │  SQLite: revisions(DRAFT/CANARY/ACTIVE/     │
  activate/rollback│          WITHDRAWN/SUPERSEDED)/stream     │
                 └───────────────┬────────────────────────────┘
                                 │ 不可变修订 content_hash + expected_version
                 ┌───────────────▼────────────────────────────┐
   用户删除申请  │                coordinator :8080            │
 ─────────────▶│  engine tick loop (状态机/退避/轮询/补偿)     │
 POST /requests │  policy manager: 不可变缓存/dry-run/可恢复迁移│
                │  SQLite: requests/items/reports/events/      │
                │   tombstones/certificates/policy_revisions/  │
                │   migrations/migration_items(checkpoint)     │
                └───┬───────────┬───────────┬─────────────────┘
            /internal/*    /internal/*    /internal/*
            (Bearer 内部令牌)
                ▼               ▼               ▼
          orders:9101     billing:9102     profile:9103     （同一镜像，环境变量区分）
          记录/命令幂等    含法律保留 inv-1   记录/副本检疫
          SEAL/RELEASE    SEAL/RELEASE       SEAL/RELEASE
                └───────────────┴───────────────┘
                         verifier 容器：黑盒 e2e + 独立密码学复验
```

### 计划项状态机

```
PENDING ──RESTRICT命令──▶ DISPATCHED/ERROR ──回报──▶ RESTRICTED ──PURGE闸门──▶ PURGING ──▶ PURGED(终态)
                                   │                    │
                                   └────────▶ SEALED(保留中, 业务423) ─保留解除─▶ RESTRICTED（续跑）
任何阶段永久失败 ─▶ FAILED(终态)；saga 对 RESTRICTED 项 UNRESTRICT 补偿 ─▶ CANCELLED
无关联数据 ─▶ CANCELLED（不进入证书叶子）
```

## 3. 运行

### 方式 A：Docker Compose（推荐的“容器启动验证”）

```bash
# 构建并运行系统 + 独立验证容器（verifier 退出码 0 即成功）
docker compose up --build --abort-on-container-exit verifier

# 或分步
docker compose up -d --build policy coordinator orders billing profile
docker compose run --rm verifier          # 退出码 0 = 全部通过
```

### 方式 B：无容器环境（仅需 python3.11 标准库）

```bash
bash scripts/run_local.sh
# 期望末尾：通过 116 项，失败 0 项 / 全部通过：容器启动验证成功。
```

## 4. 主要 HTTP 接口

协调端：

| 方法/路径 | 说明 |
|---|---|
| `POST /requests` `{subject_id, display_name?, pause_after_resolve?}` | 提交删除申请，返回 `request_id`（202）；创建瞬间绑定不可变策略修订 |
| `GET /requests/{id}` | 计划项状态、阶段期限、overdue、全部审计事件、回报处理记录、证书、`policy_revision` |
| `GET /requests/{id}/tombstones` | 全局/各服务墓碑及推送状态 |
| `GET /internal/requests/{id}/raw`（内部令牌） | 毫秒时间戳原始证据，供第三方严格复验 |
| `POST /internal/reports`（内部令牌） | 服务回报入口：幂等/乱序/越级/封存后陈旧回调判定 |
| `POST /admin/requests/{id}/pause|resume`（管理令牌） | 编排冻结/恢复（演示与故障注入用） |
| `GET /policy/dry-run?revision=N&action=CANARY`（管理令牌） | **只读**：候选修订会改变的未完成项（SEAL/RELEASE/REBIND），不产生副作用 |
| `POST /policy/apply`（管理令牌） | 启动/重放迁移：`{revision, action, idempotency_key?, expected_version?, source_revision?, pause_after_item?}` |
| `GET /migrations` / `GET /migrations/{id}`（管理令牌） | 迁移状态与逐项 durable checkpoint（`done/of`、sealed/released/rebound） |
| `GET /policy/revisions` / `policy/revisions/{v}` / `policy/current`（管理/内部令牌） | 协调端缓存的不可变修订（含 content_hash） |
| `POST /admin/fault`（管理令牌） | 故障注入：`purge_paused` / `migration_crash`（checkpoint 后崩溃）/ `crash` / `clear` |

策略控制面（policy 组件 :8090）：

| 方法/路径 | 说明 |
|---|---|
| `POST /revisions`（管理令牌） | 起草 DRAFT：`{rules:[{id,hold,reason,hold_seconds,match:{service,record_id,record_prefix}}], canary_subjects?, note?}`，返回不可变版本与 content_hash |
| `POST /revisions/{v}/canary\|activate\|withdraw\|rollback`（管理令牌） | 状态推进；body 可带 `expected_version` 做乐观并发，冲突 409 且零写入 |
| `GET /revisions/{v}`（内部/管理令牌） | 不可变修订全文 |
| `GET /current`（内部/管理令牌） | head / active / canaries / watch（最近状态推进的版本） |
| `GET /stream?since=N`（内部/管理令牌） | 版本事件流（协调端乐观并发版本号与状态同步依据） |

业务服务（同一镜像）：

| 方法/路径 | 说明 |
|---|---|
| `POST /seed` | 播种业务数据（命中墓碑返回 410） |
| `GET /records/{id}` | 业务读：ACTIVE 200 / RESTRICTED、SEALED **423** / 删除后 404 |
| `POST /internal/resolve` | 主体关联身份解析 |
| `POST /internal/commands` | 幂等命令：RESTRICT / UNRESTRICT / PURGE / **SEAL / RELEASE（版本化策略封存/解封）** |
| `GET /internal/commands/{id}` | 命令状态查询（协调端补偿回调丢失用） |
| `GET /internal/holds/{id}` | 保留状态（到期自动失效；带 rule_id 区分内置保留与策略封存） |
| `POST /internal/tombstones` | 接收全局墓碑（反熵，令牌验签） |
| `POST /replica-events` | 迟到副本入口：命中墓碑 **410 + 检疫**，不复活 |
| `GET /admin/quarantine` / `POST /admin/fault` | 检疫区 / 故障注入（失联 503、永久 409） |

## 5. 可证明结果（证书）

证书负载（协调端对其 HMAC-SHA256 签名）：

```json
{
  "request_id": "...", "subject_id": "user-A", "version": 1,
  "merkle_root": "...", "issued_at": 1789617000000,
  "item_count": 4, "sealed_count": 1
}
```

每个叶子由 `{service, subject_id, record_id, status, result_hash, hold_code,
command_id, policy_revision, updated_at}` 规范化哈希得到（`policy_revision`
把该计划项绑定的不可变策略修订纳入证据）。验证方（如 verifier）只需：
1. 重算所有叶子哈希并成对折叠得到 Merkle 根，比对证书；
2. 用共享密钥重算 HMAC 签名比对；
3. 用密钥独立验证墓碑令牌。

> 生产化建议：将 HMAC 对称密钥替换为 Ed25519 非对称密钥并公布公钥；
> 内部令牌替换为 mTLS；SQLite 替换为带行锁/事务的数据库；
> 时间与保留期限由统一时钟/保留策略服务提供。

## 6. 验证场景（verifier 自动断言）

- **场景 A**：三服务删除；billing 的 `inv-1` 受 `LEGAL_HOLD` 封存（423）→
  证书 v1（`sealed_count=1`）；伪造/越级/倒序/重复回报全部被正确处理；
  对外确认后各服务迟到副本 410 且不复活、进检疫区；保留解除自动续跑 →
  证书 v2（全部 PURGED）；两版证书独立密码学复验通过。
- **场景 B**：orders 故障注入（内部命令 503 但健康检查正常，模拟失联）→
  超阶段期限标 `overdue`、持续退避重试、不发证书；恢复后同命令幂等收敛确认。
- **场景 C**：billing RESTRICT 一次性 409 永久失败 → 对 orders/profile 已冻结项
  局部补偿（UNRESTRICT）→ `ABORTED`、无证书、无墓碑、失败服务数据未被擦除。
- **策略 P1（金丝雀 vs 对照）**：DRAFT→CANARY 后，金丝雀主体的工作流绑定新修订、
  新匹配的 RESTRICTED 项在任何 PURGE 前变 SEALED；对照队列留在旧修订 rev0 全量 PURGED。
- **策略 P2/P3（dry-run / 迁移封存 / 撤回续跑）**：dry-run 只读零副作用；
  迁移把 RESTRICTED 项 SEALED 并换绑修订，封存后迟到的旧 PURGE 回调被拒；
  WITHDRAW 后同一工作流解封续跑至全 PURGED（无需重新申请）。
- **策略 P4（竞争收敛）**：迁移停在检查点时注入一个真实 PURGE 并回报，恢复后
  收敛到唯一合法终态 PURGED 与一张一致证书，审计记录一次竞争裁决。
- **策略 P5（幂等重放）**：相同 `idempotency_key` 重放返回同一迁移（`replayed=true`），
  不产生额外迁移事件、不抬升修订、不重复封存。
- **策略 P6（乐观并发冲突）**：陈旧 `expected_version` 在控制面与协调端都得到
  诊断性 409（含 server_head/active），且原子地所有项/事件原样不动、不留迁移记录。
- **策略 P7（崩溃恢复）**：在迁移 checkpoint 落库后注入进程崩溃，监督器/compose
  自动重启，迁移从持久断点续跑到 COMPLETED，每个项恰好一次封存事件。
- **策略 P8（回滚保历史）**：部分金丝雀化（已发含 1 项 SEALED 的证书+墓碑）后
  回滚到基线，解封续跑；历史证书行、Merkle 根、HMAC 签名与墓碑令牌均可独立复验，
  PURGED 记录与迟到副本拦截事实不被复活；策略事件流完整可审计。

## 7. 目录

```
common.py                    证据哈希/Merkle/HMAC/墓碑令牌/策略内容哈希与规则匹配
policy/service.py           版本化策略控制面（不可变修订/生命周期/乐观并发/事件流）
coordinator/store.py         SQLite 表结构、状态序、策略/迁移 checkpoint 表
coordinator/engine.py        编排引擎（解析/两阶段/保留续跑/重试/补偿/证书/墓碑/策略强制）
coordinator/policy_manager.py 不可变修订缓存/dry-run 规划器/幂等可恢复迁移/CAS 守门
coordinator/policy_client.py 协调端 -> 策略控制面 HTTP（urllib）
coordinator/http_client.py   出站 HTTP（urllib）
coordinator/app.py           协调端 HTTP API（含 /policy/*、/migrations/*、故障注入）
services/mock_service.py     多服务通用实现（SEAL/RELEASE/封存/幂等命令/墓碑/检疫）
tests/verifier.py          独立 e2e 启动验证（A/B/C 回归 + P1-P8 策略场景，116 项断言）
scripts/run_local.sh       无容器一键验证
Dockerfile, docker-compose.yml
```
