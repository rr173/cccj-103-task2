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
| 容器启动验证 | `Dockerfile` + `docker-compose.yml` 提供 coordinator / orders / billing / profile / **verifier**；verifier 退出码 0 即通过。无 Docker 时 `scripts/run_local.sh` 等价验证 |

---

## 2. 架构

```
                 ┌────────────────────────────────────────────┐
   用户删除申请  │                coordinator :8080            │
 ─────────────▶│  engine tick loop (状态机/退避/轮询/补偿)     │
 POST /requests │  SQLite: requests/items/reports/events/      │
                │          tombstones/certificates            │
                └───┬───────────┬───────────┬─────────────────┘
            /internal/*    /internal/*    /internal/*
            (Bearer 内部令牌)
                ▼               ▼               ▼
          orders:9101     billing:9102     profile:9103     （同一镜像，环境变量区分）
          记录/命令幂等    含法律保留 inv-1   记录/副本检疫
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
docker compose up -d --build coordinator orders billing profile
docker compose run --rm verifier          # 退出码 0 = 全部通过
```

### 方式 B：无容器环境（仅需 python3.11 标准库）

```bash
bash scripts/run_local.sh
# 期望末尾：通过 58 项，失败 0 项 / 全部通过：容器启动验证成功。
```

## 4. 主要 HTTP 接口

协调端：

| 方法/路径 | 说明 |
|---|---|
| `POST /requests` `{subject_id, display_name?, pause_after_resolve?}` | 提交删除申请，返回 `request_id`（202） |
| `GET /requests/{id}` | 计划项状态、阶段期限、overdue、全部审计事件、回报处理记录、证书 |
| `GET /requests/{id}/tombstones` | 全局/各服务墓碑及推送状态 |
| `GET /internal/requests/{id}/raw`（内部令牌） | 毫秒时间戳原始证据，供第三方严格复验 |
| `POST /internal/reports`（内部令牌） | 服务回报入口：幂等/乱序/越级判定 |
| `POST /admin/requests/{id}/pause|resume`（管理令牌） | 编排冻结/恢复（演示与故障注入用） |

业务服务（同一镜像）：

| 方法/路径 | 说明 |
|---|---|
| `POST /seed` | 播种业务数据（命中墓碑返回 410） |
| `GET /records/{id}` | 业务读：ACTIVE 200 / RESTRICTED、SEALED **423** / 删除后 404 |
| `POST /internal/resolve` | 主体关联身份解析 |
| `POST /internal/commands` | 幂等命令：RESTRICT / UNRESTRICT / PURGE |
| `GET /internal/commands/{id}` | 命令状态查询（协调端补偿回调丢失用） |
| `GET /internal/holds/{id}` | 保留状态（到期自动失效） |
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
command_id, updated_at}` 规范化哈希得到。验证方（如 verifier）只需：
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

## 7. 目录

```
common.py                  证据哈希/Merkle/HMAC/墓碑令牌原语
coordinator/store.py       SQLite 表结构与状态序
coordinator/engine.py      编排引擎（解析/两阶段/保留续跑/重试/补偿/证书/墓碑）
coordinator/http_client.py 出站 HTTP（urllib）
coordinator/app.py         协调端 HTTP API
services/mock_service.py   多服务通用实现（封存/幂等命令/墓碑/副本检疫/故障注入）
tests/verifier.py          独立 e2e 启动验证（58 项断言，退出码即结论）
scripts/run_local.sh       无容器一键验证
Dockerfile, docker-compose.yml
```
