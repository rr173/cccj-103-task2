"""版本化合规策略控制面（policy component）。

法律保留 / 财务留存规则以**不可变修订版本**（revision）为单位管理，
生命周期：DRAFT（起草）→ CANARY（金丝雀）→ ACTIVE（激活）→
可 WITHDRAWN（撤回）/ SUPERSEDED（被取代）；亦可 ROLLBACK 回退到历史版本。

关键不变量：
- 版本一经写入即不可变：`content_hash` 绑定规则集与金丝雀主体，重复读取逐字节一致。
- 同一时刻最多一个 ACTIVE；激活/撤回/回退都走乐观并发 `expected_version`。
- 协调端的迁移（migration）完成后才推进策略状态机（PENDING_APPLIED→生效），
  因此“金丝雀主体拿到新版本、对照主体留在旧版本”可被外部严格证明。

仅使用 Python 标准库 + SQLite。
"""
