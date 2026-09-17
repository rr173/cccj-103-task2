"""删除协调方案的共享原语：证据哈希、Merkle 根、HMAC 签名、时间。

设计原则：
- 只使用 Python 标准库，保证容器内无需任何第三方依赖即可通过启动验证。
- 生产环境可将 HMAC 对称签名替换为非对称签名（Ed25519），验证算法保持不变。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from typing import Any, Iterable

# 生产环境通过环境变量注入；此处给出与 docker-compose 一致的开发默认值。
SIGNING_SECRET = os.environ.get("DELETION_SIGNING_SECRET", "dev-deletion-secret").encode()
GLOBAL_TOMBSTONE_SECRET = os.environ.get(
    "GLOBAL_TOMBSTONE_SECRET", "dev-tombstone-secret"
).encode()


def now_ms() -> int:
    return int(time.time() * 1000)


def iso(ms: int | None = None) -> str:
    if ms is None:
        ms = now_ms()
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ms / 1000))


def canonical(obj: Any) -> bytes:
    """确定性 JSON 序列化：键排序、无空白，保证签名/哈希可复现。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def sign(payload: dict) -> str:
    """对一段可 JSON 序列化的证据负载签名，返回 hex HMAC-SHA256。"""
    return hmac_hex(SIGNING_SECRET, canonical(payload))


def verify_signature(payload: dict, signature: str) -> bool:
    return hmac.compare_digest(sign(payload), signature or "")


def evidence_leaf(item: dict) -> str:
    """单个计划项的证据叶子。

    item 需含：service, subject_id, record_id, status, result_hash,
               hold_code(可空), command_id, updated_at；
               policy_revision 为该工作流绑定的**不可变策略修订**（默认 0）。
    验证方只需这些字段即可独立复算叶子，不依赖协调端数据库。
    """
    leaf_body = {
        "service": item["service"],
        "subject_id": item["subject_id"],
        "record_id": item.get("record_id"),
        "status": item["status"],
        "result_hash": item.get("result_hash"),
        "hold_code": item.get("hold_code"),
        "command_id": item.get("command_id"),
        "policy_revision": item.get("policy_revision", 0),
        "updated_at": item["updated_at"],
    }
    return sha256_hex(canonical(leaf_body))


def merkle_root(leaves: Iterable[str]) -> str:
    """标准成对 Merkle 根；奇数节点复制最后一个。"""
    level = list(leaves)
    if not level:
        return sha256_hex(b"")
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [
            sha256_hex(level[i].encode() + level[i + 1].encode())
            for i in range(0, len(level), 2)
        ]
    return level[0]


def tombstone_token(request_id: str, subject_id: str) -> str:
    """全局墓碑令牌：任何服务/副本凭此即可判断"该主体已被删除，禁止复活"。"""
    body = {"request_id": request_id, "subject_id": subject_id}
    return f"tomb:{hmac_hex(GLOBAL_TOMBSTONE_SECRET, canonical(body))}"


def verify_tombstone_token(request_id: str, subject_id: str, token: str) -> bool:
    return hmac.compare_digest(tombstone_token(request_id, subject_id), token or "")


# -- 合规策略（法律保留 / 财务留存）版本化原语 ------------------------------
# 修订版本内容不可变：规则集 + 金丝雀主体集合的哈希即其身份，
# 协调端拉取后只按哈希缓存，重复拉取必须逐字节一致，否则视为篡改。
def policy_content_hash(rules: list[dict], canary_subjects: list[str]) -> str:
    body = {"canary_subjects": sorted(canary_subjects or []), "rules": rules or []}
    return sha256_hex(canonical(body))


def policy_rule_matches(rule: dict, service: str | None,
                        record_id: str | None) -> bool:
    """规则匹配：service / record_id 精确匹配 + record_prefix 前缀匹配。"""
    m = rule.get("match") or {}
    if m.get("service") and m["service"] != service:
        return False
    if m.get("record_id") and m["record_id"] != record_id:
        return False
    if m.get("record_prefix") and not (record_id or "").startswith(
            m["record_prefix"]):
        return False
    return True
