"""删除协调方案的共享原语：证据哈希、Merkle 根、HMAC 签名、时间、策略规则匹配。

设计原则：
- 只使用 Python 标准库，保证容器内无需任何第三方依赖即可通过启动验证。
- 生产环境可将 HMAC 对称签名替换为非对称签名（Ed25519），验证算法保持不变。
"""
from __future__ import annotations

import fnmatch
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
               hold_code(可空), command_id, updated_at, policy_revision(可空)
    叶子绑定策略修订号：状态迁移所属的合规策略版本由此成为证据的一部分，
    回滚策略不会改写历史证书中的叶子哈希。
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
        "updated_at": item["updated_at"],
        "policy_revision": item.get("policy_revision"),
    }
    return sha256_hex(canonical(leaf_body))


# -- 合规策略规则匹配（策略组件/协调端/验证方共享同一份语义） ----------------
POLICY_ACTIONS = {"SEAL", "RELEASE"}


def normalize_rule(rule: dict) -> dict:
    """校验并规范化一条策略规则；非法规则抛 ValueError。"""
    action = rule.get("action")
    if action not in POLICY_ACTIONS:
        raise ValueError(f"invalid rule action: {action!r}")
    service = rule.get("service")
    record_glob = rule.get("record_glob", "*")
    subject_glob = rule.get("subject_glob", "*")
    hold_code = rule.get("hold_code")
    if not service or not isinstance(service, str):
        raise ValueError("rule requires non-empty service")
    if not isinstance(record_glob, str) or not isinstance(subject_glob, str):
        raise ValueError("record_glob/subject_glob must be strings")
    if action == "SEAL" and not hold_code:
        raise ValueError("SEAL rule requires hold_code")
    return {
        "action": action,
        "service": service,
        "record_glob": record_glob or "*",
        "subject_glob": subject_glob or "*",
        "hold_code": hold_code,
        "hold_reason": rule.get("hold_reason", ""),
        "retention_seconds": int(rule.get("retention_seconds", 0)),
    }


def normalize_rules(rules: list[dict] | None) -> list[dict]:
    return [normalize_rule(r) for r in (rules or [])]


def rule_matches(rule: dict, *, service: str, subject_id: str,
                 record_id: str | None) -> bool:
    """fnmatch glob 匹配：service 精确（大小写敏感），record/subject 支持通配。"""
    if rule.get("service") != service:
        return False
    if not fnmatch.fnmatchcase(subject_id or "", rule.get("subject_glob", "*")):
        return False
    return fnmatch.fnmatchcase(record_id or "", rule.get("record_glob", "*"))


def matching_rule(rules: list[dict], action: str, *, service: str,
                  subject_id: str, record_id: str | None) -> dict | None:
    for rule in rules:
        if rule.get("action") == action and rule_matches(
                rule, service=service, subject_id=subject_id,
                record_id=record_id):
            return rule
    return None


def seal_rule_for(rules: list[dict], *, service: str, subject_id: str,
                  record_id: str | None) -> dict | None:
    return matching_rule(rules, "SEAL", service=service,
                         subject_id=subject_id, record_id=record_id)


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


def policy_content_hash(rules: list[dict]) -> str:
    """修订内容指纹：同一 revision 的规则内容不可变（immutable revision）。

    规则集合与其书写顺序无关（按规范化字节排序后再哈希），
    同语义规则集合无论提交顺序如何都得到同一指纹。
    """
    norm = normalize_rules(rules)
    ordered = sorted(norm, key=canonical)
    return sha256_hex(canonical({"rules": ordered}))
