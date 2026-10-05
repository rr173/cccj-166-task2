"""密码学与摘要工具（全部使用标准库）。

* 指令参数采用确定性规范化 JSON 计算 SHA-256 摘要：创建时冻结，
  确认时第二角色必须复核摘要，防止"创建的指令"与"看到的指令"被调包；
* 设备通道使用 HMAC-SHA256 对请求体做签名（共享密钥预置）；
* 带外确认码仅在创建响应中返回一次明文，库存的是其哈希值；
* 审计事件链：event_hash_n = SHA256(prev_hash || canonical(payload))。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from typing import Any

GENESIS_HASH = "0" * 64


def canonical_json(obj: Any) -> str:
    """键排序、无多余空白、不转义非 ASCII 的确定性 JSON。"""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def digest_payload(payload: dict) -> str:
    """计算冻结负载摘要（设备集合 + 参数 + 时间窗口）。"""
    frozen = {
        "devices": sorted(payload.get("devices", [])),
        "params": payload.get("params", {}),
        "valid_from": payload.get("valid_from"),
        "valid_to": payload.get("valid_to"),
        "action": payload.get("action", ""),
    }
    return sha256_hex(canonical_json(frozen))


def new_confirm_code() -> str:
    """6 位带外确认码（安全通道在创建指令后通过独立手段告知第二角色）。"""
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_confirm_code(code: str) -> str:
    # 加服务侧盐，避免码空间小被反查
    return sha256_hex("gw-confirm-code/v1:" + code)


def new_session_id() -> str:
    return secrets.token_urlsafe(24)


def new_boot_code() -> str:
    """设备启动代号：设备每次冷启动生成的随机高熵代号。"""
    return "BOOT-" + secrets.token_hex(10).upper()


def hmac_sign(key: str, message: bytes) -> str:
    return hmac.new(key.encode("utf-8"), message, hashlib.sha256).hexdigest()


def verify_hmac(key: str, message: bytes, signature: str) -> bool:
    return hmac.compare_digest(hmac_sign(key, message), signature or "")


def event_hash(prev_hash: str, event_type: str, payload: dict) -> str:
    body = canonical_json({"prev": prev_hash, "type": event_type, "payload": payload})
    return sha256_hex(body)
