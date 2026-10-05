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


# ================= 现场执行账簿（带签名 / 代次内哈希链 / 指令指纹）=================
LEDGER_GENESIS = "0" * 64


def ledger_entry_hash(boot_code: str, seq: int, command_id: str,
                      result: str, prev: str) -> str:
    """账簿条目哈希：把启动代号（代次）、单调序号、指令 ID、执行结果与上一条
    哈希串成代次内哈希链。篡改/重排任何字段都会断链。"""
    body = canonical_json({"boot_code": boot_code, "seq": seq,
                           "command_id": command_id, "result": result,
                           "prev": prev})
    return sha256_hex(body)


def command_fingerprint(command_id: str, digest: str | None = None) -> str:
    """指令指纹：指令 ID + 创建时冻结摘要。设备执行时核对，防止条目被改挂到
    别的指令上（只改 command_id 而不持有冻结摘要即可被识别）。"""
    return sha256_hex(canonical_json(
        {"command_id": command_id, "digest": digest or ""}))


def sign_ledger_entry(key: str, entry_hash: str) -> str:
    """设备密钥对条目哈希逐条 HMAC 签名。"""
    return hmac_sign(key, entry_hash.encode("utf-8"))


def verify_ledger_entry_signature(key: str, entry_hash: str, signature: str) -> bool:
    return verify_hmac(key, entry_hash.encode("utf-8"), signature or "")
