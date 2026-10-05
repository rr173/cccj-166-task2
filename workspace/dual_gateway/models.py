"""状态机常量。

指令 (command) 级状态::

    PENDING ──确认──▶ CONFIRMED ──全部设备回执──▶ EXECUTED / PARTIAL_FAILED
       │                 │
       │             窗口过期/离线未达
       │                 ▼
       ├─拒绝─▶ REJECTED  EXPIRED（未确认）/ CLOSED（已确认但有未达目标）
       ├─超时─▶ EXPIRED
       └─撤销─▶ REVOKED（仅当尚无任何设备实际执行时允许）

目标 (command_target, 指令×单设备) 级状态::

    PENDING 未下发
    DISPATCHED 已投递给设备（设备已拉取）
    DOUBT 网关重启后、或长时间无回执，是否执行未知，需设备账本对账
    EXECUTED / FAILED 设备回执确认（终态，事实不可覆盖）
    SKIPPED 确认前设备被移出 / 指令未确认而冻结（终态）
    MISSED 窗口关闭时尚未下发成功（终态）
"""
from __future__ import annotations

# 指令级
CMD_PENDING = "PENDING"
CMD_CONFIRMED = "CONFIRMED"
CMD_EXECUTED = "EXECUTED"
CMD_PARTIAL_FAILED = "PARTIAL_FAILED"
CMD_REJECTED = "REJECTED"
CMD_EXPIRED = "EXPIRED"
CMD_REVOKED = "REVOKED"
CMD_CLOSED = "CLOSED"

CMD_TERMINAL = {
    CMD_EXECUTED, CMD_PARTIAL_FAILED, CMD_REJECTED,
    CMD_EXPIRED, CMD_REVOKED, CMD_CLOSED,
}

# 目标级
TGT_PENDING = "PENDING"
TGT_DISPATCHED = "DISPATCHED"
TGT_DOUBT = "DOUBT"
TGT_EXECUTED = "EXECUTED"
TGT_FAILED = "FAILED"
TGT_SKIPPED = "SKIPPED"
TGT_MISSED = "MISSED"

TGT_TERMINAL = {TGT_EXECUTED, TGT_FAILED, TGT_SKIPPED, TGT_MISSED}

# 回执结果
RESULT_EXECUTED = "EXECUTED"
RESULT_FAILED = "FAILED"

# 回执来源
SRC_RECEIPT = "RECEIPT"          # 设备正常上送
SRC_LEDGER = "LEDGER_RECOVERY"   # 重连/重启后从设备持久账本补记

# 审计动作分类
AUDIT_BIZ = "BIZ"
AUDIT_SEC = "SECURITY"
AUDIT_DEV = "DEVICE"
AUDIT_SYS = "SYSTEM"
