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
    MISSED 窗口关闭时尚未下发成功（终态；但若之后签名账簿补证已执行，
           事实优先，目标改写为 EXECUTED/FAILED）

事故恢复对账工单 (recovery_ticket, 指令×单设备，唯一)::

    OPEN ──签名账簿补记事实──▶ RESOLVED/FACT_RECOVERED
      │  ──正常回执形成事实──▶ RESOLVED/FACT_REPORTED
      │  ──确认未执行+窗口内─▶ 仍 OPEN（已重置可投递，重投后随回执解决）
      │  ──窗口外/过期───────▶ RESOLVED/CLOSED_MISSED
      └─人工处置（仅安全角色）：备注、批准重投、定 MISSED；
        任何人工处置都不能写入或覆盖 EXECUTED/FAILED 执行事实。
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

# 事故恢复对账工单（recovery ticket）
# 每个“已送达现场但缺少终态回报”的目标在网关重启/窗口关闭后挂一张工单，
# 只允许安全通道角色查看与处置；设备重连上传签名账簿后由系统自动对账。
TKT_OPEN = "OPEN"
TKT_RESOLVED = "RESOLVED"

TKT_TERMINAL = {TKT_RESOLVED}

# 工单挂起原因
TKT_REASON_RESTART = "RESTART_NO_TERMINAL"  # 服务重启：已投递无终态
TKT_REASON_WINDOW = "WINDOW_CLOSED"         # 有效窗口关闭时仍在途
TKT_REASON_DOUBT = "UNRESOLVED_DOUBT"       # 重启前已挂起但无工单的存量 DOUBT

# 工单处置历史动作
ACT_CREATED = "CREATED"
ACT_NOTE = "MANUAL_NOTE"
ACT_FACT_REPORTED = "FACT_REPORTED"                 # 正常回执形成事实
ACT_FACT_RECOVERED = "FACT_RECOVERED"               # 签名账簿补记事实
ACT_FACT_AFTER_MISSED = "FACT_RECOVERED_AFTER_MISSED"  # 账簿推翻陈旧 MISSED 结论
ACT_REDELIVERED = "REDELIVER_AFTER_REBOOT"          # 系统确认未执行后自动重投
ACT_REDELIVER_APPROVED = "APPROVE_REDELIVER"        # 安全员人工批准重投
ACT_MISSED = "CLOSED_MISSED"                        # 系统/人工按过期定 MISSED
ACT_LEDGER_CONFLICT = "LEDGER_CONFLICT"             # 账簿材料冲突，已隔离

# 人工处置动作集合（任何人工动作都不能直接形成执行事实）
MANUAL_ACTIONS = {ACT_NOTE, ACT_REDELIVER_APPROVED, ACT_MISSED}

# 账簿隔离原因（编号缺口 / 矛盾记录 / 过期时限 / 旧代次材料等只隔离留痕）
Q_BAD_ENTRY = "LEDGER_BAD_ENTRY"
Q_ENTRY_HASH = "LEDGER_ENTRY_HASH"
Q_SIGNATURE = "LEDGER_BAD_SIGNATURE"
Q_UNKNOWN_BOOT = "LEDGER_UNKNOWN_BOOT"
Q_FINGERPRINT = "LEDGER_FINGERPRINT_MISMATCH"
Q_NEVER_DISPATCHED = "LEDGER_NEVER_DISPATCHED"
Q_CHAIN_BROKEN = "LEDGER_CHAIN_BROKEN"
Q_SEQ_GAP = "LEDGER_SEQ_GAP"
Q_FACT_CONFLICT = "LEDGER_FACT_CONFLICT"
Q_STATE = "LEDGER_STATE_FORBIDDEN"
Q_BOOT_MISMATCH = "LEDGER_BOOT_MISMATCH"

# 审计动作分类
AUDIT_BIZ = "BIZ"
AUDIT_SEC = "SECURITY"
AUDIT_DEV = "DEVICE"
AUDIT_SYS = "SYSTEM"
