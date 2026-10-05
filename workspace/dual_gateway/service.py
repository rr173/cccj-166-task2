"""核心领域服务：全部安全不变量在这里收口。

线程模型：HTTP 三通道 + 后台清扫线程并发访问，所有公共方法在同一把
可重入锁内执行；每个“事件 + 状态变更”在一个 SQLite 事务内提交，
保证审计与状态要么同时生效、要么都不生效。
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from typing import Any, Callable, Optional

from . import models as M
from .errors import (Conflict, DeviceRejected, FrozenMismatch, InvalidReceipt,
                     InvalidState, NotFound)
from .security import (canonical_json, digest_payload, hash_confirm_code,
                       new_confirm_code)
from .storage import Storage


def _cmd_dict(row: dict) -> dict:
    return {
        "command_id": row["command_id"],
        "action": row["action"],
        "devices": json.loads(row["device_set"]),
        "params": json.loads(row["params"]),
        "digest": row["digest"],
        "valid_from": row["valid_from"],
        "valid_to": row["valid_to"],
        "confirm_deadline": row["confirm_deadline"],
        "status": row["status"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
        "confirmed_by": row["confirmed_by"],
        "confirmed_at": row["confirmed_at"],
        "revoked_by": row["revoked_by"],
        "revoked_at": row["revoked_at"],
        "reject_reason": row["reject_reason"],
    }


class CommandService:
    def __init__(self, storage: Storage, config, clock: Callable[[], float] = time.time):
        self.db = storage
        self.cfg = config
        self.now = clock
        self._lock = threading.RLock()

    # ================= 业务通道：创建 / 查询 / 撤销 =================
    def create_command(self, actor: str, action: str, devices: list[str],
                       params: dict[str, Any],
                       valid_seconds: Optional[int] = None) -> dict:
        """高风险指令创建：冻结设备集合、参数摘要与有效窗口。

        返回体里的 confirm_code 只出现这一次明文——业务系统应把它交给
        独立带外通道（语音/短信/硬令牌）送达第二角色，服务端只存哈希。
        """
        with self._lock:
            now = self.now()
            if not action or not isinstance(action, str):
                raise InvalidState("action 不能为空")
            if not devices:
                raise InvalidState("devices 不能为空")
            devices = sorted(set(devices))
            unknown = [d for d in devices if not self.db.get_device(d)]
            if unknown:
                raise NotFound(f"未注册设备: {unknown}", details={"unknown": unknown})
            if not isinstance(params, dict):
                raise InvalidState("params 必须是对象")

            valid_seconds = valid_seconds or self.cfg.default_valid_seconds
            if valid_seconds <= 0:
                raise InvalidState("有效窗口必须为正")
            valid_from = now
            valid_to = now + valid_seconds
            confirm_deadline = min(valid_to, now + self.cfg.confirm_timeout_seconds)
            command_id = "CMD-" + uuid.uuid4().hex[:12].upper()
            code = new_confirm_code()

            frozen = {
                "action": action,
                "devices": devices,
                "params": params,
                "valid_from": valid_from,
                "valid_to": valid_to,
            }
            row = {
                "command_id": command_id,
                "action": action,
                "params": params,
                "digest": digest_payload(frozen),
                "valid_from": valid_from,
                "valid_to": valid_to,
                "confirm_deadline": confirm_deadline,
                "status": M.CMD_PENDING,
                "confirm_code_hash": hash_confirm_code(code),
                "created_by": actor,
            }
            try:
                self.db.append_event(
                    now, actor, M.AUDIT_BIZ, "CMD_CREATED",
                    {"command_id": command_id, "frozen": {
                        **frozen, "params": json.loads(canonical_json(params))},
                     "digest": row["digest"], "confirm_deadline": confirm_deadline},
                    command_id=command_id)
                self.db.insert_command(row, devices, now)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            return {**_cmd_dict(self.db.get_command_row(command_id)),
                    "confirm_code": code}

    def get_command(self, command_id: str) -> dict:
        with self._lock:
            row = self.db.get_command_row(command_id)
            if not row:
                raise NotFound("指令不存在")
            out = _cmd_dict(row)
            out["targets"] = [self._target_view(t) for t in self.db.list_targets(command_id)]
            return out

    def list_commands(self, status: Optional[str] = None, limit: int = 100) -> list[dict]:
        with self._lock:
            return [_cmd_dict(r) for r in self.db.list_commands(limit, status)]

    def revoke_command(self, actor: str, command_id: str, reason: str = "") -> dict:
        """撤销。硬约束：任何设备一旦形成执行事实（或指令已在途不可证明未执行），
        撤销一律拒绝——已执行事实不能被撤销覆盖；在途目标必须先对账。"""
        with self._lock:
            now = self.now()
            row = self.db.get_command_row(command_id)
            if not row:
                raise NotFound("指令不存在")
            status = row["status"]
            targets = self.db.list_targets(command_id)
            executed = [t["device_id"] for t in targets if t["status"] in (M.TGT_EXECUTED, M.TGT_FAILED)]
            inflight = [t["device_id"] for t in targets if t["status"] in (M.TGT_DISPATCHED, M.TGT_DOUBT)]

            if executed:
                raise Conflict(
                    "存在已执行回执，已执行事实不可撤销",
                    details={"executed": executed})
            if status in (M.CMD_EXECUTED, M.CMD_PARTIAL_FAILED, M.CMD_CLOSED):
                raise Conflict("指令已终结，不可撤销", details={"status": status})
            if status in (M.CMD_REVOKED, M.CMD_REJECTED, M.CMD_EXPIRED):
                raise Conflict("指令已终结，不可重复撤销", details={"status": status})
            if inflight:
                # 已投递给现场设备：无法保证设备没有执行，必须等设备账本对账，
                # 绝不能用“撤销”把在途指令一笔勾销后又重投。
                raise Conflict(
                    "指令已下发在途，需设备重连对账后处理，禁止直接撤销",
                    details={"inflight": inflight})

            # PENDING 或 CONFIRMED 且所有目标仍 PENDING：指令从未到达任何设备
            assert all(t["status"] == M.TGT_PENDING for t in targets)
            try:
                self.db.append_event(
                    now, actor, M.AUDIT_BIZ, "CMD_REVOKED",
                    {"command_id": command_id, "reason": reason},
                    command_id=command_id)
                self.db.mark_revoked(command_id, actor, now)
                self.db.conn.execute(
                    "UPDATE targets SET status='SKIPPED',updated_at=? "
                    "WHERE command_id=? AND status='PENDING'", (now, command_id))
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            return self.get_command(command_id)

    # ================= 安全通道：第二角色确认 / 拒绝 =================
    def confirm_command(self, actor: str, command_id: str, code: str,
                        digest_ack: str) -> dict:
        """第二角色确认。三重独立证据缺一不可：

        1. 已登录的安全通道会话（独立口令，见 web 层）；
        2. 带外送达的 6 位确认码（不经过业务通道）；
        3. 第二角色亲眼复核冻结摘要并回传（防创建页/工作台内容被调包）。
        """
        with self._lock:
            now = self.now()
            row = self.db.get_command_row(command_id)
            if not row:
                raise NotFound("指令不存在")
            if row["status"] != M.CMD_PENDING:
                raise InvalidState("仅待确认指令可确认", details={"status": row["status"]})
            if now > row["confirm_deadline"]:
                # 懒清扫：即使后台线程没跑到，也绝不放行超时确认
                self._expire_one(row, now)
                raise InvalidState("确认超时，指令已冻结为 EXPIRED")
            import hmac as _hmac
            if not _hmac.compare_digest(hash_confirm_code(code or ""), row["confirm_code_hash"]):
                self._sec_event("CONFIRM_DENIED", actor, command_id,
                                {"reason": "BAD_CODE"})
                raise FrozenMismatch("确认码错误")
            if not digest_ack or not _hmac.compare_digest(digest_ack, row["digest"]):
                self._sec_event("CONFIRM_DENIED", actor, command_id,
                                {"reason": "DIGEST_MISMATCH"})
                raise FrozenMismatch("冻结摘要复核不一致，拒绝确认（内容可能已被调包）")
            try:
                self.db.append_event(
                    now, actor, M.AUDIT_SEC, "CMD_CONFIRMED",
                    {"command_id": command_id, "digest": row["digest"]},
                    command_id=command_id)
                self.db.mark_confirmed(command_id, actor, now)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            return self.get_command(command_id)

    def reject_command(self, actor: str, command_id: str, reason: str) -> dict:
        with self._lock:
            now = self.now()
            row = self.db.get_command_row(command_id)
            if not row:
                raise NotFound("指令不存在")
            if row["status"] != M.CMD_PENDING:
                raise InvalidState("仅待确认指令可拒绝", details={"status": row["status"]})
            if now > row["confirm_deadline"]:
                self._expire_one(row, now)
                raise InvalidState("确认超时，指令已冻结为 EXPIRED")
            try:
                self.db.append_event(
                    now, actor, M.AUDIT_SEC, "CMD_REJECTED",
                    {"command_id": command_id, "reason": reason},
                    command_id=command_id)
                self.db.mark_rejected(command_id, reason or "第二角色拒绝", now)
                self.db.conn.execute(
                    "UPDATE targets SET status='SKIPPED',updated_at=? "
                    "WHERE command_id=? AND status='PENDING'", (now, command_id))
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            return self.get_command(command_id)

    def _sec_event(self, action: str, actor: str, command_id: str, payload: dict):
        try:
            self.db.append_event(self.now(), actor, M.AUDIT_SEC, action, payload,
                                 command_id=command_id)
            self.db.commit()
        except Exception:
            self.db.rollback()

    def _expire_one(self, row: dict, now: float):
        try:
            self.db.append_event(
                now, "system", M.AUDIT_SYS, "CMD_EXPIRED",
                {"command_id": row["command_id"], "reason": "CONFIRM_TIMEOUT"},
                command_id=row["command_id"])
            self.db.conn.execute(
                "UPDATE commands SET status='EXPIRED' WHERE command_id=? AND status='PENDING'",
                (row["command_id"],))
            self.db.conn.execute(
                "UPDATE targets SET status='SKIPPED',updated_at=? "
                "WHERE command_id=? AND status='PENDING'",
                (now, row["command_id"]))
            self.db.commit()
        except Exception:
            self.db.rollback()

    # ================= 设备通道：握手 / 心跳 / 拉取 / 回执 =================
    def hello(self, device_id: str, boot_code: str, first_seq: int = 1,
              ledger: Optional[list[dict]] = None) -> dict:
        """设备（重新）上线握手。

        设备每次启动生成新 boot_code 并带上持久账本：账本是设备本地
        “执行事实”的权威来源（设备在执行前先落盘再上送回执）。
        网关据此与在途指令对账：已执行的补记事实，未执行的安全重投。
        """
        with self._lock:
            now = self.now()
            dev = self.db.get_device(device_id)
            if not dev:
                raise NotFound("设备未注册")
            if not boot_code or first_seq < 1:
                raise DeviceRejected("boot_code / first_seq 非法")

            known = self.db.boot_known(device_id, boot_code)
            if known and known["first_seq"] != first_seq:
                raise DeviceRejected(
                    "同一起动代号声明了不同起始序号，疑似伪造",
                    details={"known": known["first_seq"], "got": first_seq})
            rebooted = dev["current_boot"] is not None and dev["current_boot"] != boot_code
            try:
                self.db.know_boot(device_id, boot_code, first_seq, now)
                self.db.mark_online(device_id, boot_code, first_seq, now)
                self.db.append_event(
                    now, device_id, M.AUDIT_DEV, "DEVICE_HELLO",
                    {"boot_code": boot_code, "first_seq": first_seq,
                     "rebooted": rebooted},
                    device_id=device_id)
                self.db.commit()
                self._reconcile_ledger(device_id, boot_code, ledger or [], now)
                self._recover_undelivered(device_id, boot_code, now)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            return {"device_id": device_id, "online": True, "boot_code": boot_code,
                    "rebooted": rebooted}

    def _reconcile_ledger(self, device_id: str, current_boot: str,
                          ledger: list[dict], now: float):
        """用设备持久账本恢复执行事实。宁可保留 DOUBT，绝不臆断执行/未执行。"""
        dev = self.db.get_device(device_id)
        recovered, ignored = [], []
        # 按 (启动代号起始序, 序号) 排序，保证严格递增重放
        def _key(e: dict):
            b = self.db.boot_known(device_id, e.get("boot_code", ""))
            base = b["first_seq"] if b else 10**12
            return (base, int(e.get("seq", 0)))

        for e in sorted(ledger, key=_key):
            boot = e.get("boot_code", "")
            seq = int(e.get("seq", 0))
            cid = e.get("command_id", "")
            result = e.get("result", "")
            known = self.db.boot_known(device_id, boot)
            tgt = self.db.get_target(cid, device_id)

            if not known:
                ignored.append({"entry": e, "reason": "UNKNOWN_BOOT"})
                continue
            if result not in (M.RESULT_EXECUTED, M.RESULT_FAILED) or not cid:
                ignored.append({"entry": e, "reason": "BAD_ENTRY"})
                continue
            if not tgt:
                # 网关从未向该设备投递过此指令：伪造/串扰，留痕但绝不改状态
                ignored.append({"entry": e, "reason": "NEVER_DISPATCHED"})
                self.db.insert_rejected(device_id, boot, seq, "LEDGER_NEVER_DISPATCHED",
                                        e, now)
                continue

            existing = self.db.get_receipt(cid, device_id)
            if existing:
                if existing["result"] != result:
                    ignored.append({"entry": e, "reason": "FACT_CONFLICT"})
                    self.db.insert_rejected(device_id, boot, seq,
                                            "LEDGER_FACT_CONFLICT", e, now)
                continue

            if tgt["status"] not in (M.TGT_DISPATCHED, M.TGT_DOUBT):
                # PENDING（没投递过）/ SKIPPED（撤销/拒绝/过期）都不能被账本“执行”
                ignored.append({"entry": e, "reason": f"STATE_{tgt['status']}"})
                self.db.insert_rejected(device_id, boot, seq,
                                        f"LEDGER_STATE_{tgt['status']}", e, now)
                continue
            if tgt["dispatched_boot"] not in (None, boot):
                ignored.append({"entry": e, "reason": "BOOT_MISMATCH"})
                self.db.insert_rejected(device_id, boot, seq,
                                        "LEDGER_BOOT_MISMATCH", e, now)
                continue

            status = M.TGT_EXECUTED if result == M.RESULT_EXECUTED else M.TGT_FAILED
            event_id = self.db.append_event(
                now, device_id, M.AUDIT_DEV, "LEDGER_RECOVERY",
                {"command_id": cid, "boot_code": boot, "seq": seq,
                 "result": result, "message": e.get("message", "")},
                command_id=cid, device_id=device_id)
            ok = self.db.insert_receipt({
                "command_id": cid, "device_id": device_id, "boot_code": boot,
                "seq": seq, "result": result, "message": e.get("message", ""),
                "source": M.SRC_LEDGER, "event_id": event_id, "received_at": now})
            if ok:
                self.db.settle_target(cid, device_id, status, now)
                self.db.advance_ledger_head(device_id, seq)
                recovered.append({"command_id": cid, "result": result})
                self._recompute(cid, now)

        self.db.append_event(
            now, device_id, M.AUDIT_DEV, "LEDGER_RECONCILED",
            {"recovered": recovered, "ignored": ignored}, device_id=device_id)

    def _recover_undelivered(self, device_id: str, current_boot: str, now: float):
        """重启/重连后处理仍悬而未决的目标。

        * 同一启动代号下仍在途 → 保持 DOUBT，等回执（设备账本未提到它，
          可能正在执行，不能重投，否则可能双触发）；
        * 设备已重启（代号变化）且账本无该指令 → 未执行是确定的：
          窗口内重置为 PENDING 由设备重新拉取，窗口外记 MISSED。
        """
        rows = self.db.conn.execute(
            "SELECT t.* FROM targets t JOIN commands c ON c.command_id=t.command_id "
            "WHERE t.device_id=? AND t.status='DOUBT'", (device_id,)).fetchall()
        for r in rows:
            t = dict(r)
            if t["dispatched_boot"] == current_boot:
                continue  # 同代号，执行与否未知，继续等回执
            if self.db.get_receipt(t["command_id"], device_id):
                continue  # 账本阶段已补记
            cmd = self.db.get_command_row(t["command_id"])
            if now < cmd["valid_to"] and cmd["status"] in (M.CMD_CONFIRMED,):
                self.db.reset_to_pending(t["command_id"], device_id, now)
                self.db.append_event(
                    now, device_id, M.AUDIT_SYS, "REDELIVER_AFTER_REBOOT",
                    {"command_id": t["command_id"], "old_boot": t["dispatched_boot"],
                     "new_boot": current_boot},
                    command_id=t["command_id"], device_id=device_id)
            else:
                self.db.conn.execute(
                    "UPDATE targets SET status='MISSED',updated_at=? "
                    "WHERE command_id=? AND device_id=? AND status='DOUBT'",
                    (now, t["command_id"], device_id))
                self.db.append_event(
                    now, device_id, M.AUDIT_SYS, "MISSED_AFTER_REBOOT",
                    {"command_id": t["command_id"], "reason": "WINDOW_CLOSED_OR_CMD_TERMINAL",
                     "cmd_status": cmd["status"]},
                    command_id=t["command_id"], device_id=device_id)
                self._recompute(t["command_id"], now)

    def heartbeat(self, device_id: str, boot_code: str) -> dict:
        with self._lock:
            dev = self.db.get_device(device_id)
            if not dev:
                raise NotFound("设备未注册")
            now = self.now()
            if not self.db.heartbeat(device_id, boot_code, now):
                # 旧启动代号的心跳：设备疑似重启后的残影/伪造，不改在线状态
                self.db.append_event(
                    now, device_id, M.AUDIT_DEV, "HEARTBEAT_STALE_BOOT",
                    {"got": boot_code, "current": dev["current_boot"]},
                    device_id=device_id)
                self.db.commit()
                raise DeviceRejected("旧启动代号心跳被拒绝")
            self.db.commit()
            return {"ok": True}

    def pull(self, device_id: str, boot_code: str) -> dict:
        """设备拉取已确认且窗口内的指令。离线设备/旧代号一律不给指令。"""
        with self._lock:
            now = self.now()
            dev = self.db.get_device(device_id)
            if not dev:
                raise NotFound("设备未注册")
            if not dev["online"] or dev["current_boot"] != boot_code:
                raise DeviceRejected("握手失效或启动代号不匹配，请先 HELLO")
            rows = self.db.pending_for_device(device_id, now)
            delivered = []
            try:
                for r in rows:
                    if self.db.mark_dispatched(r["command_id"], device_id, boot_code, now):
                        self.db.append_event(
                            now, device_id, M.AUDIT_DEV, "COMMAND_DISPATCHED",
                            {"command_id": r["command_id"], "boot_code": boot_code,
                             "digest": r["digest"]},
                            command_id=r["command_id"], device_id=device_id)
                        delivered.append({
                            "command_id": r["command_id"],
                            "action": r["action"],
                            "params": json.loads(r["params"]),
                            "digest": r["digest"],
                            "valid_to": r["valid_to"],
                        })
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            return {"device_id": device_id, "boot_code": boot_code,
                    "commands": delivered}

    def receipt(self, device_id: str, boot_code: str, seq: int,
                command_id: str, result: str, message: str = "") -> dict:
        """处理设备回执。核心防线：

        * 旧启动代号：拒绝（重启前的残影不得改变当前状态）；
        * 序号必须严格 +1：乱序/跳号拒绝，重复序号按幂等回放处理；
        * 网关未投递 / 已撤销过期 / 已有不同终态事实：拒绝且不改状态；
        * 一旦接受，执行事实唯一且不可被后续任何操作覆盖。
        """
        with self._lock:
            now = self.now()
            dev = self.db.get_device(device_id)
            if not dev:
                raise NotFound("设备未注册")

            def _reject(reason: str):
                try:
                    self.db.insert_rejected(device_id, boot_code, _safe_int(seq),
                                            reason,
                                            {"boot_code": boot_code, "seq": seq,
                                             "command_id": command_id, "result": result},
                                            now)
                    self.db.append_event(
                        now, device_id, M.AUDIT_DEV, "RECEIPT_REJECTED",
                        {"reason": reason, "boot_code": boot_code, "seq": seq,
                         "command_id": command_id, "result": result},
                        command_id=command_id, device_id=device_id)
                    self.db.commit()
                except Exception:
                    self.db.rollback()
                raise InvalidReceipt(f"回执被拒绝: {reason}", details={"reason": reason})

            if dev["current_boot"] != boot_code:
                _reject("STALE_BOOT")
            try:
                seq = int(seq)
            except (TypeError, ValueError):
                _reject("BAD_SEQ")
            if result not in (M.RESULT_EXECUTED, M.RESULT_FAILED):
                _reject("BAD_RESULT")

            head = dev["ledger_head_seq"] if dev["ledger_head_seq"] is not None else 0
            expected = head + 1

            # 幂等回放 / 序号复用
            prior = self.db.find_receipt_by_seq(device_id, boot_code, seq) if hasattr(
                self.db, "find_receipt_by_seq") else None
            if seq < expected:
                if prior and prior["command_id"] == command_id and prior["result"] == result:
                    return {"accepted": False, "duplicate": True,
                            "command_id": command_id, "result": result}
                _reject("REUSED_OR_OLD_SEQ")
            if seq > expected:
                _reject("OUT_OF_ORDER_GAP")

            tgt = self.db.get_target(command_id, device_id)
            if not tgt:
                _reject("UNKNOWN_TARGET")
            if tgt["status"] == M.TGT_PENDING:
                _reject("NOT_DISPATCHED")
            if tgt["status"] in (M.TGT_SKIPPED, M.TGT_MISSED):
                _reject(f"TARGET_{tgt['status']}")
            if tgt["status"] in (M.TGT_EXECUTED, M.TGT_FAILED):
                existing = self.db.get_receipt(command_id, device_id)
                if existing and existing["result"] == result:
                    return {"accepted": False, "duplicate": True,
                            "command_id": command_id, "result": result}
                _reject("FACT_IMMUTABLE")
            if tgt["dispatched_boot"] not in (None, boot_code):
                _reject("BOOT_MISMATCH")

            status = M.TGT_EXECUTED if result == M.RESULT_EXECUTED else M.TGT_FAILED
            try:
                event_id = self.db.append_event(
                    now, device_id, M.AUDIT_DEV, "RECEIPT_ACCEPTED",
                    {"command_id": command_id, "boot_code": boot_code, "seq": seq,
                     "result": result, "message": message},
                    command_id=command_id, device_id=device_id)
                ok = self.db.insert_receipt({
                    "command_id": command_id, "device_id": device_id,
                    "boot_code": boot_code, "seq": seq, "result": result,
                    "message": message, "source": M.SRC_RECEIPT,
                    "event_id": event_id, "received_at": now})
                if not ok:
                    # 并发重复：回滚事件，按幂等返回
                    self.db.rollback()
                    existing = self.db.get_receipt(command_id, device_id)
                    if existing and existing["result"] == result:
                        return {"accepted": False, "duplicate": True,
                                "command_id": command_id, "result": result}
                    _reject("FACT_IMMUTABLE")
                self.db.settle_target(command_id, device_id, status, now)
                self.db.advance_ledger_head(device_id, seq)
                self._recompute(command_id, now)
                self.db.commit()
            except InvalidReceipt:
                raise
            except Exception:
                self.db.rollback()
                raise
            return {"accepted": True, "duplicate": False,
                    "command_id": command_id, "result": result}

    # ================= 后台清扫 / 重启恢复 =================
    def startup_recovery(self):
        """网关重启后：所有“已投递但无终态”的目标转 DOUBT。

        不做任何乐观重放——设备可能已经执行。等设备重新 HELLO 带账本对账，
        确保未执行指令不误执行、已执行事实不丢失。
        """
        with self._lock:
            now = self.now()
            rows = self.db.dangling_dispatched()
            if not rows:
                return {"doubt": 0}
            try:
                for r in rows:
                    self.db.mark_doubt(r["command_id"], r["device_id"], now)
                self.db.append_event(
                    now, "system", M.AUDIT_SYS, "GATEWAY_RESTART_RECOVERY",
                    {"doubt_targets": rows})
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            return {"doubt": len(rows)}

    def sweep(self) -> dict:
        with self._lock:
            now = self.now()
            expired, closed, offline = [], [], []
            try:
                for cid in self.db.expire_pending_commands(now):
                    self.db.append_event(
                        now, "system", M.AUDIT_SYS, "CMD_EXPIRED",
                        {"command_id": cid, "reason": "CONFIRM_TIMEOUT"},
                        command_id=cid)
                    expired.append(cid)

                closed_ids = self.db.close_due_windows(now)
                for cid in closed_ids:
                    self.db.append_event(
                        now, "system", M.AUDIT_SYS, "WINDOW_CLOSED",
                        {"command_id": cid}, command_id=cid)
                    self._recompute(cid, now)
                    closed.append(cid)

                for d in self.db.list_devices():
                    if d["online"] and d["last_seen"] is not None \
                            and now - d["last_seen"] > self.cfg.offline_seconds:
                        self.db.mark_offline(d["device_id"])
                        self.db.append_event(
                            now, "system", M.AUDIT_DEV, "DEVICE_OFFLINE",
                            {"device_id": d["device_id"], "last_seen": d["last_seen"]},
                            device_id=d["device_id"])
                        offline.append(d["device_id"])
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            return {"expired": expired, "windows_closed": closed, "offline": offline}

    # ================= 派生状态 / 审计视图 =================
    def _recompute(self, command_id: str, now: float):
        """根据目标终态重算指令级状态（仅在已确认生命周期内演进）。"""
        row = self.db.get_command_row(command_id)
        if not row or row["status"] not in (
                M.CMD_CONFIRMED, M.CMD_CLOSED, M.CMD_PARTIAL_FAILED):
            return
        targets = self.db.list_targets(command_id)
        n_exec = sum(t["status"] == M.TGT_EXECUTED for t in targets)
        n_fail = sum(t["status"] == M.TGT_FAILED for t in targets)
        n_missed = sum(t["status"] == M.TGT_MISSED for t in targets)
        outstanding = [t for t in targets
                       if t["status"] in (M.TGT_PENDING, M.TGT_DISPATCHED, M.TGT_DOUBT)]
        new_status: Optional[str] = None
        if not outstanding:
            if n_exec and not n_fail and not n_missed:
                new_status = M.CMD_EXECUTED
            elif n_exec or n_fail:
                new_status = M.CMD_PARTIAL_FAILED
            else:
                new_status = M.CMD_CLOSED
        elif now >= row["valid_to"]:
            # 仍有悬置目标但窗口已关：先闭合，待账本对账后可继续演进为部分失败/完成
            new_status = M.CMD_CLOSED
        if new_status and new_status != row["status"]:
            self.db.set_command_status(command_id, new_status)

    def _target_view(self, t: dict) -> dict:
        out = dict(t)
        rec = self.db.get_receipt(t["command_id"], t["device_id"])
        out["receipt"] = {
            "boot_code": rec["boot_code"], "seq": rec["seq"], "result": rec["result"],
            "message": rec["message"], "source": rec["source"],
            "received_at": rec["received_at"],
        } if rec else None
        return out

    def audit_events(self, limit: int = 200, command_id: Optional[str] = None,
                     device_id: Optional[str] = None) -> list[dict]:
        with self._lock:
            rows = self.db.list_events(limit, command_id, device_id)
            for r in rows:
                r["payload"] = json.loads(r["payload"])
            return rows

    def verify_audit_chain(self) -> dict:
        with self._lock:
            return self.db.verify_chain()

    def rejected_receipts(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self.db.list_rejected(limit)
            for r in rows:
                r["raw"] = json.loads(r["raw"])
            return rows

    def list_devices(self) -> list[dict]:
        with self._lock:
            devs = self.db.list_devices()
            for d in devs:
                d.pop("preshared_key", None)
            return devs


def _safe_int(v: Any):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
