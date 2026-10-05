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
from .security import (LEDGER_GENESIS, canonical_json, command_fingerprint,
                       digest_payload, hash_confirm_code, ledger_entry_hash,
                       new_confirm_code, sha256_hex, verify_ledger_entry_signature)
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
                summary = getattr(self, "_reconcile_summary", None)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            out = {"device_id": device_id, "online": True, "boot_code": boot_code,
                   "rebooted": rebooted}
            if summary is not None:
                out["ledger"] = {
                    "recovered": len(summary["recovered"]),
                    "duplicates": len(summary["duplicates"]),
                    "quarantined": [
                        {"command_id": q["entry"].get("command_id"),
                         "reason": q["reason"], "duplicate": q["duplicate"]}
                        for q in summary["quarantined"]],
                }
            return out

    def _reconcile_ledger(self, device_id: str, current_boot: str,
                          ledger: list[dict], now: float):
        """用设备持久签名账簿恢复执行事实。

        每条账簿材料依次过四关，任何一关失败只进隔离区留痕、绝不改状态：

        1. 代次：boot_code 必须是该设备登记过的启动代号（旧代次/未知代次隔离）；
        2. 单调编号：同一代次内按 seq 严格递增，缺口隔离（不臆补）；
        3. 指令指纹：条目哈希（代次+序号+指令+结果+前驱）与签名必须与设备密钥吻合，
           且 command_id 必须是网关投递给该设备的目标；
        4. 账簿连续性：代次内 prev 哈希必须逐条链接，断链隔离。

        重复上传幂等：完全相同的有效条目重放不产生第二条事实；完全相同的坏
        材料重复隔离也只留一条痕。宁可保留 DOUBT，绝不臆断执行/未执行。
        """
        dev = self.db.get_device(device_id)
        key = dev["preshared_key"]
        recovered, quarantined, duplicates = [], [], []
        conflict_targets: set[tuple[str, str]] = set()
        seen_batch: set[tuple[str, str, int, str]] = set()
        # 代次 -> 该代次账簿链头与下一个期望序号
        chain_tip: dict[str, str] = {}
        next_seq: dict[str, int] = {}

        def _order_key(e: dict):
            b = self.db.boot_known(device_id, str(e.get("boot_code", "")))
            return (b["hello_at"], b["first_seq"], int(e.get("seq", 0))) if b \
                else (10**12, 10**12, int(e.get("seq", 0)))

        def _quarantine(e: dict, reason: str, eh: str, ticket):
            ok = self.db.insert_quarantine(
                device_id, ticket["id"] if ticket else None, eh, reason, e, now)
            item = {"entry": e, "reason": reason, "duplicate": not ok}
            quarantined.append(item)
            if ticket and ok:
                self._note_ticket_conflict(ticket["id"], reason, now,
                                           {"entry_hash": eh, "reason": reason})

        for e in sorted(ledger, key=_order_key):
            boot = str(e.get("boot_code", ""))
            seq = _safe_int(e.get("seq"))
            cid = str(e.get("command_id", ""))
            result = str(e.get("result", ""))
            prev = str(e.get("prev", LEDGER_GENESIS))
            raw_hash = sha256_hex(canonical_json(e))
            ticket = self.db.get_ticket_for_target(cid, device_id) if cid else None

            # 0) 结构完整性
            if seq is None or seq < 1 or not boot or not cid or \
                    result not in (M.RESULT_EXECUTED, M.RESULT_FAILED):
                _quarantine(e, M.Q_BAD_ENTRY, raw_hash, ticket)
                continue

            # 1) 代次
            known = self.db.boot_known(device_id, boot)
            if not known:
                _quarantine(e, M.Q_UNKNOWN_BOOT, raw_hash, ticket)
                continue

            tip = chain_tip.get(boot, LEDGER_GENESIS)
            expected_seq = next_seq.get(boot, known["first_seq"])

            # 2) 条目自证：重算条目哈希并验签（指纹：代次+编号+指令+结果+前驱）
            eh = ledger_entry_hash(boot, seq, cid, result, prev)
            if str(e.get("entry_hash", "")) != eh:
                _quarantine(e, M.Q_ENTRY_HASH, raw_hash, ticket)
                # 不推进链头：后续条目要么与该条无关（缺口），要么同样断链
                continue
            if not verify_ledger_entry_signature(key, eh, str(e.get("signature", ""))):
                _quarantine(e, M.Q_SIGNATURE, raw_hash, ticket)
                continue

            # 3) 账簿连续性：前驱哈希必须与网关重放的链头一致，序号必须严格 +1
            batch_key = (boot, cid, seq, result)
            batch_duplicate = batch_key in seen_batch
            seen_batch.add(batch_key)
            if batch_duplicate:
                # 同批次内完全相同的条目（设备重传）：幂等回放，不隔离、不重收
                duplicates.append({"command_id": cid, "seq": seq})
                continue
            if prev != tip:
                if seq > expected_seq:
                    reason = M.Q_SEQ_GAP
                else:
                    reason = M.Q_CHAIN_BROKEN
                _quarantine(e, reason, raw_hash, ticket)
                # 该条本身签名真实但与已见材料不连续：隔离、不采信，
                # 并以它为新链头继续，避免后面的诚实条目被级联误判。
                chain_tip[boot] = eh
                next_seq[boot] = seq + 1
                continue
            if seq < expected_seq:
                # 回看是否为同一事实的幂等重放
                existing = self.db.get_receipt(cid, device_id)
                if existing and existing["boot_code"] == boot and \
                        existing["seq"] == seq and existing["result"] == result:
                    duplicates.append({"command_id": cid, "seq": seq})
                    chain_tip[boot] = eh
                    next_seq[boot] = seq + 1
                else:
                    _quarantine(e, M.Q_FACT_CONFLICT, raw_hash, ticket)
                continue
            if seq > expected_seq:
                _quarantine(e, M.Q_SEQ_GAP, raw_hash, ticket)
                chain_tip[boot] = eh
                next_seq[boot] = seq + 1
                continue

            tgt = self.db.get_target(cid, device_id)
            if not tgt:
                # 网关从未向该设备投递过此指令：伪造/串扰
                _quarantine(e, M.Q_NEVER_DISPATCHED, raw_hash, ticket)
                chain_tip[boot] = eh
                next_seq[boot] = seq + 1
                continue

            # 指令指纹：设备执行时对 command_id + 冻结摘要签名留底，
            # 防止条目被改挂到其他指令上。
            cmd = self.db.get_command_row(cid)
            expect_fp = command_fingerprint(cid, cmd["digest"] if cmd else None)
            if str(e.get("fingerprint", "")) != expect_fp:
                _quarantine(e, M.Q_FINGERPRINT, raw_hash, ticket)
                chain_tip[boot] = eh
                next_seq[boot] = seq + 1
                continue

            existing = self.db.get_receipt(cid, device_id)
            if existing:
                if existing["result"] == result and existing["boot_code"] == boot \
                        and existing["seq"] == seq:
                    duplicates.append({"command_id": cid, "seq": seq})
                else:
                    _quarantine(e, M.Q_FACT_CONFLICT, raw_hash, ticket)
                chain_tip[boot] = eh
                next_seq[boot] = seq + 1
                continue

            # 4) 目标状态门：只有在途/挂起/陈旧 MISSED 才能被有效账簿补记
            if tgt["status"] in (M.TGT_EXECUTED, M.TGT_FAILED):
                _quarantine(e, M.Q_FACT_CONFLICT, raw_hash, ticket)
                chain_tip[boot] = eh
                next_seq[boot] = seq + 1
                continue
            if tgt["status"] in (M.TGT_PENDING, M.TGT_SKIPPED):
                # 没投递过 / 已撤销拒绝过期：不能被账簿“执行”
                _quarantine(e, f"{M.Q_STATE}:{tgt['status']}", raw_hash, ticket)
                chain_tip[boot] = eh
                next_seq[boot] = seq + 1
                continue
            if tgt["dispatched_boot"] not in (None, boot):
                _quarantine(e, M.Q_BOOT_MISMATCH, raw_hash, ticket)
                chain_tip[boot] = eh
                next_seq[boot] = seq + 1
                continue

            # —— 校验通过：补记既成执行事实（事实优先于窗口/MISSED 结论）——
            status = M.TGT_EXECUTED if result == M.RESULT_EXECUTED else M.TGT_FAILED
            was_missed = tgt["status"] == M.TGT_MISSED
            event_id = self.db.append_event(
                now, device_id, M.AUDIT_DEV, "LEDGER_RECOVERY",
                {"command_id": cid, "boot_code": boot, "seq": seq,
                 "result": result, "message": e.get("message", ""),
                 "entry_hash": eh, "after_missed": was_missed},
                command_id=cid, device_id=device_id)
            ok = self.db.insert_receipt({
                "command_id": cid, "device_id": device_id, "boot_code": boot,
                "seq": seq, "result": result, "message": e.get("message", ""),
                "source": M.SRC_LEDGER, "event_id": event_id, "received_at": now})
            if ok:
                if was_missed:
                    self.db.recover_terminal(cid, device_id, status, now)
                else:
                    self.db.settle_target(cid, device_id, status, now)
                if boot == current_boot:
                    # 仅当前代次的补记推进序号水位；旧代次历史不影响新代次
                    self.db.advance_ledger_head(device_id, seq)
                self._recompute(cid, now)
                recovered.append({"command_id": cid, "result": result,
                                  "after_missed": was_missed})
                # 工单结案：执行事实由签名账簿补记，非人工操作
                tk = self.db.get_ticket_for_target(cid, device_id)
                if tk:
                    if tk["status"] == M.TKT_RESOLVED and was_missed:
                        # 陈旧 MISSED 结论被既成事实推翻：重开后按事实结案并留痕
                        self.db.reopen_ticket(tk["id"], now)
                        self.db.add_ticket_action(
                            tk["id"], now, "system", M.ACT_FACT_AFTER_MISSED,
                            {"old_resolution": tk["resolution"], "result": result,
                             "entry_hash": eh})
                    self._close_ticket(
                        tk["id"], M.ACT_FACT_RECOVERED, "system", now,
                        {"boot_code": boot, "seq": seq, "result": result,
                         "entry_hash": eh, "event_id": event_id})
            chain_tip[boot] = eh
            next_seq[boot] = seq + 1

        # 链连续性复核：同代次上传的相邻条目若曾出现 prev 对不上的情况，
        # 已在上面按 ENTRY_HASH/GAP 隔离；这里把整批汇总事件落审计。
        self.db.append_event(
            now, device_id, M.AUDIT_DEV, "LEDGER_RECONCILED",
            {"recovered": recovered, "duplicates": duplicates,
             "quarantined": [{"command_id": q["entry"].get("command_id"),
                              "reason": q["reason"],
                              "duplicate": q["duplicate"]}
                             for q in quarantined]},
            device_id=device_id)
        for q in quarantined:
            cid = q["entry"].get("command_id")
            if cid:
                conflict_targets.add((str(cid), device_id))
        self._reconcile_summary = {
            "recovered": recovered, "duplicates": duplicates,
            "quarantined": quarantined,
            "conflict_targets": conflict_targets}

    def _recover_undelivered(self, device_id: str, current_boot: str, now: float):
        """重启/重连后处理仍悬而未决的目标。

        * 同一启动代号下仍在途 → 保持 DOUBT，等回执（设备账簿未提到它，
          可能正在执行，不能重投，否则可能双触发）；
        * 设备已重启（代号变化）且账簿无该指令 → 未执行是确定的：
          窗口内重置为 PENDING 由设备重新拉取（工单保持 OPEN，随回执结案），
          窗口外记 MISSED（工单按过期结案）。
        """
        rows = self.db.conn.execute(
            "SELECT t.* FROM targets t JOIN commands c ON c.command_id=t.command_id "
            "WHERE t.device_id=? AND t.status='DOUBT'", (device_id,)).fetchall()
        summary = getattr(self, "_reconcile_summary", None)
        conflict_targets = summary["conflict_targets"] if summary else set()
        for r in rows:
            t = dict(r)
            if t["dispatched_boot"] == current_boot:
                continue  # 同代号，执行与否未知，继续等回执
            if self.db.get_receipt(t["command_id"], device_id):
                continue  # 账簿阶段已补记（工单已随事实结案）
            if (t["command_id"], device_id) in conflict_targets:
                # 本次上传含该目标的矛盾/非法材料：保持 DOUBT，不自动重投，
                # 等安全员在工单工作台核查后人工处置
                continue
            cmd = self.db.get_command_row(t["command_id"])
            ticket = self.db.get_ticket_for_target(t["command_id"], device_id)
            if now < cmd["valid_to"] and cmd["status"] in (M.CMD_CONFIRMED,):
                self.db.reset_to_pending(t["command_id"], device_id, now)
                event_id = self.db.append_event(
                    now, device_id, M.AUDIT_SYS, "REDELIVER_AFTER_REBOOT",
                    {"command_id": t["command_id"], "old_boot": t["dispatched_boot"],
                     "new_boot": current_boot},
                    command_id=t["command_id"], device_id=device_id)
                if ticket and ticket["status"] == M.TKT_OPEN:
                    self.db.add_ticket_action(
                        ticket["id"], now, "system", M.ACT_REDELIVERED,
                        {"old_boot": t["dispatched_boot"], "new_boot": current_boot,
                         "event_id": event_id})
                    self.db.touch_ticket(ticket["id"], now)
            else:
                self.db.conn.execute(
                    "UPDATE targets SET status='MISSED',updated_at=? "
                    "WHERE command_id=? AND device_id=? AND status='DOUBT'",
                    (now, t["command_id"], device_id))
                event_id = self.db.append_event(
                    now, device_id, M.AUDIT_SYS, "MISSED_AFTER_REBOOT",
                    {"command_id": t["command_id"], "reason": "WINDOW_CLOSED_OR_CMD_TERMINAL",
                     "cmd_status": cmd["status"]},
                    command_id=t["command_id"], device_id=device_id)
                self._recompute(t["command_id"], now)
                if ticket and ticket["status"] == M.TKT_OPEN:
                    self._close_ticket(
                        ticket["id"], M.ACT_MISSED, "system", now,
                        {"reason": "WINDOW_CLOSED_OR_CMD_TERMINAL",
                         "cmd_status": cmd["status"], "event_id": event_id})

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
                # 回执形成既成事实：对应事故恢复工单按事实结案（系统动作，非人工）
                ticket = self.db.get_ticket_for_target(command_id, device_id)
                if ticket:
                    self._close_ticket(
                        ticket["id"], M.ACT_FACT_REPORTED, "system", now,
                        {"boot_code": boot_code, "seq": seq, "result": result,
                         "event_id": event_id})
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
        """网关重启后：所有“已投递但无终态”的目标转 DOUBT 并挂事故恢复工单。

        不做任何乐观重放——设备可能已经执行。工单只允许安全通道角色查看/处置；
        等设备重新 HELLO 带签名账簿对账，未执行指令不误执行、已执行事实不丢失。
        同一目标重复扫描不会重复建工单（表级唯一约束兜底）。
        """
        with self._lock:
            now = self.now()
            rows = self.db.open_doubt_targets()
            if not rows:
                return {"doubt": 0, "tickets": 0}
            n_tickets = 0
            try:
                for r in rows:
                    was_doubt = r["status"] == M.TGT_DOUBT
                    self.db.mark_doubt(r["command_id"], r["device_id"], now)
                    reason = M.TKT_REASON_DOUBT if was_doubt else M.TKT_REASON_RESTART
                    if self._ensure_ticket(r["command_id"], r["device_id"], reason,
                                           "system", now):
                        n_tickets += 1
                self.db.append_event(
                    now, "system", M.AUDIT_SYS, "GATEWAY_RESTART_RECOVERY",
                    {"doubt_targets": rows, "tickets": n_tickets})
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            return {"doubt": len(rows), "tickets": n_tickets}

    # ================= 事故恢复对账工单 =================
    def _ticket_evidence(self, command_id: str, device_id: str,
                         tgt: Optional[dict] = None) -> dict:
        """汇总工单证据：指令冻结信息、投递代次/时间、窗口、既有回执。"""
        cmd = self.db.get_command_row(command_id)
        tgt = tgt or self.db.get_target(command_id, device_id)
        rec = self.db.get_receipt(command_id, device_id)
        return {
            "command_id": command_id,
            "device_id": device_id,
            "action": cmd["action"] if cmd else None,
            "digest": cmd["digest"] if cmd else None,
            "valid_to": cmd["valid_to"] if cmd else None,
            "target_status": tgt["status"] if tgt else None,
            "dispatched_at": tgt["dispatched_at"] if tgt else None,
            "dispatched_boot": tgt["dispatched_boot"] if tgt else None,
            "receipt": ({
                "boot_code": rec["boot_code"], "seq": rec["seq"],
                "result": rec["result"], "source": rec["source"],
                "received_at": rec["received_at"],
            } if rec else None),
        }

    def _ensure_ticket(self, command_id: str, device_id: str, reason: str,
                       actor: str, now: float,
                       evidence: Optional[dict] = None) -> bool:
        """幂等确保工单存在。新建时写 CREATED 处置历史；已存在返回 False。"""
        existing = self.db.get_ticket_for_target(command_id, device_id)
        if existing:
            return False
        ticket_id = "TKT-" + uuid.uuid4().hex[:12].upper()
        tgt = self.db.get_target(command_id, device_id)
        ev = evidence or self._ticket_evidence(command_id, device_id, tgt)
        self.db.insert_ticket({
            "id": ticket_id, "command_id": command_id, "device_id": device_id,
            "status": M.TKT_OPEN, "reason": reason, "evidence": ev,
        }, now)
        self.db.add_ticket_action(ticket_id, now, actor, M.ACT_CREATED,
                                  {"reason": reason, "evidence": ev})
        return True

    def _close_ticket(self, ticket_id: str, action: str, actor: str, now: float,
                      detail: dict):
        """系统/人工结单：写处置历史并置 RESOLVED。"""
        self.db.add_ticket_action(ticket_id, now, actor, action, detail)
        self.db.resolve_ticket(ticket_id, action, actor, now)

    def _note_ticket_conflict(self, ticket_id: str, reason: str, now: float,
                              detail: dict):
        """冲突材料隔离后在工单留痕（工单保持 OPEN）。"""
        self.db.touch_ticket(ticket_id, now, conflict_reason=reason)
        self.db.add_ticket_action(ticket_id, now, "system",
                                  M.ACT_LEDGER_CONFLICT,
                                  {"reason": reason, **detail})

    def list_recovery_tickets(self, status: Optional[str] = None,
                              limit: int = 200) -> list[dict]:
        with self._lock:
            out = []
            for t in self.db.list_tickets(status, limit):
                out.append(self._ticket_view(t))
            return out

    def get_recovery_ticket(self, ticket_id: str) -> dict:
        with self._lock:
            t = self.db.get_ticket(ticket_id)
            if not t:
                raise NotFound("对账工单不存在")
            return self._ticket_view(t, with_actions=True)

    def _ticket_view(self, t: dict, with_actions: bool = False) -> dict:
        out = {
            "ticket_id": t["id"],
            "command_id": t["command_id"],
            "device_id": t["device_id"],
            "status": t["status"],
            "reason": t["reason"],
            "resolution": t["resolution"],
            "conflict_reason": t["conflict_reason"],
            "evidence": json.loads(t["evidence"]),
            "created_at": t["created_at"],
            "updated_at": t["updated_at"],
            "resolved_at": t["resolved_at"],
            "resolved_by": t["resolved_by"],
        }
        if with_actions:
            out["history"] = [
                {"id": a["id"], "ts": a["ts"], "actor": a["actor"],
                 "action": a["action"], "note": a["note"],
                 "detail": json.loads(a["detail"])}
                for a in self.db.list_ticket_actions(t["id"])]
            out["quarantine"] = [
                {"id": q["id"], "reason": q["reason"],
                 "raw": json.loads(q["raw"]), "received_at": q["received_at"]}
                for q in self.db.list_quarantine(device_id=t["device_id"])
                if q["ticket_id"] == t["id"]]
        return out

    def list_quarantine(self, device_id: Optional[str] = None,
                        limit: int = 200) -> list[dict]:
        with self._lock:
            rows = self.db.list_quarantine(limit, device_id)
            for r in rows:
                r["raw"] = json.loads(r["raw"])
            return rows

    def dispose_ticket(self, actor: str, ticket_id: str, action: str,
                       note: str = "") -> dict:
        """安全角色人工处置工单。

        硬边界：人工只能 ① 备注 ② 批准重投（必须未执行且窗口仍有效）
        ③ 人工定 MISSED（窗口必须已过期）。任何人工动作都不能写入或覆盖
        EXECUTED/FAILED——执行事实只能来自设备回执或校验通过的签名账簿。
        """
        with self._lock:
            now = self.now()
            t = self.db.get_ticket(ticket_id)
            if not t:
                raise NotFound("对账工单不存在")
            if action not in M.MANUAL_ACTIONS:
                raise InvalidState(
                    "非法人工处置动作", details={"allowed": sorted(M.MANUAL_ACTIONS)})
            command_id, device_id = t["command_id"], t["device_id"]
            tgt = self.db.get_target(command_id, device_id)
            cmd = self.db.get_command_row(command_id)

            # 已确认执行事实的工单：任何人工处置（除备注外）一律拒绝
            fact = self.db.get_receipt(command_id, device_id)
            if fact:
                raise Conflict(
                    "已确认执行事实，人工处置不得覆盖（执行事实不可变）",
                    details={"result": fact["result"], "source": fact["source"]})

            if action == M.ACT_REDELIVER_APPROVED:
                if t["status"] != M.TKT_OPEN:
                    raise InvalidState("仅挂起工单可批准重投",
                                       details={"status": t["status"]})
                if tgt["status"] != M.TGT_DOUBT:
                    raise InvalidState(
                        "仅 DOUBT 目标可批准重投", details={"target": tgt["status"]})
                if not cmd or now >= cmd["valid_to"]:
                    raise Conflict("原有效时限已过期，不能批准重投（只能定 MISSED）")
                if cmd["status"] != M.CMD_CONFIRMED:
                    raise Conflict("指令不在 CONFIRMED 生命周期，不能重投",
                                   details={"cmd_status": cmd["status"] if cmd else None})
                try:
                    self.db.reset_to_pending(command_id, device_id, now)
                    self.db.append_event(
                        now, actor, M.AUDIT_SEC, "TICKET_REDELIVER_APPROVED",
                        {"ticket_id": ticket_id, "command_id": command_id,
                         "device_id": device_id, "note": note},
                        command_id=command_id, device_id=device_id)
                    self.db.add_ticket_action(ticket_id, now, actor, action,
                                              {"note": note}, note=note)
                    self.db.touch_ticket(ticket_id, now)
                    self.db.commit()
                except Exception:
                    self.db.rollback()
                    raise
                return self.get_recovery_ticket(ticket_id)

            if action == M.ACT_MISSED:
                if t["status"] != M.TKT_OPEN:
                    raise InvalidState("仅挂起工单可定 MISSED",
                                       details={"status": t["status"]})
                if not cmd or now < cmd["valid_to"]:
                    raise Conflict("原有效时限仍有效，不能人工定 MISSED")
                try:
                    self.db.conn.execute(
                        "UPDATE targets SET status='MISSED',updated_at=? "
                        "WHERE command_id=? AND device_id=? AND status='DOUBT'",
                        (now, command_id, device_id))
                    event_id = self.db.append_event(
                        now, actor, M.AUDIT_SEC, "TICKET_MANUAL_MISSED",
                        {"ticket_id": ticket_id, "command_id": command_id,
                         "device_id": device_id, "note": note},
                        command_id=command_id, device_id=device_id)
                    self._close_ticket(ticket_id, action, actor, now,
                                       {"note": note, "event_id": event_id})
                    self._recompute(command_id, now)
                    self.db.commit()
                except Exception:
                    self.db.rollback()
                    raise
                return self.get_recovery_ticket(ticket_id)

            # 默认：仅备注，不动任何状态（已结工单也允许追加备注）
            try:
                self.db.append_event(
                    now, actor, M.AUDIT_SEC, "TICKET_NOTE",
                    {"ticket_id": ticket_id, "note": note},
                    command_id=command_id, device_id=device_id)
                self.db.add_ticket_action(ticket_id, now, actor, action,
                                          {"note": note}, note=note)
                self.db.touch_ticket(ticket_id, now)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            return self.get_recovery_ticket(ticket_id)

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
                # 窗口关闭瞬间 DISPATCHED→DOUBT 的目标：先补事故恢复工单（幂等）
                for cid in closed_ids:
                    for t in self.db.list_targets(cid):
                        if t["status"] == M.TGT_DOUBT:
                            self._ensure_ticket(cid, t["device_id"],
                                                M.TKT_REASON_WINDOW, "system", now)
                # 重启后已挂 DOUBT 的目标，窗口关闭后仍无回执/账簿：
                # 结算 MISSED 并结事故工单（之后签名账簿补证已执行仍可翻案，
                # recover_terminal + 重开工单路径保留）。
                stale_doubt = self.db.conn.execute(
                    "SELECT t.command_id,t.device_id FROM targets t "
                    "JOIN commands c ON c.command_id=t.command_id "
                    "WHERE t.status='DOUBT' AND c.status='CONFIRMED' "
                    "AND c.valid_to<=?",
                    (now,)).fetchall()
                for r in stale_doubt:
                    cid, did = r["command_id"], r["device_id"]
                    self.db.conn.execute(
                        "UPDATE targets SET status='MISSED',updated_at=? "
                        "WHERE command_id=? AND device_id=? AND status='DOUBT'",
                        (now, cid, did))
                    event_id = self.db.append_event(
                        now, "system", M.AUDIT_SYS, "MISSED_WINDOW_EXPIRED",
                        {"command_id": cid, "device_id": did},
                        command_id=cid, device_id=did)
                    ticket = self.db.get_ticket_for_target(cid, did)
                    if ticket and ticket["status"] == M.TKT_OPEN:
                        self._close_ticket(
                            ticket["id"], M.ACT_MISSED, "system", now,
                            {"reason": "WINDOW_EXPIRED_NO_FACT",
                             "event_id": event_id})
                    if cid not in closed_ids:
                        closed_ids.append(cid)
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
