"""核心领域规则单元测试（无 HTTP，直接驱动服务层）。"""
from __future__ import annotations

import os
import tempfile
import unittest

from dual_gateway.config import load_config
from dual_gateway.errors import (Conflict, DeviceRejected, FrozenMismatch,
                                 InvalidReceipt, InvalidState, NotFound)
from dual_gateway.service import CommandService
from dual_gateway.storage import Storage


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class ServiceTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.clock = Clock()
        cfg = load_config(db_path=os.path.join(self.tmp, "g.db"),
                          default_valid_seconds=100,
                          confirm_timeout_seconds=50,
                          offline_seconds=5)
        self.cfg = cfg
        self.db = Storage(cfg.db_path)
        for d, k in cfg.device_keys.items():
            self.db.seed_device(d, k, self.clock())
        self.db.commit()
        self.svc = CommandService(self.db, cfg, clock=self.clock)

    def tearDown(self):
        self.db.close()

    def _create(self, devices=("DEV-A1", "DEV-A2"), code_out=True, **kw):
        out = self.svc.create_command(
            actor="ops", action="EMERGENCY_STOP", devices=list(devices),
            params={"rpm": 0, "valve": "close"}, **kw)
        return out

    def _confirm(self, c):
        return self.svc.confirm_command("supervisor", c["command_id"],
                                        c["confirm_code"], c["digest"])

    def _hello(self, dev="DEV-A1", boot="BOOT-1", ledger=None):
        return self.svc.hello(dev, boot, 1, ledger or [])

    def _receipt(self, dev, boot, seq, cid, result="EXECUTED"):
        return self.svc.receipt(dev, boot, seq, cid, result, "ok")


class TestCreateConfirm(ServiceTestBase):
    def test_frozen_create_and_code_once(self):
        c = self._create()
        self.assertEqual(c["status"], "PENDING")
        got = self.svc.get_command(c["command_id"])
        self.assertNotIn("confirm_code", got)  # 明文码只能出现一次
        self.assertEqual(len(c["digest"]), 64)

    def test_confirm_requires_code_and_digest(self):
        c = self._create()
        with self.assertRaises(FrozenMismatch):
            self.svc.confirm_command("supervisor", c["command_id"], "000000", c["digest"])
        with self.assertRaises(FrozenMismatch):
            self.svc.confirm_command("supervisor", c["command_id"],
                                     c["confirm_code"], "deadbeef")
        ok = self._confirm(c)
        self.assertEqual(ok["status"], "CONFIRMED")
        with self.assertRaises(InvalidState):
            self._confirm(c)  # 重复确认

    def test_unknown_device_rejected(self):
        with self.assertRaises(NotFound):
            self._create(devices=("DEV-A1", "GHOST"))

    def test_reject_closes(self):
        c = self._create()
        out = self.svc.reject_command("supervisor", c["command_id"], "看着不对")
        self.assertEqual(out["status"], "REJECTED")
        self.assertTrue(all(t["status"] == "SKIPPED" for t in out["targets"]))


class TestReceiptOrdering(ServiceTestBase):
    def _ready_one(self, dev="DEV-A1"):
        c = self._create(devices=(dev,))
        self._confirm(c)
        self._hello(dev, "B1")
        self.svc.pull(dev, "B1")
        return c

    def test_happy_path_seq_and_terminal(self):
        c = self._ready_one()
        self._receipt("DEV-A1", "B1", 1, c["command_id"])
        got = self.svc.get_command(c["command_id"])
        self.assertEqual(got["status"], "EXECUTED")
        self.assertEqual(got["targets"][0]["receipt"]["boot_code"], "B1")

    def test_stale_boot_rejected(self):
        c = self._ready_one()
        with self.assertRaises(InvalidReceipt) as cm:
            self._receipt("DEV-A1", "BOOT-OLD", 1, c["command_id"])
        self.assertEqual(cm.exception.details["reason"], "STALE_BOOT")
        # 状态未变
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t["status"], "DISPATCHED")

    def test_gap_rejected(self):
        c = self._ready_one()
        with self.assertRaises(InvalidReceipt) as cm:
            self._receipt("DEV-A1", "B1", 2, c["command_id"])
        self.assertEqual(cm.exception.details["reason"], "OUT_OF_ORDER_GAP")

    def test_seq_reuse_rejected(self):
        c = self._ready_one()
        self._receipt("DEV-A1", "B1", 1, c["command_id"])
        # 同序号但换一条指令：拒绝，序号不能复用
        c2 = self._create(devices=("DEV-A1",))
        self._confirm(c2)
        self.svc.pull("DEV-A1", "B1")
        with self.assertRaises(InvalidReceipt) as cm:
            self._receipt("DEV-A1", "B1", 1, c2["command_id"])
        self.assertEqual(cm.exception.details["reason"], "REUSED_OR_OLD_SEQ")

    def test_duplicate_is_idempotent_not_state_change(self):
        c = self._ready_one()
        self._receipt("DEV-A1", "B1", 1, c["command_id"], "EXECUTED")
        # 设备重发同一回执：返回 duplicate，且不能把 EXECUTED 改成 FAILED
        out = self._receipt("DEV-A1", "B1", 1, c["command_id"], "EXECUTED")
        self.assertTrue(out["duplicate"])
        with self.assertRaises(InvalidReceipt):
            self._receipt("DEV-A1", "B1", 1, c["command_id"], "FAILED")
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t["status"], "EXECUTED")

    def test_receipt_for_unknown_or_undispatched(self):
        c = self._create(devices=("DEV-A1",))
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        with self.assertRaises(InvalidReceipt) as cm:
            self._receipt("DEV-A1", "B1", 1, "CMD-NOPE")
        self.assertEqual(cm.exception.details["reason"], "UNKNOWN_TARGET")
        # 未 PULL 就回执
        with self.assertRaises(InvalidReceipt) as cm:
            self._receipt("DEV-A1", "B1", 1, c["command_id"])
        self.assertEqual(cm.exception.details["reason"], "NOT_DISPATCHED")


class TestRevoke(ServiceTestBase):
    def test_revoke_before_confirm(self):
        c = self._create()
        out = self.svc.revoke_command("ops", c["command_id"], "取消")
        self.assertEqual(out["status"], "REVOKED")

    def test_revoke_after_dispatch_blocked(self):
        c = self._create(devices=("DEV-A1",))
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        with self.assertRaises(Conflict) as cm:
            self.svc.revoke_command("ops", c["command_id"])
        self.assertIn("在途", cm.exception.message)

    def test_revoke_after_executed_impossible(self):
        c = self._create(devices=("DEV-A1",))
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        self._receipt("DEV-A1", "B1", 1, c["command_id"])
        with self.assertRaises(Conflict):
            self.svc.revoke_command("ops", c["command_id"])

    def test_revoke_multi_device_with_one_executed_blocked(self):
        c = self._create(devices=("DEV-A1", "DEV-A2"))
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self._hello("DEV-A2", "B2")
        self.svc.pull("DEV-A1", "B1")
        self._receipt("DEV-A1", "B1", 1, c["command_id"])
        # A2 尚未投递，但 A1 已执行：整单不可撤销，事实不能被覆盖
        with self.assertRaises(Conflict):
            self.svc.revoke_command("ops", c["command_id"])


class TestTimeout(ServiceTestBase):
    def test_confirm_timeout_expires(self):
        c = self._create()
        self.clock.advance(60)
        self.svc.sweep()
        got = self.svc.get_command(c["command_id"])
        self.assertEqual(got["status"], "EXPIRED")
        with self.assertRaises(InvalidState):
            self._confirm(c)

    def test_window_close_pending_missed(self):
        c = self._create(devices=("DEV-A1", "DEV-A2"), valid_seconds=10)
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        # DEV-A2 一直离线；窗口关闭
        self.clock.advance(11)
        self.svc.sweep()
        got = self.svc.get_command(c["command_id"])
        statuses = {t["device_id"]: t["status"] for t in got["targets"]}
        self.assertEqual(statuses["DEV-A1"], "DOUBT")   # 在途等对账
        self.assertEqual(statuses["DEV-A2"], "MISSED")  # 未投递不补发
        self.assertEqual(got["status"], "CLOSED")


class TestOffline(ServiceTestBase):
    def test_offline_detection_and_old_boot_heartbeat(self):
        self._hello("DEV-A1", "B1")
        self.clock.advance(10)
        self.svc.sweep()
        dev = next(d for d in self.svc.list_devices() if d["device_id"] == "DEV-A1")
        self.assertFalse(dev["online"])
        # 设备重连用新代号；旧代号心跳必须被拒
        self.svc.hello("DEV-A1", "B2", 1)
        with self.assertRaises(DeviceRejected):
            self.svc.heartbeat("DEV-A1", "B1")
        self.svc.heartbeat("DEV-A1", "B2")  # 新代号正常

    def test_offline_device_gets_no_commands(self):
        c = self._create(devices=("DEV-A1",))
        self._confirm(c)
        # 从未 HELLO
        with self.assertRaises(DeviceRejected):
            self.svc.pull("DEV-A1", "B1")


class TestRestartRecovery(ServiceTestBase):
    def test_doubt_after_gateway_restart(self):
        c = self._create(devices=("DEV-A1",))
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        # 网关重启：startup_recovery 把 DISPATCHED -> DOUBT
        self.svc.startup_recovery()
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t["status"], "DOUBT")

    def test_ledger_recovers_executed_fact(self):
        c = self._create(devices=("DEV-A1",))
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        self.svc.startup_recovery()
        # 设备也重启了（新代号），但账本证明旧代号下已执行
        self.svc.hello("DEV-A1", "B2", 1, ledger=[
            {"command_id": c["command_id"], "boot_code": "B1", "seq": 1,
             "result": "EXECUTED", "message": "done"}])
        got = self.svc.get_command(c["command_id"])
        self.assertEqual(got["status"], "EXECUTED")
        self.assertEqual(got["targets"][0]["receipt"]["source"], "LEDGER_RECOVERY")

    def test_ledger_absent_after_reboot_redelivers_within_window(self):
        c = self._create(devices=("DEV-A1",))
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        self.svc.startup_recovery()
        # 设备重启、账本为空 → 未执行确定 → 窗口内重新投递
        self.svc.hello("DEV-A1", "B2", 1, ledger=[])
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t["status"], "PENDING")
        cmds = self.svc.pull("DEV-A1", "B2")["commands"]
        self.assertEqual(len(cmds), 1)

    def test_ledger_absent_after_window_missed_not_executed(self):
        c = self._create(devices=("DEV-A1",), valid_seconds=10)
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        self.svc.startup_recovery()
        self.clock.advance(20)
        # 设备重启账本为空，窗口已过：MISSED，绝不补发执行
        self.svc.hello("DEV-A1", "B2", 1, ledger=[])
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t["status"], "MISSED")

    def test_same_boot_doubt_waits_no_redeliver(self):
        c = self._create(devices=("DEV-A1",))
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        self.svc.startup_recovery()
        # 设备未重启（同一代号重连）：是否执行未知，不重投，继续等回执
        self.svc.hello("DEV-A1", "B1", 1, ledger=[])
        cmds = self.svc.pull("DEV-A1", "B1")["commands"]
        self.assertEqual(cmds, [])
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t["status"], "DOUBT")

    def test_fabricated_ledger_ignored(self):
        # 对从未投递的指令伪造账本：不改任何状态
        self._hello("DEV-A1", "B1")
        self.svc.hello("DEV-A1", "B2", 1, ledger=[
            {"command_id": "CMD-FAKE", "boot_code": "B1", "seq": 1,
             "result": "EXECUTED"}])
        rejected = self.svc.rejected_receipts()
        self.assertTrue(any(r["reason"] == "LEDGER_NEVER_DISPATCHED" for r in rejected))

    def test_ledger_for_revoked_command_rejected(self):
        c = self._create(devices=("DEV-A1",))
        self.svc.revoke_command("ops", c["command_id"])
        self._hello("DEV-A1", "B1")
        self.svc.hello("DEV-A1", "B2", 1, ledger=[
            {"command_id": c["command_id"], "boot_code": "B1", "seq": 1,
             "result": "EXECUTED"}])
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t["status"], "SKIPPED")  # 已撤销事实不被账本翻案


class TestAuditChain(ServiceTestBase):
    def test_chain_verifies(self):
        for i in range(3):
            c = self._create(devices=("DEV-A1",))
            self._confirm(c)
        r = self.svc.verify_audit_chain()
        self.assertTrue(r["ok"])
        self.assertGreater(r["events"], 5)

    def test_chain_detects_tampering(self):
        c = self._create()
        self._confirm(c)
        # 直接篡改审计负载
        self.db.conn.execute("UPDATE events SET payload=? WHERE id=1",
                             ('{"hacked":true}',))
        self.db.commit()
        r = self.svc.verify_audit_chain()
        self.assertFalse(r["ok"])
        self.assertEqual(r["broken_at"], 1)  # 首条负载即被篡改，哈希立即对不上


if __name__ == "__main__":
    unittest.main()
