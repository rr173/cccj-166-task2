"""核心领域规则单元测试（无 HTTP，直接驱动服务层）。"""
from __future__ import annotations

import os
import tempfile
import unittest

from dual_gateway.config import load_config
from dual_gateway.errors import (Conflict, DeviceRejected, FrozenMismatch,
                                 InvalidReceipt, InvalidState, NotFound)
from dual_gateway.security import (command_fingerprint, ledger_entry_hash,
                                   sign_ledger_entry)
from dual_gateway.service import CommandService
from dual_gateway.storage import Storage

LEDGER_GENESIS = "0" * 64


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

    def _ledger_entry(self, dev, cid, boot, seq, result="EXECUTED",
                      digest=None, prev=LEDGER_GENESIS, message="done",
                      bad_sig=False, fingerprint=None, entry_hash=None,
                      key=None):
        """构造一条合法（或可注入篡改的）签名账簿条目。"""
        if digest is None:
            cmd = self.db.get_command_row(cid)
            digest = cmd["digest"] if cmd else None
        eh = entry_hash if entry_hash is not None else ledger_entry_hash(
            boot, seq, cid, result, prev)
        k = key if key is not None else cfg_keys(self.cfg)[dev]
        sig = "deadbeef" if bad_sig else sign_ledger_entry(k, eh)
        return {
            "command_id": cid, "boot_code": boot, "seq": seq,
            "result": result, "message": message,
            "prev": prev, "entry_hash": eh,
            "fingerprint": fingerprint if fingerprint is not None
            else command_fingerprint(cid, digest),
            "signature": sig,
        }


def cfg_keys(cfg):
    return cfg.device_keys


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
        # DEV-A2 一直离线；窗口关闭：A1 在途无终态→按过期 MISSED，A2 未投递→MISSED
        self.clock.advance(11)
        self.svc.sweep()
        got = self.svc.get_command(c["command_id"])
        statuses = {t["device_id"]: t["status"] for t in got["targets"]}
        self.assertEqual(statuses["DEV-A1"], "MISSED")
        self.assertEqual(statuses["DEV-A2"], "MISSED")
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
        info = self.svc.startup_recovery()
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t["status"], "DOUBT")
        self.assertEqual(info["tickets"], 1)
        tk = self.svc.list_recovery_tickets()
        self.assertEqual(len(tk), 1)
        self.assertEqual(tk[0]["status"], "OPEN")
        # 重复执行恢复扫描：幂等，不重复建工单
        self.svc.startup_recovery()
        self.assertEqual(len(self.svc.list_recovery_tickets()), 1)

    def test_ticket_not_created_for_never_dispatched(self):
        self._create(devices=("DEV-A1",))
        self.svc.startup_recovery()
        self.assertEqual(self.svc.list_recovery_tickets(), [])

    def test_ledger_recovers_executed_fact(self):
        c = self._create(devices=("DEV-A1",))
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        self.svc.startup_recovery()
        # 设备也重启了（新代号），但签名账簿证明旧代号下已执行
        self.svc.hello("DEV-A1", "B2", 1, ledger=[
            self._ledger_entry("DEV-A1", c["command_id"], "B1", 1)])
        got = self.svc.get_command(c["command_id"])
        self.assertEqual(got["status"], "EXECUTED")
        self.assertEqual(got["targets"][0]["receipt"]["source"], "LEDGER_RECOVERY")
        # 工单按事实结案，且结案动作是系统行为
        tk = self.svc.list_recovery_tickets(status="RESOLVED")[0]
        self.assertEqual(tk["resolution"], "FACT_RECOVERED")
        actions = {a["action"] for a in
                   self.svc.get_recovery_ticket(tk["ticket_id"])["history"]}
        self.assertIn("CREATED", actions)
        self.assertIn("FACT_RECOVERED", actions)

    def test_ledger_replay_is_idempotent(self):
        c = self._create(devices=("DEV-A1",))
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        self.svc.startup_recovery()
        entry = self._ledger_entry("DEV-A1", c["command_id"], "B1", 1)
        self.svc.hello("DEV-A1", "B2", 1, ledger=[entry])
        # 现场重复上传完全相同的账簿：整批从头幂等重放，不产生第二条事实/隔离
        out = self.svc.hello("DEV-A1", "B2", 1, ledger=[entry, entry])
        self.assertEqual(out["ledger"]["duplicates"], 2)
        self.assertEqual(out["ledger"]["recovered"], 0)
        self.assertEqual(out["ledger"]["quarantined"], [])
        got = self.svc.get_command(c["command_id"])
        self.assertEqual(len([t for t in got["targets"] if t["receipt"]]), 1)
        self.assertEqual(len(self.svc.list_quarantine()), 0)
        # 再只传一次同样也是 duplicate
        out = self.svc.hello("DEV-A1", "B2", 1, ledger=[entry])
        self.assertEqual(out["ledger"]["duplicates"], 1)

    def test_ledger_bad_signature_quarantined_no_state_change(self):
        c = self._create(devices=("DEV-A1",))
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        self.svc.startup_recovery()
        bad = self._ledger_entry("DEV-A1", c["command_id"], "B1", 1, bad_sig=True)
        self.svc.hello("DEV-A1", "B2", 1, ledger=[bad])
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t["status"], "DOUBT")  # 未执行结论不变
        self.assertIsNone(t["receipt"])
        q = self.svc.list_quarantine()
        self.assertEqual({x["reason"] for x in q}, {"LEDGER_BAD_SIGNATURE"})
        # 重复上传同一条坏材料：隔离区幂等，只留一条
        self.svc.hello("DEV-A1", "B2", 1, ledger=[bad])
        self.assertEqual(len(self.svc.list_quarantine()), 1)
        tk = self.svc.list_recovery_tickets()[0]
        self.assertEqual(tk["conflict_reason"], "LEDGER_BAD_SIGNATURE")

    def test_ledger_seq_gap_quarantined(self):
        c1 = self._create(devices=("DEV-A1",))
        self._confirm(c1)
        c2 = self._create(devices=("DEV-A1",))
        self._confirm(c2)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        self.svc.startup_recovery()
        # 只上传 c2 的 seq=2（缺口在 seq=1）：缺口隔离；c2 保持 DOUBT 不重投，
        # c1 没有任何材料，按“重启后未执行”正常重投
        e2 = self._ledger_entry("DEV-A1", c2["command_id"], "B1", 2)
        self.svc.hello("DEV-A1", "B2", 1, ledger=[e2])
        self.assertEqual({x["reason"] for x in self.svc.list_quarantine()},
                         {"LEDGER_SEQ_GAP"})
        s1 = self.svc.get_command(c1["command_id"])["targets"][0]["status"]
        s2 = self.svc.get_command(c2["command_id"])["targets"][0]["status"]
        self.assertEqual(s1, "PENDING")
        self.assertEqual(s2, "DOUBT")

    def test_ledger_chain_tamper_quarantined(self):
        c = self._create(devices=("DEV-A1",))
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        self.svc.startup_recovery()
        # 自洽签名但 prev 指向伪造前驱（断链）
        e = self._ledger_entry("DEV-A1", c["command_id"], "B1", 1,
                               prev="a" * 64)
        self.svc.hello("DEV-A1", "B2", 1, ledger=[e])
        reasons = {x["reason"] for x in self.svc.list_quarantine()}
        self.assertIn("LEDGER_CHAIN_BROKEN", reasons)
        self.assertIsNone(
            self.svc.get_command(c["command_id"])["targets"][0]["receipt"])

    def test_ledger_fingerprint_mismatch_quarantined(self):
        c = self._create(devices=("DEV-A1",))
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        self.svc.startup_recovery()
        e = self._ledger_entry("DEV-A1", c["command_id"], "B1", 1,
                               fingerprint="0" * 64)
        self.svc.hello("DEV-A1", "B2", 1, ledger=[e])
        self.assertEqual({x["reason"] for x in self.svc.list_quarantine()},
                         {"LEDGER_FINGERPRINT_MISMATCH"})
        self.assertEqual(
            self.svc.get_command(c["command_id"])["targets"][0]["status"], "DOUBT")

    def test_ledger_fact_conflict_quarantined(self):
        c = self._create(devices=("DEV-A1",))
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        self._receipt("DEV-A1", "B1", 1, c["command_id"], "EXECUTED")
        # 同代次同序号但结果矛盾：矛盾记录隔离，既成事实不动
        e = self._ledger_entry("DEV-A1", c["command_id"], "B1", 1, "FAILED")
        self.svc.hello("DEV-A1", "B2", 1, ledger=[e])
        self.assertEqual({x["reason"] for x in self.svc.list_quarantine()},
                         {"LEDGER_FACT_CONFLICT"})
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t["status"], "EXECUTED")

    def test_ledger_old_boot_material_quarantined(self):
        # 未知（旧代次/伪造）启动代号材料：只隔离留痕
        self._hello("DEV-A1", "B1")
        entry = {
            "command_id": "CMD-X", "boot_code": "BOOT-OLD-GEN", "seq": 1,
            "result": "EXECUTED", "prev": LEDGER_GENESIS,
            "entry_hash": ledger_entry_hash(
                "BOOT-OLD-GEN", 1, "CMD-X", "EXECUTED", LEDGER_GENESIS),
            "fingerprint": command_fingerprint("CMD-X", None),
            "signature": sign_ledger_entry(
                self.cfg.device_keys["DEV-A1"],
                ledger_entry_hash("BOOT-OLD-GEN", 1, "CMD-X", "EXECUTED",
                                  LEDGER_GENESIS)),
        }
        self.svc.hello("DEV-A1", "B2", 1, ledger=[entry])
        self.assertEqual({x["reason"] for x in self.svc.list_quarantine()},
                         {"LEDGER_UNKNOWN_BOOT"})

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
        # 自动重投在工单历史留痕，工单仍 OPEN（等回执结案）
        tk = self.svc.list_recovery_tickets(status="OPEN")[0]
        actions = [a["action"] for a in
                   self.svc.get_recovery_ticket(tk["ticket_id"])["history"]]
        self.assertIn("REDELIVER_AFTER_REBOOT", actions)

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
        tk = self.svc.list_recovery_tickets(status="RESOLVED")[0]
        self.assertEqual(tk["resolution"], "CLOSED_MISSED")

    def test_ledger_after_missed_reopens_and_recovers_fact(self):
        c = self._create(devices=("DEV-A1",), valid_seconds=10)
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        self.svc.startup_recovery()
        self.clock.advance(20)
        self.svc.hello("DEV-A1", "B2", 1, ledger=[])  # 先判 MISSED 结案
        self.assertEqual(
            self.svc.get_command(c["command_id"])["targets"][0]["status"], "MISSED")
        # 之后设备重连同代号旧账，带签名账簿补证当时已执行：事实优先
        self.svc.hello("DEV-A1", "B2", 1, ledger=[
            self._ledger_entry("DEV-A1", c["command_id"], "B1", 1)])
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t["status"], "EXECUTED")
        tk = self.svc.list_recovery_tickets(status="RESOLVED")[0]
        self.assertEqual(tk["resolution"], "FACT_RECOVERED")
        actions = {a["action"] for a in
                   self.svc.get_recovery_ticket(tk["ticket_id"])["history"]}
        self.assertIn("FACT_RECOVERED_AFTER_MISSED", actions)

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
        # 对从未投递的指令伪造合法格式签名账簿：不改任何状态，进隔离区
        self._hello("DEV-A1", "B1")
        fake = {
            "command_id": "CMD-FAKE", "boot_code": "B1", "seq": 1,
            "result": "EXECUTED", "prev": LEDGER_GENESIS,
            "entry_hash": ledger_entry_hash(
                "B1", 1, "CMD-FAKE", "EXECUTED", LEDGER_GENESIS),
            "fingerprint": command_fingerprint("CMD-FAKE", None),
            "signature": sign_ledger_entry(
                self.cfg.device_keys["DEV-A1"],
                ledger_entry_hash("B1", 1, "CMD-FAKE", "EXECUTED",
                                  LEDGER_GENESIS)),
        }
        self.svc.hello("DEV-A1", "B2", 1, ledger=[fake])
        self.assertTrue(any(q["reason"] == "LEDGER_NEVER_DISPATCHED"
                            for q in self.svc.list_quarantine()))

    def test_ledger_for_revoked_command_rejected(self):
        c = self._create(devices=("DEV-A1",))
        self.svc.revoke_command("ops", c["command_id"])
        self._hello("DEV-A1", "B1")
        self.svc.hello("DEV-A1", "B2", 1, ledger=[
            self._ledger_entry("DEV-A1", c["command_id"], "B1", 1)])
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t["status"], "SKIPPED")  # 已撤销事实不被账本翻案
        self.assertTrue(any(q["reason"].startswith("LEDGER_STATE_FORBIDDEN")
                            for q in self.svc.list_quarantine()))


class TestTicketDisposition(ServiceTestBase):
    def _open_ticket(self, valid_seconds=100):
        c = self._create(devices=("DEV-A1",), valid_seconds=valid_seconds)
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        self.svc.startup_recovery()
        return c, self.svc.list_recovery_tickets()[0]

    def test_note_does_not_change_state(self):
        c, tk = self._open_ticket()
        out = self.svc.dispose_ticket("supervisor", tk["ticket_id"],
                                      "MANUAL_NOTE", "等现场回传")
        self.assertEqual(out["status"], "OPEN")
        self.assertEqual(
            self.svc.get_command(c["command_id"])["targets"][0]["status"], "DOUBT")

    def test_approve_redeliver_within_window(self):
        c, tk = self._open_ticket()
        self.svc.dispose_ticket("supervisor", tk["ticket_id"],
                                "APPROVE_REDELIVER", "人工核实未执行")
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t["status"], "PENDING")
        # 工单仍挂起，设备以新代号上线拉取后回执结案
        self._hello("DEV-A1", "B2")
        self.svc.pull("DEV-A1", "B2")
        self._receipt("DEV-A1", "B2", 1, c["command_id"])
        tk2 = self.svc.get_recovery_ticket(tk["ticket_id"])
        self.assertEqual(tk2["status"], "RESOLVED")
        self.assertEqual(tk2["resolution"], "FACT_REPORTED")

    def test_approve_redeliver_after_window_refused(self):
        c, tk = self._open_ticket(valid_seconds=10)
        self.clock.advance(20)
        with self.assertRaises(Conflict):
            self.svc.dispose_ticket("supervisor", tk["ticket_id"],
                                    "APPROVE_REDELIVER")

    def test_manual_missed_requires_expired_window(self):
        c, tk = self._open_ticket()
        with self.assertRaises(Conflict):
            self.svc.dispose_ticket("supervisor", tk["ticket_id"], "CLOSED_MISSED")
        self.clock.advance(120)
        out = self.svc.dispose_ticket("supervisor", tk["ticket_id"],
                                      "CLOSED_MISSED", "现场确认未执行且窗口关闭")
        self.assertEqual(out["status"], "RESOLVED")
        self.assertEqual(out["resolution"], "CLOSED_MISSED")
        self.assertEqual(
            self.svc.get_command(c["command_id"])["targets"][0]["status"], "MISSED")

    def test_human_cannot_overwrite_executed_fact(self):
        c, tk = self._open_ticket()
        # 签名账簿补记已执行事实
        self.svc.hello("DEV-A1", "B2", 1, ledger=[
            self._ledger_entry("DEV-A1", c["command_id"], "B1", 1)])
        # 任何人工处置（除备注）都必须被拒绝
        for act in ("APPROVE_REDELIVER", "CLOSED_MISSED"):
            with self.assertRaises(Conflict):
                self.svc.dispose_ticket("supervisor", tk["ticket_id"], act)
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t["status"], "EXECUTED")
        self.assertEqual(t["receipt"]["result"], "EXECUTED")


class TestWindowTickets(ServiceTestBase):
    def test_window_close_creates_ticket_for_doubt(self):
        c = self._create(devices=("DEV-A1", "DEV-A2"), valid_seconds=10)
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")  # A1 在途；A2 从未上线
        self.clock.advance(11)
        self.svc.sweep()
        # A1：窗口关闭仍无事实→MISSED；事故工单已创建并按过期结案
        t1 = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t1["status"], "MISSED")
        tickets = self.svc.list_recovery_tickets()
        self.assertEqual(len(tickets), 1)  # A1 有事故工单，A2（从未送达）没有
        self.assertEqual(tickets[0]["device_id"], "DEV-A1")
        self.assertEqual(tickets[0]["reason"], "WINDOW_CLOSED")
        self.assertEqual(tickets[0]["status"], "RESOLVED")
        self.assertEqual(tickets[0]["resolution"], "CLOSED_MISSED")
        self.assertEqual(
            self.svc.get_command(c["command_id"])["targets"][1]["status"], "MISSED")
        # 之后签名账簿补证 A1 当时已执行：事实翻案，工单重开后按事实结案
        self.svc.hello("DEV-A1", "B2", 1, ledger=[
            self._ledger_entry("DEV-A1", c["command_id"], "B1", 1)])
        t1 = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t1["status"], "EXECUTED")
        tk = self.svc.get_recovery_ticket(tickets[0]["ticket_id"])
        self.assertEqual(tk["resolution"], "FACT_RECOVERED")
        self.assertTrue(any(a["action"] == "FACT_RECOVERED_AFTER_MISSED"
                            for a in tk["history"]))


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
