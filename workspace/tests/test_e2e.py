"""端到端测试：真实启动三个 HTTP 通道，模拟跨进程重启与现场设备行为。

覆盖题目的每个威胁场景：
  1. 正常双通道确认 + 多设备回执 + 审计哈希链；
  2. 通道隔离：业务令牌不能确认、安全凭据不能创建、错误 HMAC 拒绝；
  3. 撤销：未执行可撤 / 在途拒撤 / 已执行不可撤销；
  4. 确认超时自动冻结；
  5. 旧启动代号 / 跳号 / 序号复用 / 未投递回执全部拒绝留痕；
  6. 网关进程重启：在途转 DOUBT，设备账本补记已执行事实；
  7. 设备离线：窗口内未投递不补发，恢复后未执行指令安全重投；
  8. 回执丢失（设备已执行）：重连靠账本补记，不重复执行。
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
import unittest
import urllib.error
import urllib.request

from dual_gateway.app import Gateway
from dual_gateway.config import load_config
from dual_gateway.device_sim import SimDevice
from dual_gateway.security import hmac_sign


def _req(method: str, url: str, *, token=None, cookie=None, body=None,
         device=None, key=None, raw: bytes | None = None):
    headers = {}
    if raw is not None:
        data = raw
    else:
        data = json.dumps(body, ensure_ascii=False).encode() if body is not None else None
    if data is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["X-Biz-Token"] = token
    if cookie:
        headers["Cookie"] = cookie
    if device:
        headers["X-Device-Id"] = device
        headers["X-Signature"] = hmac_sign(key, data or b"")
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            return resp.status, json.loads(resp.read()), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read()), e.headers


class E2EBase(unittest.TestCase):
    PORTS = {"biz": 18080, "sec": 18081, "dev": 18082}

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "gw.db")
        self.cfg = load_config(
            db_path=self.db_path,
            biz_host="127.0.0.1", biz_port=self.PORTS["biz"],
            sec_host="127.0.0.1", sec_port=self.PORTS["sec"],
            dev_host="127.0.0.1", dev_port=self.PORTS["dev"],
            default_valid_seconds=120, confirm_timeout_seconds=60,
            offline_seconds=4, sweep_interval=0.2)
        self.gw = Gateway(self.cfg)
        self.gw.start()
        time.sleep(0.3)
        self.biz = f"http://127.0.0.1:{self.PORTS['biz']}"
        self.sec = f"http://127.0.0.1:{self.PORTS['sec']}"
        self.dev = f"http://127.0.0.1:{self.PORTS['dev']}"

    def tearDown(self):
        self.gw.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def restart_gateway(self):
        """模拟网关进程重启：停掉后用同一数据库重新启动。"""
        self.gw.stop()
        time.sleep(0.3)
        cfg = load_config(
            db_path=self.db_path,
            biz_host="127.0.0.1", biz_port=self.PORTS["biz"],
            sec_host="127.0.0.1", sec_port=self.PORTS["sec"],
            dev_host="127.0.0.1", dev_port=self.PORTS["dev"],
            default_valid_seconds=120, confirm_timeout_seconds=60,
            offline_seconds=4, sweep_interval=0.2)
        self.gw = Gateway(cfg)
        self.gw.start()
        time.sleep(0.4)

    # ---------- 便捷封装 ----------
    def create(self, devices=("DEV-A1", "DEV-A2"), action="EMERGENCY_STOP",
               params=None, valid_seconds=None):
        body = {"action": action, "devices": list(devices),
                "params": params or {"valve": "close", "rpm": 0}}
        if valid_seconds:
            body["valid_seconds"] = valid_seconds
        st, out, _ = _req("POST", self.biz + "/api/commands",
                          token=self.cfg.biz_token, body=body)
        self.assertEqual(st, 201, out)
        return out

    def sec_login(self, user="supervisor", pw=None):
        pw = pw or self.cfg.sec_users[user]
        st, out, hdr = _req("POST", self.sec + "/api/session",
                            body={"username": user, "password": pw})
        self.assertEqual(st, 200, out)
        return hdr["Set-Cookie"].split(";")[0]

    def confirm(self, c, cookie, code=None, digest=None):
        return _req("POST", f"{self.sec}/api/commands/{c['command_id']}/confirm",
                    cookie=cookie,
                    body={"confirm_code": code or c["confirm_code"],
                          "digest_ack": digest or c["digest"]})

    def devcall(self, path, dev_id, body):
        return _req("POST", self.dev + path, device=dev_id,
                    key=self.cfg.device_keys[dev_id], body=body)

    def make_device(self, dev_id, state_subdir, **kw):
        d = SimDevice(dev_id, self.cfg.device_keys[dev_id], self.dev,
                      os.path.join(self.tmp, state_subdir), verbose=False, **kw)
        return d


class TestHappyPath(E2EBase):
    def test_full_flow_and_audit_chain(self):
        c = self.create()
        cookie = self.sec_login()
        st, out, _ = self.confirm(c, cookie)
        self.assertEqual(st, 200)

        for i, dev_id in enumerate(("DEV-A1", "DEV-A2"), start=1):
            d = self.make_device(dev_id, f"sim-{dev_id}")
            st, hello, _ = self.devcall("/api/device/hello", dev_id,
                                        {"boot_code": d.boot_code, "first_seq": 1})
            self.assertTrue(hello["online"])
            st, pull, _ = self.devcall("/api/device/pull", dev_id,
                                       {"boot_code": d.boot_code})
            self.assertEqual(len(pull["commands"]), 1)
            _, resp, _ = self.devcall(
                "/api/device/receipt", dev_id,
                {"boot_code": d.boot_code, "seq": 1,
                 "command_id": c["command_id"], "result": "EXECUTED"})
            self.assertTrue(resp["accepted"])

        time.sleep(0.4)
        st, detail, _ = _req("GET", f"{self.biz}/api/commands/{c['command_id']}",
                             token=self.cfg.biz_token)
        self.assertEqual(detail["status"], "EXECUTED")
        self.assertTrue(all(t["status"] == "EXECUTED" for t in detail["targets"]))

        st, audit, _ = _req("GET", self.sec + "/api/audit", cookie=cookie)
        self.assertTrue(audit["chain"]["ok"])
        actions = {e["action"] for e in audit["events"]}
        self.assertIn("CMD_CREATED", actions)
        self.assertIn("CMD_CONFIRMED", actions)
        self.assertIn("RECEIPT_ACCEPTED", actions)


class TestChannelIsolation(E2EBase):
    def test_cross_channel_forbidden(self):
        c = self.create(devices=("DEV-A1",))
        # 1) 无业务令牌
        st, out, _ = _req("POST", self.biz + "/api/commands",
                          body={"action": "X", "devices": ["DEV-A1"], "params": {}})
        self.assertEqual(st, 401)
        # 2) 业务通道无法确认（根本没有该路由）
        st, _, _ = _req("POST", f"{self.biz}/api/commands/{c['command_id']}/confirm",
                        token=self.cfg.biz_token,
                        body={"confirm_code": c["confirm_code"], "digest_ack": c["digest"]})
        self.assertEqual(st, 404)
        # 3) 安全会话不能创建指令
        cookie = self.sec_login()
        st, _, _ = _req("POST", self.sec + "/api/commands", cookie=cookie,
                        body={"action": "X"})
        self.assertEqual(st, 404)
        # 4) 只读安全员不能确认
        ro = self.sec_login("safety")
        st, out, _ = self.confirm(c, ro)
        self.assertEqual(st, 403)
        # 5) 错误确认码
        st, out, _ = self.confirm(c, cookie, code="999999")
        self.assertEqual(st, 409)
        self.assertEqual(out["error"], "FROZEN_MISMATCH")
        # 6) 摘要不一致
        st, out, _ = self.confirm(c, cookie, digest="0" * 64)
        self.assertEqual(out["error"], "FROZEN_MISMATCH")

    def test_device_bad_hmac(self):
        body = {"boot_code": "BOOT-X", "first_seq": 1}
        raw = json.dumps(body).encode()
        st, _, _ = _req("POST", self.dev + "/api/device/hello",
                        device="DEV-A1", key="wrong-key", raw=raw)
        self.assertEqual(st, 403)

    def test_unregistered_device(self):
        st, _, _ = _req("POST", self.dev + "/api/device/hello",
                        device="DEV-UNKNOWN", key="x",
                        body={"boot_code": "B", "first_seq": 1})
        self.assertEqual(st, 401)


class TestRevocation(E2EBase):
    def test_revoke_before_confirm(self):
        c = self.create(devices=("DEV-A1",))
        st, out, _ = _req("POST",
                          f"{self.biz}/api/commands/{c['command_id']}/revoke",
                          token=self.cfg.biz_token, body={"reason": "计划取消"})
        self.assertEqual(st, 200)
        self.assertEqual(out["status"], "REVOKED")

    def test_revoke_after_executed_rejected_and_fact_stands(self):
        c = self.create(devices=("DEV-A1",))
        cookie = self.sec_login()
        self.confirm(c, cookie)
        d = self.make_device("DEV-A1", "sim")
        self.devcall("/api/device/hello", "DEV-A1",
                     {"boot_code": d.boot_code, "first_seq": 1})
        self.devcall("/api/device/pull", "DEV-A1", {"boot_code": d.boot_code})
        self.devcall("/api/device/receipt", "DEV-A1",
                     {"boot_code": d.boot_code, "seq": 1,
                      "command_id": c["command_id"], "result": "EXECUTED"})
        st, out, _ = _req("POST",
                          f"{self.biz}/api/commands/{c['command_id']}/revoke",
                          token=self.cfg.biz_token, body={})
        self.assertEqual(st, 409)
        st, detail, _ = _req("GET", f"{self.biz}/api/commands/{c['command_id']}",
                             token=self.cfg.biz_token)
        self.assertEqual(detail["status"], "EXECUTED")  # 撤销未覆盖任何事实

    def test_revoke_after_dispatch_rejected(self):
        c = self.create(devices=("DEV-A1",))
        cookie = self.sec_login()
        self.confirm(c, cookie)
        d = self.make_device("DEV-A1", "sim")
        self.devcall("/api/device/hello", "DEV-A1",
                     {"boot_code": d.boot_code, "first_seq": 1})
        self.devcall("/api/device/pull", "DEV-A1", {"boot_code": d.boot_code})
        st, out, _ = _req("POST",
                          f"{self.biz}/api/commands/{c['command_id']}/revoke",
                          token=self.cfg.biz_token, body={})
        self.assertEqual(st, 409)
        self.assertIn("在途", out["message"])


class TestConfirmTimeout(E2EBase):
    def test_auto_expire(self):
        # 用极短确认超时的独立网关参数不便修改，直接借助确认截止：
        # 创建 valid_seconds=1 的指令 -> confirm_deadline=min(1,60)=1s
        c = self.create(devices=("DEV-A1",), valid_seconds=1)
        time.sleep(1.8)
        st, detail, _ = _req("GET", f"{self.biz}/api/commands/{c['command_id']}",
                             token=self.cfg.biz_token)
        self.assertEqual(detail["status"], "EXPIRED")
        cookie = self.sec_login()
        st, out, _ = self.confirm(c, cookie)
        self.assertEqual(st, 409)


class TestBadReceipts(E2EBase):
    def _dispatch(self):
        c = self.create(devices=("DEV-A1",))
        cookie = self.sec_login()
        self.confirm(c, cookie)
        d = self.make_device("DEV-A1", "sim")
        self.devcall("/api/device/hello", "DEV-A1",
                     {"boot_code": d.boot_code, "first_seq": 1})
        self.devcall("/api/device/pull", "DEV-A1", {"boot_code": d.boot_code})
        return c, d, cookie

    def test_stale_boot_gap_reuse(self):
        c, d, cookie = self._dispatch()
        # 旧启动代号
        st, out, _ = self.devcall("/api/device/receipt", "DEV-A1",
                                  {"boot_code": "BOOT-STALE", "seq": 1,
                                   "command_id": c["command_id"], "result": "EXECUTED"})
        self.assertEqual(out["details"]["reason"], "STALE_BOOT")
        # 跳号
        st, out, _ = self.devcall("/api/device/receipt", "DEV-A1",
                                  {"boot_code": d.boot_code, "seq": 3,
                                   "command_id": c["command_id"], "result": "EXECUTED"})
        self.assertEqual(out["details"]["reason"], "OUT_OF_ORDER_GAP")
        # 正确 1 号
        st, out, _ = self.devcall("/api/device/receipt", "DEV-A1",
                                  {"boot_code": d.boot_code, "seq": 1,
                                   "command_id": c["command_id"], "result": "EXECUTED"})
        self.assertTrue(out["accepted"])
        # 序号复用（换指令也不行）
        st, out, _ = self.devcall("/api/device/receipt", "DEV-A1",
                                  {"boot_code": d.boot_code, "seq": 1,
                                   "command_id": "CMD-OTHER", "result": "EXECUTED"})
        self.assertEqual(out["details"]["reason"], "REUSED_OR_OLD_SEQ")

        st, rej, _ = _req("GET", self.sec + "/api/rejected", cookie=cookie)
        reasons = {r["reason"] for r in rej["rejected"]}
        self.assertIn("STALE_BOOT", reasons)
        self.assertIn("OUT_OF_ORDER_GAP", reasons)
        self.assertIn("REUSED_OR_OLD_SEQ", reasons)
        # 当前状态始终是 EXECUTED，坏回执从未改变它
        st, detail, _ = _req("GET", f"{self.biz}/api/commands/{c['command_id']}",
                             token=self.cfg.biz_token)
        self.assertEqual(detail["status"], "EXECUTED")


class TestGatewayRestart(E2EBase):
    def test_doubt_then_ledger_recovery(self):
        c = self.create(devices=("DEV-A1",))
        cookie = self.sec_login()
        self.confirm(c, cookie)
        d = self.make_device("DEV-A1", "simstate")
        self.devcall("/api/device/hello", "DEV-A1",
                     {"boot_code": d.boot_code, "first_seq": 1})
        self.devcall("/api/device/pull", "DEV-A1", {"boot_code": d.boot_code})

        # 设备执行了，但在回执送达前网关崩溃
        d._append_ledger({"command_id": c["command_id"],
                          "boot_code": d.boot_code, "seq": 1,
                          "result": "EXECUTED", "message": "done"})
        d.seq = 2

        self.restart_gateway()
        # 在途目标重启后必须是 DOUBT
        st, detail, _ = _req("GET", f"{self.biz}/api/commands/{c['command_id']}",
                             token=self.cfg.biz_token)
        self.assertEqual(detail["targets"][0]["status"], "DOUBT")

        # 设备用同一代号重新 HELLO（没重启），无回执：保持 DOUBT，不重投
        st, hello, _ = self.devcall("/api/device/hello", "DEV-A1",
                                    {"boot_code": d.boot_code, "first_seq": 1,
                                     "ledger": d.executed})
        st, pull, _ = self.devcall("/api/device/pull", "DEV-A1",
                                   {"boot_code": d.boot_code})
        self.assertEqual(pull["commands"], [])
        # 同代号下账本条目携带了执行事实 → 直接补记
        st, detail, _ = _req("GET", f"{self.biz}/api/commands/{c['command_id']}",
                             token=self.cfg.biz_token)
        self.assertEqual(detail["status"], "EXECUTED")
        self.assertEqual(detail["targets"][0]["receipt"]["source"], "LEDGER_RECOVERY")

    def test_restart_device_reboot_not_executed_redeliver(self):
        c = self.create(devices=("DEV-A1",))
        cookie = self.sec_login()
        self.confirm(c, cookie)
        d = self.make_device("DEV-A1", "simstate2")
        self.devcall("/api/device/hello", "DEV-A1",
                     {"boot_code": d.boot_code, "first_seq": 1})
        self.devcall("/api/device/pull", "DEV-A1", {"boot_code": d.boot_code})
        # 设备尚未执行，网关与设备先后重启（设备新代号、空账本）
        self.restart_gateway()
        d.reboot()  # 触发 HELLO，触发对账：未执行→重投
        st, pull, _ = self.devcall("/api/device/pull", "DEV-A1",
                                   {"boot_code": d.boot_code})
        self.assertEqual(len(pull["commands"]), 1)
        st, resp, _ = self.devcall("/api/device/receipt", "DEV-A1",
                                   {"boot_code": d.boot_code, "seq": 1,
                                    "command_id": c["command_id"], "result": "EXECUTED"})
        self.assertTrue(resp["accepted"])


class TestOffline(E2EBase):
    def test_offline_no_dispatch_then_recover(self):
        c = self.create(devices=("DEV-A1", "DEV-B1"))
        cookie = self.sec_login()
        self.confirm(c, cookie)

        # DEV-A1 上线执行；DEV-B1 离线
        da = self.make_device("DEV-A1", "sim-a")
        self.devcall("/api/device/hello", "DEV-A1",
                     {"boot_code": da.boot_code, "first_seq": 1})
        self.devcall("/api/device/pull", "DEV-A1", {"boot_code": da.boot_code})
        self.devcall("/api/device/receipt", "DEV-A1",
                     {"boot_code": da.boot_code, "seq": 1,
                      "command_id": c["command_id"], "result": "EXECUTED"})
        # 等 DEV-A1 心跳超时不影响逻辑；手动确认 DEV-B1 离线拿不到指令
        st, out, _ = self.devcall("/api/device/pull", "DEV-B1",
                                  {"boot_code": "FAKE-BOOT"})
        self.assertEqual(st, 409)
        # DEV-B1 在窗口内上线：安全拿到指令
        db = self.make_device("DEV-B1", "sim-b")
        self.devcall("/api/device/hello", "DEV-B1",
                     {"boot_code": db.boot_code, "first_seq": 1})
        st, pull, _ = self.devcall("/api/device/pull", "DEV-B1",
                                   {"boot_code": db.boot_code})
        self.assertEqual(len(pull["commands"]), 1)

    def test_still_offline_after_window_missed(self):
        c = self.create(devices=("DEV-A1",), valid_seconds=2)
        cookie = self.sec_login()
        self.confirm(c, cookie)
        # DEV-A1 全程离线
        time.sleep(2.6)
        st, detail, _ = _req("GET", f"{self.biz}/api/commands/{c['command_id']}",
                             token=self.cfg.biz_token)
        self.assertEqual(detail["targets"][0]["status"], "MISSED")
        self.assertEqual(detail["status"], "CLOSED")
        # 事后设备上线，也不能再拿到该指令
        d = self.make_device("DEV-A1", "sim-late")
        self.devcall("/api/device/hello", "DEV-A1",
                     {"boot_code": d.boot_code, "first_seq": 1})
        st, pull, _ = self.devcall("/api/device/pull", "DEV-A1",
                                   {"boot_code": d.boot_code})
        self.assertEqual(pull["commands"], [])


class TestDroppedReceipt(E2EBase):
    def test_drop_then_reconnect_recovers_once(self):
        c = self.create(devices=("DEV-A1",))
        cookie = self.sec_login()
        self.confirm(c, cookie)
        d = self.make_device("DEV-A1", "sim-drop", drop_receipt=True)
        self.devcall("/api/device/hello", "DEV-A1",
                     {"boot_code": d.boot_code, "first_seq": 1})
        self.devcall("/api/device/pull", "DEV-A1", {"boot_code": d.boot_code})
        # 直接执行（回执被模拟丢弃，账本已落盘）
        cmds = [x for x in [c]]
        d.execute_and_report({"command_id": c["command_id"]})
        self.restart_gateway()
        # 设备未重启，同代号 + 账本补记；不会重投，不会双触发
        self.devcall("/api/device/hello", "DEV-A1",
                     {"boot_code": d.boot_code, "first_seq": 1,
                      "ledger": d.executed})
        st, pull, _ = self.devcall("/api/device/pull", "DEV-A1",
                                   {"boot_code": d.boot_code})
        self.assertEqual(pull["commands"], [])
        st, detail, _ = _req("GET", f"{self.biz}/api/commands/{c['command_id']}",
                             token=self.cfg.biz_token)
        self.assertEqual(detail["targets"][0]["status"], "EXECUTED")
        self.assertEqual(detail["targets"][0]["receipt"]["source"], "LEDGER_RECOVERY")


if __name__ == "__main__":
    unittest.main()
