"""SQLite 持久层：append-only 事件日志 + 物化状态表。

不变量：

1. 任何状态变迁都先在同一事务里追加一条带哈希链的审计事件，
   事件链为 EVENTS 表上的全序链：hash_n = SHA256(hash_{n-1} || type || payload)；
2. 已写为 EXECUTED/FAILED 的目标终态，UPDATE 语句层面带状态条件，
   即使上层逻辑出错也无法被覆盖；
3. (command_id, device_id) 上的回执唯一约束保证同一设备对同一指令
   至多形成一条执行事实；乱序/旧代号的回执写入 rejected_receipts 留痕。
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Optional

from .security import GENESIS_HASH, event_hash

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    device_id       TEXT PRIMARY KEY,
    preshared_key   TEXT NOT NULL,
    registered_at   REAL NOT NULL,
    online          INTEGER NOT NULL DEFAULT 0,
    current_boot    TEXT,
    boot_first_seq  INTEGER,
    ledger_head_seq INTEGER,
    last_seen       REAL
);

CREATE TABLE IF NOT EXISTS device_boots (
    device_id TEXT NOT NULL,
    boot_code TEXT NOT NULL,
    first_seq INTEGER NOT NULL,
    hello_at  REAL NOT NULL,
    PRIMARY KEY (device_id, boot_code)
);

CREATE TABLE IF NOT EXISTS commands (
    command_id        TEXT PRIMARY KEY,
    action            TEXT NOT NULL,
    device_set        TEXT NOT NULL,   -- JSON sorted list，冻结
    params            TEXT NOT NULL,   -- JSON canonical，冻结
    digest            TEXT NOT NULL,   -- 冻结摘要
    valid_from        REAL NOT NULL,
    valid_to          REAL NOT NULL,
    confirm_deadline  REAL NOT NULL,
    status            TEXT NOT NULL,
    confirm_code_hash TEXT NOT NULL,
    created_by        TEXT NOT NULL,
    created_at        REAL NOT NULL,
    confirmed_by      TEXT,
    confirmed_at      REAL,
    revoked_by        TEXT,
    revoked_at        REAL,
    reject_reason     TEXT
);

CREATE TABLE IF NOT EXISTS targets (
    command_id      TEXT NOT NULL,
    device_id       TEXT NOT NULL,
    status          TEXT NOT NULL,
    dispatched_at   REAL,
    dispatched_boot TEXT,
    updated_at      REAL NOT NULL,
    PRIMARY KEY (command_id, device_id)
);

CREATE TABLE IF NOT EXISTS receipts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    command_id  TEXT NOT NULL,
    device_id   TEXT NOT NULL,
    boot_code   TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    result      TEXT NOT NULL,
    message     TEXT,
    source      TEXT NOT NULL,
    event_id    INTEGER NOT NULL,
    received_at REAL NOT NULL,
    UNIQUE (command_id, device_id)
);

CREATE TABLE IF NOT EXISTS rejected_receipts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   TEXT NOT NULL,
    boot_code   TEXT,
    seq         INTEGER,
    reason      TEXT NOT NULL,
    raw         TEXT NOT NULL,
    received_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    actor     TEXT NOT NULL,
    channel   TEXT NOT NULL,
    action    TEXT NOT NULL,
    command_id TEXT,
    device_id TEXT,
    payload   TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_targets_device ON targets(device_id, status);
CREATE INDEX IF NOT EXISTS idx_commands_status ON commands(status);
CREATE INDEX IF NOT EXISTS idx_receipts_device ON receipts(device_id);
CREATE INDEX IF NOT EXISTS idx_receipts_seq ON receipts(device_id, boot_code, seq);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
"""


class Storage:
    def __init__(self, db_path: str):
        if db_path != ":memory:":
            import os
            os.makedirs(os.path.dirname(os.path.abspath(db_path)) or ".", exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self):
        self.conn.close()

    # ---------- 基础工具 ----------
    @staticmethod
    def _jloads(s: str) -> Any:
        return json.loads(s) if s is not None else None

    def meta_get(self, key: str) -> Optional[str]:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def meta_set(self, key: str, value: str):
        self.conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def append_event(self, ts: float, actor: str, channel: str, action: str,
                     payload: dict, command_id: str | None = None,
                     device_id: str | None = None) -> int:
        """在事务内取链尾哈希、计算新哈希并追加事件（调用方持锁）。"""
        cur = self.conn.execute(
            "SELECT hash FROM events ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        prev = row["hash"] if row else GENESIS_HASH
        h = event_hash(prev, action, payload)
        cur = self.conn.execute(
            "INSERT INTO events(ts,actor,channel,action,command_id,device_id,"
            "payload,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?)",
            (ts, actor, channel, action, command_id, device_id,
             json.dumps(payload, ensure_ascii=False, sort_keys=True), prev, h))
        return cur.lastrowid

    def list_events(self, limit: int = 200, command_id: str | None = None,
                    device_id: str | None = None) -> list[dict]:
        sql = "SELECT * FROM events WHERE 1=1"
        args: list = []
        if command_id:
            sql += " AND command_id=?"
            args.append(command_id)
        if device_id:
            sql += " AND device_id=?"
            args.append(device_id)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        rows = self.conn.execute(sql, args).fetchall()
        return [dict(r) for r in rows]

    def verify_chain(self) -> dict:
        """独立重放全链，校验哈希完整性与全序性。"""
        rows = self.conn.execute("SELECT * FROM events ORDER BY id").fetchall()
        prev = GENESIS_HASH
        for r in rows:
            payload = self._jloads(r["payload"])
            expect = event_hash(prev, r["action"], payload)
            if r["prev_hash"] != prev:
                return {"ok": False, "broken_at": r["id"], "reason": "prev_hash mismatch"}
            if r["hash"] != expect:
                return {"ok": False, "broken_at": r["id"], "reason": "hash mismatch"}
            prev = r["hash"]
        return {"ok": True, "events": len(rows), "head": prev}

    # ---------- 设备 ----------
    def seed_device(self, device_id: str, key: str, now: float):
        self.conn.execute(
            "INSERT OR IGNORE INTO devices(device_id,preshared_key,registered_at) "
            "VALUES(?,?,?)", (device_id, key, now))

    def get_device(self, device_id: str) -> Optional[dict]:
        row = self.conn.execute("SELECT * FROM devices WHERE device_id=?",
                                (device_id,)).fetchone()
        return dict(row) if row else None

    def list_devices(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM devices ORDER BY device_id")]

    def know_boot(self, device_id: str, boot_code: str, first_seq: int, now: float):
        self.conn.execute(
            "INSERT OR IGNORE INTO device_boots(device_id,boot_code,first_seq,hello_at)"
            " VALUES(?,?,?,?)", (device_id, boot_code, first_seq, now))

    def boot_known(self, device_id: str, boot_code: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM device_boots WHERE device_id=? AND boot_code=?",
            (device_id, boot_code)).fetchone()
        return dict(row) if row else None

    def mark_online(self, device_id: str, boot_code: str, first_seq: int, now: float):
        """HELLO：登记新启动代号。

        boot_first_seq 为该启动代号下首个回执序号（通常为 1）；
        ledger_head_seq 为已连续确认到的序号（初始 first_seq-1）。
        """
        self.conn.execute(
            "UPDATE devices SET online=1,current_boot=?,boot_first_seq=?,"
            "ledger_head_seq=?,last_seen=? WHERE device_id=?",
            (boot_code, first_seq, first_seq - 1, now, device_id))

    def heartbeat(self, device_id: str, boot_code: str, now: float) -> bool:
        # 心跳必须携带当前启动代号；旧代号心跳视为重启后的残影，拒绝并留痕由上层做
        cur = self.conn.execute(
            "UPDATE devices SET last_seen=? WHERE device_id=? AND current_boot=?",
            (now, device_id, boot_code))
        return cur.rowcount == 1

    def mark_offline(self, device_id: str):
        self.conn.execute("UPDATE devices SET online=0 WHERE device_id=?", (device_id,))

    def advance_ledger_head(self, device_id: str, seq: int):
        self.conn.execute(
            "UPDATE devices SET ledger_head_seq=? WHERE device_id=? AND "
            "(ledger_head_seq IS NULL OR ledger_head_seq<?)",
            (seq, device_id, seq))

    # ---------- 指令 ----------
    def insert_command(self, c: dict, devices: list[str], now: float):
        self.conn.execute(
            "INSERT INTO commands(command_id,action,device_set,params,digest,"
            "valid_from,valid_to,confirm_deadline,status,confirm_code_hash,"
            "created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (c["command_id"], c["action"], json.dumps(devices, ensure_ascii=False),
             json.dumps(c["params"], ensure_ascii=False, sort_keys=True),
             c["digest"], c["valid_from"], c["valid_to"], c["confirm_deadline"],
             c["status"], c["confirm_code_hash"], c["created_by"], now))
        self.conn.executemany(
            "INSERT INTO targets(command_id,device_id,status,updated_at)"
            " VALUES(?,?,?,?)",
            [(c["command_id"], d, "PENDING", now) for d in devices])

    def get_command_row(self, command_id: str) -> Optional[dict]:
        row = self.conn.execute("SELECT * FROM commands WHERE command_id=?",
                                (command_id,)).fetchone()
        return dict(row) if row else None

    def list_commands(self, limit: int = 100, status: str | None = None) -> list[dict]:
        if status:
            rows = self.conn.execute(
                "SELECT * FROM commands WHERE status=? ORDER BY created_at DESC LIMIT ?",
                (status, limit)).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM commands ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def set_command_status(self, command_id: str, status: str):
        self.conn.execute("UPDATE commands SET status=? WHERE command_id=?",
                          (status, command_id))

    def mark_confirmed(self, command_id: str, by: str, now: float):
        self.conn.execute(
            "UPDATE commands SET status='CONFIRMED',confirmed_by=?,confirmed_at=? "
            "WHERE command_id=?", (by, now, command_id))

    def mark_rejected(self, command_id: str, reason: str, now: float):
        self.conn.execute(
            "UPDATE commands SET status='REJECTED',reject_reason=? WHERE command_id=?",
            (reason, command_id))

    def mark_revoked(self, command_id: str, by: str, now: float):
        self.conn.execute(
            "UPDATE commands SET status='REVOKED',revoked_by=?,revoked_at=? "
            "WHERE command_id=?", (by, now, command_id))

    def expire_pending_commands(self, now: float) -> list[str]:
        """确认超时：未确认指令冻结。返回受影响 command_id。"""
        rows = self.conn.execute(
            "SELECT command_id FROM commands WHERE status='PENDING' AND confirm_deadline<=?",
            (now,)).fetchall()
        ids = [r["command_id"] for r in rows]
        if ids:
            self.conn.executemany(
                "UPDATE commands SET status='EXPIRED' WHERE command_id=? AND status='PENDING'",
                [(i,) for i in ids])
            self.conn.executemany(
                "UPDATE targets SET status='SKIPPED',updated_at=? "
                "WHERE command_id=? AND status='PENDING'",
                [(now, i) for i in ids])
        return ids

    def close_due_windows(self, now: float) -> list[str]:
        """有效窗口关闭：未投递给设备的目标记 MISSED；在途目标留 DOUDT 待对账。

        返回所有窗口刚关闭的 command_id（无论当前是否还有 DOUBT）。
        """
        rows = self.conn.execute(
            "SELECT command_id FROM commands WHERE status='CONFIRMED' AND valid_to<=?",
            (now,)).fetchall()
        ids = [r["command_id"] for r in rows]
        if ids:
            self.conn.executemany(
                "UPDATE targets SET status='MISSED',updated_at=? "
                "WHERE command_id=? AND status='PENDING'", [(now, i) for i in ids])
            self.conn.executemany(
                "UPDATE targets SET status='DOUBT',updated_at=? "
                "WHERE command_id=? AND status='DISPATCHED'", [(now, i) for i in ids])
        return ids

    def dangling_dispatched(self) -> list[dict]:
        """重启恢复：所有在途（DISPATCHED）目标——网关已投递但未拿到终态回执。"""
        rows = self.conn.execute(
            "SELECT t.command_id,t.device_id,t.dispatched_boot "
            "FROM targets t JOIN commands c ON c.command_id=t.command_id "
            "WHERE t.status='DISPATCHED'").fetchall()
        return [dict(r) for r in rows]

    # ---------- 目标 ----------
    def list_targets(self, command_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM targets WHERE command_id=? ORDER BY device_id", (command_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_target(self, command_id: str, device_id: str) -> Optional[dict]:
        row = self.conn.execute("SELECT * FROM targets WHERE command_id=? AND device_id=?",
                                (command_id, device_id)).fetchone()
        return dict(row) if row else None

    def pending_for_device(self, device_id: str, now: float) -> list[dict]:
        """设备拉取：已确认、窗口内、该设备仍 PENDING 的指令，按创建顺序。"""
        rows = self.conn.execute(
            "SELECT c.*, t.status AS tstatus FROM commands c "
            "JOIN targets t ON t.command_id=c.command_id "
            "WHERE t.device_id=? AND t.status='PENDING' AND c.status='CONFIRMED' "
            "AND c.valid_from<=? AND c.valid_to>? "
            "ORDER BY c.created_at", (device_id, now, now)).fetchall()
        return [dict(r) for r in rows]

    def mark_dispatched(self, command_id: str, device_id: str, boot_code: str, now: float):
        # 条件更新：只有 PENDING 才能变为 DISPATCHED，杜绝重复下发
        cur = self.conn.execute(
            "UPDATE targets SET status='DISPATCHED',dispatched_at=?,dispatched_boot=?,"
            "updated_at=? WHERE command_id=? AND device_id=? AND status='PENDING'",
            (now, boot_code, now, command_id, device_id))
        return cur.rowcount == 1

    def mark_doubt(self, command_id: str, device_id: str, now: float):
        self.conn.execute(
            "UPDATE targets SET status='DOUBT',updated_at=? "
            "WHERE command_id=? AND device_id=? AND status IN ('DISPATCHED','DOUBT')",
            (now, command_id, device_id))

    def reset_to_pending(self, command_id: str, device_id: str, now: float):
        """账本证明设备重启后未执行：可安全重新投递。"""
        cur = self.conn.execute(
            "UPDATE targets SET status='PENDING',dispatched_at=NULL,dispatched_boot=NULL,"
            "updated_at=? WHERE command_id=? AND device_id=? AND status='DOUBT'",
            (now, command_id, device_id))
        return cur.rowcount == 1

    def settle_target(self, command_id: str, device_id: str, status: str, now: float):
        """写入执行终态。仅 DOUBT/DISPATCHED 可结算，终态之间不可互相覆盖。"""
        cur = self.conn.execute(
            "UPDATE targets SET status=?,updated_at=? "
            "WHERE command_id=? AND device_id=? AND status IN ('DISPATCHED','DOUBT')",
            (status, now, command_id, device_id))
        return cur.rowcount == 1

    def recover_terminal(self, command_id: str, device_id: str, status: str, now: float):
        """MISSED 目标被账本补证为已执行（事实优先，窗口状态不能抹掉事实）。"""
        cur = self.conn.execute(
            "UPDATE targets SET status=?,updated_at=? "
            "WHERE command_id=? AND device_id=? AND status='MISSED'",
            (status, now, command_id, device_id))
        return cur.rowcount == 1

    # ---------- 回执 ----------
    def insert_receipt(self, rec: dict) -> bool:
        try:
            self.conn.execute(
                "INSERT INTO receipts(command_id,device_id,boot_code,seq,result,message,"
                "source,event_id,received_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (rec["command_id"], rec["device_id"], rec["boot_code"], rec["seq"],
                 rec["result"], rec.get("message"), rec["source"],
                 rec["event_id"], rec["received_at"]))
            return True
        except sqlite3.IntegrityError:
            return False

    def get_receipt(self, command_id: str, device_id: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM receipts WHERE command_id=? AND device_id=?",
            (command_id, device_id)).fetchone()
        return dict(row) if row else None

    def find_receipt_by_seq(self, device_id: str, boot_code: str, seq: int) -> Optional[dict]:
        """同一启动代号下该序号是否已被使用（用于识别“序号复用”伪造）。"""
        row = self.conn.execute(
            "SELECT * FROM receipts WHERE device_id=? AND boot_code=? AND seq=?",
            (device_id, boot_code, seq)).fetchone()
        return dict(row) if row else None

    def list_receipts(self, command_id: str | None = None) -> list[dict]:
        if command_id:
            rows = self.conn.execute(
                "SELECT * FROM receipts WHERE command_id=? ORDER BY id", (command_id,)).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM receipts ORDER BY id DESC LIMIT 200").fetchall()
        return [dict(r) for r in rows]

    def insert_rejected(self, device_id: str, boot_code: str | None, seq: int | None,
                        reason: str, raw: dict, now: float):
        self.conn.execute(
            "INSERT INTO rejected_receipts(device_id,boot_code,seq,reason,raw,received_at)"
            " VALUES(?,?,?,?,?,?)",
            (device_id, boot_code, seq, reason,
             json.dumps(raw, ensure_ascii=False, sort_keys=True), now))

    def list_rejected(self, limit: int = 100) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM rejected_receipts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()
