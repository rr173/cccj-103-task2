"""协调端 SQLite 存储。

单连接 + 进程锁：协调端本身是单实例编排器，所有写入在锁内串行，
消除"重复/乱序回报"造成的竞态。WAL 模式保证健康检查等读不阻塞写。
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests(
  id TEXT PRIMARY KEY,
  subject_id TEXT NOT NULL,
  display_name TEXT,
  status TEXT NOT NULL,              -- RESOLVING/IN_PROGRESS/CONFIRMED/ABORTED
  deadline_ms INTEGER NOT NULL,
  cert_version INTEGER NOT NULL DEFAULT 0,
  engine_paused INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS items(
  id TEXT PRIMARY KEY,              -- request_id:service[:record_id]
  request_id TEXT NOT NULL,
  service TEXT NOT NULL,
  subject_id TEXT,
  record_id TEXT,
  status TEXT NOT NULL,             -- 见 STATUS_RANK
  attempts INTEGER NOT NULL DEFAULT 0,
  command_id_restrict TEXT,
  command_id_purge TEXT,
  active_command_id TEXT,           -- 当前阶段期望的命令（幂等/陈旧判定）
  hold_code TEXT,
  hold_reason TEXT,
  hold_releases_at INTEGER,
  result_hash TEXT,
  evidence TEXT,                    -- 服务回报的完整证据 JSON
  overdue INTEGER NOT NULL DEFAULT 0,
  overdue_event INTEGER NOT NULL DEFAULT 0,
  fatal INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  next_attempt_at INTEGER NOT NULL DEFAULT 0,
  purge_due_ms INTEGER NOT NULL DEFAULT 0,
  holds_checked_at INTEGER NOT NULL DEFAULT 0,
  report_seq INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS reports(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id TEXT NOT NULL,
  item_id TEXT NOT NULL,
  service TEXT NOT NULL,
  command_id TEXT,
  attempt INTEGER,
  reported_status TEXT,
  result_hash TEXT,
  hold_code TEXT,
  accepted INTEGER NOT NULL,        -- 0=被判定为重复/乱序/伪造而忽略
  reason TEXT,
  received_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id TEXT NOT NULL,
  ts INTEGER NOT NULL,
  type TEXT NOT NULL,
  detail TEXT
);
CREATE TABLE IF NOT EXISTS tombstones(
  request_id TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  service TEXT NOT NULL,            -- '*' 表示全局墓碑
  token TEXT NOT NULL,
  version INTEGER NOT NULL,
  pushed INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(request_id, subject_id, service, version)
);
CREATE TABLE IF NOT EXISTS certificates(
  request_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  merkle_root TEXT NOT NULL,
  signature TEXT NOT NULL,
  leaves TEXT NOT NULL,
  item_count INTEGER NOT NULL,
  sealed_count INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(request_id, version)
);
"""

# 计划项状态序：只允许"同命令幂等重放"或"向前推进"，倒序回报一律拒绝。
STATUS_RANK = {
    "PENDING": 0,
    "DISPATCHED": 1,
    "ERROR": 1,        # 瞬态失败，与 DISPATCHED 同级，允许迟到成功回调把它推进
    "RESTRICTED": 2,
    "SEALED": 2,       # 受限变体：受法律/财务保留，只能封存
    "PURGING": 3,
    "PURGED": 4,       # 终态：已擦除
    "FAILED": 5,       # 终态：永久失败（saga 中止）
    "CANCELLED": 5,    # 终态：被补偿撤销
}
TERMINAL = {"PURGED", "FAILED", "CANCELLED"}
SEALED_LIKE = {"RESTRICTED", "SEALED"}


class Store:
    def __init__(self, path: str):
        first_init = not os.path.exists(path)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self.lock = threading.RLock()
        self._first_init = first_init

    # -- 基础辅助 ----------------------------------------------------------
    def tx(self):
        return self.conn  # 所有写操作在 self.lock 内进行，末尾显式 commit

    def commit(self):
        self.conn.commit()

    def event(self, request_id: str, etype: str, detail: Any = None):
        with self.lock:
            self.conn.execute(
                "INSERT INTO events(request_id, ts, type, detail) VALUES(?,?,?,?)",
                (request_id, int(time.time() * 1000), etype,
                 json.dumps(detail, ensure_ascii=False, sort_keys=True)),
            )
            self.conn.commit()

    # -- 读模型 ------------------------------------------------------------
    def get_request(self, rid: str) -> dict | None:
        r = self.conn.execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone()
        return dict(r) if r else None

    def list_items(self, rid: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM items WHERE request_id=? ORDER BY service, record_id", (rid,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_item(self, iid: str) -> dict | None:
        r = self.conn.execute("SELECT * FROM items WHERE id=?", (iid,)).fetchone()
        return dict(r) if r else None

    def list_reports(self, rid: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM reports WHERE request_id=? ORDER BY id", (rid,)
        ).fetchall()
        return [dict(r) for r in rows]

    def list_events(self, rid: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, ts, type, detail FROM events WHERE request_id=? ORDER BY id", (rid,)
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["detail"] = json.loads(d["detail"])
            except Exception:
                pass
            out.append(d)
        return out

    def list_certificates(self, rid: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM certificates WHERE request_id=? ORDER BY version", (rid,)
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["leaves"] = json.loads(d["leaves"])
            out.append(d)
        return out

    def list_tombstones(self, rid: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT request_id, subject_id, service, token, version, pushed, created_at "
            "FROM tombstones WHERE request_id=? ORDER BY version, service", (rid,)
        ).fetchall()
        return [dict(r) for r in rows]

    def active_requests(self) -> list[dict]:
        # 注意必须包含 RESOLVING：身份解析常在单个 tick 内完成，
        # 若漏选 RESOLVING，请求会永久停滞在解析态。
        rows = self.conn.execute(
            "SELECT * FROM requests WHERE status IN ('RESOLVING','IN_PROGRESS','CONFIRMED')"
        ).fetchall()
        return [dict(r) for r in rows]

    def request_view(self, rid: str) -> dict | None:
        req = self.get_request(rid)
        if not req:
            return None
        req["items"] = self.list_items(rid)
        req["events"] = self.list_events(rid)
        req["reports"] = self.list_reports(rid)
        req["certificates"] = self.list_certificates(rid)
        return req
