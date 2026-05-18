from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from astrbot.api import logger


def _sanitize(text: str) -> str:
    """去除控制字符，防止日志注入。"""
    return "".join(ch for ch in text if ch.isprintable() or ch in {"\n", "\r", "\t"})


class AuditStore:
    def __init__(self, mode: str, base_dir: Path, max_memory: int = 200):
        self.mode = mode.lower()
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._memory: list[dict[str, Any]] = []
        self._max_memory = max_memory
        self._sqlite_conn: sqlite3.Connection | None = None
        self._last_error = ""
        if self.mode == "sqlite":
            self._init_sqlite()

    def append(self, record: Any) -> None:
        rec = asdict(record) if hasattr(record, "__dataclass_fields__") else dict(record)
        # 统一字段
        rec.setdefault("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        rec.setdefault("allowed", True)
        rec.setdefault("block_reason", "")

        # 内存始终保留（用于快速查询）
        self._memory.append(rec)
        if len(self._memory) > self._max_memory:
            self._memory = self._memory[-self._max_memory:]

        if self.mode == "file":
            self._write_file(rec)
        elif self.mode == "sqlite":
            self._write_sqlite(rec)

    def query(
        self, limit: int = 20, sender_id: str = "", allowed: bool | None = None
    ) -> list[dict[str, Any]]:
        if self.mode == "sqlite":
            return self._query_sqlite(limit, sender_id, allowed)
        # memory / file 都从内存返回最新记录
        result = list(self._memory)
        if sender_id:
            result = [r for r in result if r.get("sender_id") == sender_id]
        if allowed is not None:
            result = [r for r in result if r.get("allowed") == allowed]
        result.reverse()
        return result[:limit]

    def count(self) -> int:
        if self.mode == "sqlite":
            try:
                conn = self._get_sqlite_conn()
                row = conn.execute("SELECT COUNT(1) FROM ssh_audit").fetchone()
                return int(row[0]) if row and row[0] is not None else 0
            except Exception:
                return 0
        return len(self._memory)

    def _write_file(self, rec: dict[str, Any]) -> None:
        date = rec.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))[:10]
        log_file = self.base_dir / f"ssh_audit_{date}.log"
        try:
            with log_file.open("a", encoding="utf-8") as f:
                line = json.dumps(rec, ensure_ascii=False)
                f.write(_sanitize(line) + "\n")
        except Exception as e:
            self._last_error = f"audit_file_write: {e}"
            logger.warning(f"[iris_sshtoolspack] 审计文件写入失败: {e}")

    def _init_sqlite(self) -> None:
        conn = self._get_sqlite_conn()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ssh_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                sender_id TEXT,
                profile TEXT,
                host TEXT,
                command_preview TEXT,
                exit_status INTEGER,
                duration_ms INTEGER,
                allowed INTEGER,
                block_reason TEXT
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON ssh_audit(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_sender ON ssh_audit(sender_id)")
        conn.commit()

    def _get_sqlite_conn(self) -> sqlite3.Connection:
        if self._sqlite_conn is None:
            db_path = self.base_dir / "ssh_audit.db"
            self._sqlite_conn = sqlite3.connect(str(db_path), check_same_thread=False)
            self._sqlite_conn.execute("PRAGMA journal_mode=WAL")
            self._sqlite_conn.execute("PRAGMA synchronous=NORMAL")
        return self._sqlite_conn

    def _write_sqlite(self, rec: dict[str, Any]) -> None:
        try:
            conn = self._get_sqlite_conn()
            conn.execute(
                """
                INSERT INTO ssh_audit(timestamp, sender_id, profile, host, command_preview,
                                      exit_status, duration_ms, allowed, block_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rec.get("timestamp", ""),
                    rec.get("sender_id", ""),
                    rec.get("profile", ""),
                    rec.get("host", ""),
                    rec.get("command_preview", ""),
                    rec.get("exit_status", -1),
                    rec.get("duration_ms", 0),
                    1 if rec.get("allowed", True) else 0,
                    rec.get("block_reason", ""),
                ),
            )
            conn.commit()
        except Exception as e:
            self._last_error = f"audit_sqlite_write: {e}"
            logger.warning(f"[iris_sshtoolspack] 审计 SQLite 写入失败: {e}")

    def _query_sqlite(
        self, limit: int, sender_id: str, allowed: bool | None
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM ssh_audit WHERE 1=1"
        args: list[Any] = []
        if sender_id:
            sql += " AND sender_id = ?"
            args.append(sender_id)
        if allowed is not None:
            sql += " AND allowed = ?"
            args.append(1 if allowed else 0)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        try:
            conn = self._get_sqlite_conn()
            rows = conn.execute(sql, tuple(args)).fetchall()
            cols = [d[0] for d in conn.execute("SELECT * FROM ssh_audit LIMIT 0").description]
            result: list[dict[str, Any]] = []
            for row in rows:
                result.append({k: row[i] for i, k in enumerate(cols)})
            return result
        except Exception as e:
            self._last_error = f"audit_sqlite_query: {e}"
            logger.warning(f"[iris_sshtoolspack] 审计 SQLite 查询失败: {e}")
            return []

    def close(self) -> None:
        if self._sqlite_conn is not None:
            try:
                self._sqlite_conn.close()
            except Exception:
                pass
            self._sqlite_conn = None
