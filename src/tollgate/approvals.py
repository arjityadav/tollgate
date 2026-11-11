"""Out-of-band human approvals, stored in SQLite so the gateway and the CLI share them."""

import hashlib
import json
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

TTL_SECONDS = 15 * 60


def args_hash(tool: str, args: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps([tool, args], sort_keys=True, default=str).encode()).hexdigest()


class Approvals:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, isolation_level=None)  # autocommit
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS approvals (
                 id TEXT PRIMARY KEY, tool TEXT, args TEXT, hash TEXT,
                 status TEXT, created REAL, decided REAL)"""
        )

    def check(self, tool: str, args: dict[str, Any]) -> tuple[str, str]:
        """Return ("approved", id) once per approval, else ("pending" | "denied", id)."""
        h = args_hash(tool, args)
        cutoff = time.time() - TTL_SECONDS
        row = self.db.execute(
            "SELECT id, status FROM approvals WHERE hash=? AND created>? AND status!='used' "
            "ORDER BY created DESC LIMIT 1",
            (h, cutoff),
        ).fetchone()
        if row and row[1] == "approved":
            self.db.execute("UPDATE approvals SET status='used' WHERE id=?", (row[0],))  # single use
            return "approved", row[0]
        if row:
            return row[1], row[0]
        approval_id = secrets.token_hex(3)
        self.db.execute(
            "INSERT INTO approvals VALUES (?,?,?,?, 'pending', ?, NULL)",
            (approval_id, tool, json.dumps(args, default=str), h, time.time()),
        )
        return "pending", approval_id

    def decide(self, approval_id: str, approve: bool) -> bool:
        cur = self.db.execute(
            "UPDATE approvals SET status=?, decided=? WHERE id=? AND status='pending'",
            ("approved" if approve else "denied", time.time(), approval_id),
        )
        return cur.rowcount == 1

    def pending(self) -> list[tuple[str, str, str]]:
        cutoff = time.time() - TTL_SECONDS
        return self.db.execute(
            "SELECT id, tool, args FROM approvals WHERE status='pending' AND created>? ORDER BY created",
            (cutoff,),
        ).fetchall()
