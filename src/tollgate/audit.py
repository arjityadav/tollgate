"""Tamper-evident audit log: every record contains the hash of the previous one."""

import hashlib
import json
import time
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(record: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(record, sort_keys=True, default=str).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.prev, self.seq = GENESIS, 0
        if path.exists():
            lines = path.read_text(encoding="utf-8").splitlines()
            if lines:
                last = json.loads(lines[-1])
                self.prev, self.seq = last["hash"], last["seq"]

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        self.seq += 1
        record = {"seq": self.seq, "ts": time.time(), "prev": self.prev, **event}
        record["hash"] = _digest(record)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")
        self.prev = record["hash"]
        return record


def verify(path: Path) -> tuple[bool, int, str]:
    """Return (ok, records_checked, message)."""
    prev = GENESIS
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    for i, line in enumerate(lines, start=1):
        record = json.loads(line)
        claimed = record.pop("hash")
        if record["prev"] != prev:
            return False, i, f"record {i}: chain broken (a record before it was removed or edited)"
        if _digest(record) != claimed:
            return False, i, f"record {i}: contents were modified"
        prev = claimed
    return True, len(lines), f"{len(lines)} records, chain intact"
