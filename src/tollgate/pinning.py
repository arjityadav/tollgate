"""Pin tool definitions by hash so a server can't silently change them later ("rug pull")."""

import hashlib
import json
from pathlib import Path

from mcp.types import Tool


def fingerprint(tool: Tool) -> str:
    payload = {"name": tool.name, "description": tool.description, "input_schema": tool.input_schema}
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


class PinStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.pins: dict[str, str] = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}

    def check(self, qualified_name: str, tool: Tool) -> str:
        """Return "new", "ok" or "changed"."""
        pinned = self.pins.get(qualified_name)
        if pinned is None:
            return "new"
        return "ok" if pinned == fingerprint(tool) else "changed"

    def pin(self, qualified_name: str, tool: Tool) -> None:
        self.pins[qualified_name] = fingerprint(tool)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.pins, indent=2, sort_keys=True), encoding="utf-8")
