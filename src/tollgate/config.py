"""Load tollgate.yaml into typed objects."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml

Action = Literal["allow", "deny", "approve"]


@dataclass
class Rule:
    tool: str                                            # glob over "upstream__tool"
    action: Action
    when: dict[str, str] = field(default_factory=dict)   # argument name -> regex
    reason: str = ""


@dataclass
class Config:
    upstreams: dict[str, dict[str, Any]]                 # name -> {command, args, env}
    rules: list[Rule]
    default_action: Action = "approve"                   # fail safe
    trust_on_first_use: bool = True
    data_dir: Path = Path(".tollgate")

    @property
    def lockfile(self) -> Path:
        return self.data_dir / "tools.lock.json"

    @property
    def audit_log(self) -> Path:
        return self.data_dir / "audit.jsonl"

    @property
    def approvals_db(self) -> Path:
        return self.data_dir / "approvals.sqlite"


def load_config(path: str | Path) -> Config:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    rules = [Rule(**r) for r in raw.get("rules", [])]
    for r in rules:
        if r.action not in ("allow", "deny", "approve"):
            raise ValueError(f"Rule for {r.tool!r} has invalid action {r.action!r}")
    return Config(
        upstreams=raw.get("upstreams", {}),
        rules=rules,
        default_action=raw.get("default_action", "approve"),
        trust_on_first_use=raw.get("trust_on_first_use", True),
        data_dir=Path(raw.get("data_dir", ".tollgate")),
    )
