"""Decide allow / deny / approve for a tool call. First matching rule wins."""

import re
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Any

from tollgate.config import Action, Rule


@dataclass
class Decision:
    action: Action
    reason: str


def _matches(rule: Rule, tool: str, args: dict[str, Any]) -> bool:
    if not fnmatch(tool, rule.tool):
        return False
    # Every `when` condition must match. A missing argument matches as "".
    return all(re.search(pattern, str(args.get(arg, ""))) for arg, pattern in rule.when.items())


def decide(rules: list[Rule], default: Action, tool: str, args: dict[str, Any]) -> Decision:
    for rule in rules:
        if _matches(rule, tool, args):
            return Decision(rule.action, rule.reason or f"matched rule {rule.tool!r}")
    return Decision(default, "no rule matched (default action)")
