"""Heuristic scanner for tool poisoning and prompt injection.

Used on tool descriptions when an upstream connects, and on tool outputs before they
reach the model. Heuristics never catch everything; they are one layer of several.
"""

import json
import re
from dataclasses import dataclass
from typing import Literal

from mcp.types import Tool

Severity = Literal["high", "medium"]


@dataclass
class Finding:
    rule: str
    severity: Severity
    excerpt: str


PATTERNS: list[tuple[str, Severity, re.Pattern[str]]] = [
    ("instruction_override", "high",
     re.compile(r"(ignore|disregard|forget)\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)", re.I)),
    ("hidden_tag", "high",
     re.compile(r"<\s*/?\s*(important|system|secret|hidden|instructions?)\s*>", re.I)),
    ("secrecy", "high",
     re.compile(r"(do\s*not|don't|never)\s+(tell|mention|inform|reveal|show)[^.\n]{0,40}\b(user|human)", re.I)),
    ("sensitive_path", "high",
     re.compile(r"(~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|/etc/passwd|\.env\b|mcp\.json|claude_desktop_config)", re.I)),
    ("cross_tool_hijack", "medium",
     re.compile(r"(before|after|when(ever)?)\s+(using|calling|invoking)\s+(any|the|other|another)\b[^.\n]{0,30}\btool", re.I)),
    ("exfiltration", "high",
     re.compile(r"(send|forward|upload|post|email)\b[^.\n]{0,60}\b(to|at)\s+(https?://|[\w.+-]+@[\w-]+\.)", re.I)),
    ("role_play", "medium",
     re.compile(r"\b(you are now|act as|new instructions:|system prompt)\b", re.I)),
]

# Zero-width, bidi-override, invisible-operator and BOM characters, plus Unicode tag characters.
INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤﻿\U000e0000-\U000e007f]")
MAX_DESCRIPTION_CHARS = 1500


def scan_text(text: str) -> list[Finding]:
    findings = []
    for name, severity, pattern in PATTERNS:
        if m := pattern.search(text):
            start = max(m.start() - 20, 0)
            findings.append(Finding(name, severity, text[start : m.end() + 20].replace("\n", " ")))
    if INVISIBLE.search(text):
        findings.append(Finding("invisible_unicode", "high", "text contains invisible/tag unicode characters"))
    return findings


def scan_tool(tool: Tool) -> list[Finding]:
    # Attackers hide instructions in parameter descriptions too, so scan the whole schema.
    text = f"{tool.description or ''}\n{json.dumps(tool.input_schema)}"
    findings = scan_text(text)
    if len(tool.description or "") > MAX_DESCRIPTION_CHARS:
        findings.append(Finding("oversized_description", "medium", f"{len(tool.description or '')} chars"))
    return findings


def is_dangerous(findings: list[Finding]) -> bool:
    return any(f.severity == "high" for f in findings)
