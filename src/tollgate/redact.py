"""Redact secrets and personal data from tool outputs and audit records."""

import re
from typing import Any

# Order matters: the private key runs first so its body is gone before shorter patterns look at it.
SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "api_key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}(?:\s?[A-Z0-9]{1,3})?\b"),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
}


def redact_text(text: str) -> tuple[str, dict[str, int]]:
    counts: dict[str, int] = {}
    for kind, pattern in SECRET_PATTERNS.items():
        text, n = pattern.subn(f"[REDACTED:{kind}]", text)
        if n:
            counts[kind] = n
    return text, counts


def redact_value(value: Any) -> tuple[Any, dict[str, int]]:
    """Recursively redact strings inside dicts/lists (structured content, audit args)."""
    totals: dict[str, int] = {}

    def walk(v: Any) -> Any:
        if isinstance(v, str):
            out, counts = redact_text(v)
            for k, n in counts.items():
                totals[k] = totals.get(k, 0) + n
            return out
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        return v

    return walk(value), totals
