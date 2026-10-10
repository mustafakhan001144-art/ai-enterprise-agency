"""Helpers shared by the deterministic workflow engines."""

from __future__ import annotations

import hashlib
import re
from typing import Any

import rfc8785

BANNED_PHRASES = (
    "likely",
    "probably",
    "appears to",
    "appears",
    "may have",
    "could indicate",
    "could be",
    "seems",
    "presumably",
    "was intended to",
    "the developer wanted",
    "for historical reasons",
)
_BANNED_RE = re.compile(r"\b(" + "|".join(re.escape(p) for p in BANNED_PHRASES) + r")\b", re.IGNORECASE)

# Secret patterns. Each match is replaced by [REDACTED:<type>] in excerpts and is only
# ever reported as a SHA-256 fingerprint.
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "private_key",
        re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z ]+ )?PRIVATE KEY-----|$)"),
    ),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("api_key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("bearer_token", re.compile(r"Bearer (?P<v>[A-Za-z0-9._~+/-]{16,}=*)")),
    (
        "password",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|api_key|apikey|access_token|auth_token|token)[\"']?\s*[:=]\s*[\"']?"
            r"(?P<v>[^\s\"',;&}]{4,})"
        ),
    ),
]


def canonical_digest(value: Any) -> str:
    """SHA-256 of the RFC 8785 canonical JSON encoding."""
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def find_secrets(text: str) -> list[tuple[str, str]]:
    """Return (type, secret value) pairs found in text, de-duplicated, in order of appearance."""
    found: list[tuple[int, str, str]] = []
    for kind, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            group = "v" if "v" in pattern.groupindex else 0
            value = match.group(group)
            if value and not value.startswith("[REDACTED"):
                found.append((match.start(group), kind, value))
    seen: set[str] = set()
    result = []
    for _, kind, value in sorted(found):
        if value not in seen:
            seen.add(value)
            result.append((kind, value))
    return result


def redact(text: str) -> str:
    for kind, value in find_secrets(text):
        text = text.replace(value, f"[REDACTED:{kind}]")
    return text


def excerpt(text: str, limit: int) -> str:
    """Redact first, then truncate, so a secret is never split and partially shown."""
    return redact(text)[:limit]


def has_banned_phrase(value: Any) -> bool:
    if isinstance(value, str):
        return bool(_BANNED_RE.search(value))
    if isinstance(value, dict):
        return any(has_banned_phrase(v) for v in value.values())
    if isinstance(value, list):
        return any(has_banned_phrase(v) for v in value)
    return False
