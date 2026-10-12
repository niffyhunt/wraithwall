"""MemoryGate — the single choke point for RavenScan memory writes.

Hermes principle adapted as Raven form (deliverable 6 section 3): scan/tool/
operator text may never reach a persistent table without passing deterministic
checks here. One code path so tests can assert "all writes go through the gate".

Classes (deliverable 6 section 1): only operator-validated and pipeline-validated
records persist. SECRET_NEVER_STORE is rejected or redacted at this boundary and
is never stored raw, in any encoding. Stored text is data, never instructions.
"""
from __future__ import annotations

import hashlib
import math
import re
from typing import Iterable

MAX_FIELD_LEN = 4096

# Reason codes are stable strings so audit rows and tests can assert on them.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("pem_private_key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}\b")),
    ("api_key_token", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    (
        "assigned_secret",
        re.compile(
            r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token)"
            r"\s*[:=]\s*[\"']?[A-Za-z0-9/+_.-]{8,}"
        ),
    ),
)

_ENTROPY_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{20,}")


class GateRejected(ValueError):
    """A memory write failed deterministic gate checks."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def secret_reasons(text: str) -> list[str]:
    """Return secret reason codes present in text — never the matched content."""
    if not text:
        return []
    codes = [name for name, pat in _PATTERNS if pat.search(text)]
    for tok in _ENTROPY_TOKEN.findall(text):
        # Require token variety so ordinary words never trip the check.
        has_digit = any(ch.isdigit() for ch in tok)
        has_alpha = any(ch.isalpha() for ch in tok)
        if has_digit and has_alpha and _shannon_entropy(tok) >= 4.0:
            codes.append("high_entropy_token")
            break
    return codes


def admit_operator_text(field: str, text: str | None) -> str:
    """Admit operator-authored text (reason, detector, id) or raise.

    Secrets are rejected outright: the operator can rephrase; nothing is
    stored, not even redacted, because the write itself is refused.
    """
    value = (text or "").strip()
    if len(value) > MAX_FIELD_LEN:
        raise GateRejected("too_long")
    reasons = secret_reasons(value)
    if reasons:
        raise GateRejected(f"secret:{reasons[0]}@{field}")
    return value


def redact_scan_text(text: str, *, truncate: bool = True) -> tuple[str, list[str]]:
    """Redact secret matches from scan-derived text; return (safe, codes).

    Pipeline-derived evidence may legitimately quote repository content, so the
    gate never stores the raw blob: matched spans are replaced with a descriptor.
    ``truncate=False`` for structured payloads (JSON) where truncation would
    corrupt the document; length limits on those are enforced by the writers.
    """
    if not text:
        return "", []
    codes: list[str] = []
    safe = text
    for name, pat in _PATTERNS:
        if pat.search(safe):
            codes.append(name)
            safe = pat.sub(f"[REDACTED:{name}]", safe)
    for tok in list(dict.fromkeys(_ENTROPY_TOKEN.findall(safe))):
        has_digit = any(ch.isdigit() for ch in tok)
        has_alpha = any(ch.isalpha() for ch in tok)
        if has_digit and has_alpha and _shannon_entropy(tok) >= 4.0:
            codes.append("high_entropy_token")
            safe = safe.replace(tok, "[REDACTED:high_entropy_token]")
    if truncate and len(safe) > MAX_FIELD_LEN:
        safe = safe[:MAX_FIELD_LEN]
        codes.append("truncated")
    return safe, codes


def admit_scope(scope: str | None) -> str:
    """Scopes are required, bounded, and free of control characters."""
    value = (scope or "").strip()
    if not value:
        raise GateRejected("missing_scope")
    if len(value) > 256:
        raise GateRejected("scope_too_long")
    if any(ord(ch) < 32 for ch in value):
        raise GateRejected("scope_control_chars")
    return value


def record_hash(*parts: Iterable[str] | str | None) -> str:
    """Stable content hash for audit before/after integrity records."""
    hasher = hashlib.sha256()
    for part in parts:
        if part is None:
            hasher.update(b"\x00")
        elif isinstance(part, str):
            hasher.update(part.encode("utf-8", "replace"))
            hasher.update(b"\x01")
        else:
            for item in part:
                hasher.update(str(item).encode("utf-8", "replace"))
                hasher.update(b"\x02")
    return hasher.hexdigest()
