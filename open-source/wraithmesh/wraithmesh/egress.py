"""Privacy egress enforcement — observations must not leak forbidden fields."""

from __future__ import annotations

from typing import Any

DEFAULT_ALLOWLIST = frozenset({
    "schema_version",
    "observation_id",
    "equivalence_key",
    "technique_set",
    "sensor_class",
    "confidence",
    "seen_count_bucket",
    "first_seen",
    "last_seen",
    "node_id",
    "epoch",
    "signature",
})

FORBIDDEN_SUBSTRINGS = (
    "src_ip",
    "hostname",
    "customer_id",
    "password",
    "username",
    "commands",
    "session_id",
    "email",
)


def count_bucket(count: int) -> str:
    if count <= 1:
        return "1"
    if count <= 10:
        return "2-10"
    if count <= 100:
        return "11-100"
    return "100+"


def sanitize_observation(obs: dict[str, Any], allowlist: set[str] | frozenset[str] | None = None) -> dict[str, Any]:
    """Return only allowlisted keys; raise if forbidden content appears in values."""
    allowed = allowlist or DEFAULT_ALLOWLIST
    out: dict[str, Any] = {}
    for key in allowed:
        if key in obs:
            out[key] = obs[key]
    blob = str(out).lower()
    for token in FORBIDDEN_SUBSTRINGS:
        if token in blob:
            raise ValueError(f"forbidden egress field detected: {token}")
    return out