"""HMAC-SHA256 signing for mesh manifests and observations."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

DEFAULT_KEY_ENV = "WRAITHMESH_KEY"


def node_id_from_key(key: str | bytes) -> str:
    """Derive a stable 16-char node id from a signing key."""
    raw = key.encode() if isinstance(key, str) else key
    return hashlib.sha256(raw).hexdigest()[:16]


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def sign_payload(payload: dict[str, Any], key: str | bytes) -> str:
    raw = key.encode() if isinstance(key, str) else key
    body = canonical_json(payload)
    return hmac.new(raw, body.encode(), hashlib.sha256).hexdigest()[:32]


def verify_payload(payload: dict[str, Any], signature: str, key: str | bytes) -> bool:
    expected = sign_payload(payload, key)
    return hmac.compare_digest(expected, signature)


def load_key(key_env: str = DEFAULT_KEY_ENV) -> bytes:
    value = os.environ.get(key_env, "")
    if not value:
        raise ValueError(f"Signing key not found: set {key_env}")
    return value.encode()