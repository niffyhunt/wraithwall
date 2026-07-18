"""Trusted node key registry for multi-node aggregator verification."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_trusted_keys(path: str | Path) -> dict[str, str]:
    """Load node_id -> signing secret mapping."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("trusted keys file must be a JSON object")
    return {str(k): str(v) for k, v in data.items()}


def resolve_verification_key(obs: dict[str, Any], key: str | bytes | dict[str, str]) -> str | bytes:
    if isinstance(key, dict):
        node_id = obs.get("node_id", "")
        if node_id not in key:
            raise ValueError(f"untrusted node_id: {node_id}")
        return key[node_id]
    return key