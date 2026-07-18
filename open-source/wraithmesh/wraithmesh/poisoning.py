"""TIE feed-integrity trap keys — detect poisoned equivalence submissions."""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Iterable


def generate_trap_keys(count: int = 3) -> list[str]:
    """Generate synthetic equivalence keys planted by the exchange operator."""
    return [secrets.token_hex(8) for _ in range(count)]


def load_trap_keys(path: str | Path) -> set[str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        keys = data.get("trap_keys") or data.get("keys") or []
    elif isinstance(data, list):
        keys = data
    else:
        raise ValueError("trap keys file must be a JSON list or {trap_keys: [...]}")
    return {str(k).lower() for k in keys}


def save_trap_keys(path: str | Path, keys: Iterable[str]) -> None:
    payload = {"trap_keys": sorted(set(keys))}
    Path(path).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def is_trap_key(equivalence_key: str, trap_keys: set[str]) -> bool:
    return equivalence_key.lower() in trap_keys