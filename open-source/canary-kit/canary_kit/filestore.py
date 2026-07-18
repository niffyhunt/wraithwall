"""A JSON-file-backed :class:`~canary_kit.storage.CanaryStore`.

Used by the CLI so that tokens registered in one invocation are visible to the
next. The file path is always supplied by the caller; nothing is hardcoded.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Optional

from .tokens import CanaryToken


class FileStore:
    """Persist token records as a JSON document at ``path``."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def _read(self) -> dict[str, dict]:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text()).get("tokens", {})
        except (json.JSONDecodeError, OSError):
            return {}

    def _write(self, data: dict[str, dict]) -> None:
        self.path.write_text(json.dumps({"tokens": data}, indent=2))

    def put(self, record: CanaryToken) -> None:
        with self._lock:
            data = self._read()
            data[record.token] = record.to_dict()
            self._write(data)

    def get(self, token: str) -> Optional[CanaryToken]:
        with self._lock:
            raw = self._read().get(token)
        return CanaryToken.from_dict(raw) if raw else None

    def all(self) -> list[CanaryToken]:
        with self._lock:
            values = list(self._read().values())
        return [CanaryToken.from_dict(v) for v in values]

    def tokens(self) -> list[str]:
        with self._lock:
            return list(self._read().keys())


__all__ = ["FileStore"]
