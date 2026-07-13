"""Pluggable storage for the canary token registry and trigger log.

Storage is abstracted behind :class:`CanaryStore` so the library never connects
to any backend at import time. An in-memory implementation is the default; a
Redis-backed adapter is provided for callers who inject their own redis client.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Optional, Protocol, runtime_checkable

from .tokens import CanaryToken


@runtime_checkable
class CanaryStore(Protocol):
    """Storage interface for issued tokens and their trigger state.

    Implementations persist :class:`CanaryToken` records keyed by their token
    string and support listing all tokens. They need not be thread-safe unless
    documented; the bundled :class:`InMemoryStore` is.
    """

    def put(self, record: CanaryToken) -> None:
        """Insert or overwrite a token record."""
        ...

    def get(self, token: str) -> Optional[CanaryToken]:
        """Return the record for ``token`` or ``None`` if unknown."""
        ...

    def all(self) -> list[CanaryToken]:
        """Return every stored token record."""
        ...

    def tokens(self) -> list[str]:
        """Return every stored token string."""
        ...


class InMemoryStore:
    """Thread-safe in-memory :class:`CanaryStore`. The default backend."""

    def __init__(self) -> None:
        self._data: dict[str, dict] = {}
        self._lock = threading.Lock()

    def put(self, record: CanaryToken) -> None:
        with self._lock:
            self._data[record.token] = record.to_dict()

    def get(self, token: str) -> Optional[CanaryToken]:
        with self._lock:
            raw = self._data.get(token)
        return CanaryToken.from_dict(raw) if raw else None

    def all(self) -> list[CanaryToken]:
        with self._lock:
            values = list(self._data.values())
        return [CanaryToken.from_dict(v) for v in values]

    def tokens(self) -> list[str]:
        with self._lock:
            return list(self._data.keys())


class RedisStore:
    """A :class:`CanaryStore` backed by a caller-supplied redis client.

    The client is injected, never constructed here, so no connection is made at
    import time and no ``REDIS_URL`` is read. The client must behave like
    ``redis.Redis(decode_responses=True)``.

    Args:
        client: A redis client exposing ``get``, ``setex``, ``scan``.
        prefix: Key prefix for stored records.
        ttl_seconds: Expiry applied to each record (default 365 days).
    """

    def __init__(
        self,
        client: object,
        *,
        prefix: str = "canary_kit:",
        ttl_seconds: int = 86400 * 365,
    ) -> None:
        self._r = client
        self._prefix = prefix
        self._ttl = ttl_seconds

    def _key(self, token: str) -> str:
        return f"{self._prefix}{token}"

    def put(self, record: CanaryToken) -> None:
        self._r.setex(self._key(record.token), self._ttl, json.dumps(record.to_dict()))
        try:
            self._r.zadd(f"{self._prefix}active", {record.token: time.time()})
        except Exception:
            pass

    def get(self, token: str) -> Optional[CanaryToken]:
        raw = self._r.get(self._key(token))
        if not raw:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode()
        return CanaryToken.from_dict(json.loads(raw))

    def all(self) -> list[CanaryToken]:
        records = (self.get(t) for t in self.tokens())
        return [r for r in records if r is not None]

    def tokens(self) -> list[str]:
        out: list[str] = []
        cursor = 0
        pattern = f"{self._prefix}*"
        while True:
            cursor, keys = self._r.scan(cursor, match=pattern, count=100)
            for key in keys:
                if isinstance(key, bytes):
                    key = key.decode()
                if key == f"{self._prefix}active":
                    continue
                out.append(key[len(self._prefix):])
            if cursor == 0:
                break
        return out


__all__ = ["CanaryStore", "InMemoryStore", "RedisStore"]
