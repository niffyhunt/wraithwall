"""Replay / alert deduplication.

A single worm or campaign arriving from a botnet's worth of source IPs is one
incident, not N. We collapse identical-payload sessions into a single alert by
hashing the session's command list and grouping every source IP under that
signature within a sliding TTL window.

The dedup **key** is stable across command ordering: it is a SHA-256 over the
*sorted* command list, truncated to 16 hex characters — preserved verbatim from
the original pipeline.

The TTL store is pluggable. The default :class:`InMemoryDedupStore` uses
timestamp-based expiry and needs no external services. An optional Redis-backed
adapter can be injected for cross-process sharing.
"""

from __future__ import annotations

import hashlib
import time
from typing import Dict, List, Optional, Protocol, Set

# Default window (seconds) over which identical-payload sessions collapse.
DEFAULT_DEDUP_WINDOW: int = 900  # 15 minutes


def dedup_key(commands: List[str]) -> str:
    """Compute the order-independent dedup signature for a command list.

    The key is ``sha256("\\n".join(sorted(commands)))`` truncated to 16 hex
    characters, so two sessions running the same commands in different orders
    collapse to the same key.

    Args:
        commands: The session's command lines.

    Returns:
        A 16-character hex signature.
    """
    payload = '\n'.join(sorted(commands)).encode()
    return hashlib.sha256(payload).hexdigest()[:16]


class DedupStore(Protocol):
    """Pluggable TTL-backed dedup store.

    Implementations track, per signature, the set of source IPs seen and whether
    this is the first occurrence within the active TTL window.
    """

    def register(self, signature: str, src_ip: str) -> bool:
        """Record an occurrence of ``signature`` from ``src_ip``.

        Args:
            signature: The dedup key for the session payload.
            src_ip: Source IP to aggregate under the signature.

        Returns:
            ``True`` if this is the first occurrence in the current window (the
            caller should emit an alert), ``False`` if it is a duplicate that
            should be suppressed.
        """
        ...

    def source_ips(self, signature: str) -> Set[str]:
        """Return the set of source IPs aggregated under ``signature``."""
        ...


class InMemoryDedupStore:
    """In-process dedup store with timestamp-based expiry.

    No external dependencies. Entries expire ``window`` seconds after they are
    first registered; an expired signature is treated as new again.
    """

    def __init__(self, window: int = DEFAULT_DEDUP_WINDOW) -> None:
        """Initialize the store.

        Args:
            window: Dedup window in seconds.
        """
        self.window = window
        # signature -> {"first_seen": float, "ips": set[str]}
        self._entries: Dict[str, Dict[str, object]] = {}

    def _expired(self, entry: Dict[str, object], now: float) -> bool:
        return (now - float(entry['first_seen'])) > self.window

    def register(self, signature: str, src_ip: str) -> bool:
        now = time.time()
        entry = self._entries.get(signature)

        if entry is None or self._expired(entry, now):
            self._entries[signature] = {
                'first_seen': now,
                'ips': {src_ip} if src_ip else set(),
            }
            return True

        ips: Set[str] = entry['ips']  # type: ignore[assignment]
        if src_ip:
            ips.add(src_ip)
        return False

    def source_ips(self, signature: str) -> Set[str]:
        entry = self._entries.get(signature)
        if entry is None or self._expired(entry, time.time()):
            return set()
        return set(entry['ips'])  # type: ignore[arg-type]


class RedisDedupStore:
    """Redis-backed dedup store for cross-process sharing.

    Mirrors the original pipeline's scheme: a per-signature IP set plus an
    incrementing counter, both expiring after ``window`` seconds. The Redis
    client is injected — this module never connects on import.
    """

    def __init__(self, redis_client: object, window: int = DEFAULT_DEDUP_WINDOW,
                 prefix: str = 'cowrie') -> None:
        """Initialize the store.

        Args:
            redis_client: A ``redis``-compatible client (``sadd``, ``expire``,
                ``incr``, ``smembers``).
            window: Dedup window in seconds.
            prefix: Key namespace prefix.
        """
        self.redis = redis_client
        self.window = window
        self.prefix = prefix

    def register(self, signature: str, src_ip: str) -> bool:
        ip_key = f"{self.prefix}_campaign_ips:{signature}"
        dedup_count_key = f"{self.prefix}_alert_dedup:{signature}"
        if src_ip:
            self.redis.sadd(ip_key, src_ip)  # type: ignore[attr-defined]
            self.redis.expire(ip_key, self.window)  # type: ignore[attr-defined]
        seen = self.redis.incr(dedup_count_key)  # type: ignore[attr-defined]
        if int(seen) == 1:
            self.redis.expire(dedup_count_key, self.window)  # type: ignore[attr-defined]
            return True
        return False

    def source_ips(self, signature: str) -> Set[str]:
        members = self.redis.smembers(f"{self.prefix}_campaign_ips:{signature}")  # type: ignore[attr-defined]
        return {m.decode() if isinstance(m, bytes) else m for m in members}
