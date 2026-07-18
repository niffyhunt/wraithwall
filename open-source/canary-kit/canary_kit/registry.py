"""Token registration and beacon/trigger detection.

A :class:`CanaryRegistry` ties a :class:`~canary_kit.storage.CanaryStore` to the
token lifecycle: minting + registering a token, then matching an inbound beacon
back to a previously issued token (the trigger-detection step that signals the
canary "fired").
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from .storage import CanaryStore, InMemoryStore
from .tokens import (
    TOKEN_TYPE_RUNTIME,
    CanaryToken,
    mint_token,
)


@dataclass
class BeaconResult:
    """Outcome of matching an inbound beacon against the registry.

    Attributes:
        matched: True if the beacon's token was a known issued token.
        token: The token string from the beacon.
        record: The updated :class:`CanaryToken` record when matched, else None.
        reason: Human-readable explanation (useful when ``matched`` is False).
    """

    matched: bool
    token: str
    record: Optional[CanaryToken] = None
    reason: str = ""


class CanaryRegistry:
    """Mints, registers, and detects triggers for canary tokens.

    Args:
        store: Storage backend; defaults to a fresh
            :class:`~canary_kit.storage.InMemoryStore`.
    """

    def __init__(self, store: Optional[CanaryStore] = None) -> None:
        self.store: CanaryStore = store or InMemoryStore()

    # ── registration ────────────────────────────────────────

    def register(
        self,
        package_name: str,
        version: str,
        *,
        token_type: str = TOKEN_TYPE_RUNTIME,
        salt: Optional[str] = None,
        token: Optional[str] = None,
        **extra: object,
    ) -> CanaryToken:
        """Mint (or accept) a token, persist its metadata, and return it.

        Args:
            package_name: Package the canary is planted in.
            version: Package version.
            token_type: One of the canary token types.
            salt: Optional explicit salt for deterministic minting.
            token: Optionally register a pre-computed token instead of minting.
            **extra: Arbitrary metadata stored under ``CanaryToken.extra``.

        Returns:
            The persisted :class:`CanaryToken` record.
        """
        tok = token or mint_token(package_name, version, salt=salt)
        record = CanaryToken(
            token=tok,
            package_name=package_name,
            version=version,
            token_type=token_type,
            extra=dict(extra),
        )
        self.store.put(record)
        return record

    def get(self, token: str) -> Optional[CanaryToken]:
        """Return the record for ``token`` or ``None``."""
        return self.store.get(token)

    def list_tokens(self) -> list[str]:
        """Return all issued token strings."""
        return self.store.tokens()

    def all_records(self) -> list[CanaryToken]:
        """Return all issued token records."""
        return self.store.all()

    # ── beacon / trigger detection ──────────────────────────

    def detect(
        self,
        token: str,
        *,
        ip_address: str = "",
        env_hash: str = "unknown",
        version: str = "unknown",
    ) -> BeaconResult:
        """Match an inbound beacon to an issued token and record the trigger.

        This is the detection core: if ``token`` corresponds to a registered
        canary, the record is marked fired, counters/IPs/environments are
        appended, and the updated record is persisted. An unknown token yields
        ``matched=False`` and no state change.

        Args:
            token: The token value carried by the beacon.
            ip_address: Source IP of the beacon, if known.
            env_hash: Opaque environment fingerprint reported by the beacon.
            version: Package version reported by the beacon.

        Returns:
            A :class:`BeaconResult` describing the outcome.
        """
        if not token:
            return BeaconResult(matched=False, token=token, reason="empty token")

        record = self.store.get(token)
        if record is None:
            return BeaconResult(matched=False, token=token, reason="unknown token")

        now = datetime.now(timezone.utc).isoformat()
        record.fired = True
        record.fire_count += 1
        record.last_fired = now
        if ip_address:
            record.fire_ips.append(ip_address)
        record.fire_environments.append(
            {
                "env_hash": env_hash,
                "version": version,
                "ip": ip_address,
                "timestamp": now,
            }
        )
        self.store.put(record)
        return BeaconResult(matched=True, token=token, record=record)

    #: Backwards-compatible alias mirroring the original ``report_beacon`` name.
    report_beacon = detect


__all__ = ["BeaconResult", "CanaryRegistry"]
