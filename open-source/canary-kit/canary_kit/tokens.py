"""Canary token minting, metadata, and deterministic derivations.

The minting and watermark-encoding logic here is kept faithful to the original
WraithWall supply-chain canary implementation: a token is a 24-hex-char digest
derived from the package name, version, and per-token random salt, and the
zero-width watermark is derived deterministically from the first 8 hex chars of
the token.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

# ────────────────────────────────────────────────────────────
# TOKEN TYPES
# ────────────────────────────────────────────────────────────

#: A canary embedded as runtime code that beacons home on import.
TOKEN_TYPE_RUNTIME = "runtime"
#: A canary embedded as a DNS hostname in package metadata.
TOKEN_TYPE_DNS = "dns"
#: A canary embedded as a zero-width-character watermark in docstrings.
TOKEN_TYPE_WATERMARK = "watermark"

TOKEN_TYPES = (TOKEN_TYPE_RUNTIME, TOKEN_TYPE_DNS, TOKEN_TYPE_WATERMARK)

# Zero-width characters used for watermark encoding. Built from codepoints so
# the (invisible) values are unambiguous in source. Matches the original impl:
#   U+200B zero-width space (bit 0), U+200C ZWNJ (bit 1), U+200D ZWJ (separator).
ZW_ZERO = chr(0x200B)  # zero-width space      -> bit 0
ZW_ONE = chr(0x200C)   # zero-width non-joiner -> bit 1
ZW_SEP = chr(0x200D)   # zero-width joiner     -> delimiter


# ────────────────────────────────────────────────────────────
# TOKEN METADATA MODEL
# ────────────────────────────────────────────────────────────


@dataclass
class CanaryToken:
    """Metadata for a single issued canary token.

    Attributes:
        token: The 24-char hex token string (the registry key).
        package_name: Name of the package the canary was planted in.
        version: Version of the package the canary was planted in.
        token_type: One of :data:`TOKEN_TYPES`.
        created_at: ISO-8601 UTC timestamp of minting.
        fired: Whether at least one beacon has been matched to this token.
        fire_count: Number of beacons matched to this token.
        last_fired: ISO-8601 UTC timestamp of the most recent beacon, if any.
        fire_ips: List of source IPs that triggered the token.
        fire_environments: Per-beacon trigger detail records.
        extra: Arbitrary caller-supplied metadata.
    """

    token: str
    package_name: str
    version: str
    token_type: str = TOKEN_TYPE_RUNTIME
    created_at: str = field(default_factory=lambda: _utc_now())
    fired: bool = False
    fire_count: int = 0
    last_fired: Optional[str] = None
    fire_ips: list[str] = field(default_factory=list)
    fire_environments: list[dict] = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialise to a plain JSON-safe dict."""
        return {
            "token": self.token,
            "package_name": self.package_name,
            "version": self.version,
            "token_type": self.token_type,
            "created_at": self.created_at,
            "fired": self.fired,
            "fire_count": self.fire_count,
            "last_fired": self.last_fired,
            "fire_ips": list(self.fire_ips),
            "fire_environments": list(self.fire_environments),
            "extra": dict(self.extra),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CanaryToken":
        """Reconstruct a :class:`CanaryToken` from :meth:`to_dict` output."""
        return cls(
            token=data["token"],
            package_name=data.get("package_name", ""),
            version=data.get("version", ""),
            token_type=data.get("token_type", TOKEN_TYPE_RUNTIME),
            created_at=data.get("created_at", _utc_now()),
            fired=bool(data.get("fired", False)),
            fire_count=int(data.get("fire_count", 0)),
            last_fired=data.get("last_fired"),
            fire_ips=list(data.get("fire_ips", [])),
            fire_environments=list(data.get("fire_environments", [])),
            extra=dict(data.get("extra", {})),
        )


def _utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


# ────────────────────────────────────────────────────────────
# TOKEN MINTING
# ────────────────────────────────────────────────────────────


def mint_token(package_name: str, version: str, *, salt: Optional[str] = None) -> str:
    """Mint a new 24-char hex canary token.

    The token is ``sha256(f"{package_name}:{version}:{salt}")[:24]``. When
    ``salt`` is omitted a cryptographically random 8-byte hex salt is generated
    with :mod:`secrets`, so repeated calls with the same package/version are
    unique. Pass an explicit ``salt`` to derive a token deterministically (used
    by the tests to verify reproducibility).

    Args:
        package_name: Name of the package the canary belongs to.
        version: Version string of the package.
        salt: Optional explicit salt for deterministic derivation.

    Returns:
        A 24-character lowercase hex token.
    """
    if salt is None:
        salt = secrets.token_hex(8)
    seed = f"{package_name}:{version}:{salt}"
    return hashlib.sha256(seed.encode()).hexdigest()[:24]


def derive_token(package_name: str, version: str, salt: str) -> str:
    """Deterministically derive a token from a known salt.

    Identical to ``mint_token(package_name, version, salt=salt)``; provided as a
    named helper for clarity when reproducibility is the intent.
    """
    return mint_token(package_name, version, salt=salt)


# ────────────────────────────────────────────────────────────
# ZERO-WIDTH WATERMARK (deterministic from token prefix)
# ────────────────────────────────────────────────────────────


def encode_watermark(token: str) -> str:
    """Encode the first 8 hex chars of ``token`` as a zero-width watermark.

    The 32-bit value of ``token[:8]`` is written as zero-width characters,
    bracketed by separator characters, suitable for hiding inside a docstring.
    """
    bits = bin(int(token[:8], 16))[2:].zfill(32)
    body = "".join(ZW_ONE if b == "1" else ZW_ZERO for b in bits)
    return ZW_SEP + body + ZW_SEP


def decode_watermark(text: str) -> Optional[str]:
    """Recover the 8-char token prefix from text containing a watermark.

    Returns ``None`` if no valid watermark is present.
    """
    if ZW_SEP not in text:
        return None
    for part in text.split(ZW_SEP):
        if len(part) == 32 and all(c in (ZW_ZERO, ZW_ONE) for c in part):
            bits = "".join("1" if c == ZW_ONE else "0" for c in part)
            return hex(int(bits, 2))[2:].zfill(8)
    return None


__all__ = [
    "CanaryToken",
    "TOKEN_TYPE_RUNTIME",
    "TOKEN_TYPE_DNS",
    "TOKEN_TYPE_WATERMARK",
    "TOKEN_TYPES",
    "ZW_ZERO",
    "ZW_ONE",
    "ZW_SEP",
    "mint_token",
    "derive_token",
    "encode_watermark",
    "decode_watermark",
]
