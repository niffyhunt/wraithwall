"""Canary Kit — supply-chain canary token minting & beacon/trigger detection.

Plant uniquely-derived canary tokens in software packages, then detect when one
"fires" by matching an inbound beacon back to the issued token. Pure stdlib at
its core; storage is pluggable (in-memory by default, optional injected Redis).

Part of the WraithWall project — https://wraithwall.online · by Niffy_hunt
"""

from __future__ import annotations

from .registry import BeaconResult, CanaryRegistry
from .storage import CanaryStore, InMemoryStore, RedisStore
from .tokens import (
    TOKEN_TYPE_DNS,
    TOKEN_TYPE_RUNTIME,
    TOKEN_TYPE_WATERMARK,
    TOKEN_TYPES,
    CanaryToken,
    decode_watermark,
    derive_token,
    encode_watermark,
    mint_token,
)

__version__ = "0.1.0"

def create_canary(
    package_name: str,
    version: str,
    *,
    token_type: str = TOKEN_TYPE_RUNTIME,
    salt: str | None = None,
) -> CanaryToken:
    """Public API: mint and return a new canary token record."""
    return CanaryToken(
        token=mint_token(package_name, version, salt=salt),
        package_name=package_name,
        version=version,
        token_type=token_type,
    )


__all__ = [
    "__version__",
    # tokens
    "CanaryToken",
    "mint_token",
    "create_canary",
    "derive_token",
    "encode_watermark",
    "decode_watermark",
    "TOKEN_TYPE_RUNTIME",
    "TOKEN_TYPE_DNS",
    "TOKEN_TYPE_WATERMARK",
    "TOKEN_TYPES",
    # registry / detection
    "CanaryRegistry",
    "BeaconResult",
    # storage
    "CanaryStore",
    "InMemoryStore",
    "RedisStore",
]
