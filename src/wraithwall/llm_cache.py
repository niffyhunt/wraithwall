"""
Shared LLM response cache backed by Redis. Deduplicates identical prompts
across llm_honeypot, llm_firewall, and cowrie_intelligence to avoid
redundant API costs.

Usage:
    from llm_cache import cached_llm_call

    result = cached_llm_call(
        prefix="honeypot",        # namespace (honeypot|firewall|cowrie)
        prompt=json.dumps(msgs),  # cache key input
        ttl=300,                  # seconds
        callable=my_llm_function  # called on cache miss
    )
"""

import hashlib
import json
import logging
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# ── Redis connection (lazy singleton, shared with main.py pattern) ──────────
_redis = None

def _get_redis():
    global _redis
    if _redis is not None:
        return _redis
    try:
        import os
        import redis
        url = os.getenv("REDIS_URL", "")
        if not url:
            return None
        _redis = redis.from_url(url, decode_responses=True)
        _redis.ping()
    except Exception:
        _redis = None
    return _redis

# ── Core cache function ─────────────────────────────────────────────────────

def cached_llm_call(
    prefix: str,
    prompt: str,
    ttl: int,
    callable_fn: Callable[[], Any],
    serializer: Optional[Callable[[Any], str]] = None,
    deserializer: Optional[Callable[[str], Any]] = None,
) -> Any:
    """
    Return cached result if present, otherwise call `callable_fn`,
    cache the result, and return it.

    Args:
        prefix:    Redis key namespace (e.g. "honeypot", "firewall", "cowrie")
        prompt:    String to hash as cache key (typically serialized messages)
        ttl:       Cache TTL in seconds (0 = no expiry)
        callable_fn: Function to call on cache miss
        serializer:   Optional function to serialize result (default: json.dumps)
        deserializer: Optional function to deserialize result (default: json.loads)

    Returns:
        The cached result (deserialized), or the live result from callable_fn.
        Returns None if callable_fn returns None and no cache exists.
    """
    if serializer is None:
        serializer = json.dumps
    if deserializer is None:
        deserializer = json.loads

    r = _get_redis()
    if not r:
        # Redis unavailable — skip cache, call live
        return callable_fn()

    # Build deterministic cache key: prefix + sha256 of prompt
    key = f"llm_cache:{prefix}:{hashlib.sha256(prompt.encode()).hexdigest()[:32]}"

    # Try cache hit
    try:
        cached = r.get(key)
        if cached is not None:
            try:
                return deserializer(cached)
            except Exception:
                # Corrupt cache entry — fall through to recompute
                pass
    except Exception:
        pass

    # Cache miss — call live
    try:
        result = callable_fn()
    except Exception:
        return None

    if result is None:
        return None

    # Store in cache
    try:
        r.setex(key, ttl if ttl > 0 else 86400, serializer(result))
    except Exception:
        pass

    return result

# ── Convenience wrappers per subsystem ───────────────────────────────────────

def honeypot_cache(prompt: str, ttl: int, fn: Callable[[], Any]) -> Any:
    """Cache for LLM honeypot responses (default TTL: 5 min)."""
    return cached_llm_call("honeypot", prompt, ttl, fn)

def firewall_cache(prompt: str, ttl: int, fn: Callable[[], Any]) -> Any:
    """Cache for LLM firewall classification (default TTL: 1 hour)."""
    return cached_llm_call("firewall", prompt, ttl, fn)

def cowrie_cache(prompt: str, ttl: int, fn: Callable[[], Any]) -> Any:
    """Cache for Cowrie session analysis (default TTL: 24 hours)."""
    return cached_llm_call("cowrie", prompt, ttl, fn)

def invalidate_prefix(prefix: str) -> int:
    """Remove all cached entries for a given prefix. Returns count deleted."""
    r = _get_redis()
    if not r:
        return 0
    pattern = f"llm_cache:{prefix}:*"
    keys = list(r.scan_iter(match=pattern, count=100))
    if keys:
        return r.delete(*keys)
    return 0

def cache_stats(prefix: str = None) -> dict:
    """Return approximate cache stats for a prefix (or all if None)."""
    r = _get_redis()
    if not r:
        return {"available": False, "keys": 0}
    pattern = f"llm_cache:{prefix or ''}*"
    keys = list(r.scan_iter(match=pattern, count=1000))
    return {"available": True, "keys": len(keys)}
