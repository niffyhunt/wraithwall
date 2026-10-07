"""Authorize dossier packet access. Cross-tenant and unknown ids both 404.

The published package ships no account stack, so auth symbols are read from
:mod:`wraithwall.host_auth` (bound once at startup by the deployment) instead
of a monolith ``main`` module that only exists in the WraithWall repository.
Reading an unbound symbol raises ``RuntimeError(host_auth.AUTH_RUNTIME_ERROR)``
— loud and actionable, never ``ModuleNotFoundError``.
"""
from __future__ import annotations

import re
from typing import Optional, Tuple

CAMPAIGN_ID_RE = re.compile(r"^[A-Za-z0-9]{8,64}$")


def sanitize_campaign_id(raw: str) -> Optional[str]:
    if raw is None:
        return None
    value = str(raw)
    if "%" in value or ".." in value or "/" in value or "\\" in value or "\x00" in value:
        return None
    if not CAMPAIGN_ID_RE.fullmatch(value):
        return None
    return value


def principal_tenant() -> Tuple[Optional[str], Optional[int]]:
    """(tenant_id, http_error). http_error is 401 if unauthenticated.

    Requires ``host_auth.bind(is_logged_in=..., verify_api_signature=...,
    auth_context=...)`` where ``auth_context()`` returns ``(tenant_id,
    caller_ref)``. Unbound raises ``host_auth.AUTH_RUNTIME_ERROR``.
    """
    from wraithwall.host_auth import (  # noqa: F401 — raises when unbound
        auth_context, is_logged_in, verify_api_signature,
    )
    if not is_logged_in():
        from flask import request, g
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None, 401
        ok, result = verify_api_signature()
        if not ok:
            return None, 401
        g.raven_api_key = result
    tenant, _ = auth_context()
    if not tenant:
        return None, 401
    from .campaign_correlator import _strict_tenant_id
    strict = _strict_tenant_id(tenant)
    if not strict:
        return None, 401
    return strict, None


def load_owned_campaign(campaign_id: str, tenant_id: str):
    from .campaign_correlator import get_correlator
    c = get_correlator()._get_campaign(campaign_id, tenant_id)
    if not c or c.get("tenant_id") != tenant_id:
        return None
    return c


def authorize_packet(raw_id: str):
    cid = sanitize_campaign_id(raw_id)
    if not cid:
        return None, 404, None
    tenant, err = principal_tenant()
    if err:
        return None, err, None
    camp = load_owned_campaign(cid, tenant)
    if not camp:
        return None, 404, tenant
    return camp, None, tenant


def _as_text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def redis_ready(correlator) -> bool:
    """True only if the live campaign store answers PING. False is UNAVAILABLE, not empty."""
    r = getattr(correlator, "redis", None)
    if r is None:
        return False
    try:
        return bool(r.ping())
    except Exception:
        return False


def list_owned_campaigns(tenant_id: str, limit: int = 100):
    """Load tenant-scoped campaign dicts from the live linker store.

    Returns (state, campaigns) where state is 'ok', 'empty', or 'unavailable'.
    Does not score, merge, or write Redis.
    """
    from .campaign_correlator import get_correlator

    corr = get_correlator()
    if not redis_ready(corr):
        return "unavailable", []
    r = corr.redis
    try:
        zids = r.zrange(f"active_campaigns:{tenant_id}", 0, -1) or []
        lids = r.lrange(f"campaigns:{tenant_id}:active", 0, max(limit - 1, 0)) or []
    except Exception:
        return "unavailable", []
    seen = set()
    ids = []
    for raw in list(zids) + list(lids):
        cid = _as_text(raw)
        if not cid or cid in seen:
            continue
        seen.add(cid)
        ids.append(cid)
        if len(ids) >= limit:
            break
    campaigns = []
    for cid in ids:
        camp = load_owned_campaign(cid, tenant_id)
        if camp:
            campaigns.append(camp)
    if not campaigns:
        return "empty", []
    campaigns.sort(key=lambda c: str(c.get("last_seen") or ""), reverse=True)
    return "ok", campaigns
