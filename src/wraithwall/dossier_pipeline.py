"""Hook dossier generation onto existing campaign.created / campaign.updated emits."""
from __future__ import annotations

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)
_installed = False


def on_campaign_event(event_type: str, payload: Dict[str, Any]) -> None:
    if event_type not in ("campaign.created", "campaign.updated"):
        return
    cid = (payload or {}).get("campaign_id")
    if not cid:
        return
    campaign = None
    try:
        from .campaign_correlator import _strict_tenant_id, get_correlator
        corr = get_correlator()
        tenant = _strict_tenant_id((payload or {}).get("tenant_id"))
        if tenant:
            campaign = corr._get_campaign(cid, tenant)
        if not campaign and getattr(corr, "redis", None):
            for key in corr.redis.scan_iter(match="active_campaigns:*", count=50):
                name = key.decode() if isinstance(key, bytes) else str(key)
                t = name.split(":", 1)[-1]
                if not _strict_tenant_id(t):
                    continue
                campaign = corr._get_campaign(cid, t)
                if campaign:
                    break
        if not campaign:
            return
    except Exception:
        logger.exception("dossier_pipeline load campaign failed")
        return
    try:
        from .dossier_events import from_campaign_event
        from .dossier_store import upsert_packet
        from .dossier_packet import packet_from_campaign
        pkt = packet_from_campaign(campaign)
        if not pkt:
            return
        event = from_campaign_event(event_type, campaign)
        if not event:
            return
        upsert_packet(pkt)
        _fanout(event, campaign.get("tenant_id"))
    except Exception:
        logger.exception("dossier_pipeline emit failed")


def _fanout(event: dict, tenant_id) -> None:
    try:
        from .dossier_webhook import deliver, load_or_create_secret, validate_webhook_url
        secret = load_or_create_secret()
        from . import dossier_destinations as dests
        for url in dests.urls_for_tenant(tenant_id, event["event"]):
            if validate_webhook_url(url):
                continue
            deliver(url, event, secret)
    except Exception:
        logger.debug("dossier fanout skipped", exc_info=True)


def install() -> None:
    global _installed
    if _installed:
        return
    import webhooks
    orig = webhooks.emit_safe

    def wrapped(event_type, payload=None, *args, **kwargs):
        result = orig(event_type, payload, *args, **kwargs)
        try:
            if event_type in ("campaign.created", "campaign.updated"):
                on_campaign_event(event_type, payload or {})
        except Exception:
            logger.exception("dossier_pipeline wrapper")
        return result

    webhooks.emit_safe = wrapped
    _installed = True
    logger.info("dossier_pipeline hooked emit_safe")
