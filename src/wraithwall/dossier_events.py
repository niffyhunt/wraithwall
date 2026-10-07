"""Emit dossier.created / dossier.updated only from campaign lifecycle."""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, Optional

from .dossier_packet import packet_from_campaign, validate_packet


def make_event(kind: str, packet: Dict[str, Any]) -> Dict[str, Any]:
    if kind not in ("dossier.created", "dossier.updated"):
        raise ValueError("kind")
    validate_packet(packet)
    return {
        "event_id": uuid.uuid4().hex,
        "timestamp": int(time.time()),
        "dossier_contract_version": packet.get("schema_version") or "1",
        "campaign_id": packet["campaign_id"],
        "event": kind,
        "payload": packet,
    }


def from_campaign_event(event_type: str, campaign: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if event_type == "campaign.created":
        kind = "dossier.created"
    elif event_type == "campaign.updated":
        kind = "dossier.updated"
    else:
        return None
    if not campaign:
        return None
    pkt = packet_from_campaign(campaign)
    if not pkt:
        return None
    return make_event(kind, pkt)
