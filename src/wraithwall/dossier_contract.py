"""Dossier case-file contract.

Maps a campaign dict the linker already emitted onto DOSSIER_CONTRACT.
Does not score, cluster, or write Redis. schema_version is contract metadata.
"""

from typing import Any, Dict, List, Optional

SCHEMA_VERSION = "1"

# Linker threat_level values. Create path writes medium|high
# (campaign_correlator._create_campaign). Update path overwrites via
# CampaignCorrelator._assess_threat which returns low|medium|high|critical.
LINKER_THREAT_LEVELS = ("low", "medium", "high", "critical")

# Top-level keys _create_campaign writes (campaign_correlator.py).
LINKER_CAMPAIGN_KEYS = frozenset({
    "actor_uuids",
    "asns",
    "campaign_confidence",
    "campaign_id",
    "command_pattern_hash",
    "correlation_evidence",
    "countries",
    "deception_events",
    "first_seen",
    "human_confidence",
    "last_seen",
    "mitre_stages",
    "mitre_techniques",
    "representative_fingerprint",
    "sensors_hit",
    "session_count",
    "session_ids",
    "session_pacing",
    "status",
    "tenant_id",
    "threat_level",
    "tool_sequence",
    "tool_signatures",
    "tools",
    "unique_ips",
})

# Keys that stay inside WraithWall. Not copied onto the case JSON.
INTERNAL_ONLY = frozenset({
    "unique_ips",
    "sensors_hit",
    "asns",
    "countries",
    "representative_fingerprint",
    "correlation_evidence",
    "tool_signatures",
    "tenant_id",
})


def campaign_to_dossier(campaign: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Project a linker campaign dict to DOSSIER_CONTRACT.

    Returns None if campaign_id is missing. Unknown linker fields are dropped.
    """
    if not isinstance(campaign, dict):
        return None
    cid = campaign.get("campaign_id")
    if not cid:
        return None

    rep = campaign.get("representative_fingerprint") or {}
    if not isinstance(rep, dict):
        rep = {}
    normalized = rep.get("normalized_commands") or []
    if not isinstance(normalized, list):
        normalized = []

    evid = campaign.get("correlation_evidence") or []
    session_ids = list(campaign.get("session_ids") or [])
    if isinstance(evid, list):
        for item in evid:
            if isinstance(item, dict) and item.get("session_id"):
                sid = item["session_id"]
                if sid not in session_ids:
                    session_ids.append(sid)

    threat = campaign.get("threat_level") or "medium"
    if threat not in LINKER_THREAT_LEVELS:
        threat = "medium"

    return {
        "schema_version": SCHEMA_VERSION,
        "campaign_id": str(cid),
        "status": campaign.get("status") or "active",
        "threat_level": threat,
        "campaign_confidence": _num_or_none(campaign.get("campaign_confidence")),
        "session_count": int(campaign.get("session_count") or 0),
        "first_seen": campaign.get("first_seen"),
        "last_seen": campaign.get("last_seen"),
        "identity": {
            "command_pattern_hash": campaign.get("command_pattern_hash"),
            "tools": list(campaign.get("tools") or []),
            "tool_sequence": list(campaign.get("tool_sequence") or []),
            "session_pacing": campaign.get("session_pacing") or "unknown",
            "human_confidence": _num_or_none(campaign.get("human_confidence")),
            "normalized_commands": [str(x) for x in normalized],
            "actor_uuids": list(campaign.get("actor_uuids") or []),
        },
        "evidence": {
            "session_ids": [str(x) for x in session_ids if x],
        },
        "mitre_techniques": list(campaign.get("mitre_techniques") or []),
        "mitre_stages": list(campaign.get("mitre_stages") or []),
        "deception_events": int(campaign.get("deception_events") or 0),
    }


def _num_or_none(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
