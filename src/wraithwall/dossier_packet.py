"""Build a DOSSIER_CONTRACT packet from linker campaign JSON. No scoring."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

# The mapper and its JSON schema ship inside the package (both were monolith
# files reached through a hardcoded server path before). Resolving them beside
# this module keeps a pip install working with no deployment layout assumed.
SCHEMA_PATH = Path(__file__).with_name("dossier-contract.schema.json")

EXCLUDED = (
    "unique_ips",
    "tenant_id",
    "representative_fingerprint",
    "correlation_evidence",
    "tool_signatures",
    "sensors_hit",
    "asns",
    "countries",
    "feature_vector",
    "src_ip",
    "src_port",
)


def _mapper():
    from .dossier_contract import campaign_to_dossier
    return campaign_to_dossier


def packet_from_campaign(campaign: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    fn = _mapper()
    pkt = fn(campaign)
    if not pkt:
        return None
    for bad in EXCLUDED:
        if bad in pkt:
            raise ValueError(f"excluded field leaked: {bad}")
        if bad in (pkt.get("identity") or {}) or bad in (pkt.get("evidence") or {}):
            raise ValueError(f"excluded field leaked: {bad}")
    return pkt


def validate_packet(pkt: Dict[str, Any]) -> None:
    schema = json.loads(SCHEMA_PATH.read_text())
    required = schema.get("required") or []
    for k in required:
        if k not in pkt:
            raise ValueError(f"missing {k}")
    extras = set(pkt) - set((schema.get("properties") or {}).keys())
    if extras:
        raise ValueError(f"undeclared fields {sorted(extras)}")
    ident = pkt.get("identity") or {}
    ireq = (((schema.get("properties") or {}).get("identity") or {}).get("required")) or []
    for k in ireq:
        if k not in ident:
            raise ValueError(f"missing identity.{k}")
    if pkt.get("schema_version") != "1":
        raise ValueError("schema_version")


def dumps(pkt: Dict[str, Any]) -> bytes:
    validate_packet(pkt)
    return json.dumps(pkt, separators=(",", ":"), sort_keys=True).encode("utf-8")
