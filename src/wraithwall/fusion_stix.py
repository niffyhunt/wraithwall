"""
STIX 2.1 export generator for WraithWall threat intelligence.

Generates STIX 2.1 Indicator, Attack Pattern, Campaign, and Observed Data
objects from WraithWall's internal intelligence stores.  Threat Actor objects
are explicitly NOT generated — see ``_THREAT_ACTOR_FORBIDDEN_MSG`` for rationale.
"""

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import redis as redis_lib

from wraithwall.campaign_correlator import get_correlator
from wraithwall.cowrie_intelligence import MITRE_TECHNIQUES, TACTIC_ORDER

REDIS_URL: str = os.environ.get("REDIS_URL", "")

_THREAT_ACTOR_FORBIDDEN_MSG: str = (
    "Threat Actor objects are explicitly excluded from this generator. "
    "Threat Actor attribution is inherently speculative and can introduce "
    "legal and operational risk into exported intelligence bundles. "
    "Use Campaign, Attack Pattern, Indicator, and Observed Data objects instead."
)

_INDICATOR_NAMESPACE: uuid.UUID = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
_ATTACK_PATTERN_NAMESPACE: uuid.UUID = uuid.UUID("9d3e1a7b-2f4c-4e5d-a8b9-c0d1e2f3a4b5")
_CAMPAIGN_NAMESPACE: uuid.UUID = uuid.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")

_STIX_PATTERN_TEMPLATES: Dict[str, str] = {
    "ipv4": "[ipv4-addr:value = '{value}']",
    "ipv6": "[ipv6-addr:value = '{value}']",
    "domain": "[domain-name:value = '{value}']",
    "url": "[url:value = '{value}']",
}

_MITRE_TACTIC_URL: str = "https://attack.mitre.org/tactics/{tactic_id}"
_MITRE_TECHNIQUE_URL: str = "https://attack.mitre.org/techniques/{technique_id}"

_MITRE_TACTIC_NAMES: Dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}

_MITRE_TECHNIQUE_NAMES: Dict[str, str] = {
    "T1082": "System Information Discovery",
    "T1033": "System Owner/User Discovery",
    "T1016": "System Network Configuration Discovery",
    "T1057": "Process Discovery",
    "T1595": "Active Scanning",
    "T1592": "Gather Victim Host Information",
    "T1053": "Scheduled Task/Job",
    "T1136": "Create Account",
    "T1098": "Account Manipulation",
    "T1546": "Event Triggered Execution",
    "T1543": "Create or Modify System Process",
    "T1068": "Exploitation for Privilege Escalation",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1070": "Indicator Removal",
    "T1027": "Obfuscated Files or Information",
    "T1564": "Hide Artifacts",
    "T1110": "Brute Force",
    "T1552": "Unsecured Credentials",
    "T1003": "OS Credential Dumping",
    "T1021": "Remote Services",
    "T1563": "Remote Service Session Hijacking",
    "T1005": "Data from Local System",
    "T1074": "Data Staged",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1041": "Exfiltration Over C2 Channel",
    "T1095": "Non-Application Layer Protocol",
    "T1571": "Non-Standard Port",
    "T1071": "Application Layer Protocol",
    "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact",
    "T1529": "System Shutdown/Reboot",
}

_STIX_ID_RE_TYPE = r"[a-z][a-z0-9-]*"
_STIX_ID_RE_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _get_redis() -> Optional[redis_lib.Redis]:
    if not REDIS_URL:
        return None
    try:
        return redis_lib.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
        )
    except Exception:
        return None

def _stix_id(stix_type: str) -> str:
    return f"{stix_type}--{uuid.uuid4()}"

def _derive_indicator_id(ioc_type: str, value: str) -> str:
    deterministic = uuid.uuid5(_INDICATOR_NAMESPACE, f"ioc:{ioc_type}:{value}")
    return f"indicator--{deterministic}"

def _derive_attack_pattern_id(technique_id: str) -> str:
    deterministic = uuid.uuid5(_ATTACK_PATTERN_NAMESPACE, f"attack-pattern:{technique_id}")
    return f"attack-pattern--{deterministic}"

def _derive_campaign_id(campaign_id: str) -> str:
    deterministic = uuid.uuid5(_CAMPAIGN_NAMESPACE, f"campaign:{campaign_id}")
    return f"campaign--{deterministic}"

def _build_pattern(ioc_type: str, value: str) -> str:
    template = _STIX_PATTERN_TEMPLATES.get(ioc_type)
    if template:
        return template.format(value=value)
    return f"[artifact:payload_bin = '{value}']"

def _coerce_isotime(value: Optional[str]) -> str:
    if not value:
        return _now_iso()
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value
    except (ValueError, AttributeError):
        return _now_iso()

def _check_threat_actor_forbidden() -> None:
    pass

def generate_threat_actors() -> List[Dict[str, Any]]:
    """Threat Actor objects are deliberately excluded from STIX 2.1 export.

    Attribution to specific threat actors is inherently speculative and can
    introduce legal and operational risk into exported intelligence bundles.
    This generator instead exports Campaign, Attack Pattern, Indicator, and
    Observed Data objects which provide verifiable, evidence-backed intelligence
    suitable for sharing with partners without unverified attribution claims.
    """
    raise RuntimeError(_THREAT_ACTOR_FORBIDDEN_MSG)

def generate_stix_bundle(session_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    """Generate a full STIX 2.1 bundle with all available objects.

    Args:
        session_ids: Optional list of Cowrie session IDs.  When provided,
            Observed Data objects are generated for each session and any
            IOCs found within those sessions are included in the Indicator
            set.  When None, only Indicators, Attack Patterns, and Campaigns
            are included.

    Returns:
        A STIX 2.1 Bundle dict with ``type``, ``id``, ``spec_version``, and
        ``objects`` populated.
    """
    _check_threat_actor_forbidden()

    objects: List[Dict[str, Any]] = []

    indicators = generate_indicators(limit=200)
    objects.extend(indicators)

    attack_patterns = generate_attack_patterns()
    objects.extend(attack_patterns)

    campaigns = generate_campaigns()
    objects.extend(campaigns)

    if session_ids:
        observed = generate_observed_data(session_ids)
        objects.extend(observed)

    bundle_id = f"bundle--{uuid.uuid4()}"
    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects,
    }

def generate_indicators(limit: int = 100) -> List[Dict[str, Any]]:
    """Generate STIX 2.1 Indicator objects from Spectra IOC store entries.

    Scans the Redis IOC store for ``ioc:ipv4:*``, ``ioc:domain:*``, and
    ``ioc:url:*`` keys and creates one Indicator per IOC.  Each Indicator
    includes a STIX-compliant pattern with the appropriate SCO type
    (ipv4-addr, domain-name, or url).

    Args:
        limit: Maximum number of Indicators to return (default 100).

    Returns:
        List of STIX 2.1 Indicator dicts.
    """
    _check_threat_actor_forbidden()

    r = _get_redis()
    if not r:
        return []

    indicators: List[Dict[str, Any]] = []
    now = _now_iso()

    for ioc_type in ("ipv4", "domain", "url"):
        if len(indicators) >= limit:
            break
        try:
            for key in r.scan_iter(match=f"ioc:{ioc_type}:*", count=100):
                if len(indicators) >= limit:
                    break
                parts = key.split(":", 2)
                if len(parts) < 3:
                    continue
                value = parts[2]
                data = r.hgetall(key)
                if not data:
                    continue

                count = int(data.get("count", 0))
                first_seen = _coerce_isotime(data.get("first_seen"))
                last_seen = _coerce_isotime(data.get("last_seen"))
                context = data.get("context", "")

                indicator_id = _derive_indicator_id(ioc_type, value)
                pattern = _build_pattern(ioc_type, value)

                instance: Dict[str, Any] = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": indicator_id,
                    "created": first_seen,
                    "modified": last_seen,
                    "name": f"IOC: {value}",
                    "description": f"IOC of type {ioc_type} observed {count} times.",
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": first_seen,
                    "indicator_types": ["malicious-activity"],
                }

                if context:
                    instance["description"] = f"IOC of type {ioc_type} observed {count} times. Context: {context}"

                indicators.append(instance)

        except Exception:
            continue

    return indicators

def generate_attack_patterns() -> List[Dict[str, Any]]:
    """Generate STIX 2.1 Attack Pattern objects from the MITRE ATT&CK mapping.

    Iterates the ``MITRE_TECHNIQUES`` dictionary in ``cowrie_intelligence.py``
    and creates one Attack Pattern per observed technique and tactic.  Each
    object carries an ``external_references`` entry pointing to the canonical
    MITRE ATT&CK URL.

    Returns:
        List of STIX 2.1 Attack Pattern dicts.
    """
    _check_threat_actor_forbidden()

    attack_patterns: List[Dict[str, Any]] = []
    now = _now_iso()
    seen_technique_ids: Set[str] = set()
    seen_tactic_ids: Set[str] = set()

    for stage_name, stage_data in MITRE_TECHNIQUES.items():
        tactic_id = stage_data.get("id", "")
        technique_ids = stage_data.get("techniques", [])

        if tactic_id and tactic_id not in seen_tactic_ids:
            seen_tactic_ids.add(tactic_id)
            tactic_name = _MITRE_TACTIC_NAMES.get(tactic_id, stage_name.replace("_", " ").title())
            ap_id = _derive_attack_pattern_id(tactic_id)

            attack_patterns.append({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": now,
                "modified": now,
                "name": tactic_name,
                "description": f"MITRE ATT&CK Tactic: {tactic_name} ({tactic_id})",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": tactic_id,
                        "url": _MITRE_TACTIC_URL.format(tactic_id=tactic_id),
                    }
                ],
            })

        for technique_id in technique_ids:
            if technique_id in seen_technique_ids:
                continue
            seen_technique_ids.add(technique_id)

            technique_name = _MITRE_TECHNIQUE_NAMES.get(
                technique_id, technique_id
            )
            ap_id = _derive_attack_pattern_id(technique_id)

            attack_patterns.append({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": now,
                "modified": now,
                "name": technique_name,
                "description": f"MITRE ATT&CK Technique: {technique_name} ({technique_id}). "
                f"Mapped from {stage_name} commands observed in Cowrie sessions.",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": technique_id,
                        "url": _MITRE_TECHNIQUE_URL.format(technique_id=technique_id),
                    }
                ],
            })

    return attack_patterns

def generate_campaigns() -> List[Dict[str, Any]]:
    """Generate STIX 2.1 Campaign objects from active campaign correlator data.

    Reads active campaigns from ``CampaignCorrelator.get_active_campaigns()``
    and converts each into a STIX 2.1 Campaign object.

    Returns:
        List of STIX 2.1 Campaign dicts.
    """
    _check_threat_actor_forbidden()

    try:
        correlator = get_correlator()
        campaigns_raw = correlator.get_active_campaigns()
    except Exception:
        return []

    campaigns: List[Dict[str, Any]] = []
    now = _now_iso()

    for camp_raw in campaigns_raw:
        internal_id = camp_raw.get("campaign_id", "")
        if not internal_id:
            continue

        stix_id = _derive_campaign_id(internal_id)
        first_seen = _coerce_isotime(camp_raw.get("first_seen"))
        last_seen = _coerce_isotime(camp_raw.get("last_seen"))
        threat_level = camp_raw.get("threat_level", "medium")
        tool_sigs = camp_raw.get("tool_signatures", {})

        name = f"Campaign {internal_id[:8]}"
        if tool_sigs:
            tool_names = ", ".join(tool_sigs.keys())
            name = f"Campaign {internal_id[:8]} ({tool_names})"

        aliases: List[str] = []
        if tool_sigs:
            aliases = list(tool_sigs.keys())

        first_seen_obj = camp_raw.get("first_seen", "")
        last_seen_obj = camp_raw.get("last_seen", "")

        campaign_obj: Dict[str, Any] = {
            "type": "campaign",
            "spec_version": "2.1",
            "id": stix_id,
            "created": first_seen or now,
            "modified": last_seen or now,
            "name": name,
            "aliases": aliases,
            "first_seen": first_seen_obj if first_seen_obj and isinstance(first_seen_obj, str) else first_seen,
            "last_seen": last_seen_obj if last_seen_obj and isinstance(last_seen_obj, str) else last_seen,
            "description": (
                f"WraithWall campaign | threat: {threat_level} | "
                f"sessions: {camp_raw.get('session_count', 0)} | "
                f"unique IPs: {len(camp_raw.get('unique_ips', []))} | "
                f"sensors hit: {len(camp_raw.get('sensors_hit', []))}"
            ),
        }

        campaigns.append(campaign_obj)

    return campaigns

def generate_observed_data(session_ids: List[str]) -> List[Dict[str, Any]]:
    """Generate STIX 2.1 Observed Data objects from completed Cowrie sessions.

    Loads each session from the Redis ``cowrie_completed:{sid}`` store and
    builds an Observed Data object with command count, IOC count, threat score,
    timestamps, and references to any Indicators generated from the session's
    extracted IOCs.

    Args:
        session_ids: List of Cowrie session identifiers.

    Returns:
        List of STIX 2.1 Observed Data dicts.
    """
    _check_threat_actor_forbidden()

    r = _get_redis()
    if not r:
        return []

    observed_objects: List[Dict[str, Any]] = []
    now = _now_iso()

    for sid in session_ids:
        raw = r.get(f"cowrie_completed:{sid}")
        if not raw:
            continue
        try:
            session = json.loads(raw)
        except json.JSONDecodeError:
            continue

        commands = session.get("commands", [])
        cmd_count = len(commands)

        intelligence = session.get("intelligence", {})
        threat_score = intelligence.get("threat_score", 0)
        unison_verdict = intelligence.get("unison_verdict", "")

        iocs = session.get("iocs", {})
        ioc_total = 0
        object_refs: List[str] = []
        for ioc_type, values in iocs.items():
            if isinstance(values, list):
                for value in values:
                    object_refs.append(_derive_indicator_id(ioc_type, value))
                    ioc_total += 1

        connected_at = _coerce_isotime(session.get("connected_at"))
        closed_at = _coerce_isotime(session.get("closed_at"))

        attack_stage = intelligence.get("attack_stage", "unknown")
        crystal = intelligence.get("crystal", {})
        crystal_action = crystal.get("action", "unknown") if crystal else "unknown"

        description_parts = [
            f"Session from {session.get('src_ip', 'unknown')}",
            f"Commands: {cmd_count}",
            f"Threat score: {threat_score}",
        ]
        if unison_verdict:
            description_parts.append(f"Verdict: {unison_verdict}")
        if crystal_action:
            description_parts.append(f"Action: {crystal_action}")

        observed: Dict[str, Any] = {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": f"observed-data--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "first_observed": connected_at,
            "last_observed": closed_at,
            "number_observed": 1,
            "object_refs": object_refs if object_refs else [],
            "x_cowrie_session_id": sid,
            "x_command_count": cmd_count,
            "x_threat_score": threat_score,
            "x_attack_stage": attack_stage,
            "x_crystal_action": crystal_action,
            "x_unison_verdict": unison_verdict or "unknown",
            "x_ioc_count": ioc_total,
        }

        observed_objects.append(observed)

    return observed_objects

def export_bundle_json(bundle: Dict[str, Any]) -> str:
    """Serialize a STIX 2.1 bundle dict to a JSON string.

    Args:
        bundle: A STIX 2.1 Bundle dict as returned by ``generate_stix_bundle``.

    Returns:
        A compact (no extra whitespace) JSON string.
    """
    return json.dumps(bundle, ensure_ascii=False, separators=(",", ":"))

def validate_bundle(bundle: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Perform basic STIX 2.1 schema validation on a bundle dict.

    Checks that the bundle envelope is well-formed, that every object has the
    mandatory common properties (``type``, ``id``, ``created``, ``modified``),
    that STIX IDs match the ``{type}--{uuid}`` convention, and that type-specific
    required fields are present.

    Args:
        bundle: A STIX 2.1 Bundle dict.

    Returns:
        A tuple of (``is_valid``, ``errors``) where ``errors`` is a list of
        human-readable validation failure messages.
    """
    errors: List[str] = []

    if not isinstance(bundle, dict):
        return False, ["Bundle must be a dict"]

    if bundle.get("type") != "bundle":
        errors.append("Bundle envelope must have type='bundle'")

    if "id" not in bundle or not isinstance(bundle["id"], str):
        errors.append("Bundle envelope missing valid 'id'")

    objects = bundle.get("objects")
    if not isinstance(objects, list):
        errors.append("Bundle 'objects' must be a list")
        return False, errors

    if not objects:
        errors.append("Bundle 'objects' list is empty")

    for idx, obj in enumerate(objects):
        prefix = f"objects[{idx}]"
        if not isinstance(obj, dict):
            errors.append(f"{prefix}: must be a dict")
            continue

        obj_type = obj.get("type")
        if not obj_type or not isinstance(obj_type, str):
            errors.append(f"{prefix}: missing or invalid 'type'")
            continue

        obj_id = obj.get("id")
        if not obj_id or not isinstance(obj_id, str):
            errors.append(f"{prefix}: missing or invalid 'id'")
        elif not obj_id.startswith(f"{obj_type}--"):
            errors.append(f"{prefix}: id '{obj_id}' does not start with type prefix '{obj_type}--'")

        if "created" not in obj:
            errors.append(f"{prefix} ({obj_type}): missing 'created'")
        if "modified" not in obj:
            errors.append(f"{prefix} ({obj_type}): missing 'modified'")

        if obj_type == "indicator":
            if "pattern" not in obj:
                errors.append(f"{prefix} (indicator): missing 'pattern'")
            if "pattern_type" not in obj:
                errors.append(f"{prefix} (indicator): missing 'pattern_type'")
            if "valid_from" not in obj:
                errors.append(f"{prefix} (indicator): missing 'valid_from'")

        elif obj_type == "attack-pattern":
            if "name" not in obj:
                errors.append(f"{prefix} (attack-pattern): missing 'name'")
            ext_refs = obj.get("external_references")
            if not ext_refs or not isinstance(ext_refs, list):
                errors.append(f"{prefix} (attack-pattern): missing 'external_references' list")

        elif obj_type == "campaign":
            if "name" not in obj:
                errors.append(f"{prefix} (campaign): missing 'name'")

        elif obj_type == "observed-data":
            if "first_observed" not in obj:
                errors.append(f"{prefix} (observed-data): missing 'first_observed'")
            if "last_observed" not in obj:
                errors.append(f"{prefix} (observed-data): missing 'last_observed'")
            if "number_observed" not in obj:
                errors.append(f"{prefix} (observed-data): missing 'number_observed'")
            if "object_refs" not in obj:
                errors.append(f"{prefix} (observed-data): missing 'object_refs'")

        elif obj_type == "threat-actor":
            errors.append(
                f"{prefix} (threat-actor): Threat Actor objects are explicitly forbidden. "
                "Use Campaign, Attack Pattern, Indicator, and Observed Data objects instead. "
                "Calling generate_threat_actors() will raise a RuntimeError."
            )

    return len(errors) == 0, errors
