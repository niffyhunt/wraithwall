import os
from typing import Any, Dict, List, Optional, Tuple

MIN_SIGNALS_FOR_CRITICAL = int(os.environ.get("UNISON_MIN_SIGNALS_CRITICAL", "2"))
UNISON_WEIGHTS_JSON = os.environ.get(
    "UNISON_WEIGHTS_JSON",
    '{"asn_risk":0.12,"fingerprint_threat":0.10,"campaign_threat":0.10,"mitre_threat":0.14,"reverb_amplified":0.10,"bgp_hijack":0.06,"gateway_threat":0.04,"hassh_anomaly":0.08,"vanish_anonymization":0.06,"cred_storm":0.08,"shift_velocity":0.04,"mirage_fidelity":0.04,"ioc_count":0.04,"ioc_diversity":0.04}',
)

import json

WEIGHTS: Dict[str, float] = {}

try:
    WEIGHTS = json.loads(UNISON_WEIGHTS_JSON)
except (json.JSONDecodeError, TypeError):
    WEIGHTS = {
        "asn_risk": 0.12,
        "fingerprint_threat": 0.10,
        "campaign_threat": 0.10,
        "mitre_threat": 0.14,
        "reverb_amplified": 0.10,
        "bgp_hijack": 0.06,
        "gateway_threat": 0.04,
        "hassh_anomaly": 0.08,
        "vanish_anonymization": 0.06,
        "cred_storm": 0.08,
        "shift_velocity": 0.04,
        "mirage_fidelity": 0.04,
        "ioc_count": 0.04,
        "ioc_diversity": 0.04,
    }

VERDICT_THRESHOLDS: List[Tuple[str, float]] = [
    ("CRITICAL", 0.85),
    ("HIGH", 0.65),
    ("MEDIUM", 0.40),
    ("LOW", 0.20),
    ("CLEAN", 0.0),
]

def _normalize(value: float, src_min: float, src_max: float) -> float:
    if src_max <= src_min:
        return 0.0
    clamped = max(src_min, min(value, src_max))
    return (clamped - src_min) / (src_max - src_min)

def compute_unison_score(session: Dict, intelligence: Dict) -> Dict[str, Any]:
    signals: Dict[str, float] = {}
    contributions: Dict[str, float] = {}

    asn_risk = intelligence.get("asn_risk_score", 0) or 0
    signals["asn_risk"] = _normalize(float(asn_risk), 0.0, 100.0)

    fingerprint_threat = intelligence.get("fingerprint_threat_score", 0) or 0
    signals["fingerprint_threat"] = _normalize(float(fingerprint_threat), 0.0, 1.0)

    campaign = intelligence.get("campaign_threat", {}) or {}
    campaign_labels = {"low": 0.25, "medium": 0.50, "high": 0.75, "critical": 1.0}
    signals["campaign_threat"] = campaign_labels.get(
        str(campaign.get("threat_level", "") or "").lower(), 0.0
    )

    mitre_threat = intelligence.get("threat_score", 0) or 0
    signals["mitre_threat"] = _normalize(float(mitre_threat), 0.0, 100.0)

    reverb_amplified = intelligence.get("amplified_score", 0) or 0
    signals["reverb_amplified"] = _normalize(float(reverb_amplified), 0.0, 100.0)

    bgp_hijack = 1.0 if (intelligence.get("bgp_hijack") or intelligence.get("bgp_hijack_risk")) else 0.0
    signals["bgp_hijack"] = bgp_hijack

    gateway_threat = intelligence.get("gateway_threat_score", None)
    if gateway_threat is not None:
        signals["gateway_threat"] = _normalize(float(gateway_threat), 0.0, 1.0)
    else:
        signals["gateway_threat"] = 0.0

    mirage = session.get("mirage", {}) or {}
    mirage_fidelity = float(mirage.get("fidelity_score", 0) or 0)
    mirage_norm = _normalize(mirage_fidelity, 0.0, 100.0)

    signals["mirage_fidelity"] = 1.0 - mirage_norm

    ioc_count = intelligence.get("ioc_count", 0) or 0
    ioc_norm = _normalize(float(ioc_count), 0.0, 50.0)
    signals["ioc_count"] = ioc_norm

    ioc_diversity = intelligence.get("ioc_diversity", 0) or 0
    ioc_div_norm = _normalize(float(ioc_diversity), 0.0, 10.0)
    signals["ioc_diversity"] = ioc_div_norm

    has_hassh_match = bool(intelligence.get("hassh_match"))
    signals["hassh_anomaly"] = 1.0 if has_hassh_match else 0.0

    vanish = session.get("anonymization", {}) or {}
    vanish_anon_count = sum(
        1 for k in ("is_tor", "is_vpn", "is_proxy", "is_hosting") if vanish.get(k)
    )
    signals["vanish_anonymization"] = _normalize(float(vanish_anon_count), 0.0, 4.0)

    cred_attack = session.get("credential_attack", {}) or {}
    attack_type = str(cred_attack.get("attack_type", "") or "")
    cred_labels = {"none": 0.0, "low": 0.25, "medium": 0.50, "high": 0.75, "critical": 1.0}
    signals["cred_storm"] = cred_labels.get(attack_type.lower(), 0.0)

    shift = session.get("geo_velocity", {}) or {}
    shift_flag = bool(shift.get("implausible", False))
    signals["shift_velocity"] = 1.0 if shift_flag else 0.0

    weighted_sum = 0.0
    total_weight_used = 0.0
    active_signals = 0
    for sig_name, weight in WEIGHTS.items():
        sig_value = signals.get(sig_name, 0.0)
        if sig_value > 0:
            active_signals += 1
        contribution = sig_value * weight
        contributions[sig_name] = round(contribution, 4)
        weighted_sum += contribution
        total_weight_used += weight

    if total_weight_used > 0:
        unison_score = min(int((weighted_sum / total_weight_used) * 100), 100)
    else:
        unison_score = 0

    if unison_score >= 85 and active_signals < MIN_SIGNALS_FOR_CRITICAL:
        unison_score = 80

    verdict = "CLEAN"
    for label, threshold in VERDICT_THRESHOLDS:
        norm_score = unison_score / 100.0
        if norm_score >= threshold:
            verdict = label
            break

    return {
        "unison_score": unison_score,
        "verdict": verdict,
        "contributions": contributions,
        "active_signals": active_signals,
        "signals": {k: round(v, 4) for k, v in signals.items()},
    }
