"""
CRYSTAL / UNISON recalibration loop.

Reads analyst-labeled Cowrie sessions from Redis, computes observed
precision and recall per signal and for CRYSTAL suppression decisions,
and proposes weight/threshold adjustments.

CONSTRAINT: This module READS constants from unison_score.py and
cowrie_intelligence.py but NEVER writes them. Changes are proposed
as a report; a separate approved pass applies them.
"""

from __future__ import annotations

import json
import logging
import os
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

REDIS_URL = os.environ.get("REDIS_URL", "")
VALID_LABELS = {"true_positive", "false_positive", "benign"}
MIN_LABELED = 200
MIN_SUPPRESSED_FRACTION = 0.20

def _get_redis():
    if not REDIS_URL:
        return None
    try:
        import redis as redis_lib
        return redis_lib.from_url(REDIS_URL, socket_connect_timeout=5,
                                  socket_timeout=10, decode_responses=True)
    except Exception as e:
        logger.error(f"Redis connect failed: {e}")
        return None

def load_labeled_sessions() -> Tuple[List[Dict], List[Dict]]:
    """Load all labeled sessions, split into alerted and suppressed groups.

    Returns:
        (alerted_sessions, suppressed_sessions) — each a list of session dicts
        with at minimum: session_id, label, crystal_action, intelligence signals.
    """
    r = _get_redis()
    if not r:
        return [], []

    labeled_ids = r.smembers("cowrie:labeled_sessions") or set()
    if not labeled_ids:
        logger.warning("No labeled sessions found")
        return [], []

    alerted: List[Dict] = []
    suppressed: List[Dict] = []

    for sid in labeled_ids:
        raw = r.get(f"cowrie_completed:{sid}")
        if not raw:
            continue
        try:
            session = json.loads(raw)
        except json.JSONDecodeError:
            continue

        label = session.get("label")
        if label not in VALID_LABELS:
            continue

        crystal = session.get("intelligence", {}).get("crystal", {})
        action = session.get("crystal_action", crystal.get("action", "unknown"))

        entry = {
            "session_id": sid,
            "label": label,
            "crystal_action": action,
            "src_ip": session.get("src_ip", ""),
            "commands": session.get("commands", []),
            "intelligence": session.get("intelligence", {}),
            "connected_at": session.get("connected_at", ""),
            "closed_at": session.get("closed_at", ""),
            "labeled_at": session.get("labeled_at", ""),
        }

        if action == "suppress":
            suppressed.append(entry)
        else:
            alerted.append(entry)

    return alerted, suppressed

def check_preconditions() -> Optional[str]:
    """Verify minimum labeled sample exists before running calibration.

    Returns:
        None if preconditions are met, otherwise an error string describing
        what is missing.
    """
    alerted, suppressed = load_labeled_sessions()
    total = len(alerted) + len(suppressed)

    if total < MIN_LABELED:
        return (
            f"Only {total} labeled sessions found (need ≥{MIN_LABELED}). "
            f"Label more sessions via POST /api/cowrie/label before recalibration."
        )

    suppressed_ratio = len(suppressed) / total if total > 0 else 0.0
    if suppressed_ratio < MIN_SUPPRESSED_FRACTION:
        return (
            f"Only {len(suppressed)}/{total} ({suppressed_ratio:.0%}) labeled sessions "
            f"are from CRYSTAL-suppressed sessions (need ≥{MIN_SUPPRESSED_FRACTION:.0%}). "
            f"Label a random sample of suppressed sessions via "
            f"GET /api/cowrie/suppressed to avoid systematic bias."
        )

    return None

def compute_per_signal_metrics(
    alerted: List[Dict], suppressed: List[Dict]
) -> Dict[str, Dict]:
    """Compute precision and recall per UNISON signal on the labeled set.

    A session is considered "positive" if labeled true_positive.
    A signal is considered "fired" per the CRYSTAL decision log.

    Returns:
        Dict mapping signal_name → {precision, recall, support, fired_count}.
    """
    all_sessions = alerted + suppressed
    positives = [s for s in all_sessions if s["label"] == "true_positive"]

    signal_stats: Dict[str, Dict[str, float]] = defaultdict(
        lambda: {"tp": 0, "fp": 0, "fn": 0, "fired": 0}
    )

    for session in all_sessions:
        crystal = session.get("intelligence", {}).get("crystal", {})
        signals = crystal.get("signals", {})
        if not signals:
            continue
        is_positive = session["label"] == "true_positive"

        for sig_name, sig_value in signals.items():
            if isinstance(sig_value, (int, float)) and sig_value > 0:
                signal_stats[sig_name]["fired"] += 1
                if is_positive:
                    signal_stats[sig_name]["tp"] += 1
                else:
                    signal_stats[sig_name]["fp"] += 1

    for session in positives:
        crystal = session.get("intelligence", {}).get("crystal", {})
        signals = crystal.get("signals", {})
        if not signals:
            continue
        for sig_name, sig_value in signals.items():
            if isinstance(sig_value, (int, float)) and sig_value == 0:
                signal_stats[sig_name]["fn"] += 1

    result: Dict[str, Dict] = {}
    for sig_name, stats in signal_stats.items():
        tp = stats["tp"]
        fp = stats["fp"]
        fn = stats["fn"]
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        support = tp + fn
        result[sig_name] = {
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "support": support,
            "fired_count": stats["fired"],
            "tp": tp,
            "fp": fp,
            "fn": fn,
        }

    return result

def compute_crystal_accuracy(
    alerted: List[Dict], suppressed: List[Dict]
) -> Dict[str, float]:
    """Compute how often CRYSTAL's alert/suppress decision matched the label.

    true_positive + false_positive labeled sessions should ideally all be
    alerted; benign sessions should be suppressed.
    """
    correct = 0
    total = 0
    alerted_correct = 0
    suppressed_correct = 0

    for session in alerted:
        total += 1
        label = session["label"]
        if label == "true_positive" or label == "false_positive":
            correct += 1
            alerted_correct += 1

    for session in suppressed:
        total += 1
        label = session["label"]
        if label == "benign":
            correct += 1
            suppressed_correct += 1

    return {
        "overall_accuracy": round(correct / total, 3) if total > 0 else 0.0,
        "alerted_correct": alerted_correct,
        "alerted_total": len(alerted),
        "suppressed_correct": suppressed_correct,
        "suppressed_total": len(suppressed),
        "total_labeled": total,
    }

def propose_weight_adjustments(
    per_signal: Dict[str, Dict]
) -> List[Dict]:
    """Propose per-signal weight deltas based on observed precision/recall.

    Rules (deterministic, not ML):
    - If precision < 0.5 and support ≥ 5: reduce weight by (1 - precision) * 0.5
    - If recall < 0.5 and support ≥ 5: increase weight by (1 - recall) * 0.3
    - If support < 5: leave unchanged (insufficient data)
    - If precision ≥ 0.7 and recall ≥ 0.7: no change needed

    Returns:
        List of proposed adjustments with reasoning.
    """
    proposals: List[Dict] = []

    for sig_name, metrics in sorted(per_signal.items()):
        precision = metrics["precision"]
        recall = metrics["recall"]
        support = metrics["support"]

        if support < 5:
            proposals.append({
                "signal": sig_name,
                "action": "no_change",
                "reason": f"Insufficient labeled data (support={support}, need ≥5)",
                "current_precision": precision,
                "current_recall": recall,
                "proposed_delta": 0.0,
            })
            continue

        delta = 0.0
        reasons: List[str] = []

        if precision < 0.5:
            reduction = round((1.0 - precision) * 0.5, 3)
            delta -= reduction
            reasons.append(
                f"Low precision ({precision:.2f}) → reduce weight by {reduction:.3f}"
            )

        if recall < 0.5:
            increase = round((1.0 - recall) * 0.3, 3)
            delta += increase
            reasons.append(
                f"Low recall ({recall:.2f}) → increase weight by {increase:.3f}"
            )

        if precision >= 0.7 and recall >= 0.7:
            reasons.append(
                f"Good signal (precision={precision:.2f}, recall={recall:.2f})"
            )

        action = "adjust" if abs(delta) > 0.001 else "no_change"

        proposals.append({
            "signal": sig_name,
            "action": action,
            "reason": "; ".join(reasons) if reasons else "Within acceptable range",
            "current_precision": precision,
            "current_recall": recall,
            "proposed_delta": delta,
        })

    return proposals

def propose_suppression_threshold(
    alerted: List[Dict], suppressed: List[Dict]
) -> Optional[Dict]:
    """Propose CRYSTAL suppression threshold adjustment.

    If >30% of alerted sessions are labeled benign, the suppression
    threshold is too permissive and should be lowered. If >20% of
    suppressed sessions are labeled true_positive, the threshold is
    too aggressive and should be raised.
    """
    if not alerted and not suppressed:
        return None

    alerted_benign = sum(1 for s in alerted if s["label"] == "benign")
    alerted_ratio = alerted_benign / len(alerted) if alerted else 0.0

    suppressed_tp = sum(1 for s in suppressed if s["label"] == "true_positive")
    suppressed_ratio = suppressed_tp / len(suppressed) if suppressed else 0.0

    proposal: Dict = {
        "alerted_benign_count": alerted_benign,
        "alerted_total": len(alerted),
        "alerted_benign_ratio": round(alerted_ratio, 3),
        "suppressed_tp_count": suppressed_tp,
        "suppressed_total": len(suppressed),
        "suppressed_tp_ratio": round(suppressed_ratio, 3),
        "action": "no_change",
        "reason": "Thresholds within acceptable range",
    }

    if alerted_ratio > 0.30:
        proposal["action"] = "adjust"
        proposal["reason"] = (
            f"{alerted_benign}/{len(alerted)} ({alerted_ratio:.0%}) alerted "
            f"sessions are benign → lower suppression threshold to reduce noise"
        )
        proposal["suggested_threshold_delta"] = -0.05

    if suppressed_ratio > 0.20:
        proposal["action"] = "adjust"
        proposal["reason"] = (
            f"{suppressed_tp}/{len(suppressed)} ({suppressed_ratio:.0%}) suppressed "
            f"sessions are true positives → raise suppression threshold to catch more threats"
        )
        proposal["suggested_threshold_delta"] = 0.05

    return proposal

def run_recalibration() -> Dict:
    """Run the full recalibration analysis. Returns a report dict.

    Does NOT modify any constants in unison_score.py or cowrie_intelligence.py.
    """
    error = check_preconditions()
    if error:
        return {"ok": False, "error": error, "stage": "precondition_check"}

    alerted, suppressed = load_labeled_sessions()
    total = len(alerted) + len(suppressed)

    per_signal = compute_per_signal_metrics(alerted, suppressed)
    crystal_acc = compute_crystal_accuracy(alerted, suppressed)
    weight_proposals = propose_weight_adjustments(per_signal)
    threshold_proposal = propose_suppression_threshold(alerted, suppressed)

    first_labeled = ""
    last_labeled = ""
    all_sessions = sorted(alerted + suppressed, key=lambda s: s.get("labeled_at", ""))
    if all_sessions:
        first_labeled = all_sessions[0].get("labeled_at", "")
        last_labeled = all_sessions[-1].get("labeled_at", "")

    return {
        "ok": True,
        "generated_at": datetime.utcnow().isoformat(),
        "sample_composition": {
            "total_labeled": total,
            "alerted_count": len(alerted),
            "suppressed_count": len(suppressed),
            "suppressed_ratio": round(len(suppressed) / total, 3) if total > 0 else 0.0,
            "date_range": {"first": first_labeled, "last": last_labeled},
        },
        "crystal_accuracy": crystal_acc,
        "per_signal_metrics": per_signal,
        "weight_proposals": weight_proposals,
        "suppression_threshold_proposal": threshold_proposal,
        "warning": (
            "NO CONSTANTS HAVE BEEN CHANGED. Review these proposals and "
            "apply them in a separate approved pass."
        ),
    }

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    report = run_recalibration()
    json.dump(report, sys.stdout, indent=2, default=str)
    print()
