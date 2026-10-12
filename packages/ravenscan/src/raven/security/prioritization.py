"""Deterministic, evidence-preserving finding prioritization."""

from __future__ import annotations

from raven.core.models import SecurityFinding, Severity


def prioritize_finding(finding: SecurityFinding) -> tuple[str, float, list[str]]:
    """Return a priority label, score, and explainable reasons.

    This function never changes severity or evidence. Unknown exposure remains
    unknown rather than receiving an assumed public-facing boost.
    """
    score = {
        Severity.CRITICAL: 100.0,
        Severity.HIGH: 75.0,
        Severity.MEDIUM: 50.0,
        Severity.LOW: 25.0,
        Severity.INFO: 10.0,
    }.get(finding.severity, 10.0)
    reasons = [f"severity={finding.severity.value}"]
    if finding.confidence.value == "high":
        score += 8
        reasons.append("high detector confidence")
    if finding.exposure == "public":
        score += 10
        reasons.append("evidence indicates public exposure")
    if finding.recurrence_count:
        score += min(12.0, finding.recurrence_count * 3.0)
        reasons.append(f"recurring finding ({finding.recurrence_count})")
    if finding.reintroduction_count:
        score += min(15.0, finding.reintroduction_count * 5.0)
        reasons.append(f"reintroduced ({finding.reintroduction_count})")
    if finding.feedback_outcome == "confirmed":
        score += 5.0
        reasons.append("operator confirmed detector outcome")
    elif finding.feedback_outcome == "false_positive":
        # Feedback informs triage but never suppresses the finding.
        score = max(0.0, score - 5.0)
        reasons.append("operator marked false positive (advisory only)")
    elif finding.feedback_outcome == "accepted_risk" or finding.accepted_risk:
        score = max(0.0, score - 8.0)
        reasons.append("accepted risk (policy remains visible)")
    score = min(100.0, score)
    label = "critical" if score >= 90 else "high" if score >= 70 else "medium" if score >= 45 else "low"
    return label, score, reasons
