"""Phase 7 — Daily Engineering Forensics Report."""

from __future__ import annotations

from raven.core.models import (
    DailyReport,
    ChangeSummary,
    ActionItem,
    RepositoryProfile,
    ArchitectureGraph,
    SecurityReport,
    Severity,
)


def generate(
    profile: RepositoryProfile,
    architecture: ArchitectureGraph,
    security: SecurityReport,
    project_name: str = "",
) -> DailyReport:
    """Generate a daily forensics report synthesizing all phase outputs.

    Produces a concise summary of what changed, why it matters, risk trend,
    immediate actions, and long-term recommendations.
    """
    changes: list[ChangeSummary] = []
    actions: list[ActionItem] = []

    if architecture.findings:
        changes.append(
            ChangeSummary(
                category="Architecture",
                description=f"{len(architecture.findings)} architecture findings detected.",
                impact=_summarize_arch_impact(architecture),
                affected_files=list({f for af in architecture.findings for f in af.affected_files})[:10],
            )
        )

    if security.findings:
        changes.append(
            ChangeSummary(
                category="Security",
                description=f"{security.total_findings} security findings ({security.critical_count} critical, {security.high_count} high).",
                impact=_summarize_security_impact(security),
                affected_files=list({sf.affected_file for sf in security.findings})[:10],
            )
        )

    for sf in security.findings:
        if sf.severity in (Severity.CRITICAL, Severity.HIGH):
            actions.append(
                ActionItem(
                    priority=sf.severity,
                    description=f"{sf.cwe.cwe_id}: {sf.title} in {sf.affected_file}",
                    timeframe="immediate",
                )
            )

    for af in architecture.findings:
        if af.severity in (Severity.CRITICAL, Severity.HIGH):
            actions.append(
                ActionItem(
                    priority=af.severity,
                    description=f"Architecture: {af.title}",
                    timeframe="immediate" if af.severity == Severity.CRITICAL else "short-term",
                )
            )

    if security.critical_count > 0:
        risk_trend = "elevated"
    elif security.high_count > 3 or len(architecture.findings) > 5:
        risk_trend = "increasing"
    else:
        risk_trend = "stable"

    summary = (
        f"{profile.language_primary} project — "
        f"{security.total_findings} security findings, "
        f"{len(architecture.findings)} architecture findings. "
    )
    if security.critical_count > 0:
        summary += f"**{security.critical_count} critical issues require immediate attention.**"
    elif security.high_count > 0:
        summary += f"{security.high_count} high-severity issues should be addressed soon."
    else:
        summary += "No critical or high-severity issues found."

    return DailyReport(
        project=project_name or (profile.structure.root if profile.structure else ""),
        summary=summary,
        changes=changes,
        security_impact=_summarize_security_impact(security),
        architecture_impact=_summarize_arch_impact(architecture),
        operational_impact="No operational data available (Phase 6 deferred to v0.2).",
        risk_trend=risk_trend,
        immediate_actions=actions[:10],
        long_term_actions=[
            ActionItem(
                priority=Severity.LOW,
                description="Run raven regularly to track trends over time.",
                timeframe="long-term",
            ),
            ActionItem(
                priority=Severity.LOW,
                description="Address medium/low-severity findings to improve overall score.",
                timeframe="long-term",
            ),
        ],
        interesting_observations=[
            f"Primary language: {profile.language_primary}",
            f"Dependencies: {len(profile.dependencies)} packages",
            f"Docker: {'Yes' if profile.has_docker else 'No'} | CI: {'Yes' if profile.has_ci else 'No'}",
            f"Background workers: {', '.join(profile.bg_workers) if profile.bg_workers else 'none'}",
        ],
    )


def _summarize_arch_impact(arch: ArchitectureGraph) -> str:
    if not arch.findings:
        return "No significant architecture concerns."
    parts: list[str] = []
    if circ := arch.circular_imports:
        parts.append(f"{len(circ)} circular import{'s' if len(circ) > 1 else ''}")
    if gm := arch.god_modules:
        parts.append(f"{len(gm)} god module{'s' if len(gm) > 1 else ''}")
    if dc := arch.dead_code:
        parts.append(f"{len(dc)} potentially dead module{'s' if len(dc) > 1 else ''}")
    return "; ".join(parts) if parts else "Minor architecture issues."


def _summarize_security_impact(sec: SecurityReport) -> str:
    if not sec.findings:
        return "No security findings."
    parts: list[str] = []
    if sec.critical_count:
        parts.append(f"{sec.critical_count} critical")
    if sec.high_count:
        parts.append(f"{sec.high_count} high")
    if sec.medium_count:
        parts.append(f"{sec.medium_count} medium")
    if sec.low_count:
        parts.append(f"{sec.low_count} low")
    return f"{sec.total_findings} total findings ({', '.join(parts)})."
