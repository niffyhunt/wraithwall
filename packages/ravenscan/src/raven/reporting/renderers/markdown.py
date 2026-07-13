"""Markdown renderer — renders Pydantic models to human-readable Markdown.

IMPORTANT: markdown is generated FROM the canonical JSON model, never
hand-assembled independently.  This guarantees the two outputs never drift.
"""

from __future__ import annotations

from typing import Any

from raven.core.models import (
    RepositoryProfile,
    ArchitectureGraph,
    SecurityReport,
    DailyReport,
    RiskScore,
    Severity,
)


def render_markdown(data: Any) -> str:
    """Dispatch to the correct renderer based on model type."""
    if isinstance(data, RepositoryProfile):
        return _render_profile(data)
    if isinstance(data, ArchitectureGraph):
        return _render_architecture(data)
    if isinstance(data, SecurityReport):
        return _render_security(data)
    if isinstance(data, DailyReport):
        return _render_daily(data)
    if isinstance(data, RiskScore):
        return _render_score(data)
    return f"```json\n{data.model_dump_json(indent=2) if hasattr(data, 'model_dump_json') else str(data)}\n```"


def _severity_emoji(sev: Severity) -> str:
    mapping = {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🟢",
        Severity.INFO: "🔵",
    }
    return mapping.get(sev, "⚪")


def _render_profile(p: RepositoryProfile) -> str:
    s = p.structure
    lines = [
        "# Repository Profile",
        "",
        f"**Scanned:** {p.scanned_at}",
        f"**Schema version:** {p.schema_version}",
        "",
        "## Structure",
        f"- Primary language: **{p.language_primary}**",
        f"- Languages: {', '.join(p.languages) or 'unknown'}",
        f"- Total files: {s.total_files if s else 'N/A'}",
        f"- Total lines: {s.total_lines if s else 'N/A'}",
        f"- Python files: {s.total_python_files if s else 'N/A'}",
        f"- Directories: {s.directory_count if s else 'N/A'}",
    ]
    if p.frameworks:
        lines.append(f"- Frameworks: {', '.join(f.name for f in p.frameworks)}")
    lines.extend([
        f"- Package manager: {p.package_manager}",
        "",
        "## Infrastructure",
        f"- Docker: {'Yes' if p.has_docker else 'No'}",
        f"- CI/CD: {'Yes' if p.has_ci else 'No'}{' (' + p.ci_provider + ')' if p.has_ci and p.ci_provider != 'unknown' else ''}",
        f"- Database: {p.database}",
    ])
    if p.bg_workers:
        lines.append(f"- Background workers: {', '.join(p.bg_workers)}")
    if p.dependencies:
        lines.append("")
        lines.append("## Dependencies")
        lines.append(f"Total: {len(p.dependencies)}")
        lines.append("")
        lines.append("| Package | Version | Source |")
        lines.append("|---------|---------|--------|")
        for d in p.dependencies[:50]:
            lines.append(f"| {d.name} | {d.version} | {d.source} |")
        if len(p.dependencies) > 50:
            lines.append(f"| ... | ({len(p.dependencies) - 50} more) | |")
    if p.api_routes:
        lines.append("")
        lines.append("## API Routes")
        for r in p.api_routes[:30]:
            lines.append(f"- `{r}`")
        if len(p.api_routes) > 30:
            lines.append(f"- ... ({len(p.api_routes) - 30} more)")
    return "\n".join(lines)


def _render_architecture(a: ArchitectureGraph) -> str:
    lines = [
        "# Architecture Graph",
        "",
        f"**Scanned:** {a.scanned_at}",
        f"**Schema version:** {a.schema_version}",
        f"**Modules:** {len(a.modules)}",
        f"**Findings:** {len(a.findings)}",
    ]
    if a.findings:
        lines.append("")
        lines.append("## Findings")
        for f in a.findings:
            lines.append(f"\n### {_severity_emoji(f.severity)} {f.title}")
            lines.append(f"**Category:** {f.category} | **Confidence:** {f.confidence}")
            lines.append(f"\n{f.description}")
            lines.append(f"\n**Evidence:** {f.evidence}")
            if f.affected_files:
                lines.append(f"\n**Files:** {', '.join(f.affected_files)}")
            if f.recommendation:
                lines.append(f"\n**Recommendation:** {f.recommendation}")
    if a.modules:
        lines.append("")
        lines.append("## Module List")
        lines.append("| Module | Lines | Classes | Functions | Imports | Imported By |")
        lines.append("|--------|-------|---------|-----------|---------|-------------|")
        for m in sorted(a.modules, key=lambda m: m.lines, reverse=True)[:30]:
            lines.append(f"| {m.name} | {m.lines} | {m.classes} | {m.functions} | {len(m.imports)} | {len(m.imported_by)} |")
        if len(a.modules) > 30:
            lines.append(f"| ... | | | | ({len(a.modules) - 30} more) | |")
    return "\n".join(lines)


def _render_security(s: SecurityReport) -> str:
    lines = [
        "# Security Report",
        "",
        f"**Scanned:** {s.scanned_at}",
        f"**Schema version:** {s.schema_version}",
        f"**Total findings:** {s.total_findings}",
        f"- 🔴 Critical: {s.critical_count}",
        f"- 🟠 High: {s.high_count}",
        f"- 🟡 Medium: {s.medium_count}",
        f"- 🟢 Low: {s.low_count}",
        f"- 🔵 Info: {s.info_count}",
    ]
    if s.findings:
        lines.append("")
        lines.append("## Findings by Severity")
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            sev_findings = [f for f in s.findings if f.severity == sev]
            if not sev_findings:
                continue
            lines.append(f"\n### {_severity_emoji(sev)} {sev.value.upper()}")
            for f in sev_findings:
                lines.append(f"\n#### {f.title}")
                lines.append(f"**CWE:** {f.cwe.cwe_id} — {f.cwe.name}")
                lines.append(f"**Confidence:** {f.confidence}")
                lines.append(f"\n{f.description}")
                lines.append(f"\n**Evidence:** {f.evidence}")
                lines.append(f"**File:** `{f.affected_file}`")
                if f.affected_lines:
                    lines.append(f"**Lines:** {f.affected_lines}")
                if f.exploitation_scenario:
                    lines.append(f"\n**Exploitation Scenario:** {f.exploitation_scenario}")
                if f.recommendation:
                    lines.append(f"\n**Recommendation:** {f.recommendation}")
    return "\n".join(lines)


def _render_daily(d: DailyReport) -> str:
    lines = [
        "# Daily Engineering Forensics",
        "",
        f"**Project:** {d.project}",
        f"**Generated:** {d.generated_at}",
        f"**Schema version:** {d.schema_version}",
        "",
        "## Summary",
        d.summary,
    ]
    if d.changes:
        lines.append("\n## What Changed")
        for c in d.changes:
            lines.append(f"\n### {c.category}")
            lines.append(c.description)
            lines.append(f"\n**Impact:** {c.impact}")
            if c.affected_files:
                lines.append(f"**Files:** {', '.join(c.affected_files)}")
    lines.append(f"\n## Risk Trend: {d.risk_trend}")
    if d.security_impact:
        lines.append(f"\n## Security Impact\n{d.security_impact}")
    if d.architecture_impact:
        lines.append(f"\n## Architecture Impact\n{d.architecture_impact}")
    if d.operational_impact:
        lines.append(f"\n## Operational Impact\n{d.operational_impact}")
    if d.immediate_actions:
        lines.append("\n## Immediate Actions")
        for a in d.immediate_actions:
            lines.append(f"- {_severity_emoji(a.priority)} {a.description}")
    if d.long_term_actions:
        lines.append("\n## Long-Term Actions")
        for a in d.long_term_actions:
            lines.append(f"- {a.description}")
    if d.interesting_observations:
        lines.append("\n## Interesting Observations")
        for o in d.interesting_observations:
            lines.append(f"- {o}")
    return "\n".join(lines)


def _render_score(s: RiskScore) -> str:
    lines = [
        "# Risk Score",
        "",
        f"**Scored:** {s.scored_at}",
        f"**Schema version:** {s.schema_version}",
        f"**Overall Score:** {s.overall:.1f}/100 — **Grade: {s.grade}**",
        "",
        "## Category Scores",
        "| Category | Score | Trend |",
        "|----------|-------|-------|",
    ]
    for c in s.categories:
        trend = f"{c.trend_vs_previous:+.1f}" if c.trend_vs_previous is not None else "N/A"
        lines.append(f"| {c.category.value} | {c.score:.1f} | {trend} |")
    lines.append("")
    for c in s.categories:
        lines.append(f"### {c.category.value.replace('_', ' ').title()}")
        if c.why:
            lines.append(f"\n{c.why}")
        if c.evidence:
            lines.append("\n**Evidence:**")
            for e in c.evidence:
                lines.append(f"- {e}")
        if c.recommendations:
            lines.append("\n**Recommendations:**")
            for r in c.recommendations:
                lines.append(f"- {r}")
        lines.append("")
    return "\n".join(lines)
