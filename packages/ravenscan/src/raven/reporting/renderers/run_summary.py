"""Run summary renderer — the fixed R-01 reflection template.

A single deterministic template guarantees a stable format across runs
(consistency: fixed summary template). Input is the structured summary dict
stored by ``MemoryStore.build_run_summary`` — no free text, no repository
content, nothing that could carry injected instructions.
"""

from __future__ import annotations

from typing import Any


def render_run_summary(summary: dict[str, Any]) -> str:
    """Render the run summary dict as Markdown (fixed layout)."""
    score = summary.get("score") or {}
    findings = summary.get("findings") or {}
    mem = summary.get("memory") or {}
    revs = summary.get("revisions") or {}
    cur = revs.get("current") or {}
    prev = revs.get("previous")
    versions = summary.get("versions") or {}

    lines = [
        "# Raven Run Summary",
        "",
        f"**Scan:** #{summary.get('scan_id')} at {summary.get('created_at')}",
        f"**Scope:** {summary.get('scope')}",
        f"**Commit:** {cur.get('commit') or 'unknown'} ({cur.get('branch') or 'no branch'})",
        "",
    ]
    if summary.get("first_run") or prev is None:
        lines += ["**Since last run:** first run in this scope — no prior baseline.", ""]
    else:
        lines += [
            f"**Since last run:** previous scan #{prev.get('scan_id')} at {prev.get('scanned_at')}",
            "",
        ]

    delta = score.get("delta")
    delta_txt = "n/a" if delta is None else f"{float(delta):+.1f}"
    prev_score = score.get("previous")
    prev_txt = "n/a" if prev_score is None else str(prev_score)
    lines += [
        "## Score",
        f"**{score.get('current')}/100** (previous: {prev_txt}, delta: {delta_txt})",
        "",
        "## Findings since last run",
        f"- New: {findings.get('new', 0)}",
        f"- Existing: {findings.get('existing', 0)}",
        f"- Reintroduced: {findings.get('reintroduced', 0)}",
        f"- Resolved: {findings.get('resolved', 0)}",
        f"- Total: {findings.get('total', 0)} "
        f"(critical {findings.get('critical', 0)}, high {findings.get('high', 0)})",
        "",
        "## Recurring debt",
    ]
    debt = summary.get("recurring_debt") or []
    if debt:
        for item in debt:
            lines.append(
                f"- {item.get('finding_id')} — reintroduced "
                f"{item.get('reintroduction_count', 0)}x (severity {item.get('severity')})"
            )
    else:
        lines.append("- none")
    lines += [
        "",
        "## Memory (verified records only)",
        f"- False positives: {mem.get('false_positives', 0)}",
        f"- Detector outcomes: {mem.get('detector_outcomes', 0)}",
        "",
        "## Versions",
        f"- Ruleset: {versions.get('ruleset')}",
        f"- Templates: {versions.get('template')}",
        "",
    ]
    return "\n".join(lines) + "\n"
