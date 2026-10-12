"""R-04 run-comparison renderer — what changed since the last run.

Renders the deterministic comparison dict from ``MemoryStore.compare_scans``
to Markdown. Content is structured record data only (finding IDs, severities,
CWE refs, stored file paths) — never free text from repository content.
"""
from __future__ import annotations

from typing import Any


def render_changes(comparison: dict[str, Any]) -> str:
    """Render a run_comparison/1 dict to Markdown."""
    base = comparison["base"]
    head = comparison["head"]
    score = comparison["score"]
    lines = [
        "# Raven Changes",
        "",
        f"**Base:** scan #{base['scan_id']} at {base['scanned_at']}",
        f"**Head:** scan #{head['scan_id']} at {head['scanned_at']}",
        "",
        "## Score",
        "",
    ]
    if score["delta"] is None:
        lines.append(f"Current: {score['current']} — no comparable previous score")
    else:
        direction = "improved" if score["delta"] > 0 else "regressed" if score["delta"] < 0 else "unchanged"
        lines.append(
            f"Current: {score['current']} — previous: {score['previous']} — "
            f"delta: {score['delta']:+.2f} ({direction})"
        )

    def _rows(entries: list[dict[str, Any]]) -> list[str]:
        out = ["", f"Count: {len(entries)}", ""]
        for entry in entries:
            out.append(
                f"- `{entry['finding_id'][:16]}` {entry['severity'].upper()} "
                f"{entry['cwe_id']} — {entry['file']}"
            )
        return out

    lines += ["", "## New findings"]
    lines += _rows(comparison["new"])

    lines += ["", "## Resolved findings"]
    lines += _rows(comparison["resolved"])

    lines += ["", "## Recurring findings"]
    lines += _rows(comparison["recurring"])

    lines += ["", "## Severity changes", "", f"Count: {len(comparison['severity_changed'])}", ""]
    for change in comparison["severity_changed"]:
        lines.append(
            f"- `{change['finding_id'][:16]}` {change['from'].upper()} → {change['to'].upper()}"
        )

    lines.append("")
    return "\n".join(lines)
