"""Semantic cross-revision delta analyzers.

Each analyzer compares two analysis snapshots (previous and current) and
produces DeltaEntry objects with confidence scores, evidence, and severity.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

from raven.delta.base import DeltaEntry, DeltaCategory, ChangeType, RevisionDelta


def compare_architecture(
    prev_arch: dict[str, Any] | None,
    curr_arch: dict[str, Any] | None,
) -> list[DeltaEntry]:
    """Compare module graphs between two revisions.

    Detects: added modules, removed modules, changed module sizes,
    new/removed circular imports, new/removed god modules.
    """
    if not prev_arch or not curr_arch:
        return []
    entries: list[DeltaEntry] = []

    prev_modules = {m["name"]: m for m in prev_arch.get("modules", [])}
    curr_modules = {m["name"]: m for m in curr_arch.get("modules", [])}

    for name, curr_m in curr_modules.items():
        if name not in prev_modules:
            entries.append(DeltaEntry(
                category=DeltaCategory.ARCHITECTURE,
                change_type=ChangeType.ADDED,
                entity=name,
                description=f"New module: {name} ({curr_m.get('lines', 0)} lines)",
                confidence=0.95,
            ))
        else:
            prev_m = prev_modules[name]
            prev_lines = prev_m.get("lines", 0)
            curr_lines = curr_m.get("lines", 0)
            if abs(curr_lines - prev_lines) > max(prev_lines * 0.3, 100):
                entries.append(DeltaEntry(
                    category=DeltaCategory.ARCHITECTURE,
                    change_type=ChangeType.MODIFIED,
                    entity=name,
                    description=f"Module size changed: {name} ({prev_lines} -> {curr_lines} lines)",
                    confidence=0.85,
                    before=prev_lines,
                    after=curr_lines,
                ))

    for name in prev_modules:
        if name not in curr_modules:
            entries.append(DeltaEntry(
                category=DeltaCategory.ARCHITECTURE,
                change_type=ChangeType.REMOVED,
                entity=name,
                description=f"Removed module: {name}",
                confidence=0.90,
            ))

    prev_findings = {f["title"]: f for f in prev_arch.get("findings", [])}
    curr_findings = {f["title"]: f for f in curr_arch.get("findings", [])}
    for title in curr_findings:
        if title not in prev_findings:
            entries.append(DeltaEntry(
                category=DeltaCategory.ARCHITECTURE,
                change_type=ChangeType.ADDED,
                entity=title,
                description=f"New architecture finding: {title}",
                confidence=0.80,
                severity=curr_findings[title].get("severity", "info"),
            ))
    for title in prev_findings:
        if title not in curr_findings:
            entries.append(DeltaEntry(
                category=DeltaCategory.ARCHITECTURE,
                change_type=ChangeType.REMOVED,
                entity=title,
                description=f"Resolved architecture finding: {title}",
                confidence=0.80,
            ))

    return entries


def compare_security(
    prev_sec: dict[str, Any] | None,
    curr_sec: dict[str, Any] | None,
) -> list[DeltaEntry]:
    """Compare security posture between two revisions.

    Detects: new findings, resolved findings, severity shifts,
    changes in finding counts per severity level.
    """
    if not prev_sec or not curr_sec:
        return []
    entries: list[DeltaEntry] = []

    prev_findings = {f"{f['title']}:{f['affected_file']}": f for f in prev_sec.get("findings", [])}
    curr_findings = {f"{f['title']}:{f['affected_file']}": f for f in curr_sec.get("findings", [])}

    for key, f in curr_findings.items():
        if key not in prev_findings:
            cwe_id = f.get("cwe", {}).get("cwe_id", "")
            entries.append(DeltaEntry(
                category=DeltaCategory.SECURITY,
                change_type=ChangeType.ADDED,
                entity=f["title"],
                description=f"New security finding: {f['title']} ({cwe_id})",
                confidence=0.85,
                severity=f.get("severity", "info"),
                affected_files=[f.get("affected_file", "")],
            ))

    for key, f in prev_findings.items():
        if key not in curr_findings:
            entries.append(DeltaEntry(
                category=DeltaCategory.SECURITY,
                change_type=ChangeType.REMOVED,
                entity=f["title"],
                description=f"Resolved security finding: {f['title']}",
                confidence=0.80,
            ))

    prev_counts = {sev: prev_sec.get(f"{sev}_count", 0) for sev in ("critical", "high", "medium", "low", "info")}
    curr_counts = {sev: curr_sec.get(f"{sev}_count", 0) for sev in ("critical", "high", "medium", "low", "info")}
    for sev in ("critical", "high"):
        if curr_counts[sev] > prev_counts[sev]:
            entries.append(DeltaEntry(
                category=DeltaCategory.SECURITY,
                change_type=ChangeType.MODIFIED,
                entity=f"{sev}_count",
                description=f"{sev.title()} findings increased: {prev_counts[sev]} -> {curr_counts[sev]}",
                confidence=0.90,
                severity=sev,
                before=prev_counts[sev],
                after=curr_counts[sev],
            ))

    return entries


def compare_dependencies(
    prev_profile: dict[str, Any] | None,
    curr_profile: dict[str, Any] | None,
) -> list[DeltaEntry]:
    """Compare dependency lists between two revisions.

    Detects: new dependencies, removed dependencies, version changes.
    """
    if not prev_profile or not curr_profile:
        return []
    entries: list[DeltaEntry] = []

    prev_deps = {d["name"]: d for d in prev_profile.get("dependencies", [])}
    curr_deps = {d["name"]: d for d in curr_profile.get("dependencies", [])}

    for name, curr in curr_deps.items():
        if name not in prev_deps:
            entries.append(DeltaEntry(
                category=DeltaCategory.DEPENDENCIES,
                change_type=ChangeType.ADDED,
                entity=name,
                description=f"New dependency: {name}@{curr.get('version', '?')}",
                confidence=0.95,
            ))
        else:
            prev = prev_deps[name]
            if prev.get("version") != curr.get("version") and curr.get("version") != "unknown":
                entries.append(DeltaEntry(
                    category=DeltaCategory.DEPENDENCIES,
                    change_type=ChangeType.MODIFIED,
                    entity=name,
                    description=f"Dependency version change: {name} ({prev.get('version')} -> {curr.get('version')})",
                    confidence=0.90,
                    before=prev.get("version"),
                    after=curr.get("version"),
                ))

    for name in prev_deps:
        if name not in curr_deps:
            entries.append(DeltaEntry(
                category=DeltaCategory.DEPENDENCIES,
                change_type=ChangeType.REMOVED,
                entity=name,
                description=f"Removed dependency: {name}",
                confidence=0.85,
            ))

    return entries


def compare_routes(
    prev_routes: list[str] | None,
    curr_routes: list[str] | None,
) -> list[DeltaEntry]:
    """Compare API route definitions between two revisions."""
    if prev_routes is None or curr_routes is None:
        return []
    entries: list[DeltaEntry] = []

    prev_set = set(prev_routes)
    curr_set = set(curr_routes)

    for route in curr_set - prev_set:
        entries.append(DeltaEntry(
            category=DeltaCategory.ROUTES,
            change_type=ChangeType.ADDED,
            entity=route,
            description=f"New API route: {route}",
            confidence=0.90,
        ))
    for route in prev_set - curr_set:
        entries.append(DeltaEntry(
            category=DeltaCategory.ROUTES,
            change_type=ChangeType.REMOVED,
            entity=route,
            description=f"Removed API route: {route}",
            confidence=0.90,
        ))

    return entries


def compare_symbols(
    prev_arch: dict[str, Any] | None,
    curr_arch: dict[str, Any] | None,
) -> list[DeltaEntry]:
    """Compare module-level symbol counts (functions, classes) between revisions."""
    if not prev_arch or not curr_arch:
        return []
    entries: list[DeltaEntry] = []

    prev_mods = {m["name"]: m for m in prev_arch.get("modules", [])}
    curr_mods = {m["name"]: m for m in curr_arch.get("modules", [])}

    for name, curr_m in curr_mods.items():
        if name not in prev_mods:
            continue
        prev_m = prev_mods[name]
        for attr in ("functions", "classes", "lines"):
            prev_val = prev_m.get(attr, 0)
            curr_val = curr_m.get(attr, 0)
            if abs(curr_val - prev_val) >= max(prev_val * 0.5, 5):
                entries.append(DeltaEntry(
                    category=DeltaCategory.SYMBOLS,
                    change_type=ChangeType.MODIFIED,
                    entity=f"{name}:{attr}",
                    description=f"{name} {attr}: {prev_val} -> {curr_val}",
                    confidence=0.80,
                    before=prev_val,
                    after=curr_val,
                ))

    return entries


def compare_imports(
    prev_arch: dict[str, Any] | None,
    curr_arch: dict[str, Any] | None,
) -> list[DeltaEntry]:
    """Compare import relationships between revisions.

    Detects modules with significantly changed import counts or new/removed
    import relationships.
    """
    if not prev_arch or not curr_arch:
        return []
    entries: list[DeltaEntry] = []

    prev_mods = {m["name"]: m for m in prev_arch.get("modules", [])}
    curr_mods = {m["name"]: m for m in curr_arch.get("modules", [])}

    for name, curr_m in curr_mods.items():
        prev_m = prev_mods.get(name)
        if prev_m is None:
            continue
        prev_imports = set(prev_m.get("imports", []))
        curr_imports = set(curr_m.get("imports", []))
        new_imports = curr_imports - prev_imports
        for imp in new_imports:
            entries.append(DeltaEntry(
                category=DeltaCategory.IMPORTS,
                change_type=ChangeType.ADDED,
                entity=f"{name} -> {imp}",
                description=f"New import: {name} now imports {imp}",
                confidence=0.75,
            ))

    return entries


def compare_evolution(
    prev_score: dict[str, Any] | None,
    curr_score: dict[str, Any] | None,
) -> list[DeltaEntry]:
    """Compute historical trend analysis between two scoring snapshots."""
    if not prev_score or not curr_score:
        return []
    entries: list[DeltaEntry] = []

    prev_overall = prev_score.get("overall", 0)
    curr_overall = curr_score.get("overall", 0)
    delta = curr_overall - prev_overall

    if abs(delta) >= 5:
        direction = "improved" if delta > 0 else "declined"
        entries.append(DeltaEntry(
            category=DeltaCategory.EVOLUTION,
            change_type=ChangeType.MODIFIED,
            entity="overall_score",
            description=f"Overall score {direction} by {abs(delta):.1f} points ({prev_overall:.1f} -> {curr_overall:.1f})",
            confidence=0.95,
            before=prev_overall,
            after=curr_overall,
        ))

    prev_cats = {c["category"]: c["score"] for c in prev_score.get("categories", [])}
    curr_cats = {c["category"]: c["score"] for c in curr_score.get("categories", [])}

    for cat_name, curr_cat_score in curr_cats.items():
        prev_cat_score = prev_cats.get(cat_name, 0)
        cat_delta = curr_cat_score - prev_cat_score
        if abs(cat_delta) >= 10:
            direction = "improved" if cat_delta > 0 else "declined"
            entries.append(DeltaEntry(
                category=DeltaCategory.EVOLUTION,
                change_type=ChangeType.MODIFIED,
                entity=f"category:{cat_name}",
                description=f"{cat_name} score {direction} by {abs(cat_delta):.1f} points ({prev_cat_score:.1f} -> {curr_cat_score:.1f})",
                confidence=0.85,
                before=prev_cat_score,
                after=curr_cat_score,
            ))

    return entries


def build_delta(
    prev_profile: dict[str, Any] | None = None,
    prev_arch: dict[str, Any] | None = None,
    prev_sec: dict[str, Any] | None = None,
    prev_score: dict[str, Any] | None = None,
    curr_profile: dict[str, Any] | None = None,
    curr_arch: dict[str, Any] | None = None,
    curr_sec: dict[str, Any] | None = None,
    curr_score: dict[str, Any] | None = None,
    base_ref: str = "previous",
    head_ref: str = "current",
) -> RevisionDelta:
    """Build a complete RevisionDelta from two sets of analysis artifacts.

    Args:
        prev_*: Analysis artifacts from the base (previous) revision.
        curr_*: Analysis artifacts from the head (current) revision.
        base_ref: Human-readable label for the base revision.
        head_ref: Human-readable label for the head revision.
    """
    now = datetime.now(timezone.utc).isoformat()
    entries: list[DeltaEntry] = []

    entries.extend(compare_architecture(prev_arch, curr_arch))
    entries.extend(compare_security(prev_sec, curr_sec))
    entries.extend(compare_dependencies(prev_profile, curr_profile))
    entries.extend(compare_symbols(prev_arch, curr_arch))
    entries.extend(compare_imports(prev_arch, curr_arch))
    entries.extend(compare_evolution(prev_score, curr_score))

    if curr_profile:
        curr_routes = curr_profile.get("api_routes", [])
        prev_routes = prev_profile.get("api_routes", []) if prev_profile else []
        entries.extend(compare_routes(prev_routes, curr_routes))

    total = len(entries)
    high_conf = sum(1 for e in entries if e.confidence >= 0.8)
    summary = f"{total} changes detected ({high_conf} high-confidence) between {base_ref} and {head_ref}"

    return RevisionDelta(
        base_revision=base_ref,
        head_revision=head_ref,
        scanned_at=now,
        entries=sorted(entries, key=lambda e: e.confidence, reverse=True),
        summary=summary,
    )
