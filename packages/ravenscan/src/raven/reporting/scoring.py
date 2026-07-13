"""Phase 9 — Intelligence Scoring.

Computes weighted scores across categories from all phase outputs.
Operational health data from Phase 6 can optionally influence the score.
"""

from __future__ import annotations

from __future__ import annotations

from typing import TYPE_CHECKING

from raven.core.models import (
    RiskScore,
    CategoryScore,
    ScoreCategory,
    RepositoryProfile,
    ArchitectureGraph,
    SecurityReport,
    OperationalHealthModel,
    Severity,
)

if TYPE_CHECKING:
    from raven.drift.analyzer import DriftSnapshot


def score(
    profile: RepositoryProfile,
    architecture: ArchitectureGraph,
    security: SecurityReport,
    drift: "DriftSnapshot | None" = None,
    operational: OperationalHealthModel | None = None,
) -> RiskScore:
    """Compute a composite risk score from all phase outputs.

    Args:
        profile: Phase 1 repository profile.
        architecture: Phase 2 architecture graph.
        security: Phase 3 security report.
        drift: Phase 5 drift snapshot for trend analysis.
        operational: Phase 6 operational health data. When provided,
            container health, resource usage, and anomalies influence
            the operational score. When None, falls back to static
            infrastructure checks (Docker/CI presence).
    """

    arch_score = _score_architecture(architecture, profile)
    sec_score = _score_security(security)
    maint_score = _score_maintainability(profile, architecture)
    ops_score = _score_operational(profile, operational)
    doc_score = _score_documentation(profile)
    testing_score = _score_testing(profile)
    tech_debt_score = _score_technical_debt(architecture)
    doc_score = _score_documentation(profile)
    testing_score = _score_testing(profile)
    tech_debt_score = _score_technical_debt(architecture)
    dx_score = _score_developer_experience(profile, architecture, drift)

    categories = [
        arch_score,
        sec_score,
        maint_score,
        ops_score,
        doc_score,
        testing_score,
        tech_debt_score,
        dx_score,
    ]

    overall = sum(c.score for c in categories) / len(categories)

    return RiskScore(overall=round(overall, 1), categories=categories)


def _score_architecture(arch: ArchitectureGraph, profile: RepositoryProfile) -> CategoryScore:
    score = 100.0
    reasons: list[str] = []

    for f in arch.circular_imports:
        score -= 15
        reasons.append(f"Circular import: {f.title}")
    for f in arch.god_modules:
        score -= 10
        reasons.append(f"God module: {f.title}")
    for f in arch.dead_code:
        score -= 5
        reasons.append(f"Dead code: {f.title}")
    for f in arch.findings:
        if f.category == "tight_coupling":
            score -= 8
            reasons.append(f"Tight coupling: {f.title}")

    return CategoryScore(
        category=ScoreCategory.ARCHITECTURE,
        score=max(0.0, score),
        why="Architecture score based on module structure, coupling, and code organization.",
        evidence=reasons[:5] if reasons else ["No significant architecture issues detected."],
        recommendations=_arch_recommendations(arch),
    )


def _score_security(security: SecurityReport) -> CategoryScore:
    score = 100.0
    reasons: list[str] = []

    deductions = {
        Severity.CRITICAL: 20,
        Severity.HIGH: 10,
        Severity.MEDIUM: 5,
        Severity.LOW: 2,
        Severity.INFO: 1,
    }

    for f in security.findings:
        score -= deductions.get(f.severity, 1)
        if f.severity in (Severity.CRITICAL, Severity.HIGH):
            reasons.append(f"{f.cwe.cwe_id}: {f.title}")

    return CategoryScore(
        category=ScoreCategory.SECURITY,
        score=max(0.0, score),
        why="Security score based on detected vulnerabilities mapped to CWE.",
        evidence=reasons[:5] if reasons else ["No critical or high-severity security findings."],
        recommendations=[
            "Address all critical and high-severity findings immediately.",
            "Run security scans as part of CI/CD pipeline.",
        ],
    )


def _score_maintainability(profile: RepositoryProfile, arch: ArchitectureGraph) -> CategoryScore:
    score = 100.0
    reasons: list[str] = []

    total = profile.structure.total_files if profile.structure else 1
    py_files = profile.structure.total_python_files if profile.structure else 0

    if py_files > 0:
        avg_size = profile.structure.total_lines / max(py_files, 1) if profile.structure else 0
        if avg_size > 500:
            score -= 10
            reasons.append(f"High average file size: {avg_size:.0f} lines")

    if len(arch.modules) > 50:
        god_count = sum(1 for m in arch.modules if m.lines > 3000)
        if god_count > 2:
            score -= 10
            reasons.append(f"{god_count} modules exceed 3000 lines")

    return CategoryScore(
        category=ScoreCategory.MAINTAINABILITY,
        score=max(0.0, score),
        why="Maintainability based on file sizes, module organization, and code structure.",
        evidence=reasons if reasons else ["Code structure looks maintainable."],
        recommendations=[
            "Split large files into smaller, focused modules.",
            "Keep average file size under 500 lines where practical.",
        ],
    )


def _score_operational(
    profile: RepositoryProfile,
    operational: OperationalHealthModel | None = None,
) -> CategoryScore:
    score = 80.0
    reasons: list[str] = []

    if profile.has_docker:
        score += 10
    else:
        reasons.append("No Docker configuration detected.")

    if profile.has_ci:
        score += 10
    else:
        reasons.append("No CI/CD pipeline detected.")

    if operational is not None:
        if operational.overall_status == "healthy":
            score += 10
            reasons.append("Runtime operational health: healthy")
        elif operational.overall_status == "degraded":
            score -= 20
            reasons.append(f"Runtime operational health: {operational.overall_status}")
        elif operational.overall_status == "warning":
            score -= 10
            reasons.append(f"Runtime operational health: {operational.overall_status}")

        if operational.anomalies:
            score -= len(operational.anomalies) * 5
            for anomaly in operational.anomalies[:3]:
                reasons.append(f"Operational anomaly: {anomaly}")

        if operational.warnings:
            score -= len(operational.warnings) * 2
            for warning in operational.warnings[:3]:
                reasons.append(f"Operational warning: {warning}")

        if operational.cpu_percent > 75:
            score -= 5
            reasons.append(f"CPU usage: {operational.cpu_percent:.0f}%")
        if operational.memory_percent > 75:
            score -= 5
            reasons.append(f"Memory usage: {operational.memory_percent:.0f}%")
        if operational.disk_percent > 80:
            score -= 5
            reasons.append(f"Disk usage: {operational.disk_percent:.0f}%")

        recommendations = [
            f"Address {len(operational.anomalies)} operational anomalies." if operational.anomalies else "",
            f"Monitor {len(operational.warnings)} operational warnings." if operational.warnings else "",
        ]
    else:
        recommendations = [
            "Add Docker support for consistent deployments." if not profile.has_docker else "",
            "Set up CI/CD for automated testing and deployment." if not profile.has_ci else "",
            "Run 'raven scan' from the deployment environment to include runtime operational health.",
        ]

    return CategoryScore(
        category=ScoreCategory.OPERATIONAL,
        score=min(100.0, max(0.0, score)),
        why="Operational score based on infrastructure configuration and runtime health.",
        evidence=[f"Docker: {'Yes' if profile.has_docker else 'No'}", f"CI/CD: {'Yes' if profile.has_ci else 'No'}"] + reasons,
        recommendations=[r for r in recommendations if r],
    )


def _score_documentation(profile: RepositoryProfile) -> CategoryScore:
    score = 50.0

    from pathlib import Path
    root = Path(profile.structure.root) if profile.structure else Path(".")
    doc_files = list(root.glob("*.md")) + list(root.glob("docs/**/*.md"))
    doc_count = len(doc_files)

    if doc_count > 0:
        score += min(30, doc_count * 5)
    else:
        score -= 10

    has_readme = (root / "README.md").exists() or (root / "README.rst").exists()
    if has_readme:
        score += 20

    return CategoryScore(
        category=ScoreCategory.DOCUMENTATION,
        score=min(100.0, max(0.0, score)),
        why="Documentation score based on presence of README, docs directory, and documentation files.",
        evidence=[f"Documentation files found: {doc_count}"],
        recommendations=[
            "Add a README.md with project overview and setup instructions." if not has_readme else "",
            "Maintain documentation in a docs/ directory." if doc_count < 3 else "",
        ],
    )


def _score_testing(profile: RepositoryProfile) -> CategoryScore:
    score = 50.0

    from pathlib import Path
    root = Path(profile.structure.root) if profile.structure else Path(".")
    test_dirs = list(root.glob("tests")) + list(root.glob("test"))
    test_files = list(root.rglob("test_*.py")) + list(root.rglob("*_test.py"))

    has_test_dir = len(test_dirs) > 0
    test_count = len(test_files)

    if has_test_dir:
        score += 20
    if test_count > 0:
        score += min(30, test_count * 2)

    return CategoryScore(
        category=ScoreCategory.TESTING,
        score=min(100.0, max(0.0, score)),
        why="Testing score based on presence of test directory and test files.",
        evidence=[f"Test files found: {test_count}"],
        recommendations=[
            "Add a tests/ directory with unit tests." if not has_test_dir else "",
            "Increase test coverage." if test_count < 10 else "",
        ],
    )


def _score_technical_debt(arch: ArchitectureGraph) -> CategoryScore:
    score = 100.0
    reasons: list[str] = []

    for f in arch.findings:
        if f.category in ("god_module", "tight_coupling", "dead_code"):
            score -= 5
        if f.category == "circular_import":
            score -= 10

    return CategoryScore(
        category=ScoreCategory.TECHNICAL_DEBT,
        score=max(0.0, score),
        why="Technical debt score based on accumulated architecture issues.",
        evidence=reasons if reasons else ["No significant technical debt indicators."],
        recommendations=[
            "Refactor god modules into smaller, focused modules.",
            "Break circular dependencies.",
            "Remove dead code.",
        ],
    )


def _score_developer_experience(
    profile: RepositoryProfile,
    arch: ArchitectureGraph,
    drift: "DriftSnapshot | None" = None,
) -> CategoryScore:
    """Score developer experience based on tooling, structure, and workflow indicators."""
    score = 70.0
    reasons: list[str] = []

    if profile.has_ci:
        score += 10
        reasons.append("CI/CD configured")
    if profile.package_manager != "unknown":
        score += 5
    if profile.has_docker:
        score += 5
        reasons.append("Docker support")

    if drift is not None:
        if drift.comment_to_code_ratio > 0.1:
            score += 5
            reasons.append("Good documentation ratio")
        if drift.total_todos < 20:
            score += 5
        else:
            reasons.append(f"{drift.total_todos} TODO markers outstanding")
        if drift.duplicate_blocks > 5:
            score -= 10
            reasons.append(f"{drift.duplicate_blocks} duplicate code blocks detected")

    return CategoryScore(
        category=ScoreCategory.DEVELOPER_EXPERIENCE,
        score=min(100.0, max(0.0, score)),
        why="Developer experience based on CI, containerization, documentation, and code quality.",
        evidence=reasons if reasons else ["Basic DX indicators met."],
        recommendations=[
            "Set up CI/CD if not already configured." if not profile.has_ci else "",
            "Add Docker support for consistent dev environments." if not profile.has_docker else "",
            "Reduce TODO/FIXME count to improve code quality signal.",
        ],
    )


def _arch_recommendations(arch: ArchitectureGraph) -> list[str]:
    recs: list[str] = []
    if arch.circular_imports:
        recs.append("Break circular imports by extracting shared dependencies.")
    if arch.god_modules:
        recs.append("Split large modules into smaller, focused ones.")
    if arch.dead_code:
        recs.append("Remove or repurpose dead modules.")
    if not recs:
        recs.append("Maintain current architecture standards.")
    return recs
