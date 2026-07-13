"""Tests for scoring and daily report."""

from raven.core.models import (
    RepositoryProfile,
    RepoStructure,
    ArchitectureGraph,
    SecurityReport,
    SecurityFinding,
    Severity,
    Confidence,
    CweReference,
)
from raven.reporting.scoring import score
from raven.reporting.daily_report import generate


def test_scoring_clean_project():
    profile = RepositoryProfile(
        structure=RepoStructure(
            root="/test",
            total_files=10,
            total_lines=200,
            total_python_files=8,
            directory_count=3,
        ),
        language_primary="python",
        has_docker=True,
        has_ci=True,
        ci_provider="GitHub Actions",
    )
    arch = ArchitectureGraph()
    sec = SecurityReport(findings=[])

    risk = score(profile, arch, sec)
    assert risk.overall > 70
    assert risk.grade in ("A", "B")


def test_scoring_with_critical_findings():
    profile = RepositoryProfile(
        structure=RepoStructure(
            root="/test",
            total_files=5,
            total_lines=100,
            total_python_files=5,
            directory_count=1,
        ),
    )
    arch = ArchitectureGraph()
    sec = SecurityReport(findings=[
        SecurityFinding(
            severity=Severity.CRITICAL,
            cwe=CweReference(cwe_id="CWE-798", name="Hardcoded Credentials"),
            title="Secret in code",
            description="Found hardcoded API key.",
            evidence="config.py:1",
            affected_file="config.py",
            affected_lines=[1],
            recommendation="Use env vars.",
            confidence=Confidence.HIGH,
        ),
        SecurityFinding(
            severity=Severity.CRITICAL,
            cwe=CweReference(cwe_id="CWE-94", name="Code Injection"),
            title="eval() call",
            description="Unsafe eval.",
            evidence="app.py:42",
            affected_file="app.py",
            affected_lines=[42],
            recommendation="Remove eval.",
            confidence=Confidence.HIGH,
        ),
    ])

    risk = score(profile, arch, sec)
    assert risk.overall < 80  # should be penalized
    security_score = next(c for c in risk.categories if c.category.value == "security")
    assert security_score.score < 70


def test_scoring_grades():
    """Verify grade boundaries."""
    grades = [
        (95, "A"),
        (85, "B"),
        (75, "C"),
        (65, "D"),
        (40, "F"),
    ]
    for val, expected_grade in grades:
        risk = score(
            RepositoryProfile(
                structure=RepoStructure(
                    root="/test", total_files=1, total_lines=1, total_python_files=1, directory_count=0,
                ),
                has_docker=True,
                has_ci=True,
            ),
            ArchitectureGraph(),
            SecurityReport(findings=[]),
        )
        # We can't force exact values, but grade boundaries should be correct
        # Just verify RiskScore.grade property works
        risk.overall = val
        assert risk.grade == expected_grade, f"Expected {expected_grade} for {val}, got {risk.grade}"


def test_daily_report_generates():
    profile = RepositoryProfile(
        structure=RepoStructure(
            root="/test", total_files=3, total_lines=50, total_python_files=3, directory_count=1,
        ),
        language_primary="python",
        has_docker=True,
        has_ci=True,
        bg_workers=["Celery"],
    )
    arch = ArchitectureGraph()
    sec = SecurityReport(findings=[])

    report = generate(profile, arch, sec, "test-proj")
    assert report.project == "test-proj"
    assert report.risk_trend == "stable"
    assert len(report.immediate_actions) >= 0
    assert len(report.long_term_actions) >= 1
    assert len(report.interesting_observations) >= 1
