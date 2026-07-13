"""Tests for Markdown rendering."""

from raven.core.models import (
    RepositoryProfile,
    RepoStructure,
    SecurityReport,
    SecurityFinding,
    Severity,
    Confidence,
    CweReference,
    ArchitectureGraph,
    RiskScore,
    CategoryScore,
    ScoreCategory,
    DailyReport,
)
from raven.reporting.renderers.markdown import render_markdown


def test_render_profile():
    profile = RepositoryProfile(
        structure=RepoStructure(
            root="/test", total_files=3, total_lines=100, total_python_files=3, directory_count=2,
        ),
        language_primary="python",
        languages=["python"],
        dependencies=[],
    )
    md = render_markdown(profile)
    assert "# Repository Profile" in md
    assert "python" in md


def test_render_security():
    report = SecurityReport(findings=[
        SecurityFinding(
            severity=Severity.CRITICAL,
            cwe=CweReference(cwe_id="CWE-798", name="Hardcoded Credentials"),
            title="API key hardcoded",
            description="A secret was found.",
            evidence="config.py:10",
            affected_file="config.py",
            affected_lines=[10],
            recommendation="Use env vars.",
            confidence=Confidence.HIGH,
        ),
    ])
    md = render_markdown(report)
    assert "# Security Report" in md
    assert "CWE-798" in md
    assert "CRITICAL" in md


def test_render_architecture():
    arch = ArchitectureGraph()
    md = render_markdown(arch)
    assert "# Architecture Graph" in md


def test_render_score():
    score = RiskScore(
        overall=82.5,
        categories=[
            CategoryScore(
                category=ScoreCategory.SECURITY,
                score=90.0,
                why="Good posture.",
                evidence=["No critical findings."],
            ),
        ],
    )
    md = render_markdown(score)
    assert "# Risk Score" in md
    assert "82.5" in md
    assert "B" in md


def test_render_daily():
    report = DailyReport(
        project="test",
        summary="All good.",
        risk_trend="stable",
    )
    md = render_markdown(report)
    assert "# Daily Engineering Forensics" in md
    assert "stable" in md
