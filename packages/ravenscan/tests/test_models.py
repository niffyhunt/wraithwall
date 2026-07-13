"""Tests for Raven core models."""

import json

from raven.core.models import (
    RepositoryProfile,
    RepoStructure,
    ArchitectureGraph,
    ModuleNode,
    ArchitectureFinding,
    SecurityReport,
    SecurityFinding,
    CweReference,
    Severity,
    Confidence,
    RiskScore,
    CategoryScore,
    ScoreCategory,
    DailyReport,
)


def test_repository_profile_serialization():
    profile = RepositoryProfile(
        structure=RepoStructure(
            root="/test",
            total_files=10,
            total_lines=500,
            total_python_files=8,
            directory_count=3,
        ),
        language_primary="python",
        languages=["python", "javascript"],
    )
    data = json.loads(profile.model_dump_json())
    assert data["schema_version"] == "1"
    assert data["structure"]["total_files"] == 10
    assert data["language_primary"] == "python"


def test_architecture_graph():
    arch = ArchitectureGraph(
        modules=[
            ModuleNode(name="main", path="main.py", imports=["utils"], imported_by=[]),
            ModuleNode(name="utils", path="utils.py", imports=[], imported_by=["main"]),
        ],
        findings=[
            ArchitectureFinding(
                severity=Severity.HIGH,
                category="circular_import",
                title="Circular: main <-> utils",
                description="Modules form a circular dependency.",
                evidence="Import chain: main -> utils -> main",
                affected_files=["main.py", "utils.py"],
                recommendation="Break the cycle.",
                confidence=Confidence.HIGH,
            ),
        ],
    )
    assert len(arch.modules) == 2
    assert len(arch.circular_imports) == 1
    assert len(arch.god_modules) == 0


def test_security_report_counts():
    findings = [
        SecurityFinding(
            severity=Severity.CRITICAL,
            cwe=CweReference(cwe_id="CWE-798", name="Hardcoded Credentials"),
            title="Hardcoded secret",
            description="A secret is hardcoded.",
            evidence="Line 42",
            affected_file="config.py",
            affected_lines=[42],
            recommendation="Use env vars.",
            confidence=Confidence.HIGH,
        ),
        SecurityFinding(
            severity=Severity.HIGH,
            cwe=CweReference(cwe_id="CWE-78", name="OS Command Injection"),
            title="Command injection",
            description="shell=True with user input.",
            evidence="Line 100",
            affected_file="worker.py",
            affected_lines=[100],
            recommendation="Use shell=False.",
            confidence=Confidence.MEDIUM,
        ),
        SecurityFinding(
            severity=Severity.LOW,
            cwe=CweReference(cwe_id="CWE-489", name="Active Debug Code"),
            title="Debug enabled",
            description="debug=True",
            evidence="Line 5",
            affected_file="app.py",
            affected_lines=[5],
            recommendation="Use env var.",
            confidence=Confidence.MEDIUM,
        ),
    ]
    report = SecurityReport(findings=findings)
    assert report.total_findings == 3
    assert report.critical_count == 1
    assert report.high_count == 1
    assert report.low_count == 1
    assert report.medium_count == 0


def test_risk_score():
    score = RiskScore(
        overall=78.5,
        categories=[
            CategoryScore(
                category=ScoreCategory.SECURITY,
                score=85.0,
                why="Good security posture.",
                evidence=["No critical findings."],
                recommendations=["Keep it up."],
            ),
            CategoryScore(
                category=ScoreCategory.ARCHITECTURE,
                score=72.0,
                why="Some circular imports.",
                evidence=["2 circular imports detected."],
                recommendations=["Break cycles."],
            ),
        ],
    )
    assert score.grade == "C"
    assert score.overall == 78.5
    data = json.loads(score.model_dump_json())
    assert data["overall"] == 78.5


def test_daily_report():
    report = DailyReport(
        project="test-project",
        summary="No critical issues.",
        risk_trend="stable",
    )
    assert report.schema_version == "1"
    assert report.risk_trend == "stable"


def test_schema_version_present():
    """Every model must carry a schema_version field."""
    models = [
        RepositoryProfile(),
        ArchitectureGraph(),
        SecurityReport(findings=[]),
        RiskScore(overall=50.0, categories=[]),
        DailyReport(),
    ]
    for m in models:
        assert m.schema_version == "1", f"{type(m).__name__} missing schema_version"
