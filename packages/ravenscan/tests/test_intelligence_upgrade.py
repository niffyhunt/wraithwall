"""Tests for the additive Phase 1-3 intelligence layer."""

import json
from pathlib import Path

from raven.core.config import RavenConfig
from raven.core.context import DependencyInfo
from raven.core.models import CweReference, SecurityFinding, SecurityReport, Severity
from raven.memory.store import MemoryStore
from raven.reporting.renderers.sarif import render_sarif
from raven.repository.intel import build_context
from raven.security.taint import analyze_taint, build_attack_paths, dependency_reachability
from raven.security.calibration import outcome_calibration
from raven.delta.analyzers import build_delta


def make_finding(path: str, line: int) -> SecurityFinding:
    return SecurityFinding(
        severity=Severity.HIGH,
        cwe=CweReference(cwe_id="CWE-78", name="OS Command Injection"),
        title="Potential command injection",
        description="user input reaches command sink",
        evidence=f"Found at {path}:{line}",
        affected_file=path,
        affected_lines=[line],
    )


def test_finding_id_survives_path_and_line_move():
    assert make_finding("old.py", 10).finding_id == make_finding("new.py", 30).finding_id


def test_history_tracks_reintroduction_and_debt(tmp_path: Path):
    store = MemoryStore(tmp_path / "history.db")
    first = make_finding("app.py", 1)
    assert store.reconcile_findings([first])[0].historical_state == "new"
    assert store.reconcile_findings([make_finding("app.py", 2)])[0].historical_state == "existing"
    store.reconcile_findings([])
    returned = store.reconcile_findings([make_finding("app.py", 3)])[0]
    assert returned.historical_state == "reintroduced"
    assert store.recurring_debt()[0]["reintroduction_count"] == 1


def test_explicit_finding_id_is_preserved():
    finding = make_finding("app.py", 4)
    finding.finding_id = "legacy-finding-123"
    finding.refresh_provenance(recompute_id=False)
    assert finding.finding_id == "legacy-finding-123"


def test_identity_ignores_description_rewording():
    first = make_finding("app.py", 4)
    second = SecurityFinding(
        severity=Severity.HIGH,
        cwe=first.cwe,
        title=first.title,
        description="The detector emitted different explanatory prose.",
        evidence=first.evidence,
        affected_file=first.affected_file,
        affected_lines=first.affected_lines,
    )
    assert first.finding_id == second.finding_id


def test_canonical_rule_context_survives_detector_prose_changes():
    kwargs = {
        "analyzer": "command_injection",
        "rule_id": "python.command-injection.os-system",
        "identity_context": "python.ast.call:os.system:request-derived-argument",
        "cwe_id": "CWE-78",
        "title": "changed title",
        "description": "changed description",
        "evidence": "changed evidence at moved.py:90",
    }
    first = SecurityFinding(
        severity=Severity.HIGH,
        cwe=CweReference(cwe_id="CWE-78", name="OS Command Injection"),
        title="old title",
        description="old description",
        evidence="old evidence at app.py:4",
        affected_file="app.py",
        affected_lines=[4],
        **{k: v for k, v in kwargs.items() if k not in ("cwe_id", "title", "description", "evidence")},
    )
    second = SecurityFinding(
        severity=Severity.HIGH,
        cwe=first.cwe,
        title=kwargs["title"],
        description=kwargs["description"],
        evidence=kwargs["evidence"],
        affected_file="moved.py",
        affected_lines=[90],
        analyzer=kwargs["analyzer"],
        rule_id=kwargs["rule_id"],
        identity_context=kwargs["identity_context"],
    )
    assert first.finding_id == second.finding_id


def test_sarif_contains_cwe_location_and_fingerprint():
    finding = make_finding("app.py", 4)
    data = json.loads(render_sarif(SecurityReport(findings=[finding])))
    result = data["runs"][0]["results"][0]
    assert data["version"] == "2.1.0"
    assert result["ruleId"] == "CWE-78"
    assert result["fingerprints"]["ravenFindingId"] == finding.finding_id
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 4
    assert "helpUri" not in data["runs"][0]["tool"]["driver"]["rules"][0] or data["runs"][0]["tool"]["driver"]["rules"][0]["helpUri"].startswith("https://")


def test_taint_flow_and_attack_path_are_evidence_backed(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "from flask import request\nimport os\nx = request.args.get('x')\nos.system(x)\n"
    )
    ctx = build_context(RavenConfig(path=tmp_path))
    flows = analyze_taint(ctx)
    assert len(flows) == 1
    finding = SecurityFinding(
        severity=Severity.HIGH,
        cwe=CweReference(cwe_id="CWE-78", name="OS Command Injection"),
        title="Command sink",
        description="sink",
        evidence="app.py:4",
        affected_file="app.py",
        affected_lines=[4],
    )
    paths = build_attack_paths(flows, [finding])
    assert len(paths) == 1
    assert finding.finding_id in paths[0].finding_ids


def test_outcome_calibration_is_advisory_without_data():
    result = outcome_calibration("CWE-78")
    assert result["status"] == "insufficient-data"
    assert result["advisory"] is True
    assert result["false_positive_rate"] is None


def test_diff_marks_reintroduced_finding_as_regression():
    previous = make_finding("app.py", 4).model_dump(mode="json")
    current = make_finding("app.py", 4)
    current.historical_state = "reintroduced"
    current.reintroduction_count = 1
    delta = build_delta(
        prev_sec={"findings": [previous]},
        curr_sec={"findings": [current.model_dump(mode="json")]},
    )
    assert delta.security_summary["regressions"] == 1
    assert any("Reintroduced" in entry.description for entry in delta.entries)


def test_dependency_reachability_is_conservative(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.0\nunused-lib==1.0\n")
    (tmp_path / "app.py").write_text("import requests\n")
    ctx = build_context(RavenConfig(path=tmp_path))
    results = {item.dependency: item for item in dependency_reachability(ctx)}
    assert results["requests"].status == "demonstrated_reachability"
    assert results["unused-lib"].status == "unknown_reachability"
