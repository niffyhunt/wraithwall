"""R-01 run summaries + R-02 decision traces (test plan deliverable 10).

Gates: trace presence per scan; trace fields never sourced from free text;
summary derives only from verified records; no summary when disabled;
double-run identity modulo timestamps; version-mismatch detection;
rollback flags restore the pre-increment artifact set.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO / "tests" / "fixtures" / "golden_repo"
MALICIOUS = REPO / "tests" / "fixtures" / "golden_repo_malicious"
_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?")
_REV = re.compile(r"\*\*Commit:\*\*.*")


def _run_scan(fixture: Path, out_dir: Path, *, memory: str | None = None,
              extra: list[str] | None = None, quiet: bool = True) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO / "src") + os.pathsep + env.get("PYTHONPATH", "")
    if memory is not None:
        env["RAVEN_MEMORY"] = memory
    else:
        env.pop("RAVEN_MEMORY", None)
    cmd = [sys.executable, "-m", "raven.cli.main", "scan", str(fixture), "-o", str(out_dir)]
    if quiet:
        cmd.append("--quiet")
    cmd.extend(extra or [])
    return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=180)


def _norm(text: str, fixture: Path, out_dir: Path) -> str:
    text = _TS.sub("<TS>", text)
    text = _REV.sub("**Commit:** <REV>", text)
    text = text.replace(str(fixture.resolve()), "<PROJECT>")
    text = text.replace(str(out_dir), "<OUT>")
    text = text.replace(str(out_dir.parent), "<TMP>")
    return text


def test_trace_present_per_scan(tmp_path):
    """R-02: every scan emits a trace with phase/decision/reason/fingerprint."""
    out = tmp_path / "out"
    proc = _run_scan(FIXTURE, out)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    trace = json.loads((out / "decision_trace.json").read_text(encoding="utf-8"))
    assert trace["schema"] == "decision_trace/1"
    assert trace["versions"] == {"ruleset": "1.0", "template": "1.0"}
    assert "version_change" not in trace, "fresh store must not claim drift"
    phases = set()
    for d in trace["decisions"]:
        assert set(d) == {"phase", "decision", "reason", "input_fingerprint"}
        assert len(d["input_fingerprint"]) == 16
        assert d["reason"], "empty reason"
        phases.add(d["phase"])
    assert {"config", "repository", "architecture", "security_plugins", "scoring", "report"} <= phases
    # Reason and decision values are built from structured engine/config state
    # only — selection reasons are fixed phrasing, never repository prose.
    blob = json.dumps(trace)
    assert "ignore all previous instructions" not in blob


def test_trace_never_sources_free_text(tmp_path):
    """R-02 + plan §3: hostile fixture content must not reach the trace."""
    out = tmp_path / "out"
    proc = _run_scan(MALICIOUS, out)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    trace = json.loads((out / "decision_trace.json").read_text(encoding="utf-8"))
    blob = json.dumps(trace, ensure_ascii=False)
    for marker in ("ignore all previous instructions", "jndi:ldap", "{{7*7}}", "\x1b["):
        assert marker not in blob, f"free text leaked into trace: {marker!r}"


def test_summary_written_and_derived_from_verified_records(tmp_path):
    """R-01: summary artifact exists, is structured, carries no free text."""
    out = tmp_path / "out"
    proc = _run_scan(MALICIOUS, out)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    text = (out / "RunSummary.md").read_text(encoding="utf-8")
    assert text.startswith("# Raven Run Summary")
    assert "**Since last run:** first run in this scope" in text
    assert "## Score" in text and "## Findings since last run" in text
    assert "## Versions" in text and "Ruleset: 1.0" in text
    for marker in ("ignore all previous instructions", "jndi:ldap", "{{7*7}}"):
        assert marker not in text, "summary must derive only from verified structured records"
    # Stored row exists beside the artifact.
    from raven.memory.store import MemoryStore
    from sqlalchemy import text as sql_text
    store = MemoryStore(out / "history.db")
    with store.engine.connect() as conn:
        rows = conn.exec_driver_sql("SELECT scan_id, summary_json FROM run_summaries").fetchall()
    assert len(rows) == 1
    assert json.loads(rows[0][1])["schema"] == "run_summary/1"


def test_summary_shows_prior_scan_delta(tmp_path):
    """R-01: second run references the first and computes a score delta."""
    out = tmp_path / "out"
    assert _run_scan(FIXTURE, out).returncode == 0
    assert _run_scan(FIXTURE, out).returncode == 0
    text = (out / "RunSummary.md").read_text(encoding="utf-8")
    assert "**Since last run:** previous scan #1 at" in text
    assert "previous: " in text and "delta: " in text


def test_no_summary_when_disabled(tmp_path):
    """R-01 test plan: memory off ⇒ no summary artifact; trace still written."""
    out = tmp_path / "out"
    proc = _run_scan(FIXTURE, out, memory="0")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not (out / "RunSummary.md").exists(), "no summary when memory is disabled"
    assert (out / "decision_trace.json").is_file(), "trace is not memory-derived"


def test_double_run_identity_summary_and_trace(tmp_path):
    """Plan §2: two runs produce identical summary/trace modulo ts/paths."""
    a, b = tmp_path / "a", tmp_path / "b"
    assert _run_scan(FIXTURE, a).returncode == 0
    assert _run_scan(FIXTURE, b).returncode == 0
    for name in ("RunSummary.md", "decision_trace.json"):
        ta = _norm((a / name).read_text(encoding="utf-8"), FIXTURE, a)
        tb = _norm((b / name).read_text(encoding="utf-8"), FIXTURE, b)
        assert ta == tb, f"double-run identity broken for {name}"


def test_version_mismatch_detection(tmp_path):
    """R-02: stamped version drift is surfaced to the operator and in the trace."""
    out = tmp_path / "out"
    assert _run_scan(FIXTURE, out).returncode == 0
    import sqlite3
    db = sqlite3.connect(out / "history.db")
    db.execute("UPDATE scan_records SET ruleset_version='0.9', template_version='0.9'")
    db.commit()
    db.close()
    proc = _run_scan(FIXTURE, out, quiet=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ruleset version changed 0.9 → 1.0" in proc.stdout
    assert "template version changed 0.9 → 1.0" in proc.stdout
    trace = json.loads((out / "decision_trace.json").read_text(encoding="utf-8"))
    assert trace["version_change"]["ruleset"] == {"was": "0.9", "now": "1.0"}
    assert trace["version_change"]["template"] == {"was": "0.9", "now": "1.0"}
    # Stamped into scan_records for the next comparison.
    from raven.memory.store import MemoryStore
    store = MemoryStore(out / "history.db")
    versions = store.latest_versions()
    assert versions == {"ruleset": "1.0", "template": "1.0"}


def test_rollback_flags_restore_artifact_set(tmp_path):
    """R-01/R-02 rollback: --no-summary / --no-trace hide the new artifacts."""
    out = tmp_path / "out"
    proc = _run_scan(FIXTURE, out, extra=["--no-summary", "--no-trace"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not (out / "RunSummary.md").exists()
    assert not (out / "decision_trace.json").exists()
    for name in ("RepositoryProfile.md", "SecurityReport.md", "DailyReport.md"):
        assert (out / name).is_file()
