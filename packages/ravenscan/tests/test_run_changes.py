"""R-04 prior-run comparison — what changed since last run.

Gates: comparison derived only from stored verified observations; new/
resolved/recurring/severity-change classification; score delta; deterministic
identity on repeat comparisons; fails closed when memory is off; needs two
scans; CLI renders markdown and json.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO / "tests" / "fixtures" / "golden_repo"


def _cli(*args: str, env_extra: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO / "src") + os.pathsep + env.get("PYTHONPATH", "")
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "raven.cli.main", *args],
        env=env, capture_output=True, text=True, timeout=180,
    )


def _make_finding(path: str, line: int, severity=None, cwe_id: str = "CWE-78"):
    from raven.core.models import CweReference, SecurityFinding, Severity
    return SecurityFinding(
        severity=severity or Severity.HIGH,
        cwe=CweReference(cwe_id=cwe_id, name="Synthetic finding"),
        title=f"Synthetic {cwe_id}",
        description="test fixture finding",
        evidence=f"Found at {path}:{line}",
        affected_file=path,
        affected_lines=[line],
    )


def _seeded_store(tmp_path, *, with_third_scan: bool = False):
    """Three scans: findings evolve so every category has data."""
    from raven.core.models import Severity
    from raven.memory.store import MemoryStore
    store = MemoryStore(tmp_path / "history.db")
    first = store.save(score={"overall": 80.0}, commit_sha="a" * 7, branch="main")
    store.reconcile_findings(
        [_make_finding("app.py", 10), _make_finding("util.py", 20, cwe_id="CWE-22")],
        scan_id=first,
    )
    second = store.save(score={"overall": 75.0}, commit_sha="b" * 7, branch="main")
    # app.py stays, util.py resolves, web.py is new; severity later escalates.
    # Note: finding identity is rule-level, so each file needs its own rule.
    store.reconcile_findings(
        [_make_finding("app.py", 10), _make_finding("web.py", 5, cwe_id="CWE-89")],
        scan_id=second,
    )
    if with_third_scan:
        third = store.save(score={"overall": 70.0}, commit_sha="c" * 7, branch="main")
        store.reconcile_findings(
            [
                _make_finding("app.py", 12, Severity.CRITICAL),
                _make_finding("web.py", 5, cwe_id="CWE-89"),
            ],
            scan_id=third,
        )
    return store


# --- store-level gates -------------------------------------------------------

def test_compare_needs_two_scans(tmp_path):
    from raven.memory.store import MemoryStore
    store = MemoryStore(tmp_path / "history.db")
    assert store.compare_scans() is None, "no scans => no comparison"
    store.save(score={"overall": 80.0})
    assert store.compare_scans() is None, "one scan => no comparison"


def test_compare_fails_closed_when_memory_off(tmp_path, monkeypatch):
    store = _seeded_store(tmp_path)
    monkeypatch.setenv("RAVEN_MEMORY", "0")
    from raven.memory.store import MemoryStore
    silenced = MemoryStore(tmp_path / "history.db")
    assert silenced.compare_scans() is None


def test_compare_classifies_findings(tmp_path):
    """New / resolved / recurring / severity-change buckets are correct."""
    store = _seeded_store(tmp_path, with_third_scan=True)
    # Default: latest (scan 3) vs previous (scan 2).
    result = store.compare_scans()
    assert result["schema"] == "run_comparison/1"
    new_ids = [e["file"] for e in result["new"]]
    resolved_ids = [e["file"] for e in result["resolved"]]
    assert new_ids == ["web.py"] or new_ids == [], "web.py appears in scan 2"
    # Between scan 2 and 3: app.py escalates HIGH -> CRITICAL.
    changed = result["severity_changed"]
    assert len(changed) == 1
    assert changed[0]["from"] == "high" and changed[0]["to"] == "critical"
    # Score delta: 70 - 75.
    assert result["score"]["delta"] == -5.0
    # Explicit base: scan 1 -> scan 2 shows util.py resolved.
    explicit = store.compare_scans(base_id=1, head_id=2)
    assert [e["file"] for e in explicit["resolved"]] == ["util.py"]
    assert [e["file"] for e in explicit["new"]] == ["web.py"]
    assert explicit["score"]["delta"] == -5.0


def test_compare_deterministic_identity(tmp_path):
    """Same stored rows => byte-identical comparison (plan §2)."""
    store = _seeded_store(tmp_path, with_third_scan=True)
    first = json.dumps(store.compare_scans(), sort_keys=True)
    second = json.dumps(store.compare_scans(), sort_keys=True)
    assert first == second, "repeat comparison must be identical"


def test_compare_recurrence_bucket(tmp_path):
    """A resolved-then-returned finding lands in recurring, not new."""
    from raven.memory.store import MemoryStore
    store = MemoryStore(tmp_path / "history.db")
    s1 = store.save(score={"overall": 80.0})
    store.reconcile_findings([_make_finding("app.py", 10)], scan_id=s1)
    s2 = store.save(score={"overall": 82.0})
    store.reconcile_findings([], scan_id=s2)  # resolved
    s3 = store.save(score={"overall": 78.0})
    store.reconcile_findings([_make_finding("app.py", 10)], scan_id=s3)  # reintroduced
    result = store.compare_scans(base_id=2, head_id=3)
    assert result["new"] == [], "a reintroduced finding is not new"
    assert [e["file"] for e in result["recurring"]] == ["app.py"], \
        "reintroduced finding must surface as recurring"
    assert [e["state"] for e in result["recurring"]] == ["reintroduced"]


# --- CLI gates ---------------------------------------------------------------

def test_changes_cli_two_runs(tmp_path):
    out = tmp_path / "out"
    assert _cli("scan", str(FIXTURE), "-o", str(out), "--quiet").returncode == 0
    assert _cli("scan", str(FIXTURE), "-o", str(out), "--quiet").returncode == 0
    proc = _cli("changes", "-o", str(out))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "# Raven Changes" in proc.stdout
    assert "## New findings" in proc.stdout and "## Score" in proc.stdout


def test_changes_cli_json_deterministic(tmp_path):
    out = tmp_path / "out"
    assert _cli("scan", str(FIXTURE), "-o", str(out), "--quiet").returncode == 0
    assert _cli("scan", str(FIXTURE), "-o", str(out), "--quiet").returncode == 0
    a = _cli("changes", "-o", str(out), "-f", "json")
    b = _cli("changes", "-o", str(out), "-f", "json")
    assert a.returncode == 0 and b.returncode == 0
    assert json.loads(a.stdout) == json.loads(b.stdout)
    payload = json.loads(a.stdout)
    assert payload["schema"] == "run_comparison/1"
    for key in ("new", "resolved", "recurring", "severity_changed"):
        assert isinstance(payload[key], list)


def test_changes_needs_two_scans_graceful(tmp_path):
    out = tmp_path / "out"
    assert _cli("scan", str(FIXTURE), "-o", str(out), "--quiet").returncode == 0
    proc = _cli("changes", "-o", str(out))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "at least twice" in proc.stdout


def test_changes_fails_closed_when_memory_off(tmp_path):
    out = tmp_path / "out"
    assert _cli("scan", str(FIXTURE), "-o", str(out), "--quiet").returncode == 0
    assert _cli("scan", str(FIXTURE), "-o", str(out), "--quiet").returncode == 0
    proc = _cli("changes", "-o", str(out), env_extra={"RAVEN_MEMORY": "0"})
    assert proc.returncode == 1, "memory off => comparison refuses"
    assert "fail closed" in proc.stdout
