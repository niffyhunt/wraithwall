"""R-03 project-scoped operator preferences.

Gates: preference applied across runs; explicit CLI flag beats preference;
--no-prefs rollback; scope isolation; policy keys unreachable; secret values
rejected at the gate; scan content can never write preferences (security);
memory kill switch silences preferences.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO / "tests" / "fixtures" / "golden_repo"
MALICIOUS = REPO / "tests" / "fixtures" / "golden_repo_malicious"


def _cli(*args: str, env_extra: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO / "src") + os.pathsep + env.get("PYTHONPATH", "")
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "raven.cli.main", *args],
        env=env, capture_output=True, text=True, timeout=180,
    )


# --- store-level gates -------------------------------------------------------

def test_prefs_default_empty_and_roundtrip(tmp_path):
    from raven.memory.store import MemoryStore
    store = MemoryStore(tmp_path / "history.db")
    assert store.preferences() == {}
    store.set_preference("format", "json")
    store.set_preference("fail_under", "72.5")
    assert store.preferences() == {"fail_under": "72.5", "format": "json"}
    assert store.unset_preference("format")
    assert store.preferences() == {"fail_under": "72.5"}
    assert not store.unset_preference("format")


def test_policy_keys_are_unreachable(tmp_path):
    """Kill switch / scope / phases / gate are not preference-addressable."""
    from raven.memory import gate
    from raven.memory.store import MemoryStore
    store = MemoryStore(tmp_path / "history.db")
    for key in store.POLICY_KEYS:
        with pytest.raises(gate.GateRejected) as exc:
            store.set_preference(key, "1")
        assert exc.value.reason_code == "key_not_allowlisted"
    assert store.preferences() == {}
    # Unknown keys are rejected too — allow-list, not deny-list.
    with pytest.raises(gate.GateRejected):
        store.set_preference("exclude_patterns", "*")
    # The kill switch itself still only moves through disable()/enable().
    store.disable()
    assert not store.enabled


def test_pref_write_audited_with_hashes(tmp_path):
    from raven.memory.store import MemoryStore
    store = MemoryStore(tmp_path / "history.db")
    store.set_preference("format", "json")
    store.unset_preference("format")
    actions = [row["action"] for row in store.audit_log(limit=10)]
    assert "set_pref" in actions and "unset_pref" in actions
    set_row = next(r for r in store.audit_log(limit=10) if r["action"] == "set_pref")
    assert set_row["record_type"] == "operator_preference"
    assert set_row["after_hash"], "set_pref must record an after hash"


def test_secret_value_rejected_at_gate(tmp_path):
    from raven.memory import gate
    from raven.memory.store import MemoryStore
    store = MemoryStore(tmp_path / "history.db")
    with pytest.raises(gate.GateRejected) as exc:
        store.set_preference("format", "sk-abcdefghijklmnopqrstuvwx")
    assert exc.value.reason_code.startswith("secret:")
    assert store.preferences() == {}, "rejected value must not persist"


def test_memory_kill_switch_silences_prefs(tmp_path, monkeypatch):
    from raven.memory import gate
    from raven.memory.store import MemoryStore
    store = MemoryStore(tmp_path / "history.db")
    store.set_preference("format", "json")
    monkeypatch.setenv("RAVEN_MEMORY", "0")
    silenced = MemoryStore(tmp_path / "history.db")
    assert silenced.preferences() == {}, "env kill switch silences prefs"
    with pytest.raises(gate.GateRejected):
        silenced.set_preference("format", "markdown")


def test_scope_isolation(tmp_path):
    """Preferences belong to one project store — never shared across scopes."""
    from raven.memory.store import MemoryStore
    a = MemoryStore(tmp_path / "proj_a" / "history.db")
    b = MemoryStore(tmp_path / "proj_b" / "history.db")
    a.set_preference("format", "json")
    assert a.preferences() == {"format": "json"}
    assert b.preferences() == {}


# --- CLI gates ---------------------------------------------------------------

def test_pref_applies_across_runs(tmp_path):
    """Set once: a later scan without flags uses the stored format."""
    out = tmp_path / "out"
    assert _cli("prefs", "set", "format", "json", "-o", str(out)).returncode == 0
    proc = _cli("scan", str(FIXTURE), "-o", str(out), "--quiet")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (out / "SecurityReport.json").is_file(), "preference format must apply"
    assert not (out / "SecurityReport.md").exists()


def test_explicit_flag_beats_preference(tmp_path):
    out = tmp_path / "out"
    assert _cli("prefs", "set", "format", "json", "-o", str(out)).returncode == 0
    proc = _cli("scan", str(FIXTURE), "-o", str(out), "--quiet", "-f", "markdown")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (out / "SecurityReport.md").is_file()


def test_no_prefs_rollback(tmp_path):
    """--no-prefs ignores stored preferences entirely."""
    out = tmp_path / "out"
    assert _cli("prefs", "set", "format", "json", "-o", str(out)).returncode == 0
    proc = _cli("scan", str(FIXTURE), "-o", str(out), "--quiet", "--no-prefs")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (out / "SecurityReport.md").is_file()


def test_fail_under_pref_gates_score(tmp_path):
    """score honors the fail_under preference without repeating the flag."""
    out = tmp_path / "out"
    assert _cli("prefs", "set", "fail_under", "99.9", "-o", str(out)).returncode == 0
    proc = _cli("score", str(FIXTURE), "-o", str(out), "--quiet")
    assert proc.returncode == 1, "stored fail_under must gate score"
    rolled = _cli("score", str(FIXTURE), "-o", str(out), "--quiet", "--no-prefs")
    assert rolled.returncode == 0, "--no-prefs must restore un-gated score"


# --- security: scan content can never write preferences ----------------------

def test_scan_content_cannot_write_prefs(tmp_path):
    """Hostile fixture content must not create or alter preferences."""
    from raven.memory.store import MemoryStore
    out = tmp_path / "out"
    proc = _cli("scan", str(MALICIOUS), "-o", str(out), "--quiet")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    store = MemoryStore(out / "history.db")
    assert store.preferences() == {}, "scan-derived text must never write prefs"
    # No preference audit rows either — the write path is operator-only.
    pref_rows = [r for r in store.audit_log(limit=500) if r["record_type"] == "operator_preference"]
    assert pref_rows == []
