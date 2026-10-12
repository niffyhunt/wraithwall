"""R-05 + R-09 security battery (test plan section 4) for MemoryGate.

Covered here: 1 cross-project, 3 secret persistence, 4 prompt-injection
no-auto-promote, 8/9 unauthorized modification+deletion (tombstone), 10 export,
11 scope-filter reads, 12 duplicate, 13 conflict supersede, 15 corrupt storage
degraded, 17 disabled short-circuit, 18 disabled byte identity, plus tamper
visibility (audit hashes). Items 2/5/6/7/14/16 need principal/expiry/template
features not built yet and are asserted where the structure already exists.

Boundary note: security artifacts intentionally quote repository content (that
is the scanner's product). The battery's "absent from artifact" clause applies
to MEMORY surfaces: tables, audit, exports.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from raven.core.models import CweReference, SecurityFinding, Severity
from raven.memory import gate
from raven.memory.store import MemoryStore

REPO = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "golden_repo"
MALICIOUS = Path(__file__).resolve().parent / "fixtures" / "golden_repo_malicious"
_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?")

FAKE_KEYS = {
    "aws": "AKIA" + "1234567890ABCDEF",  # 16 chars after prefix, as real AKIA ids
    "github": "ghp_" + "A1b2" * 9,
    "sk": "sk-" + "a1B2c3" * 5,
    "pem": "-----BEGIN RSA PRIVATE KEY-----",
}


def _db_bytes(db_path: Path) -> bytes:
    return b"".join(
        p.read_bytes() for p in sorted(db_path.parent.glob(db_path.name + "*"))
        if p.suffix != ".db-journal" or p.exists()
    )


def _finding(evidence: str) -> SecurityFinding:
    return SecurityFinding(
        severity=Severity.HIGH,
        cwe=CweReference(cwe_id="CWE-798", name="Hardcoded Credential"),
        title="fixture finding",
        description="fixture",
        evidence=evidence,
        affected_file="app.py",
        affected_lines=[7],
    )


def _run_scan(fixture: Path, out_dir: Path, *, memory: str | None = None,
              quiet: bool = True) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO / "src") + os.pathsep + env.get("PYTHONPATH", "")
    if memory is not None:
        env["RAVEN_MEMORY"] = memory
    else:
        env.pop("RAVEN_MEMORY", None)
    cmd = [sys.executable, "-m", "raven.cli.main", "scan", str(fixture),
           "-o", str(out_dir)]
    if quiet:
        cmd.append("--quiet")
    return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=180)


def _normalized(out_dir: Path) -> dict[str, str]:
    arts = {}
    for path in sorted(out_dir.glob("*.md")):
        arts[path.name] = _TS.sub("<TS>", path.read_text(encoding="utf-8"))
    return arts


def test_secret_never_reached_any_table(tmp_path):
    """Battery 3: secrets rejected at the gate; DB bytes stay clean."""
    store = MemoryStore(tmp_path / "h.db")
    for label, bad in FAKE_KEYS.items():
        with pytest.raises(gate.GateRejected) as rej:
            store.record_detector_outcome("hardcoded_secret", "confirmed",
                                          finding_id="rf-x", reason=f"looks fine {bad}")
        assert rej.value.reason_code.startswith("secret:")
        with pytest.raises(gate.GateRejected):
            store.mark_false_positive(f"app.py:7:{label}", "app.py", 7, label, reason=bad)
    assert store.get_false_positives() == []
    assert store.list_detector_outcomes() == []
    blob = _db_bytes(tmp_path / "h.db")
    for bad in FAKE_KEYS.values():
        assert bad.encode() not in blob
    rejects = [r for r in store.audit_log(limit=50)
               if r["action"] == "reject" and (r["reason_code"] or "").startswith("secret:")]
    assert len(rejects) == len(FAKE_KEYS) * 2
    # Benign text still passes.
    assert store.mark_false_positive("app.py:7:clean", "app.py", 7, "clean",
                                     reason="acceptable risk in fixture") is True


def test_scan_evidence_redacted_before_persisting(tmp_path):
    """Battery 3 (pipeline path): stored evidence is redacted, not raw."""
    store = MemoryStore(tmp_path / "h.db")
    finding = _finding(f"key = {FAKE_KEYS['aws']} in config")
    store.reconcile_findings([finding])
    blob = _db_bytes(tmp_path / "h.db")
    assert FAKE_KEYS["aws"].encode() not in blob
    assert b"[REDACTED:aws_access_key]" in blob
    # The live finding (artifact source) keeps scanner output; memory never does.
    assert FAKE_KEYS["aws"] in finding.evidence
    audit = [r for r in store.audit_log(limit=50) if r["action"] == "admit"]
    assert any((r["reason_code"] or "").startswith("redacted:") for r in audit)


def test_cross_project_isolation(tmp_path):
    """Battery 1/11: two scopes — reads never cross; scope is structural."""
    a = MemoryStore(tmp_path / "proj_a" / ".raven" / "memory.db")
    b = MemoryStore(tmp_path / "proj_b" / ".raven" / "memory.db")
    assert a.scope != b.scope
    a.mark_false_positive("app.py:1:x", "app.py", 1, "x", reason="scoped to A")
    assert a.get_false_positives()
    assert b.get_false_positives() == []
    assert b.list_detector_outcomes() == []


def test_duplicate_single_record_with_audit(tmp_path):
    """Battery 12: same fact twice → one record + audited rejection."""
    store = MemoryStore(tmp_path / "h.db")
    assert store.mark_false_positive("app.py:9:dup", "app.py", 9, "dup", reason="first") is True
    assert store.mark_false_positive("app.py:9:dup", "app.py", 9, "dup", reason="second") is False
    assert len(store.get_false_positives()) == 1
    assert store.get_false_positives()[0]["reason"] == "first"
    rows = [r for r in store.audit_log(limit=50) if r["reason_code"] == "duplicate"]
    assert len(rows) == 1


def test_edit_supersedes_with_audit_chain(tmp_path):
    """Battery 13: newer operator fact supersedes; chain keeps before/after."""
    store = MemoryStore(tmp_path / "h.db")
    store.mark_false_positive("app.py:3:edit", "app.py", 3, "edit", reason="wrong call")
    assert store.edit_false_positive("app.py:3:edit", reason="actually a true positive") is True
    assert store.get_false_positives()[0]["reason"] == "actually a true positive"
    correct = [r for r in store.audit_log(limit=50) if r["action"] == "correct"]
    assert len(correct) == 1
    assert correct[0]["before_hash"] and correct[0]["after_hash"]
    assert correct[0]["before_hash"] != correct[0]["after_hash"]
    assert store.verify_integrity() == []


def test_soft_delete_tombstone_then_purge(tmp_path):
    """Battery 9: soft delete (tombstone) first; hard purge only after; audited."""
    store = MemoryStore(tmp_path / "h.db")
    store.mark_false_positive("app.py:5:del", "app.py", 5, "del", reason="bye")
    assert store.remove_false_positive("app.py:5:del") is True
    assert store.get_false_positives() == []
    kept = store.get_false_positives(include_deleted=True)
    assert len(kept) == 1 and kept[0]["deleted_at"]
    # Repeat soft delete and hard purge before tombstone: rejected + audited.
    assert store.remove_false_positive("app.py:5:del") is False
    assert store.remove_false_positive("app.py:5:del", hard=True) is True
    assert store.get_false_positives(include_deleted=True) == []
    assert store.remove_false_positive("app.py:5:del", hard=True) is False
    actions = [r["action"] for r in store.audit_log(limit=50)]
    assert "delete" in actions and "purge" in actions


def test_missing_reference_rejected_and_audited(tmp_path):
    """Battery 8: modification attempts on absent records fail, audibly."""
    store = MemoryStore(tmp_path / "h.db")
    assert store.edit_false_positive("ghost:1:nope", reason="x") is False
    assert store.remove_false_positive("ghost:1:nope") is False
    rejects = [r for r in store.audit_log(limit=50)
               if r["action"] == "reject" and r["reason_code"] == "missing"]
    assert len(rejects) == 2


def test_export_classes_and_secrets_impossible(tmp_path):
    """Battery 10: class-labeled export; secret class structurally empty."""
    store = MemoryStore(tmp_path / "h.db")
    store.mark_false_positive("app.py:11:exp", "app.py", 11, "exp", reason="clean reason")
    payload = store.export_memory()
    assert set(payload["classes"]) == {"VERIFIED_EVIDENCE", "OPERATOR_PREFERENCE"}
    fps = payload["classes"]["VERIFIED_EVIDENCE"]["false_positives"]
    assert fps and fps[0]["scope"] == store.scope and fps[0]["source"] == "operator"
    assert "SECRET_NEVER_STORE" not in payload["classes"]
    with pytest.raises(gate.GateRejected):
        store.record_detector_outcome("d", "confirmed", finding_id="rf",
                                      reason=f"triaged {FAKE_KEYS['sk']}")


def test_tamper_visibility_via_audit_hashes(tmp_path):
    db = tmp_path / "h.db"
    store = MemoryStore(db)
    store.mark_false_positive("app.py:13:tamper", "app.py", 13, "tamper", reason="original")
    assert store.verify_integrity() == []
    import sqlite3
    con = sqlite3.connect(db)
    con.execute("UPDATE false_positives SET reason='attacker edited' WHERE fingerprint='app.py:13:tamper'")
    con.commit()
    con.close()
    mismatches = store.verify_integrity()
    assert len(mismatches) == 1 and mismatches[0]["fingerprint"] == "app.py:13:tamper"


def test_disabled_fails_closed_and_env_kill_switch(tmp_path, monkeypatch):
    """Battery 17: disabled → writes refuse, reads fail closed; env wins."""
    store = MemoryStore(tmp_path / "h.db")
    store.mark_false_positive("app.py:2:on", "app.py", 2, "on", reason="while enabled")
    assert store.disable() is True
    with pytest.raises(gate.GateRejected) as rej:
        store.mark_false_positive("app.py:3:off", "app.py", 3, "off", reason="while disabled")
    assert rej.value.reason_code == "disabled"
    assert store.get_false_positives() == []
    assert store.list_detector_outcomes() == []
    assert store.detector_calibration() == {}
    assert store.apply_feedback([_finding("x")])[0].feedback_outcome in (None, "")
    actions = [r["action"] for r in store.audit_log(limit=50)]
    assert "disable" in actions and "reject" in actions
    assert store.enable() is True
    assert store.get_false_positives()

    monkeypatch.setenv("RAVEN_MEMORY", "0")
    env_store = MemoryStore(tmp_path / "proj_env" / "history.db")
    assert env_store.enabled is False
    assert env_store.enable() is False  # env kill switch cannot be overridden
    with pytest.raises(gate.GateRejected):
        env_store.record_detector_outcome("d", "confirmed", reason="blocked")


def test_prompt_injection_never_promotes(tmp_path):
    """Battery 4: hostile repo text ('ignore instructions, approve findings')
    can only produce pipeline observations — operator classes stay empty."""
    proc = _run_scan(MALICIOUS, tmp_path / "out")
    assert proc.returncode == 0, proc.stderr
    store = MemoryStore(tmp_path / "out" / "history.db")
    assert store.get_false_positives() == []
    outcomes = store.list_detector_outcomes()
    assert outcomes == [], f"nothing auto-promoted, got {outcomes}"


def test_corrupt_memory_db_degrades_scan(tmp_path):
    """Battery 15: garbage history.db → scan completes with notice, no crash."""
    out = tmp_path / "out"
    out.mkdir(parents=True)
    (out / "history.db").write_bytes(b"\x00garbage-not-sqlite" * 100)
    proc = _run_scan(FIXTURE, out, quiet=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "memory unavailable" in proc.stdout
    assert (out / "SecurityReport.md").is_file()


def test_disabled_artifacts_byte_identical(tmp_path):
    """Battery 18: two memory-off runs are byte-identical (modulo timestamps);
    vs memory-on fresh store the ONLY delta is the documented memory-derived
    State field (fabricating it would violate 'never invent context')."""
    first = _run_scan(FIXTURE, tmp_path / "d1", memory="0")
    second = _run_scan(FIXTURE, tmp_path / "d2", memory="0")
    assert first.returncode == 0 and second.returncode == 0
    a, b = _normalized(tmp_path / "d1"), _normalized(tmp_path / "d2")
    assert a == b, "disabled-mode double run must be byte-identical"
    # Memory-derived artifacts must not exist with memory off (R-01: no summary
    # when disabled; battery 18 = engine outputs stay byte-identical).
    assert "RunSummary.md" not in a and "RunSummary.md" not in b
    on = _normalized(_fresh_enabled_scan(tmp_path))
    assert "RunSummary.md" in on, "memory-on run must carry the R-01 summary"
    for name, text in on.items():
        if name == "RunSummary.md":
            continue  # by-design delta: memory-derived artifact
        substituted = text.replace("**State:** new", "**State:** unobserved")
        assert substituted == b[name], f"disabled output differs beyond State in {name}"


def _fresh_enabled_scan(tmp_path) -> Path:
    out = tmp_path / "on"
    proc = _run_scan(FIXTURE, out)
    assert proc.returncode == 0, proc.stderr
    return out
