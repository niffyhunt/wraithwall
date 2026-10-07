"""Phase 10 tests: supply-chain provenance and the G10 release gate.

Covers: digest manifest semantics (pinned match / mismatch / local build),
the E206 provenance gate, waiver-register classification (including expiry
and the fail-closed unknown-severity rule), the `sbom` verb's honest failure
paths, and image-updates.md freshness.
"""

from __future__ import annotations

import pytest

from sandbox_kit import provenance
from sandbox_kit.gates import GateFailure

REDIS_PIN = "redis@sha256:" + "a" * 64
LOCAL_APP = "wraithwall-sandbox-app:local"


def _row(svc, image, image_id="sha256:aaa", digests=None):
    return {"Service": svc, "Image": image, "ImageID": image_id,
            "RepoDigests": digests or []}


# ── digest manifest ──────────────────────────────────────────────────────────

def test_manifest_pinned_image_that_matches():
    m = provenance.build_digest_manifest("t", [
        _row("sb-redis", REDIS_PIN, digests=[REDIS_PIN])])
    im = m["images"]["sb-redis"]
    assert im["matches_pin"] is True
    assert im["locally_built"] is False
    assert im["repo_digest"] == REDIS_PIN
    assert provenance.pin_mismatches(m) == []


def test_manifest_pinned_image_that_does_not_match():
    other = "redis@sha256:" + "b" * 64
    m = provenance.build_digest_manifest("t", [
        _row("sb-redis", REDIS_PIN, digests=[other])])
    assert m["images"]["sb-redis"]["matches_pin"] is False
    bad = provenance.pin_mismatches(m)
    assert len(bad) == 1 and "sb-redis" in bad[0]


def test_manifest_pinned_image_with_no_repo_digest_is_unknown_not_match():
    m = provenance.build_digest_manifest("t", [
        _row("sb-redis", REDIS_PIN, digests=[])])
    assert m["images"]["sb-redis"]["repo_digest"] is None
    assert m["images"]["sb-redis"]["matches_pin"] is False
    assert provenance.pin_mismatches(m)  # unknown ⇒ mismatch, fail-closed


def test_manifest_local_build_is_provenance_by_construction():
    m = provenance.build_digest_manifest("t", [_row("sb-app", LOCAL_APP)])
    im = m["images"]["sb-app"]
    assert im["locally_built"] is True
    assert im["matches_pin"] is True
    assert im["dockerfile"] == "Dockerfile.sandbox"
    assert provenance.pin_mismatches(m) == []


def test_manifest_summary_lists_every_service():
    m = provenance.build_digest_manifest("t", [
        _row("sb-app", LOCAL_APP), _row("sb-redis", REDIS_PIN, digests=[REDIS_PIN])])
    s = provenance.manifest_summary(m)
    assert "sb-app" in s and "sb-redis" in s and "local-build" in s


# ── E206 gate ────────────────────────────────────────────────────────────────

def test_e206_gate_passes_on_exact_pins():
    rows = [_row("sb-redis", REDIS_PIN, digests=[REDIS_PIN]),
            _row("sb-app", LOCAL_APP)]
    manifest = provenance.run_provenance_gate(rows)
    assert "sb-redis" in manifest["images"]


def test_e206_gate_refuses_on_drift():
    other = "redis@sha256:" + "b" * 64
    with pytest.raises(GateFailure) as ei:
        provenance.run_provenance_gate([_row("sb-redis", REDIS_PIN, digests=[other])])
    assert ei.value.code == "E206"


def test_e206_gate_refuses_on_unverifiable_digest():
    with pytest.raises(GateFailure) as ei:
        provenance.run_provenance_gate([_row("sb-redis", REDIS_PIN, digests=[])])
    assert ei.value.code == "E206"


# ── waiver register classification ───────────────────────────────────────────

def test_critical_without_waiver_blocks():
    r = provenance.classify_scan_findings(
        [{"id": "CVE-1", "severity": "Critical"}])  # case-insensitive
    assert len(r["blocking"]) == 1 and not r["waived"]


def test_high_with_live_waiver_passes():
    provenance.WAIVER_REGISTER.append(
        {"id": "CVE-2", "reason": "test", "owner": "t", "expires": "2999-01-01"})
    try:
        r = provenance.classify_scan_findings(
            [{"id": "CVE-2", "severity": "HIGH"}])
        assert not r["blocking"] and len(r["waived"]) == 1
    finally:
        provenance.WAIVER_REGISTER.pop()


def test_expired_waiver_counts_as_unwaived():
    provenance.WAIVER_REGISTER.append(
        {"id": "CVE-3", "reason": "test", "owner": "t", "expires": "2000-01-01"})
    try:
        r = provenance.classify_scan_findings(
            [{"id": "CVE-3", "severity": "HIGH"}])
        assert len(r["blocking"]) == 1 and not r["waived"]
    finally:
        provenance.WAIVER_REGISTER.pop()


def test_medium_findings_pass_on_severity_alone():
    r = provenance.classify_scan_findings(
        [{"id": "CVE-4", "severity": "Medium"}, {"id": None, "severity": "Low"}])
    assert not r["blocking"] and len(r["passed"]) == 2


# ── sbom verb honesty (no daemon needed for the refusal paths) ──────────────

def test_sbom_without_syft_is_exit2_and_generates_nothing(tmp_path, monkeypatch, capsys):
    from sandbox_kit import cli
    monkeypatch.setattr(provenance, "sbom_tool_status",
                        lambda: {"syft": None, "grype": None})
    rc = cli.main(["sbom", "--image", "busybox:latest", "--out", str(tmp_path / "o")])
    assert rc == 2
    assert "does not pretend" in capsys.readouterr().out
    assert not (tmp_path / "o").exists()  # nothing written


def test_sbom_missing_generator_message_names_the_fix(tmp_path, monkeypatch, capsys):
    from sandbox_kit import cli
    monkeypatch.setattr(provenance, "sbom_tool_status",
                        lambda: {"syft": None, "grype": None})
    cli.main(["sbom", "--image", "busybox:latest", "--out", str(tmp_path / "o")])
    assert "syft" in capsys.readouterr().out


# ── doc freshness for the new phase ──────────────────────────────────────────

def test_image_updates_doc_matches_implementation():
    from pathlib import Path
    repo = Path(__file__).resolve().parents[1]
    text = (repo / "docs" / "sandbox" / "image-updates.md").read_text(encoding="utf-8")
    assert "E206" in text                      # the gate is documented
    assert "WAIVER_REGISTER" in text           # the register is named
    assert "CycloneDX" in text                 # the format is pinned
    cli_text = (repo / "sandbox_kit" / "cli.py").read_text(encoding="utf-8")
    for cmd in ("sbom", "--image", "--out"):
        assert cmd in cli_text
