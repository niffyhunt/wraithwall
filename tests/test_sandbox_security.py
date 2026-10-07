"""Phase 6/7 unit tests: security-state card + `verify` tri-state semantics.

No docker daemon is touched: the compose layer is stubbed at the same
boundaries the kit tests use. The tri-state rule is the point — missing data
scores `unknown`, never a silent pass; only daemon-read False scores FAIL.
"""
import json

import pytest

from sandbox_kit import cli, security_posture as sp, state


@pytest.fixture
def sbx_dir(tmp_path, monkeypatch):
    home = tmp_path / "sbx"
    monkeypatch.setenv("WRAITHWALL_SANDBOX_DIR", str(home))
    return home


def _full_result(**over):
    """A fully-passing collected posture (the daemon-read happy path)."""
    base = {
        "sandbox": "default",
        "state": "RUNNING",
        "profile": "local-sandbox",
        "tier": "T1",
        "hardening": {
            "services_seen": 2, "privileged": False, "caps_dropped_all": True,
            "no_new_privileges": True, "readonly_rootfs": True, "uid_1000": True,
            "bind_mounts": 0, "resource_limits": True, "restart_never": True,
        },
        "egress": {"denied": True, "verdict": "EGRESS_DENY_OK"},
        "ports": {"published": [], "all_loopback": True},
        "docker_socket": {"checked": True, "reachable": False},
        "provenance": {"local_marked": True, "digest_matches": True},
        "errors": [],
    }
    base.update(over)
    return base


# ── collect_security_posture: never raises, degraded = data ────────────────

def test_posture_on_unbuilt_sandbox_is_data_not_crash(sbx_dir, capsys):
    # Unknown name, no explicit project: honest early return, no daemon probing
    # (we cannot know which project to look at).
    result = sp.collect_security_posture("ghost")
    assert result["state"] is None
    assert any("unbuilt" in e for e in result["errors"])
    checks = sp.run_security_checks(result)
    assert all(c["status"] in ("unknown", "error") for c in checks)

    # Known-but-stopped name: still readable live (project is derivable).
    state.write_state("stopped", {"state": "STOPPED", "project": "ww-sb-stopped"})
    result2 = sp.collect_security_posture("stopped")
    assert any("no RUNNING state marker" in e for e in result2["errors"])
    assert result2["hardening"].get("services_seen") is not None


def test_status_json_is_valid_json_with_checks(sbx_dir, monkeypatch, capsys):
    monkeypatch.setattr(sp, "collect_security_posture",
                        lambda name, deep=True, project=None: _full_result())
    assert cli.main(["status", "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["profile"] == "local-sandbox"
    assert {c["id"] for c in doc["checks"]} == {c[0] for c in sp.SECURITY_CHECKS}
    assert all(c["status"] == "pass" for c in doc["checks"])


def test_status_security_card_renders(sbx_dir, monkeypatch, capsys):
    monkeypatch.setattr(sp, "collect_security_posture",
                        lambda name, deep=True, project=None: _full_result())
    assert cli.main(["status", "--security"]) == 0
    out = capsys.readouterr().out
    assert "security state" in out
    assert "[✓]" in out
    assert "isolation checks:" in out


# ── tri-state scoring: the core honesty rule ────────────────────────────────

def test_missing_services_score_unknown_not_pass():
    result = _full_result()
    result["hardening"] = {k: None for k in result["hardening"]}
    result["hardening"]["services_seen"] = 0
    result["hardening"]["bind_mounts"] = 0
    checks = sp.run_security_checks(result)
    by_id = {c["id"]: c["status"] for c in checks}
    assert by_id["no-privileged"] == "unknown"
    assert by_id["caps-dropped-all"] == "unknown"
    # egress/ports/provenance have their own data sources — untouched here
    assert by_id["egress-denied"] == "pass"


def test_privileged_container_scores_FAIL():
    result = _full_result()
    result["hardening"]["privileged"] = True
    checks = sp.run_security_checks(result)
    by_id = {c["id"]: c["status"] for c in checks}
    assert by_id["no-privileged"] == "FAIL"
    # ...and only that one flips: scoring is per-check, not all-or-nothing
    assert by_id["caps-dropped-all"] == "pass"


def test_nonloopback_publish_scores_FAIL():
    result = _full_result()
    result["ports"] = {"published": ["0.0.0.0:8180->8000"], "all_loopback": False}
    checks = sp.run_security_checks(result)
    by_id = {c["id"]: c["status"] for c in checks}
    assert by_id["loopback-only-publish"] == "FAIL"


def test_digest_mismatch_flags_provenance_but_not_local_marker():
    result = _full_result()
    result["provenance"] = {"local_marked": True, "digest_matches": False}
    checks = sp.run_security_checks(result)
    by_id = {c["id"]: c["status"] for c in checks}
    assert by_id["telemetry-local-marked"] == "pass"
    # digest mismatch is surfaced as data, not scored here (reset owns it)


def test_verify_exit_codes(sbx_dir, monkeypatch, capsys):
    state.write_state("default", {"state": "RUNNING", "project": "ww-sb-default",
                                  "profile": "local-sandbox", "tier": "T1"})
    # all-pass → 0
    monkeypatch.setattr(sp, "collect_security_posture", lambda name, deep=True, project=None: _full_result())
    assert cli.main(["verify"]) == 0
    assert "all 12 security checks pass" in capsys.readouterr().out
    # one FAIL → 1, named
    failing = _full_result()
    failing["hardening"]["privileged"] = True
    monkeypatch.setattr(sp, "collect_security_posture",
                        lambda name, deep=True, project=None: failing)
    assert cli.main(["verify"]) == 1
    out = capsys.readouterr().out
    assert "no-privileged" in out and "FAILED" in out
    # unknown + --strict → 1
    partial = _full_result()
    partial["egress"] = {"denied": None}
    monkeypatch.setattr(sp, "collect_security_posture",
                        lambda name, deep=True, project=None: partial)
    assert cli.main(["verify", "--strict"]) == 1
    capsys.readouterr()
    # non-RUNNING → 2 (--name is a top-level arg, as sandbox.sh passes it)
    assert cli.main(["--name", "ghost", "verify"]) == 2


# ── module self-consistency ─────────────────────────────────────────────────

def test_every_check_id_is_unique_and_described():
    ids = [c[0] for c in sp.SECURITY_CHECKS]
    assert len(ids) == len(set(ids))
    assert all(c[1] for c in sp.SECURITY_CHECKS)
