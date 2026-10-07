"""Phase 8 — cross-platform compatibility (G14 platform-control reporter).

Roadmap acceptance: the support matrix is *reality-labeled*, degradation is
honest (tri-state), and a load-bearing control that is UNAVAILABLE/UNKNOWN
refuses startup fail-closed (E203) — never a silent fallback to an unsafe
mode. All probes are injected, so every platform in the Stage 3 matrix is
simulated exactly, including the Docker-Desktop-VM semantics where host-side
answers honestly differ from the enforcing kernel.
"""

import json

import pytest

from sandbox_kit import cli
from sandbox_kit.gates import GateFailure, run_all_gates, run_platform_controls_gate
from sandbox_kit.platform import (
    ACTIVE,
    UNAVAILABLE,
    UNKNOWN,
    classify,
    report_platform_controls,
)
from sandbox_kit.profiles import get_profile

# ── probe factories per Stage 3 platform matrix row ────────────────────────

LINUX = {"system": lambda: ("Linux", "6.8.0", "x86_64")}
APPLE = {"system": lambda: ("Darwin", "23.5.0", "arm64")}
WSL2 = {"system": lambda: ("Linux", "5.15.153.1-microsoft-standard-WSL2", "x86_64")}
WINDOWS = {"system": lambda: ("Windows", "10", "AMD64")}

DOCKER_ROOTFUL = {
    "docker_info": lambda: {"SecurityOptions": [
        "name=apparmor", "name=seccomp,profile=builtin", "name=cgroupns"]},
    "userns": lambda: True,
    "cgroup": lambda: True,
}
DOCKER_DESKTOP_VM = {
    # Desktop daemons answer from inside the VM; host-side userns probe is
    # meaningless there — the reporter must not pretend otherwise.
    "docker_info": lambda: {"SecurityOptions": ["name=seccomp,profile=builtin"]},
    "userns": lambda: False,          # Docker Desktop VM sysctl
    "cgroup": lambda: True,
}
DOCKER_ROOTLESS = {
    "docker_info": lambda: {"SecurityOptions": [
        "name=rootless", "name=seccomp,profile=builtin"]},
    "userns": lambda: True,
    "cgroup": lambda: True,
}
DAEMON_DOWN = {"docker_info": lambda: {}}

FULL_RUNTIME = {"runtime": lambda: ("/usr/bin/docker", "docker")}

BASE_T1 = dict(
    platform=lambda: ("Linux", "6.8"),
    python=lambda: (3, 12),
    runtime=lambda: ("/usr/bin/docker", "docker"),
    compose=lambda rt: True,
    ram=lambda: 8192,
)


def _t1_probes(**over):
    p = dict(BASE_T1)
    p.update(DOCKER_ROOTFUL)
    p.update(over)
    return p


# ── tri-state honesty ───────────────────────────────────────────────────────

def test_linux_rootful_reference_platform_all_active_except_rootless():
    r = report_platform_controls(runtime="docker", **LINUX, **DOCKER_ROOTFUL)
    s = r.summary()
    assert {"no-new-privileges", "caps-drop-all", "read-only-rootfs",
            "seccomp", "resource-limits", "user-namespace"} <= set(s["active"])
    assert s["unknown"] == []
    # reference platform runs rootful docker — rootless is honestly UNAVAILABLE
    assert "rootless-runtime" in s["unavailable"]


def test_unknown_is_never_counted_as_present():
    r = report_platform_controls(runtime="docker", **LINUX, **DAEMON_DOWN,
                                 **{"userns": lambda: (_ for _ in ()).throw(OSError)})
    s = r.summary()
    # daemon down → seccomp unverifiable; userns probe crashed → UNKNOWN
    assert "seccomp" in s["unknown"]
    assert "user-namespace" in s["unknown"]
    # and the tri-state invariant: a key never appears in two states
    for st in (s["active"], s["unavailable"], s["unknown"]):
        assert len(st) == len(set(st))
    assert not (set(s["active"]) & set(s["unknown"]))


def test_daemon_down_baseline_controls_are_unknown_not_active():
    r = report_platform_controls(runtime="docker", **LINUX, **DAEMON_DOWN,
                                 **{"userns": lambda: True, "cgroup": lambda: True})
    s = r.summary()
    # no daemon answer → seccomp/rootless cannot be claimed
    assert "seccomp" in s["unknown"]
    assert "rootless-runtime" in s["unknown"]
    # …and must NOT be overclaimed as verified-absent either
    assert "rootless-runtime" not in s["unavailable"]
    assert "seccomp" not in s["unavailable"]


def test_app_only_no_runtime_claims_nothing():
    r = report_platform_controls(runtime="", **LINUX, **DOCKER_ROOTFUL)
    s = r.summary()
    # host-side facts (userns, lsm) are answerable without a runtime — only
    # daemon/kernel-container facts are UNKNOWN when no runtime exists.
    assert s["active"] == ["lsm", "user-namespace"]
    daemon_facts = {"no-new-privileges", "caps-drop-all", "read-only-rootfs",
                    "seccomp", "resource-limits", "rootless-runtime"}
    assert daemon_facts <= set(s["unknown"])


def test_render_groups_and_marks_load_bearing():
    r = report_platform_controls(runtime="docker", **LINUX, **DOCKER_ROOTFUL)
    out = r.render()
    assert "ACTIVE:" in out and "UNAVAILABLE:" in out
    assert "[load-bearing]" in out
    assert "✓" in out and "✗" in out


def test_to_dict_json_roundtrip():
    r = report_platform_controls(runtime="docker", **LINUX, **DOCKER_ROOTFUL)
    d = json.loads(json.dumps(r.to_dict()))
    assert d["system"] == "Linux" and d["runtime"] == "docker"
    keys = {"key", "label", "status", "load_bearing", "detail"}
    assert all(set(c) == keys for c in d["controls"])


# ── platform semantics: VM boundary must be labeled, not faked ─────────────

def test_macos_reports_vm_boundary_honestly():
    r = report_platform_controls(runtime="docker", **APPLE, **DOCKER_DESKTOP_VM)
    by_key = {c.key: c for c in r.controls}
    assert r.system == "Darwin"
    # userns is host-side meaningless on macOS: UNAVAILABLE with VM detail —
    # NOT faked to ACTIVE even though the Desktop VM kernel enables it.
    assert by_key["user-namespace"].status == UNAVAILABLE
    assert "runtime VM" in by_key["user-namespace"].detail
    assert by_key["resource-limits"].status == ACTIVE
    assert "runtime VM" in by_key["resource-limits"].detail


def test_wsl2_detected_and_labeled():
    r = report_platform_controls(runtime="docker", **WSL2, **DOCKER_DESKTOP_VM)
    assert "WSL2" in r.release
    by_key = {c.key: c for c in r.controls}
    # The WSL2 VM's kernel sysctl answered: that kernel IS the enforcement
    # boundary, so its answer is authoritative. Detail names the sysctl, and
    # the render contract stays tri-state honest.
    assert by_key["user-namespace"].status == UNAVAILABLE
    assert "sysctl" in by_key["user-namespace"].detail


def test_rootless_runtime_detected():
    r = report_platform_controls(runtime="docker", **LINUX, **DOCKER_ROOTLESS)
    assert "rootless-runtime" in r.summary()["active"]


def test_podman_counts_as_rootless():
    r = report_platform_controls(
        runtime="podman", **LINUX,
        **{**DOCKER_ROOTFUL, "docker_info": lambda: {
            "_podman": True, "SecurityOptions": ["name=seccomp"]}})
    assert "rootless-runtime" in r.summary()["active"]


# ── E203 classification: tier-aware, fail-closed ───────────────────────────

def test_t1_platform_gap_is_warning_never_refusal():
    r = report_platform_controls(runtime="docker", **LINUX, **DOCKER_ROOTFUL)
    refusals, warnings = classify(r, "T1")
    assert refusals == []
    assert any("rootless-runtime" in w for w in warnings)


def test_t2_load_bearing_unavailable_refuses_e203():
    r = report_platform_controls(runtime="docker", **LINUX, **DOCKER_ROOTFUL)
    refusals, _ = classify(r, "T2")
    assert any("rootless-runtime" in x for x in refusals)


def test_t2_unknown_load_bearing_also_refuses():
    # rootless probe can't answer (daemon down) → UNKNOWN → fail-closed for T2
    r = report_platform_controls(runtime="docker", **LINUX, **DAEMON_DOWN,
                                 **{"userns": lambda: True, "cgroup": lambda: True})
    refusals, _ = classify(r, "T2")
    assert any("rootless-runtime" in x and "could not be verified" in x
               for x in refusals)


def test_t2_rootless_platform_passes_classification():
    r = report_platform_controls(runtime="docker", **LINUX, **DOCKER_ROOTLESS)
    refusals, _ = classify(r, "T2")
    assert refusals == []


def test_unknown_tier_is_safe_default():
    r = report_platform_controls(runtime="docker", **LINUX, **DOCKER_ROOTFUL)
    refusals, _ = classify(r, "T99")
    assert refusals == []  # unknown tier designates nothing load-bearing


# ── gate wiring: E203 through run_platform_controls_gate / run_all_gates ───

def test_gate_t1_passes_with_warning_and_records_report():
    profile = get_profile("local-sandbox")
    summary = run_platform_controls_gate(profile, "docker", dict(LINUX, **DOCKER_ROOTFUL))
    assert summary["system"] == "Linux"
    assert "rootless-runtime" in summary["unavailable"]
    assert summary["unknown"] == []


def test_gate_future_t2_refuses_fail_closed():
    """T2 machinery proof: when a tier designates a missing control as
    load-bearing, startup is refused with E203 — the Phase 8 security control."""
    profile = get_profile("local-sandbox")
    from unittest.mock import patch
    with patch("sandbox_kit.gates.classify",
               side_effect=lambda rep, tier: classify(rep, "T2")):
        with pytest.raises(GateFailure) as ei:
            run_platform_controls_gate(profile, "docker",
                                       dict(LINUX, **DOCKER_ROOTFUL))
    assert ei.value.code == "E203"
    assert "rootless-runtime" in ei.value.message
    assert "Startup refused" in ei.value.message


def test_run_all_gates_app_only_has_no_platform_controls():
    probes = _t1_probes()
    results = run_all_gates(get_profile("app-only"), ui_port=8200, probes=probes)
    assert "platform_controls" not in results


def test_run_all_gates_t1_carries_platform_report():
    results = run_all_gates(get_profile("local-sandbox"), ui_port=8100,
                            probes=_t1_probes())
    pc = results["platform_controls"]
    assert pc["system"] == "Linux" and pc["unknown"] == []


def test_run_all_gates_e203_blocks_t1_when_load_bearing_missing():
    """Simulated future regression: if T1 ever designates user-namespace as
    load-bearing (e.g. a rootless-first default), a userns-disabled host must
    refuse with E203 instead of degrading. This is the mutation test for the
    fail-closed contract."""
    from unittest.mock import patch
    with patch("sandbox_kit.gates.classify",
               side_effect=lambda rep, tier: classify(rep, "T2")):
        with pytest.raises(GateFailure) as ei:
            run_all_gates(get_profile("local-sandbox"), ui_port=8100,
                          probes=_t1_probes(**{"userns": lambda: False}))
    assert ei.value.code == "E203"


# ── CLI: `platform` verb ────────────────────────────────────────────────────

def test_cli_platform_human_and_json(capsys):
    assert cli.main(["platform"]) == 0
    human = capsys.readouterr().out
    assert "platform:" in human and "ACTIVE:" in human

    assert cli.main(["platform", "--json"]) == 0
    d = json.loads(capsys.readouterr().out)
    assert d["system"] in ("Linux", "Darwin", "Windows")
    assert len(d["controls"]) >= 7
    assert set(d["summary"]) == {"active", "unavailable", "unknown"}


def test_cli_help_lists_platform():
    """Doc-freshness gate: documented commands must exist in --help."""
    import contextlib
    buf = io_string()
    with contextlib.redirect_stdout(buf):
        try:
            cli.main(["--help"])
        except SystemExit:
            pass
    assert "platform" in buf.getvalue()


# ── red-team findings → permanent regressions ──────────────────────────────

def test_hostile_daemon_strings_never_propagate_into_report():
    """Red-team: a compromised/lying daemon must not be able to inject
    attacker-controlled strings into the report (log/CLI injection)."""
    r = report_platform_controls(
        **LINUX, runtime="docker",
        **{"docker_info": lambda: {"SecurityOptions": [
            'name=seccomp,profile=builtin"><script>alert(1)</script>']}},
    )
    dumped = json.dumps(r.to_dict())
    assert "<script>" not in dumped
    # recognition still works: the seccomp prefix matched, but only the static
    # label ships — detail text is reporter-owned, never daemon-owned
    assert "seccomp" in r.summary()["active"]


def test_all_probes_crashing_degrades_to_full_unknown():
    """Red-team: every probe raising must yield a fully-UNKNOWN report —
    never a crash, never a claim. Unknown load-bearing controls refuse."""
    def boom():
        raise RuntimeError("fuzzed")
    r = report_platform_controls(
        **LINUX, runtime="docker",
        **{"docker_info": boom, "userns": boom, "cgroup": boom, "lsm": boom},
    )
    s = r.summary()
    assert s["active"] == [] and s["unavailable"] == []
    assert {"seccomp", "user-namespace", "rootless-runtime", "lsm",
            "no-new-privileges", "caps-drop-all", "read-only-rootfs",
            "resource-limits"} == set(s["unknown"])
    # fail-closed: T2 (which designates userns+rootless) refuses on unknowns
    refusals, _ = classify(r, "T2")
    assert len(refusals) == 2


# ── doc-freshness gate (roadmap Phase 8 acceptance) ─────────────────────────

def test_doc_freshness_platforms_doc_matches_implementation():
    """The documented matrix and the reporter must agree: every documented
    control key exists in the reporter's output, the documented tri-state
    table matches the shipped constants, and the documented commands exist."""
    from pathlib import Path
    doc = Path("docs/sandbox/platforms.md").read_text()

    # documented controls are exactly the reporter's keys
    r = report_platform_controls(runtime="docker", **LINUX, **DOCKER_ROOTFUL)
    for c in r.controls:
        assert c.key in doc, f"control {c.key} undocumented in platforms.md"

    # documented tri-state table matches shipped constants
    for state in ("ACTIVE", "UNAVAILABLE", "UNKNOWN"):
        assert state in doc

    # documented commands exist in the CLI parser
    import contextlib
    buf = io_string()
    with contextlib.redirect_stdout(buf):
        try:
            cli.main(["--help"])
        except SystemExit:
            pass
    help_text = buf.getvalue()
    assert "platform" in help_text

    # documented CI matrix rows exist in the workflow
    wf = Path(".github/workflows/ci.yml").read_text()
    assert "sandbox-platform-linux" in wf
    assert "sandbox-platform-macos" in wf
    assert "sandbox-platform-arm64" in wf


def io_string():
    import io
    return io.StringIO()
