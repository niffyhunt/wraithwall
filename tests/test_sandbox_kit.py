"""Phase 2 sandbox_kit tests — gate matrix, profile flow, state, CLI contract.

Gate failures must carry the exact E-codes from the Stage 3 failure catalog.
Fail-closed: every refusal exits non-zero and writes nothing. The CLI up-flow
is exercised through cli.main() with an isolated sandbox dir (tmp_path).
"""
import builtins
import os

import pytest

from sandbox_kit import cli, compose, state
from sandbox_kit.gates import (
    GateFailure,
    run_all_gates,
    run_platform_gate,
    run_port_gate,
    run_python_gate,
    run_resources_gate,
    run_runtime_gate,
)
from sandbox_kit.profiles import FUTURE_PROFILES, MVP_PROFILES, get_profile


# ── helpers ─────────────────────────────────────────────────────────────────

GOOD_PROBES = {
    "platform": lambda: ("Linux", "6.8"),
    "python": lambda: (3, 12),
    "runtime": lambda: ("/usr/bin/docker", "docker"),
    "compose": lambda rt: True,
    "ram": lambda: 8192,
}


@pytest.fixture()
def sbx_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("WRAITHWALL_SANDBOX_DIR", str(tmp_path / "sbx"))
    return tmp_path / "sbx"


# ── gate matrix (exact E-codes) ─────────────────────────────────────────────

def test_e104_windows_native_refused():
    with pytest.raises(GateFailure) as ei:
        run_platform_gate(probe=lambda: ("Windows", "11"))
    assert ei.value.code == "E104"
    assert "WSL2" in ei.value.message


def test_e103_python_too_old():
    with pytest.raises(GateFailure) as ei:
        run_python_gate(probe=lambda: (3, 11))
    assert ei.value.code == "E103"
    assert "3.12" in ei.value.message


def test_e101_runtime_missing_for_local_sandbox():
    profile = get_profile("local-sandbox")
    with pytest.raises(GateFailure) as ei:
        run_runtime_gate(profile, runtime_probe=lambda: (None, None),
                         compose_probe=lambda rt: False)
    assert ei.value.code == "E101"
    assert "app-only" in ei.value.message  # honest fallback pointer


def test_e102_compose_v1_refused():
    profile = get_profile("local-sandbox")
    with pytest.raises(GateFailure) as ei:
        run_runtime_gate(profile, runtime_probe=lambda: ("/usr/bin/docker", "docker"),
                         compose_probe=lambda rt: False)
    assert ei.value.code == "E102"


def test_e105_low_ram():
    profile = get_profile("local-sandbox")
    with pytest.raises(GateFailure) as ei:
        run_resources_gate(profile, ram_probe=lambda: 2048)
    assert ei.value.code == "E105"
    assert "fail-closed" in ei.value.message


def test_e105_ram_unknown_fails_closed():
    profile = get_profile("local-sandbox")
    with pytest.raises(GateFailure) as ei:
        run_resources_gate(profile, ram_probe=lambda: -1)
    assert ei.value.code == "E105"


def test_e106_explicit_port_busy():
    profile = get_profile("app-only")
    import sandbox_kit.gates as g
    orig = g._port_free
    g._port_free = lambda p: False
    try:
        with pytest.raises(GateFailure) as ei:
            run_port_gate(profile, ui_port=8205)
        assert ei.value.code == "E106"
        assert "8205" in ei.value.message
    finally:
        g._port_free = orig


def test_e106_range_exhausted():
    profile = get_profile("app-only")
    import sandbox_kit.gates as g
    orig = g._port_free
    g._port_free = lambda p: False
    try:
        with pytest.raises(GateFailure) as ei:
            run_port_gate(profile, ui_port=None)
        assert ei.value.code == "E106"
        assert "8200-8299" in ei.value.message
    finally:
        g._port_free = orig


def test_port_autopick_returns_first_free():
    profile = get_profile("app-only")
    import sandbox_kit.gates as g
    orig = g._port_free
    g._port_free = lambda p: p != 8200  # 8200 busy, 8201 free
    try:
        assert run_port_gate(profile, ui_port=None) == 8201
    finally:
        g._port_free = orig


def test_app_only_skips_runtime_gate():
    profile = get_profile("app-only")
    results = run_all_gates(profile, probes={
        **GOOD_PROBES,
        "runtime": lambda: (None, None),      # no docker at all
        "compose": lambda rt: False,
        "ram": lambda: 600,
    })
    assert results["runtime"] == ""


# ── profile model ───────────────────────────────────────────────────────────

def test_unknown_profile_rejected():
    """Phase 11 promoted research-sandbox to a real profile; the remaining
    future names still refuse honestly."""
    with pytest.raises(KeyError):
        get_profile("vm-sandbox")
    with pytest.raises(KeyError):
        get_profile("external-sensor")
    assert "vm-sandbox" in FUTURE_PROFILES
    assert "external-sensor" in FUTURE_PROFILES


def test_mvp_profile_shapes():
    t0 = get_profile("app-only")
    assert t0.tier == "T0" and not t0.requires_runtime and t0.confirmation == "none"
    t1 = get_profile("local-sandbox")
    assert t1.tier == "T1" and t1.requires_runtime and t1.confirmation == "one-time"


# ── CLI flow ────────────────────────────────────────────────────────────────

def test_up_app_only_happy_path(sbx_dir, capsys):
    rc = cli.main(["up", "--profile", "app-only"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "PREPARED" in out
    st = state.read_state("default")
    assert st["state"] == "PREPARED"
    assert st["profile"] == "app-only"
    assert st["gates"]["ui_port"] in range(8200, 8300)


def test_up_idempotent(sbx_dir, capsys):
    assert cli.main(["up", "--profile", "app-only"]) == 0
    capsys.readouterr()
    assert cli.main(["up", "--profile", "app-only"]) == 0
    assert "already prepared" in capsys.readouterr().out


def test_up_profile_switch_refused(sbx_dir, capsys):
    assert cli.main(["up", "--profile", "app-only"]) == 0
    capsys.readouterr()
    rc = cli.main(["up", "--profile", "local-sandbox", "--yes"])
    assert rc == 2
    assert "cannot be silently switched" in capsys.readouterr().out


def _stub_container_layer(monkeypatch, *, egress_ok=True, hardening_ok=True, unhealthy=False):
    """Replace the docker layer so CLI tests never touch a real daemon.

    Returns the list of teardown calls so tests can assert rollback behaviour.
    """
    import sandbox_kit.compose as c
    import sandbox_kit.gates as g

    monkeypatch.setattr(g, "_probe_runtime", lambda: ("/usr/bin/docker", "docker"))
    monkeypatch.setattr(g, "_probe_compose_v2", lambda rt: True)
    monkeypatch.setattr(g, "_probe_free_ram_mb", lambda: 16384)

    torn_down = []
    monkeypatch.setattr(c, "docker_available", lambda: True)
    monkeypatch.setattr(c, "prepare_build_context", lambda dest: dest)
    monkeypatch.setattr(c, "build_images", lambda ctx, log=print: None)
    monkeypatch.setattr(c, "up", lambda project, extra_env=None: None)
    monkeypatch.setattr(c, "app_address", lambda project: "172.30.0.5")
    monkeypatch.setattr(c, "teardown", lambda project: torn_down.append(project))

    def _egress(project, timeout=120):
        if egress_ok:
            return "EGRESS_DENY_OK"
        raise GateFailure("E202", "✗ ISOLATION SELF-CHECK FAILED")

    def _hardening(project, services=None):
        if hardening_ok:
            return {"sb-app": {}, "sb-redis": {}}
        raise GateFailure("E205", "✗ Effective container configuration failed")

    def _require_healthy(project, service="sb-app", timeout=180):
        if not hardening_ok:
            return
        if not egress_ok:
            return
        if unhealthy:
            raise GateFailure("E305", "✗ Service 'sb-app' is not healthy")

    monkeypatch.setattr(c, "verify_egress_denied", _egress)
    monkeypatch.setattr(c, "verify_hardening", _hardening)
    monkeypatch.setattr(c, "require_healthy", _require_healthy)

    # Phase 4 seed layer: the one-shot seed completes and reports the digest
    # the launcher's own corpus module computes.
    from sandbox_kit.seed import corpus as _corpus
    monkeypatch.setattr(c, "wait_seed_complete", lambda project, timeout=300: 0)
    monkeypatch.setattr(c, "read_seed_receipt", lambda project: {
        "events": 283, "sessions": 24,
        "corpus_sha256": _corpus.corpus_digest(),
        "seed_version": "1",
    })
    return torn_down


def test_up_local_sandbox_boots_hardened_project(sbx_dir, capsys, monkeypatch):
    _stub_container_layer(monkeypatch)
    rc = cli.main(["up", "--profile", "local-sandbox", "--yes"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "RUNNING" in out
    assert "published ports:   none" in out
    st = state.read_state("default")
    assert st["state"] == "RUNNING"
    assert st["ack"] is True
    assert st["project"].startswith("ww-sb-")
    assert (state.sandbox_dir("default") / "ack.txt").exists()


def test_up_rolls_back_when_egress_canary_fails(sbx_dir, capsys, monkeypatch):
    """E202 must refuse, tear down, and never report RUNNING."""
    torn_down = _stub_container_layer(monkeypatch, egress_ok=False)
    rc = cli.main(["up", "--profile", "local-sandbox", "--yes"])
    assert rc == 2
    out = capsys.readouterr().out
    assert "ISOLATION SELF-CHECK FAILED" in out
    assert "Rolled back" in out
    st = state.read_state("default")
    assert st["state"] == "PARTIAL"
    assert st["failed_code"] == "E202"
    assert st["rolled_back"] is True
    assert torn_down, "teardown was not called after a failed self-check"


def test_up_rolls_back_when_hardening_posture_fails(sbx_dir, capsys, monkeypatch):
    torn_down = _stub_container_layer(monkeypatch, hardening_ok=False)
    rc = cli.main(["up", "--profile", "local-sandbox", "--yes"])
    assert rc == 2
    assert "Effective container configuration failed" in capsys.readouterr().out
    st = state.read_state("default")
    assert st["state"] == "PARTIAL"
    assert st["failed_code"] == "E205"
    assert torn_down, "teardown was not called after a failed posture check"


def test_up_rolls_back_when_app_never_becomes_healthy(sbx_dir, capsys, monkeypatch):
    """E305: RUNNING must never be claimed without a healthy app."""
    torn_down = _stub_container_layer(monkeypatch, unhealthy=True)
    rc = cli.main(["up", "--profile", "local-sandbox", "--yes"])
    assert rc == 2
    assert "not healthy" in capsys.readouterr().out
    st = state.read_state("default")
    assert st["state"] == "PARTIAL"
    assert st["failed_code"] == "E305"
    assert torn_down, "teardown was not called after a health failure"


def test_up_local_sandbox_requires_ack(sbx_dir, capsys, monkeypatch):
    """The one-time acknowledgement must gate the container path."""
    import sandbox_kit.gates as g
    monkeypatch.setattr(g, "_probe_runtime", lambda: ("/usr/bin/docker", "docker"))
    monkeypatch.setattr(g, "_probe_compose_v2", lambda rt: True)
    monkeypatch.setattr(g, "_probe_free_ram_mb", lambda: 16384)
    monkeypatch.setattr(builtins, "input", lambda *a: "n")
    rc = cli.main(["up", "--profile", "local-sandbox"])
    assert rc == 2
    assert "acknowledgement declined" in capsys.readouterr().out
    assert state.read_state("default") is None


def test_up_ack_declined_refuses_and_writes_nothing(sbx_dir, capsys, monkeypatch):
    import sandbox_kit.gates as g
    monkeypatch.setattr(g, "_probe_runtime", lambda: ("/usr/bin/docker", "docker"))
    monkeypatch.setattr(g, "_probe_compose_v2", lambda rt: True)
    monkeypatch.setattr(g, "_probe_free_ram_mb", lambda: 16384)
    monkeypatch.setattr(builtins, "input", lambda *a: "n")
    rc = cli.main(["up", "--profile", "local-sandbox"])
    assert rc == 2
    assert "acknowledgement declined" in capsys.readouterr().out
    assert state.read_state("default") is None


def test_up_gate_failure_refuses_fail_closed(sbx_dir, capsys, monkeypatch):
    import sandbox_kit.gates as g
    monkeypatch.setattr(g, "_probe_free_ram_mb", lambda: 100)  # below app-only floor? no—512
    rc = cli.main(["up", "--profile", "local-sandbox", "--yes"])
    assert rc == 2
    out = capsys.readouterr().out
    assert "E105" in out
    assert "Nothing was started" in out
    assert state.read_state("default") is None


def test_destroy_refuses_without_yes(sbx_dir, capsys):
    """Phase 9: the Stage 3 contract (refuse without --yes) is real."""
    assert cli.main(["up", "--profile", "app-only"]) == 0
    capsys.readouterr()
    rc = cli.main(["destroy"])
    assert rc == 2
    out = capsys.readouterr().out
    assert "refusing to destroy" in out
    assert "destroy --yes" in out
    # nothing was destroyed: state survives
    assert state.read_state("default") is not None


def test_destroy_receipt_and_fresh_restart(sbx_dir, capsys):
    assert cli.main(["up", "--profile", "app-only"]) == 0
    capsys.readouterr()
    rc = cli.main(["destroy", "--yes"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "verified_empty=True" in out
    assert state.read_state("default") is None
    # up after destroy starts fresh without complaint
    assert cli.main(["up", "--profile", "app-only"]) == 0
    assert state.read_state("default")["state"] == "PREPARED"


def test_destroy_when_absent_is_idempotent(sbx_dir, capsys):
    rc = cli.main(["destroy", "--yes"])
    assert rc == 0
    assert "verified_empty=True" in capsys.readouterr().out


def test_name_traversal_refused(sbx_dir):
    with pytest.raises(ValueError):
        state.sandbox_dir("../evil")


def test_unreadable_marker_reports_partial_not_crash(sbx_dir):
    d = state.sandbox_dir("default")
    d.mkdir(parents=True)
    (d / "state.json").write_text("{corrupt")
    st = state.read_state("default")
    assert st["state"] == "PARTIAL"


def test_phase5_lifecycle_refuses_cleanly_when_unbuilt(sbx_dir, capsys):
    """Phase 5 commands are real, but every state-touching verb fails closed
    on a sandbox that does not exist — with a reason, never an invention."""
    assert cli.main(["logs"]) == 2
    assert "no project" in capsys.readouterr().out
    for cmd in ["inspect", "export", "reset"]:
        assert cli.main([cmd]) == 2, cmd
        assert "does not exist" in capsys.readouterr().out
    # recover on UNBUILT is a truthful no-op
    assert cli.main(["recover"]) == 0
    assert "nothing to recover" in capsys.readouterr().out


def test_phase5_recover_corrects_lying_running_state(sbx_dir, capsys, monkeypatch):
    """State says RUNNING, daemon says nothing is live → recover corrects the
    marker to STOPPED (truth) instead of leaving a lie in place (E301)."""
    import sandbox_kit.compose as c
    monkeypatch.setattr(c, "docker_available", lambda: True)
    monkeypatch.setattr(c, "ps", lambda project: [])
    state.write_state("default", {
        "state": "RUNNING", "profile": "local-sandbox", "tier": "T1",
        "ack": True, "project": "ww-sb-default",
        "seed": {"events": 283, "sessions": 24,
                 "corpus_sha256": "x", "seed_version": "1"},
    })
    assert cli.main(["recover"]) == 0
    out = capsys.readouterr().out
    assert "correcting to STOPPED" in out
    assert state.read_state("default")["state"] == "STOPPED"


def test_phase5_recover_tears_down_orphans(sbx_dir, capsys, monkeypatch):
    """Interrupted startup left live containers → recover removes them (G8:
    no orphaned sandbox processes) and leaves PARTIAL + a clean-start hint."""
    import sandbox_kit.compose as c
    monkeypatch.setattr(c, "docker_available", lambda: True)
    monkeypatch.setattr(c, "ps", lambda project: [
        {"Service": "sb-app", "State": "running"},
        {"Service": "sb-redis", "State": "running"},
    ])
    torn = []
    monkeypatch.setattr(c, "teardown", lambda p: torn.append(p))
    state.write_state("default", {
        "state": "PREPARED", "profile": "local-sandbox", "tier": "T1",
        "ack": True, "project": "ww-sb-default",
    })
    assert cli.main(["recover"]) == 0
    out = capsys.readouterr().out
    assert "tearing down" in out and torn == ["ww-sb-default"]
    assert state.read_state("default")["state"] == "PARTIAL"
    assert "rolled_back" in state.read_state("default")


def test_phase5_export_gates_on_secrets_and_never_overwrites(sbx_dir, capsys,
                                                             monkeypatch):
    """E307: a bundle that scans dirty is DELETED, not delivered; an existing
    destination is never silently overwritten."""
    import sandbox_kit.compose as c
    state.write_state("default", {
        "state": "RUNNING", "profile": "local-sandbox", "tier": "T1",
        "ack": True, "project": "ww-sb-default",
        "seed": {"events": 1, "sessions": 1,
                 "corpus_sha256": "x", "seed_version": "1"},
    })
    dest = sbx_dir / "export-here"

    # Existing destination → refuse before touching anything.
    dest.mkdir()
    rc = cli.main(["export", "--out", str(dest)])
    assert rc == 2 and "already exists" in capsys.readouterr().out
    dest.rmdir()

    # Dirty bundle → assembled, scanned, deleted, refused (E307).
    def _fake_export(project, d):
        d.mkdir(parents=True, exist_ok=False)
        (d / "synthetic.jsonl").write_text(
            'xoxb-" + "A" * 20 + "\n')
        return {"marker": "m", "files": {}}
    monkeypatch.setattr(c, "export_bundle", _fake_export)
    rc = cli.main(["export", "--out", str(dest)])
    assert rc == 2 and "E307" in capsys.readouterr().out
    assert not dest.exists() and not dest.with_name(dest.name + ".partial").exists()

    # Clean bundle → delivered with the manifest.
    def _fake_export_clean(project, d):
        d.mkdir(parents=True, exist_ok=False)
        (d / "synthetic.jsonl").write_text("LOCAL\n")
        return {"marker": "WRAITHWALL-LOCAL-SYNTHETIC", "files": {
            "synthetic.jsonl": {"bytes": 6, "sha256": "a" * 64}}}
    monkeypatch.setattr(c, "export_bundle", _fake_export_clean)
    monkeypatch.setattr(c, "scan_bundle_for_secrets", lambda d: [])
    rc = cli.main(["export", "--out", str(dest)])
    assert rc == 0
    assert "sanitized export written" in capsys.readouterr().out
    assert (dest / "synthetic.jsonl").exists()


def test_phase5_reset_requires_confirmation_and_purges(sbx_dir, capsys,
                                                       monkeypatch):
    """`reset` purges disposable telemetry (G8) with an explicit confirmation,
    and clears the seed info from the state marker."""
    import sandbox_kit.compose as c
    monkeypatch.setattr(c, "reset_bundle",
                        lambda project: ["volume:/state/synthetic",
                                         "redis: 42 keys"])
    state.write_state("default", {
        "state": "RUNNING", "profile": "local-sandbox", "tier": "T1",
        "ack": True, "project": "ww-sb-default",
        "seed": {"events": 283, "sessions": 24,
                 "corpus_sha256": "x", "seed_version": "1"},
    })
    # Declined confirmation → nothing happens.
    monkeypatch.setattr("builtins.input", lambda *a: "n")
    assert cli.main(["reset"]) == 2
    assert "declined" in capsys.readouterr().out
    assert state.read_state("default")["seed"]
    # Confirmed → purge + state seed cleared.
    monkeypatch.setattr("builtins.input", lambda *a: "y")
    assert cli.main(["reset"]) == 0
    out = capsys.readouterr().out
    assert "reset complete" in out and "redis: 42 keys" in out
    assert state.read_state("default")["seed"] is None


def test_phase5_upgrade_refuses_while_running(sbx_dir, capsys):
    state.write_state("default", {
        "state": "RUNNING", "profile": "local-sandbox", "tier": "T1",
        "ack": True, "project": "ww-sb-default",
    })
    assert cli.main(["upgrade"]) == 2
    assert "Stop it first" in capsys.readouterr().out


def test_phase5_uplink_off_by_default_and_gated(sbx_dir, capsys, monkeypatch):
    """The uplink never starts silently: default up publishes nothing; the
    opt-in path brings the proxy up and re-runs the in-app egress canary."""
    _stub_container_layer(monkeypatch)
    started = {}
    monkeypatch.setattr(compose, "up",
                        lambda project, extra_env=None, profiles=None:
                        started.setdefault("profiles", profiles))
    rc = cli.main(["up", "--profile", "local-sandbox", "--yes"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "published ports:   none" in out
    assert "UI uplink: off (default)" in out
    st = state.read_state("default")
    assert st["uplink_port"] is None

    # Opt-in: second up() carries the uplink profile, app addr, and port; the
    # in-app canary result is shown. (A DESTROYED marker gives the second up a
    # clean fresh-start path without patching read_state.)
    monkeypatch.setenv("WRAITHWALL_SANDBOX_UPLINK", "1")
    state.write_state("default", {"state": "DESTROYED"})
    monkeypatch.setattr(compose, "address_on",
                        lambda project, service, net: "172.31.0.9")
    calls = {"require": [], "canary": 0}
    monkeypatch.setattr(compose, "require_healthy",
                        lambda project, service="sb-app", timeout=180:
                        calls["require"].append(service))
    monkeypatch.setattr(compose, "verify_egress_denied_all",
                        lambda project: "UPLINK_EGRESS_DENY_OK")
    monkeypatch.setattr(compose, "uplink_port", lambda project: 8180)
    monkeypatch.setattr(compose, "probe_loopback_publish",
                        lambda host_port, timeout=8.0: True)
    rc = cli.main(["up", "--profile", "local-sandbox", "--yes"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "published ports:   127.0.0.1:8180" in out
    assert "UPLINK_EGRESS_DENY_OK" in out
    assert "sb-uplink" in calls["require"]
    assert state.read_state("default")["uplink_port"] == 8180


    # E107 fail-closed probe: a healthy proxy on a host whose firewall eats
    # host->published-port traffic must refuse startup, not report a UI that
    # cannot be reached. (Verified live: ufw OUTPUT policy DROP discards
    # host-originated packets to the new bridge subnet while the container
    # healthcheck — container->itself — still passes.)
    state.write_state("default", {"state": "DESTROYED"})
    monkeypatch.setattr(compose, "uplink_port", lambda project: 8180)
    monkeypatch.setattr(compose, "probe_loopback_publish",
                        lambda host_port, timeout=8.0: False)
    rc = cli.main(["up", "--profile", "local-sandbox", "--yes"])
    assert rc == 2
    out = capsys.readouterr().out
    assert "cannot reach 127.0.0.1" in out
    assert "ufw allow out" in out
    assert "172.16.0.0/12" in out
    assert state.read_state("default")["state"] == "PARTIAL"
    # Reachable host: the probe passes and up succeeds.
    state.write_state("default", {"state": "DESTROYED"})
    monkeypatch.setattr(compose, "probe_loopback_publish",
                        lambda host_port, timeout=8.0: True)
    rc = cli.main(["up", "--profile", "local-sandbox", "--yes"])
    assert rc == 0
    assert state.read_state("default")["uplink_port"] == 8180


def test_replay_refuses_without_running_sandbox(sbx_dir, capsys):
    """Phase 4: replay is real but requires a RUNNING local-sandbox."""
    assert cli.main(["replay"]) == 2
    assert "not RUNNING" in capsys.readouterr().out


def test_read_ttylog_is_binary_safe(sbx_dir, capsys, monkeypatch):
    """Regression (Phase 4 live run): ttylogs contain arbitrary bytes (length
    prefixes, payloads with bytes >= 0x80). The docker-exec capture must be
    binary mode — strict UTF-8 text capture explodes before parse_ttylog runs.
    Pins the _run_bytes boundary with a non-UTF-8 payload."""
    from subprocess import CompletedProcess
    import struct

    # Real cowrie ttylog frame: hdr "<iLiiLL" = [op=3 WRITE][tty][len=3]
    # [direction=1 INPUT][sec][usec], payload b"\xefid" (0xEF start byte pins
    # binary-safety through the docker-exec capture boundary).
    blob = struct.pack("<iLiiLL", 3, 0, 3, 1, 1767576800, 0) + b"\xefid"
    monkeypatch.setattr(compose, "container_id", lambda *a, **k: "cid0")
    monkeypatch.setattr(
        compose, "_run_bytes",
        lambda cmd, timeout=None, check=True: CompletedProcess(
            cmd, 0, stdout=blob, stderr=b""))

    state.write_state("default", {
        "state": "RUNNING", "profile": "local-sandbox", "tier": "T1",
        "ack": True, "project": "p",
        "seed": {"events": 1, "sessions": 1,
                 "corpus_sha256": "x", "seed_version": "1"},
    })
    assert cli.main(["replay", "--session", "aabbccdd11223344"]) == 0
    out = capsys.readouterr().out
    assert "1 frames" in out and "id" in out


def test_stop_with_no_sandbox_is_a_noop(sbx_dir, capsys):
    assert cli.main(["stop"]) == 0
    assert "nothing to stop" in capsys.readouterr().out


def test_status_unbuilt(sbx_dir, capsys):
    assert cli.main(["status"]) == 0
    out = capsys.readouterr().out
    assert "UNBUILT" in out
    assert "UNBUILT" in out.split("NOT guaranteed malware containment")[0]


def test_profiles_output_lists_all_five(sbx_dir, capsys):
    assert cli.main(["profiles"]) == 0
    out = capsys.readouterr().out
    for key in ["app-only", "local-sandbox", "research-sandbox",
                "vm-sandbox", "external-sensor"]:
        assert key in out
