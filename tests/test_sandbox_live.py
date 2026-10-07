"""Live sandbox verification (Phase 3) — opt-in, Docker required.

These tests build the sandbox images, boot the two-plane project, verify the
hardening posture from `docker inspect`, run the egress-deny canary, and check
that teardown leaves nothing behind. They are **opt-in** because they consume
real disk (image layers) and several GB of RAM:

    WRAITHWALL_SANDBOX_LIVE=1 pytest tests/test_sandbox_live.py -v

They are never skipped silently in CI: the roadmap requires these to run on a
machine with headroom (the project's rule is that no space-heavy verification
happens on the production host). A skip here means "not run", not "passed".
"""
from __future__ import annotations

import json
import os
import re
import socket
import tempfile
import time
from pathlib import Path

import pytest
import yaml

from sandbox_kit import cli, compose, images, state
from sandbox_kit import security_posture

pytestmark = pytest.mark.skipif(
    os.environ.get("WRAITHWALL_SANDBOX_LIVE") != "1",
    reason="live sandbox tests are opt-in: set WRAITHWALL_SANDBOX_LIVE=1 "
           "(builds images and boots containers)",
)

PROJECT = "ww-sb-livetest"


def _docker_ok() -> bool:
    return compose.docker_available()


requires_docker = pytest.mark.skipif(not _docker_ok(), reason="docker daemon unavailable")


def _wait_healthy(project: str, service: str, timeout: int = 180) -> str:
    deadline = time.time() + timeout
    last = "unknown"
    while time.time() < deadline:
        cid = compose.container_id(project, service)
        if cid:
            state = compose.inspect(cid).get("State") or {}
            last = ((state.get("Health") or {}).get("Status")) or state.get("Status") or "unknown"
            if last == "healthy":
                return last
        time.sleep(3)
    return last


def _tcp_reachable(host: str, port: int, timeout: float = 5.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ── session fixture: build once, boot once, always tear down ───────────────

@pytest.fixture(scope="module")
def built_images():
    if not _docker_ok():
        pytest.skip("docker daemon unavailable")
    with tempfile.TemporaryDirectory(prefix="ww-sbx-live-ctx-") as tmp:
        context = compose.prepare_build_context(Path(tmp) / "ctx")
        # Sanity: the context must not contain host secrets.
        assert not (context / ".env").exists()
        compose.build_images(context)
    return True


@pytest.fixture(scope="module")
def running(built_images):
    compose.down(PROJECT)
    compose.up(PROJECT)
    try:
        yield PROJECT
    finally:
        compose.teardown(PROJECT)


# ── tests ──────────────────────────────────────────────────────────────────

def _compose_app_tmpfs() -> list:
    """The `sb-app` tmpfs mounts exactly as compose declares them.

    Same single-source-of-truth rule as the environment. This test originally
    listed its writable mounts by hand and missed one of them, which made the
    import fail with EROFS and looked like an image bug when it was a test bug.
    """
    doc = yaml.safe_load(compose.COMPOSE_FILE.read_text())
    args = []
    for entry in doc["services"]["sb-app"].get("tmpfs") or []:
        args += ["--tmpfs", entry]
    return args


def _compose_app_env() -> list:
    """The `sb-app` environment exactly as compose defines it.

    Derived from the compose file rather than restated here: when this test
    hard-coded its own environment it drifted from the real one and produced a
    false failure (the sandbox-only store paths were missing). One source of
    truth for the environment, same as for the image list and the canary.
    """
    doc = yaml.safe_load(compose.COMPOSE_FILE.read_text())
    args = []
    for key, value in (doc["services"]["sb-app"]["environment"] or {}).items():
        text = str(value)
        if text.startswith("${") and text.endswith("}"):
            inner = text[2:-1]
            name, _, default = inner.partition(":-")
            text = os.environ.get(name) or default
        args += ["--env", f"{key}={text}"]
    return args


@requires_docker
def test_image_can_import_the_oss_package(built_images):
    """Fast, precise signal for the nastiest failure mode in this phase.

    gunicorn exits 3 ("worker failed to boot") for any missing import, and the
    only symptom at the launcher level is "app not healthy". Asserting the
    import directly makes the cause obvious.

    Writable mounts are required even for an import-only run: several modules
    create files or directories at import time (the gateway's audit log, the
    SQLite stores). The tmpfs list comes
    from the compose file; /state is added as a tmpfs because compose uses a
    named volume there and `docker run` has no volume to reuse.

    TESTING=1 is forced so the engine supervisor does not start threads that
    outlive the import (the health test covers full startup).
    """
    result = compose._run([
        "docker", "run", "--rm",
        "--network", "none",
        "--user", "1000:1000",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--read-only",
        *_compose_app_tmpfs(),
        "--tmpfs", "/state:size=64M,mode=1777",
        *_compose_app_env(),
        "--env", "TESTING=1",  # override: import only, no engine threads
        images.APP_IMAGE,
        "python", "-c", "import main; print('IMPORT_OK')",
    ], check=False, timeout=300)
    output = (result.stdout or "") + (result.stderr or "")
    assert "IMPORT_OK" in output, output[-4000:]


@requires_docker
def test_all_four_services_are_created(running):
    rows = compose.ps(running)
    services = {r.get("Service") for r in rows}
    assert services == {"sb-app", "sb-redis", "sb-seed", "sb-busybox",
                        "sb-busybox-t"}


@requires_docker
def test_redis_and_app_reach_healthy(running):
    assert _wait_healthy(running, "sb-redis") == "healthy"
    assert _wait_healthy(running, "sb-app") == "healthy"


@requires_docker
def test_one_shot_services_exit_zero(running):
    assert compose.wait_for_exit(running, "sb-seed") == 0, "seed generator failed"
    assert compose.wait_for_exit(running, "sb-busybox") == 0, "egress canary (app plane) failed"
    assert compose.wait_for_exit(running, "sb-busybox-t") == 0, "egress canary (telemetry plane) failed"


# ── Phase 4: synthetic telemetry end-to-end ────────────────────────────────


def _app_exec(project: str, args: list, timeout: int = 120):
    cid = compose.container_id(project, "sb-app")
    assert cid, "sb-app container not found"
    return compose._run(["docker", "exec", cid] + args,
                        check=False, timeout=timeout)


@requires_docker
def test_seed_receipt_matches_pinned_corpus(running):
    """The seed wrote exactly the deterministic corpus this repo pins."""
    receipt = compose.read_seed_receipt(running)
    from sandbox_kit.seed import corpus
    assert receipt["corpus_sha256"] == corpus.corpus_digest()
    assert receipt["events"] == corpus.record_count()
    assert receipt["sessions"] == 24
    assert receipt["marking"] == "LOCAL"
    assert receipt["tty_logs"] == 24


@requires_docker
def test_seed_log_carries_local_banner(running):
    cid = compose.container_id(running, "sb-seed")
    logs = compose._run(["docker", "logs", cid], check=False).stdout
    assert "[[WRAITHWALL-LOCAL-SYNTHETIC]]" in logs
    assert "seed complete" in logs


@requires_docker
def test_pipeline_ingests_synthetic_sessions(running):
    """The app's OWN watcher consumed the corpus through the REAL pipeline:
    sessions finalized into cowrie_completed:* via the unchanged code path."""
    deadline = time.time() + 120
    snippet = (
        "import json,os,redis\n"
        "r=redis.from_url(os.environ.get('REDIS_URL','redis://127.0.0.1:6379/0'),"
        "decode_responses=True)\n"
        "ids=r.lrange('cowrie_sessions:recent',0,-1)\n"
        "done=[i for i in ids if r.get('cowrie_completed:'+i)]\n"
        "print(json.dumps({'total':len(ids),'completed':len(done)}))"
    )
    total = completed = 0
    while time.time() < deadline:
        result = _app_exec(running, ["python", "-c", snippet])
        if result.returncode == 0:
            payload = json.loads(result.stdout)
            total, completed = payload["total"], payload["completed"]
            if completed >= 24:
                break
        time.sleep(5)
    assert completed >= 24, (
        f"pipeline finalized only {completed}/{total} synthetic sessions "
        "within 120s — the COWRIE_LOG_PATH tail or watcher is broken")


@requires_docker
def test_ingested_sessions_are_local_marked(running):
    """Provenance survives the pipeline: finalized sessions still carry the
    LOCAL sensor name (this is what keeps synthetic data auditable)."""
    snippet = (
        "import json,os,redis\n"
        "r=redis.from_url(os.environ.get('REDIS_URL','redis://127.0.0.1:6379/0'),"
        "decode_responses=True)\n"
        "ids=r.lrange('cowrie_sessions:recent',0,4)\n"
        "sensors=[json.loads(r.get('cowrie_completed:'+i)).get('sensor') for i in ids]\n"
        "print(json.dumps({'sensors':sensors}))"
    )
    result = _app_exec(running, ["python", "-c", snippet])
    assert result.returncode == 0, result.stderr[-300:]
    sensors = json.loads(result.stdout)["sensors"]
    assert sensors and all(s == "ww-sandbox-local" for s in sensors), sensors


@requires_docker
def test_deception_bus_fires_on_synthetic_bait(running):
    """Bait-reading sessions must light the deception bus via the REAL
    handler path (deception_event_bus.HONEYFS_BAIT_MAP matching)."""
    snippet = (
        "import json,os,redis\n"
        "r=redis.from_url(os.environ.get('REDIS_URL','redis://127.0.0.1:6379/0'),"
        "decode_responses=True)\n"
        "n=r.llen('deception:events')\n"
        "print(json.dumps({'deception_events':n}))"
    )
    deadline = time.time() + 60
    n = 0
    while time.time() < deadline:
        result = _app_exec(running, ["python", "-c", snippet])
        if result.returncode == 0:
            n = json.loads(result.stdout)["deception_events"]
            if n > 0:
                break
        time.sleep(5)
    assert n > 0, "no deception-bus events from bait-reading synthetic sessions"


@requires_docker
def test_ship_protocol_accepted_signed_batches(running):
    """The wire-protocol exercise actually happened: the seed's signed batches
    were accepted and are present in the cowrie:log list."""
    receipt = compose.read_seed_receipt(running)
    assert receipt["shipped"], "ship exercise did not run"
    shipped = sum(b["lines"] for b in receipt["shipped"])
    assert shipped == receipt["events"]
    snippet = (
        "import json,os,redis\n"
        "r=redis.from_url(os.environ.get('REDIS_URL','redis://127.0.0.1:6379/0'),"
        "decode_responses=True)\n"
        "print(json.dumps({'cowrie_log_len': r.llen('cowrie:log')}))"
    )
    result = _app_exec(running, ["python", "-c", snippet])
    assert result.returncode == 0, result.stderr[-300:]
    assert json.loads(result.stdout)["cowrie_log_len"] >= shipped


@requires_docker
def test_cli_replay_lists_and_replays_synthetic_sessions(
        running, tmp_path, monkeypatch):
    """The user-facing Phase 4 surface: list + replay one synthetic session."""
    monkeypatch.setenv("WRAITHWALL_SANDBOX_DIR", str(tmp_path / "state"))
    from sandbox_kit import state
    import io
    from contextlib import redirect_stdout

    # Seed the CLI's view of the world from the live project (avoids a second
    # full boot; the state marker is the contract under test here).
    state.write_state("replay-t", {
        "state": "RUNNING", "profile": "local-sandbox", "tier": "T1",
        "ack": True, "project": running,
        "seed": {"events": 283, "sessions": 24,
                 "corpus_sha256": "live", "seed_version": "1"},
    })
    try:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["--name", "replay-t", "replay"])
        out = buf.getvalue()
        assert rc == 0
        assert "LOCAL" in out and "synthetic sessions ingested" in out
        assert "ww-sandbox-local" in out

        # Replay the first listed session by id (16-hex token from the
        # listing line — not the literal four-space split, which would
        # grab the column header when formatting changes).
        m = re.search(r"\b[0-9a-f]{16}\b", out)
        sid = m.group(0) if m else None
        assert sid, "no session id listed: " + out[:400]
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["--name", "replay-t", "replay", "--session", sid])
        out2 = buf.getvalue()
        assert rc == 0
        assert "frames" in out2
        assert "WRAITHWALL-LOCAL-SYNTHETIC" in out2
    finally:
        state.destroy("replay-t")


@requires_docker
def test_egress_denied_from_application_plane(running):
    """G7 dynamic: the canary must report no internet and no DNS path."""
    output = compose.verify_egress_denied(running)
    assert "EGRESS_DENY_OK" in output


@requires_docker
def test_canary_actually_detects_egress(built_images):
    """Negative control for the canary — without this, "OK" is meaningless.

    On a normal bridge (which does have NAT/egress) the same script must fail.
    This is the mutation test for the self-check itself: it caught a real bug
    where Compose interpolation turned the canary into an unconditional pass.
    """
    control = "ww-sb-canarycontrol"
    compose._run(["docker", "network", "rm", control], check=False)
    compose._run(["docker", "network", "create", control])
    try:
        result = compose.run_canary_on_network(control, images.PINNED_IMAGES["busybox"])
        combined = (result.stdout or "") + (result.stderr or "")
        assert result.returncode != 0, (
            "canary passed on a permissive network — the self-check is vacuous"
        )
        assert "EGRESS_PROBE_FAILED" in combined, combined[-400:]
    finally:
        compose._run(["docker", "network", "rm", control], check=False)


@requires_docker
def test_hardening_posture_matches_stage2_baseline(running):
    posture = compose.verify_hardening(running)
    for service, cfg in posture.items():
        assert cfg["privileged"] is False, service
        assert cfg["caps_dropped"] == ["ALL"], service
        assert any("no-new-privileges" in s for s in (cfg["security_opt"] or [])), service
        assert cfg["readonly_rootfs"] is True, service
        assert str(cfg["user"]).split(":")[0] == "1000", service
        assert cfg["memory"], service
        assert cfg["nano_cpus"], service
        assert cfg["pids_limit"], service
        assert cfg["restart"] in ("no", ""), service
        assert cfg["network_mode"] != "host", service


@requires_docker
def test_runtime_uid_is_non_root(running):
    assert compose.runtime_uid(running, "sb-app") == "1000"


@requires_docker
def test_no_published_ports_anywhere(running):
    """Nothing is exposed to the LAN or the internet (G6, strictest form)."""
    for service in ("sb-app", "sb-redis", "sb-seed", "sb-busybox", "sb-busybox-t"):
        cid = compose.container_id(running, service)
        host = compose.inspect(cid).get("HostConfig") or {}
        assert not host.get("PortBindings"), f"{service} publishes {host.get('PortBindings')}"


@requires_docker
def test_no_host_bind_mounts(running):
    for service in ("sb-app", "sb-redis", "sb-seed", "sb-busybox", "sb-busybox-t"):
        cid = compose.container_id(running, service)
        for mount in compose.inspect(cid).get("Mounts") or []:
            assert mount.get("Type") != "bind", f"{service} bind-mounts {mount.get('Source')}"


@requires_docker
def test_networks_are_internal(running):
    for service in ("sb-app", "sb-redis"):
        cid = compose.container_id(running, service)
        nets = (compose.inspect(cid).get("NetworkSettings") or {}).get("Networks") or {}
        assert nets, service
        # NetworkMode must be a project-scoped bridge, never host/default.
        mode = (compose.inspect(cid).get("HostConfig") or {}).get("NetworkMode")
        assert mode not in ("host", "bridge", "default"), f"{service} uses {mode}"


@requires_docker
def test_app_serves_health_from_inside_its_namespace(running):
    """Portable liveness check: the app answers on its own loopback.

    Deliberately *not* a host→container check. See the reachability note below:
    that path depends on the host firewall, not on Docker, so asserting it here
    would fail on correctly configured hardened hosts.
    """
    cid = compose.container_id(running, "sb-app")
    assert cid, "app container not found"
    result = compose._run(
        ["docker", "exec", cid, "curl", "-fsS", "-m", "5",
         "http://127.0.0.1:8000/api/health"],
        check=False, timeout=60,
    )
    assert result.returncode == 0, (result.stdout or "") + (result.stderr or "")


@requires_docker
def test_app_has_no_egress_while_serving(running):
    """Both properties must hold at once: the app serves, and nothing leaves."""
    assert "EGRESS_DENY_OK" in compose.verify_egress_denied(running)
    cid = compose.container_id(running, "sb-app")
    assert compose._run(["docker", "exec", cid, "id", "-u"], check=False).stdout.strip() == "1000"


@requires_docker
def test_host_to_bridge_reachability_is_characterised(running):
    """Informational, non-failing: records a host-firewall dependency.

    Measured on two hosts with an identical Docker version:
      * host without restrictive ufw   → host reaches the container IP: OK
      * host with `ufw` INPUT/FORWARD DROP → BLOCKED (timeout), and **not**
        specific to internal networks — a plain bridge is blocked too.

    Consequence: host→container reachability is a property of the *host
    firewall*, not of this compose file. Phase 5's loopback uplink therefore
    cannot rely on it and must use Docker's published-port mechanism on a
    dedicated non-internal bridge. This test only records the observation so
    the dependency is visible in results instead of being discovered later.
    """
    address = compose.app_address(running)
    assert address, "app container has no bridge address"
    reachable = _tcp_reachable(address, 8000, timeout=5)
    print(f"\n[informational] host -> app bridge address:8000 reachable = {reachable}")


@requires_docker
def test_two_sandboxes_use_distinct_projects_and_networks(running):
    """G11: no shared networks or volumes between concurrent sandboxes."""
    other = "ww-sb-livetest2"
    assert other != running
    compose.down(other)
    compose.up(other)
    try:
        ids_a = {compose.inspect(compose.container_id(running, s))["Id"]
                 for s in ("sb-app", "sb-redis")}
        ids_b = {compose.inspect(compose.container_id(other, s))["Id"]
                 for s in ("sb-app", "sb-redis")}
        assert not (ids_a & ids_b), "containers are shared between projects"

        nets_a = set((compose.inspect(compose.container_id(running, "sb-app"))
                      .get("NetworkSettings") or {}).get("Networks") or {})
        nets_b = set((compose.inspect(compose.container_id(other, "sb-app"))
                      .get("NetworkSettings") or {}).get("Networks") or {})
        assert not (nets_a & nets_b), f"projects share a network: {nets_a & nets_b}"

        for project in (running, other):
            vols = compose._run(["docker", "volume", "ls", "-q", "--filter",
                                 f"label=com.docker.compose.project={project}"]).stdout
            assert vols.strip(), f"{project} has no volumes"
    finally:
        compose.teardown(other)


@requires_docker
def test_teardown_leaves_nothing_running(built_images):
    project = "ww-sb-teardown"
    compose.down(project)
    compose.up(project)
    assert compose.ps(project), "nothing started"
    compose.teardown(project)
    assert compose.ps(project) == [], "containers survived teardown"
    remaining = compose._run(["docker", "network", "ls", "-q",
                              "--filter", f"label=com.docker.compose.project={project}"]).stdout
    assert not remaining.strip(), "networks survived teardown"


# ── CLI end-to-end (the actual acceptance path) ────────────────────────────

@requires_docker
def test_cli_up_boots_sandbox_and_destroy_cleans_up(built_images, tmp_path, monkeypatch):
    monkeypatch.setenv("WRAITHWALL_SANDBOX_DIR", str(tmp_path / "state"))

    rc = cli.main(["--name", "e2e", "up", "--profile", "local-sandbox", "-y"])
    assert rc == 0, "sandbox up failed"

    from sandbox_kit import state
    st = state.read_state("e2e")
    assert st is not None
    assert st["state"] == "RUNNING"
    project = st["project"]
    assert compose.ps(project), "up reported RUNNING but no containers exist"

    rc = cli.main(["--name", "e2e", "destroy"])
    assert rc == 0
    assert compose.ps(project) == [], "destroy left containers running"
    assert state.read_state("e2e") is None, "destroy left state behind"


@requires_docker
def test_cli_stop_preserves_state_and_volume(built_images, tmp_path, monkeypatch):
    monkeypatch.setenv("WRAITHWALL_SANDBOX_DIR", str(tmp_path / "state2"))
    assert cli.main(["--name", "stopper", "up", "--profile", "local-sandbox", "-y"]) == 0
    from sandbox_kit import state
    project = state.read_state("stopper")["project"]

    assert cli.main(["--name", "stopper", "stop"]) == 0
    st = state.read_state("stopper")
    assert st["state"] == "STOPPED"
    volumes = compose._run(["docker", "volume", "ls", "-q",
                            "--filter", f"label=com.docker.compose.project={project}"]).stdout
    assert volumes.strip(), "stop removed the state volume (should be preserved)"

    # Clean up without leaving anything behind.
    cli.main(["--name", "stopper", "destroy"])


# ── Phase 5: lifecycle verbs against a real project ────────────────────────

@requires_docker
def test_cli_logs_inspect_and_recover_on_live_project(built_images, tmp_path,
                                                      monkeypatch):
    """logs is readable, inspect verifies the live posture, recover is a
    truthful no-op on a healthy sandbox — the Stage 3 contract row by row."""
    import io
    from contextlib import redirect_stdout
    monkeypatch.setenv("WRAITHWALL_SANDBOX_DIR", str(tmp_path / "lc"))
    assert cli.main(["--name", "lc", "up", "--profile", "local-sandbox",
                     "-y"]) == 0
    project = state.read_state("lc")["project"]
    try:
        # logs: readable without follow; service filter works.
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["--name", "lc", "logs", "--service", "sb-app",
                           "--tail", "20"])
        assert rc == 0

        # inspect: live posture re-verified (raises GateFailure on regression).
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["--name", "lc", "inspect"])
        out = buf.getvalue()
        assert rc == 0
        assert "UPLINK" not in out or "not attached" in out
        assert "hardened services" in out or "user=" in out

        # recover on a healthy RUNNING sandbox: truthful no-op, no teardown.
        names = lambda: sorted(r.get("Service") for r in compose.ps(project))
        before = names()
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["--name", "lc", "recover"])
        assert rc == 0
        assert "nothing to recover" in buf.getvalue()
        assert names() == before
    finally:
        cli.main(["--name", "lc", "destroy"])


@requires_docker
def test_cli_export_bundle_is_sanitized_and_local(built_images, tmp_path,
                                                 monkeypatch):
    """Export assembles the LOCAL-marked bundle, the manifest carries SHA-256s,
    and no secret-shaped string survives the E307 scan."""
    import json as _json
    monkeypatch.setenv("WRAITHWALL_SANDBOX_DIR", str(tmp_path / "exp"))
    assert cli.main(["--name", "exp", "up", "--profile", "local-sandbox",
                     "-y"]) == 0
    project = state.read_state("exp")["project"]
    try:
        dest = tmp_path / "exp" / "bundle"
        rc = cli.main(["--name", "exp", "export", "--out", str(dest)])
        assert rc == 0, "export of the LOCAL corpus must pass the E307 scan"
        manifest = _json.loads((dest / "manifest.json").read_text())
        assert manifest["marker"] == "WRAITHWALL-LOCAL-SYNTHETIC"
        assert "synthetic.jsonl" in manifest["files"]
        for rel, meta in manifest["files"].items():
            assert meta["sha256"] and meta["bytes"] > 0, rel
        tty_files = [r for r in manifest["files"] if r.startswith("tty/")]
        assert len(tty_files) == 24, "all synthetic tty logs must be exported"
    finally:
        cli.main(["--name", "exp", "destroy"])


@requires_docker
def test_cli_reset_purges_telemetry_and_pipeline_state(built_images, tmp_path,
                                                       monkeypatch):
    """Reset returns the sandbox to the clean baseline (G8): corpus, tty logs,
    receipt and pipeline records are gone while the sandbox stays up."""
    monkeypatch.setenv("WRAITHWALL_SANDBOX_DIR", str(tmp_path / "rst"))
    assert cli.main(["--name", "rst", "up", "--profile", "local-sandbox",
                     "-y"]) == 0
    project = state.read_state("rst")["project"]
    try:
        cid = compose.container_id(project, "sb-app")
        assert cid
        rc = cli.main(["--name", "rst", "reset", "-y"])
        assert rc == 0
        # The volume paths are gone.
        r = compose._run_bytes(["docker", "exec", cid, "sh", "-c",
                                "ls /state/synthetic/tty 2>&1; "
                                "ls /state/synthetic/synthetic.jsonl 2>&1; "
                                "ls /state/synthetic/seed_receipt.json 2>&1"],
                               check=False)
        assert r.returncode != 0 or b"No such file" in (r.stdout or b""), \
            "synthetic artifacts must be gone after reset"
        # Pipeline records are gone.
        out = compose._run(["docker", "exec", cid, "python", "-c",
                            "import json,os,redis\n"
                            "r=redis.from_url(os.environ.get('REDIS_URL',"
                            "'redis://127.0.0.1:6379/0'),decode_responses=True)\n"
                            "print(len(r.lrange('cowrie_sessions:recent',0,-1)))"],
                           check=False)
        assert out.stdout.strip() == "0"
        # The state marker no longer claims telemetry.
        assert state.read_state("rst")["seed"] is None
    finally:
        cli.main(["--name", "rst", "destroy"])


@requires_docker
def test_cli_recover_after_forced_partial(built_images, tmp_path, monkeypatch):
    """Interrupted-startup simulation: a PREPARED marker with live containers
    converges to PARTIAL + clean teardown (the E301 recovery path)."""
    monkeypatch.setenv("WRAITHWALL_SANDBOX_DIR", str(tmp_path / "rec"))
    assert cli.main(["--name", "rec", "up", "--profile", "local-sandbox",
                     "-y"]) == 0
    st = state.read_state("rec")
    project = st["project"]
    # Simulate the interrupted state: marker reset to PREPARED while live.
    state.write_state("rec", {**st, "state": "PREPARED"})
    try:
        rc = cli.main(["--name", "rec", "recover"])
        assert rc == 0
        st2 = state.read_state("rec")
        assert st2["state"] == "PARTIAL" and st2.get("rolled_back") is True
        assert compose.ps(project) == [], "recover left containers behind"
    finally:
        cli.main(["--name", "rec", "destroy"])


# ── Phase 6/7: security-state visibility + verify (live) ───────────────────

@requires_docker
def test_collect_security_posture_reads_real_daemon(running):
    """Phase 6: posture collection against real containers returns honest,
    daemon-derived data (not compose-file inference) and all blocks populate."""
    result = security_posture.collect_security_posture(
        "live", project=PROJECT)
    assert result["hardening"]["services_seen"] >= 4
    assert result["hardening"]["privileged"] is False
    assert result["hardening"]["caps_dropped_all"] is True
    assert result["hardening"]["uid_1000"] is True
    assert result["hardening"]["bind_mounts"] == 0
    assert result["egress"]["denied"] is True
    assert result["docker_socket"]["checked"] is True
    assert result["docker_socket"]["reachable"] is False
    assert result["provenance"]["local_marked"] is True
    assert result["provenance"]["digest_matches"] is True
    assert result["errors"] == []


@requires_docker
def test_verify_all_checks_pass_on_running_sandbox(running, tmp_path,
                                                   monkeypatch, capsys):
    """Phase 7: `verify` runs the full checklist against a live boot and every
    check passes — the documented claims, machine-checked."""
    monkeypatch.setenv("WRAITHWALL_SANDBOX_DIR", str(tmp_path / "sec"))
    state.write_state("sec", {"state": "RUNNING", "project": PROJECT,
                              "profile": "local-sandbox", "tier": "T1"})
    rc = cli.main(["--name", "sec", "verify", "--json"])
    out = capsys.readouterr().out
    # --json prints the document, then the human verdict line(s); raw_decode
    # takes the first JSON value and ignores the trailer. On failure, surface
    # the verdict so the failed check names are IN the assertion, not lost to
    # capsys (this test once failed opaquely for exactly that reason).
    doc, _ = json.JSONDecoder().raw_decode(out)
    failed = [c for c in doc["checks"] if c["status"] != "pass"]
    assert rc == 0, f"verify rc={rc}; failed/unknown checks: {failed}; errors: {doc['errors']}"
    assert {c["id"] for c in doc["checks"]} == \
        {c[0] for c in security_posture.SECURITY_CHECKS}
    assert all(c["status"] == "pass" for c in doc["checks"]), failed


@requires_docker
def test_status_security_card_against_live_daemon(running, tmp_path,
                                                  monkeypatch, capsys):
    monkeypatch.setenv("WRAITHWALL_SANDBOX_DIR", str(tmp_path / "sec2"))
    state.write_state("sec2", {"state": "RUNNING", "project": PROJECT,
                               "profile": "local-sandbox", "tier": "T1"})
    rc = cli.main(["--name", "sec2", "status", "--security"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "[✓]" in out and "isolation checks:" in out
    assert "NOT guaranteed malware containment" in out  # non-claims footer
