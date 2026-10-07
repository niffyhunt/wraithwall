"""Live Phase 5 uplink tests (opt-in boot).

Boots its own sandbox project with WRAITHWALL_SANDBOX_UPLINK=1 so the default
suite can keep asserting the publish-nothing posture. Proves the three claims
that matter about the uplink:

1. the UI is reachable from the host on 127.0.0.1:<port> (the whole point),
2. the publish is loopback-only and the proxy container is hardened,
3. the in-app egress canary passes with the uplink network attached —
   "non-internal" did not become "internet".

Requires docker + WRAITHWALL_SANDBOX_LIVE=1 like the rest of the live suite.
"""
from __future__ import annotations

import socket
import urllib.request

import pytest
import yaml

from sandbox_kit import cli, compose, state

pytestmark = [
    pytest.mark.skipif(
        __import__("os").environ.get("WRAITHWALL_SANDBOX_LIVE") != "1",
        reason="live suite (set WRAITHWALL_SANDBOX_LIVE=1)"),
]


def _docker_up() -> bool:
    try:
        return compose.docker_available()
    except Exception:
        return False


requires_docker = pytest.mark.skipif(not _docker_up(), reason="docker needed")


def _http_probe(url: str, timeout: float = 4.0) -> int | None:
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except Exception:
        return None


@pytest.fixture(scope="module")
def uplink_env(tmp_path_factory):
    """One sandbox booted with the uplink for the whole module."""
    import os
    state_dir = tmp_path_factory.mktemp("uplink-state")
    old_dir = os.environ.get("WRAITHWALL_SANDBOX_DIR")
    old_uplink = os.environ.get("WRAITHWALL_SANDBOX_UPLINK")
    os.environ["WRAITHWALL_SANDBOX_DIR"] = str(state_dir)
    os.environ["WRAITHWALL_SANDBOX_UPLINK"] = "1"  # the opt-in under test
    try:
        rc = cli.main(["--name", "uplink-live", "up",
                       "--profile", "local-sandbox", "--yes",
                       "--ui-port", "8181"])
        assert rc == 0, "uplink boot failed"
        yield state.read_state("uplink-live")
    finally:
        try:
            cli.main(["--name", "uplink-live", "destroy"])
        except Exception:
            pass
        if old_dir is None:
            os.environ.pop("WRAITHWALL_SANDBOX_DIR", None)
        else:
            os.environ["WRAITHWALL_SANDBOX_DIR"] = old_dir
        if old_uplink is None:
            os.environ.pop("WRAITHWALL_SANDBOX_UPLINK", None)
        else:
            os.environ["WRAITHWALL_SANDBOX_UPLINK"] = old_uplink


@requires_docker
def test_uplink_serves_ui_on_host_loopback(uplink_env):
    """The decisive positive: http://127.0.0.1:<port> answers from the host."""
    port = uplink_env["uplink_port"]
    assert port == 8181
    # /api/health is the endpoint `up` itself gates on; through the proxy it
    # must answer the same way.
    status = _http_probe(f"http://127.0.0.1:{port}/api/health")
    assert status == 200, "UI not reachable through the loopback uplink"


@requires_docker
def test_uplink_publish_is_loopback_only_and_hardened(uplink_env):
    """127.0.0.1 binding + the standard hardening posture on sb-uplink."""
    st = uplink_env
    project = st["project"]
    cid = compose.container_id(project, "sb-uplink")
    assert cid, "sb-uplink container missing"
    d = compose.inspect(cid)
    host = d.get("HostConfig") or {}
    cfg = d.get("Config") or {}
    # Loopback-only publish, verified from the daemon (not the compose file).
    bindings = (d.get("NetworkSettings") or {}).get("Ports") or {}
    for binding in bindings.get("8000/tcp") or []:
        assert binding.get("HostIp") == "127.0.0.1", binding
    # The proxy runs under the same hardening as every other service.
    assert (host.get("CapDrop") or []) == ["ALL"]
    assert "no-new-privileges" in " ".join(host.get("SecurityOpt") or [])
    assert host.get("ReadonlyRootfs") is True
    assert str(cfg.get("User") or "").split(":")[0] == "1000"
    assert host.get("Privileged") is not True


@requires_docker
def test_uplink_does_not_break_egress_denial(uplink_env):
    """In-app canary with the uplink attached: the app still has no route out."""
    st = uplink_env
    verdict = compose.verify_egress_denied_all(st["project"])
    assert verdict == "UPLINK_EGRESS_DENY_OK"
