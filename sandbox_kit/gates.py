"""Fail-closed prerequisite gates (Phase 2) — E101..E106.

Every probe is injectable so tests can simulate any host. Gate failures exit
non-zero with the exact E-code message from the Stage 3 failure catalog.
Fail-closed rule: absence, misconfiguration, or probe errors always refuse
startup — never a silent fallback to an unsafe mode.
"""
from __future__ import annotations

import platform
import re
import shutil
import socket
import subprocess
import sys

from sandbox_kit.platform import classify, report_platform_controls
from sandbox_kit.profiles import Profile


# ── failure type ────────────────────────────────────────────────────────────

class GateFailure(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


def _fail(code: str, lines: list) -> GateFailure:
    body = "\n".join(lines)
    docs = "Docs: docs/sandbox/quickstart.md"
    return GateFailure(
        code,
        f"{body}\n  Startup refused (fail-closed). Nothing was started.\n  Code: {code}\n  {docs}",
    )


# ── probes (all injectable via the run_* functions' probe args) ────────────

def _probe_platform() -> tuple:
    return platform.system(), platform.release()


def _probe_python() -> tuple:
    return sys.version_info[:2]


def _probe_runtime() -> tuple:
    docker = shutil.which("docker")
    podman = shutil.which("podman")
    if docker:
        return docker, "docker"
    if podman:
        return podman, "podman"
    return None, None


def _probe_compose_v2(runtime: str) -> bool:
    if not runtime:
        return False
    try:
        r = subprocess.run(
            [runtime, "compose", "version", "--short"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            v = (r.stdout.strip() or "0").lstrip("v")
            m = re.match(r"(\d+)", v)
            if m:
                return int(m.group(1)) >= 2
    except Exception:
        pass
    try:
        r = subprocess.run(
            [runtime, "compose"],
            capture_output=True, text=True, timeout=10,
        )
        return r.returncode == 0 and "v2" in (r.stdout + r.stderr).lower()
    except Exception:
        return False


def _probe_free_ram_mb() -> int:
    try:
        import psutil  # type: ignore
        return int(psutil.virtual_memory().available / (1024 * 1024))
    except Exception:
        pass
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable"):
                    return int(int(line.split()[1]) / 1024)
    except Exception:
        pass
    return -1  # unknown → treated as failure (fail-closed)


def _port_free(port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", port))
            return True
    except OSError:
        return False
    except Exception:
        return False


def find_free_port_in_range(lo: int, hi: int) -> int:
    """Return the first free loopback port in [lo, hi], else -1."""
    for p in range(lo, hi + 1):
        if _port_free(p):
            return p
    return -1


# ── gate implementations ────────────────────────────────────────────────────

def run_platform_gate(probe=_probe_platform) -> None:
    system, _release = probe()
    if system == "Windows":
        raise _fail("E104", [
            "✗ Windows native is not supported (sandbox uses POSIX-only components).",
            "  Fix:  install WSL2 + Docker Desktop, run inside WSL2.",
        ])


def run_python_gate(probe=_probe_python) -> None:
    major, minor = probe()
    if (major, minor) < (3, 12):
        raise _fail("E103", [
            f"✗ Python 3.12+ required (found {major}.{minor}).",
            "  Fix:  install Python 3.12 or newer, then re-run.",
        ])


def run_runtime_gate(profile: Profile, runtime_probe=_probe_runtime,
                     compose_probe=_probe_compose_v2) -> str:
    """Return the runtime binary path. Raises E101/E102 when unusable."""
    if not profile.requires_runtime:
        return ""
    runtime, kind = runtime_probe()
    if not runtime:
        raise _fail("E101", [
            "✗ Docker/Podman not found.",
            "  The local-sandbox profile requires a container runtime.",
            "  Fix:  install Docker Desktop or Engine, then re-run: wraithwall sandbox up",
            "  Or:   start without containers:  wraithwall sandbox up --profile app-only",
        ])
    if not compose_probe(runtime):
        raise _fail("E102", [
            "✗ docker compose v2 required (found v1 / none).",
            "  Fix:  Docker Desktop ≥ 24 or docker-compose-plugin, then re-run.",
        ])
    return runtime


def run_resources_gate(profile: Profile, ram_probe=_probe_free_ram_mb) -> int:
    free_mb = ram_probe()
    if free_mb < profile.min_free_ram_mb:
        shown = f"{free_mb} MB" if free_mb >= 0 else "unknown"
        raise _fail("E105", [
            "✗ Not enough free resources for the selected profile:",
            f"    RAM: {shown} free (need ≥ {profile.min_free_ram_mb} MB)",
            "  Fix:  free memory, or use --profile app-only (no containers)."
            if profile.key != "app-only" else
            "  Fix:  free memory (app-only needs ≥ 512 MB).",
        ])
    return free_mb


def run_platform_controls_gate(profile: Profile, runtime: str,
                               platform_probes: dict) -> dict:
    """G14 — platform control report + E203 classification (Phase 8).

    Runs for container profiles after the runtime gate: controls only mean
    something once we know a runtime exists. A load-bearing control that is
    UNAVAILABLE (or UNKNOWN — fail-closed) refuses startup with E203. Non-
    load-bearing gaps print honest warnings; nothing degrades silently.

    Returns the serializable report summary for the state file.
    """
    report = report_platform_controls(runtime=runtime, **platform_probes)
    refusals, warnings = classify(report, profile.tier)
    for w in warnings:
        print(f"  ! platform warning: {w}")
    if refusals:
        active, unavail = report.summary()["active"], report.summary()["unavailable"]
        raise _fail("E203", [
            "✗ Load-bearing isolation control(s) unavailable on this platform:",
            *[f"    - {r}" for r in refusals],
            f"  ACTIVE: {', '.join(active) or 'none'}   "
            f"UNAVAILABLE: {', '.join(unavail) or 'none'}",
            "  Paths: (a) run a lower tier, (b) docs/sandbox/platforms.md "
            "for the VM recipe.",
            "  Full report: wraithwall sandbox platform --json",
        ])
    return {
        "system": report.system,
        "release": report.release,
        "machine": report.machine,
        "runtime": report.runtime,
        **report.summary(),
    }


def run_port_gate(profile: Profile, ui_port: int | None) -> int:
    """Pick/verify the loopback UI port. Returns the chosen port."""
    lo, hi = profile.ui_port_range
    if ui_port is not None:
        if not _port_free(ui_port):
            raise _fail("E106", [
                f"✗ Requested UI port {ui_port} is unavailable.",
                f"  Fix:  wraithwall sandbox ps   (find a running instance) → stop it, or",
                f"        wraithwall sandbox up --ui-port <free-port>",
            ])
        return ui_port
    port = find_free_port_in_range(lo, hi)
    if port < 0:
        raise _fail("E106", [
            f"✗ UI port unavailable. Launcher asked for a free 127.0.0.1 port in {lo}-{hi};",
            "  all busy or bind-restricted.",
            "  Fix:  wraithwall sandbox ps   (find running instance) → stop it, or",
            "        wraithwall sandbox up --ui-port <free-port>",
        ])
    return port


def run_all_gates(profile: Profile, ui_port: int | None = None,
                  probes: dict | None = None) -> dict:
    """Run the full fail-closed gate sequence. Returns gate results dict."""
    probes = probes or {}
    run_platform_gate(probes.get("platform", _probe_platform))
    run_python_gate(probes.get("python", _probe_python))
    runtime = run_runtime_gate(
        profile,
        runtime_probe=probes.get("runtime", _probe_runtime),
        compose_probe=probes.get("compose", _probe_compose_v2),
    )
    run_resources_gate(profile, ram_probe=probes.get("ram", _probe_free_ram_mb))
    port = run_port_gate(profile, ui_port)
    results = {"runtime": runtime, "ui_port": port}
    if runtime:
        # G14 (Phase 8): only meaningful with a container runtime; app-only
        # has no containers, so no controls apply and none are claimed.
        platform_probes = {}
        for probe_key in ("system", "docker_info", "userns", "cgroup"):
            if probe_key in probes:
                platform_probes[probe_key] = probes[probe_key]
        results["platform_controls"] = run_platform_controls_gate(
            profile, runtime, platform_probes)
    return results
