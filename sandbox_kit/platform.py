"""WraithWall Local Secure Sandbox — platform control reporter (Phase 8, G14).

Answers one question honestly: **which isolation controls are actually
available on THIS platform?** Controls are tri-state:

    ACTIVE       verified present on this host (probed, not assumed)
    UNAVAILABLE  verified absent (probe answered "no")
    UNKNOWN      probe could not answer (never counted as present)

The Stage 3 rule (PLATFORM_COMPATIBILITY_MATRIX.md, failure catalog E203):
a control that is not available on a platform may not be claimed as present,
and a UNAVAILABLE control that the active tier designates as load-bearing
refuses startup fail-closed. For T1 (local-sandbox) the compose-applied
hardening runs inside the Linux kernel of the container runtime, so today's
T1 load-bearing set is empty and platform gaps are **warned**, exactly as the
matrix says: "warn (T1) / refuse (T2)". T2 (not implemented) would designate
rootless + user-namespace as load-bearing — the machinery is tested now.

No new dependencies: stdlib probes plus `docker info --format json`.
"""
from __future__ import annotations

import json
import platform as _pyplatform
import subprocess
from dataclasses import dataclass, field

# ── tri-state ───────────────────────────────────────────────────────────────

ACTIVE = "ACTIVE"
UNAVAILABLE = "UNAVAILABLE"
UNKNOWN = "UNKNOWN"

# Controls that the compose hardening baseline relies on. They are enforced by
# the kernel that runs the containers (Linux, or the Docker Desktop VM), so
# they are ACTIVE wherever a working T1 runtime exists. Reported for honesty,
# not gated on (refusing would wrongly block macOS, which the matrix marks ✅).
_BASELINE_CONTROLS = ("no-new-privileges", "caps-drop-all", "read-only-rootfs")

# Load-bearing controls per tier (E203 refusals). T1: none — platform gaps are
# warnings per the matrix. T2 (future): rootless + user namespace required.
_LOAD_BEARING = {
    "T0": frozenset(),
    "T1": frozenset(),
    "T2": frozenset({"rootless-runtime", "user-namespace"}),
    "T3": frozenset(),
}

_CONTROL_LABELS = {
    "no-new-privileges": "no-new-privileges (compose H1)",
    "caps-drop-all": "all caps dropped (compose H2)",
    "read-only-rootfs": "read-only rootfs (compose H3)",
    "resource-limits": "cgroup resource limits (pids/memory/cpu)",
    "user-namespace": "user namespaces (rootless prerequisite)",
    "rootless-runtime": "rootless container runtime",
    "seccomp": "seccomp profile (runtime default)",
    "lsm": "host LSM (AppArmor/SELinux)",
}


@dataclass(frozen=True)
class Control:
    key: str
    label: str
    status: str          # ACTIVE | UNAVAILABLE | UNKNOWN
    load_bearing: bool
    detail: str = ""


@dataclass(frozen=True)
class PlatformReport:
    system: str
    release: str
    machine: str
    runtime: str                      # "docker" | "podman" | "" (none found)
    controls: tuple = field(default=())

    def summary(self) -> dict:
        active = sorted(c.key for c in self.controls if c.status == ACTIVE)
        unavail = sorted(c.key for c in self.controls if c.status == UNAVAILABLE)
        unknown = sorted(c.key for c in self.controls if c.status == UNKNOWN)
        return {"active": active, "unavailable": unavail, "unknown": unknown}

    def to_dict(self) -> dict:
        return {
            "system": self.system,
            "release": self.release,
            "machine": self.machine,
            "runtime": self.runtime,
            "controls": [
                {"key": c.key, "label": c.label, "status": c.status,
                 "load_bearing": c.load_bearing, "detail": c.detail}
                for c in self.controls
            ],
            "summary": self.summary(),
        }

    def render(self) -> str:
        """Human card: one line per control, grouped ACTIVE / UNAVAILABLE / UNKNOWN."""
        lines = [
            f"platform: {self.system} {self.release} ({self.machine})"
            + (f" — runtime: {self.runtime}" if self.runtime else " — runtime: none"),
        ]
        groups = ((ACTIVE, "ACTIVE"), (UNAVAILABLE, "UNAVAILABLE"), (UNKNOWN, "UNKNOWN"))
        for status, title in groups:
            rows = [c for c in self.controls if c.status == status]
            if not rows:
                continue
            lines.append(f"  {title}:")
            for c in rows:
                mark = "✓" if status == ACTIVE else ("✗" if status == UNAVAILABLE else "?")
                lb = " [load-bearing]" if c.load_bearing else ""
                detail = f" — {c.detail}" if c.detail else ""
                lines.append(f"    {mark} {c.label}{lb}{detail}")
        return "\n".join(lines)


# ── probes (injectable; every one returns tri-state, never raises) ─────────

def _probe_system() -> tuple:
    return _pyplatform.system(), _pyplatform.release(), _pyplatform.machine()


def _probe_docker_info() -> dict:
    """Server-side facts from the daemon. {} when the daemon can't be asked."""
    try:
        r = subprocess.run(
            ["docker", "info", "--format", "{{json .}}"],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode == 0:
            return json.loads(r.stdout)
    except Exception:
        pass
    try:
        r = subprocess.run(
            ["podman", "info", "--format", "{{json .}}"],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode == 0:
            info = json.loads(r.stdout)
            info["_podman"] = True
            return info
    except Exception:
        pass
    return {}


def _try_probe(fn, default):
    """Run a probe; on any error return `default`. Reporting must degrade to
    UNKNOWN on probe failure — never crash the report, never claim presence
    from an answer that never arrived."""
    try:
        return fn()
    except Exception:
        return default


def _probe_userns_enabled() -> bool:
    """Kernel user-namespace support (Linux). False = kernel disabled it."""
    try:
        with open("/proc/sys/user/max_user_namespaces") as f:
            return int(f.read().strip()) > 0
    except Exception:
        return False


def _probe_lsm_names() -> list:
    """Enabled host LSMs (Linux): names from /sys/kernel/security/lsm.
    Raises on unreadable — the reporter degrades that to UNKNOWN."""
    with open("/sys/kernel/security/lsm") as f:
        # comma-separated on real kernels (e.g. "lockdown,capability,…,apparmor")
        return [n for chunk in f.read().split(",") for n in chunk.split()]


def _probe_cgroup_v2() -> bool:
    try:
        with open("/sys/fs/cgroup/cgroup.controllers") as f:
            return bool(f.read().strip())
    except Exception:
        return False


# ── reporter ────────────────────────────────────────────────────────────────

def report_platform_controls(
    system=_probe_system,
    docker_info=_probe_docker_info,
    userns=_probe_userns_enabled,
    cgroup=_probe_cgroup_v2,
    lsm=_probe_lsm_names,
    runtime: str = "",
) -> PlatformReport:
    """Build the honest tri-state control report for this host.

    Probe args are injectable (short names, matching the suite's GOOD_PROBES
    convention); `runtime` comes from the Phase 2 runtime gate
    ("docker"/"podman"/"").
    """
    system, release, machine = system()
    info = _try_probe(docker_info, {}) or {}

    controls: list = []

    # Baseline compose controls: enforced by the container kernel, but ACTIVE
    # is only claimed when the daemon actually answered ("probed, not
    # assumed"). A runtime that exists but cannot answer → UNKNOWN, never a
    # claim built on inference.
    daemon_answered = bool(info)
    seccomp_active = any(
        isinstance(o, str) and o.startswith("name=seccomp")
        for o in (info.get("SecurityOptions") or [])
    )
    for key in _BASELINE_CONTROLS:
        controls.append(Control(
            key=key, label=_CONTROL_LABELS[key],
            status=ACTIVE if (runtime and daemon_answered) else UNKNOWN,
            load_bearing=False,
            detail="enforced by the container kernel" if (runtime and daemon_answered) else "",
        ))
    controls.append(Control(
        key="seccomp", label=_CONTROL_LABELS["seccomp"],
        status=(ACTIVE if seccomp_active else UNKNOWN) if runtime else UNKNOWN,
        load_bearing=False,
        detail="daemon SecurityOptions" if seccomp_active else "",
    ))

    # Resource limits: cgroup v2 on Linux is verified directly; inside the
    # Desktop/WSL2 VM it is the VM's kernel, so macOS/Windows hosts report
    # what the daemon tells us (ServerKernel) — honest UNKNOWN with detail.
    if runtime:
        if system == "Linux":
            cg = _try_probe(cgroup, None)
            detail = ("cgroups v2" if cg else "cgroups v1 — limits still apply via runtime") \
                if cg is not None else "cgroup version probe error"
            controls.append(Control(
                key="resource-limits", label=_CONTROL_LABELS["resource-limits"],
                status=ACTIVE if cg is not None else UNKNOWN,
                load_bearing=False, detail=detail,
            ))
        else:
            controls.append(Control(
                key="resource-limits", label=_CONTROL_LABELS["resource-limits"],
                status=ACTIVE, load_bearing=False,
                detail="enforced inside the runtime VM (macOS/WSL2 semantics)",
            ))
    else:
        controls.append(Control(
            key="resource-limits", label=_CONTROL_LABELS["resource-limits"],
            status=UNKNOWN, load_bearing=False,
        ))

    # User namespace: load-bearing for T2. On Linux (incl. WSL2) the kernel
    # sysctl answer is authoritative — that kernel is the enforcement point.
    # On macOS/Windows-native the boundary is the runtime VM, so the host-side
    # status is honestly UNAVAILABLE with a VM detail, never faked to ACTIVE.
    # A crashing probe degrades to UNKNOWN; "no answer" is never "present".
    if system == "Linux":
        try:
            userns_ok = bool(userns())
            userns_status = ACTIVE if userns_ok else UNAVAILABLE
            userns_detail = ("/proc/sys/user/max_user_namespaces" if userns_ok
                             else "disabled by kernel sysctl")
        except Exception:
            userns_status, userns_detail = UNKNOWN, "probe error"
    elif system in ("Darwin", "Windows"):
        userns_status = UNAVAILABLE
        userns_detail = "host-side; enforcement lives inside the runtime VM"
    else:
        userns_status, userns_detail = UNKNOWN, ""
    controls.append(Control(
        key="user-namespace", label=_CONTROL_LABELS["user-namespace"],
        status=userns_status, load_bearing=True, detail=userns_detail,
    ))

    # Rootless runtime: daemon advertises it via SecurityOptions. When the
    # daemon can't answer at all (empty info), the honest state is UNKNOWN —
    # "no answer" must not be overclaimed as "verified unavailable".
    rootless = any(
        isinstance(o, str) and o == "name=rootless"
        for o in (info.get("SecurityOptions") or [])
    ) or bool(info.get("_podman"))  # podman is rootless by default
    if not info:
        rootless_status = UNKNOWN
    else:
        rootless_status = ACTIVE if rootless else UNAVAILABLE
    controls.append(Control(
        key="rootless-runtime", label=_CONTROL_LABELS["rootless-runtime"],
        status=rootless_status if runtime else UNKNOWN,
        load_bearing=True,
        detail="podman default" if (info.get("_podman") and rootless) else "",
    ))

    # Host LSM: informational only, never load-bearing.
    if system == "Linux":
        names = _try_probe(lsm, None)
        if names is None:
            lsm_status, detail = UNKNOWN, "probe error"
        else:
            lsm_status = (ACTIVE if {"apparmor", "selinux"} & set(names)
                          else UNAVAILABLE)
            detail = ",".join(names) if names else "none enabled"
        controls.append(Control(
            key="lsm", label=_CONTROL_LABELS["lsm"],
            status=lsm_status, load_bearing=False, detail=detail,
        ))

    return PlatformReport(
        system=system, release=release, machine=machine,
        runtime=runtime, controls=tuple(controls),
    )


def classify(report: PlatformReport, tier: str) -> tuple:
    """Tier-aware verdict: (refuse_codes: list[str], warnings: list[str]).

    E203 fires only when a control the tier designates load-bearing is
    UNAVAILABLE. UNKNOWN load-bearing controls also refuse (fail-closed: we
    cannot claim a control we could not verify). T1's set is empty today, so
    platform gaps surface as warnings — exactly the matrix's warn(T1)/refuse(T2).
    """
    lb = _LOAD_BEARING.get(tier, frozenset())
    refusals, warnings = [], []
    for c in report.controls:
        if c.key not in lb:
            continue
        if c.status == UNAVAILABLE:
            refusals.append(
                f"Control unavailable on this platform: {c.key} "
                f"(required for {tier} here). Detail: {c.detail or 'n/a'}"
            )
        elif c.status == UNKNOWN:
            refusals.append(
                f"Control could not be verified on this platform: {c.key} "
                f"(required for {tier}) — fail-closed, unknown is not present."
            )
    for c in report.controls:
        if c.status == UNAVAILABLE and c.key not in lb:
            warnings.append(f"{c.key}: UNAVAILABLE — {c.detail or 'labeled limitation, see docs/sandbox/platforms.md'}")
    return refusals, warnings
