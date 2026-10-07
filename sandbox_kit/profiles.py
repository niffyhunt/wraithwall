"""WraithWall Local Secure Sandbox — profile model.

Three profiles ship: T0 (app-only) and T1 (local-sandbox) are the MVP pair;
T2 (research-sandbox, Phase 11) is the higher-isolation untrusted-content
profile that requires a rootless-capable runtime, a per-session confirmation,
and an explicit per-session host allowlist. It never activates silently and
its confirmation is per-session by design — no stored "always allow".
`vm-sandbox`/`external-sensor` remain honest pointers to capabilities this
repository does not ship.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Profile:
    key: str
    tier: str
    purpose: str
    requires_runtime: bool          # container runtime needed?
    min_free_ram_mb: int
    ui_port_range: tuple            # loopback port scan range for the launcher
    confirmation: str               # one-time | none
    data_source: str


MVP_PROFILES = {
    "app-only": Profile(
        key="app-only",
        tier="T0",
        purpose="Run the WraithWall app locally with zero attacker-like input — code, routes, UI, tests.",
        requires_runtime=False,
        min_free_ram_mb=512,
        ui_port_range=(8200, 8299),
        confirmation="none",
        data_source="None (no telemetry generated)",
    ),
    "local-sandbox": Profile(
        key="local-sandbox",
        tier="T1",
        purpose="Full synthetic telemetry experience: dashboards, SSE, TTY replay, correlation, MITRE mapping.",
        requires_runtime=True,
        min_free_ram_mb=4096,
        ui_port_range=(8100, 8199),
        confirmation="one-time",
        data_source="Synthetic seed generator (repo-shipped, fixed-seed). LOCAL data only.",
    ),
    "research-sandbox": Profile(
        key="research-sandbox",
        tier="T2",
        purpose=(
            "Untrusted-content testing: the existing detonation stack fetches "
            "ONLY developer-listed hosts through a deny-by-default egress "
            "proxy. Improved isolation — NOT hostile-code containment."
        ),
        requires_runtime=True,
        min_free_ram_mb=6144,
        ui_port_range=(8300, 8399),
        # Per-session: every single `up` re-asks. Nothing is persisted (no
        # ack.txt reuse), so a stored "always allow" cannot come to exist.
        confirmation="per-session",
        data_source=(
            "Developer-supplied URLs (fetched only through the T2 egress "
            "proxy) + the T1 synthetic corpus. No real attacker traffic."
        ),
    ),
}

FUTURE_PROFILES = {
    "vm-sandbox": (
        "T3 (VM-backed isolation) is a documented recipe only — no VM tooling "
        "exists in this repository yet."
    ),
    "external-sensor": (
        "external-sensor is not a local profile. It ships telemetry to a real "
        "deployment using an operator-issued sensor key and is never enabled "
        "by a local sandbox command."
    ),
}


def get_profile(key: str) -> Profile:
    if key not in MVP_PROFILES:
        raise KeyError(key)
    return MVP_PROFILES[key]
