"""`wraithwall sandbox` CLI (Phases 2–5: profiles, gates, boot, lifecycle).

Phase 2 built the profile model, the fail-closed prerequisite gates, the
one-time risk acknowledgement and the state markers. Phase 3 added the
hardened container boundary: static compose gates, an allowlist build context,
a two-plane internal network, the egress-deny canary, and `docker inspect`
verification of the hardening posture before a sandbox is ever reported as
RUNNING. Phase 4 wired the deterministic synthetic seed through the real
pipeline. Phase 5 completes the lifecycle: `logs`, `inspect`, `export`,
`reset`, `recover`, `rebuild-images`, `upgrade`, and the optional loopback UI
uplink. Phase 11 adds the T2 research-sandbox: per-session confirmation,
an explicit per-session host allowlist (E210), rootless enforcement already
gated via E203, and the research-plane self-checks (E202/E212).

Everything stays fail-closed: lifecycle verbs that cannot be performed safely
refuse with an E-code rather than guessing, and `destroy` remains the always-
available clean exit.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from sandbox_kit import compose, state
from sandbox_kit import provenance as _provenance
from sandbox_kit.seed import corpus as seed_corpus
from sandbox_kit.gates import GateFailure, run_all_gates
from sandbox_kit.gates_static import inspect_compose
from sandbox_kit.profiles import FUTURE_PROFILES, MVP_PROFILES, Profile, get_profile

PROGRAM = "wraithwall sandbox"

#: One-shot services whose clean exit is the self-check (G7 dynamic).
_CANARY_SERVICE = "sb-busybox"


def _print_profile_table() -> None:
    print("Available profiles:")
    for p in MVP_PROFILES.values():
        print(f"  {p.key:<14} [{p.tier}] {p.purpose}")
        print(f"  {'':<14} data: {p.data_source}")
        print(f"  {'':<14} confirmation: {p.confirmation}")
    print("\nNot available in this release:")
    for k, note in FUTURE_PROFILES.items():
        print(f"  {k:<14} {note}")


def _confirm_ack(profile: Profile, assume_yes: bool) -> bool:
    """Risk acknowledgement. T0/T1: one-time (persisted as ack.txt).
    T2 (research-sandbox): per-session — every `up` re-asks, nothing is
    persisted, so a stored "always allow" can never come to exist."""
    if profile.confirmation == "none":
        return True
    if profile.confirmation == "per-session":
        return _confirm_research(assume_yes)
    if assume_yes:
        print("[ack] --yes supplied: risk acknowledgement recorded non-interactively.")
        return True
    print(
        f"\nProfile {profile.key} [{profile.tier}] will:\n"
        "  • run local containers on this machine (nothing published; UI is\n"
        "    loopback-only once the launcher uplink lands in Phase 5),\n"
        "  • generate synthetic LOCAL telemetry only (never real attacker traffic),\n"
        "  • have no internet egress by default,\n"
        "  • store disposable state that reset/destroy can wipe.\n"
        f"{state._NON_CLAIMS}\n"
    )
    try:
        answer = input("Acknowledge and continue? [y/N] ").strip().lower()
    except EOFError:
        answer = ""
    return answer in ("y", "yes")


def _confirm_research(assume_yes: bool) -> bool:
    """T2 per-session confirmation. Never stored, never skippable by state.
    --yes records an explicit non-interactive acknowledgement for THIS run
    only; the next `up` asks again."""
    if assume_yes:
        print("[ack] --yes supplied: per-session research acknowledgement "
              "recorded for THIS run only (you will be asked again next time).")
        return True
    print(
        "\nresearch-sandbox [T2] — per-session confirmation required:\n"
        "  • a detonation container will fetch ONLY hosts you list via\n"
        "    --allow-host, through a deny-by-default egress proxy,\n"
        "  • untrusted page content will execute inside that container,\n"
        "  • isolation is improved but NOT guaranteed containment: this shares\n"
        "    your machine's kernel and is not a malware-analysis lab,\n"
        "  • metadata/internal/IPv6/DoH paths are denied by policy even for\n"
        "    allowlisted hosts,\n"
        f"  • state is disposable and destroyed with the sandbox.\n"
        f"{state._NON_CLAIMS}\n"
    )
    try:
        answer = input("Acknowledge for THIS session and continue? [y/N] ").strip().lower()
    except EOFError:
        answer = ""
    return answer in ("y", "yes")


def _persist_ack(name: str, profile: Profile) -> None:
    ack_file = state.sandbox_dir(name) / "ack.txt"
    if ack_file.exists():
        return
    state.sandbox_dir(name).mkdir(parents=True, exist_ok=True)
    ack_file.write_text(
        f"acknowledged={state.now_iso()} profile={profile.key} tier={profile.tier}\n"
        f"non_claims={state._NON_CLAIMS}\n"
    )


# ── Phase 11: T2 research-plane helpers ────────────────────────────────────

def _parse_allow_hosts(raw: str | None) -> list[str]:
    """Strict allowlist parse for E210. Lowercase, trimmed, dot-suffixes
    stripped, deduplicated, order-stable. A scheme/URL is tolerated by taking
    its hostname — but any other garbage is refused by the caller."""
    if not raw:
        return []
    hosts, seen = [], set()
    for part in raw.split(","):
        h = part.strip().lower().rstrip(".")
        if not h:
            continue
        if "://" in h:
            h = h.split("://", 1)[1].split("/", 1)[0]
        if "/" in h or "@" in h or " " in h:
            raise ValueError(
                f"invalid --allow-host entry: {part.strip()!r} (hostnames only)")
        if h in seen:
            continue
        seen.add(h)
        hosts.append(h)
    return hosts


def _validate_allow_hosts(hosts: list[str]) -> str | None:
    """Return a refusal message when a host would be policy-denied anyway,
    so the developer learns at start time, not at fetch time."""
    from sandbox_kit.egress_policy import classify
    for h in hosts:
        denied, why = classify(h)
        if denied:
            return (f"allowlisted host '{h}' is refused by the egress policy: {why}.\n"
                    "  Remove it from --allow-host and re-run. (The policy layer\n"
                    "  would deny it at fetch time regardless; refusing now is\n"
                    "  the honest behavior.)")
    return None


# ── up ─────────────────────────────────────────────────────────────────────

def cmd_up(args) -> int:
    name = args.name
    profile = get_profile(args.profile)

    # ── E210: research-sandbox requires an explicit per-session allowlist ──
    # Fail-closed: no --allow-host (or an empty one) means nothing may be
    # fetched, so the profile refuses rather than starting an inert plane the
    # developer might mistake for a working one. The PROXY also denies all
    # when its list is empty — this gate is the earlier, clearer half.
    allow_hosts: list[str] = []
    if profile.tier == "T2":
        try:
            allow_hosts = _parse_allow_hosts(getattr(args, "allow_host", None))
        except ValueError as ve:
            print(f"✗ {ve}\n  Code: E210\n  Docs: docs/sandbox/network.md")
            return 2
        if not allow_hosts:
            print("✗ research-sandbox requires at least one host to fetch.\n"
                  "  Pass --allow-host example.com (repeatable/comma-separated).\n"
                  "  Deny-by-default: with no hosts there is nothing this profile\n"
                  "  can do, so startup refuses instead of pretending.\n"
                  "  Code: E210\n  Docs: docs/sandbox/network.md")
            return 2
        refusal = _validate_allow_hosts(allow_hosts)
        if refusal:
            print(f"✗ {refusal}\n  Code: E210\n  Docs: docs/sandbox/network.md")
            return 2
    elif getattr(args, "allow_host", None):
        # Symmetric fail-closed half of E210: --allow-host on a profile that
        # never fetches developer-supplied URLs is a silent no-op otherwise —
        # the developer would believe egress is restricted when the flag did
        # nothing. Refuse instead of ignoring.
        print("✗ --allow-host is only valid for the research-sandbox (T2).\n"
              f"  Profile '{profile.key}' never fetches developer-supplied URLs,\n"
              "  so there is nothing to allowlist; accepting the flag would\n"
              "  falsely suggest this profile's egress is allowlist-gated.\n"
              "  Code: E210\n  Docs: docs/sandbox/network.md")
        return 2
    existing = state.read_state(name)

    if existing and existing.get("state") == "DESTROYED":
        print(f"! sandbox '{name}' was destroyed; starting fresh.")
        existing = None

    if existing and existing.get("profile") and existing["profile"] != profile.key:
        print(
            f"✗ sandbox '{name}' exists with profile '{existing.get('profile')}'.\n"
            f"  Requested: '{profile.key}'. Profiles cannot be silently switched.\n"
            f"  Fix:  {PROGRAM} destroy --name {name} && "
            f"{PROGRAM} up --profile {profile.key} --name {name}"
        )
        return 2

    if existing and existing.get("state") == "RUNNING":
        print(f"= sandbox '{name}' is already RUNNING (profile {profile.key}); nothing to do.")
        _print_status_body(name)
        return 0

    # A repeated `up` for a profile with nothing to run is a no-op, not a
    # re-run of the gates. (For `local-sandbox` a PREPARED marker means a
    # previous boot was interrupted, so that case falls through and continues.)
    if existing and existing.get("state") == "PREPARED" and not profile.requires_runtime:
        print(f"= sandbox '{name}' already prepared (profile {profile.key}); nothing to do.")
        _print_status_body(name)
        return 0

    # ── prerequisite gates (E101–E106, fail-closed) ────────────────────────
    try:
        results = run_all_gates(profile, ui_port=args.ui_port)
    except GateFailure as gf:
        print(gf.message)
        return 2

    # ── static compose posture gates (G1–G6, G9 → E205/E204) ──────────────
    if profile.requires_runtime:
        try:
            inspect_compose(compose.COMPOSE_FILE)
        except GateFailure as gf:
            print(gf.message)
            return 2

    # ── risk acknowledgement ──────────────────────────────────────────────
    # T0/T1: one-time, persisted as ack.txt. T2: per-session — the confirmation
    # runs on EVERY up regardless of any stored state, and is never persisted,
    # so no "always allow" can exist (Phase 11 contract).
    ack_file = state.sandbox_dir(name) / "ack.txt"
    if profile.confirmation == "per-session":
        if not _confirm_ack(profile, args.yes):
            print("Startup refused: per-session acknowledgement declined. "
                  "Nothing was started.")
            return 2
    elif not (existing and existing.get("ack")) and not ack_file.exists():
        if not _confirm_ack(profile, args.yes):
            print("Startup refused: acknowledgement declined. Nothing was started.")
            return 2
    _persist_ack(name, profile)

    base_state = {
        "profile": profile.key,
        "tier": profile.tier,
        "ack": True,
        "created_at": (existing or {}).get("created_at") or state.now_iso(),
        "gates": results,
    }

    # ── app-only: no containers exist for this profile ─────────────────────
    if not profile.requires_runtime:
        state.write_state(name, {**base_state, "state": "PREPARED",
                                 "updated_at": state.now_iso()})
        print(f"\n✓ gates passed: ui_port would be 127.0.0.1:{results['ui_port']}")
        print(f"✓ sandbox '{name}' prepared (profile {profile.key}, state PREPARED).")
        print("  app-only runs nothing at runtime by design — there are no "
              "containers to start.")
        return 0

    # ── local-sandbox / research-sandbox: build + boot + verify, or roll back ─
    project = compose.project_name(name)
    # The pinned corpus digest this launcher expects; the seed container must
    # reproduce exactly these bytes (E304 if it does not).
    seed_digest = seed_corpus.corpus_digest()
    # Record intent before touching the daemon, so an interrupted boot leaves a
    # truthful marker rather than a missing one (E301 recovery path in Phase 5).
    state.write_state(name, {**base_state, "state": "PREPARED", "project": project,
                             "updated_at": state.now_iso()})
    print(f"  project: {project}")
    uplink_port = None  # set only when the opt-in uplink actually comes up
    is_research = profile.tier == "T2"

    try:
        if not compose.docker_available():
            raise GateFailure("E101", "✗ Docker daemon is not reachable.\n"
                                      "  Fix: start Docker, then re-run.")
        print("✓ static gates passed (G1–G6, G9, G7-T2)")
        print("  preparing build context (allowlist) …")
        with tempfile.TemporaryDirectory(prefix="ww-sbx-ctx-") as tmp:
            ctx = compose.prepare_build_context(Path(tmp) / "ctx")
            compose.build_images(ctx)
        print("  starting sandbox project …")
        if is_research:
            compose.up(project, extra_env={
                "WRAITHWALL_SANDBOX_ALLOWED_HOSTS": ",".join(allow_hosts),
            }, profiles=[compose.RESEARCH_PROFILE])
        else:
            compose.up(project)
        print("  waiting for the egress-deny canary (G7) …")
        canary = compose.verify_egress_denied(project)
        print(f"✓ {canary.strip().splitlines()[-1] if canary.strip() else 'EGRESS_DENY_OK'}")
        if is_research:
            # ── Phase 11 T2 self-checks: the research plane must prove its
            # closure before the profile reports RUNNING.
            print("  running the research-plane self-checks (E202/E212) …")
            compose.verify_research_plane(project)
            print("  waiting for the enforcing proxy's policy self-test …")
            compose.require_healthy(project, "sb-egress", timeout=90)
            print(f"✓ egress policy verified; allowlist: {', '.join(allow_hosts)}")
        print("  verifying hardening posture from docker inspect …")
        posture = compose.verify_hardening(
            project,
            services=("sb-redis", "sb-app", "sb-seed", "sb-busybox", "sb-busybox-t",
                      "sb-egress", "sb-detonate", "sb-policy-selftest",
                      "sb-research-canary") if is_research else None)
        # ── Phase 10: supply-chain gate (E206) — the daemon must be running
        # exactly what compose pinned. Manifest recorded in the state file.
        print("  verifying image provenance against the pinned supply chain …")
        digest_manifest = _provenance.run_provenance_gate(compose.digest_rows(project))
        # RUNNING is only claimed when something is actually serving. Health is
        # the slowest and last check; a container that exits 3 satisfies every
        # other gate, so this is what stops the state marker from lying.
        print("  waiting for the application healthcheck …")
        compose.require_healthy(project, "sb-app")
        # ── Phase 4: the seed runs as part of `up` ──────────────────────────
        # sb-seed is one-shot and auto-started by compose once sb-app is
        # healthy (depends_on: service_healthy). The launcher waits for its
        # exit and verifies the receipt before RUNNING may be claimed: a
        # sandbox whose telemetry never arrived must not report a fully
        # working local-sandbox. The seed wrote directly into the shared
        # in-project volume, so there is no second run and no double-write.
        print("  waiting for synthetic telemetry seed …")
        seed_exit = compose.wait_seed_complete(project)
        if seed_exit != 0:
            msg = ("seed container did not complete"
                   if seed_exit is None else f"seed container exited {seed_exit}")
            raise GateFailure("E304", f"✗ Synthetic seed generation failed: {msg}.\n"
                                      "  State marked PARTIAL. Fix:  remove and re-run up.\n"
                                      '  Logs: docker logs $(docker ps -aq --filter '
                                      f'label=com.docker.compose.project={project} '
                                      '--filter name=seed)')
        try:
            seed_receipt = compose.read_seed_receipt(project)
        except Exception as exc:
            raise GateFailure("E304", f"✗ Synthetic seed generation failed: "
                                      f"receipt unreadable ({exc}).\n"
                                      "  State marked PARTIAL. Fix:  remove and re-run up.")
        if seed_receipt.get("corpus_sha256") != seed_digest:
            raise GateFailure(
                "E304",
                "✗ Synthetic seed generation failed: corpus digest mismatch "
                f"(receipt {seed_receipt.get('corpus_sha256', '?')[:12]}… != "
                f"expected {seed_digest[:12]}…).\n"
                "  The seed image is not generating the pinned corpus for this "
                "sandbox_kit version. Rebuild images and re-run up.")
        print(f"✓ seed complete: {seed_receipt.get('events')} events / "
              f"{seed_receipt.get('sessions')} sessions (LOCAL-marked)")

        # ── Phase 5: optional loopback UI uplink ──────────────────────────
        # Opt-in via WRAITHWALL_SANDBOX_UPLINK=1 in the launcher's environment
        # (never by default). Two-phase bring-up: the core project boots first
        # (this block runs inside the same try/rollback umbrella), then the
        # proxy starts with the app's *actual* bridge IP — no DNS, no catch-22.
        # After it is up, the in-app egress canary re-runs against the app's
        # full network set: the uplink bridge has a gateway, so this is the
        # control that keeps "non-internal" from meaning "internet".
        uplink_requested = os.environ.get("WRAITHWALL_SANDBOX_UPLINK") == "1"
        uplink_port = None
        if uplink_requested:
            print("  starting loopback UI uplink (opt-in) …")
            # Driver options apply only at network creation; force recreation
            # so the declared masquerade/DNS posture is what actually ships.
            compose.reset_uplink_network(project)
            compose.up(project, extra_env={
                "WRAITHWALL_SANDBOX_UPLINK": "1",
                "WRAITHWALL_SANDBOX_APP_ADDR": "",  # placeholder, set below
            }, profiles=["uplink"])
            # The proxy must target the app on the UPLINK subnet (same-subnet
            # L2). The app-net address would require cross-bridge host
            # forwarding, which default-deny firewalls block.
            app_addr = compose.address_on(project, "sb-app", "ww-uplink-net")
            if not app_addr:
                raise GateFailure("E106", "✗ Uplink requested but the app has "
                                          "no address on the uplink network.\n"
                                          "  Startup refused; containers are "
                                          "being stopped.")
            # The proxy started once without a target (refused, exit 3 — by
            # design); recreate it now that the real address is known.
            compose.up(project, extra_env={
                "WRAITHWALL_SANDBOX_UPLINK": "1",
                "WRAITHWALL_SANDBOX_APP_ADDR": app_addr,
                "WRAITHWALL_SANDBOX_UI_PORT": str(results["ui_port"]),
            }, profiles=["uplink"])
            compose.require_healthy(project, "sb-uplink", timeout=60)
            uplink_port = compose.uplink_port(project)
            # E107 fail-closed probe: the container can be healthy while the
            # HOST's own firewall still eats host->container traffic to the
            # new bridge subnet (verified on hardened ufw OUTPUT-DROP hosts).
            # Never report an uplink the developer cannot actually reach.
            if not uplink_port or not compose.probe_loopback_publish(uplink_port):
                raise GateFailure(
                    "E107", "✗ Uplink proxy is up, but the host cannot reach "
                            f"127.0.0.1:{uplink_port or '<unset>'}.\n"
                            "  Your host firewall is dropping host-originated "
                            "traffic to the sandbox bridge.\n"
                            "  Scoped remediation (Linux/ufw host, removable):\n"
                            "    sudo ufw allow out from any to 172.16.0.0/12 "
                            "comment 'wraithwall-sandbox-uplink'\n"
                            "  This allows host->docker-bridge-subnet traffic "
                            "only (no WAN exposure). Containers stay internal "
                            "otherwise.")
            verdict = compose.verify_egress_denied_all(project)
            print(f"✓ {verdict}: UI at http://127.0.0.1:{uplink_port} "
                  "(host loopback only)")
    except GateFailure as gf:
        compose.teardown(project)
        state.write_state(name, {**base_state, "state": "PARTIAL", "project": project,
                                 "rolling_back": False, "rolled_back": True,
                                 "failed_code": gf.code, "updated_at": state.now_iso()})
        print(gf.message)
        print("  Rolled back: this sandbox left no running containers.")
        return 2
    except Exception as exc:  # build/daemon errors: roll back, never half-live
        compose.teardown(project)
        state.write_state(name, {**base_state, "state": "PARTIAL", "project": project,
                                 "rolled_back": True, "failed_reason": str(exc)[:300],
                                 "updated_at": state.now_iso()})
        print(f"✗ sandbox start failed and was rolled back:\n  {exc}")
        return 2

    state.write_state(name, {
        **base_state,
        "state": "RUNNING",
        "project": project,
        "canary": _CANARY_SERVICE,
        "services": sorted(posture),
        "app_address": compose.app_address(project),
        "uplink_port": uplink_port,
        "allow_hosts": allow_hosts,
        "seed": {
            "events": seed_receipt.get("events"),
            "sessions": seed_receipt.get("sessions"),
            "corpus_sha256": seed_receipt.get("corpus_sha256"),
            "seed_version": seed_receipt.get("seed_version"),
            "receipt_path": compose.SEED_RECEIPT_PATH,
        },
        "provenance": digest_manifest,
        "updated_at": state.now_iso(),
    })
    print(f"\n✓ sandbox '{name}' is RUNNING (profile {profile.key}, project {project}).")
    print(f"  hardened services: {', '.join(sorted(posture))}")
    if is_research:
        print(f"  egress allowlist:  {', '.join(allow_hosts)} (per-session; "
              "policy refuses metadata/internal/IPv6/DoH regardless)")
        print("  detonate a URL:    "
              f"{PROGRAM} detonate --name {name} --url <url>")
    if uplink_port:
        print(f"  published ports:   127.0.0.1:{uplink_port} → UI (uplink; "
              "host loopback only, opt-in)")
    else:
        print(f"  published ports:   none (all planes unpublishable or "
              "loopback-only)")
    print(f"  synthetic corpus:  {seed_receipt.get('events')} events, "
          f"sha256 {seed_receipt.get('corpus_sha256', '')[:12]}… (LOCAL-marked)")
    print("  image provenance:  " + _provenance.manifest_summary(digest_manifest).lstrip())
    address = compose.app_address(project)
    if address:
        print(f"  app (management plane): http://{address}:8000")
    if uplink_port:
        print(f"  UI (uplink):            http://127.0.0.1:{uplink_port}")
    else:
        print("  UI uplink: off (default). Enable explicitly with "
              "WRAITHWALL_SANDBOX_UPLINK=1 — loopback-only, documented in "
              "docs/sandbox/network.md")
    return 0


# ── status ─────────────────────────────────────────────────────────────────

def _print_status_body(name: str) -> None:
    st = state.read_state(name)
    if not st:
        print(f"sandbox '{name}': UNBUILT (no state).")
        print(f"  Start: {PROGRAM} up --profile app-only")
        print(f"  {state._NON_CLAIMS}")
        return
    print(f"sandbox '{name}':")
    print(f"  state:      {st.get('state')}")
    print(f"  profile:    {st.get('profile')} [{st.get('tier')}]")
    print(f"  ack:        {bool(st.get('ack'))}")
    if st.get("project"):
        print(f"  project:    {st.get('project')}")
    print(f"  gates:      {st.get('gates')}")
    if st.get("seed"):
        s = st["seed"]
        print(f"  telemetry:  {s.get('events')} synthetic events / "
              f"{s.get('sessions')} sessions (LOCAL-marked)")
        print(f"  corpus:     sha256 {str(s.get('corpus_sha256'))[:12]}… "
              f"(seed v{s.get('seed_version')})")
    elif st.get("state") == "RUNNING":
        print("  telemetry:  none recorded (reset, or started before Phase 4)")
    if st.get("uplink_port"):
        print(f"  uplink:     http://127.0.0.1:{st['uplink_port']} "
              "(host loopback only)")
    if st.get("state") in ("RUNNING", "STOPPED") and st.get("project"):
        # Cheap liveness cross-check so the marker cannot contradict reality.
        try:
            rows = compose.ps(st["project"])
            running = [r.get("Service") for r in rows if r.get("State") == "running"]
            print(f"  containers: {len(running)} running of {len(rows)} known")
        except Exception:
            print("  containers: unknown (docker unavailable)")
    print(f"  updated_at: {st.get('updated_at')}")
    print(f"  {state._NON_CLAIMS}")


def cmd_status(args) -> int:
    if getattr(args, "json", False):
        from sandbox_kit import security_posture as sp
        result = sp.collect_security_posture(args.name)
        checks = sp.run_security_checks(result)
        result["checks"] = checks
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if getattr(args, "security", False):
        from sandbox_kit import security_posture as sp
        result = sp.collect_security_posture(args.name)
        checks = sp.run_security_checks(result)
        print(sp.format_posture(result, checks))
        return 0
    _print_status_body(args.name)
    return 0


# ── verify (Phase 7: machine-checked isolation claims) ─────────────────────

def cmd_verify(args) -> int:
    """Run the full security checklist against a sandbox and exit honestly.

    Exit 0 only when every check passes; exit 1 names each failure; exit 2
    when the target cannot be verified at all. Tool absence or degraded
    visibility reports as unknown — never silently scored as a pass.
    """
    from sandbox_kit import security_posture as sp
    name = args.name
    st = state.read_state(name)
    if not st or st.get("state") != "RUNNING":
        print(f"✗ sandbox '{name}' is not RUNNING; nothing to verify.")
        return 2
    result = sp.collect_security_posture(name)
    checks = sp.run_security_checks(result)
    if args.json:
        result["checks"] = checks
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(sp.format_posture(result, checks))
    failed = [c for c in checks if c["status"] == "FAIL"]
    unknown = [c for c in checks if c["status"] not in ("pass", "FAIL")]
    if failed:
        print(f"✗ verify: {len(failed)} check(s) FAILED:")
        for c in failed:
            print(f"  ✗ {c['id']}: {c['desc']}")
        return 1
    if unknown:
        print(f"= verify: {len(unknown)} check(s) UNKNOWN (degraded visibility):")
        for c in unknown:
            print(f"  ? {c['id']}: {c['status']}")
        if args.strict:
            print("  strict mode: unknown counts as failure.")
            return 1
        return 0
    print(f"✓ verify: all {len(checks)} security checks pass.")
    return 0


# ── replay (Phase 4: synthetic sessions) ───────────────────────────────────

def cmd_replay(args) -> int:
    """List or replay the sandbox's LOCAL synthetic sessions.

    Listing reads the app's own pipeline state (cowrie_sessions:recent +
    cowrie_completed:*) through a read-only exec inside sb-app. Session
    replay reads the binary ttylog the seed wrote into the shared sandbox
    volume and parses it with the production parser
    (``wraithwall.replay_tty.parse_ttylog``).
    Everything shown is LOCAL-marked synthetic telemetry.
    """
    import json as _json
    import os as _os
    import tempfile as _tempfile

    name = args.name
    st = state.read_state(name)
    if not st or st.get("state") != "RUNNING":
        print(f"✗ sandbox '{name}' is not RUNNING; start it first:  "
              f"{PROGRAM} up --profile local-sandbox")
        return 2
    project = st.get("project") or compose.project_name(name)
    seed = st.get("seed") or {}
    if not seed:
        print(f"✗ sandbox '{name}' has no synthetic telemetry recorded "
              "(started before Phase 4?). Re-create it with:  "
              f"{PROGRAM} destroy --name {name} && {PROGRAM} up --profile local-sandbox")
        return 2

    print(seed_corpus.LOCAL_MARKER_TAG + " synthetic telemetry — not production data")

    if args.session:
        if not compose._SID_RE.fullmatch(args.session):
            print(f"✗ invalid session id: {args.session!r}")
            return 2
        try:
            blob = compose.read_ttylog(project, args.session)
            from wraithwall.replay_tty import parse_ttylog
            with _tempfile.NamedTemporaryFile(suffix=".ttylog",
                                              delete=False) as tf:
                tf.write(blob)
                tmp = tf.name
            try:
                frames = parse_ttylog(tmp)
            finally:
                _os.unlink(tmp)
        except Exception as exc:
            print(f"✗ cannot read ttylog for {args.session}: {exc}")
            return 2
        print(f"session {args.session}: {len(frames)} frames")
        for ts, text in frames:
            print(f"  [{ts:9.0f}] {text}", end="" if text.endswith("\n") else "\n")
        return 0

    # Listing: read the app's pipeline state from inside sb-app.
    snippet = (
        "import json,os,redis\n"
        "r=redis.from_url(os.environ.get('REDIS_URL','redis://127.0.0.1:6379/0'),"
        "decode_responses=True)\n"
        "out=[]\n"
        "for s in r.lrange('cowrie_sessions:recent',0,-1):\n"
        "    raw=r.get('cowrie_completed:'+s)\n"
        "    if raw:\n"
        "        d=json.loads(raw)\n"
        "        out.append({'session_id':s,'src_ip':d.get('src_ip'),"
        "                    'sensor':d.get('sensor'),"
        "                    'commands':len(d.get('commands',[])),"
        "                    'logins':len(d.get('login_attempts',[])),"
        "                    'duration':d.get('duration',0)})\n"
        "print(json.dumps({'count':len(out),'sessions':out}))"
    )
    try:
        cid = compose.container_id(project, "sb-app")
        if not cid:
            raise RuntimeError("sb-app container not found")
        result = compose._run(["docker", "exec", cid,
                               "python", "-c", snippet], check=False, timeout=120)
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout or "")[-300:])
        payload = _json.loads(result.stdout)
    except Exception as exc:
        print(f"✗ cannot list sessions: {exc}")
        return 2

    sessions = payload.get("sessions", [])
    if not sessions:
        print("  0 sessions ingested yet — the watcher may still be catching up;"
              " try again in a few seconds.")
        return 0
    print(f"  synthetic sessions ingested: {payload.get('count')} "
          f"(corpus sha256 {str(seed.get('corpus_sha256'))[:12]}…)")
    for s in sessions[:max(0, args.limit)]:
        print(f"    {s['session_id']}  src={s['src_ip']:<13} cmds={s['commands']:<3} "
              f"logins={s['logins']:<3} dur={s['duration']}s  [{s['sensor']}]")
    print("  Replay one:  " + PROGRAM + f" replay --name {name} --session <id>")
    return 0


def cmd_profiles(_args) -> int:
    _print_profile_table()
    return 0


def cmd_platform(args) -> int:
    """G14 (Phase 8): honest ACTIVE/UNAVAILABLE/UNKNOWN control report."""
    from sandbox_kit.platform import report_platform_controls
    from sandbox_kit.platform import classify as _classify_platform
    from sandbox_kit.gates import _probe_runtime
    runtime, _kind = _probe_runtime()
    report = report_platform_controls(runtime=runtime)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.render())
        if runtime:
            refusals, warnings = _classify_platform(report, "T1")
            for w in warnings:
                print(f"  ! {w}")
            for r in refusals:
                print(f"  ✗ {r}")
    return 0


# ── stop / destroy ─────────────────────────────────────────────────────────

def cmd_stop(args) -> int:
    name = args.name
    st = state.read_state(name)
    if not st:
        print(f"sandbox '{name}': UNBUILT (nothing to stop).")
        return 0
    project = st.get("project") or compose.project_name(name)
    print(f"stopping project {project} …")
    try:
        # Volumes are deliberately preserved: `stop` is reversible, `destroy` is
        # not. Named volume keeps the sandbox's telemetry state across a stop.
        compose.down(project, remove_volumes=False)
    except Exception as exc:
        print(f"✗ stop failed: {exc}")
        return 2
    state.write_state(name, {**st, "state": "STOPPED", "updated_at": state.now_iso()})
    print(f"✓ sandbox '{name}' stopped (state STOPPED). State volume preserved.")
    return 0


def cmd_destroy(args) -> int:
    # Confirmation gate (Stage 3 lifecycle contract: destructive op must be
    # explicit). Refuses without --yes; tells the user exactly what to type.
    if not getattr(args, "yes", False):
        st = state.read_state(args.name)
        target = st["project"] if st and st.get("project") else f"sandbox '{args.name}'"
        print(f"✗ refusing to destroy {target} without confirmation.\n"
              "  Destroy stops services and DELETES all sandbox state "
              "(containers, volumes, state file). This cannot be undone.\n"
              f"  Fix:  {PROGRAM} destroy --yes")
        return 2
    name = args.name
    try:
        project = compose.project_name(name)
    except ValueError as ve:
        print(f"✗ {ve}")
        return 2
    st = state.read_state(name)
    if st and st.get("project"):
        project = st["project"]
    teardown = "no containers were known"
    try:
        if compose.docker_available():
            before = compose.ps(project)
            compose.teardown(project)
            after = compose.ps(project)
            teardown = f"removed {len(before)} container(s); remaining {len(after)}"
    except Exception as exc:
        print(f"! container teardown reported an error (continuing): {exc}")
    try:
        receipt = state.destroy(name)
    except ValueError as ve:
        print(f"✗ {ve}")
        return 2
    print(f"✓ destroyed '{receipt['name']}': "
          f"{len(receipt['removed_paths'])} files removed; "
          f"verified_empty={receipt['verified_empty']}")
    print(f"  containers: {teardown}")
    for p in receipt["removed_paths"]:
        print(f"  - {p}")
    return 0


# ── Phase 5: full lifecycle ────────────────────────────────────────────────

def _running_or_none(name: str) -> dict | None:
    """State dict when the sandbox exists and is RUNNING, else None (with a
    printed reason). Lifecycle verbs are read-only or constructive; none of
    them invent a project name."""
    st = state.read_state(name)
    if not st:
        print(f"✗ sandbox '{name}' does not exist (UNBUILT). Start it first:\n"
              f"  {PROGRAM} up --profile local-sandbox")
        return None
    if st.get("state") != "RUNNING":
        print(f"✗ sandbox '{name}' is not RUNNING (state: {st.get('state')}).\n"
              f"  Recover:  {PROGRAM} recover --name {name}\n"
              f"  Restart:  {PROGRAM} up --profile {st.get('profile', 'local-sandbox')} --name {name}")
        return None
    if not st.get("project"):
        print(f"✗ sandbox '{name}' has no compose project recorded; state is "
              "inconsistent. Destroy and re-create it.")
        return None
    return st


def cmd_logs(args) -> int:
    """`logs` — read-only service logs via docker compose logs.

    Idempotent by nature: reading never mutates. Works for RUNNING sandboxes;
    after a crash or stop, docker still holds the logs of exited containers,
    so logs remain readable while the project exists.
    """
    st = state.read_state(args.name)
    if not st or not st.get("project"):
        print(f"✗ sandbox '{args.name}' has no project; nothing to read logs from.")
        return 2
    return compose.service_logs(st["project"], service=args.service,
                                tail=args.tail, follow=args.follow)


def cmd_inspect(args) -> int:
    """`inspect` — the security posture + state inventory, on demand.

    Re-runs the same dynamic verification `up` performs (G7 canary set,
    hardening posture) and adds the app-IP/telemetry summary. Read-only.
    """
    st = _running_or_none(args.name)
    if not st:
        return 2
    project = st["project"]
    print(f"project {project} — live security posture:")
    try:
        canary = compose.verify_egress_denied(project)
        print(f"  egress (planes):    {canary.strip().splitlines()[-1]}")
        uplink = compose.verify_egress_denied_all(project)
        print(f"  egress (uplink):    {uplink}")
        posture = compose.verify_hardening(project)
        for svc, info in sorted(posture.items()):
            print(f"  {svc:<12} user={info.get('user')!r} image={info.get('image')!r}")
        address = compose.app_address(project)
        if address:
            print(f"  app (internal):     http://{address}:8000")
        port = compose.uplink_port(project)
        print(f"  uplink:             "
              + (f"http://127.0.0.1:{port}" if port else "not attached"))
    except GateFailure as gf:
        print(gf.message)
        print("\n  The live posture regressed below the baseline. Treat the "
              "sandbox as suspect:\n"
              f"    {PROGRAM} destroy --name {args.name}")
        return 2
    seed = st.get("seed") or {}
    if seed:
        print(f"  telemetry:          {seed.get('events')} events / "
              f"{seed.get('sessions')} sessions, sha256 "
              f"{str(seed.get('corpus_sha256'))[:12]}… (LOCAL-marked)")
    print(f"  {state._NON_CLAIMS}")
    return 0


def cmd_export(args) -> int:
    """`export` — sanitized LOCAL telemetry bundle (E307-gated).

    Assembles the synthetic corpus, tty logs and pipeline session records from
    the sandbox volume into a directory, then refuses to keep it if anything
    secret-shaped is found: the bundle is deleted and the command exits 2.
    """
    st = _running_or_none(args.name)
    if not st:
        return 2
    project = st["project"]
    dest = (Path(args.out).resolve() if args.out
            else Path.cwd() / f"{project}-export")
    if dest.exists() and not args.force:
        print(f"✗ export destination {dest} already exists.\n"
              "  Nothing was written (no overwrites, E307).\n"
              f"  Fix:  choose another --out, or pass --force to overwrite "
              "intentionally.")
        return 2
    tmp = dest.with_name(dest.name + ".partial")
    if tmp.exists():
        shutil.rmtree(tmp)
    try:
        manifest = compose.export_bundle(project, tmp)
        findings = compose.scan_bundle_for_secrets(tmp)
        if findings:
            shutil.rmtree(tmp, ignore_errors=True)
            print("✗ Export blocked: the bundle contains a secret-shaped string.\n"
                  "  This is a generator bug — the bundle was NOT delivered.\n"
                  f"  Code: E307 — report per docs/sandbox/bug-reports.md")
            for rule, path, sample in findings[:6]:
                print(f"    rule={rule!r} file={path} sample={sample}")
            return 2
        if dest.exists():
            shutil.rmtree(dest)
        tmp.rename(dest)
    except Exception as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        print(f"✗ export failed (nothing was delivered): {exc}")
        return 2
    print(f"✓ sanitized export written: {dest}")
    print(f"  marker: {manifest['marker']} (synthetic — safe to share)")
    for rel, meta in sorted(manifest["files"].items()):
        print(f"  {rel:<28} {meta['bytes']:>9} B  sha256 {meta['sha256'][:12]}…")
    print("  Manifest includes per-file SHA-256s for provenance.")
    return 0


def cmd_reset(args) -> int:
    """`reset` — disposable state back to the clean baseline (G8).

    Purges the synthetic corpus, tty logs, pipeline session records and the
    seed receipt while the sandbox stays up. Re-running the seed afterwards is
    a destroy + up (the seed is one-shot by design; no double-write into a
    file the watcher tails).
    """
    st = _running_or_none(args.name)
    if not st:
        return 2
    project = st["project"]
    if not args.yes:
        answer = input(f"Purge synthetic telemetry for '{args.name}'? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("Reset declined; nothing changed.")
            return 2
    try:
        removed = compose.reset_bundle(project)
    except Exception as exc:
        print(f"✗ reset failed: {exc}")
        return 2
    state.write_state(args.name, {
        **st, "seed": None, "updated_at": state.now_iso()})
    print(f"✓ reset complete for '{args.name}' — telemetry state is the clean "
          "baseline:")
    for item in removed:
        print(f"  - {item}")
    print("  To regenerate telemetry: destroy, then up again (the seed is "
          "one-shot; re-running it would double-write a tailed file).")
    return 0


def cmd_recover(args) -> int:
    """`recover` — converge a PARTIAL/STALE sandbox back to truth (E301).

    Detects the last interrupted state, reconciles with the daemon, and always
    finishes in a state that matches reality: RUNNING-verified, STOPPED, or
    destroyed with nothing left behind.
    """
    name = args.name
    st = state.read_state(name)
    if not st:
        print(f"sandbox '{name}': UNBUILT — nothing to recover.")
        return 0
    project = st.get("project") or compose.project_name(name)
    live = []
    if compose.docker_available():
        try:
            live = compose.ps(project)
        except Exception:
            live = []
    running = [r for r in live if r.get("State") == "running"]
    if st.get("state") == "RUNNING" and not running:
        print(f"! state says RUNNING but 0 containers are live; correcting to "
              "STOPPED.")
        state.write_state(name, {**st, "state": "STOPPED",
                                 "updated_at": state.now_iso()})
        print(f"✓ recovered: state now STOPPED (truth). Restart with:")
        print(f"  {PROGRAM} up --profile {st.get('profile', 'local-sandbox')} --name {name}")
        return 0
    if running:
        if st.get("state") == "RUNNING":
            # A RUNNING marker plus live containers is only a recovery case if
            # the sandbox is actually broken. Verify before touching anything:
            # never tear down a healthy sandbox that someone merely inspects.
            try:
                compose.require_healthy(project, "sb-app", timeout=30)
            except GateFailure:
                print(f"! state says RUNNING but the app is unhealthy; "
                      "tearing down and marking PARTIAL (E301).")
                compose.teardown(project)
                state.write_state(name, {**st, "state": "PARTIAL",
                                         "rolled_back": True,
                                         "updated_at": state.now_iso()})
                print("✓ recovered: leftovers removed. Clean start:")
                print(f"  {PROGRAM} up --profile "
                      f"{st.get('profile', 'local-sandbox')} --name {name}")
                return 0
            print("✓ nothing to recover: sandbox is RUNNING and verified "
                  "healthy.")
            return 0
        print(f"! {len(running)} container(s) still running from an interrupted "
              "start; tearing down (G8: no orphaned sandbox processes).")
        compose.teardown(project)
        state.write_state(name, {**st, "state": "PARTIAL",
                                 "rolled_back": True,
                                 "updated_at": state.now_iso()})
        print("✓ recovered: leftovers removed. Clean start:")
        print(f"  {PROGRAM} up --profile {st.get('profile', 'local-sandbox')} --name {name}")
        return 0
    print(f"✓ nothing to recover: no live containers, state is {st.get('state')}.")
    print(f"  Clean start: {PROGRAM} up --profile {st.get('profile', 'local-sandbox')} --name {name}")
    return 0


def cmd_rebuild_images(args) -> int:
    """`rebuild-images` — fresh images from the pinned Dockerfiles.

    No cache (--no-cache), so a suspect or stale image can be replaced with a
    provably fresh build of the same reviewed sources. Old layers fall out of
    the build cache naturally; nothing else is touched.
    """
    if not compose.docker_available():
        print("✗ Docker daemon is not reachable; cannot rebuild.")
        return 2
    print("  preparing build context (allowlist) …")
    with tempfile.TemporaryDirectory(prefix="ww-sbx-ctx-") as tmp:
        ctx = compose.prepare_build_context(Path(tmp) / "ctx")
        import subprocess as _sp
        for tag, dockerfile in compose.DOCKERFILES.items():
            print(f"  building {tag} (no cache) …")
            r = _sp.run(["docker", "build", "--no-cache", "-f",
                         str(compose.REPO_ROOT / dockerfile), "-t", tag,
                         str(ctx)], timeout=compose.BUILD_TIMEOUT)
            if r.returncode != 0:
                print(f"✗ rebuild of {tag} failed.")
                return 2
    print("✓ images rebuilt from the pinned sources (--no-cache).")
    return 0


def cmd_sbom(args) -> int:
    """`sbom` — SBOM generation + vulnerability classification (Phase 10, G10).

    Honest tooling: no syft ⇒ no SBOM and exit 2 (the tool never pretends).
    Scan findings are classified against the waiver register; CRITICAL/HIGH
    without a live waiver ⇒ exit 1 (release blocking).
    """
    if args.image:
        rows = [{"Service": a.split("@")[0].split(":")[0].replace("/", "-"),
                 "Image": a} for a in args.image]
    else:
        st = _running_or_none(args.name)
        if not st:
            return 2
        project = st["project"]
        rows = compose.digest_rows(project)
        if not rows:
            print(f"✗ no services found for project '{project}'; nothing to scan.")
            return 2
    tools = _provenance.sbom_tool_status()
    if not tools["syft"]:
        print("✗ No SBOM generator available (syft not found).\n"
              "  Nothing was generated — this tool does not pretend.\n"
              "  Fix:  install syft (anchore/syft), or use the CI supply-chain\n"
              "        job, which installs it.")
        return 2
    out = (Path(args.out).resolve() if args.out
           else Path.cwd() / "sbom" / f"local-{args.name}")
    out.mkdir(parents=True, exist_ok=True)
    print(f"  generating SBOMs for {len(rows)} image(s) → {out}")
    import subprocess as _sp
    for row in rows:
        svc, image = row["Service"], row["Image"]
        dest = out / f"{svc}.cdx.json"
        r = _sp.run(["syft", image, "-o", "cyclonedx-json",
                     f"--file={dest}"], timeout=600)
        if r.returncode != 0:
            print(f"✗ syft failed for {svc} ({image}).")
            return 2
        print(f"  ✓ {svc}: {dest.name}")
    if not tools["grype"]:
        print("  ! grype not found — SBOMs written, vulnerability scan NOT run "
              "(honest skip, not a pass).")
        return 0
    findings = []
    for row in rows:
        r = _sp.run(["grype", row["Image"], "-o", "json"],
                    capture_output=True, text=True, timeout=600)
        try:
            data = json.loads(r.stdout or "{}")
        except json.JSONDecodeError:
            print(f"✗ grype produced unparseable output for {row['Image']}.")
            return 2
        for m in data.get("matches", []):
            v = m.get("vulnerability") or {}
            findings.append({"id": v.get("id"), "severity": v.get("severity")})
    verdict = _provenance.classify_scan_findings(findings)
    print(f"  scan: {len(verdict['blocking'])} blocking / "
          f"{len(verdict['waived'])} waived / {len(verdict['passed'])} passed")
    for f in verdict["blocking"][:10]:
        print(f"    BLOCKING {f.get('severity')} {f.get('id')}")
    if verdict["blocking"]:
        print("\n✗ Release gate (G10): unwaived CRITICAL/HIGH findings block release.\n"
              "  Waivers live in sandbox_kit/provenance.py::WAIVER_REGISTER\n"
              "  (reason + owner + expiry; expired == unwaived).")
        return 1
    print("✓ no unwaived CRITICAL/HIGH findings (G10 pass)")
    return 0


def cmd_upgrade(args) -> int:
    """`upgrade` — re-converge a stopped sandbox onto current images/config.

    The sandbox is disposable by design; `upgrade` simply re-runs the gates
    and boot against whatever the repository now ships. On any failure the
    result is PARTIAL + rollback, never a half-upgraded live sandbox.
    """
    name = args.name
    st = state.read_state(name)
    if st and st.get("state") == "RUNNING":
        print(f"✗ sandbox '{name}' is RUNNING. Stop it first (stop is "
              "reversible; upgrades are not in-place):")
        print(f"  {PROGRAM} stop --name {name} && {PROGRAM} upgrade --name {name}")
        return 2
    print("Converging onto the current repository state — this is a fresh "
          "`up` of the same sandbox name:")
    profile = st.get("profile") if st else None
    profile = profile or "local-sandbox"
    ns = argparse.Namespace(
        name=name, profile=profile, ui_port=getattr(args, "ui_port", None),
        allow_host=None, yes=args.yes)
    return cmd_up(ns)


# ── detonate (Phase 11, T2) ────────────────────────────────────────────────

def _sanitize_raw_output(text: str) -> str:
    """Make untrusted process output safe to echo into a terminal.

    Strips ANSI/CSI escape sequences and replaces the remaining C0 control
    characters (except tab/newline) before printing. Used by `detonate`'s
    raw-output fallback, where the text can embed hostile-page console data.
    """
    import re as _re
    clean = _re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", text)
    clean = _re.sub(r"\x1b\][^\x07]*(?:\x07|\x1b\\)", "", clean)  # OSC sequences
    clean = _re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "?", clean)
    return clean[-4000:]


def cmd_detonate(args) -> int:
    """`detonate` — fetch a developer-supplied URL inside the T2 plane.

    Safety contract:
    * requires a RUNNING research-sandbox (this verb does not exist for other
      profiles);
    * the target host must be on the session's allowlist (E211) — the per-session
      list passed at `up --allow-host` is the authoritative scope, and the
      in-proxy policy layer still denies infrastructure regardless;
    * the report comes back through `docker exec` stdout; nothing is written
      outside the project volume.
    """
    st = _running_or_none(args.name)
    if not st:
        return 2
    if st.get("tier") != "T2":
        print("✗ `detonate` requires a research-sandbox (T2). This sandbox is "
              f"profile {st.get('profile')} [{st.get('tier')}].")
        return 2
    target = (args.url or "").strip()
    if not target:
        print("✗ --url is required.")
        return 2
    if "\n" in target or "\r" in target or "\x00" in target:
        print("✗ --url contains control characters; refusing.")
        return 2
    from urllib.parse import urlparse
    p = urlparse(target if "://" in target else "https://" + target)
    if p.scheme not in ("http", "https"):
        print(f"✗ unsupported URL scheme '{p.scheme or '<none>'}' (http/https only).\n  Code: E211")
        return 2
    host = (p.hostname or "").lower().rstrip(".")
    allowed = set(st.get("allow_hosts") or [])
    if host not in allowed:
        print(f"✗ '{host or target}' is not on this session's allowlist.\n"
              f"  Allowed this session: {', '.join(sorted(allowed)) or '<none>'}\n"
              "  The allowlist is per-session: destroy and re-run `up "
              "--profile research-sandbox --allow-host …` to change it.\n"
              "  Code: E211\n  Docs: docs/sandbox/network.md")
        return 2
    from sandbox_kit.egress_policy import classify
    denied, why = classify(host)
    if denied:
        print(f"✗ egress policy refuses '{host}': {why}\n  Code: E211")
        return 2
    project = st["project"]
    print(f"  detonating {target} inside {project} (allowlisted, policy-clean) …")
    cid = compose.container_id(project, "sb-detonate")
    if not cid:
        print("✗ sb-detonate container not found; sandbox state is inconsistent. "
              "Recover or restart the sandbox.")
        return 2
    result = compose._run(
        ["docker", "exec", cid, "python3", "/sandbox/detonate.py", target],
        check=False, timeout=180)
    out = (result.stdout or "").strip()
    if result.returncode != 0 or not out:
        print(f"✗ detonation failed (exit {result.returncode}):\n"
              f"  {(result.stderr or out or '')[-800:]}")
        return 2
    try:
        report = json.loads(out)
    except json.JSONDecodeError:
        # Raw-output fallback: sanitized — the output can embed hostile-page
        # console text, and echoing raw terminal escapes would let a detonated
        # page write into the developer's terminal.
        print(_sanitize_raw_output(out))
        return 0
    summary = {
        "url": report.get("url"), "final_url": report.get("final_url"),
        "error": report.get("error"),
        "redirects": len(report.get("redirect_chain") or []),
        "network_requests": len(report.get("network") or []),
        "downloads": report.get("download_hashes") or [],
        "threat_signals": report.get("threat_signals"),
        "report_sha256": report.get("_report_hash"),
    }
    print(json.dumps(summary, indent=2))
    if args.json:
        print(out)
    print("\n  report stored inside the sandbox volume; it dies with the "
          "project. LOCAL research data only.")
    return 0


# ── parser ─────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog=PROGRAM,
        description="WraithWall Local Secure Sandbox — safe local profiles (fail-closed).",
    )
    ap.add_argument("--name", default="default", help="sandbox instance name")
    sub = ap.add_subparsers(dest="command", required=True)

    p_up = sub.add_parser("up", help="run gates and start a sandbox")
    p_up.add_argument("--profile", default="app-only", choices=sorted(MVP_PROFILES))
    p_up.add_argument("--ui-port", type=int, default=None,
                      help="explicit loopback UI port (else auto-pick from profile range)")
    p_up.add_argument("--allow-host", dest="allow_host", default=None,
                      help=("research-sandbox only: hosts the session may fetch "
                            "(repeatable via comma-separated list; deny-by-default)"))
    p_up.add_argument("-y", "--yes", action="store_true",
                      help="non-interactive risk acknowledgement (research: THIS run only)")
    p_up.set_defaults(func=cmd_up)

    p_det = sub.add_parser("detonate", help="fetch a URL inside the T2 research plane (research-sandbox only)")
    p_det.add_argument("--url", required=True,
                       help="target URL (host must be on the session allowlist)")
    p_det.add_argument("--json", action="store_true",
                       help="print the full JSON report after the summary")
    p_det.set_defaults(func=cmd_detonate)

    p_st = sub.add_parser("status", help="read-only sandbox status")
    p_st.add_argument("--security", action="store_true",
                      help="show the live security-state card")
    p_st.add_argument("--json", action="store_true",
                      help="machine-readable posture + checks (implies --security)")
    p_st.set_defaults(func=cmd_status)

    p_pr = sub.add_parser("profiles", help="list profiles (and honest future pointers)")
    p_pr.set_defaults(func=cmd_profiles)

    p_plat = sub.add_parser("platform", help="show this platform's isolation-control report (G14)")
    p_plat.add_argument("--json", action="store_true",
                        help="machine-readable control report")
    p_plat.set_defaults(func=cmd_platform)

    p_stop = sub.add_parser("stop", help="stop services, preserving sandbox state")
    p_stop.set_defaults(func=cmd_stop)

    p_d = sub.add_parser("destroy", help="stop services and delete sandbox state")
    p_d.add_argument("--yes", action="store_true",
                     help="required confirmation: destroy deletes state and cannot be undone")
    p_d.set_defaults(func=cmd_destroy)

    p_rp = sub.add_parser("replay", help="list/replay LOCAL synthetic sessions")
    p_rp.add_argument("--session", default=None,
                      help="session id to replay (default: list sessions)")
    p_rp.add_argument("--limit", type=int, default=20,
                      help="listing limit (default 20)")
    p_rp.set_defaults(func=cmd_replay)

    p_logs = sub.add_parser("logs", help="print/stream sandbox logs")
    p_logs.add_argument("--service", default=None,
                        help="limit to one service (e.g. sb-app)")
    p_logs.add_argument("--tail", type=int, default=200,
                        help="lines to show (default 200)")
    p_logs.add_argument("-f", "--follow", action="store_true",
                        help="stream until interrupted")
    p_logs.set_defaults(func=cmd_logs)

    p_insp = sub.add_parser("inspect", help="live security posture + inventory")
    p_insp.set_defaults(func=cmd_inspect)

    p_exp = sub.add_parser("export", help="export sanitized telemetry bundle")
    p_exp.add_argument("--out", default=None,
                       help="destination directory (default: ./<project>-export)")
    p_exp.add_argument("--force", action="store_true",
                       help="allow overwriting an existing destination")
    p_exp.set_defaults(func=cmd_export)

    p_reset = sub.add_parser("reset", help="reset telemetry state to the clean baseline")
    p_reset.add_argument("-y", "--yes", action="store_true",
                         help="non-interactive confirmation")
    p_reset.set_defaults(func=cmd_reset)

    p_rec = sub.add_parser("recover", help="converge a PARTIAL/stale sandbox back to truth")
    p_rec.set_defaults(func=cmd_recover)

    p_ver = sub.add_parser("verify", help="run the security checklist against a RUNNING sandbox")
    p_ver.add_argument("--json", action="store_true",
                       help="machine-readable posture + check results")
    p_ver.add_argument("--strict", action="store_true",
                       help="treat unknown checks as failures")
    p_ver.set_defaults(func=cmd_verify)

    p_sbom = sub.add_parser("sbom", help="generate SBOMs and classify vulnerabilities (G10)")
    p_sbom.add_argument("--out", default=None,
                        help="output directory (default sbom/local-<name>)")
    p_sbom.add_argument("--image", action="append", default=None,
                        help="scan explicit image ref(s) instead of a running sandbox (repeatable)")
    p_sbom.set_defaults(func=cmd_sbom)

    p_rb = sub.add_parser("rebuild-images", help="rebuild images from pinned sources (--no-cache)")
    p_rb.set_defaults(func=cmd_rebuild_images)

    p_upg = sub.add_parser("upgrade", help="re-converge a stopped sandbox onto current config")
    p_upg.add_argument("--ui-port", type=int, default=None,
                       help="explicit loopback UI port (else auto-pick from profile range)")
    p_upg.add_argument("-y", "--yes", action="store_true",
                       help="non-interactive risk acknowledgement")
    p_upg.set_defaults(func=cmd_upgrade)

    return ap


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ValueError as ve:
        print(f"✗ {ve}")
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
