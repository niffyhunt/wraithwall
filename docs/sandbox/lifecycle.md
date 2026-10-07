# Lifecycle reference

Every operation is idempotent or states why it cannot be. Exit codes: `0`
success, `1` gate refusal (fail-closed), `2` precondition error (nothing
running, destination exists, …). The authoritative contract lives in the
CLI (`sandbox_kit/cli.py`); this page is the user edition of the Stage 3
lifecycle contract.

## Start — `up`

```bash
./sandbox.sh up --profile app-only            # T0, no containers
./sandbox.sh up --profile local-sandbox -y    # T1, non-interactive ack
./sandbox.sh up --ui-port 8150                # explicit loopback port
```

Sequence: platform report (G14) → prerequisite gates (E101–E107) → static
compose posture gates (E202–E205) → image build/converge → seed → health →
`RUNNING`. Every gate refusal prints its E-code, the cause, and the fix.
The state file records the gates that passed, so `status` can show what was
verified at start time rather than inferred later.

Duplicate `up` on a RUNNING sandbox does not create a parallel environment —
it reports the existing one. A PARTIAL/stale state is refused with a pointer
to `recover`.

## Listing profiles — `profiles`

```bash
./sandbox.sh profiles
```

Prints the two real profiles and the honest future pointers, generated from
the same objects `profiles.md` documents (see that page for the full table).

## Stop — `stop`

Stops services, **preserves** sandbox state (volumes, seed baseline, state
file). Idempotent: stopping a stopped sandbox succeeds trivially.

## Status — `status`, `status --security`, `status --json`

Human card by default; `--security` adds the per-container hardening
aggregate, network-plane report, and provenance digest; `--json` is
machine-readable. Read-only against the recorded state and the Docker daemon
— never compose-inferred.

## Logs — `logs [service]`

Prints or streams compose logs. Works while stopped for services with
persisted logs (postgres, sb-app).

## Inspect — `inspect`

Live security posture + inventory, re-verified on demand: per-container
hardening, published ports, egress canary, provenance digests. This is what
`status --security` summarizes; `inspect` re-derives it from the daemon.

## Replay — `replay`

```bash
./sandbox.sh replay list          # LOCAL synthetic sessions
./sandbox.sh replay <session-id>  # TTY replay via replay_tty
```

Only sessions born from the synthetic corpus are replayable, and they are
marked LOCAL end to end.

## Export — `export [--out DIR] [--force]`

Assembles the synthetic corpus, tty logs, and pipeline session records into a
directory, then **scans the bundle for secret-shaped strings before keeping
it**. Anything secret-shaped ⇒ bundle deleted, exit 2, code **E307** — a
generator bug you're asked to report per `bug-reports.md`. Refuses to
overwrite an existing destination unless `--force`.

## Reset — `reset`

Returns telemetry state to the clean baseline: clears pipeline/telemetry
state, re-seeds deterministically. Idempotent by construction — the baseline
is a fixed-seed function, so reset always converges to identical bytes. Does
not touch images or config.

## Destroy — `destroy --yes`

Stops services **and deletes** sandbox state (containers, volumes, state
file). Refuses without `--yes` (it is the destructive one). After `destroy`,
nothing sandbox-owned remains; images are kept unless you also clean them.

## Rebuild images — `rebuild-images`

`--no-cache` rebuild from the pinned Dockerfiles. Use after pulling changes
that touch images, or when you suspect image drift.

## SBOM & scan — `sbom [--out DIR]`

Generates a CycloneDX SBOM per running image (syft) and classifies
vulnerability findings against the waiver register (grype when present).
Fail-closed semantics: no syft ⇒ exit 2, **nothing generated**; unwaived
CRITICAL/HIGH ⇒ exit 1 (release-blocking). Details: `image-updates.md`.

```bash
./sandbox.sh sbom                  # SBOMs to sbom/local-<name>/ + verdict
./sandbox.sh sbom --out /tmp/sb    # explicit destination
./sandbox.sh detonate --url https://example.com   # T2 research plane only (E211-gated)
```

## Upgrade — `upgrade`

Re-converges a **stopped** sandbox onto current config: config drift is
detected and the topology is brought to the new desired state. Run after
pulling; pair with `rebuild-images` when image inputs changed.

## Recover — `recover`

Converges a PARTIAL/STALE sandbox back to truth (code **E301** covers the
stale-marker case). Handles interrupted starts: containers that exist but
aren't in state, state that claims services the daemon doesn't have. When in
doubt after a crash or kill mid-start: `recover`, then `status`.

## Failure quick map

| Code | Meaning | First move |
|---|---|---|
| E101–E107 | prerequisite gate refused (OS, runtime, resources, ports, rootless, host firewall) | do what the message says; see `troubleshooting.md` |
| E202–E205 | compose posture gate refused (hardening/network/limits) | do not bypass; `troubleshooting.md` |
| E203 | load-bearing platform control missing (tier-aware) | see `platforms.md` |
| E301 | stale/PARTIAL state | `./sandbox.sh recover` |
| E206 | running images do not match the pinned supply chain | `rebuild-images`, re-run `up`; see `image-updates.md` |
| E304 | synthetic seed generation failed | check disk space; `rebuild-images` if the generator image changed |
| E307 | export blocked (secret-shaped or destination exists) | read the message; report if secret-shaped |
