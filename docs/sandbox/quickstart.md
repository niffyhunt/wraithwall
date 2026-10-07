# WraithWall Local Secure Sandbox — Quick Start

> **What this is:** an optional, disposable local environment for developing
> and demonstrating WraithWall safely. `app-only` runs the app with no
> attacker-like input; `local-sandbox` adds the hardened two-plane container
> boundary and (from Phase 4) synthetic LOCAL telemetry driving the real
> dashboards.
>
> **What this is NOT:** guaranteed malware containment. The sandbox shares the
> host kernel; it never runs hostile code, never listens on the internet, and
> never touches production data. Higher-risk work needs a VM or a dedicated
> host. Read `docs/sandbox/security-model.md` before quoting any security claim.

## Prerequisites

| Profile | Needs |
|---|---|
| `app-only` | Python 3.12+ · 512 MB free RAM |
| `local-sandbox` | Python 3.12+ · Docker or Podman with **Compose v2** · 4 GB free RAM · ~2 GB free disk for the first image build |
| `research-sandbox` | local-sandbox prerequisites **plus** verified rootless daemon · 6 GB free RAM · ~5 GB free disk for the detonation image |

Supported: Linux x86_64 (reference). macOS 13+ via Docker Desktop (labeled
limits). Windows: WSL2 only — native Windows is refused (E104).

## Start

```bash
./sandbox.sh up --profile app-only          # T0: gates + state, no containers
./sandbox.sh up --profile local-sandbox     # T1: build, boot, self-check (one-time ack)
./sandbox.sh platform                       # this host's isolation-control report (G14)
./sandbox.sh status
./sandbox.sh stop                           # stop services, keep the state volume
./sandbox.sh destroy --yes                  # stop services and delete all sandbox state (requires --yes)
```

The launcher is **fail-closed**: if a prerequisite, a static security gate, the
egress self-check, or the hardening inspection fails, it refuses with an E-code,
**tears down anything it started**, and reports what happened. There is no silent
fallback to a less safe mode, and a failed start never leaves containers behind.

### What `up --profile local-sandbox` actually does

1. prerequisite gates (E101–E106) against the host
2. static gates over `compose.sandbox.yml` (G1–G6, G7, G9, H10)
3. one-time risk acknowledgement (persisted)
4. builds the two sandbox images from an **allowlist** build context
5. `docker compose -p ww-sb-<name> up -d` — 4 services, 2 internal networks
6. **egress canary**: a probe on the application plane must fail to reach the
   internet *and* fail to resolve an external name (E202 if it succeeds)
7. **posture inspection**: `docker inspect` must show `cap_drop: [ALL]`,
   `no-new-privileges`, a read-only rootfs, uid `1000`, memory/CPU/PID caps and
   `restart: no` on every service (E205 otherwise)
8. only then is the sandbox reported `RUNNING`

The first run builds images, which takes a few minutes and roughly 2 GB of disk.
Later runs reuse the layers.

> **Uplink (opt-in, Phase 5).** Because both planes are `internal: true`,
> nothing is published by default (a published port is impossible on an
> internal network) — the UI is reachable only via the CLI. If you want the
> web UI in a browser, opt in explicitly:
>
> ```bash
> WRAITHWALL_SANDBOX_UPLINK=1 WRAITHWALL_SANDBOX_UI_PORT=8181 \
>   ./sandbox.sh up --profile local-sandbox
> ```
>
> This attaches a third, non-internal `uplink` network with **IP masquerade
> disabled** and re-runs the in-app egress canary on every start, so the app
> still has no route to the internet (measured, not assumed — hosts with
> default-deny firewalls block host→container forwarding entirely, which is
> why the uplink uses Docker's own publish path). The publish is
> `127.0.0.1`-only: nothing is exposed to your LAN. The uplink is a
> convenience, not an isolation boundary — see
> `docs/sandbox/network.md §2` for the full residual-risk write-up.

## Profiles

| Profile | Tier | Purpose | Data | Confirmation |
|---|---|---|---|---|
| `app-only` | T0 | Run the app locally; code, routes, UI, tests | none | none |
| `local-sandbox` | T1 | Hardened containers + synthetic LOCAL telemetry | synthetic, LOCAL, fixed-seed | one-time acknowledgement |
| `research-sandbox` | T2 | Untrusted-content testing via the enforcing egress proxy (opt-in) | developer-listed hosts + synthetic corpus | **per-session** + `--allow-host` |
| `vm-sandbox` | T3 | *recipe only* — disposable VM, no tooling in repo yet | — | — |
| `external-sensor` | T4-adjacent | *not a local profile* — ships to a real deployment with an operator key | — | — |

## research-sandbox (T2) in thirty seconds

```bash
./sandbox.sh up --profile research-sandbox --allow-host example.com
./sandbox.sh detonate --url https://example.com
./sandbox.sh logs --service sb-egress   # every EGRESS_ALLOW / EGRESS_DENY decision
./sandbox.sh destroy --yes
```

Rootless runtime required (E203 otherwise). Nothing is fetchable except the
hosts you listed (E210/E211), metadata/internal/IPv6/DoH are denied by policy
even for listed hosts, and two self-checks (E202/E212) must pass before the
profile reports RUNNING. Improved isolation — **not** hostile-code
containment; see `profiles.md` and `threat-model.md` for the honest limits.

## Services in `local-sandbox`

| Service | Role | Network | Published |
|---|---|---|---|
| `sb-app` | the application (hardened build, `WRAITHWALL_SANDBOX=1`) | `ww-app-net` + `ww-telemetry-net` | nothing |
| `sb-redis` | telemetry bus (ephemeral, tmpfs) | `ww-telemetry-net` | nothing |
| `sb-seed` | synthetic producer — fixed-seed LOCAL-marked corpus + tty logs (Phase 4) | `ww-telemetry-net` | nothing (writes into the shared project volume) |
| `sb-busybox-t` | egress-deny canary for the telemetry plane | `ww-telemetry-net` | nothing |
| `sb-busybox` | egress-deny self-check, runs on every start | `ww-app-net` | nothing |

## Failure codes

| Code | Meaning | Typical fix |
|---|---|---|
| E101 | container runtime missing | install Docker/Podman, or `--profile app-only` |
| E102 | Compose v2 missing / v1 found | Docker Desktop ≥ 24 or docker-compose-plugin |
| E103 | Python < 3.12 | install newer Python |
| E104 | native Windows | use WSL2 + Docker Desktop |
| E105 | RAM below the profile floor | free memory or `--profile app-only` |
| E106 | UI port unavailable | `./sandbox.sh status` → stop instance, or `--ui-port <free>` |
| E202 | **egress self-check failed** — a plane reached the network | report it; run `destroy` then `up` |
| E204 | secret-shaped value in the generated configuration | remove the value; report it |
| E205 | banned container option in the effective configuration | remove the override file named in the message |

State markers live in `~/.wraithwall-sandbox/<name>/` (override with
`WRAITHWALL_SANDBOX_DIR`). `destroy` removes the compose project (containers,
networks and volumes) **and** the state directory, and prints a receipt.

## Lifecycle commands

Available now: `up`, `status`, `profiles`, `platform`, `stop`, `destroy --yes`,
`logs`, `inspect`, `replay`, `export`, `reset`, `recover`, `verify`,
`rebuild-images`, `upgrade`.

### Your synthetic telemetry (Phase 4)

`local-sandbox` seeds itself: during `up`, the one-shot `sb-seed` container
writes a deterministic, LOCAL-marked corpus (24 sessions / 283 events) into
the sandbox volume, and the app's own watcher ingests it through the normal
pipeline — dashboards, correlation, MITRE mapping, deception bus and SSE all
light up with clearly-fake data.

```bash
./sandbox.sh status                          # shows telemetry counts + corpus digest
./sandbox.sh replay                          # list ingested synthetic sessions
./sandbox.sh replay --session <id>           # terminal replay of one session (tty)
```

Every record is marked `LOCAL` / sensor `ww-sandbox-local` — nothing here is
production telemetry, and the corpus is byte-identical for a given seed
version (see docs/sandbox/data-policy.md). Bug reports: `bug-reports.md`.
Reset/cleanup details: `reset-cleanup.md`. The full command reference:
`lifecycle.md`. What the sandbox is (and is not) relative to a real
deployment: `vs-production.md`. The abridged threat model:
`threat-model.md`. Profile semantics: `profiles.md`.

## Lifecycle (Phase 5)

```bash
./sandbox.sh logs --service sb-app --tail 100   # read service logs (-f to stream)
./sandbox.sh inspect                            # re-verify the live security posture on demand
./sandbox.sh export --out /tmp/bundle           # sanitized LOCAL telemetry bundle (SHA-256 manifest)
./sandbox.sh reset                              # purge synthetic telemetry back to the clean baseline
./sandbox.sh recover                            # converge a PARTIAL/stale sandbox back to truth
./sandbox.sh rebuild-images                     # fresh --no-cache build from the pinned sources
./sandbox.sh upgrade                            # re-converge a stopped sandbox onto current config
```

All lifecycle verbs are idempotent or explain why they cannot be, fail closed
with an E-code rather than guessing, and never leave a state marker that
contradicts reality. `destroy` remains the always-available clean exit.

## Seeing and verifying the security state

```bash
# one-card view of what is enforced right now (daemon-read, not compose-inferred)
./sandbox.sh status --security

# machine-readable posture + per-check results (12 isolation checks)
./sandbox.sh status --json

# score the RUNNING sandbox against the full checklist; exit 1 on any FAIL,
# unknown checks listed honestly (pass --strict to fail on those too)
./sandbox.sh verify
```

Every check scores tri-state: **pass** (daemon-verified), **FAIL** (control
absent), **unknown** (cannot know — degraded visibility is reported, never
silently scored as a pass). The card always carries the non-claims footer —
T1 isolation is blast-radius reduction, not hostile-code containment.

```bash
# static gates only — no daemon, no disk (runs in CI)
pytest tests/test_sandbox_static_gates.py -q

# live: builds images, boots the project, inspects posture, runs the canary.
# Heavy — run this on a machine with disk and RAM headroom, never on the
# production host.
WRAITHWALL_SANDBOX_LIVE=1 pytest tests/test_sandbox_live.py -v
```
