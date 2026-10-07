# Sandbox security model

What the local sandbox actually enforces, how each control is verified, and
what it explicitly does not claim. Read this before repeating any security
statement about the sandbox in a README, a release note or a talk.

---

## 1. Honest claim

> The default sandbox (`local-sandbox`, Tier 1) runs WraithWall and synthetic
> telemetry in **containers with a hardened configuration on your machine**.
> This reduces blast radius and keeps everything local. It is **not** malware
> containment, and it is **not** a substitute for a VM or a dedicated host.

Every container shares the host kernel. A container escape is prevented by
container controls, not by a hypervisor. That is a real limitation of this tier,
and it is the reason tiers 3 and 4 exist.

## 2. Tiers

| Tier | Profile | Isolation | Allowed claim | Status |
|---|---|---|---|---|
| T0 | `app-only` | normal local processes | development/demo convenience | **shipped** |
| T1 | `local-sandbox` | hardened containers, internal networks, no egress, disposable volumes | bounded local development isolation | **shipped (Phase 3)** |
| T2 | `research-sandbox` | T1 + rootless enforcement (E203-refused without it) + per-session allowlist through the enforcing egress proxy (`sb-egress`) + policy deny (metadata/internal/IPv6/DoH) + two startup self-checks | improved isolation for untrusted-content testing; **not** hostile-code containment | **shipped (Phase 11, opt-in)** |
| T3 | `vm-sandbox` | disposable VM per session | stronger boundary; still needs operational discipline | *recipe only* |
| T4 | — | separate lab host or cloud isolation | not part of local startup | *out of scope* |

The default experience deliberately favours safe, understandable behaviour over
an implied guarantee. There is no silent path to a higher tier: `up` refuses
unimplemented profiles with a pointer instead of approximating them, and T2
requires an explicit per-session confirmation plus `--allow-host` before any
of its capabilities exist.

## 3. Hardening baseline (Stage 2 H1–H13)

Applied to **every** service in `compose.sandbox.yml`.

| ID | Requirement | Where it is enforced | How it is verified |
|---|---|---|---|
| H1 | `cap_drop: [ALL]`, no `cap_add` | compose, every service | gate G1 (static) + `HostConfig.CapDrop` (live) |
| H2 | `no-new-privileges` | compose `security_opt` | gate G1 + `HostConfig.SecurityOpt` |
| H3 | non-root, uid 1000 | compose `user:` + image `USER` | gate G4 + `docker exec id -u` |
| H4 | read-only rootfs, tmpfs scratch | compose `read_only` + `tmpfs` | gate G5 + `HostConfig.ReadonlyRootfs` |
| H5 | default seccomp profile | Docker default; nothing loosened | no `seccomp` override exists to weaken |
| H6 | mem/cpu/pids caps + log rotation | compose limits | gate G5 + `HostConfig.Memory/NanoCpus/PidsLimit` |
| H7 | no docker.sock, no privileged, no host net, no host binds | absent by construction | gates G1/G2/G3/G6 + `Mounts` inspection |
| H8 | published ports loopback-only | **nothing is published** | gate G6 + `HostConfig.PortBindings` empty |
| H9 | internal planes | `internal: true` on both networks | gate G7 + the egress canary (G7 dynamic), on **both** planes since Phase 4 |
| H10 | digest-pinned images | `sandbox_kit/images.py` | gate H10 |
| H11 | healthcheck per service | compose healthchecks | launcher waits; unhealthy = failed start |
| H12 | no `env_file`, explicit env allowlist | compose `environment` | gate G9 static + env-key check (G9 dynamic) |
| H13 | named volumes only, removed on reset | compose `volumes:` | gate G3 + `down -v` in teardown |

Two of these are worth calling out because they are stricter than the
requirement:

* **H8.** The requirement is "loopback-only publishing". This file publishes
  nothing at all — even to loopback — because a publish is incompatible with an
  internal network. See `docs/sandbox/network.md`.
* **H10.** The images *built from this repository* are tagged
  `wraithwall-sandbox-app:local` / `:local`, not digest-pinned, because a
  locally built image has no digest until it is pushed somewhere. The gate
  accepts exactly those two tags and rejects everything else that is unpinned.

## 4. The build context is an allowlist

Images are built from an explicit list of paths
(`sandbox_kit/images.py :: BUILD_CONTEXT_ALLOWLIST`), not from the repository
root. A `.dockerignore` denylist would have been the conventional choice, and it
is the wrong one here: a denylist can silently start shipping a file that a
future commit adds — a new `.env`, a new key. An allowlist cannot. A file that
is not named is not visible to the build.

This also keeps the context around 17 MB instead of ~5 GB. That matters on a
host without BuildKit, where a root-context build streams the entire repository
(venv, git history, sibling projects) to the daemon — which is what happened on
the first attempt here, and is why the allowlist exists.

## 5. Build-time network vs. runtime network

The image build has network access — pip has to reach an index. That is a build
concern and it happens on the developer's machine in their own daemon. The
**runtime** network is the one this document is about, and it is default-deny.

If you need reproducible, network-isolated builds, that is Phase 10 work
(provenance, SBOM, scanning, pinned build inputs).

## 6. What is deliberately not done

| Not done | Why |
|---|---|
| Running untrusted files or URLs | T1 does not claim containment. Use T3. |
| Publishing any port | incompatible with internal networks; see `network.md` |
| Mounting the repo into containers | a host mount is a two-way path (gate G3) |
| Copying `.env` or inheriting host env | G9; the compose file pins every provider key to `""` |
| Running as root "just for the sandbox" | there is no such exception; uid 1000 everywhere |
| Adding capabilities for convenience | gate G1 refuses `cap_add` without a written justification |
| Auto-selecting a weaker mode when a control is missing | fail-closed: refuse, print an E-code, change nothing |

## 7. Failure codes

| Code | Meaning |
|---|---|
| E101 | no container runtime |
| E102 | no Compose v2 |
| E103 | Python < 3.12 |
| E104 | native Windows (use WSL2) |
| E105 | RAM below the profile floor |
| E106 | UI port unavailable |
| E202 | **egress self-check failed** — a sandbox plane has an egress path |
| E204 | secret-shaped value in the generated configuration |
| E205 | banned container option in the effective configuration |

E202 is the important one: it means the isolation property did not hold, so the
start is refused and the containers are torn down. It should never appear. If it
does, it is a bug worth reporting.

## 8. Platform matrix (T1)

Full support matrix and the G14 control report: `docs/sandbox/platforms.md`.
Summary: Linux x86_64 is the reference platform; macOS/WSL2 are supported
with the runtime-VM boundary labeled; Windows-native is refused (E104);
UNAVAILABLE controls are warned on T1 and refuse with E203 when load-bearing
for the tier.

| Platform | Status | Notes |
|---|---|---|
| Linux x86_64 | reference | `internal: true` enforced by the host kernel |
| Linux arm64 | expected to work | not exercised in the reference run |
| macOS 13+ | supported via Docker Desktop | enforcement lives inside the Desktop VM; boundary is relative to that VM |
| Windows 11 + WSL2 | supported | run inside WSL2; native Windows is refused (E104) |
| Offline | works | images are pulled once; runtime needs no network |

Controls marked ACTIVE/UNAVAILABLE must be reported honestly rather than
silently skipped — a control that is not available on a platform may not be
claimed as present.

## 9. Verification

* **Static** (no daemon, runs in CI on every commit): the G1–G7/G9/H10 matrix,
  including a mutation test per gate that proves it fails closed.
* **Runtime** (`./sandbox.sh verify`): scores a RUNNING sandbox against a
  12-check isolation checklist (privileges, caps, no-new-privileges,
  read-only rootfs, uid 1000, bind mounts, resource limits, egress, docker
  socket, publish policy, telemetry provenance, restart policies) — all read
  from the Docker daemon, none inferred from compose files. Checks are
  tri-state: pass / FAIL / **unknown** (missing data is reported, never
  counted as a pass). `--json` emits the same data machine-readably.
* **Live** (opt-in, needs Docker and headroom):
  `WRAITHWALL_SANDBOX_LIVE=1 pytest tests/test_sandbox_live.py` — builds the
  images, boots the project, asserts the `docker inspect` posture, runs the
  egress canary in both the "host reaches app" and "app reaches nothing"
  directions, checks runtime uid, and proves teardown leaves nothing behind.

  These tests are space- and RAM-heavy and are **not** run on the production
  host; they were executed on a dedicated host with free disk.
