# Threat model (contributor edition)

The full threat model lives in `LOCAL_SANDBOX_THREAT_MODEL.md` (Stage 2
artifact, 25-row register with likelihood/impact/preventive/detective/
recovery columns). This page is the abridged edition a contributor actually
needs: the threats that shaped the default configuration, and what is
honestly left over.

## The one-line model

The sandbox's enemies are: **attacker-shaped data treated as instructions**,
**container escape**, **credential/environment discovery**, **unwanted
egress**, and **resource exhaustion**. Its assets are: your host, your
credentials, your network position, and your trust in what the dashboards
show you.

## Abridged register — highest-relevance rows

| Threat | Attack path | Preventive control (shipped) | Residual risk |
|---|---|---|---|
| Prompt/instruction injection via telemetry | Hostile strings from sessions becoming agent/operator instructions | Hostile content is corpus **data** (G12 tested: commands classify as data, never execute); docs treated as untrusted | A human reading raw logs can still be socially engineered — logging shows LOCAL marking everywhere |
| Container escape from a hardened service | Kernel exploit from inside sb-app/sb-redis/sb-postgres | Rootless-style hardening: `no-new-privileges`, all caps dropped, read-only rootfs, seccomp default, no socket mounts, non-root users, resource caps | Kernel-sharing containers are **not** a guaranteed host boundary — escape is low-likelihood, high-impact; for hostile content use a VM (T3 recipe), not T1 |
| Docker socket exposure | Container talks to the daemon, owns the host | **No socket mounts anywhere in the sandbox topology** (E205-gated); verified by `verify` live by *trying* it | If you add a socket mount yourself, you own the consequences |
| Credential/environment discovery | Attacker-controlled content scraping env vars | Sandbox containers receive no provider secrets; E204 refuses secret-shaped generated config; export deletes secret-shaped bundles | Host-level env of your *own* shell is yours to protect; keep real keys out of the sandbox on principle |
| Unrestricted outbound access | Sandbox phones home, joins C2, exfiltrates | Default-deny egress, proven live by the in-container canary (E202 refuses boot without proof); DNS blackholed on the uplink path | Kernel-level side channels and timing exist; "nothing leaves" is verified control, not physics |
| LAN/public exposure of ports | Neighbors reach the sandbox UI/db | Every publish is `127.0.0.1`-only, verified live (`verify` fails on any non-loopback publish); LAN address actively refuses connections | Other users on a multi-user host share your loopback — use per-user namespaces there |
| Resource exhaustion / fork bombs | A bug eats RAM/CPU/disk, host suffers | Per-service mem/cpu/pids caps at compose level; E105 refuses under-provisioned hosts | Disk-fill inside caps still reachable; caps bound the blast radius, not to zero |
| Persistent volumes surviving "cleanup" | Stale state masquerading as fresh | `reset` recomputes the baseline; `destroy --yes` removes volumes; `recover` reconciles ghosts | You can still `docker volume` around the tool; manual nuke doc shows how to check |
| Malicious/compromised image | Supply-chain pivot via base image | Digest-pinned images, `rebuild-images` from pinned sources, provenance digest recorded in state + shown by `status --security` | Registry compromise upstream is out of any local tool's reach; see `image-updates.md` (Phase 10) for SBOM/scan gates |
| Startup-script / repo-instruction abuse | Malicious README/scripts telling you to run dangerous things | Gates print exactly what will run and refuse unknown flags; docs are untrusted data | Read what `up` says before `-y`-ing; the acknowledgement is yours |
| T2: untrusted page content escapes the detonation container | Hostile fetched page exploits Chromium/kernel from `sb-detonate` | Rootless **enforced** (E203 refuses without it), same hardening anchor as every service, no direct DNS (`dns: 127.0.0.1`), no publishes, per-session allowlist + policy deny (E210/E211), self-checks E202/E212 before RUNNING | This is the highest-risk tier: a kernel escape from fetched content is possible by construction; treat T2 as improved isolation, **never** as containment — hostile-content work above toy scale belongs on a VM (T3 recipe) or a separate host |
| T2: allowlist mis-scoped to infrastructure | Developer allowlists `169.254.169.254` or a metadata-shaped host | E210 refuses at start time; the in-proxy policy refuses again at fetch time even if the list contained it; every decision logged | None known — two independent layers must both fail for this to reach the network |

## What is *not* in the model (because it is out of scope by design)

- **Arbitrary malware detonation** — T1 is not a malware lab; T2 adds
  untrusted-*content* fetching under enforced rootless + allowlist + policy
  controls, and still does not claim containment. T3 (VM recipe) is the
  documented escalation and remains tooling-free in this repository.
- **Host-level attacker containment** — a determined attacker with an escape
  exploit is a kernel problem, not a compose problem.
- **Multi-tenant separation on a shared laptop** — loopback is per-host, not
  per-user; see `platforms.md` for the shared-host caveat.

## How to verify these claims on *your* machine

```bash
./sandbox.sh platform            # what your host actually supports (tri-state)
./sandbox.sh verify              # 12 isolation checks against a RUNNING sandbox
./sandbox.sh status --security   # what was enforced when it started
```

`verify` re-proves the live claims: loopback-only publish, no socket access
(it tries), dropped capabilities, egress canary, provenance digests. If any
check can't be proven, it reports **unknown** — never silently pass.
