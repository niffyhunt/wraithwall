# Platform support & the G14 control report

WraithWall Local Secure Sandbox is a **Linux-container product with labeled
degradation** — not a universally portable one. This page is the honest
support matrix, and it is cross-checked by CI: the matrix below and the
`sandbox matrix: …` CI jobs must agree (doc-freshness gate,
`tests/test_sandbox_platform.py`).

## TL;DR

| Platform | app-only (T0) | local-sandbox (T1) | Notes |
|---|---|---|---|
| Linux x86_64 (Ubuntu 22.04+/Debian 12+) | ✅ Full (reference) | ✅ Full (reference) | All controls verify ACTIVE; rootless UNAVAILABLE unless run rootless |
| Linux arm64 (Graviton, RPi 5 8GB, AS VMs) | ✅ Full | ✅ Full with arm64 image variants | QEMU CI job is best-effort; digest-pinned images need arm64 variants |
| Linux rootless (rootless docker/podman) | ✅ | ✅ Preferred | podman counts as rootless by default in the G14 report |
| macOS 13+ (Apple Silicon / Intel) | ✅ Full | ✅ Full inside Docker Desktop VM | **Boundary = the Desktop VM**; G14 labels userns UNAVAILABLE host-side honestly |
| Windows 11 + WSL2 | ✅ (inside WSL2) | ✅ (WSL2 + Docker Desktop) | WSL2 kernel answers the userns sysctl — it *is* the enforcing kernel |
| Windows native (no WSL2) | ❌ refused (E104) | ❌ refused (E104) | Fail-closed message with WSL2 instructions; never degrades silently |
| Offline / restricted network | ✅ | ⚠️ pre-pull images (`rebuild-images`) | Runtime itself needs no network |

## The G14 report

Every container-profile startup (and `wraithwall sandbox platform`) probes the
actual host and daemon, then reports each isolation control as one of:

| State | Meaning | CI / gate behavior |
|---|---|---|
| **ACTIVE** | Verified present on this host (probed, not assumed) | counts toward the posture |
| **UNAVAILABLE** | Verified absent (probe answered "no") | warning on T1; **E203 refusal if load-bearing for the tier** |
| **UNKNOWN** | Probe could not answer (daemon down, crash, no runtime) | never counted as present; **E203 refusal if load-bearing for the tier** |

Current controls: `no-new-privileges`, `caps-drop-all`, `read-only-rootfs`
(compose baseline, enforced by the container kernel), `seccomp`,
`resource-limits`, `user-namespace` (load-bearing for the future T2),
`rootless-runtime` (load-bearing for the future T2), and host `lsm`
(informational).

Commands:

```bash
./sandbox.sh platform          # human card: ACTIVE / UNAVAILABLE / UNKNOWN
./sandbox.sh platform --json   # machine-readable report (CI consumes this)
```

The report is embedded in the state file's `gates` block at `up` time, so a
sandbox records exactly what was verified on its host when it started.

## Tier rule (E203)

T0/T1 designate **no** load-bearing platform controls today: platform gaps are
printed as warnings and labeled — exactly the Stage 3 matrix's
`warn (T1) / refuse (T2)` split. Since Phase 11 the research-sandbox (T2)
designates `rootless-runtime` + `user-namespace` load-bearing: without them
startup refuses fail-closed with E203. That refusal path exists,
is mutation-tested, and never degrades silently. Run `./sandbox.sh platform`
before attempting T2 — it is the same report the gate consumes.

## WSL2 checklist (Windows contributors)

1. Install WSL2 (`wsl --install`) — WSL2 itself is the VM boundary for T1.
2. Install Docker Desktop with the **WSL2 backend** enabled.
3. Work *inside* the WSL2 distro (native `main.py` is refused — POSIX-only
   components such as `fcntl`).
4. Run `./sandbox.sh platform` first: the WSL2 kernel is the enforcement
   point, so its sysctl answers are authoritative in the report.
5. Filesystem note: keep the repo inside the distro's home (`~/…`), not
   `/mnt/c/…` — bind-mount performance and permission semantics differ.

## Docker Desktop (macOS) honesty note

On macOS, hardening controls (caps drop, no-new-privileges, read-only
rootfs, seccomp) are enforced by the **Linux kernel inside the Docker
Desktop VM**, not by macOS itself. The G14 report labels this
("enforcement lives inside the runtime VM") rather than pretending the
host kernel enforces anything. This is a labeled limitation, not a
different security claim: the T1 boundary statement in
`security-model.md` is unchanged.

## Doc-freshness gate

`tests/test_sandbox_platform.py` verifies: the `platform` command exists in
`--help` output, its `--json` shape carries the documented summary keys, and
the matrix rows above match the platforms the CI jobs actually run
(linux-x86_64 reference, macOS best-effort, arm64 QEMU best-effort). If you
edit this matrix, run that test file — it fails when docs and reality drift.
