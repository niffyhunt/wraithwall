# Troubleshooting

Every sandbox failure exits non-zero with an **E-code**, a cause, and a fix.
This page maps each code to what actually happened. The codes are defined in
code — `sandbox_kit/gates.py` (E1xx), `sandbox_kit/gates_static.py` and
`sandbox_kit/compose.py` (E2xx/E3xx) — so if this page and the code ever
disagree, trust the code and file a bug (see `bug-reports.md`).

## Prerequisite gates (E1xx) — before anything starts

| Code | Meaning | Fix |
|---|---|---|
| **E101** | Container runtime binary missing or unusable (`docker` not found) | Install Docker Engine ≥ 24 (Linux) or Docker Desktop (macOS/WSL2); re-run. `app-only` needs no runtime. |
| **E102** | Runtime present but not Compose v2 (`docker compose` subcommand missing) | Install the `docker-compose-plugin` / update Docker Desktop ≥ 24. |
| **E103** | Python too old | Install Python 3.12+; re-run. |
| **E104** | Windows native refused | The sandbox uses POSIX-only components. Install WSL2 + Docker Desktop and run inside WSL2 (see `platforms.md`). This refusal is by design, not a bug. |
| **E105** | Not enough free resources for the profile | Free memory or drop to `--profile app-only` (needs ≥ 512 MB; `local-sandbox` needs ≥ 4096 MB). |
| **E106** | UI port unavailable (requested port busy, or the whole 8100–8199 / 8200–8299 range is taken/restricted) | `./sandbox.sh status` to find running instances and stop one, or `up --ui-port <free-port>`. |
| **E107** | Host firewall blocks host→container traffic — containers can be "healthy" while the UI is unreachable | Grant outbound access from the host to the sandbox's internal network (e.g. `ufw allow out <net>/24`, scoped to the sandbox subnet). Full write-up: `network.md §E107`. |

Gates are **fail-closed**: probe errors (permission denied reading cgroups,
daemon unreachable mid-probe) refuse startup with the same codes rather than
falling back to an unsafe or unknown state.

## Compose posture gates (E2xx) — static checks before boot

| Code | Meaning | Fix |
|---|---|---|
| **E202** | Egress isolation self-check failed — the sandbox could not prove default-deny egress from inside | Do not bypass. Check host firewall/DNS interference; see `network.md`. If you *intentionally* attached the opt-in uplink and the canary still fails, report it per `bug-reports.md`. |
| **E203** | Load-bearing platform isolation control UNAVAILABLE/UNKNOWN for the selected tier (tier-aware: warn on T1, refuse on future T2) | Run `./sandbox.sh platform --json` for the full tri-state report; drop to a lower tier or follow the VM recipe in `platforms.md`. |
| **E204** | Secret-shaped value detected in generated config | Never occurs with repo defaults; it means your environment leaks secrets into compose generation. Do not "fix" by stripping the check — find the leaking variable. |
| **E205** | Banned/broken compose option detected (privileged, host network, host PID, socket mounts, etc.) | The compose file is protected by its own gate. If you edited it, revert; if not, report it. |
| **E206** | Running images do not match the pinned supply chain (daemon digest ≠ pinned digest) | `./sandbox.sh rebuild-images`, then `up` again. If you cannot explain the drift, treat the environment as suspect (see `image-updates.md`). |
| **E210** | research-sandbox started without a usable `--allow-host` list (missing, empty, malformed, or every host refused by the egress policy) | Pass `--allow-host example.com` (comma-separated for several). Deny-by-default: with no hosts the profile can do nothing, so it refuses. Metadata/internal/IPv6/DoH-shaped hosts are refused here rather than silently at fetch time. |
| **E211** | `detonate` target is not on this session's allowlist, or is refused by the egress policy anyway | The allowlist is per-session (`up --allow-host …`). Destroy and re-run `up --profile research-sandbox --allow-host <host>` to change scope. The proxy enforces the same list at fetch time — the CLI refusal is the earlier, clearer half. |
| **E212** | Egress policy self-test failed inside the proxy image (a canonical deny case was ALLOWED) | The research plane must not start with a policy that cannot prove itself. `rebuild-images` and re-run; if it persists, report per `bug-reports.md` — do not bypass. |

E203 (platform controls) has its own row above; `platforms.md` is the deep dive.

## Lifecycle codes (E3xx) — while running

| Code | Meaning | Fix |
|---|---|---|
| **E301** | Stale/PARTIAL state — the state file disagrees with what the daemon actually has | `./sandbox.sh recover`. It converges state to truth or tells you the truth is gone (`destroy --yes` then `up` fresh). |
| **E304** | Synthetic seed generation failed | Usually disk space. Check `df -h`, free space, re-run; if the generator image changed, `rebuild-images` first. |
| **E305** | A service failed its health check during startup | `./sandbox.sh logs <service>` for the reason. Common causes: port stolen by another process after the gate, image pulled wrong architecture, OOM kill. |
| **E307** | Export refused — destination exists (pass `--force` to mean it), or the bundle contained a **secret-shaped string** and was deleted | Secret-shaped = generator bug: report per `bug-reports.md`. Never share a bundle that failed this check. |

## Patterns that are not bugs

- **`up` says already RUNNING with a different port** — a sandbox is live from
  an earlier session; `status` shows it. One sandbox per state file is the
  anti-parallel-start guarantee.
- **First `up` takes minutes, later ones don't** — image build happens once;
  `rebuild-images` forces it again.
- **`status` after reboot shows PARTIAL** — the Docker daemon restarted; the
  state file is honest about what's gone. `recover` handles it.
- **UI unreachable though compose says healthy on Linux with ufw** — that is
  E107, see above.

## Getting help

Collect a bundle first (`bug-reports.md`) — it contains the state file, gate
results, and compose posture snapshot with secrets redacted by design, so it
is safe to attach.
