# Profiles

WraithWall Local Secure Sandbox ships **three real profiles** and two honestly
named future pointers. This page mirrors `sandbox_kit/profiles.py` — the code
is the single source of truth, and the doc-freshness gate
(`tests/test_sandbox_platform.py`) cross-checks vocabulary and commands.

## The five names

| Profile | Tier | Real? | Runtime | Confirmation | Data source | Port range (loopback) |
|---|---|---|---|---|---|---|
| `app-only` | T0 | **Yes — default** | not required | none | none (no telemetry generated) | 8200–8299 |
| `local-sandbox` | T1 | **Yes** | required | one-time risk acknowledgement | repo-shipped synthetic seed, fixed-seed, LOCAL-marked | 8100–8199 |
| `research-sandbox` | T2 | **Yes — opt-in** | required + **rootless enforced (E203)** | **per-session** (never stored) | developer-listed hosts via the T2 egress proxy + the T1 synthetic corpus | 8300–8399 |
| `vm-sandbox` | T3 | recipe only | — | — | — | — |
| `external-sensor` | — | not a local profile | — | — | — | — |

## app-only (T0) — the default

```bash
./sandbox.sh up --profile app-only
```

Runs the WraithWall application so you can read code, exercise routes, run the
UI, and develop — with **zero attacker-like input**. No containers, no
telemetry, no generator. If you asked to "just run WraithWall locally", this
is what you get. Higher memory floor than a bare Flask run, but no runtime
prerequisites beyond Python.

## local-sandbox (T1) — the full synthetic experience

```bash
./sandbox.sh up --profile local-sandbox
```

Boots the hardened compose topology and flows the deterministic synthetic
corpus through the **real, unmodified** Cowrie intelligence pipeline, so
dashboards, SSE live events, TTY replay, campaign correlation, and MITRE
mapping all work against data that was born synthetic and stays local.

**One-time confirmation gate**: the first `up` for this profile prints what
will run, what is isolated, what is *not* guaranteed, and requires an explicit
yes (`-y` for scripts). The acknowledgement is recorded in the sandbox state;
it never auto-activates a higher tier later.

## research-sandbox (T2) — untrusted-content testing, opt-in

```bash
./sandbox.sh up --profile research-sandbox --allow-host example.com
./sandbox.sh detonate --url https://example.com
```

The only profile where sandbox code fetches anything you point it at. The
shape, enforced by compose gates and two self-checks on every start:

- **Rootless enforced**: T2 treats `rootless-runtime` and `user-namespace` as
  load-bearing controls (`./sandbox.sh platform`); without them startup
  refuses with **E203** — it never degrades to a weaker mode.
- **Per-session allowlist (E210)**: you list the hosts this session may fetch.
  Deny-by-default — no list, no start. The list lives in the sandbox state
  and dies with the project.
- **Enforcing proxy**: all fetches go through `sb-egress`, which applies two
  layers — the session allowlist, then the shared deny policy
  (`sandbox_kit/egress_policy.py`): RFC1918, loopback, link-local/metadata
  ranges and hostnames, CGNAT, Docker's DNS stub, all IPv6 (incl. mapped),
  DoT and DoH shapes. Policy fires **even for allowlisted hosts**.
- **Per-session confirmation**: every `up` re-asks; nothing is persisted, so
  a stored "always allow" cannot exist.
- **Self-checked**: the policy classifies a canonical deny set inside the
  image (E212 path) and the detonation container must prove it has no direct
  egress or DNS (E202 path) before the profile reports RUNNING.

**Honest claims**: improved isolation for untrusted-*content* testing — NOT
hostile-code containment. The detonation container shares your kernel; do not
detone anything whose escape you are not prepared to survive (see
`threat-model.md`). There is no malware corpus, no sample hosting, no
"containment" claim anywhere in this profile.

## The future pointers (and why they don't run)

Asking for them is not an error — the CLI tells you the truth:

- **vm-sandbox (T3)**: VM-backed isolation is a documented recipe only — no VM
  tooling exists in this repository.
- **external-sensor**: not a local profile at all; it concerns shipping
  telemetry to a real deployment and is deliberately outside the sandbox.

See `security-model.md` for the tier definitions and exactly which claims each
tier is allowed to make, and `platforms.md` for what `./sandbox.sh platform`
verifies about *your* host before T2 starts.

## Listing profiles

```bash
./sandbox.sh profiles
```

Output is generated from the same `MVP_PROFILES` / `FUTURE_PROFILES` objects
this page documents — if they ever disagree, that's a bug, and the
doc-freshness test is the tripwire.
