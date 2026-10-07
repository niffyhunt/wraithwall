# The sandbox vs. a real deployment (the Cowrie VPS)

This page exists because the most common point of confusion deserves its own
URL. It is kept as the canonical framing of what the sandbox actually is.

## The one-paragraph version

WraithWall's intelligence stack — Cowrie session analysis, campaign
correlation, MITRE mapping, bait commands, canaries, dashboards — normally
runs on a **real deployment**: a hardened VPS running a real honeypot that
real attackers on the real internet connect to. The Local Secure Sandbox is
**that same application pipeline, running locally, fed synthetic telemetry
instead of internet traffic**. Same engines, same dashboards, same replay —
zero internet exposure. Nothing listens for attackers; nothing reaches out to
them; the "attackers" are a deterministic, repo-shipped corpus.

## Side by side

| | Real deployment (Cowrie VPS) | Local sandbox (T1) |
|---|---|---|
| Who connects | Real attackers, real internet | Nobody — synthetic corpus is injected |
| Where data comes from | Actual SSH/Telnet sessions | Fixed-seed generator, byte-identical on every machine |
| Egress | By design of the deployment | Default-deny, proven by live canary at every boot |
| Exposure | Public IP, monitored, defended | `127.0.0.1`-only publishes, LAN refuses |
| Data sensitivity | Real attacker behavior — handle accordingly | LOCAL-marked synthetic — safe to inspect/export |
| Purpose | Production intelligence | Development, demos, replay, bug reproduction |
| Persistence | Operational state, kept | Disposable by design; reset/destroy anytime |

## What this means for demos and bug reports

- **A demo never pretends to be live telemetry.** Everything on the
  dashboard is LOCAL-marked end to end, and `replay list` only ever shows
  synthetic sessions. If you screenshot it, the provenance is in the data.
- **A bug report can be replayed byte-for-byte.** Because the corpus is a
  pure function of `seed_version`, a maintainer sees exactly what you saw —
  the thing a real deployment can never offer (see `bug-reports.md`).
- **Learning the operator flow is safe.** Correlation, MITRE mapping, TTY
  replay, alert wiring — the whole reasoning stack — can be exercised without
  operating a real honeypot or touching attack surface.

## What the sandbox is NOT

- **Not a honeypot.** It does not listen on attacker-facing ports, and the
  `external-sensor` "profile" that would ship telemetry to a real deployment
  is deliberately not a local profile at all.
- **Not a smaller production.** No production data, credentials, alerts, or
  infrastructure are involved or reachable; the phrase "the intelligence
  stack" always means *the application pipeline against synthetic inputs*.
- **Not a malware or attacker-content lab.** Untrusted-content testing is
  future T2 work; the honest pointer lives in `profiles.md`.

## The design reason this split exists

Real deployments earn their intelligence by being exposed — deliberately,
carefully, on infrastructure built to take hits. A developer laptop is the
opposite of that. The sandbox keeps the *analysis* half of the product
portable and safe, while the *exposure* half stays where it belongs: on
dedicated, disposable, watched infrastructure.
