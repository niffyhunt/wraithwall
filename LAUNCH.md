# WraithWall — The Cool Stuff

A field guide to what this platform actually does. WraithWall is a solo-built, production
**security operations hub** running on live internet traffic: public security tools, an
authenticated operator console, and a deep stack of **active-defense / deception**
subsystems that turn an attacker's own behaviour into intelligence.

The organizing idea behind all of it: **most security tools describe what the dashboard
shows. WraithWall is built around what the *attacker* experiences** when they hit the
perimeter — what they type, the tools they reuse, how they move — because that's where the
real signal lives.

---

## 🍯 Deception & Honeypot Intelligence

**SSH/Telnet honeypot pipeline.** A watcher tails the honeypot's JSON event log into a
bounded event queue, a small worker pool rebuilds each session in Redis, and completed
sessions that actually ran commands get scored and archived.

**Deterministic threat scoring + MITRE ATT&CK mapping.** Every session is scored with a
transparent formula — base points for the furthest kill-chain stage reached, plus
bonuses for command volume and technique diversity, capped at a ceiling — so you can
explain exactly why something lit up. Commands map to MITRE techniques by a
case-insensitive substring table (`authorized_keys` → T1098, `chmod +s` → T1068,
`uname`/`whoami` → T1082, …). An optional LLM pass adds narrative analysis, but the
deterministic core stands alone. *(→ open-sourced, see below)*

**Bot-vs-human overrides.** Two honest, deterministic rules clean up the actor label:
`mdrfckr` + `authorized_keys` together = the Outlaw/Dota SSH-key worm (botnet node); a
session that ran real commands but connected and disconnected near-instantly is a script,
not hands on a keyboard. Overrides change the *label*, never the score.

**Alert dedup that you can actually live with.** The alert key is derived from the
session's command list, deduplicated within a sliding window. One worm hitting fifty
boxes in a minute is **one** notification — but every source IP is still recorded under
the signature, so the full spread stays queryable.

**LLM honeypot.** LLM-driven responses that keep an attacker talking to a convincing
mirror instead of your real stack.

---

## 🔗 Correlation & Campaign Tracking

**Behavioural campaign correlation.** Each completed session becomes a fingerprint — a
SimHash over *normalised* commands (IPs, paths, numbers, base64 blobs collapsed to
placeholders), plus tool signatures, credential patterns, and timing. Two fingerprints
are scored across nine weighted components that sum to 1.0; strong similarity indicates
the same actor, very high similarity folds sessions into a tracked campaign. A pattern
repeating in a short window gets promoted to a tracked campaign with its own IP set,
sensor set, and tool sequence.

**Tooling detection.** Regex signatures for the usual suspects — masscan, nmap, zmap,
hydra, medusa, ncrack, metasploit, cobalt strike, mirai, xmrig, gost, chisel, frp,
linpeas.

**Fingerprint corpus.** Passive request fingerprinting (JA3 / HASSH / header-ordering /
cadence) collected as a `before_request` hook and correlated across infrastructure
rotations.

**ASN / abuse intelligence.** ASN reputation, leaderboards, and abuse reporting.

---

## 🛰️ Network & Supply-Chain Monitoring

**BGP hijack monitoring.** Learns a baseline of normal routes for owned prefixes, then
watches streamed + polled route feeds for origin-AS changes and new ASes in the path.
When a source IP sits in a prefix being hijacked right now, the session score escalates
accordingly.

**Supply-chain canary tokens.** Cryptographically-derived canary tokens planted across
the supply chain; when one beacons, the trigger is matched straight back to where it was
planted. *(→ open-sourced, see below)*

**Credential propagation.** Fake credentials derived with keyed derivation per-lure,
planted on gists/pastes and rotated on a schedule — so a planted credential turning up
in a honeypot login links straight back to its origin.

---

## 🧰 Config, Integrity & Platform

**Deception Markup Language (DML).** Traps as a versioned, signed document — nine
trigger types and eight response types, with HMAC-SHA256 signatures per-trap *and* over
the whole document, so any tampering is detectable. Honeytokens and canary records
round-trip through the same format. *(→ open-sourced, see below)*

**Hash-chained immutable audit log.** Each entry stores a SHA-256 of its data plus an
entry hash over `index : previous_hash : data_hash`; editing anything upstream breaks
the chain for everything after it. Archived to S3 daily.

**Proof-of-work gateway.** A scoring/PoW challenge gate with a Redis-backed IP blocklist
in front of the request pipeline.

**Link / URL reputation sandbox.** Public suspicious-URL and domain reputation scanning.

**Incident response playbooks**, an **admin AI console**, a **public stats API** (served
from Redis), and a session-cookie auth system with 2FA, trusted devices, and backup
codes.

---

## 🌐 The Site Itself

Vue 3 SPAs and SSG front-ends (landing, blog, operator console, authenticated dashboard,
full auth journey) over a Flask monolith holding the auth system, the JSON API, and the
scheduler — deliberately a monolith, because one engineer pays for a service mesh every
day and only collects at a team size that doesn't exist yet.

---

## 📦 What's being open-sourced

Three of the most reusable, self-contained pieces are being lifted out, cleaned of all
product/secret coupling, and released under **MIT**. If you already run a honeypot, or
you want your deception config versioned like code, these are for you:

| Project | What it does |
|---|---|
| **[Canary Kit](open-source/canary-kit/)** | Mint, register, and detect supply-chain canary tokens — match an incoming beacon straight back to the token you planted. |
| **[Honeypot → MITRE](open-source/honeypot-mitre/)** | Turn raw Cowrie honeypot logs into structured ATT&CK techniques, a deterministic score, and replay dedup — no LLM required. |
| **[Deception Markup Language](open-source/dml-spec/)** | A versioned, HMAC-signed spec for deception/trap config — validate, sign, and verify so your traps are diffable and tamper-evident. |

Each ships as a standalone `pip install`-able package with its own README, examples,
tests, and CLI. See [`open-source/README.md`](open-source/README.md) for the toolkit
overview.

---

## 📐 Architecture & runtime visualization (Phase 8–9)

**Validated corpus.** Machine-readable artifacts in `docs/architecture/` — subsystems,
dependency/runtime/event graphs, trust boundaries, live telemetry contracts.

**Public blueprints.** Four redacted engineering overviews (system, runtime, threat-intel
pipeline, notifications) ship on the landing page at
[/console#/architecture](https://wraithwall.online/console#/architecture). Hosts, deception internals,
and operator paths are redacted for safe public indexing.

**Operator console.** Authenticated users access the full diagram corpus and interactive
graph API at `/console#/architecture`.

**Live telemetry on the landing page.** HeroTerminal globe, public stats API, attack
feed table, BGP watch strip, and TelemetryChart snapshots — all fed from
`/api/public/stats` and health endpoints.

**Documentation hub.** [wraithwall.online/docs](https://wraithwall.online/docs) indexes
launch materials, blog, OSS, and architecture entry points.
[wraithwall.online/launch](https://wraithwall.online/launch) is the Phase 9 launch
summary.

Regenerate diagrams:

```bash
python3 scripts/generate_wraithwall_diagrams.py
```

---

## 📡 Cowrie integration (production path)

The Cowrie honeypot runs on a remote VPS. Logs are shipped to the main platform where
the `cowrie_intelligence.py` watcher handles session scoring, MITRE mapping, and alert
dedup, feeding into the campaign correlator for cross-session clustering.

See `cowrie-analyzer/` for the Dockerized sensor stack and
`docs/launch/WEBSITE_INTEGRATION_REPORT.md` for the Phase 9 integration summary.

---

## 📚 Technical knowledge pipeline (separate from deception)

Engineering publications for defenders live in `docs/knowledge-pipeline/`. **Not**
coupled to `credential_propagation.py` lure planting. Draft reports await operator
approval before external publish.

---

*Part of the WraithWall project — <https://wraithwall.online> ·
[Documentation](https://wraithwall.online/docs) ·
[Blog](https://wraithwall.online/blog) · by
[Niffy_hunt](https://x.com/Niffy_hunt) ·
[@wraithwalll](https://x.com/wraithwalll?s=11)*

*Historical note: Sections above were added in Phase 9 (July 2026). Earlier sections
describing "two OSS modules preparing for release" remain accurate for May 2026
context — four toolkit packages are now public.*
