# Domain Model

**Phase B — Logical domain groupings of all WraithWall subsystems**

---

## 1. Deception & Canary Systems (9 subsystems)

Subsystems that plant, track, and alert on deceptive assets to detect adversary activity.

| Subsystem | File | Role |
|-----------|------|------|
| Attractor Sandbox | `main.py`, `sandbox.py` | Contain suspicious IPs in fake environment; track exfiltration milestones |
| Hall of Mirrors | `main.py` | Psychological deception maze with layered fake environments; depth tracking |
| Honeytokens | `main.py` | Decoy API keys, credentials, and sensitive values that trigger on use |
| Timing Canaries | `main.py` | Detect credential reuse via intentional timing delays in fake credentials |
| Canary Service | `canary_service.py` | SaaS-style canary token minting with subscription/billing |
| Supply Chain Canary | `supply_chain_canary.py` | Beacons planted in code/artifacts to detect unauthorized execution environments |
| Credential Propagation | `credential_propagation.py` | Auto-rotate fake credential lures on external platforms |
| DML Engine | `dml_engine.py` | Validate/deploy Deception Markup Language trap definitions |
| Quantum Canaries | `main.py` | Fake-user / adaptive deception records (not in architecture.json 29) |
| Reverse Canaries | `main.py` | Beacon / tracking-pixel planted intelligence (not in architecture.json 29) |
| DNS Canaries | `main.py` | DNS-token / canarytoken.org resolver tracking (not in architecture.json 29) |

---

## 2. Threat Intelligence & Analysis (9 subsystems)

Subsystems that ingest, enrich, correlate, and analyze threat data from diverse sources.

| Subsystem | File | Role |
|-----------|------|------|
| Cowrie Intelligence Pipeline | `cowrie_intelligence.py` | Ingest SSH honeypot sessions; CRYSTAL triage; LLM enrichment |
| Campaign Correlator | `campaign_correlator.py` | Cluster SSH sessions into campaigns via 8-dim similarity ensemble |
| Cowrie Behavioral DNA | `behavioral_dna.py` | Track persistent SSH threat actors using behavioral biometrics |
| ASN Intelligence | `asn_intelligence.py` | IP → ASN/geo/ISP enrichment; VPN/Tor detection; attack attribution |
| BGP Monitor | `bgp_monitor.py` | BGP hijack/route-leak detection via RIPE RIS + Cloudflare Radar |
| Fingerprint Corpus | `fingerprint_corpus.py`, `main.py` | JA3/HASSH/UA fingerprint collection and threat scoring |
| Link Checker | `link_checker.py` | URL/domain/IP scanning through VT, URLScan, AbuseIPDB |
| Breach Monitor | `main.py` (proxy), `breach-monitor/` | Credential leak detection via Pastebin, GitHub, HIBP |
| Crystal Classifier | `cowrie_intelligence.py` | Decision-gate triage within Cowrie pipeline (not in architecture.json 29) |

---

## 3. Security Controls & Access (7 subsystems)

Subsystems that gate, validate, and protect access to application and AI resources.

| Subsystem | File | Role |
|-----------|------|------|
| Gateway / Proof-of-Work | `gateway.py` | Challenge-response PoW gate; IP scoring and auto-block |
| LLM Firewall | `llm_firewall.py` | 3-layer prompt security (regex → LLM → heuristic) |
| AI Runtime Security (AIRS) | `ai_runtime_security.py` | 5-detector AI abuse pipeline with per-owner policy |
| LLM Honeypot | `llm_honeypot.py` | Fake LLM endpoints that bait/detect/divert attackers |
| Provenance | `main.py` | IP mismatch / data provenance violation detection (not in architecture.json 29) |
| Request Lifecycle / Middleware | `main.py` | 8 before_request + 3 after_request handlers wrapping every HTTP request |
| Detonation Engine | `detonate.py`, `main.py` | URL sandbox detonation in Docker + Browserless |

---

## 4. Core Platform Services (10 subsystems)

Subsystems providing authentication, audit, state infrastructure, and public-facing APIs.

| Subsystem | File | Role |
|-----------|------|------|
| Auth / Session Management | `main.py` | Login, 2FA/TOTP, API keys, Google OAuth, password reset, trusted devices |
| Session DNA | `main.py` | Behavioral baselines and anomaly detection for authenticated users |
| Immutable Log | `main.py` | SHA-256 hash-chained tamper-evident audit log (40+ event types) |
| Public API / Stats | `public_api.py` | Public threat-intel statistics and live activity feed |
| Incident Response | `incident_response.py` | Playbook-driven incident response with step tracking |
| Notification Routing | `main.py`, `services/` | Dedup-aware dispatch to Telegram, Discord, Email, Slack, Webhook |
| Leader Election / Engine Supervisor | `main.py` | Redis-based leader lock ensuring single-worker engine execution |
| Terminal Replay | `replay_tty.py` | TTY session playback via xterm.js (not in architecture.json 29) |
| Terminal | `terminal_bp.py` | Terminal blueprint with 2 routes (not in architecture.json 29) |
| Attractor Profile | `main.py:3527` | Predictive canary / attacker profiling (not in architecture.json 29) |
| Ops Dashboard | `ops-dashboard/` | Standalone operations dashboard service (not in architecture.json 29) |

---

## Domain Relationship Summary

```
                      ┌──────────────────────────────┐
                      │   Request Lifecycle /         │
                      │   Middleware (8 handlers)      │
                      │   [Every HTTP request]         │
                      └──────┬───────┬───────┬───────┘
                             │       │       │
              ┌──────────────┘       │       └──────────────┐
              ▼                      ▼                      ▼
   ┌──────────────────┐  ┌────────────────────┐  ┌────────────────────┐
   │ Authentication   │  │  Fingerprint       │  │  Honeytoken        │
   │ & Session Mgmt   │  │  Corpus            │  │  Check             │
   │ (Auth Domain)    │  │  (Intel Domain)    │  │  (Deception Domain) │
   └────────┬─────────┘  └────────┬───────────┘  └──────────┬──────────┘
            │                     │                          │
            ▼                     ▼                          ▼
   ┌───────────────────────────────────────────────────────────────┐
   │                    Immutable Log (Audit)                       │
   │           SHA-256 hash chain, 40+ event types                 │
   └───────────────────────────────────────────────────────────────┘
            │                     │                          │
            ▼                     ▼                          ▼
   ┌──────────────────┐  ┌────────────────────┐  ┌────────────────────┐
   │ Notification     │  │  Threat            │  │  Sandbox /         │
   │ Routing          │  │  Intelligence      │  │  Deception         │
   │ (Telegram/Discord│  │  (Cowrie, ASN,     │  │  (Contain, Track,  │
   │  /Email/Webhook) │  │  BGP, Campaign)    │  │  Divert)           │
   └──────────────────┘  └────────────────────┘  └────────────────────┘
```

- **Deception outputs** → Immutable Log + Notification Routing + Sandbox containment
- **Intelligence outputs** → Immutable Log + Notification Routing + Campaign Correlator + Public API
- **Auth events** → Immutable Log + Session DNA + Notification Routing
- **All state** flows through Immutable Log and Notification Routing (cross-cutting concerns)
