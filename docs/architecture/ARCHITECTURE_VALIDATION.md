# Architecture Validation Report

**Phase A — Cross-referencing architecture.json (29 subsystems) against actual codebase files**

Date: 2026-07-09
Confidence scale: 0.0 (not found) → 1.0 (fully matches)

---

## Validation Table

| # | Subsystem | Owner File(s) | Confidence | Status | Key Findings |
|---|-----------|---------------|-----------|--------|-------------|
| 1 | Gateway / Proof-of-Work | `gateway.py` | 1.0 | ✅ Match | 3 routes, 4 Redis keys, all verified. |
| 2 | Attractor Sandbox | `main.py`, `sandbox.py` | 0.95 | ✅ Match | _bg_enter_sandbox threads, Redis state (`attractor_sandbox:{ip}`), SandboxSession model — all confirmed. |
| 3 | Hall of Mirrors | `main.py` | 0.90 | ⚠️ Partial | Redis keys (`mirror:{ip}:{sid}`, `mirror_depth:{ip}`) confirmed. `/api/mirror/status` route confirmed. Deception-layer integration relies on middleware interception. |
| 4 | Timing Canaries | `main.py` | 0.90 | ✅ Match | Redis keys (`timing_canary:*`) confirmed. `_bg_alerts` thread per hit. All 3 Redis patterns verified. |
| 5 | Honeytokens | `main.py` | 0.95 | ✅ Match | HoneyToken + HoneyTokenEvent models, middleware hook at line 7288, alert threads, dedup. All confirmed. |
| 6 | Canary Service | `canary_service.py` | 0.95 | ✅ Match | 16 routes, 8 Redis key patterns, 3 models, Paystack/BTCPay webhooks, trial billing — all verified in file. |
| 7 | Supply Chain Canary | `supply_chain_canary.py` | 0.90 | ✅ Match | 4 routes, 6 Redis key patterns, beacon/lure tracking. Beacon 365d TTL confirmed. |
| 8 | Fingerprint Corpus | `fingerprint_corpus.py`, `main.py` | 1.0 | ✅ Match | 7 routes, 14 Redis keys, middleware at line 1208. Every key pattern confirmed. |
| 9 | Session DNA | `main.py` | 0.95 | ✅ Match | SessionDNA/SessionEvent/DNAAlert models, `track_dna_event` at line 7112, _record_and_score_dna thread. All verified. |
| 10 | Cowrie Behavioral DNA | `behavioral_dna.py` | 0.90 | ✅ Match | BehavioralActor/MergeLog models, 4 Redis key patterns. `process_session()` API confirmed. |
| 11 | Cowrie Intelligence Pipeline | `cowrie_intelligence.py` | 0.92 | ✅ Match | 6 routes, 11 Redis keys, 3 daemon threads, event_queue/alert_queue, LLM enrichment chain (Groq→DeepSeek→Anthropic). All confirmed. |
| 12 | Campaign Correlator | `campaign_correlator.py` | 0.90 | ✅ Match | 3 routes, 5 Redis keys, 8-dim ensemble, Redis-only persistence. recent_fingerprints capped at 10000 confirmed. |
| 13 | Credential Propagation | `credential_propagation.py` | 0.85 | ✅ Match | 3 routes, 3 Redis keys, auto_rotate daemon. stop() method defined but never called — verified. |
| 14 | ASN Intelligence | `asn_intelligence.py` | 0.95 | ✅ Match | 4 routes, 8 Redis keys, ThreadPoolExecutor(8). `_auto_report_asn` dead code (pass body) confirmed. |
| 15 | BGP Monitor | `bgp_monitor.py` | 0.95 | ✅ Match | 5 routes, 5 Redis keys, RIPE RIS WebSocket + Cloudflare Radar dual feed. Infinite reconnect loop confirmed. |
| 16 | LLM Honeypot | `llm_honeypot.py` | 0.95 | ✅ Match | 5 routes, 3 Redis keys, 3 background threads. classify_injection() used as AIRS fallback. Budget tracking confirmed. |
| 17 | LLM Firewall | `llm_firewall.py` | 0.97 | ✅ Match | 4 routes, 8 Redis keys, 3-layer analysis. Layer 1 fail CLOSED, llm_cache 3600s TTL confirmed. |
| 18 | AI Runtime Security | `ai_runtime_security.py` | 0.90 | ✅ Match | 4 routes, 2 Redis keys, 5 detectors, 2 SQLAlchemy models. Gated by `ENABLE_AI_RUNTIME_SECURITY`. |
| 19 | Link Checker | `link_checker.py` | 0.90 | ✅ Match | 5 routes, 1 Redis key (`lc_stats:{date}` — orphaned). External API chain confirmed. |
| 20 | Detonation Engine | `detonate.py`, `main.py` | 0.90 | ✅ Match | 4 routes, 4 Redis keys, Docker + Browserless. Queue cap 10, 35s timeout confirmed. |
| 21 | Breach Monitor | `main.py` (proxy), `breach-monitor/` | 0.90 | ⚠️ Partial | `breach_monitor_proxy.py` does **not exist** — proxy is inline in main.py. `keep_alive()` daemon thread confirmed. Separate subproject. |
| 22 | Incident Response | `incident_response.py` | 0.75 | ⚠️ Partial | 3 routes confirmed. No SQLAlchemy models in file (uses generic state). Low confidence reflects minimal implementation. |
| 23 | Immutable Log | `main.py` | 1.0 | ✅ Match | ImmutableLog model, write_immutable_log() called by 10+ subsystems, SHA-256 hash chain, S3/R2 try/except archive. All confirmed. |
| 24 | Public API / Stats | `public_api.py` | 0.95 | ✅ Match | 2 routes, 3 Redis keys. Reads cowrie_sessions:recent and bgp_monitor:alerts per request. |
| 25 | DML Engine | `dml_engine.py` | 0.80 | ⚠️ Partial | 3 routes, 2 Redis keys. CanaryRecord + HoneyToken DB writes confirmed. Deployed trap tracking uses Redis-only state. |
| 26 | Auth / Session Management | `main.py` | 0.95 | ✅ Match | 9+ routes, 12 models, 6 background threads per login. All 20 event types confirmed. |
| 27 | Notification Routing | `main.py`, `services/` | 0.97 | ✅ Match | 4 channels (Telegram, Discord, Email, Slack, Webhook), 25+ templates, Redis SETNX dedup. Fire-and-forget design confirmed. |
| 28 | Request Lifecycle / Middleware | `main.py` | 1.0 | ✅ Match | 8 before_request + 3 after_request handlers. Every middleware point confirmed at documented line numbers. |
| 29 | Leader Election / Engine Supervisor | `main.py` | 0.95 | ✅ Match | Redis lock `wraithwall:engine_leader` (SET NX, 45s TTL, 15s heartbeat). All 5 engine groups leader-gated. 2 unconditional threads. |

---

## Additional Codebase Components (not in architecture.json 29)

These files/nodes exist in the actual codebase but are not catalogued as distinct subsystems:

| Component | File | Notes |
|-----------|------|-------|
| Terminal Replay | `replay_tty.py` | Blueprint with 2 routes for TTY session playback via xterm.js |
| Ops Dashboard | `ops-dashboard/` | Standalone service (not part of main monolith) |
| Terminal | `terminal_bp.py` | 5364 bytes, 2 routes, registered in main.py |
| Attractor Profile | `main.py:3527` | Predictive canary / attacker profiling service |
| Provenance | `main.py` | IP mismatch / data provenance violation detection |
| Quantum Canaries | `main.py` | Fake-user / adaptive deception records |
| DNS Canaries | `main.py` | DNS-token / canarytoken.org resolver tracking |
| Reverse Canaries | `main.py` | Beacon / tracking-pixel planted intelligence |
| Crystal Classifier | `cowrie_intelligence.py` | Decision-gate triage (sub-component of Cowrie Pipeline) |

---

## Issues Discovered

| Severity | Issue | Subsystem(s) | Details |
|----------|-------|-------------|---------|
| 🔴 High | Redis-only persistence for campaign state | Campaign Correlator (12), Credential Propagation (13) | Redis restart loses all campaign/lure state. No PostgreSQL fallback. |
| 🟠 Medium | Dead code path | ASN Intelligence (14) | `_auto_report_asn` has `pass` body — abuse reports never sent despite `AUTO_ABUSE_REPORT` config. |
| 🟠 Medium | Dead code path | Credential Propagation (13) | `stop()` method defined but never called — daemon thread cannot be cleanly shut down. |
| 🟠 Medium | Orphaned Redis key | Link Checker (19) | `lc_stats:{date}` written via HINCRBY but never queried externally. |
| 🟡 Low | No standalone proxy file | Breach Monitor (21) | `breach_monitor_proxy.py` documented but does not exist; proxy logic is inline in main.py. |
| 🟡 Low | Incident Response has no models | Incident Response (22) | No SQLAlchemy models in file; minimal state management. Confidence 0.75 reflects thin implementation. |
| 🟢 Info | Cowrie `recent_events` vs `sessions:recent` drift | Cowrie Pipeline (11) | Two different Redis lists for similar cowrie session data — potential staleness in one path. |
| 🟢 Info | No SSE for sandbox/dna events | Middleware (28), Session DNA (9) | Public-facing SSE exists for link checker and cowrie but not for internal security event streaming. |

---

## Coverage Summary

- **29/29 subsystems validated** against codebase
- **25 subsystems** at confidence ≥ 0.90 (full match)
- **4 subsystems** between 0.75–0.90 (partial match / lower confidence)
- **9 additional codebase components** not in architecture.json
- **3 dead/orphaned code paths** discovered
- **1 Redis-only persistence risk** affecting 2+ subsystems
