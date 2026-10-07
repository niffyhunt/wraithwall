# WraithWall Architectural Findings

**Derived from:** architecture.json, dependency_graph.json, event_graph.json, api_surface.json, scheduler_graph.json, redis_graph.json, RUNTIME_BEHAVIORAL_MODEL.txt, RUNTIME_EVENT_SPECIFICATION, VISUALIZATION_ARCHITECTURE.md

**Date:** July 9, 2026

---

## 1. Architectural Findings

Ranked by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO).

### Orphan Subsystems

| Severity | Description | Location | Impact | Recommendation |
|----------|-------------|----------|--------|----------------|
| MEDIUM | **Incident Response** subsystem has 3 routes but no DB models declared in its own blueprint, no persistent state, and confidence_score=0.75 — the lowest in the system. Its Redis usage is described as "1 Redis key" but the JSON declares `redis_keys: []`. The playbook system may be a stub. | `incident_response.py`, `architecture.json` subsystem #22 | Unclear if subsystem is functional; routes may return empty/placeholder data | Audit incident_response.py to confirm playbook implementation; either fully implement or remove routes |
| MEDIUM | **DML Engine** has confidence_score=0.8, no SQLAlchemy models despite writing to CanaryRecord/HoneyToken tables, and no background workers. May be partially implemented or sharing models via imports from main.py. | `dml_engine.py`, `architecture.json` subsystem #25 | DML trap deployment may silently fail or behave unexpectedly | Audit DML engine against actual deployment behavior; add explicit model declarations |
| LOW | **Quantum Canaries** is referenced in event spec (3 events) but absent from architecture.json subsystem list. No routes, no Redis keys, only ImmutableLog writes. May be implemented inline in main.py. | `main.py` (inline), `RUNTIME_EVENT_SPECIFICATION` section 1.10 | Small deception feature with minimal observability | Either document as inline subsystem or promote to full subsystem entry in architecture.json |

### Unreachable Routes

| Severity | Description | Location | Impact | Recommendation |
|----------|-------------|----------|--------|----------------|
| HIGH | **`/api/cowrie/recent`** reads from `cowrie:recent_events` Redis list, but the modern Cowrie pipeline writes to `cowrie_sessions:recent`. The legacy source (`cowrie:recent_events`) is never populated by the active pipeline. | `main.py` Cowrie route, `redis_graph.json` key `cowrie:recent_events` (marked STALE) | Returns increasingly stale/empty data; analysts see no results | Remove or migrate the endpoint to read from `cowrie_sessions:recent` |
| MEDIUM | **`/api/cowrie/labels`** reads from `cowrie:labeled_sessions` (SADD) which is populated by CRYSTAL, but the route has confidence_score=0.9 and no evidence of consumer usage. | `cowrie_intelligence.py` route, `redis_graph.json` key `cowrie:labeled_sessions` | Route may work but delivers unclear value; no known consumer | Audit actual usage; if unused, deprecate |
| MEDIUM | **`incident:rl:{key}`** rate limit key pattern exists in Redis for incident response, but the incident subsystem has no rate-limited routes according to its blueprint definition. | `redis_graph.json` rate_limits, `api_surface.json` incident_response_bp | Dead Redis key pattern; rate limit infrastructure with no target | Remove unused rate-limit key pattern |

### Dead Blueprints

| Severity | Description | Location | Impact | Recommendation |
|----------|-------------|----------|--------|----------------|
| MEDIUM | **`lc_stats:{date}`** Redis key is written by link_checker via HINCRBY (3 fields) but never queried externally by any subsystem. Marked as ORPHANED in redis_graph.json with confidence=0.85. | `link_checker.py`, `redis_graph.json` key `lc_stats:{date}` | Wasted Redis write operations; stats accumulated but never surfaced | Remove the write or surface the data through an API endpoint |
| MEDIUM | **`corpus:proxy_discovery`** Redis key is written but has no consumer. Marked as ORPHANED with confidence=0.8. | `fingerprint_corpus.py`, `redis_graph.json` key `corpus:proxy_discovery` | Wasted Redis write; proxy detection data accumulated but unused | Either implement a consumer or remove the write |
| LOW | **`canary:triggers:total`** global counter is INCR-ed but never read by any subsystem. Marked as ORPHANED with confidence=0.8. | `canary_service.py`, `redis_graph.json` key `canary:triggers:total` | Wasted Redis write; total trigger count lost | Surface via an API endpoint or remove |

### Duplicate Logic

| Severity | Description | Location | Impact | Recommendation |
|----------|-------------|----------|--------|----------------|
| MEDIUM | **Cowrie Behavioral DNA vs. Session DNA**: Both compute behavioral baselines on different data (SSH attackers vs web users) but share structural similarity. Cowrie DNA tracks actors via Redis+Postgres; Session DNA tracks users via Postgres only. | `behavioral_dna.py` vs `main.py` Session DNA | ~30% code duplication; shared patterns not abstracted | Extract common DNA framework if both subsystems continue to evolve independently |
| MEDIUM | **LLM Honeypot injection classifier vs. AIRS injection detector**: `llm_honeypot.classify_injection()` is called by AIRS `_detect_injection()` as fallback. Both classify injection attempts through different paths, creating potential double-classification and inconsistent verdicts. | `llm_honeypot.py`, `ai_runtime_security.py` | Two injection classification paths may produce different results for the same input | Consolidate into a single injection classifier service called by both subsystems |
| MEDIUM | **`main.py` Cowrie routes vs. `cowrie_intelligence.py` Cowrie routes**: `/api/cowrie/recent` in main.py reads `cowrie:recent_events` while `/api/cowrie/sessions` in cowrie_intelligence.py reads `cowrie_sessions:recent`. Two different data sources for the same concept. | `main.py` line ~5849, `cowrie_intelligence.py` | Inconsistent data; the main.py endpoint returns stale data from a legacy source | Consolidate to the modern `cowrie_sessions:recent` source |
| LOW | **BGP monitor uses two keys for the same concept**: `bgp_monitor:alerts` and `BGP_ALERTS_KEY` both store alerts, capped at 500 each. The uppercase constant is an alternate/duplicate. | `bgp_monitor.py`, `redis_graph.json` patterns | Two alert lists that may drift; inconsistent naming | Consolidate to a single key with consistent naming |

### Duplicate Schedulers

| Severity | Description | Location | Impact | Recommendation |
|----------|-------------|----------|--------|----------------|
| INFO | **No duplicate APScheduler jobs found**: All 9 scheduler jobs (`scheduler_graph.json`) have distinct job_ids, intervals, and subsystems. The `max_instances=1` and `coalesce=true` settings are consistent across all jobs. | `scheduler_graph.json` | No issue | None needed |

### Duplicate Redis Usage

| Severity | Description | Location | Impact | Recommendation |
|----------|-------------|----------|--------|----------------|
| MEDIUM | **`cowrie:log_pos` and `cowrie_intel:log_pos`**: Two Redis keys track log file position. One is the primary (used by the main pipeline), the other is an alternative. May be legacy from a refactor. | `cowrie_intelligence.py`, `redis_graph.json` keys | Potential log position drift; duplicate writes | Consolidate to a single key |
| MEDIUM | **`BGP_ALERTS_KEY` and `BGP_STATE_KEY`**: Uppercase constant keys duplicate the functionality of `bgp_monitor:alerts` and `bgp_monitor:route_state`. Inconsistent naming convention within the same subsystem. | `bgp_monitor.py`, `redis_graph.json` | Inconsistent naming; one of each pair may be stale | Consolidate to lowercase colon-delimited convention |
| LOW | **`detonation:recent` appears twice** in redis_graph.json with the same purpose and cap of 500. | `redis_graph.json` detonation keys | Duplicate list may cause data inconsistency | Remove duplicate declaration |

### Circular Dependencies

| Severity | Description | Location | Impact | Recommendation |
|----------|-------------|----------|--------|----------------|
| MEDIUM | **ASN ↔ BGP**: `bgp_monitor._handle_anomaly()` writes `asn:bgp_hijack:{asn}` and `asn:high_risk`. `asn_intelligence.enrich() → _check_bgp_hijack()` calls `bgp_monitor.is_ip_from_hijacked_prefix()`. This is a benign bidirectional information flow but creates conceptual circularity. | `bgp_monitor.py:522`, `asn_intelligence.py:697`, `dependency_graph.json` edges 530-583 | Not a runtime deadlock risk, but makes dependency graph harder to reason about | Document as intentional cross-feed; consider abstracting through a shared event bus |
| LOW | **Cowrie → Campaign → (possible) Cowrie**: `ingest_session` is fire-and-forget (async thread), so no return-value circularity exists. However, campaign updates can affect analyst attention on Cowrie data. | `cowrie_intelligence.py`, `campaign_correlator.py` | Data flow path exists but no blocking cycle | No action needed — fire-and-forget pattern breaks the cycle |
| LOW | **Canary Service → Cowrie → Canary Service**: Canary service reads `cowrie_sessions:recent`; Cowrie trigger events create canary alerts. Benign because reads are non-destructive. | `canary_service.py`, `cowrie_intelligence.py` | No blocking cycle | No action needed |

### Hidden Coupling

| Severity | Description | Location | Impact | Recommendation |
|----------|-------------|----------|--------|----------------|
| CRITICAL | **Synchronous `write_immutable_log()` called by 10+ subsystems**: Every security event across the platform blocks on a PostgreSQL INSERT and SHA-256 hash computation. Under high event volume (e.g., botnet-scale Cowrie session closures), this creates write contention on the `immutable_log` table and blocks all calling subsystems. | `main.py:4570-4620`, `Immutable Log` subsystem | **Single point of failure** for audit logging; 10+ subsystems degrade simultaneously under load | Make writes async (queue-based) with periodic batch inserts; keep sync verification path for critical events only |
| HIGH | **Cowrie `_cross_module_enrich()` runs synchronously for DNA, ASN, and fingerprint**: Only campaign correlation is async (threaded). The sync enrichment chain blocks the event worker for the full duration of API calls to external providers (IPInfo, Shodan, AbuseIPDB). | `cowrie_intelligence.py` cross-module enrichment | Event workers blocked on external API latency; event_queue (maxsize=5000) can back up | Make non-critical enrichment async (already done for campaign); add per-provider timeouts and circuit breakers |
| HIGH | **Login spawns 6 threads per successful login**: 3 threads for password path (`_bg_sign_session`, `_check_login_canary`, `safe_send_login_notification`) and 3 for Google path. At scale (1000+ logins/min), this creates 6000+ daemon threads. | `main.py:7710-9216` Auth subsystem | **Single point of thread exhaustion**; no thread pool cap | Consolidate to a shared notification queue consumed by a fixed-size thread pool |
| HIGH | **No thread pool for request-spawned threads**: 25+ different thread types spawn fire-and-forget with no cap. Under moderate attack traffic, 1000+ daemon threads can accumulate. | All `request_spawned` threads across all subsystems | Thread explosion under load; gunicorn worker memory exhaustion | Introduce a shared ThreadPoolExecutor with configurable max_workers; route all fire-and-forget tasks through it |
| MEDIUM | **7+ modules use late imports with `try/except ImportError`**: This pattern makes the import graph hard to reason about and silently degrades functionality if imports fail. | Across 7+ modules including `cowrie_intelligence.py`, `campaign_correlator.py`, etc. | Silent degradation; errors only surface at runtime when specific code paths execute | Replace with module-level imports and explicit dependency declarations |
| MEDIUM | **`main.py` is a ~12,289-line monolith**: 60+ route handlers, 34+ DB models, auth, session management, middleware, and admin routes all in a single file. Any change risks regression across unrelated subsystems. | `main.py` | High regression risk; poor testability; difficult to reason about | Extract auth, admin, and middleware into dedicated blueprints; split models into separate module |

### Excessive Fan-in

| Severity | Description | Location | Impact | Recommendation |
|----------|-------------|----------|--------|----------------|
| CRITICAL | **Immutable Log** — called synchronously by 10+ subsystems (Gateway, Middleware, Cowrie, BGP, LLM Honeypot, LLM Firewall, AIRS, Sandbox, Honeytokens, Link Checker, Canary Service, Supply Chain, etc.) | `main.py:4570-4620`, `ImmutableLog` table | Every subsystem's event persistence depends on this single synchronous path | See Hidden Coupling recommendation |
| HIGH | **Notification Routing** — 13+ subsystems produce events that route through the notification hub, all sharing a single `alert_dedup:{dedup_key}` Redis NX lock pattern | `main.py`, `services/` | Single dedup key namespace; all notification channels share the same dedup TTL (120-300s) | Consider per-channel dedup TTLs; add notification priority queue |
| HIGH | **Cowrie `cowrie_completed:{sid}`** — 7+ consuming subsystems depend on this single Redis key pattern (SSE streams, public API, dashboards, canary enrichment, campaign correlation) | `cowrie_intelligence.py`, `redis_graph.json` key | TTL expiry (30d) cascades to break 7+ consumers simultaneously | Consider PostgreSQL persistence for long-term session storage; keep Redis as cache |

### Excessive Fan-out

| Severity | Description | Location | Impact | Recommendation |
|----------|-------------|----------|--------|----------------|
| MEDIUM | **Cowrie pipeline sync enrichment**: The `_handle_close` handler fans out to 6+ synchronous consumers (ASN, DNA, Fingerprint, Credential Propagation, BGP, Campaign). 5 of these are synchronous, blocking the event worker. | `cowrie_intelligence.py` _cross_module_enrich | Event worker blocked for duration of all 5 sync calls sequentially | Make all enrichment calls async; use completion callbacks for dependent processing |
| MEDIUM | **Honey token check middleware (7th before_request)**: 8-branch decision tree fans out to sandbox, provenance, Discord, ImmutableLog, API key honey, predictive canary, and audit logging — many with thread spawns | `main.py:7288` honey_token_check | Single middleware handler orchestrates 6+ possible side effects per request | Consider extracting sub-checks into separate middleware handlers or a decision engine |
| MEDIUM | **Authentication login flow**: Single login POST fans out to 6 background threads, 3 DB writes, 2 Redis checks (rate limit), and 2 notification channels | `main.py:7710-9216` | High per-login overhead under normal conditions | Batch notification sends; reduce thread count by consolidating side effects |

### Single Points of Failure

| Severity | Description | Location | Impact | Recommendation |
|----------|-------------|----------|--------|----------------|
| CRITICAL | **Campaign Correlator is Redis-only**: `campaign:{id}` (7d TTL), `active_campaigns`, `recent_fingerprints` (capped 10000). All campaign state lost on Redis restart. No PostgreSQL persistence (Gap 8 from event spec). | `campaign_correlator.py` | **Redis restart destroys all campaign correlation state**. Historical campaigns are unrecoverable. | Add periodic PostgreSQL snapshots; use Redis as cache, not primary store |
| HIGH | **Cowrie Pipeline in-memory queues**: `event_queue` (maxsize=5000) and `alert_queue` (maxsize=1000) are Python `Queue` objects. Worker crash or restart drops all events in both queues. | `cowrie_intelligence.py` | Events in-flight are lost on restart; no durability for events between log tail and Redis storage | Replace with Redis-backed queues (BRPOP/LPUSH) for durability |
| HIGH | `_engine_supervisor` **daemon thread started at import time**: Runs unconditionally in every gunicorn worker unless `TESTING=1` is set. Leader election prevents duplicate engine execution, but import-time thread start is fragile. | `main.py:12254` | Import errors or slow module loading can cause supervisor to start before app is fully initialized | Defer supervisor start to `on_starting` or `after_request` first-request pattern |
| MEDIUM | **Notification threads are fire-and-forget with no dead-letter queue**: Failed notifications (Telegram 400, Discord non-200, Resend API failure) are silently dropped. No retry mechanism. | Notification Routing, all subsystems | Critical alerts may be silently lost if notification delivery fails | Add a Redis-backed dead-letter queue with periodic retry |

### Critical Execution Chains

| Severity | Description | Location | Impact | Recommendation |
|----------|-------------|----------|--------|----------------|
| CRITICAL | **Cowrie session close → cross-module enrichment chain**: `_handle_close()` → synchronous ASN enrichment (5-30s API calls) + DNA processing + fingerprint storage + credential check + BGP check + campaign ingest (async). The sync chain blocks the event worker for potentially 30+ seconds. | `cowrie_intelligence.py:1746`, section 4.1 | **Single event worker can be blocked for 30+ seconds**, starving all other sessions in the queue | Make all enrichment calls async with per-provider timeouts; use asyncio or thread pool |
| HIGH | **Request lifecycle — 8 middleware handlers**: Every HTTP request must pass through all 8 before_request handlers. Any handler can short-circuit the entire request. The honey_token_check (handler #7) has 8+ branches including thread spawns. | `main.py:960-8411` (entire middleware chain) | Middleware latency directly affects all request latency; thread spawns in middleware can cause resource exhaustion under load | Profile middleware latency per-request; consider lazy initialization for thread spawns |
| HIGH | **BGP dual-feed convergence**: Both RIPE RIS WebSocket and Cloudflare Radar polling converge at `_handle_anomaly()`. Redis keys `bgp_monitor:route_state` and `bgp_monitor:alerts` are shared between feeds. A corrupted state from one feed affects both. | `bgp_monitor.py:522` | Feed cross-contamination; corrupted baseline from one feed corrupts both | Add feed origin metadata to keys; validate writes by feed source |

### Startup Bottlenecks

| Severity | Description | Location | Impact | Recommendation |
|----------|-------------|----------|--------|----------------|
| MEDIUM | `_engine_supervisor` **starts at import time**: Before Flask app is fully configured, the engine supervisor daemon thread begins running. All engines attempt initialization during import, before the database or Redis may be fully ready. | `main.py:12254` | Engine initialization races with app setup; engines may fail to connect and need reconnection logic | Defer to `first-request` or `on_starting` gunicorn hook |
| MEDIUM | **9 APScheduler jobs start simultaneously on leader election**: All 9 jobs initialize at once on supervisor start. `max_instances=1` on `send_daily_digest` and `run_github_monitor` means stuck runs skip subsequent cycles. | `main.py` APScheduler setup | Staggered initialization would reduce startup CPU burst | Add per-job startup delays (jitter); monitor for skipped cycles |
| LOW | **All frontend Vue builds required at deploy time**: 5 separate frontends (frontend, frontend-home, frontend-auth, frontend-landing, frontend-blog) must each run `npm install && npm run build` before deployment. Build outputs are committed to git. | `static/` directories, all frontend/ directories | Deployment pipeline must orchestrate 5 independent builds; 5 build artifacts in repo | Consider CI/CD pipeline to build frontends; commit built artifacts only for deployment tags |

### Blocking Operations

| Severity | Description | Location | Impact | Recommendation |
|----------|-------------|----------|--------|----------------|
| CRITICAL | **Synchronous `write_immutable_log()`** blocks 10+ subsystems on PostgreSQL INSERT + SHA-256 hash computation | `main.py:4570-4620` | Every security event across the platform blocks on DB write | Queue writes; batch-commit every 100ms or 100 events |
| HIGH | **Cowrie synchronous enrichment chain** blocks event workers on 5+ synchronous API calls (IPInfo, Shodan, AbuseIPDB) | `cowrie_intelligence.py` cross-module enrichment | Event worker throughput capped by slowest external API | Make all enrichment async; add circuit breakers and timeouts |
| HIGH | **`_cross_module_enrich()` — sequential synchronous calls**: ASN enrichment → DNA processing → fingerprint storage → credential check → BGP check all run in sequence, not parallel | `cowrie_intelligence.py` | Total enrichment latency = sum of all 5 calls (30+ seconds) | Run independent enrichment calls in parallel via ThreadPoolExecutor |
| MEDIUM | **Cowrie `event_queue` maxsize=5000**: If workers can't keep up (e.g., external API latency, enrichments slow), producers block on put(), which blocks the log watcher, which stalls log file read position | `cowrie_intelligence.py` | Backpressure cascades to log tail; under botnet-scale attacks, log reading stalls | Increase queue size; add queue depth monitoring and alerting |
| MEDIUM | **Flask-Limiter on 50+ endpoints**: Each state-changing `/api/` request fires 2 Redis operations (INCR + EXPIRE) per decorator. Under moderate load (e.g., 500 req/s), this generates 1000 Redis ops/s. | All 50+ rate-limited endpoints in `api_surface.json` | Acceptable under normal load, but contributes to Redis CPU under attack | Consider local rate limiting with Redis sync; reduce per-request Redis round-trips |

### Architectural Smells

| Severity | Description | Location | Impact | Recommendation |
|----------|-------------|----------|--------|----------------|
| MEDIUM | **Redis key naming inconsistency**: Some use colons (`gateway:blocked:{ip}`), some use underscores (`alert_dedup:{key}`), some mix (`bgp_alert_sent:{hash}`). Some use uppercase constants (`BGP_ALERTS_KEY`, `BGP_STATE_KEY`), most use lowercase colon-delimited. | All Redis keys across all subsystems | Harder to debug; monitoring and key enumeration less predictable | Establish and enforce a naming convention (e.g., `subsystem:component:key` all lowercase) |
| MEDIUM | **Expiration cascade pattern in 4 places**: Persistent lists reference TTL-bound string keys: `cowrie_sessions:recent` → `cowrie_completed:{sid}` (30d TTL), `campaigns:active` → `campaign:{id}` (7d), `recent_fingerprints` → `fingerprint_data:{fid}` (3d). All produce stale pointers after TTL expiry. | `redis_graph.json` expiration_cascades, 4 cascades | Stale pointers cause consumers to get empty data for valid-looking list entries | Add periodic cleanup job to trim stale entries from the lists; or use Redis Streams |
| MEDIUM | **5 different fail-open behaviors** across subsystems with no consistent pattern: Gateway verify (availability), Cowrie alerts (never swallow), Canary creation (UX), LLM Firewall rate limit (disables limit), Cowrie LLM budget (fail-closed). No consistency. | All rate_limits in `redis_graph.json`, section 3 | Unpredictable behavior under Redis failure; some subsystems become less secure, others stop working | Standardize fail-open/fail-closed policy per security domain |
| LOW | **`main.py` ~12,289 lines** with 60+ route handlers, 34+ DB models, mixed concerns | `main.py` | Maintainability risk; difficult to test in isolation | Extract into domain modules or blueprints |

### Security Choke Points

| Severity | Description | Location | Impact | Recommendation |
|----------|-------------|----------|--------|----------------|
| HIGH | **`honey_token_check` middleware (handler #7)**: 8-branch decision tree is the single point where sandboxing, honeytoken detection, provenance checking, and predictive canary planting all occur. A bug in this handler bypasses all deception systems. | `main.py:7288` | **Single function controls all deception routing**: sandbox, honeytokens, reverse canaries, provenance violations, timing canaries, SQL pattern detection | Consider splitting into independent middleware handlers with clear failure isolation |
| HIGH | **Authentication session update** (handler #6): Manages session activity, idle detection (24h), thread spawn on expiry, and DNA tracking. A bug here affects all authenticated sessions. | `main.py:7068` | Session management is a single point of failure for all authenticated requests | Consider extracting session management to its own service/blueprint with circuit breaker |
| MEDIUM | **Gateway PoW** is the only pre-auth gating mechanism for `/signup` and `/admin`. If gateway:blocked:{ip} TTL expires (24h), blocked IPs regain access to signup and admin routes. | `gateway.py`, `redis_graph.json` `gateway:blocked:{ip}` | Blocked IPs regain access on TTL expiry; no persistent blocklist | Consider persistent IP blocklist with Redis as cache, not authoritative store |
| MEDIUM | **API key honey detection** is done inline in the honey_token_check middleware. If the middleware is bypassed or fails, fake API key usage goes completely undetected. | `main.py:7288` | Fake API key detection has no redundancy | Add a secondary detection path (e.g., decorator on API key verification) |

### Visualization Opportunities

| Severity | Description | Location | Impact | Recommendation |
|----------|-------------|----------|--------|----------------|
| P0 | **Unified Threat Dashboard**: 29 subsystems produce data that could be composited into a single-pane-of-glass view. All data exists in Redis/Postgres — no new backend needed. | All subsystems | **Highest-value visualization**: makes all platform activity observable in one view | Implement per VISUALIZATION_ARCHITECTURE.md Section 24 |
| P0 | **Cowrie Pipeline animated diagram**: Real-time pipeline with log watcher → event queue → workers → CRYSTAL gates → cross-module enrichment. All Redis keys exist (`cowrie_sessions:recent`, `cowrie_completed:{sid}`, `cowrie:log_pos`, `cowrie_llm:global:{day}`). | `cowrie_intelligence.py`, all 19 Redis keys | **Core intelligence visualization**: makes the 25-step SSH analysis pipeline observable | Implement per VISUALIZATION_ARCHITECTURE.md Section 4 |
| P0 | **Campaign Force Graph**: Real-time force-directed graph of 8-dimension similarity clustering. Redis keys exist (`campaign:{id}`, `active_campaigns`, `recent_fingerprints`, `fingerprint_data:{fid}`). | `campaign_correlator.py`, 5 Redis keys | **Campaign clustering visualization**: makes multi-actor correlation visible | Implement per VISUALIZATION_ARCHITECTURE.md Section 7 |
| P0 | **Attractor Sandbox Theater**: Timeline + state machine for each sandboxed IP. Data exists (`attractor_sandbox:{ip}`, `SandboxSession` table, immutable log). | `sandbox.py`, `main.py` sandbox code | **Attacker containment visualization**: see attackers navigate fake environments in real-time | Implement per VISUALIZATION_ARCHITECTURE.md Section 3 |
| P1 | **BGP Route Topology**: Network topology graph of AS nodes, BGP peer edges, hijack markers. Redis keys exist (`bgp_monitor:route_state`, `bgp_monitor:alerts`, `bgp_monitor:route_changes`, `bgp_monitor:hijacks:active:*`). | `bgp_monitor.py`, 7 Redis keys | **Network infrastructure visualization**: real-time routing security | Implement per VISUALIZATION_ARCHITECTURE.md Section 12 |
| P1 | **LLM Firewall Sankey**: 3-layer prompt analysis visualized as animated ribbon flow. Redis keys exist (`llmfw:stats:*`, `llmfw:events:*`, `llmfw:blocks:*`, `llmfw:cat:*`). | `llm_firewall.py`, 8 Redis keys | **AI security visualization**: see prompt injection prevention in real-time | Implement per VISUALIZATION_ARCHITECTURE.md Section 11 |
| P1 | **Fingerprint Intelligence Dashboard**: World heatmap + force graph + Sankey of attacker fingerprint data. Redis keys exist (`corpus:country_scores`, `corpus:techniques`, `corpus:ja3:*`, `corpus:tool:*`, `fingerprint:recent_events`). | `fingerprint_corpus.py`, 14 Redis keys | **Attacker profiling visualization**: see what tools target the platform | Implement per VISUALIZATION_ARCHITECTURE.md Section 9 |
| P1 | **Immutable Log Chain**: Animated blockchain showing SHA-256 hash chain in real-time. `ImmutableLog` table in PostgreSQL. | `main.py:4570-4620` | **Tamper-evident audit visualization**: green checkmarks for chain integrity | Implement per VISUALIZATION_ARCHITECTURE.md Section 20 |
| P2 | **ASN World Map**: Global heatmap of attack origins by ASN. Redis keys exist (`asn:leaderboard:total`, `asn:countries`, `asn:hosting_providers`, `asn:high_risk`). | `asn_intelligence.py`, 8 Redis keys | **Global threat visualization**: see attack origins geographically | Implement per VISUALIZATION_ARCHITECTURE.md Section 13 |
| P2 | **Actor Identity Graph**: Force graph of behavioral DNA actors across sessions. Data exists (`BehavioralActor` table, `dna:actor_sessions:{uuid}`, `dna:session_actor:{sid}`). | `behavioral_dna.py`, 4 Redis keys | **Threat actor tracking visualization**: see attackers across sessions | Implement per VISUALIZATION_ARCHITECTURE.md Section 8 |
| P2 | **Session DNA Dashboard**: Behavioral baseline timeline with anomaly markers. Data exists (`SessionDNA`, `SessionEvent`, `DNAAlert` tables). | `main.py` Session DNA code | **User behavior visualization**: see behavioral anomalies in context | Implement per VISUALIZATION_ARCHITECTURE.md Section 22 |
| P2 | **Lure Network Graph**: Force graph of planted credential lures. Redis keys exist (`lures:active`, `lure:{lid}`, `lures:triggered`). | `credential_propagation.py`, 3 Redis keys | **Deception network visualization**: track planted lures | Implement per VISUALIZATION_ARCHITECTURE.md Section 14 |
| P3 | **Hall of Mirrors depth visualization**: State machine of attacker mirror penetration. Redis keys exist (`mirror_depth:{ip}`, `mirror:{ip}:{sid}`). | `main.py:2993-3209`, 2 Redis keys | **Psychological deception visualization**: see attacker navigate mirror maze | Implement per VISUALIZATION_ARCHITECTURE.md Section 18 |
| P3 | **Alert Routing Sankey**: Event type → notification channel flow. Data from immutable log event types. | Notification Routing | **Notification visualization**: see which alerts go where | Implement per VISUALIZATION_ARCHITECTURE.md Section 19 |
| P3 | **Rate-Limiting Dashboard**: Live gauges for 15+ rate-limit types. Redis keys distributed across all subsystems. | All rate_limits in `redis_graph.json` | **Operational visualization**: see which limits are being hit | Implement per VISUALIZATION_ARCHITECTURE.md Section 21 |

---

## 2. Visualization Recommendations

For each of the 29 subsystems, the ideal visualization type with justification:

| # | Subsystem | Recommended Visualization | Why |
|---|-----------|--------------------------|-----|
| 1 | **Gateway / Proof-of-Work** | Sankey + Live Graph | Sankey shows pass/fail/block flow; Live Graph shows verification rate over time. Data in `gateway:fails:{ip}`, `gateway:blocked:{ip}`. PoW is a funnel — Sankey is the natural representation. |
| 2 | **Attractor Sandbox** | Timeline + State Machine + Attack Replay | Each sandboxed IP has a lifecycle: entry → actions → exfil milestones → release. Timeline shows ordered events; State Machine shows progression (probe → cred theft → exfil → persistence). Replay step-through shows fake data served. |
| 3 | **Hall of Mirrors** | State Machine + Timeline | Each mirror layer is a state. Timeline shows depth penetration over time. State Machine shows attacker navigating layers. Data in `mirror_depth:{ip}`, `mirror:{ip}:{sid}`. |
| 4 | **Timing Canaries** | Timeline | Each canary planting and hit is a timestamped event. Timeline shows credential reuse detection. Data in `timing_canary:{name}:{ip}:{ts}`, `timing_canary_hits:*`. |
| 5 | **Honeytokens** | Timeline | Each honeytoken trigger is a security event. Timeline shows when tokens were planted and triggered. Data in `HoneyTokenEvent` table and immutable log. |
| 6 | **Canary Service** | Timeline | SaaS canary token lifecycle: mint → deploy → hit → alert. Timeline per token. Data in `CanaryServiceToken`, `CanaryServiceHit` tables. |
| 7 | **Supply Chain Canary** | Force Graph + Timeline | Beacons as nodes, hits as edges. Timeline shows beacon registration → first hit → subsequent hits. Data in `supply_chain_canary:{token}`, `canaries:active`, `canaries:triggered`. Force graph reveals supply chain connections. |
| 8 | **Fingerprint Corpus** | Heatmap + Force Graph + Sankey | World heatmap of origins (from `corpus:country_scores`). Force graph of tools → techniques → target paths. Sankey of traffic source → tool → technique. Three complementary views of the same corpus. |
| 9 | **Session DNA** | Timeline + Live Graph | Behavioral baseline timeline with anomaly markers. Live graph of deviation score over time. Data in `SessionDNA`, `SessionEvent`, `DNAAlert` tables. |
| 10 | **Cowrie Behavioral DNA** | Force Graph + Timeline | Actors as hubs, sessions as spokes. Merge visualization animates actor absorption. Timeline: actor first seen → last seen. Data in `BehavioralActor`, `dna:actor_sessions:{uuid}`, `dna:hassh:*`. Force graph reveals actor relationships across sessions. |
| 11 | **Cowrie Intelligence Pipeline** | Pipeline + Force Graph + Timeline | **Primary visualization**: animated pipeline from Cowrie VPS → log watcher → event queue → workers → CRYSTAL gates → cross-module enrichment → alert router. Force graph of sessions connected by IP/command/HASSH. Timeline (Gantt) of session duration with command markers. Pipeline view shows the 25-step analysis chain. |
| 12 | **Campaign Correlator** | Force Graph + Timeline | Force-directed graph: IPs as nodes, campaign membership as edges. Timeline slider to see campaign formation over time. Node size = session count, color = threat level. Data in `campaign:{id}`, `active_campaigns`, `recent_fingerprints`. Gravity animation shows sessions merging into campaigns. |
| 13 | **Credential Propagation** | Force Graph + Timeline | Lures as nodes connected to platforms. Green (active), yellow (aging), red (triggered). Animated pulse on trigger. Data in `lures:active`, `lure:{lid}`, `lures:triggered`. |
| 14 | **ASN Intelligence** | Heatmap + Interactive Topology | World map colored by attack volume per country. Drill-down to ASN level. Enrichment overlay: hover IP for risk score, hosting status, VPN/Tor detection. Data in `asn:leaderboard:total`, `asn:countries`, `asn:high_risk`, `ip_enrich:{hash}`. |
| 15 | **BGP Monitor** | Interactive Topology + Timeline | Network topology: AS nodes connected by BGP peer edges. Highlighted monitored prefix paths. Alert markers (yellow=new AS, orange=origin change, red=hijack). Timeline slider for route state evolution. Data in `bgp_monitor:route_state`, `bgp_monitor:alerts`, `bgp_monitor:route_changes`, `bgp_monitor:hijacks:active:*`. Real-time RIPE RIS feed makes this a live topology. |
| 16 | **LLM Honeypot** | Timeline + Sequence Diagram | Chat-bubble interface showing attacker messages and fake AI responses. Overlay of injection technique, confidence, MITRE ATLAS mapping. Timeline of all sessions color-coded by threat level. Budget gauge. Data in `llm_honeypot:{ip}:{ts}`, immutable log. |
| 17 | **LLM Firewall** | Pipeline + Sankey + Live Graph | 3-layer pipeline: Request → Layer 1 (Regex) → Layer 2 (LLM) → Layer 3 (Heuristic) → Allow/Block/Flag. Sankey of prompt categories (injection, jailbreak, encoding). Live graph of requests/min and blocks/min. Data in `llmfw:stats:*`, `llmfw:events:*`, `llmfw:blocks:*`, `llmfw:cat:*`. |
| 18 | **AI Runtime Security (AIRS)** | Timeline + Sankey | 5-detector pipeline visualized as Sankey. Detection timeline with severity markers. Actor tracking table. Data in `AIRSDetection`, `AIRSActor` tables. |
| 19 | **Link Checker** | Pipeline | URL → Validation → API lookups → Results. Progress bars for multiple API calls (VT, URLScan, AbuseIPDB). Data in `lc_stats:{date}`, scan results. |
| 20 | **Detonation Engine** | Pipeline + Timeline | URL → Validation → Queue → Worker → Container → Analysis → Cross-Reference → Report. Live view of queued/running/completed detonations. Timeline of recent results. Data in `detonate:queue`, `detonate:job:{id}`, `detonation:recent`. |
| 21 | **Breach Monitor** | Pipeline + Timeline + Sankey | Sources (Pastebin, GitHub, HIBP) → Collectors → NLP Analysis → Correlation Engine → Alerts. Timeline of findings by severity. Sankey: source → type → severity. Data via breach-monitor API. |
| 22 | **Incident Response** | State Machine | Playbook step completion visualized as state transitions. Data in incident playbook state. |
| 23 | **Immutable Log** | Pipeline + Timeline (Chain) | Animated blockchain: blocks added in real-time with hash links. Verification overlay: green checkmarks for valid chain, red X for broken. Time scrubber. Data in `ImmutableLog` table. |
| 24 | **Public API / Stats** | Live Graph | Scrolling ticker of public tool usage. Live counters: total threats, active sessions, blocked IPs. Data in `public:activity`, `cowrie_sessions:recent`, `bgp_monitor:alerts`. |
| 25 | **DML Engine** | Component Diagram | DML definition components as connected nodes showing trap structure. Data in `deployed_traps:all`, `dml_trap:{fqid}`. |
| 26 | **Auth / Session Management** | State Machine | Auth flow state machine: anonymous → login → 2FA → authenticated → session active → expired/logout. Per-session state transitions. |
| 27 | **Notification Routing** | Sankey + Component Diagram | Event types → Channels (Telegram, Discord, Email, Webhook) → Success/Failure. Live counters per channel. Dedup effectiveness ratio. Data from immutable log event type distribution. |
| 28 | **Request Lifecycle / Middleware** | Sequence Diagram + C4 Container | Live request flow through 8 middleware handlers, route handler, 3 after_request handlers. Animated request packets passing through colored middleware layers. Static C4 shows defense-in-depth architecture. |
| 29 | **Leader Election / Engine Supervisor** | Deployment Topology | Which worker is leader, which engines are running, heartbeat status. Simple status grid showing engine health per worker. |

---

## 3. Final Summary

| Metric | Value | Source |
|--------|-------|--------|
| **Total subsystems discovered** | 29 | `architecture.json` metadata (total_subsystems: 29) |
| **Total subsystem entries in JSON** | 29 | `architecture.json` subsystems array (29 entries) |
| **Total runtime services** | 14 | Persistent subsystem count (Canary Service, Supply Chain Canary, Fingerprint Corpus, Cowrie Pipeline, Credential Propagation, ASN Intelligence, BGP Monitor, Detonation Engine, Breach Monitor, Immutable Log, Request Lifecycle, Leader Election, Notification Routing, Auth) |
| **Total API routes** | 109 | `api_surface.json` total_routes |
| **Total Flask blueprints** | 19 | `api_surface.json` blueprints array (19 entries) |
| **Total main app routes** | 45+ | `api_surface.json` main_app_routes array |
| **Total distinct runtime events cataloged** | 187 | `RUNTIME_EVENT_SPECIFICATION` Executive Summary + `architecture.json` total_events_cataloged |
| **Total APScheduler jobs** | 9 | `scheduler_graph.json` apscheduler_jobs array (9 entries) |
| **Total daemon thread types (persistent)** | 9 | `scheduler_graph.json` — engine-type persistent daemon threads |
| **Total daemon thread types (all, incl. request-spawned)** | 58 | `scheduler_graph.json` daemon_threads array (58 entries) |
| **Total request-spawned thread trigger types** | 25+ | `RUNTIME_BEHAVIORAL_MODEL.txt` Section 2 Group 3 table |
| **Total Redis key patterns** | 100 | `redis_graph.json` total_key_patterns |
| **Total Redis queues** | 13 | `redis_graph.json` queues array (13 entries) |
| **Total Redis locks** | 2 | `redis_graph.json` locks array |
| **Total Redis rate limit types** | 14 | `redis_graph.json` rate_limits array (14 entries) |
| **Total Redis Pub/Sub channels** | 4 | `redis_graph.json` pubsub_channels array |
| **Total Redis Streams** | 3 | `redis_graph.json` streams array |
| **Total Redis expiration cascades** | 4 | `redis_graph.json` expiration_cascades array |
| **Total external integrations** | 23 | Aggregated from all subsystems' `third_party_apis`: Groq, DeepSeek, Anthropic, AbuseIPDB, IPInfo, Shodan, VirusTotal, RDAP, URLScan, Whois, RIPE RIS, Cloudflare Radar, Google OAuth, GitHub, Paystack, BTCPay, canarytokens.org, Docker, Telegram Bot API, Discord Webhook API, Slack Webhook API, Resend API, S3/R2 |
| **Total notification channels** | 5 | Telegram, Discord, Email (Resend), Slack, Webhook (HMAC) |
| **Total SSE endpoints** | 3 | `/api/cowrie/stream`, `/api/link/scan/stream`, `/api/stream/events` |
| **Total webhook endpoints (inbound)** | 3 | Paystack HMAC, BTCPay HMAC, Telegram webhook secret |
| **Total trust boundaries** | 6 | Public → Sandbox/Canary (low trust) → Internal engines (medium) → Admin (high) → Critical (engines/dna) → Immutable Log |
| **Total SQLAlchemy models** | 34+ | Aggregated from all subsystems (User, ActiveSession, APIKey, APIKeyUsage, LoginAttempt, TrustedDevice, EmailVerification, PasswordReset, UserBehavior, SandboxSession, HoneyToken, HoneyTokenEvent, CanaryServiceToken, CanaryServiceHit, CanarySubscription, SessionDNA, SessionEvent, DNAAlert, BehavioralActor, MergeLog, ImmutableLog, AIRSDetection, AIRSActor, plus others) |
| **Total immutable log event types** | 40+ | `dependency_graph.json` immutable-log node metadata |

### Overall Architecture Scores

| Score | Value | Rationale |
|-------|-------|-----------|
| **Architecture Complexity** | **9/10** | 29 subsystems with 100 Redis key patterns, 9 schedulers, 58 thread types, 187 events, 109 routes, 23+ external integrations, 5 notification channels. Cross-subsystem dependencies form a dense graph with multiple bidirectional information flows. The middleware chain alone has 8 handlers with 17 event types. The Cowrie pipeline has a 25-step analysis chain with 6 cross-module enrichment paths. |
| **Architecture Maturity** | **7/10** | Strong security patterns (immutable log, hash chains, dedup, rate limiting, fail-open/fail-closed policies, leader election). However, 5+ dead/orphaned code paths (ASN auto-report stub, unused stop() methods, stale cowrie endpoints, orphaned Redis keys), undocumented systems (Incident Response at 0.75 confidence), Redis-only critical state (Campaign at 7d TTL, zero PostgreSQL persistence), thread-per-request pattern with no pooling, and the monolithic main.py (12,289 lines). The system works well but has significant technical debt in reliability and maintainability. |
| **Confidence Score** | **0.92** | Weighted average of subsystem confidence scores from `architecture.json` and API surface confidence from `api_surface.json` (0.92). Subsystem scores range from 0.75 (Incident Response) to 1.0 (Gateway, Fingerprint Corpus, Immutable Log, Request Lifecycle). High-confidence subsystems (≥0.95) cover the critical paths: middleware chain, immutable log, auth, Cowrie pipeline, ASN, BGP, LLM Firewall, notification routing. Low-confidence subsystems (≤0.85) are largely peripheral: Credential Propagation (0.85), DML Engine (0.8), Incident Response (0.75). |

### Key Architectural Risks Summary

1. **Redis-only state for critical subsystems**: Campaign Correlator (7d TTL), Cowrie pipeline (30d TTL), Credential Propagation (configurable TTL). Redis restart destroys all state. No PostgreSQL persistence path.
2. **Synchronous immutable log blocks 10+ subsystems**: A single PostgreSQL INSERT + SHA-256 operation gates all security event persistence.
3. **No thread pool for 25+ fire-and-forget thread types**: Under attack traffic, 1000+ daemon threads can accumulate per gunicorn worker.
4. **Login spawns 6 threads per login**: Unnecessary overhead under normal load; thread explosion under brute-force.
5. **Cowrie sync enrichment chain**: 5+ synchronous external API calls block event workers for 30+ seconds, stalling the entire pipeline.
6. **Dead execution paths**: ASN auto-abuse report (`pass` body), Credential Propagation/Cowrie Pipeline `stop()` methods never called, stale `/api/cowrie/recent` endpoint.
7. **Orphaned Redis keys**: `lc_stats:{date}`, `corpus:proxy_discovery`, `canary:triggers:total` — written but never read.
8. **main.py monolith**: 12,289 lines with 60+ route handlers and 34+ DB models — any change risks regression across unrelated subsystems.
