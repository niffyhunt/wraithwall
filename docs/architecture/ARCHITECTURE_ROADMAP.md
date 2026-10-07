# WraithWall Architecture Roadmap — Phase F

**Derived from:** architecture.json (29 subsystems), dependency_graph.json (90 edges), event_graph.json (173 events), observability.json, ARCHITECTURAL_FINDINGS.md, RUNTIME_BEHAVIORAL_MODEL.txt

**Date:** July 9, 2026

---

## 1. Subsystem Splits

Recommendations for splitting existing subsystems into smaller, independently deployable services. Ordered by impact.

### 1.1 Extract Immutable Log as Async Queue Service

**Current state:** `write_immutable_log()` in `main.py:4570-4620` — called synchronously by 10+ subsystems. Every security event blocks on PostgreSQL INSERT + SHA-256.

**Recommendation:** Extract into a dedicated `immutable-log-service` with:
- Redis-backed write queue (BRPOP from subsystems)
- Batch writer (commit every 100ms or 100 events, whichever first)
- R2/S3 archival as background job
- Separate /immutable-log blueprint with its own health endpoint

| Priority | Effort | Impact | Risk | Dependencies |
|----------|--------|--------|------|-------------|
| **HIGH** | 2-3 weeks | Removes blocking bottleneck from 10+ subsystems. Event persistence becomes non-blocking. | Low — existing writer can remain as synchronous fallback with feature flag | Must coordinate TTL of Redis queue with existing immutable log consumers |

### 1.2 Extract Auth/Session Management as Dedicated Blueprint

**Priority state:** `main.py` contains ~1,500 lines of auth code (60+ route handlers for login, 2FA, registration, password reset, API keys, sessions, admin controls).

**Recommendation:** Extract to `auth_blueprint.py`:
- Login/2FA/registration routes
- Session management middleware
- API key management
- Device verification
- OAuth handling
- Admin user management

| Priority | Effort | Impact | Risk | Dependencies |
|----------|--------|--------|------|-------------|
| **HIGH** | 3-4 weeks | Reduces main.py by ~1,500 lines. Isolates auth regression risk. Enables independent auth testing. | Medium — session cookie handling and middleware hooks must remain compatible | Must keep `update_session_activity` middleware in main.py chain unless middleware is also extracted |

### 1.3 Split Honey Token Check Middleware into Independent Handlers

**Priority:** `honey_token_check` (handler #7) at `main.py:7288` has 9+ branches: sandbox diversion, provenance check, API key honey, legitimate path, sensitive path, reverse canary, suspicious technique, SQL pattern detection.

**Recommendation:** Split into independent middleware handlers:
1. `sandbox_diversion_check` — sandbox containment only
2. `honey_token_scan` — scan payload for honeytoken values
3. `provenance_check` — data provenance verification
4. `reverse_canary_check` — reverse canary detection
5. `suspicious_technique_detect` — technique fingerprinting

| Priority | Effort | Impact | Risk | Dependencies |
|----------|--------|--------|------|-------------|
| **HIGH** | 2-3 weeks | Failure isolation — a bug in sandbox diversion doesn't break provenance checking. Each handler independently testable. | Medium (middleware ordering matters; `g.corpus_entry` must be shared) | All 5 new handlers must access same `g` context variables |

### 1.4 Split `main.py` Models into Separate Module

**Priority:** `main.py` defines 34+ SQLAlchemy models inline. Any model change requires touching the monolith.

**Recommendation:** Extract to `models/` directory:
- `models/user.py` — User, ActiveSession, APIKey, LoginAttempt, TrustedDevice
- `models/deception.py` — HoneyToken, HoneyTokenEvent, CanaryRecord, CanaryAlert, SandboxSession
- `models/dna.py` — SessionDNA, SessionEvent, DNAAlert, BehavioralActor, MergeLog
- `models/security.py` — ImmutableLog, AIRSDetection, AIRSActor, DataProvenance
- `models/canary_service.py` — CanaryServiceToken, CanaryServiceHit, CanarySubscription

| Priority | Effort | Impact | Risk | Dependencies |
|----------|--------|--------|------|-------------|
| **MEDIUM** | 2-3 weeks | Clean model separation. Enables per-model testing. Reduces main.py by ~2,000 lines. | Low (pure refactor — no logic changes) | May cause circular import issues with existing `try/except ImportError` patterns |

---

## 2. Future Service Boundaries

Subsystems that could become independently deployable microservices. Not recommended as immediate work — listed for future architecture planning.

### 2.1 Cowrie Intelligence Pipeline → Microservice

**Why:** The Cowrie pipeline is the most complex subsystem (6 daemon threads, 11 Redis keys, 5+ external APIs, 3 LLM providers). It runs independently of the Flask app and could be deployed as a separate Python service.

**Boundary:**
- **Keeps:** Cowrie log tailing, event_queue, workers, CRYSTAL, cross-module enrichment, alert_queue, alert_worker
- **Exposes:** Redis `cowrie_sessions:recent` and `cowrie_completed:{sid}` (unchanged)
- **Consumes:** Redis, LLM provider APIs, external intelligence APIs

**Effort:** 6-8 weeks
**Risk:** Medium — existing Redis consumers (7+ subsystems) don't change. The microservice simply continues writing to the same Redis keys.
**Dependencies:** Leader election must be moved to the microservice's own lock.

### 2.2 Canary Service (SaaS) → Microservice

**Why:** The canary service has billing/payment integration (Paystack, BTCPay), subscription lifecycle, user-facing dashboards, and 16 API routes. It has zero dependency on the main app beyond sharing the User model.

**Boundary:**
- **Keeps:** Token minting, subscription management, billing webhooks, hit tracking, alerting
- **Exposes:** REST API for canary token CRUD, webhook endpoints for payments
- **Consumes:** PostgreSQL (own database), Redis (shared for `cowrie_sessions:recent` read)

**Effort:** 4-6 weeks
**Risk:** Low — already has clean separation in `canary_service.py` blueprint. Main app changes from `canary_service_bp` to proxy or direct HTTP calls.
**Dependencies:** User model sharing — would need auth token exchange or shared session store.

### 2.3 Campaign Correlator → Microservice

**Why:** Campaign correlation is CPU-intensive (21-dimension fingerprint building, 8-dimension similarity computation) and Redis-only state is a single point of failure. A dedicated service could add PostgreSQL persistence.

**Boundary:**
- **Keeps:** Fingerprint building, similarity computation, campaign management, alerting
- **Exposes:** Redis `campaign:{id}` and `active_campaigns` (unchanged), plus new PostgreSQL persistence
- **Consumes:** Redis `recent_fingerprints` and `fingerprint_data:{fid}`

**Effort:** 3-4 weeks
**Risk:** Low — campaign correlator already has a clean `ingest_session()` API boundary in `campaign_correlator.py`.
**Dependencies:** Must first add PostgreSQL persistence for campaign data (currently Redis-only).

### 2.4 Canary Subsystems → Deception Service

**Potential microservice combining:**
- Attractor Sandbox (containment + exfil tracking)
- Hall of Mirrors (psychological deception)
- Honeytokens (API key/password traps)
- Timing Canaries (credential delay detection)
- DNS Canaries (DNS token tracking)
- Quantum Canaries (adaptive deception)
- Predictive Canaries (attacker prediction)
- Reverse Canaries (beacon/tracking intelligence)

**Why:** These 8 subsystems share a common purpose (deception), many share Redis key patterns (`alert_dedup:{dedup_key}`), and all feed into the honey_token_check middleware. A unified Deception Service would co-locate trap management, alert dedup, and response orchestration.

**Effort:** 12-16 weeks
**Risk:** High — honey_token_check middleware is deeply embedded in `main.py`. Extracting it requires callback-based middleware hooks or a sidecar architecture.
**Dependencies:** Must extract honey_token_check first (see Section 1.3).

---

## 3. Plugin Boundaries

Subsystems that could be externalized as plugins — loaded at runtime if configured, skipped if absent.

### 3.1 LLM Provider Adapters (Plugin-Ready)

**Current state:** LLM calls use hardcoded provider chains: Groq → DeepSeek → Anthropic (in `cowrie_intelligence.py` and `llm_honeypot.py` and `llm_firewall.py`).

**Plugin recommendation:** Extract to `plugins/providers/llm/` with:
- `base.py` — `LLMProvider` abstract class
- `groq.py` — Groq implementation
- `deepseek.py` — DeepSeek implementation  
- `anthropic.py` — Anthropic implementation
- `openai.py` — OpenAI implementation (documented but not used)
- `factory.py` — Provider selection by env var

**Effort:** 2-3 weeks
**Risk:** Low — pure refactor, no functional change
**Impact:** Adding a new LLM provider becomes a single Python file, not a search-and-replace across 3 modules.

### 3.2 External Intelligence API Adapters (Plugin-Ready)

**Current state:** 8+ external APIs called from 5+ subsystems with inconsistent timeout/retry handling.

**Plugin recommendation:** Extract to `plugins/intelligence/`:
- `base.py` — `IntelligenceProvider` abstract class with timeout, retry, circuit-breaker
- `abuseipdb.py`, `ipinfo.py`, `shodan.py`, `virustotal.py`, `rdap.py`, `urlscan.py`, `whois.py`
- Adapters register via decorator and are queried by capability ("ip-enrich", "domain-scan", "hash-lookup")

**Effort:** 3-4 weeks
**Risk:** Low — existing API calls can be wrapped gradually
**Impact:** All 5+ consumers get consistent timeout/retry/circuit-breaker behavior. Adding a new intelligence source is trivial.

### 3.3 Notification Channel Adapters (Plugin-Ready)

**Current state:** 4 notification channels (Telegram, Discord, Email, Webhook) with inconsistent handling (some threaded, some inline).

**Plugin recommendation:** Extract to `plugins/notifications/`:
- `base.py` — `NotificationChannel` abstract class with send(), validate(), health()
- `telegram.py`, `discord.py`, `email.py`, `webhook.py`, `slack.py`
- Registration via `@notification_channel("telegram")` decorator
- Channel discovery via `__init__` hook

**Effort:** 2 weeks
**Risk:** Low — 4 existing channels, clear interface
**Impact:** Adding a new channel (e.g., PagerDuty, Teams, Pushover) is a single file.

### 3.4 CRYSTAL Classifier → Plugin or Configurable Pipeline

**Current state:** The CRYSTAL triage classifier (alert/summarize/suppress) is hardcoded in `cowrie_intelligence.py` with fixed gate logic.

**Recommendation:** Define CRYSTAL gates as configurable rules:
- Rule format: `{condition: "threat_score > 80 AND reverb_amplified > 0.6", action: "alert"}`
- Rules loaded from a YAML file or DB table
- Default rules shipped with the platform
- Custom rules can be added without code changes

**Effort:** 3-4 weeks
**Risk:** Low — the current gate logic can be the default rule set
**Impact:** Operators can tune CRYSTAL behavior without editing Python code.

---

## 4. Reusable Engines

Engines that could be extracted as standalone Python libraries (importable by multiple services).

### 4.1 REVERB Amplification Engine → Library

**Current state:** Cross-module pairwise amplification logic embedded in `cowrie_intelligence.py`'s `_cross_module_enrich()`.

**Extract:** `wraithwall-reverb` library:
- `compute_amplified_score(session_signals)` — takes vanish, HASSH, BGP, campaign, geo, timing signals
- Returns amplified score for CRYSTAL consumption
- Purely functional — no Redis/DB dependency
- Unit-testable in isolation

**Effort:** 1 week
**Impact:** REVERB logic becomes testable, reusable, and independently versioned.

### 4.2 UNISON Scorer → Library

**Current state:** 14-dimension composite score calculation inline in threat dashboard logic.

**Extraction:** `wraithwall-unison` library:
- `compute_unison_score(signal_vector)` — aggregates 14 signal dimensions
- Returns composite score + verdict
- Configuration-driven (dimension weights from config)

**Effort:** 1 week
**Impact:** UNISON scoring becomes a standalone library testable without Redis/DB.

### 4.3 Fingerprint Engine → Library

**Current state:** Fingerprint building (21 dimensions for Campaign, threat scoring for Gateway, JA3/HASSH for Corpus) is duplicated across 3 subsystems.

**Extraction:** `wraithwall-fingerprint` library:
- `build_http_fingerprint(request)` — JA3, UA, headers, path, timing
- `build_ssh_fingerprint(session)` — HASSH, commands, timing, credentials
- `compute_threat_score(fingerprint)` — 0-1 score
- `compute_simhash(fingerprint)` — 64-bit SimHash for similarity
- No Redis/DB dependency — pure computation

**Effort:** 3 weeks
**Risk:** Low — pure computation, no side effects
**Impact:** Removes duplicate fingerprint logic from Gateway, Cowrie pipeline, Campaign correlator, and Fingerprint Corpus.

### 4.4 Behavioral DNA Framework → Library

**Current state:** Cowrie DNA (SSH attacker tracking) and Session DNA (web user tracking) share ~30% structural similarity but have no shared framework.

**Extraction:** `wraithwall-dna` library:
- `BehavioralProfile` class — stores feature vectors, confidence, session count
- `SimilarityEngine` — configurable dimension weights
- `BaselineUpdater` — exponential moving average baseline
- `DeviationScorer` — multi-dimensional deviation scoring
- `ActorManager` — actor creation, merging, retirement

**Usage:** Both Cowrie DNA and Session DNA inherit from the same framework with different data sources.

**Effort:** 3-4 weeks
**Risk:** Low — structural refactor, no functional change
**Impact:** Reduces duplicate code. Enables consistent actor tracking across SSH and web domains.

---

## 5. Reusable Libraries

Shared utility code that could be extracted into common libraries.

### 5.1 Redis Utilities (`wraithwall-redis`)

**Current state:** Redis key naming is inconsistent (`gateway:blocked:{ip}` vs `cowrie_alert_dedup:{sig}` vs `BGP_ALERTS_KEY`). Lock/dedup patterns are repeated across 10+ subsystems.

**Library contents:**
- `RedisLock` — SET NX with heartbeat and auto-release
- `RedisDedup` — SET NX with configurable TTL and fail-open/fail-closed
- `RedisRateLimiter` — INCR + EXPIRE with configurable window
- `RedisKeyFormatter` — enforces `subsystem:component:identifier` convention
- `RedisHealthCheck` — PING with latency percentile tracking
- `RedisQueue` — LPUSH/BRPOP with configurable cap

**Effort:** 2-3 weeks
**Impact:** Consistent key naming, deduplicated lock/rate-limit code, predictable Redis key patterns.
**Risk:** Low — pure extraction; all 10+ subsystems can migrate gradually.

### 5.2 Background Thread Utilities (`wraithwall-threads`)

**Current state:** 25+ fire-and-forget thread spawn patterns with no pooling, no cap, no monitoring.

**Library contents:**
- `ThreadPool` — configurable max_workers, queue-based task dispatch
- `BackgroundTask` — task wrapper with metrics (enqueue_time, start_time, completion_time, error)
- `ThreadHealthMonitor` — periodic check for stalled threads
- `SafeFireAndForget` — catches exceptions, logs to health endpoint

**Effort:** 2 weeks
**Impact:** Eliminates thread explosion under load. All 25+ spawn sites consolidate to pool submission.
**Risk:** Low — pool replaces `threading.Thread(target=fn).start()` with `pool.submit(fn)`.

### 5.3 Resilience Utilities (`wraithwall-resilience`)

**Current state:** External API calls use inconsistent retry/backoff/timeout patterns (some have none).

**Library contents:**
- `CircuitBreaker` — failure threshold, half-open recovery, metrics
- `RetryWithBackoff` — exponential backoff + jitter, max retries
- `TimeoutWrapper` — signal-based or concurrent.futures timeout
- `Bulkhead` — per-provider max concurrent calls
- `FallbackChain` — primary → fallback1 → fallback2 pattern (already used for LLM providers but hardcoded)

**Effort:** 2 weeks
**Impact:** Consistent resilience patterns across 23+ external integrations.
**Risk:** Low — wraps existing API calls; no functional changes during migration.

### 5.4 Security Utilities (`wraithwall-security`)

**Library contents:**
- `HashChain` — SHA-256 hash chain computation and verification
- `SSRFGuard` — private IP/subnet validation
- `HMACSigner` — consistent HMAC signing for webhooks
- `RateLimit` — token bucket implementation for local rate limiting (reduces Redis ops)
- `DataProvenance` — signed data verification

**Effort:** 2 weeks
**Impact:** Consolidates security patterns used across the codebase.
**Risk:** Low — extraction of existing logic.

---

## 6. Event Bus Improvements

### 6.1 Replace Ad-hoc Lists with Redis Streams

**Current state:** 4 subsystems use LPUSH/LRANGE polling patterns for event delivery:
- `cowrie_sessions:recent` — 7 consumers, 5s polling
- `bgp_monitor:alerts` — 3 consumers, per-request polling
- `recent_fingerprints` — 1 consumer, per-ingest polling
- `llmfw:events:{key}` — UI, per-request polling

**Recommendation:** Replace with Redis Streams (`XADD` / `XREAD`):
- Consumer groups for multi-subscriber fan-out
- `BLOCK` for push-based delivery (eliminates polling)
- `MAXLEN ~ 1000` for capped streams (replaces manual trimming)
- Per-stream message IDs eliminate cursor management

**Effort:** 3-4 weeks
**Impact:** Push-based delivery reduces Redis CPU load by eliminating polling. Event ordering guaranteed. Consumer group auto-rebalancing.
**Risk:** Low — both data structures coexist during migration. Stream consumers will still need to handle duplicate delivery (idempotent).

### 6.2 Add `/api/live/events` SSE Multiplexer

**Recommendation:** Single SSE endpoint that accepts stream name filters:
```
GET /api/live/events?streams=cowrie,campaigns,bgp
```
- Backed by Redis Stream `XREAD`
- Multiplexes events from subscribed streams
- Client controls stream filter via query param
- Auto-throttle at 5 events/sec per client
- Reconnection sends `XREAD` with last received ID (no events lost)

**Effort:** 2 weeks
**Impact:** Enables all 14 visualization real-time streams through a single connection.
**Risk:** Low — `/api/cowrie/stream` already exists; this consolidates and extends.

### 6.3 Add Dead-Letter Queue for Notification Failures

**Current state:** Failed notifications (Telegram 400s, Discord 500s, Resend failures) are silently dropped. No retry mechanism.

**Recommendation:**
- `alert_dead_letter:{hash}` — Redis SET with delivery attempts counter
- DLQ worker — periodic retry (every 60s, max 3 attempts)
- After 3 failures: alert admin via alternate channel
- Monitor: dead-letter queue depth as health indicator

**Effort:** 1 week
**Risk:** Low — additive change; existing notification flow is unchanged.
**Impact:** Critical alerts are no longer silently lost on delivery failure.

### 6.4 Add Consumer Group for Cowrie Session Events

**Current state:** 7 subsystems independently poll `cowrie_sessions:recent` (Redis list). Each poll reads the entire list, creating unnecessary Redis bandwidth.

**Recommendation:** Convert to Redis Stream consumer groups:
- One stream: `cowrie_sessions_stream`
- Consumer groups: `public_api`, `sse_stream`, `canary_enrichment`, `ops_dashboard`
- Each consumer group tracks its own cursor
- Idle consumers auto-rebalance within group

**Effort:** 2 weeks
**Impact:** Reduces Redis read volume by 7x (each event consumed once per group instead of once per poller).
**Risk:** Low — existing consumers can be migrated one at a time.

---

## 7. Redis Improvements

### 7.1 Standardize Key Naming Convention

**Current state:** 3 naming styles coexist:
- Colon-delimited: `gateway:blocked:{ip}`, `cowrie_session:{sid}`, `asn:leaderboard:total`
- Underscore: `alert_dedup:{key}`, `recent_fingerprints`
- Mixed: `bgp_alert_sent:{hash}`, `cowrie_llm:global:{day}`
- Uppercase constants: `BGP_ALERTS_KEY`, `BGP_STATE_KEY`

**Recommendation:** Enforce `subsystem:component:identifier` (all lowercase):
- `gateway:blocked:{ip}` ✅ (leave unchanged)
- `alert_dedup:{key}` → `notification:dedup:{key}`
- `bgp_alert_sent:{hash}` → `bgp:alert:sent:{hash}`
- `BGP_ALERTS_KEY` → `bgp:alerts`
- `BGP_STATE_KEY` → `bgp:state`

**Effort:** 2 weeks (mostly search-and-replace + migration script)
**Impact:** Keys are predictable, enumerable, and debuggable.
**Risk:** Low — requires coordination to avoid data loss during migration. All consumers must update read patterns simultaneously.

### 6 expired migration plan:

1. Write new keys alongside old (dual-write) for 1 TTL period
2. Migrate consumers to read from new keys
3. Remove old writes after migration period

### 7.2 Add PostgreSQL Persistence for Redis-Only Critical State

**Current at-risk state (Redis restart = data loss):**

| Subsystem | Redis Key(s) | TTL | 6 Impact |
|-----------|-------------|-----|---------|
| Campaign Correlator | `campaign:{id}`, `active_campaigns` | 7d | All campaign state lost |
| Campaign Correlator | `recent_fingerprints` | Capped 10000 | All fingerprints lost |
| Credential Propagation | `lures:active`, `lure:{lid}`, `lures:triggered` | Configurable | All lure state lost |
| Supply Chain Canary | `supply_chain_canary:{token}` | 365d | All beacon registrations lost |
| Cowrie Pipeline | `cowrie_session:{sid}` | 24h | Active session state lost |

**Recommendation by priority:**

1. **Campaign Correlator** — Add `Campaign` and `CampaignFingerprint` DB tables. Periodic snapshot from Redis (every 60s). Read from Redis (fast), fall back to PostgreSQL on Redis miss. **Effort: 2-3 weeks**

2. **Credential Propagation** — Add `CredentialLure` PostgreSQL table. Redis stays as cache. **Effort: 1 week**

3. **Supply Chain Canary** — `supply_chain_canary:{token}` has 365d TTL but no DB table. Add `SupplyChainBeacon` table. **Effort: 1-2 weeks**

4. **Cowrie Session State** — `cowrie_session:{sid}` has 24h TTL. Acceptable risk — in-flight sessions are lost but new sessions rebuild quickly. No action needed. **Effort: none**

### 7.3 Resolve Expiration Cascades

**Current state:** 4 expiration cascades create stale pointers:
- `cowrie_sessions:recent` (persistent) → `cowrie_completed:{sid}` (30d) → stale after 30d
- `campaigns:active` (persistent) → `campaign:{id}` (7d) → stale after 7d
- `recent_fingerprints` (persistent) → `fingerprint_data:{fid}` (3d) → stale after 3d
- `bgp_monitor:route_changes` (24h) → `bgp_monitor:hijacks:active:{hash}` (24h) → coordinated

**Recommendation:**
1. **Convert to Redis Streams** — `MAXLEN ~ 1000` automatically evicts oldest entries
2. **Add periodic cleanup job** — APScheduler job runs hourly, removes expired session/fingerprint/campaign pointers from lists
3. **Stream migration path:** Write new data to both list + stream, migrate consumers to stream, remove list writes

**Effort:** 2-3 weeks for full migration to streams
**Risk:** Low — additive during migration, removal after verification

### 7.4 Add Redis Memory Monitoring

**Current state:** No monitoring of Redis memory usage per subsystem. Fingerprint Corpus alone uses 14 key patterns and can grow unbounded (30d TTL per fingerprint).

**Recommendation:**
- Track `INFO MEMORY` and `INFO KEYSPACE` per subsystem prefix
- Add `corpus:total_entries` as alerting trigger (warn at 100K entries)
- Set `maxmemory-policy allkeys-lru` with `maxmemory` based on deployment size
- Monitor per-key-type memory: `corpus:*` vs `cowrie_completed:*` vs `campaign:*`

**Effort:** 1 week
**Risk:** Low — read-only monitoring, no behavioral change

### 7.5 Reorganize Lock/Dedup Key Naming

**Current state:** 7+ dedup keys across subsystems with inconsistent naming and TTLs (120-3600s).

**Recommendation:**
| Current Key | New Key | TTL |
|------------|---------|-----|
| `alert_dedup:{dedup_key}` | `notification:dedup:alert:{hash}` | 120s (unchanged) |
| `cowrie_alert_dedup:{sig}` | `cowrie:dedup:alert:{sig}` | 900s (unchanged) |
| `airs:alert:{email}:{technique}` | `airs:dedup:alert:{email}:{technique}` | 300s (unchanged) |
| `canary:rl:hit:{token}` | `canary:ratelimit:hit:{token}` | 300s (unchanged) |
| `llmfw:alert_dedup:{hash}` | `llmfw:dedup:alert:{hash}` | 120s (unchanged) |
| `bgp_alert_sent:{hash}` | `bgp:dedup:alert:{hash}` | 3600s (unchanged) |

**Effort:** 1 week (dual-write migration)
**Risk:** Low if dual-written

---

## 8. Scheduler Improvements

### 8.1 Job Distribution

**Current state:** APScheduler runs in the leader gunicorn worker. All 9 jobs start simultaneously on leader election. `max_instances=1` on critical jobs means stuck runs skip subsequent cycles.

**Recommendations:**

| Improvement | Effort | Impact | Risk |
|-------------|--------|--------|------|
| **Staggered job startup** — add 1-10s random jitter to each job's initial delay | 0.5 day | Prevents CPU burst on leader election | Low |
| **Distribute jobs** via Redis locking — each job acquires a per-job Redis lock before executing, allowing any gunicorn worker to run the job | 1 week | Eliminates single-point-of-failure for scheduler; jobs continue on any worker | Low (additive — existing scheduler continues unchanged) |
| **Move to dedicated scheduler process** — run APScheduler in a separate process/container, independent of gunicorn workers | 2-3 weeks | Full isolation; scheduler health independent of web request load | Medium (new deployment pattern) |

**Recommended path:** Start with Redis-based per-job locks (1 week), move to dedicated scheduler process later if needed.

### 8.2 Error Handling

**Current state:** APScheduler captures exceptions but:
- `breach_monitor_scan` — no retry on failure
- `run_github_monitor` — 4h interval, `max_instances=1` means failure skips next cycle
- `send_daily_digest` — 24h cron, missing a day is acceptable
- No alerting on job failure

**Recommendations:**

| Improvement | Effort | Priority |
|-------------|--------|----------|
| **Alert on job failure** — write to immutable log + Telegram on APScheduler `EVENT_JOB_ERROR` | 0.5 day | HIGH |
| **Retry failed jobs** — 2 retries with 60s delay for breach_monitor_scan and run_github_monitor | 0.5 day | HIGH |
| **Job timeout** — add `max_instances=2` with `coalesce=True` for jobs where skipping a cycle is acceptable (run_github_monitor) | 0.5 day | MEDIUM |
| **Reduce all `max_instances` to 1** + ensure `coalesce=true` is set everywhere — already done, just verify | 1 hour | INFO |

### 8.3 Job Execution Monitoring

**Current state:** No per-job metrics (duration, success rate, last run time).

**Recommendation:** Write execution metrics to Redis after each job:
- `scheduler:job:{job_id}:latency` — execution duration (ms)
- `scheduler:job:{job_id}:last_run` — timestamp
- `scheduler:job:{job_id}:status` — success/failure/error
- Expose via `/api/health/detailed`

**Effort:** 1 week
**Risk:** Low

### 8.4 Dead Exention Path Cleanup

**Current state:** 3 `stop()` methods defined but never called (Cowrie pipeline, Credential Propagation and `_auto_report_asn`).

**Recommendation:**
- `cowrie_intelligence.py stop()` — wire into gunicorn worker shutdown hook (or document as intentionally unused since daemon=True handles process exit)
- `credential_propagation.py stop()` — same
- `_auto_report_asn()` — either implement abuse email sending or remove the function and env var configuration

**Effort:** 1 week for all 3
**Risk:** Low — `stop()` methods are unused but harmless; `_auto_report_asn` is dead code

---

## 9. Architecture Maturity Assessment

### Current Maturity Level: **3.0/5**

| Criterion | Current State | Score |
|-----------|--------------|-------|
| **Deployment Isolation** | Monolith with 19 blueprints and 5 standalone services | 3 |
| **State Persistence** | Redis-only for 3 critical subsystems (Campaign, Cred Prop, Supply Chain) | 2 |
| **Observability** | 3 health endpoints, 3 SSE streams, no structured logging | 3 |
| **Resilience** | 25+ fire-and-forget thread types, no thread pool, no dead-letter queues | 2 |
| **Testability** | Tests rely on `TESTING=1` to suppress engines; 34+ models in one file | 3 |
| **Deployment** | Frontends committed to git; `_engine_supervisor` starts at import time | 3 |
| **Security** | Strong (immutable log, hash chains, dedup, rate limiting, leader election) | 4 |
| **Scalability** | Synchronous immutable log bottleneck; Cowrie enrichment chain sequential | 2 |
| **Configuration** | Environment variables only; no config file or dynamic config | 3 |
| **Code Quality** | 12,289-line main.py; late imports with ImportError catch; namespace inconsistency | 2 |

### Target Maturity Level: **4.0/5**

Achievable in 6-9 months with focused investment.

| Criterion | Target State | Score |
|-----------|-------------|-------|
| **Deployment Isolation** | Cowrie pipeline and Canary service extracted as microservices; remaining monolith well-factored | 4 |
| **State Persistence** | Campaign correlator, credential propagation, supply chain canary have PostgreSQL persistence | 4 |
| **Observability** | Structured logging (JSON), `/api/live/events` SSE stream, per-worker health metrics | 4 |
| **Resilience** | Shared thread pool for all 25+ fire-and-forget tasks; dead-letter queue for notifications | 4 |
| **Testability** | Models extracted; individual blueprints testable in isolation | 4 |
| **Deployment** | Frontends built in CI; engine supervisor deferred to first-request pattern | 4 |
| **Security** | (Maintain 4/5) | 4 |
| **Scalability** | Immutable log via async queue; enrichment parallelized | 4 |
| **Configuration** | Dynamic config via DB table with env var override | 3 |
| **Code Organization** | Models in dedicated module; blueprints extracted; no late imports | 4 |

**Total target:** 3.9/5 → rounded to **4.0/5**

### Gaps to Close

| Gap | Current | Target | Effort | Priority |
|-----|---------|--------|--------|----------|
| Campaign Redis-only → PostgreSQL | Restart destroys all campaigns | Campaign table with periodic Redis snapshot | 2-3 weeks | HIGH |
| Synchronous immutable log blocks 10+ subsystems | Inline PostgreSQL INSERT + SHA-256 | Redis-backed write queue with batch commit | 2-3 weeks | HIGH |
| No thread pool → thread explosion under attack | `threading.Thread().start()` × 25+ | Shared ThreadPoolExecutor in `wraithwall-threads` | 2 weeks | HIGH |
| main.py monolith → modular codebase | 12,289 lines, 60+ routes, 34+ models | Models in `models/`, auth extracted | 4-6 weeks | HIGH |
| SSE polling → Redis Streams push | 4 LRANGE polling consumers | XREAD consumer groups, no polling | 3-4 weeks | MEDIUM |
| Redis key naming inconsistency | 3 styles + uppercase constants | `subsystem:component:identifier` | 2 weeks | MEDIUM |
| No dead-letter queue → silent notification loss | Failed notifications dropped | Redis-backed DLQ with retry | 1 week | MEDIUM |
| Cowrie enrichment sequential → parallel | 5 sync calls blocking event worker | ThreadPoolExecutor per enrichment type | 2 weeks | MEDIUM |
| Import-time engine supervisor → deferred | daemon thread starts at import | `on_starting` or `after_request` gate | 1 week | MEDIUM |
| Dead execution paths | 3 stop() never called, auto_report is pass | Implement or remove | 1 day | LOW |

### Migration Strategy Summary

**Phase 1: Immediate Risk Mitigation (Weeks 1-4)**

| Week | Action |
|------|--------|
| 1 | Add Campaign PostgreSQL persistence — prevent data loss on Redis restart |
| 2 | Extract `wraithwall-threads` library — add shared thread pool; migrate all 25+ spawn sites |
| 3 | Make immutable log async — Redis write queue + batch PostgreSQL commit |
| 4 | Add notification dead-letter queue; add per-job Redis locks to scheduler |

**Phase 2: Maintainability (Weeks 5-10)**

| Week | Action |
|------|--------|
| 5-6 | Extract models from `main.py` into `models/` package |
| 7-8 | Extract auth subsystem as dedicated blueprint |
| 9 | Standardize Redis key naming (dual-write migration) |
| 10 | Replace dead execution paths; standardize fail-open/fail-closed policies |

**Phase 3: Scalability (Weeks 11-16)**

| Week | Action |
|------|--------|
| 11-12 | Convert Redis list polling to Redis Streams + consumer groups |
| 13-14 | Parallelize Cowrie enrichment chain; add circuit breakers to all external APIs |
| 15 | Add structured logging (JSON stdout) |
| 16 | Defer engine supervisor to first-request; add per-job startup jitter to scheduler |

**Phase 4: Extraction (Weeks 17-24, Optional)**

| Week | Action |
|------|--------|
| 17-18 | Extract Cowrie pipeline as standalone microservice |
| 19-20 | Extract `wraithwall-reverb`, `wraithwall-unison`, `wraithwall-fingerprint` libraries |
| 21-22 | Extract notification channels as plugins |
| 23-24 | Extract LLM providers as plugins; define CRYSTAL rules as configurable |

---

## 10. Summary of Priority Orders

### Hot (Do immediately — weeks 1-4)

| Item | Effort | Reason |
|------|--------|--------|
| Campaign PostgreSQL persistence | 2-3 weeks | **Prevents data loss on Redis restart.** Campaign correlator has zero durability. |
| Shared thread pool | 2 weeks | **Prevents thread explosion under attack.** Current pattern can create 1000+ daemon threads per gunicorn worker. |
| Async immutable log | 2-3 weeks | **Removes blocking write from 10+ subsystems.** Single PostgreSQL INSERT gates all security event persistence. |
| Notification dead-letter queue | 1 week | **Stops silent notification loss.** Failed Telegram/Discord/Email are currently dropped. |

### Warm (Do next — weeks 5-10)

| Item | Effort | Reason |
|------|--------|--------|
| Models extraction from main.py | 3 weeks | Enables isolated testing. Reduces regression risk. |
| Auth blueprint extraction | 3-4 weeks | Reduces main.py by ~1,500 lines. Isolates auth changes. |
| Redis key naming standardization | 2 weeks | Makes key space predictable and debuggable. |
| Redis Streams for event bus | 3-4 weeks | Eliminates polling. Enables real-time SSE. |

### Hot (Do when convenient — weeks 11+)

| Item | Effort | Reason |
|------|--------|--------|
| Parallel enrichment chain | 2 weeks | Improves Cowrie pipeline throughput. |
| Structured logging | 1 week | Enables ELK/self-managed log aggregation. |
| LLM provider plugin architecture | 2-3 weeks | Makes adding LLM providers a single file. |
| CRYSTAL configurable rules | 3-4 weeks | Operators tune classifier without code changes. |
| Microservice extraction | 16-24 weeks total | Long-term architecture goal. |

---

## 11. Architecture Evolution — Decision Matrix

| Pattern | Current Usage | Recommended Future State | When |
|---------|--------------|------------------------|------|
| Blueprint-bound routes | 19 blueprints ✅ | Continue | Now |
| Shared models in monolith | 34+ in main.py | `models/` package | Weeks 5-6 |
| Sync immutable log | All subsystems | Async queue + batch write | Week 3 |
| Ad-hoc threads | 25+ types | ThreadPoolExecutor | Week 2 |
| Redis-only state | 3 critical subsystems | PostgreSQL + Redis cache | Week 1 |
| Redis lists (polling) | 5 lists | Redis Streams (push) | Weeks 11-12 |
| Scheduler in gunicorn worker | Single APScheduler | Per-job Redis locks; dedicated process later | Week 4 |
| Hardcoded LLM providers | 3 providers in 2 files | Plugin system | Weeks 21-22 |
| Hardcoded notification channels | 4 channels | Plugin system | Weeks 23-24 |
| Environment config only | .env file | Dynamic Redis config with env override | Weeks 21-22 |
| Einstein-style deployment | No containers | Docker Compose for all services | Weeks 17-24 |