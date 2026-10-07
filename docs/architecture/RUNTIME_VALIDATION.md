# Phase D: Runtime Validation Report

**WraithWall — Runtime Behavioral Model Cross-Reference**
**Date:** July 9, 2026
**Method:** Manual audit of 4 architecture graphs against actual codebase (`.py` source)

---

## 1. APScheduler Lifecycle Verification

### Source of truth
`main.py:12168-12177` — 9 jobs registered on a `BackgroundScheduler`.

| # | Job (graph name) | Function (actual code) | Trigger (graph) | Trigger (code) | Verified? | Conflicts |
|---|------------------|-----------------------|-----------------|----------------|-----------|-----------|
| 1 | `retrain_models` | `main.retrain_models` (line 12102) | interval 604800s (7d) | `'interval', weeks=1` | ✅ | None |
| 2 | `mimicry_engine` | `main.run_mimicry_engine` (line 3814) | interval 14400s (4h) | `'interval', hours=4` | ✅ | None |
| 3 | `breach_scan_cycle` | `main.run_breach_scan_cycle` (line 640) | interval 21600s (6h) | `'interval', hours=6` | ✅ | None |
| 4 | `run_bgp_monitor` | `bgp_monitor.run_bgp_monitor` (line 505) | interval 900s (15min) | `'interval', minutes=15` | ✅ | None |
| 5 | `paste_monitor` | `main.run_paste_monitor` (line 696) | interval 7200s (2h) | `'interval', hours=2` | ✅ | None |
| 6 | `github_monitor` | `main.run_github_monitor` (line 728) | interval 14400s (4h) | `'interval', hours=4` | ✅ | None |
| 7 | `send_daily_digest` | `main.send_daily_digest` (line 572) | cron `0 8 * * *` | `'cron', hour=8, minute=0` | ✅ | None |
| 8 | `canarytokens_poll` | `main.check_canarytokens_alerts` (line 1994) | interval 900s (15min) | `'interval', minutes=15` | ✅ | None |
| 9 | `trial_billing` | `canary_service.run_trial_billing` (line 1375) | interval 3600s (1h) | `'interval', hours=1` | ✅ | None |

### Verification findings

**All 9 functions exist** at the documented locations. All trigger configurations match exactly. All jobs use `max_instances=1` with `coalesce=True` — correct for preventing overlap of long-running jobs like breach scans.

**No job conflicts.** The intervals (1h, 2h, 4h, 6h, 15min, 7d) are harmonically unrelated. The cron job (08:00 daily) does not overlap with interval jobs.

**Startup dependency:** All jobs are started by `scheduler.start()` inside `_start_all_engines()` (line 12203), which is called only after the engine supervisor acquires the Redis leader lock. This is correct — no job runs before Redis is available for dedup/state.

---

## 2. Daemon Thread Verification

### Code-counted thread universe

| File | `threading.Thread(...daemon=True)` instances | Notes |
|------|----------------------------------------------|-------|
| `main.py` | ~30 direct spawns | 3 unconditional (supervisor, keep-alive, ping), rest request-spawned |
| `cowrie_intelligence.py` | 4+2 (N workers + alert + watcher + per-event ingest threads) | 6 engine workers, +1 thread per `_cross_module_enrich` |
| `detonate.py` | 3 (worker_loop + 2× _pipeline_detonation_signals) | 1 persistent worker, 2 per-completion signals |
| `bgp_monitor.py` | 1 (_run_ripe_ris_thread) | Leader-gated daemon |
| `credential_propagation.py` | 1 (auto_rotate) | Leader-gated, conditional on AUTO_ROTATION |
| `asn_intelligence.py` | 1 (_auto_report_asn) | Request-spawned per enrichment |
| `canary_service.py` | 2 (_enrich_and_alert, _send_owner_email) | Request-spawned |
| `llm_honeypot.py` | 3 (_store_injection_attempt, _alert, fire) | Request-spawned |
| `llm_firewall.py` | 2 (_fire_alerts) | Request-spawned |
| `sandbox.py` | 1 (_send) | Request-spawned |
| `supply_chain_canary.py` | 1 (beacon fire) | Import-time unconditional |
| `terminal_bp.py` | 1 (pty_reader) | Per WebSocket session |
| `ops-dashboard/app.py` | 1 (_poll_main_events) | SSE poller, per-dashboard instance |
| `ops-dashboard/engine/terminal.py` | 1 (reader) | Per terminal session |
| `ai_runtime_security.py` | 1 (_safe_post Discord) | Request-spawned |
| **Total distinct `daemon=True`** | **~52** | Plus non-daemon threads in breach-monitor |

### Persistent daemon thread verification

| Thread | Target function | Exists? | Daemon? | Error handling | Shutdown |
|--------|-----------------|---------|---------|----------------|----------|
| `_engine_supervisor` | `main._engine_supervisor` (12211) | ✅ | ✅ | `try/except Exception` + fallback to local start | Lock released via `atexit` (12252) |
| `_watch_cowrie_log` | `cowrie_intelligence._watch_cowrie_log` (1651) | ✅ | ✅ | `try/except Exception` with sleep(5) | `_running=False` check + `join(timeout=3)` in stop() |
| `_event_worker_N` | `cowrie_intelligence._event_worker` (878) | ✅ | ✅ | `try/except Exception` with exc_info | Same stop mechanism |
| `_alert_worker` | `cowrie_intelligence._alert_worker` (1551) | ✅ | ✅ | Per-iteration try/except | Same stop mechanism |
| `auto_rotate` | `credential_propagation.auto_rotate` (605) | ✅ | ✅ | try/except in loop body | `_running` flag (no join) |
| `_run_ripe_ris_thread` | `bgp_monitor._run_ripe_ris_thread` (345) | ✅ | ✅ | wraps asyncio run, has reconnect loop | `_running` flag |
| `detonate_worker_loop` | `detonate._worker_loop` (394) | ✅ | ✅ | `try/except Exception` with sleep(5) | Daemon — abrupt exit on process end |
| `keep_alive_ping` | `main.keep_alive` / `ping` (12256) | ✅ | ✅ | Bare `try/except: pass` | Daemon — abrupt exit |

**Issues found:**

1. **Cowrie worker shutdown is best-effort.** `stop()` sets `_running=False` then joins workers with 3s timeout. Workers blocked on `event_queue.get(timeout=1.0)` will exit within 1s. However, `_handle_event` during shutdown could be mid-flight — no cancellation token for LLM calls or Redis operations.

2. **`keep_alive` has no backoff.** The `ping` thread loops every 300s with a bare `try/except: pass`. If the breach dashboard URL is unreachable, it retries immediately via sleep(300) — technically correct but produces no warning. Acceptable for a ping.

3. **`detonate._worker_loop` has no graceful shutdown.** It loops on `BRPOP` which blocks indefinitely. No `_running` flag. If the process needs to exit cleanly, the BRPOP will be interrupted by SIGTERM, but any in-flight `_exec_container()` call could orphan a Docker container. **Risk: MEDIUM**

---

## 3. Request-Spawned Thread Analysis

| Trigger location | Function | daemon | Per-request? | Risks |
|------------------|----------|--------|-------------|-------|
| `send_telegram_alert_bg` (line 139) | `send_telegram_alert` | ✅ | Yes | Unbounded under alert storm. No thread cap |
| Telegram webhook (line 474) | `process_telegram_command` | ✅ | Per webhook | Low volume. Acceptable |
| Timing canary hit (line 1866) | `_bg_alerts` | ✅ | Yes | **HIGH**: under automated credential-stuffing scan, 1000+ threads |
| Fingerprint >= 0.85 (line 11528) | `_bg_enter_sandbox` | ✅ | Yes | **HIGH**: score-based, every request can trigger |
| Admin sandbox API (line 6176) | `_bg_enter_sandbox` | ✅ | Per admin action | Low — rate-limited |
| LLM honeypot critical (llm_honeypot.py:442) | `_store_injection_attempt` | ✅ | Per injection | Medium |
| Newsletter signup (line 5546-5547) | 2× threads (discord + email) | ✅ | Per signup | Low |
| Demo request (line 5558) | `send_webhook_alert` | ✅ | Per request | Low |
| Honey token hit (line 5725) | `send_honey_alert` (captures `request` obj) | ✅ | Per hit | **HIGH**: captures gunicorn-recycled `request` |
| Canary token hit (canary_service.py:484) | `_enrich_and_alert` | ✅ | Per hit | Medium |
| Canary DB alert (line 4466) | `_send_canary_alerts` | ✅ | Per trigger | Low — dedup check before spawn |
| Password login (lines 7901, 7910, 7920) | 3× threads: `_bg_sign_session`, `_check_login_canary`, `safe_send_login_notification` | ✅ | **Per login** | **HIGH**: 3 threads per login × 2 paths |
| Google login (lines 8042-8043) | 2 threads (missing notification) | ✅ | Per login | Medium |
| New device (line 7857) | `safe_send_device_verification_email` | ✅ | Per device | Low |
| Registration (lines 8665-8666) | `safe_send_verification_email`, `safe_send_admin_signup_alert` | ✅ | Per signup | Low |
| Password reset (line 8738, 9116) | `safe_send_password_reset_email` | ✅ | Per reset | Low |
| Suspicious technique (line 7378) | `_background_predictive` | ✅ | Per suspicious request | Medium — rate-limited by technique detection |
| Every 5th auth request (line 7116) | `_record_and_score_dna` | ✅ | Per 5 events | **HIGH**: under automated auth tools, creates unbounded threads + DB writes |
| Session expiry (line 7083) | `_finalize_session_dna` | ✅ | Per expiry | Low |
| LLM injection (llm_honeypot.py:585) | `_store_injection_attempt` | ✅ | Per injection | Medium |
| LLM injection alert (llm_honeypot.py:483) | `_alert` | ✅ | Per critical | Low |
| LLM firewall block (llm_firewall.py:918) | `_fire_alerts` | ✅ | Per block | Low |
| AIRS detection (ai_runtime_security.py:509) | `_safe_post` | ✅ | Per detection | Low |
| Sandbox notification (sandbox.py:267) | `_send` | ✅ | Per sandbox event | Low |
| PTY reader (terminal_bp.py:131) | `pty_reader` | ✅ | Per WebSocket | Low — session-scoped |
| Detonation completion (detonate.py:319, 419) | `_pipeline_detonation_signals` | ✅ | Per detonation | Low |
| Supply chain beacon (supply_chain_canary.py:54) | `_sc_v` (obfuscated) | ✅ | **Import-time only** | Low — runs once |
| ASN abuse report (asn_intelligence.py:379) | `_auto_report_asn` | ✅ | Per enrichment | Low |
| Cowrie→campaign (cowrie_intelligence.py:1160) | `get_correlator().ingest_session` | ✅ | Per session close | Medium — daemon thread per cowrie session |
| Immutable log S3 archive (main.py:4469) | `_archive_log_entry` (line 4469) | ✅ | Per canary trigger | Low |

### Critical issues

**A. Request object capture (main.py:5725)**
```python
threading.Thread(target=send_honey_alert, args=(token, event, request), daemon=True).start()
```
The `request` object is passed to a daemon thread. By the time the thread reads `request.remote_addr`, `request.path`, etc., the gunicorn worker may have recycled the request context. This is a **use-after-free** race. Fix: extract values before spawning the thread.

**B. Unbounded thread creation — no pool, no cap**
36 distinct spawn sites, none with a cap. Under moderate attack (e.g., credential stuffing at 100 req/s):
- Login path: 3 threads/req × 2 paths = 6 threads per auth attempt
- DNA tracking: 1 thread per 5 auth requests
- Timing canary: 1 thread per hit
- Total potential: **hundreds of threads/second**

C Python threads are OS threads. At ~1k simultaneous threads, the GIL scheduler degrades. At ~10k, the OS may OOM.

**C. TOCTOU #1 — Predictive canary planting (main.py:7378)**
The `_background_predictive` thread checks `request_count >= 3` and `existing_alerts == 0`. Two concurrent requests both see `existing_alerts == 0` and both plant. Fix: use Redis SET NX or DB-level unique constraint.

**D. TOCTOU #2 — Sandbox entry (main.py:1881)**
The middleware checks `_is_in_sandbox(fp.ip)` before threading, then `_bg_enter_sandbox → enter_attractor_sandbox` checks Redis again. Between the two checks, two concurrent requests can both enter. Fix: use Redis `SET NX` on `attractor_sandbox:{ip}`.

---

## 4. Queue Verification

### Python `queue.Queue` — cowrie pipeline

| Queue | Location | Maxsize | Blocking mode | Full behavior | Dead-letter | Persistent? |
|-------|----------|---------|---------------|---------------|-------------|-------------|
| `CowrieIntel.event_queue` | `cowrie_intelligence.py:584` | **5000** | `put_nowait()` (raise) | Drops event, increments `events_dropped` counter (line 876) | ❌ No | ❌ In-memory |
| `CowrieIntel.alert_queue` | `cowrie_intelligence.py:585` | **1000** | `put_nowait()` (raise) | Drops alert, increments `alerts_dropped` counter (line 1568) | ❌ No | ❌ In-memory |
| `_event_queues` (ops-dashboard) | `ops-dashboard/app.py:201` | **50** | Blocking `put()` | Blocks producer | ❌ No | ❌ In-memory |

### Redis list-based queues

| Queue key | Cap | Producer | Consumer | Delivery | Persistent? |
|-----------|-----|----------|----------|----------|-------------|
| `detonate:queue` | **10** (hard rejection) | `LPUSH` | `BRPOP` | At-least-once | ✅ Redis (RDB/AOF) |
| `cowrie_sessions:recent` | **1000** (LTRIM) | Cowrie pipeline | Dashboards (LRANGE) | At-most-once polling | ✅ Redis |
| `recent_fingerprints` | **10000** (LTRIM) | Campaign correlator | Campaign correlator | At-most-once | ✅ Redis |
| `bgp_monitor:alerts` | **500** (LTRIM) | BGP monitor | Dashboards | At-most-once | ✅ Redis |
| `detonation:recent` | **500** (LTRIM) | Detonation | Dashboards | At-most-once | ✅ Redis |
| `public:activity` | **Uncapped** | Public API | Dashboards | At-most-once | ✅ Redis |
| `llmfw:events:{key}` | **100** (LTRIM) | LLM firewall | UI | At-most-once | ✅ Redis |
| `llmfw:blocks:{key}` | **500** (LTRIM) | LLM firewall | UI | At-most-once | ✅ Redis |
| `fingerprint:recent_events` | **Uncapped** | Fingerprint corpus | Admin | At-most-once | ✅ Redis |
| `canary:events:recent` | **Uncapped** | Canary service | Canary dashboards | At-most-once | ✅ Redis |
| `cowrie:recent_events` | **Uncapped** (legacy/stale) | Cowrie pipeline (stale) | Legacy endpoint | At-most-once | ✅ Redis |

### Issues

1. **`public:activity` is uncapped** — LPUSH without LTRIM. Over time this list grows unboundedly. Risk: **HIGH** — memory leak.
2. **`fingerprint:recent_events` and `canary:events:recent` are uncapped** — same unbounded growth pattern.
3. **Cowrie in-memory queues are non-persistent and drop events when full.** Under burst traffic, cowrie events are silently dropped with only a counter increment. No dead-letter queue, no replay.
4. **`detonate:queue` cap of 10** — acceptable for a container-based detonation service; queue-full rejection is clean (HTTP 503).

---

## 5. Risk Assessment and Ranking

### 5.1 Race Conditions

| # | Risk | Severity | Location | Evidence | Mitigation |
|---|------|----------|----------|----------|------------|
| R1 | **TOCTOU: predictive canary plant** | **MEDIUM** | main.py:7378 + _background_predictive | `request_count >= 3` and `existing_alerts == 0` check in thread | Redis SET NX on `canary:planted:{ip}` before planting |
| R2 | **TOCTOU: sandbox entry** | **HIGH** | main.py:11527-11532 | `_is_in_sandbox()` check then `_bg_enter_sandbox` thread races | Use Redis `SET NX attractor_sandbox:{ip}` as atomic gate |
| R3 | **TOCTOU: honey_token_check middleware** | **MEDIUM** | main.py:7288 | Multiple concurrent requests from same IP can bypass rate limiter before blocklist write | Move blocklist check into a Redis atomic write |

### 5.2 Blocking Operations

| # | Risk | Severity | Location | Evidence | Mitigation |
|---|------|----------|----------|----------|------------|
| B1 | **Cowrie LLM enrichment blocks event workers** | **HIGH** | `cowrie_intelligence.py:878-891` | `_handle_event` → `_llm_enhance_session` → HTTP POST to Groq/OpenAI (2-5s) blocks the worker queue | Move LLM calls to a dedicated thread pool; use timeout on HTTP calls |
| B2 | **DB writes in middleware block request** | **MEDIUM** | `main.py:7072` | `update_session_activity` issues `db.session.commit()` per request | This is intentional for session tracking, but under load it serializes on the DB connection |
| B3 | **Docker exec in detonation blocks worker** | **MEDIUM** | `detonate.py:412` | `_exec_container(url)` blocks the BRPOP worker for up to 35s | Worker is 1:1 with queue; acceptable since queue cap is 10. Add timeout to container exec |

### 5.3 Startup Dependencies

| # | Risk | Severity | Dependencies | Evidence |
|---|------|----------|--------------|----------|
| S1 | **Engine startup order is correct** | **LOW** | Redis → leader lock → supervisor → scheduler + engines | `main.py:12221-12235` |
| S2 | **Redis fallback degrades gracefully** | **LOW** | No Redis = engines start locally (no dedup between workers) | `main.py:12217-12219` |
| S3 | **Import-time thread in supply_chain_canary** | **MEDIUM** | `supply_chain_canary.py:54` spawns beacon thread at module import — before app is fully configured | Move to `_start_all_engines` or lazy-init |

### 5.4 Shutdown Hazards

| # | Risk | Severity | Location | Evidence |
|---|------|----------|----------|----------|
| S1 | **detonate._worker_loop no stop mechanism** | **MEDIUM** | `detonate.py:394-431` | No `_running` flag or stop method; BRPOP blocks forever |
| S2 | **Request-spawned threads orphaned on shutdown** | **HIGH** | All 36 spawn sites | Daemon threads are killed when the process exits. Any in-progress alert/fingerprint/sandbox work is lost. DB writes in threads (e.g., `_record_and_score_dna` with `app.app_context()`) may fail mid-commit. |
| S3 | **Cowrie pipeline mid-event loss on shutdown** | **MEDIUM** | `cowrie_intelligence.py:1722-1728` | `stop()` only joins with 3s timeout; events in `event_queue` are lost |

### 5.5 Memory Risks

| # | Risk | Severity | Location | Evidence |
|---|------|----------|----------|----------|
| M1 | **`public:activity` uncapped Redis list** | **HIGH** | `redis_graph.json` queue section | LPUSH without LTRIM → unbounded memory growth in Redis |
| M2 | **`fingerprint:recent_events` uncapped Redis list** | **MEDIUM** | `redis_graph.json` | Same pattern — may consume significant Redis memory over time |
| M3 | **`canary:events:recent` uncapped Redis list** | **MEDIUM** | `redis_graph.json` | Same pattern |
| M4 | **Unbounded request-spawned thread accumulation** | **CRITICAL** | 36 spawn sites, no pools, no caps | Under attack, thousands of Python threads → OOM or GSL deadlock |
| M5 | **In-memory cowrie event_queue (5000) + alert_queue (1000)** | **LOW** | `cowrie_intelligence.py:584-585` | 6000 in-memory event objects peak; bounded by Queue(maxsize) |

### 5.6 Thread Leaks

| # | Risk | Severity | Location | Evidence |
|---|------|----------|----------|----------|
| T1 | **Login path spawns 6 threads per auth** | **MEDIUM** | `main.py:7901-7926` + `8042-8043` | 3 threads per password login, 3 per Google login. User could initiate multiple concurrent logins. |
| T2 | **No cap on request-spawned threads** | **CRITICAL** | All request spawn sites | No ThreadPoolExecutor, no Semaphore, no queue of threads. Fire-and-forget with unlimited growth. |
| T3 | **Cowrie→campaign ingest_session spawned per event** | **MEDIUM** | `cowrie_intelligence.py:1160` | Each cowrie session close spawns a daemon thread for campaign ingest. At 100+ sessions/min, this accumulates |

### 5.7 Redis Failure Mode Analysis

| Pattern | Fallback | Risk | Count |
|---------|----------|------|-------|
| INCR+EXPIRE rate limit | Fail-open (no rate limit) | **MEDIUM** | ~10 keys |
| INCR+EXPIRE rate limit | Fail-closed (no LLM calls) | **LOW** (cost protection) | 2 keys |
| SET NX dedup lock | Fail-open (duplicate alerts) | **LOW** | ~5 keys |
| Leader lock (SET NX) | Fail-open (all workers run engines) | **MEDIUM** | 1 key |
| Cowrie LLM daily budget | Fail-closed (rule-based fallback) | **LOW** | 1 key |

---

## 6. Runtime Health Score

### Scoring criteria
- **CRITICAL** issues: -3 each
- **HIGH** issues: -2 each
- **MEDIUM** issues: -1 each

### Deductions

| Risk | Count | Deduction |
|------|-------|-----------|
| CRITICAL: Unbounded thread creation (M4 + T2) | 2× -3 | -6 |
| CRITICAL: TOCTOU sandbox (R2) | 1× -3 | -3 |
| HIGH: TOCTOU predictive canary (R1) | 1× -2 | -2 |
| HIGH: Orphaned request-spawned threads (H2) | 1× -2 | -2 |
| HIGH: Request object capture (A1) | 1× -2 | -2 |
| HIGH: Uncapped Redis lists (M1) | 1× -2 | -2 |
| HIGH: Login 6-thread-per-auth (T1) | 1× -2 | -2 |
| MEDIUM: Cowrie LLM blocking (B1) | 1× -1 | -1 |
| MEDIUM: Shutdown event loss (H3) | 1× -1 | -1 |
| MEDIUM: Blocking DB writes in middleware (B2) | 1× -1 | -1 |
| MEDIUM: Detonate worker no stop (H1) | 1× -1 | -1 |
| MEDIUM: Cowrie→campaign thread leak (T3) | 1× -1 | -1 |
| MEDIUM: Import-time supply chain beacon (S3) | 1× -1 | -1 |

Total deductions: **25**

Score: **10 - 25** → **Health score: 1/10** (critical remediation required)

### Score interpretation

| Score | Meaning |
|-------|---------|
| 8-10 | Production ready, minor improvements |
| 5-7 | Production capable, significant improvements needed |
| 3-4 | Risky — address HIGH items before deployment |
| 1-2 | **Critical — unsafe for production without thread model redesign** |

### Immediate action items

1. **Replace fire-and-forget `threading.Thread` with a `ThreadPoolExecutor`** (max 20-50 workers) for all request-spawned alert/notification/session tasks. This caps the thread pool and prevents OOM.

2. **Fix TOCTOU race in sandbox entry** — use Redis `SET NX attractor_sandbox:{ip}` in the middleware before spawning the background thread.

3. **Extract `request` object before passing to thread** in `send_honey_alert` (main.py:5725).

4. **Add LTRIM caps to `public:activity`, `fingerprint:recent_events`, `canary:events:recent`** Redis lists.

5. **Add `_running` stop flag and Docker container cleanup** to `detonate._worker_loop`.

6. **Consider merging Login's 6 threads into 1 or using a notification queue** to reduce thread pressure.