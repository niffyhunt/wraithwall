# Runtime Telemetry Plan

**Generated:** 2026-07-09  
**Phase:** 6 — Runtime Telemetry Mapping  
**Canonical sources:** runtime_metrics.json, telemetry_catalog.json, live_nodes.json, live_edges.json

---

## 1. Cardinality Budgets per Key Pattern

| Key Pattern | Current Est. | Budget | TTL/LTRIM | Overshoot Action |
|---|---|---|---|---|
| `gw:session:{fp}:{ip}` | 1k-5k | 10k | TTL 300s | Hard TTL enforced |
| `gw:blocklist` | 100-5k | 10k | None | Manual review >5k |
| `attractor_sandbox:{ip}` | 10-200 | 500 | TTL 172800s (48h) | SET NX prevents duplicates |
| `canary:{public_id}:hits` | 10-10k | 5k | None | **Add LTRIM 1000** — high risk |
| `ht:{tid}:hits` | 10-500 | 1k | None | **Add LTRIM 500** — medium risk |
| `corpus:fp:{hash}:data` | 1k-50k | 100k | None | Set TTL 30d on new entries |
| `bgp:route_state:*` | 1k-100k | 200k | TTL 86400s | Monitor; dynamic during churn |
| `h:log:{entry_id}` | 1k-100k | 200k | **None** | **CRITICAL** — add TTL 7d or expedite S3 archival |
| `log:index:*` | 1k-100k | 200k | **None** | **CRITICAL** — add TTL 7d or expedite S3 archival |
| `cowrie_sessions:recent` | 1k | 1k | LTRIM 1000 | Already capped |
| `public:activity` | 50 | 50 | LTRIM 50 | Already capped |
| `fingerprint:recent_events` | 50 | 50 | LTRIM 50 + TTL 30d | Already capped |

## 2. TTL Strategy

**Goal:** >80% of key patterns covered by TTL or LTRIM (currently 61.8%).

### Immediate (this week)
1. `canary:{public_id}:hits` — add `LTRIM 0 999` and `EXPIRE 604800` (7d) after each write
2. `ht:{tid}:hits` — add `LTRIM 0 499` and `EXPIRE 2592000` (30d)
3. `lc:stats:{date}` — add `EXPIRE 7776000` (90d) on creation

### Short-term (Phase 1 Weeks 3-4)
4. `h:log:{entry_id}` — add `EXPIRE 604800` (7d) as safety net before S3 archival is fully live
5. `log:index:*` — add `EXPIRE 604800` (7d) same as above

### Monitoring
6. `bgp:route_state:*` — TTL 86400s already applied; ensure cleanup runs during low-churn periods
7. `corpus:fp:{hash}:data` — evaluate TTL 30d; fingerprints older than 30d may still be relevant

## 3. Alert Thresholds

| Metric | Warning | Critical | Action |
|---|---|---|---|
| `redis_memory_usage_bytes` | >70% maxmemory | >85% maxmemory | Add memory, rotate keys, evict stale |
| `redis_key_cardinality` (h:log) | >50k | >100k | Force S3 archival, add TTL |
| `redis_key_cardinality` (bgp:route_state) | >50k | >100k | Investigate BGP churn storm |
| `canary_hits_unbounded_growth` | >5k | >10k | Apply LTRIM immediately |
| `thread_pool_utilization` | >0.8 | >0.95 | Scale workers, investigate leak |
| `notification_dlq_depth` | >5 | >20 | Investigate notification channel outage |
| `apscheduler_job_missed_runs` | >0 (any) | >3 in 1h | Restart scheduler, check worker count |
| `cowrie_recent_events_stale` | 1 | 1 | Migrate endpoint to cowrie_sessions:recent |
| `subsystem_health_status` | 0 for >30s | 0 for >120s | Pager/incident |
| `immutable_log_archival_gap` | >50k | >100k | Force archival cycle |

## 4. Instrumentation Gaps (to implement)

These metrics require code changes before they can be scraped:

1. **`redis_key_cardinality`** — Add a `/api/admin/redis-cardinality` endpoint that runs `SCAN` + `STRLEN`/`LLEN`/`SCARD`/`HLEN` per tracked pattern, or install a Redis `INFO KEYSPACE` monitor.
2. **`subsystem_health_status`** — Each subsystem needs a health endpoint. 10 of 34 nodes lack any probe (inline functions, background engines). Add `/api/health/<subsystem_id>` stubs.
3. **`subsystem_thread_count`** — Wrap `threading.active_count()` with per-subsystem labeling using `threading.current_thread().name` convention.
4. **`immutable_log_archival_gap`** — Track last archived `entry_id` offset.
5. **`campaign_correlation_latency_ms`** — Add timing around `correlate_event()`.
6. **`notification_dispatch_latency_ms`** — Add timing in each service dispatch function.
7. **`apscheduler_job_duration_ms`** / **`apscheduler_job_missed_runs`** — Add `@scheduler_listener` for `EVENT_JOB_EXECUTED` / `EVENT_JOB_MISSED` / `EVENT_JOB_ERROR`.
8. **`thread_pool_utilization`** — Expose semaphore `_value` / `_initial_value` from `BoundedSemaphore(64)`.

## 5. Remediation Actions (Prioritized)

### P0 — Memory Pressure (immutable log)
- **Owner:** All / monitoring
- **Action:** Add TTL 7d to `h:log:{entry_id}` and `log:index:*` as interim safety net
- **Why:** These are the only unbounded keys with HIGH cardinality potential. Without TTL, Redis memory grows monotonically.
- **Risk if deferred:** OOM kill of Redis instance under sustained load.

### P0 — Stale Cowrie Endpoint
- **Owner:** Cowrie Intelligence
- **Action:** Migrate `GET /api/cowrie/recent` to read from `cowrie_sessions:recent` instead of `cowrie:recent_events`
- **Why:** `cowrie:recent_events` has no writer. Returns stale or empty data.
- **Risk if deferred:** Users/consumers see empty Cowrie data silently.

### P1 — Canary Hits Unbounded
- **Owner:** Canary Service
- **Action:** Add `LTRIM 0 999` + `EXPIRE 604800` after LPUSH to `canary:{public_id}:hits`
- **Why:** Popular canaries can accumulate 10k+ hits with no bound.
- **Risk if deferred:** Redis memory grows with each canary trigger.

### P1 — Orphan Blueprint Cataloguing
- **Owner:** Architecture documentation
- **Action:** Add `replay_bp` (TTY Replay) and `terminal_bp` (Terminal Gateway) as subsystems in architecture.json
- **Why:** These are registered blueprints with no architecture entry. Visualized as grey orphans.
- **Risk if deferred:** Live graph cannot show complete runtime picture.

### P2 — Route Documentation Catch-up
- **Owner:** Each subsystem maintainer
- **Action:** Update architecture.json route lists for 7 subsystems with route drift (Fingerprint Corpus, ASN Intel, LLM Honeypot, AIRS, Supply Chain Canary, Canary Service, BGP Monitor)
- **Why:** Architecture documentation does not match deployed routes.
- **Risk if deferred:** New developers reference wrong route paths.

### P2 — False url_prefix Claims
- **Owner:** Architecture documentation
- **Action:** Remove `url_prefix` claims from Gateway, Credential Propagation, Incident Response — these blueprints register with hardcoded route paths, not url_prefix
- **Why:** If someone adds url_prefix, routes would double-prefix.
- **Risk if deferred:** Confusion on route registration pattern.

### P3 — Outbound API Dependency Updates
- **Owner:** Credential Propagation, Incident Response
- **Action:** Add GitHub API, GitLab API, Resend API to `outbound_apis` in architecture.json
- **Why:** Missing deps in architecture affect threat modeling and dependency analysis.
- **Risk if deferred:** Low — operational issue, not runtime risk.

## 6. Ongoing Telemetry Pipeline

### Data Flow

```
[Subsystem] --health probe--> [Health Checker] --metric--> [Redis metrics:YYYY-MM-DD] --scrape--> [Prometheus / Grafana]
[Subsystem] --Redis write--> [Redis] --INFO/MONITOR--> [Cardinality tracker] --alert--> [Notification Routing]
[APScheduler] --listener--> [Job Monitor] --alert--> [Notification Routing]
[Thread Pool] --semaphore check--> [Pool Monitor] --alert--> [Notification Routing]
```

### Storage Strategy
- Raw telemetry: Redis hashed time-series (`metrics:{date}:{metric_name}`) with TTL 90d
- Aggregated daily: InfluxDB or SQLite (if no Influx) with 1-year retention
- Alerts: Redis pub/sub -> Notification Routing -> Telegram/Discord/Email

### Scrape Intervals (defaults from telemetry_catalog.json)
- Redis memory: 30s
- Subsystem health: 30s
- Request rate: 30s
- Thread pool: 30s
- Key cardinality: 60s
- Campaign latency: 60s
- Notification latency: 60s
- Scheduler job duration: per run
- BGP route state: 60s
- Cowrie stale check: 3600s (hourly)
- Canary hits growth: 300s (5 min)
- Blocklist size: 300s
- Token count: 300s
- Cache hit ratio: 300s
- Immutable log archival gap: 300s
- TTL coverage: 300s
