# WraithWall Visualization Plan — Phase E

**Derived from:** architecture.json (29 subsystems), event_graph.json (173 events), dependency_graph.json (90 edges), observability.json, VISUALIZATION_ARCHITECTURE.md, RUNTIME_BEHAVIORAL_MODEL.txt Sections 10-11

**Date:** July 9, 2026

---

## 1. Visualization Readiness Scoring

Every subsystem scored 1-10 across 6 dimensions. Scores are grounded in the canonical JSON definitions, Redis key patterns, thread models, and existing SSE endpoints.

### Scoring Rubric

| Score | Meaning |
|-------|---------|
| 1-3 | Minimal/no value — data is too sparse, too transient, or too internal |
| 4-6 | Moderate value — useful but not transformative |
| 7-8 | High value — significantly improves understanding/operations |
| 9-10 | Exceptional value — transformative for the platform |

### Readiness Matrix

| # | Subsystem | Viz Value | Educational | Engineering | Executive | Debugging | Live Observability | Avg |
|---|-----------|-----------|-------------|-------------|-----------|-----------|--------------------|-----|
| 1 | Gateway / PoW | 8 | 7 | 7 | 9 | 8 | 7 | 7.7 |
| 2 | Attractor Sandbox | 10 | 10 | 9 | 10 | 9 | 9 | 9.5 |
| 3 | Hall of Mirrors | 5 | 6 | 3 | 5 | 3 | 4 | 4.3 |
| 4 | Timing Canaries | 5 | 6 | 4 | 4 | 4 | 4 | 4.5 |
| 5 | Honeytokens | 6 | 7 | 5 | 5 | 5 | 5 | 5.5 |
| 6 | Canary Service | 7 | 7 | 5 | 6 | 5 | 7 | 6.2 |
| 7 | Supply Chain Canary | 7 | 8 | 5 | 8 | 5 | 5 | 6.3 |
| 8 | Fingerprint Corpus | 8 | 9 | 8 | 8 | 8 | 9 | 8.3 |
| 9 | Session DNA | 7 | 6 | 6 | 5 | 7 | 4 | 5.8 |
| 10 | Cowrie DNA | 8 | 7 | 7 | 7 | 7 | 8 | 7.3 |
| 11 | Cowrie Pipeline | 10 | 10 | 10 | 10 | 9 | 10 | 9.8 |
| 12 | Campaign Correlator | 9 | 9 | 9 | 9 | 8 | 9 | 8.8 |
| 13 | Credential Propagation | 7 | 7 | 5 | 6 | 5 | 6 | 6.0 |
| 14 | ASN Intelligence | 8 | 9 | 7 | 8 | 7 | 8 | 7.8 |
| 15 | BGP Monitor | 9 | 9 | 8 | 9 | 7 | 9 | 8.5 |
| 16 | LLM Honeypot | 9 | 9 | 8 | 9 | 9 | 8 | 8.7 |
| 17 | LLM Firewall | 9 | 9 | 9 | 9 | 8 | 9 | 8.8 |
| 18 | AIRS | 7 | 8 | 7 | 7 | 7 | 6 | 7.0 |
| 19 | Link Checker | 6 | 5 | 6 | 3 | 6 | 6 | 5.3 |
| 20 | Detonation Engine | 8 | 8 | 8 | 7 | 7 | 8 | 7.7 |
| 21 | Breach Monitor | 8 | 8 | 7 | 8 | 7 | 7 | 7.5 |
| 22 | Incident Response | 4 | 3 | 3 | 2 | 3 | 2 | 2.8 |
| 23 | Immutable Log | 8 | 7 | 7 | 7 | 8 | 9 | 7.7 |
| 24 | Public API / Stats | 5 | 4 | 4 | 3 | 4 | 6 | 4.3 |
| 25 | DML Engine | 4 | 5 | 3 | 3 | 3 | 3 | 3.5 |
| 26 | Auth / Sessions | 5 | 4 | 6 | 4 | 5 | 5 | 4.8 |
| 27 | Notification Routing | 7 | 6 | 7 | 5 | 7 | 8 | 6.7 |
| 28 | Request Lifecycle | 9 | 10 | 9 | 10 | 8 | 9 | 9.2 |
| 29 | Leader Election / Supervisor | 4 | 3 | 4 | 2 | 3 | 4 | 3.3 |

### Top 5 by Visualization Value
1. **Cowrie Pipeline** (9.8) — 6 daemon threads + 11 Redis keys + 19 routes + 3 workers = maximum observability return
2. **Attractor Sandbox** (9.5) — 4 Redis keys + 24h-48h TTL + SandboxSession table + exfil milestones
3. **Request Lifecycle** (9.2) — 12 middleware handlers + 17 event types + 60+ DB models
4. **Campaign Correlator** (8.8) — 7 Redis keys + 8-dimension similarity + force-directed graph natural fit
5. **LLM Firewall** (8.8) — 10 Redis keys + 3 detection layers + pipeline = natural Sankey fit

### Bottom 5 (De-prioritize)
1. **Incident Response** (2.8) — 1 route, 1 Redis key, confidence 0.75, may be a stub
2. **Leader Election** (3.3) — Single Redis lock key, only relevant during startup/failover
3. **DML Engine** (3.5) — 0 routes in active deployment, confidence 0.8, partially implemented
4. **Hall of Mirrors** (4.3) — 2 Redis keys, 1h TTL, low event volume
5. **Public API / Stats** (4.3) — 2 routes, read-only aggregated data

---

## 2. Recommended Visualization Types

### Mapping: Subsystem → Primary Viz Type → Justification

| # | Subsystem | Primary Viz | Secondary Viz | SSE Live? | Animated? | Interactive? | Justification |
|---|-----------|-------------|---------------|-----------|-----------|--------------|---------------|
| 1 | Gateway / PoW | Sankey | Live Graph | Yes | Yes | Yes | Funnel flow (total → passed → failed → blocked → rate-limited). Scatter plot of score vs time. Data: `gateway:fails:{ip}`, `gateway:blocked:{ip}`, immutable log. 4 Redis keys. |
| 2 | Attractor Sandbox | Timeline | State Machine | Yes | Yes | Yes | Per-IP timeline of sandbox actions (exfil milestones at 1/5/10/25). State machine: probe → credential theft → data exfil → persistence. Replay shows fake data served. Data: `attractor_sandbox:{ip}` (48h), SandboxSession table. |
| 3 | Hall of Mirrors | State Machine | Timeline | No | Yes | Yes | Mirror depth as state machine (layers 1→N). Timeline of penetration. Data: `mirror:{ip}:{sid}` (1h), `mirror_depth:{ip}`. Very low event volume makes live animation unnecessary. |
| 4 | Timing Canaries | Timeline | — | No | No | Yes | Traditional timeline of canary plantings and hits. Data: `timing_canary:{name}:{ip}:{ts}`, `timing_canary_hits:*`. Event-driven, not real-time. |
| 5 | Honeytokens | Timeline | Event Animation | Yes | Yes | Yes | Timeline of tokens planted and triggered. Pulse animation on trigger. Data: HoneyTokenEvent table, `alert_dedup:{key}`. |
| 6 | Canary Service | Timeline | Replay View | Yes | Yes | Yes | SaaS canary lifecycle per token: mint → deployed → hit → alerted. Pulse on hit. Data: CanaryServiceToken, CanaryServiceHit tables. 16 routes, 3 background threads. |
| 7 | Supply Chain Canary | Force Graph | Timeline | No | Yes | Yes | Beacons as force-directed nodes connected to packages. Hits animate as pulses. Data: `supply_chain_canary:{token}` (365d), `canaries:active`, `canaries:triggered`. |
| 8 | Fingerprint Corpus | Heatmap | Force Graph + Sankey | Yes | Yes | Yes | World heatmap from `corpus:country_scores`. Force graph: tools → techniques → target paths. Sankey: source → tool → technique. 14 Redis keys. |
| 9 | Session DNA | Timeline | Live Graph | No | No | Yes | Behavioral baseline with anomaly markers. Deviation score over time. Data: SessionDNA, SessionEvent, DNAAlert tables (PostgreSQL). |
| 10 | Cowrie DNA | Force Graph | Timeline | Yes | Yes | Yes | Actors as hubs, sessions as spokes. Merge animation when actors consolidate. Data: BehavioralActor table, `dna:actor_sessions:{uuid}`, `dna:hassh:*`, `dna:session_actor:{sid}`. |
| 11 | Cowrie Pipeline | Pipeline | Force Graph + Timeline | Yes | Yes | Yes | **Flagship visualization**. Animated flow: Cowrie VPS → log watcher → event_queue (maxsize=5000) → N workers → CRYSTAL gates (alert/summarize/suppress) → cross-module enrichment → alert_worker → Telegram/Discord. LLM budget gauge (300/day). 11 Redis keys, 6 daemon threads. |
| 12 | Campaign Correlator | Force Graph | Timeline | Yes | Yes | Yes | IP nodes connected by campaign membership. Gravity animation: sessions merge into campaigns. Timeline slider for formation. Data: `campaign:{id}` (7d), `active_campaigns`, `recent_fingerprints` (capped 10000). |
| 13 | Credential Propagation | Force Graph | Timeline | No | Yes | Yes | Lures as nodes, green→yellow→red lifecycle. Data: `lures:active`, `lure:{lid}`, `lures:triggered`. Low frequency — animation on trigger only. |
| 14 | ASN Intelligence | Heatmap | Interactive Topology | Yes | Yes | Yes | World map colored by attack volume per country → drill to ASN. Enrichment overlay on hover. Data: `asn:leaderboard:total`, `asn:countries`, `asn:high_risk`, `ip_enrich:{hash}`. 8 Redis keys. |
| 15 | BGP Monitor | Interactive Topology | Timeline | Yes | Yes | Yes | AS nodes connected by BGP peer edges. Monitored prefix paths highlighted. Alert markers: yellow=new AS, orange=origin change, red=hijack. Timeline slider. Data: `bgp_monitor:route_state`, `bgp_monitor:alerts`, `bgp_monitor:hijacks:active:*`. Dual-feed (RIPE WS + Cloudflare). |
| 16 | LLM Honeypot | Timeline | Sequence Diagram | Yes | Yes | Yes | Chat-bubble interface showing attacker ↔ fake AI. Injection technique overlay. Timeline of sessions by threat level. Budget gauge. Data: `llm_honeypot:{ip}:{ts}`, immutable log. |
| 17 | LLM Firewall | Pipeline | Sankey + Live Graph | Yes | Yes | Yes | 3-layer detection: Layer 1 (regex) → Layer 2 (LLM) → Layer 3 (heuristic) → allow/flag/block. Sankey of prompt categories. Live graph of req/min. Data: `llmfw:stats:*`, `llmfw:events:*`, `llmfw:blocks:*`, `llmfw:cat:*`. 10 Redis keys. |
| 18 | AIRS | Timeline | Sankey | Yes | Yes | Yes | 5-detector pipeline. Detection timeline by severity. Actor tracking. Data: AIRSDetection, AIRSActor tables, 3 Redis keys. |
| 19 | Link Checker | Pipeline | No | Yes | Yes | No | URL → Validation → VT → URLScan → AbuseIPDB → Result. Progress bars per API. Data: scan results, `lc_stats:{date}`. Requires no interactivity beyond progress display. |
| 20 | Detonation Engine | Pipeline | Timeline | Yes | Yes | Yes | URL → Validation → Queue → Worker → Container → Analysis → Cross-Reference → Report. Live queue view. Data: `detonate:queue` (BRPOP), `detonate:job:{id}`, `detonation:recent`. |
| 21 | Breach Monitor | Pipeline | Timeline + Sankey | No | No | Yes | Sources → Collectors → NLP → Correlation → Alerts. Timeline of findings. Sankey: source → type → severity. Data from breach-monitor API proxy. 6h scan cadence. |
| 22 | Incident Response | State Machine | No | No | No | Yes | Playbook step completion. Minimal value — 1 route, confidence 0.75. Data: `incident:rl:{key}`. |
| 23 | Immutable Log | Pipeline (Hash Chain) | Timeline | Yes | Yes | Yes | Animated blockchain: blocks with hash links. Green checkmark for valid chain, red X for broken. Time scrubber. Data: ImmutableLog table. |
| 24 | Public API / Stats | Live Graph | No | Yes | Yes | No | Scrolling ticker of public tool usage. Live counters. Data: `public:activity`, `cowrie_sessions:recent`, `bgp_monitor:alerts`. |
| 25 | DML Engine | Component Diagram | No | No | No | Yes | Trap structure as connected nodes. Low confidence (0.8), partially implemented. Data: DML definitions. |
| 26 | Auth / Sessions | State Machine | No | No | No | Yes | Auth flow: anonymous → login → 2FA → authenticated → expired. Per-session states. Data: ActiveSession, LoginAttempt tables. |
| 27 | Notification Routing | Sankey | Component Diagram | Yes | Yes | Yes | Event types → channels (Telegram/Discord/Email/Webhook) → success/failure. Dedup effectiveness. Data from immutable log event type distribution. |
| 28 | Request Lifecycle | Sequence Diagram | C4 Container | Yes | Yes | Yes | **Architecture visualization**. Animated request packets through 12 middleware layers, color-coded by function. 8 before_request + 3 after_request + route handler. Data: timing telemetry from middleware hooks. |
| 29 | Leader Election | Deployment Topology | No | No | No | No | Simple grid showing leader status, engine health, heartbeat age. Data: `wraithwall:engine_leader` lock, `/api/health/detailed`. |

### Visualization Type Frequency

| Type | Count | Subsystems |
|------|-------|------------|
| Timeline | 18 | Sandbox, Mirrors, Canaries, Honeytokens, Canary Service, Supply Chain, Session DNA, Cowrie DNA, Cowrie Pipeline, Campaign, Cred Prop, BGP, LLM Honeypot, AIRS, Detonation, Breach, Immutable Log, Session DNA |
| Live Graph | 8 | Gateway, Fingerprint, Session DNA, LLM Firewall, Public API, Request Lifecycle, Notification, Cowrie Pipeline |
| Pipeline | 7 | Cowrie Pipeline, LLM Firewall, Link Checker, Detonation, Breach Monitor, Immutable Log, Notification |
| Force Graph | 6 | Supply Chain, Fingerprint, Cowrie DNA, Campaign, Cred Prop, ASN |
| Sankey | 5 | Gateway, Fingerprint, LLM Firewall, AIRS, Notification |
| State Machine | 4 | Sandbox, Mirrors, Incident Response, Auth |
| Heatmap | 2 | Fingerprint, ASN |
| Sequence Diagram | 2 | LLM Honeypot, Request Lifecycle |
| Interactive Topology | 2 | ASN, BGP |
| Component Diagram | 2 | DML, Notification |
| Replay View | 1 | Canary Service |
| C4 Container | 1 | Request Lifecycle |
| Deployment Topology | 1 | Leader Election |

---

## 3. Real-Time Suitability (SSE Streaming)

### Subsystems Suitable for SSE Real-Time Delivery

| # | Subsystem | Refresh Rate | SSE Stream Name | Key Data Source | Current SSE? |
|---|-----------|-------------|----------------|----------------|-----------|
| 1 | Cowrie Pipeline | <1s (real-time) | `cowrie` | `cowrie_sessions:recent`, `cowrie_completed:*`, event_queue depth | Yes — `/api/cowrie/stream` (5s poll) |
| 2 | Campaign Correlator | Seconds | `campaigns` | `campaign:*`, `active_campaigns`, `recent_fingerprints` | No |
| 3 | BGP Monitor | <1s (RIPE WS) / 15min | `bgp` | `bgp_monitor:route_state`, `bgp_monitor:alerts`, `bgp_monitor:hijacks:active:*` | No |
| 4 | LLM Firewall | Seconds (per request) | `detections` | `llmfw:events:*`, `llmfw:stats:*` | No |
| 5 | LLM Honeypot | Seconds (per request) | `detections` | `llm_honeypot:{ip}:{ts}` | No |
| 6 | Attractor Sandbox | Seconds (per action) | `deception` | `attractor_sandbox:{ip}`, SandboxSession table | No |
| 7 | Canary Service | Seconds (per trigger) | `deception` | CanaryServiceHit table | No |
| 8 | Honeytokens | Seconds (per trigger) | `deception` | HoneyTokenEvent table, immutable log | No |
| 9 | Fingerprint Corpus | Per-request (live) | `cowrie` | `fingerprint:recent_events`, `corpus:total_entries` | No |
| 10 | Gateway | Per-request | `system` | immutable log gateway events | No |
| 11 | Immutable Log | Per-write (real-time) | `system` | ImmutableLog table | No |
| 12 | Notification Routing | Per-event (real-time) | `system` | immutable log event type distribution | No |
| 13 | Detonation Engine | Seconds (per job) | `detections` | `detonate:job:{id}`, `detonate:queue` | No |
| 14 | Request Lifecycle | N/A (not pushed) | — | Middleware timing telemetry | No |

### Recommended SSE Stream Namespaces

| Stream | Subsystems | Events/sec peak | Recommended Throttle |
|--------|-----------|----------------|---------------------|
| `cowrie` | Cowrie Pipeline, Cowrie DNA, Campaign Correlator, Fingerprint Corpus | 10-50 | 5 events/sec per client |
| `deception` | Sandbox, Honeytokens, Canary Service, Timing Canaries, Mirrors | 1-5 | 2 events/sec per client |
| `detections` | LLM Firewall, LLM Honeypot, AIRS, Detonation Engine | 1-10 | 3 events/sec per client |
| `bgp` | BGP Monitor, ASN Intelligence | 0-2 (bursty) | 1 event/sec per client |
| `system` | Immutable Log, Gateway, Notification, Leader Election | 5-20 | 3 events/sec per client |

---

## 4. Animation Specification

### Subsystems Requiring Runtime Animation

| # | Subsystem | Animation Type | Duration | Trigger | Description |
|---|-----------|---------------|----------|---------|-------------|
| 1 | Cowrie Pipeline | Flow | 2-4s | Per session | Sessions as cards moving through pipeline stages. Stage color changes as processing completes. |
| 2 | Campaign Correlator | Gravity | 1-3s | Per ingest | New session nodes appear → similarity computed → edges animate → session merges into campaign or new campaign forms (gravity clustering). |
| 3 | Attractor Sandbox | Pulse | 1s | Per action | Timeline extends on new action. Countermeasure activates with icon flash when milestone reached. |
| 4 | LLM Firewall | Flow | 2-3s | Per request | Request ribbon flows through Layer 1→2→3. Color changes at each gate (green=pass, red=block, yellow=flag). |
| 5 | BGP Monitor | Explode | 0.5s | Per anomaly | Route change appears → path animates from old to new → alert marker fades. |
| 6 | Fingerprint Corpus | Pulse | 1s | Per request | Geographic pulses on world map at origin country. Scatter animation for new fingerprint clusters. |
| 7 | Immutable Log | March | 1s | Per write | New block animates in from right. Hash link appears connecting to previous block. |
| 8 | LLM Honeypot | Scan | 2s | Per message | "Analysis in progress" indicator during LLM classification. |
| 9 | Honeytokens | Pulse-Red | 0.5s | Per trigger | Red flash on source IP when a honeytoken is triggered. |
| 10 | Canary Service | Pulse | 1s | Per trigger | Canary token icon pulses purple when triggered. |
| 11 | Supply Chain Canary | Pulse | 1s | Per beacon | Beacon hit pulses from token to beacon server nodes in force graph. |
| 12 | Cowrie DNA | Orbit | 3s | Per session | Actor hub node orbits with session spokes. Merge animation: two actor nodes gravity toward each other and absorb. |
| 13 | Credential Propagation | Pulse | 1s | Per trigger | Lure node color transitions green→yellow→red. Trigger pulse explosion. |
| 14 | Gateway | Step | 0.3s | Per request | Sankey ribbon segments animate on pass/fail/block events. Scatter dots fade in. |
| 15 | Request Lifecycle | Flow | 3s | Per request | Request packet animated through 12 middleware layers, color-coded by layer function. |
| 16 | Detonation Engine | Scan | 2s | Per job | Container status indicator rotating during active detonation. |
| 17 | Notification Routing | Pulse | 1s | Per dispatch | Pulse icon on active notification channel during dispatch. |
| 18 | AIRS | Pulse | 1s | Per detection | Detection burst on 5-detector timeline. |

### Animation Library Recommendations

| Use Case | Recommended Library | Rationale |
|---------|---------------------|----------|
| Force-directed graphs (>500 nodes) | D3.js force simulation + Canvas renderer | D3 force layout is the standard; Canvas avoids SVG DOM overhead |
| Sankey diagrams | D3.js Sankey plugin | Native Sankey support, customizable ribbon widths and colors |
| Pipeline animations | Anime.js | Lightweight (13KB), excellent timeline/sequence API |
| 3D topology (BGP) | Three.js / React Three Fiber | Required for 3D AS topology with orbital controls |
| Geographic heatmaps | Leaflet + D3.js hexbin | Lightweight mapping; D3 hexbin for heatmap overlay |
| Terminal (TTY replay) | xterm.js | Existing standard for terminal replay |
| State machines | D3.js custom SVG | Straightforward state→transition→state layout |
| Timelines | uPlot (time series) + custom SVG (event markers) | uPlot is 10x faster than Chart.js for time-series; custom SVG for event markers |
| Gauges / sparklines | uPlot | Minimal overhead, high rendering performance |

---

## 5. Priority Matrix

### P0 — Must-Have (Foundation Layer)

These 4 visualizations plus the event bus form the foundation. Without them, the visualization system has no "wow factor" and no core value.

| # | Subsystem | Effort (weeks) | Complexity | Risk | Dependencies | Deliverable |
|---|-----------|----------------|------------|------|-------------|-------------|
| — | **Live Event Bus** (`/api/live/events` SSE) | 1 | Low | Low | Redis Streams, SSE library | Multiplexed SSE endpoint with per-stream filtering |
| 1 | **Cowrie Pipeline** (animated pipeline + force graph + timeline) | 6 | High | Low | SSE `cowrie` stream, existing `/api/cowrie/stream`, 11 Redis keys | Real-time pipeline visualization + session detail + LLM budget gauge |
| 2 | **Campaign Correlator** (force directed graph + timeline) | 4 | High | Medium | SSE `campaigns` stream, `campaign:{id}`, `recent_fingerprints` (Redis-only state is a risk) | Force graph with gravity animation, timeline slider, campaign detail drill-down |
| 3 | **Attractor Sandbox** (timeline + state machine theater) | 3 | Medium | Low | SSE `deception` stream, `attractor_sandbox:{ip}`, SandboxSession table | Per-IP sandbox theater with action timeline and countermeasure animation |
| 4 | **Request Lifecycle** (sequence diagram + C4) | 2 | Medium | Low | Middleware timing telemetry (need to add Redis stream writes) | Animated request lifecycle with color-coded middleware layers |

**Total P0 effort: 13 weeks** (4 core visualizations + event bus)

**P0 Risk:** The Cowrie Pipeline and Campaign Correlator both depend on Redis data that has TTL expirations (30d and 7d respectively). If Redis restarts, the Campaign Correlator loses all state. This risk is documented but does not block visualization — the visualization surfaces the current state regardless.

### P1 — High Value, Moderate Effort

| # | Subsystem | Effort (weeks) | Complexity | Risk | Dependencies |
|---|-----------|----------------|------------|------|-------------|
| 5 | **LLM Firewall** (pipeline + Sankey + live graph) | 2 | Medium | Low | `llmfw:stats:*`, `llmfw:events:*`, `llmfw:cat:*` (10 Redis keys) |
| 6 | **LLM Honeypot** (chat timeline + sequence diagram) | 2 | Low | Low | `llm_honeypot:{ip}:{ts}`, immutable log |
| 7 | **Fingerprint Corpus** (heatmap + force graph + Sankey) | 3 | Medium | Low | `corpus:country_scores`, `corpus:techniques`, `corpus:ja3:*`, `corpus:tool:*` (14 Redis keys) |
| 8 | **BGP Monitor** (interactive topology + timeline) | 4 | High | Medium | SSE `bgp` stream, `bgp_monitor:route_state`, `bgp_monitor:hijacks:active:*` |
| 9 | **Immutable Log** (hash chain visualizer) | 2 | Low | Low | ImmutableLog table (PostgreSQL) |
| 10 | **Gateway / PoW** (Sankey + scatter) | 2 | Medium | Low | Immutable log gateway events, `gateway:fails:{ip}`, `gateway:blocked:{ip}` |
| 11 | **Breach Monitor** (pipeline + timeline + Sankey) | 3 | Medium | Low | Breach-monitor API proxy |
| 12 | **System Health Dashboard** (component diagram + live graph) | 2 | Low | Low | Existing `/api/health/detailed` endpoint |

**Total P1 effort: 19 weeks**

### P2 — Nice to Have

| # | Subsystem | Effort (weeks) | Complexity | Risk | Dependencies |
|---|-----------|----------------|------------|------|-------------|
| 13 | **ASN Intelligence** (heatmap + interactive topology) | 3 | Medium | Low | `asn:leaderboard:total`, `asn:countries`, `asn:high_risk`, `ip_enrich:{hash}` |
| 14 | **Cowrie DNA** (force graph + timeline) | 3 | Medium | Low | BehavioralActor table, `dna:actor_sessions:{uuid}`, `dna:hassh:*` |
| 15 | **Session DNA** (timeline + live graph) | 2 | Medium | Low | SessionDNA, SessionEvent, DNAAlert tables |
| 16 | **Supply Chain Canary** (force graph + timeline) | 2 | Low | Low | `supply_chain_canary:{token}`, `canaries:active`, `canaries:triggered` |
| 17 | **Canary Service** (timeline) | 2 | Low | Low | CanaryServiceToken, CanaryServiceHit tables |
| 18 | **Honeytokens** (timeline + pulse animation) | 1 | Low | Low | HoneyTokenEvent table, immutable log |
| 19 | **Detonation Engine** (pipeline + timeline) | 3 | Medium | Low | `detonate:queue`, `detonate:job:{id}`, `detonation:recent` |
| 20 | **AIRS** (timeline + Sankey) | 2 | Low | Low | AIRSDetection table (gated by ENABLE_AI_RUNTIME_SECURITY) |
| 21 | **TTY Replay Enhancement** (xterm.js) | 1 | Low | Low | Existing `/api/replay/{sid}` endpoint |
| 22 | **Notification Routing** (Sankey) | 1 | Low | Low | Immutable log event type distribution |
| 23 | **Credential Propagation** (force graph + timeline) | 2 | Low | Low | `lures:active`, `lure:{lid}`, `lures:triggered` |

**Total P2 effort: 22 weeks**

### P3 — Polish / Stretch

| # | Subsystem | Effort (weeks) | Complexity | Risk | Dependencies |
|---|-----------|----------------|------------|------|-------------|
| 24 | **Hall of Mirrors** (state machine + timeline) | 1 | Low | Low | `mirror:{ip}:{sid}`, `mirror_depth:{ip}` |
| 25 | **Rate-Limiting Dashboard** (gauges + heatmap) | 1 | Low | Low | 14+ rate-limit Redis keys |
| 26 | **Timing Canaries** (timeline) | 1 | Low | Low | `timing_canary:{name}:{ip}:{ts}`, `timing_canary_hits:*` |
| 27 | **Auth Session Flow** (state machine) | 1 | Low | Low | ActiveSession, LoginAttempt tables |
| 28 | **Public API / Stats** (scrolling ticker) | 1 | Low | Low | `public:activity`, `cowrie_sessions:recent` |
| 29 | **Link Checker** (pipeline with progress bars) | 1 | Low | Low | Scan results, `lc_stats:{date}` |
| 30 | **DML Engine** (component diagram) | 1 | Low | Low | DML trap definitions |
| 31 | **Leader Election** (deployment topology) | 1 | Low | Low | `wraithwall:engine_leader` lock key |
| 32 | **Incident Response** (state machine) | 1 | Low | Low | Incident playbook state (currently confidence 0.75) |

**Total P3 effort: 9 weeks**

### Priority Matrix Summary

| Priority | Count | Total Effort | Core Systems | Deception | Intelligence | Security | Infrastructure |
|----------|-------|-------------|--------------|---------|---------------|-----------|----------------|
| **P0** | 4 + bus | 13 weeks | Request Lifecycle | Sandbox | Cowrie, Campaign | — | Event Bus |
| **P1** | 8 | 19 weeks | Immutable Log | — | BGP, ASN, Fingerprint, Breach | LLM Firewall, Gateway | System Health |
| **P2** | 11 | 22 weeks | — | DNA, Canary Service, Supply Chain, Honeytokens, Credential Prop, Detonation | ASN, Cowrie DNA, Session DNA | AIRS, TTY Replay | Notification |
| **P3** | 8 | 9 weeks | Auth, Stats | Timing Canaries, Mirrors, DML | Link Checker | Rate-Limiting | Leader Election |
| **Total** | **31 visualizations** | **63 weeks** | | | | | |

**Realistic delivery estimate (parallelized): 6 months with 2 full-time frontend engineers**

---

## 6. Subsystem Interaction Classification

### Which subsystems should be interactive?
All P0 and P1 visualizations should support:
- **Hover**: tooltip with key metrics
- **Click**: drill-down to detail view
- **Timeline scrub**: scroll through time
- **Filter**: by subsystem, event type, severity, time range
- **Search**: by IP, session ID, campaign ID, token value

### Which subsystems should be animated?
- **Mandatory animation**: Cowrie Pipeline (flow), Campaign Correlator (gravity), Attractor Sandbox (pulse), LLM Firewall (flow), BGP Monitor (explode), Immutable Log (march)
- **Recommended animation**: Fingerprint Corpus (pulse), LLM Honeypot (scan), Honeytokens (pulse-red), Canary Service (pulse), Supply Chain (pulse), Cowrie DNA (orbit), Credential Propagation (pulse), Gateway (flow), Request Lifecycle (flow), Notification (pulse), Detonation (scan), AIRS (pulse)

### Which subsystems are suitable for live SSE streaming?
See Section 3 above. **14 of 29 subsystems** should stream real-time data through SSE.

---

## 7. Technology Stack Recommendations

### Frontend (Vue 3 — existing codebase)
| Library | Version | Use Case | Bundle Size | Notes |
|---------|---------|----------|-------------|-------|
| d3.js | v7 | Force graphs, Sankey, heatmaps, timelines | 26KB (gzip) | Core visualization library |
| uPlot | 1.6+ | Time series, gauges, sparklines | 12KB (gzip) | 10x faster than Chart.js |
| xterm.js | 5+ | TTY replay | 40KB (gzip) | Already partially used |
| anime.js | 3+ | Flow animations, transitions | 13KB (gzip) | Better than GSAP for Vue |
| Leaflet | 1.9 | Geographic maps | 40KB (gzip) | Smaller than Mapbox GL |
| vue-virtual-scroller | 1.x | Infinite event feeds | 8KB (gzip) | For live event log |

### Backend Additions (Minimal)
1. **Redis Streams** → `XADD` calls in all P0/P1 subsystems
2. **SSE endpoint** `/api/live/events` — multiplexed with stream name filter
3. **Health SSE** — push system health changes through `/api/system/events`

### Existing Infrastructure to Reuse
- `/api/cowrie/stream` — refactor from 5s polling to Redis Stream push
- `/api/health/detailed` — for system health component
- `ImmutableLog` table — for hash chain and audit visualization
- All Redis keys documented in architecture.json — no new keys needed

---

## 8. Implementation Phasing

### Sprint 1-2: Foundation (Weeks 1-2)
- `/api/live/events` SSE endpoint
- SSE consumer Vue composable
- Color system + animation language (from RUNTIME_BEHAVIORAL_MODEL.txt Section 11.1)
- Request Lifecycle C4 container diagram (static, non-animated)
- System Health Dashboard

### Sprint 3-6: Core Visualizations (Weeks 3-6)
- Cowrie Pipeline animated diagram
- Campaign Force Graph with gravity animation
- Attractor Sandbox Theater
- Immutable Log Chain visualizer

### Sprint 7-10: Security Controls (Weeks 7-10)
- LLM Firewall Sankey + Pipeline
- Gateway Sankey
- LLM Honeypot Chat Timeline
- Fingerprint Corpus heatmap + force graph

### Sprint 11-14: Network & Infrastructure (Weeks 11-14)
- BGP Route Topology (3D if feasible, 2D force graph otherwise)
- ASN World Map heatmap
- Breach Monitor pipeline

### Sprint 15-18: Deception & Enhancement (Weeks 15-18)
- Cowrie DNA Actor Graph
- Supply Chain Canary force graph
- Honeytokens timeline
- Notification Routing Sankey
- Detonation Pipeline
- AIRS timeline + Sankey

### Sprint 19-20: Polish (Weeks 19-20)
- Hall of Mirrors state machine
- Rate-Limiting Dashboard
- Auth flow state machine
- Public API ticker
- Remaining P3 items

---

## 9. Risk Mitigation for Visualization Development

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| SSE overload with high-volume Cowrie events | Medium | High | Throttle to 5 events/sec per client; aggregate before sending; client controls throttle via query param |
| Redis load from real-time polling | Medium | Medium | Use Redis Streams (XREAD with BLOCK) instead of polling; consumer groups for multi-subscriber |
| Vue bundle size with D3 force graph | Low | Medium | Dynamic imports per route; lazy-load force graph library only on campaign page |
| Campaign data is Redis-only (7d TTL) | Medium | High | Add periodic PostgreSQL snapshots; visualization must handle empty state gracefully |
| Thread explosion under attack creates misleading visualizations | Low | Low | Add current thread count as system health metric; cap displayed event rate |
| Browser performance with large force graphs (>1000 nodes) | Medium | Medium | Canvas renderer threshold at 500 nodes; GPU acceleration via Three.js for BGP |
| Cowrie event_queue maxsize=5000 stalls visualization data | Low | Medium | Show event_queue depth as health indicator; show backlog as orange on pipeline |
| WebSocket/SSE connection limits with many browser tabs | Low | Low | Single shared SSE connection per browser; HTTP/2 multiplexing |
| Real-time data inconsistent with delayed write-backends | Low | Low | Show "data age" indicator on real-time panels; use server timestamps not client |

---

## 10. Key Metrics to Track During Implementation

| Metric | Target | Measure |
|--------|--------|---------|
| Event bus latency (SSE) | <1s | Time from Redis XADD to frontend render |
| Frame rate for force graphs | >30fps at 500 nodes | requestAnimationFrame frame time |
| SSE connection stability | <1 reconnect/hour per client | WebSocket/SSE onclose events |
| Dashboard load time | <3s initial render | DOMContentLoaded for dashboard route |
| Memory usage (single dashboard) | <200MB | Heap snapshot for Campaign + Cowrie + Sandbox concurrent views |
| Event throughput at client | >100 events/sec before throttle | Events rendered per second (throttled server-side) |