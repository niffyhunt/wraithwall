# WraithWall Visualization Architecture

**Principal Visualization Architect — Reverse Engineering Report**
**Date:** July 8, 2026
**Status:** Final

---

## Executive Summary

After reverse engineering every backend pipeline across 35+ Python files, 19 Flask blueprints, ~70 background threads, 10 APScheduler jobs, and 150+ Redis key patterns, this report presents a complete visualization language designed to transform WraithWall from a security platform into an observable, living security organism.

Every recommendation is grounded in existing backend capabilities. No invented endpoints. Every visualization maps to real data flowing through real pipelines.

---

## Reverse Engineered Subsystem Inventory

### Core Platform (main.py)
| Subsystem | Lines | Threads | Redis Keys | DB Models | Visualizable |
|-----------|-------|---------|------------|-----------|-------------|
| Request Lifecycle | 1-826 | 0 | 0 | 60+ models | Yes |
| Auth/2FA/Sessions | 7710-9216 | 8+ | 0 | 12+ models | Yes |
| Gateway/PoW | gateway.py:1-268 | 0 | 4 | 0 | Yes |
| Attractor Sandbox | 2095-2432 | 1+ | 1 | 2 | Yes |
| Hall of Mirrors | 2993-3209 | 0 | 2 | 0 | Yes |
| Timing Canaries | 1660-1830 | 1+ | 3 | 0 | Yes |
| Attacker Profiles | 3527-3595 | 1+ | 1 | 0 | Yes |
| Session DNA | 5140-5365 | 2+ | 0 | 3 | Yes |
| Immutable Log | 4570-4620 | 0 | 0 | 1 | Yes |
| Honeytokens | 5700-5765 | 1+ | 0 | 2 | Yes |
| Canary Records | 4400-4530 | 2+ | 2 | 3 | Yes |
| Provenance | 4950-5110 | 1+ | 0 | 1 | Yes |
| Threat Intel Tools | 9359-9910 | 0 | 0 | 0 | Yes |

### Blueprint Subsystems
| Blueprint | File | Routes | Redis Keys | Background Threads |
|-----------|------|--------|------------|-------------------|
| link_checker_bp | link_checker.py | 5 | 8 | 0 |
| incident_response_bp | incident_response.py | 1 | 1 | 0 |
| llm_honeypot_bp | llm_honeypot.py | 7 | 5 | 3+ |
| corpus_bp | fingerprint_corpus.py | 7 | 14 | 0 |
| cowrie_intel_bp | cowrie_intelligence.py | 12 | 19 | 5+ |
| replay_bp | replay_tty.py | 2 | 1 | 0 |
| campaign_bp | campaign_correlator.py | 4 | 7 | 1 |
| cred_prop_bp | credential_propagation.py | 4 | 5 | 1 |
| asn_intel_bp | asn_intelligence.py | 5 | 8 | N |
| supply_chain_bp | supply_chain_canary.py | 4 | 6 | 1 |
| bgp_bp | bgp_monitor.py | 6 | 8 | 1 |
| public_bp | public_api.py | 2 | 10 | 0 |
| gateway_bp | gateway.py | 4 | 4 | 0 |
| canary_service_bp | canary_service.py | 16 | 8 | 3+ |
| llm_firewall_bp | llm_firewall.py | 8 | 10 | 2+ |
| sandbox_bp | sandbox.py | 5 | 4 | 1 |
| detonate_bp | detonate.py | 6 | 4 | 2 |
| terminal_bp | terminal_bp.py | 2 | 0 | 1 |
| ai_runtime_bp | ai_runtime_security.py | 9 | 3 | 1 |

### Intelligence Engines
| Engine | Schedule | Data Sources | Consumers |
|--------|----------|-------------|-----------|
| Cowrie Pipeline | Continuous (file tail + pub/sub) | Cowrie VPS SSH logs, Redis | CRYSTAL Classifier, Campaign Correlator, DNA, HASSH |
| CRYSTAL Classifier | Per-session | Cowrie Pipeline | Alert Router |
| Campaign Correlator | Per-session ingest | Cowrie Pipeline, Detonation Pipeline | Campaign DB, Alert Router |
| Behavioral DNA | Per-session | Cowrie Pipeline | Actor DB \\
| Credential Propagation | 1x thread (auto_rotate) | Cowrie Pipeline | Lure DB \\
| ASN Intelligence | On-demand + per-attack | IPInfo, AbuseIPDB, Shodan, RDAP | ASN DB, Abuse Report Engine |
| BGP Monitor | 15min + RIPE RIS websocket | Cloudflare Radar, RIPE RIS | BGP DB, ASN Intelligence |
| Breach Monitor | 6h + continuous paste/GitHub scans | Pastebin, GitHub, HIBP | Breach DB, Alert Router |
| Detonation Worker | Continuous (BPOP queue) | Browserless/Docker | Campaign Correlator, Fingerprint Corpus |

### Notification Channels
| Channel | Events | Frequency | Dedup |
|---------|--------|-----------|-------|
| Telegram | All security events (25+ types) | Per-event + daily digest | Redis SETNX TTL (120-300s) |
| Discord | Canary, Sandbox, BGP, LLM, Cowrie, Breach | Per-event | Same |
| Email (Resend) | Auth, Canary triggers, Breach, Abuse reports, Billing | Per-event + scheduled | Per-target 3600s |
| Slack | Demo requests only | Per-event | None |
| Webhook | Demo requests, LLM Firewall | Per-event | HMAC-signed |
| Immutable Log | All security events (40+ types) | Every event | SHA-256 hash chain |

---

## Visualization Recommendation Matrix

For each subsystem, I recommend the optimal visualization type(s) and explain the value proposition.

### 1. FLASK REQUEST LIFECYCLE

**Visualization:** C4 Container Diagram + Live Sequence Diagram

**Recommended Type:** `C4` + `Sequence Diagram`

**Why:**
- **Users:** Understand how their requests flow through gateway, auth, rate-limiting, and to their data
- **Analysts:** Trace attacker requests through the full pipeline — gateway → sandbox check → fingerprint → canary check → honeytoken check → provenance check → route handler
- **Engineers:** Debug performance bottlenecks, identify where middleware adds latency
- **Investors:** See the defense-in-depth architecture in a single view — PoW gateway → rate limiting → auth 2FA → fingerprint analysis → canary detection → honeytoken traps → immutable audit
- **Differentiation:** No competitor visualizes their own request pipeline as a live animation showing requests bouncing through security middleware layers

**Implementation:**
- Use existing `@app.before_request` and `@app.after_request` hooks to emit timing telemetry to a Redis stream
- Vue frontend subscribes to SSE at `/api/cowrie/stream`-style endpoint
- Animated request packets flow through colored middleware layers: gray (static) → blue (gateway) → yellow (rate-limit) → green (auth) → orange (fingerprint) → red (canary check) → purple (provenance) → teal (handler)

**Priority:** P0 | **Complexity:** Medium | **Dependencies:** SSE endpoint | **Risk:** Low | **Effort:** 2-3 weeks

---

### 2. GATEWAY / PROOF-OF-WORK

**Visualization:** Live Gateway Dashboard — Sankey Flow + Scatter Plot

**Recommended Type:** `Sankey` + `Live Graph`

**Why:**
- **Users:** See who passes vs fails the PoW challenge
- **Analysts:** Detect botnet-scale verification failures, identify patterns in failed attempts
- **Engineers:** Monitor PoW difficulty tuning, detect when challenge is too easy/hard
- **Investors:** Quantify automated attack volume blocked at the front door
- **Differentiation:** A live Sankey showing "100% of traffic → 60% pass PoW → 40% fail → 5% hard-blocked" makes defense tangible

**Data Sources:**
- `gateway:fails:{ip}` — failure tracking per IP
- `gateway:blocked:{ip}` — currently blocked IPs
- `gateway:verify_rl:{ip}` — rate-limited IPs
- Gateway audit log entries (in immutable log)

**Implementation:**
- Parse gateway audit events from immutable log
- Sankey: Total Requests → PoW Passed / PoW Failed → Blocked / Rate-Limited / Allowed
- Animated scatter: each dot is a verification attempt, X=time, Y=signal score, color=verdict

**Priority:** P1 | **Complexity:** Medium | **Dependencies:** Gateway audit stream | **Risk:** Low | **Effort:** 2 weeks

---

### 3. ATTRACTOR SANDBOX

**Visualization:** Live Attacker Sandbox Theater — Timeline + State Machine

**Recommended Type:** `Timeline` + `State Machine` + `Attack Replay`

**Why:**
- **Users:** See attackers trapped in the sandbox, interacting with fake data
- **Analysts:** Replay attacker behavior within the sandbox, understand their goals
- **Engineers:** Tune sandbox responses, add new deception paths
- **Investors:** Watch "hackers hacking your fake systems" — the ultimate demo
- **Differentiation:** A live theater showing attackers navigating fake environments, stealing fake credentials, thinking they've won — while WraithWall watches

**Data Sources:**
- `attractor_sandbox:{ip}` — who's in the sandbox
- `SandboxSession` table — actions, exfil attempts, trigger reason
- Immutable log entries with `attractor_sandbox_*` event types
- Sandbox response logs (fake shell, fake API responses)

**Implementation:**
- Timeline: each sandboxed IP has a vertical timeline of every action they took
- State machine: shows the attacker progressing through stages (probe → credential theft → data exfil → persistence) with WraithWall countermeasures activating at each stage
- Replay: step through each sandbox interaction with the fake data that was served

**Priority:** P0 | **Complexity:** High | **Dependencies:** Sandbox SSE stream | **Risk:** Medium | **Effort:** 4-5 weeks

---

### 4. COWRIE HONEYPOT PIPELINE

**Visualization:** Live Cowrie Pipeline — Pipeline + Force Graph + Timeline

**Recommended Type:** `Pipeline` + `Force Graph` + `Timeline`

**Why:**
- **Users:** See real-time SSH attacks being analyzed
- **Analysts:** Trace a single session end-to-end: connect → login attempt → command → download → session close → CRYSTAL classification → enrichment → alert
- **Engineers:** Monitor pipeline health (queue depth, worker count, LLM budget, CRYSTAL gate decisions)
- **Investors:** Demonstrate the most sophisticated SSH honeypot analysis pipeline in production
- **Differentiation:** No other platform visualizes the internal pipeline of their threat analysis engine

**Data Sources:**
- `cowrie_session:{sid}` — active sessions (Redis)
- `cowrie_completed:{sid}` — completed sessions (Redis)
- `cowrie_sessions:recent` — session list (Redis)
- Cowrie intelligence pipeline metrics (event queue depth, worker status, LLM budget)
- CRYSTAL classification results

**Implementation:**
- Pipeline view: animated flow from "Cowrie VPS" → "Log Watcher" → "Event Queue" → "N Workers" → "Event Handlers" → "CRYSTAL Classifier" → "Cross-Module Enrichment" → "Alert Router"
- Each session appears as a card moving through pipeline stages with live status
- Force graph: sessions connected by shared IPs, commands, HASSH, targets
- Timeline: a Gantt-style view of session duration with command markers

**Priority:** P0 | **Complexity:** High | **Dependencies:** `api/cowrie/stream` SSE, Redis pipeline metrics | **Risk:** Low | **Effort:** 5-6 weeks

---

### 5. COWRIE TTY REPLAY

**Visualization:** Terminal Replay with xterm.js

**Recommended Type:** `Timeline` (already partially implemented)

**Why:**
- **Analysts:** Watch exactly what the attacker typed, character by character, with original timing
- **Engineers:** Debug TTY log parsing, improve sanitization
- **Differentiation:** Full xterm.js replay with speed control, timeline scrubbing, and search

**Implementation:**
- Enhance existing `replay_tty.py` playback page
- Add search (highlight matching text in replay)
- Add timeline scrubber bar
- Add session context sidebar (commands, downloads, logins)
- Add "download as script" button

**Priority:** P1 | **Complexity:** Low | **Dependencies:** Existing endpoint (replay_tty.py) | **Risk:** Low | **Effort:** 1-2 weeks

---

### 6. CRYSTAL CLASSIFIER

**Visualization:** CRYSTAL Decision Tree — Interactive Flowchart

**Recommended Type:** `State Machine` + `Sankey`

**Why:**
- **Analysts:** See why a session was suppressed/summarized/alerted
- **Engineers:** Tune gate thresholds, debug classification logic
- **Investors:** Demonstrate sophisticated AI-guided triage
- **Differentiation:** An interactive visualization of the decision tree that processes every SSH attack

**Data Sources:**
- CRYSTAL classifier output (per session, stored in session intelligence JSON)
- Gate application reasons
- Priority scores

**Implementation:**
- Sankey of sessions flowing through CRYSTAL gates: background_radiation → mass_scanner → benign_behavior → alert_velocity → final_action
- Each gate shows how many sessions it filtered
- Click on a gate to see sample sessions that hit it
- Real-time animation as new sessions flow through

**Priority:** P2 | **Complexity:** Medium | **Dependencies:** Cowrie pipeline data | **Risk:** Low | **Effort:** 2-3 weeks

---

### 7. CAMPAIGN CORRELATOR

**Visualization:** Campaign Topology Graph — Interactive Force Graph + Timeline

**Recommended Type:** `Force Graph` + `Timeline`

**Why:**
- **Analysts:** See how individual attacks cluster into campaigns across time, IPs, and tools
- **Engineers:** Debug similarity thresholds, understand clustering quality
- **Investors:** A beautiful force graph of "hacker campaigns detected" is instantly understandable
- **Differentiation:** Real-time campaign clustering visualization is rare in security products

**Data Sources:**
- `campaign:{id}` — campaign data (Redis)
- `active_campaigns` — active campaign set (Redis)
- Campaign stats: sessions, IPs, sensors, threat level
- Individual sessions within each campaign

**Implementation:**
- Force-directed graph: nodes = attacker IPs, edges = shared campaign membership
- Node size = session count, color = threat level, edge thickness = similarity score
- Timeline slider to see campaigns form over time
- Click a campaign to see member sessions, tools used, targeted sensors
- Animated: new sessions cause nodes to appear/merge as campaigns form

**Priority:** P0 | **Complexity:** High | **Dependencies:** Campaign correlator Redis data | **Risk:** Medium | **Effort:** 4-5 weeks

---

### 8. BEHAVIORAL DNA / ACTOR TRACKING

**Visualization:** Actor Identity Graph — Force Graph + Timeline

**Recommended Type:** `Force Graph` + `Timeline`

**Why:**
- **Analysts:** Track persistent threat actors across sessions, sensors, and time
- **Engineers:** Validate DNA merging logic, debug false positives
- **Differentiation:** Visualizing behavioral biometrics to track hackers across different IPs is advanced

**Data Sources:**
- `BehavioralActor` table (Postgres)
- `dna:actor_sessions:{uuid}` — sessions per actor (Redis)
- `dna:session_actor:{sid}` — actor per session (Redis)
- Cowrie sessions linked to actors

**Implementation:**
- Force graph: actors as central hubs, sessions as spokes, colored by sensor
- Timeline: actor first seen → last seen → session timeline
- Merge visualization: when actors merge, animate the absorption
- HASSH and command hash signatures as identity markers

**Priority:** P2 | **Complexity:** Medium | **Dependencies:** Behavioral DNA Redis data | **Risk:** Low | **Effort:** 3 weeks

---

### 9. FINGERPRINT CORPUS

**Visualization:** Fingerprint Intelligence Dashboard — Heatmap + Force Graph + Sankey

**Recommended Type:** `Live Graph` + `Sankey` + `Force Graph`

**Why:**
- **Analysts:** Explore the corpus of attacker fingerprints (JA3, HASSH, UA, header signatures)
- **Engineers:** Identify new tools targeting the platform
- **Differentiation:** Visualizing a fingerprint corpus in real-time, showing which tools target which attack paths

**Data Sources:**
- `corpus:country_scores` — sorted set of country frequencies
- `corpus:techniques` — sorted set of MITRE technique frequencies
- `corpus:ja3:{ja3}` — JA3 fingerprint sets
- `corpus:hassh:{hassh}` — HASSH fingerprint sets
- `corpus:tool:{tool}` — tool fingerprint sets
- `corpus:total_entries` — global counter
- `fingerprint:recent_events` — live feed

**Implementation:**
- World heatmap: countries of origin for fingerprint events
- Force graph: tools connected to the techniques they use, connected to the paths they target
- Sankey: Traffic Source → Tool → Target Path → Technique
- Live counter: fingerprints collected per minute

**Priority:** P1 | **Complexity:** Medium | **Dependencies:** Existing corpus API endpoints | **Risk:** Low | **Effort:** 2-3 weeks

---

### 10. LLM HONEYPOT

**Visualization:** LLM Honeypot Theater — Timeline + Sequence Diagram

**Recommended Type:** `Timeline` + `Sequence Diagram`

**Why:**
- **Analysts:** Review attacker conversations with the fake AI, understand injection techniques
- **Engineers:** Monitor LLM budget consumption, detect new injection patterns
- **Investors:** See hackers trying to jailbreak a "real" AI — and getting fed fake credentials
- **Differentiation:** Visualizing LLM honeypot interactions in real-time is novel

**Implementation:**
- Chat-bubble interface showing attacker messages and fake AI responses
- Overlay showing detected injection technique, confidence score, MITRE ATLAS mapping
- Timeline of all sessions, color-coded by threat level
- Real-time notification when sandbox entry is triggered
- Budget gauge showing daily LLM usage

**Priority:** P1 | **Complexity:** Low | **Dependencies:** `llm_honeypot:{ip}:{ts}` Redis data | **Risk:** Low | **Effort:** 2 weeks

---

### 11. LLM FIREWALL

**Visualization:** LLM Firewall Dashboard — Pipeline + Live Graph + Sankey

**Recommended Type:** `Pipeline` + `Live Graph` + `Sankey`

**Why:**
- **Users:** See how many prompts are blocked/flagged/allowed in real-time
- **Analysts:** Investigate blocked prompts, tune detection rules
- **Engineers:** Monitor rate limiting, LLM provider availability
- **Investors:** Product visualization for enterprise AI security
- **Differentiation:** Three-layer detection visualized as an animated pipeline

**Data Sources:**
- `llmfw:stats:{key}:{day}` — daily stats hash
- `llmfw:events:{key}` — event list
- `llmfw:cat:{key}:{day}` — category breakdown
- `llmfw:blocks:{key}` — blocked prompt list

**Implementation:**
- Pipeline: Request → API Key Auth → Rate Limit → Layer 1 (Regex) → Layer 2 (LLM) → Layer 3 (Heuristic) → Allow/Block/Flag
- Each layer shows pass/fail counts with animation
- Sankey of prompt categories: injection, jailbreak, encoding, etc.
- Live graph: requests per minute, blocked per minute

**Priority:** P1 | **Complexity:** Medium | **Dependencies:** Existing `llmfw:*` Redis data | **Risk:** Low | **Effort:** 3 weeks

---

### 12. BGP MONITOR

**Visualization:** BGP Route Map — Interactive Topology Graph

**Recommended Type:** `Interactive Topology` + `Timeline`

**Why:**
- **Analysts:** See route hijacks in real-time on a global routing topology
- **Engineers:** Debug BGP route state engine
- **Investors:** "Internet routing hijack detected" is powerful in a demo
- **Differentiation:** Real-time BGP hijack visualization with ASN topology

**Data Sources:**
- `bgp_monitor:route_state` — known routes (Redis)
- `bgp_monitor:alerts` — anomaly alerts (Redis)
- `bgp_monitor:route_changes` — time-series of changes (Redis)
- `bgp_monitor:hijacks:active:{hash}` — active hijacks (Redis)

**Implementation:**
- Graph: AS nodes connected by BGP peer edges
- Highlighted paths show monitored prefixes
- Animated alerts when a route changes or hijack is detected
- Timeline slider to see route state evolution
- Color: normal (green), new AS in path (yellow), origin change (orange), hijack (red)

**Priority:** P1 | **Complexity:** High | **Dependencies:** BGP monitor Redis data | **Risk:** Medium | **Effort:** 5-6 weeks

---

### 13. ASN INTELLIGENCE

**Visualization:** ASN World Map — Heatmap + Force Graph

**Recommended Type:** `Interactive Topology` + `Heatmap`

**Why:**
- **Analysts:** See attack origins by ASN, identify malicious hosting providers
- **Engineers:** Monitor enrichment cache hit rates, abuse report effectiveness
- **Differentiation:** Global ASN attack visualization with enrichment overlays

**Data Sources:**
- `asn:leaderboard:total` — all-time ASN hit counts
- `asn:leaderboard:24h` — rolling 24h counts
- `asn:countries` — country distribution
- `asn:hosting_providers` — hosting provider distribution
- `asn:high_risk` — high-risk ASNs
- IP enrichment cache (ASN, hosting, VPN/Tor, risk score)

**Implementation:**
- World map: countries colored by attack volume, click to drill into ASNs
- Force graph: ASNs connected by shared attack patterns
- Sidebar: top 10 ASNs with live counters
- Enrichment overlay: hover an IP to see its enrichment data (hosting, VPN, abuse score)

**Priority:** P2 | **Complexity:** Medium | **Dependencies:** ASN intelligence Redis data | **Risk:** Low | **Effort:** 3 weeks

---

### 14. CREDENTIAL PROPAGATION

**Visualization:** Lure Network Graph — Interactive Topology + Timeline

**Recommended Type:** `Force Graph` + `Timeline`

**Why:**
- **Analysts:** Track planted credentials across platforms, see when they're used
- **Engineers:** Monitor lure rotation, health of propagation network
- **Differentiation:** Visualizing fake credential propagation and trigger events in real-time

**Data Sources:**
- `lure:{lid}` — lure details (Redis)
- `lures:active` — active lure set (Redis)
- `lures:triggered` — triggered lure set (Redis)
- Lure stats: active count, triggered count, trigger history

**Implementation:**
- Force graph: lures as nodes connected to the platforms they were planted on
- Lure health: green (active), yellow (aging), red (triggered)
- Animated pulse when a lure is triggered
- Timeline: when each lure was planted, when it was triggered

**Priority:** P2 | **Complexity:** Low | **Dependencies:** Credential propagation Redis data | **Risk:** Low | **Effort:** 2 weeks

---

### 15. SUPPLY CHAIN CANARY

**Visualization:** Supply Chain Beacon Map — Interactive Topology + Timeline

**Recommended Type:** `Force Graph` + `Timeline`

**Why:**
- **Analysts:** Track canary tokens across packages, see beacon hits
- **Engineers:** Monitor beacon registration, detect evasion
- **Differentiation:** Visualizing supply chain security beacons across the software supply chain

**Data Sources:**
- `supply_chain_canary:{token}` — token registry
- `canaries:active` — active canaries
- `canaries:triggered` — triggered canaries
- Beacon hit data (env hashes, IPs)

**Implementation:**
- Graph: packages as nodes, edges show where tokens were injected
- Beacon hits animate as pulses from token to beacon server
- Timeline: registration date → first hit → subsequent hits
- Environment hash breakdown

**Priority:** P2 | **Complexity:** Low | **Dependencies:** Supply-chain canary Redis data | **Risk:** Low | **Effort:** 2 weeks

---

### 16. BREACH MONITOR

**Visualization:** Breach Intelligence Dashboard — Pipeline + Timeline + Sankey

**Recommended Type:** `Pipeline` + `Timeline` + `Sankey`

**Why:**
- **Analysts:** See data leaks detected in real-time across paste sites, GitHub, and dark web
- **Engineers:** Monitor collector health, correlation engine performance
- **Investors:** "Leaked credentials detected before they're used" is a powerful narrative
- **Differentiation:** Visualizing the breach intelligence pipeline end-to-end

**Data Sources:**
- Breach-monitor internal API (`/api/breach/status`, `/api/breach/findings`)
- Collector health data
- Correlation intelligence
- Alert routing decisions

**Implementation:**
- Pipeline: Sources (Pastebin, GitHub, HIBP) → Collectors → NLP Analysis → Correlation Engine → Alerts
- Timeline: findings over time, colored by severity
- Sankey: Source → Type → Severity
- Collector health status indicators

**Priority:** P1 | **Complexity:** Medium | **Dependencies:** Breach-monitor API proxy | **Risk:** Low | **Effort:** 3 weeks

---

### 17. DETONATION ENGINE (URL SANDBOX)

**Visualization:** Detonation Pipeline — Pipeline + Timeline

**Recommended Type:** `Pipeline` + `Timeline`

**Why:**
- **Analysts:** Watch URLs being detonated in the sandbox, see redirect chains and threats found
- **Engineers:** Monitor queue depth, worker health, detonation results
- **Investors:** "URL detonation with full browser isolation" is visually impressive

**Data Sources:**
- `detonate:job:{job_id}` — job results (Redis)
- `detonate:queue` — job queue
- Detonation threat assessment results
- Cross-referencing results (campaign, fingerprint)

**Implementation:**
- Pipeline: URL → Validation → Queue → Worker → Container → Analysis → Cross-Reference → Report
- Live view of queued, running, and completed detonations
- Individual detonation report with redirect chain graph, threat signals, screenshots
- Timeline of recent detonations with verdicts

**Priority:** P2 | **Complexity:** Medium | **Dependencies:** Detonate API endpoints | **Risk:** Low | **Effort:** 3 weeks

---

### 18. HALL OF MIRRORS

**Visualization:** Mirror Depth Visualization — State Machine + Timeline

**Recommended Type:** `State Machine` + `Timeline`

**Why:**
- **Analysts:** See how deep attackers penetrate the mirror maze
- **Engineers:** Tune mirror depth thresholds, add new layers
- **Differentiation:** Visualizing a psychological deception maze in real-time is unique

**Data Sources:**
- `mirror_depth:{ip}` — current depth per attacker
- `mirror:{ip}:{session}` — mirror session data
- Immutable log entries for mirror events

**Implementation:**
- State machine: each mirror layer is a "room" the attacker navigates through
- Animated: attacker enters → finds fake data → goes deeper → hits threshold → blocked/altered
- Timeline: path through mirror layers with timestamps

**Priority:** P3 | **Complexity:** Low | **Dependencies:** Hall of Mirrors Redis data | **Risk:** Low | **Effort:** 1-2 weeks

---

### 19. NOTIFICATION ROUTING

**Visualization:** Alert Routing Topology — Sankey + Pipeline

**Recommended Type:** `Sankey` + `Pipeline`

**Why:**
- **Analysts:** See which alerts went where, verify notification delivery
- **Engineers:** Debug notification failures, tune dedup windows
- **Investors:** Demonstrate multi-channel alerting infrastructure

**Data Sources:**
- Immutable log event types and counts
- Alert dedup Redis keys (for volume estimation)
- Known alert types and their configured routing

**Implementation:**
- Sankey: Event Types → Channels (Telegram, Discord, Email, Webhook) → Success/Failure
- Live counters for each channel
- Dedup effectiveness: total events → unique alerts
- Histogram of alert volume by type

**Priority:** P3 | **Complexity:** Low | **Dependencies:** Immutable log data | **Risk:** Low | **Effort:** 1 week

---

### 20. IMMUTABLE LOG

**Visualization:** Hash Chain Visualizer — Pipeline + Timeline

**Recommended Type:** `Pipeline` + `Timeline`

**Why:**
- **Analysts:** Verify chain integrity, audit events
- **Engineers:** Debug chain continuity
- **Investors:** "Tamper-proof audit trail" visualized as an unbreakable chain
- **Differentiation:** A visual hash chain that animates as new entries are added

**Data Sources:**
- `ImmutableLog` table (Postgres)
- Chain verification results

**Implementation:**
- Animated chain: blocks added in real-time, with previous_hash connections
- Hover for entry details
- Verification overlay: green checkmarks for valid chains
- Time scrubber to walk through history

**Priority:** P1 | **Complexity:** Low | **Dependencies:** ImmutableLog model | **Risk:** Low | **Effort:** 1-2 weeks

---

### 21. ALERT DEDUP / RATE LIMITING

**Visualization:** Rate-Limiting Dashboard — Live Graph + Heatmap

**Recommended Type:** `Live Graph` + `Heatmap`

**Why:**
- **Engineers:** See which rate limits are being hit, tune thresholds
- **Analysts:** Identify IPs triggering many different rate limits
- **Differentiation:** Internal rate-limiting infrastructure visualized in real-time

**Data Sources:**
- 15+ rate-limit Redis keys across subsystems (llm, link_checker, canary, gateway, etc.)
- Rate-limit hit counters
- Flask-Limiter data

**Implementation:**
- Grid of gauges, one per rate limit type
- Top-N IPs hitting each rate limit
- Heatmap: time × rate-limit type, colored by hit density
- Alerts when any rate limit exceeds 80% of its threshold

**Priority:** P3 | **Complexity:** Low | **Dependencies:** Redis rate-limit key scan | **Risk:** Low | **Effort:** 1 week

---

### 22. SESSION DNA / USER BEHAVIOR

**Visualization:** Behavioral Baseline Dashboard — Timeline + Live Graph

**Recommended Type:** `Timeline` + `Live Graph`

**Why:**
- **Users:** See their own behavioral baseline and anomaly alerts
- **Analysts:** Monitor all user baselines for compromised accounts
- **Differentiation:** Visualizing user behavioral biometrics for account security

**Data Sources:**
- `SessionDNA` table (Postgres)
- `DNAAlert` table (Postgres)
- Deviation scores
- Discord notification history

**Implementation:**
- Gauge: current deviation score vs baseline
- Timeline: session activity with anomaly markers
- Radar chart: deviation dimensions (speed, endpoints, hours, patterns)
- Per-user baseline profile card

**Priority:** P2 | **Complexity:** Medium | **Dependencies:** SessionDNA API endpoints | **Risk:** Low | **Effort:** 2-3 weeks

---

### 23. SYSTEM HEALTH / PLATFORM STATUS

**Visualization:** Platform Status Dashboard — Live Graph + Component Diagram

**Recommended Type:** `Component Diagram` + `Live Graph`

**Why:**
- **Engineers:** Monitor all pipeline health in one place
- **Investors:** "Platform health" for demos and uptime confidence
- **Differentiation:** Animated component health with live data flow indicators

**Data Sources:**
- `/api/health/detailed` — pipeline health
- `/api/health` — basic health
- `/api/platform/health` — platform health
- Redis connectivity checks
- Worker/engine heartbeat data

**Implementation:**
- Component diagram: all subsystems as connected nodes, colored by health
- Live pulse: green pulsing dots for healthy, yellow for degraded, red for down
- Drill-down: click a subsystem for detailed metrics
- Uptime timeline

**Priority:** P1 | **Complexity:** Low | **Dependencies:** Existing health endpoints | **Risk:** Low | **Effort:** 1-2 weeks

---

### 24. UNIFIED THREAT DASHBOARD

**Visualization:** Single-Pane-of-Glass Threat Dashboard — Composite

**Recommended Type:** `Live Graph` (all types composited)

**Why:**
- **Analysts:** See everything at once
- **CISOs:** "Executive dashboard" showing current threat posture
- **Differentiation:** A real-time security operations center view

**Data Sources:**
All existing APIs aggregated into a single view

**Implementation:**
- Top bar: threat counters (active sessions, blocked IPs, sandboxed attackers, active campaigns, canary hits, BGP alerts, breach findings)
- Left: world map with live attack origins
- Center: force graph of active campaigns with connected attacker IPs
- Right: live event feed from all subsystems
- Bottom: timeline chart of events per subsystem over last 24h

**Priority:** P0 | **Complexity:** High | **Dependencies:** All other visualizations | **Risk:** Low | **Effort:** 6-8 weeks

---

## Visualization Language: Design System

### Color Palette
| Role | Color | Hex | Usage |
|------|-------|-----|-------|
| Safe/Pass | Green | `#00ff88` | PoW pass, allow verdict, healthy |
| Warning | Yellow | `#ffd700` | Summarize, suspicious, medium threat |
| Danger | Orange | `#ff6600` | High threat, flag, rate-limited |
| Critical | Red | `#ff0044` | Block, critical threat, emergency |
| Info/Cold | Blue | `#0088ff` | Information, passive observe |
| Deception | Purple | `#8833ff` | Canary traps, honeytokens, sandbox |
| Intelligence | Teal | `#00ffcc` | AI analysis, enrichment |
| Background | Dark | `#0a0a0f` | Canvas background |
| Surface | Dark | `#141420` | Card/surface background |
| Border | Dim | `#2a2a3a` | Subtle borders |
| Text | Light | `#e0e0f0` | Primary text |
| Text Dim | Gray | `#666680` | Secondary/muted text |

### Animation Language
| Animation | Duration | Meaning |
|-----------|----------|---------|
| Pulse | 1s cycle | Active/live data |
| Flow | 2-4s path | Data movement through pipeline |
| Fade | 0.3s | Transitions, status changes |
| Explode | 0.5s | Alert, trigger event |
| Orbit | 3s cycle | Connected/related |
| Gravity | 1-3s | Nodes clustering into groups |
| Scatter | 0.5s | Disconnection, isolation |
| Scan | 2s sweep | Analysis in progress |
| Pulse-Red | 0.5s flash | Critical event |
| March | 1s step | Sequential processing |

### Interaction Patterns
| Gesture | Action |
|---------|--------|
| Hover | Tooltip with detail |
| Click | Drill into detail |
| Drag | Reposition graph nodes |
| Scroll | Timeline scrub |
| Pinch | Zoom (touch) |
| Ctrl+Scroll | Zoom (desktop) |
| Select + Drag | Marquee select |
| Double-click | Expand/collapse |

### Layout Conventions
- **Pipelines**: Left-to-right flow
- **Timelines**: Top-to-bottom (newest at top)
- **Force graphs**: Center = most connected, periphery = isolated
- **Sankey**: Top-to-bottom flow
- **Maps**: Geographic orientation
- **State machines**: Ordered left-to-right, cycles return left

---

## Implementation Roadmap

### Phase 1: Foundation (Weeks 1-4)
**Focus:** Reuse existing SSE/streaming infrastructure, build the core observability pipeline

| Item | Priority | Effort |
|------|----------|--------|
| Live Event Bus (Redis Stream → SSE) | P0 | 1 week |
| Unified Threat Dashboard (P0) | P0 | 3 weeks |
| Attractor Sandbox Theater (P0) | P0 | 4 weeks |

### Phase 2: Core Intelligence (Weeks 5-8)
**Focus:** Visualize the primary intelligence pipelines

| Item | Priority | Effort |
|------|----------|--------|
| Cowrie Pipeline (P0) | P0 | 5 weeks |
| Campaign Force Graph (P0) | P0 | 4 weeks |
| Immutable Log Chain (P1) | P1 | 1 week |
| System Health Dashboard (P1) | P1 | 1 week |

### Phase 3: Security Controls (Weeks 9-12)
**Focus:** Security tool visualizations

| Item | Priority | Effort |
|------|----------|--------|
| Gateway Sankey (P1) | P1 | 2 weeks |
| Fingerprint Intelligence (P1) | P1 | 2 weeks |
| LLM Honeypot Theater (P1) | P1 | 2 weeks |
| LLM Firewall Pipeline (P1) | P1 | 3 weeks |
| Breach Monitor Dashboard (P1) | P1 | 3 weeks |

### Phase 4: Advanced Intelligence (Weeks 13-16)
**Focus:** Network and infrastructure visualizations

| Item | Priority | Effort |
|------|----------|--------|
| BGP Route Topology (P1) | P1 | 5 weeks |
| ASN World Map (P2) | P2 | 3 weeks |
| CRYSTAL Decision Tree (P2) | P2 | 2 weeks |
| Actor Identity Graph (P2) | P2 | 3 weeks |

### Phase 5: Deception & Polish (Weeks 17-20)
**Focus:** Deception subsystems and refinement

| Item | Priority | Effort |
|------|----------|--------|
| Lure Network Graph (P2) | P2 | 2 weeks |
| Supply Chain Map (P2) | P2 | 2 weeks |
| Session DNA Dashboard (P2) | P2 | 2 weeks |
| Detonation Pipeline (P2) | P2 | 3 weeks |
| TTY Replay Enhancement (P1) | P1 | 1 week |
| Hall of Mirrors (P3) | P3 | 1 week |
| Rate-Limiting Dashboard (P3) | P3 | 1 week |
| Alert Routing Sankey (P3) | P3 | 1 week |

---

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| SSE performance with high-volume streams | Medium | High | Throttle to 1-2 events/sec per visualization, aggregate before sending |
| Redis load from real-time polling | Medium | Medium | Use Redis Streams (consumer groups), not polling; TTL caches aggressively |
| Vue bundle size with D3/force-graph libs | Low | Medium | Dynamic imports, lazy-load per route, code-split vis libraries |
| WebSocket connection limits per user | Low | Low | SSE over HTTP/2, single multiplexed stream per session |
| Browser performance with large force graphs | Medium | Medium | Canvas renderer for graphs >500 nodes, GPU-accelerated |
| Engineer bandwidth for 5-phase plan | High | High | Deliver critical P0s first, defer P3s, iterate based on user feedback |

---

## Technology Recommendations

### Visualization Libraries
- **D3.js (v7)**: Force-directed graphs, Sankey, heatmaps, custom SVG
- **Three.js / React Three Fiber**: 3D BGP topology, particle effects, immersive graphs
- **Cytoscape.js**: Graph visualization with performance at scale
- **Chart.js / uPlot**: Time-series, gauges, sparklines (lighter than ECharts)
- **Leaflet / Mapbox GL**: Geographic heatmaps
- **xterm.js**: Terminal replay
- **Anime.js / GSAP**: Animation compositing

### Frontend Architecture
- Vue 3 composables for each visualization type
- SSE consumer composable that parses events and dispatches to reactive stores
- Canvas-based rendering for any graph exceeding 500 elements
- Virtualized list for event feeds (vue-virtual-scroller)
- Shared animation controller composable for pause/resume/speed

### Backend Additions
- **Redis Streams** for the live event bus (replaces ad-hoc LPUSH/LRANGE patterns)
- **SSE endpoint** `/api/live/events` — multiplexed stream with event type filtering
- **No new DB tables** — all visualizations use existing Redis/Postgres data

---

## Conclusion

WraithWall has 24 distinct subsystems that should become visual. The recommended approach prioritizes 4 P0 visualizations (Unified Dashboard, Sandbox Theater, Cowrie Pipeline, Campaign Force Graph) that together create the "wow factor" needed for investor demos and analyst daily use, while the P1-P3 items fill out the complete observability picture.

The total engineering effort is approximately 20 person-weeks for all 24 visualizations. Phase 1 (Foundation) delivers the highest-impact items in 4 weeks.

The key insight from this reverse engineering is that WraithWall's backend is already extremely rich — the data exists, the pipelines exist, the events exist. The visualization work is primarily about surfacing what's already happening, not inventing new data sources.
