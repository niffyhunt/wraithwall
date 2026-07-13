# Metrics methodology

How WraithWall performance numbers are defined, measured, and scoped. **Do not compare subsystems using a single headline rate** — each layer has different noise characteristics.

## Scope matrix

| Layer | Signal quality | FP meaning |
| ----- | -------------- | ---------- |
| **Cowrie honeypot** | No legitimate user traffic — every session is adversarial or probe | "False positive" = analyst labels session `false_positive` after review, not "wrong traffic" |
| **Breach monitor** | Paste/GitHub/HIBP correlation — mixed signal | FP = finding dismissed after cross-source validation |
| **Campaign / CRYSTAL** | Multi-engine scoring + suppression | FP = `recalibration.py` precision on analyst-labeled sessions |
| **Public landing counters** | Aggregated Redis (`/api/public/stats`) | Not a precision metric — volume telemetry only |

---

## 1. Detection latency

### Breach monitor (credential / paste exposure)

**Definition:** Wall-clock time from source artifact appearance to first operator alert (Telegram/Discord/email).

**Measurement:**

1. Worker ingests paste/GitHub/HIBP hit (`breach-monitor/` scanners, main app `run_breach_scan` every 6h + paste monitor 2h per `scheduler_graph.json`).
2. Finding persisted with `timestamp` in SQLite / notification payload.
3. Latency = `alert_sent_at - source_first_seen_at`.

**Typical production window:** Sub-minute to low-minute for Telegram bot path when worker is active and source is in monitored set. **Not** the same as enterprise "mean time to detect" across all breach types globally.

### Cowrie honeypot (SSH session intelligence)

**Definition:** Time from `cowrie.session.connect` event written to `cowrie.json` → processed by `cowrie_intelligence.py` watcher → high-risk command or session-close alert enqueued.

**Measurement:**

1. Event `timestamp` in the honeypot JSON log on the remote VPS.
2. Watcher tail position tracked in Redis.
3. Alert queue drain in `_alert_worker` (Telegram/Discord).

**Order of magnitude:** Sub-second to tens of seconds for log tail + queue — dominated by session duration and command count, not batch ETL.

### What “&lt;30 seconds” referred to (historical README claim)

Operator-reported **breach-monitor alert path** under 30-day production monitoring: time from automated ingest to Telegram delivery for confirmed credential-format matches. **Recompute before citing publicly:**

```bash
# Export findings with timestamps from breach-monitor DB / alert logs
# Latency = alert_timestamp - finding_detected_timestamp
```

---

## 2. False-positive rate

### Cowrie / CRYSTAL (scoring layer)

**Definition:** Among analyst-labeled sessions, share marked `false_positive` vs `true_positive`.

**Measurement** (`recalibration.py`):

- Labels stored per session → `label` ∈ `{true_positive, false_positive, benign}` via `/api/cowrie/label` (admin).
- Tracked in Redis for recalibration access.
- Precision per signal: `tp / (tp + fp)` from `load_labeled_sessions()`.
- **Minimum sample:** 200 labeled sessions before recalibration proposals.

**Formula:**

```
FP_rate = false_positive_labels / (true_positive_labels + false_positive_labels)
```

**Important:** Honeypot raw traffic is not "noisy" like SIEM — FP here means **wrong alert classification**, not benign user mistaken for attacker.

### Breach monitor

FP = findings downgraded or discarded after:

- Cross-source corroboration (same secret not repeated across sources)
- AI enrichment marked low-confidence
- Operator manual dismiss

Track in breach-monitor DB / audit trail — not merged into Cowrie FP rate.

### What “&lt;8%” referred to (historical README claim)

Scoped to **labeled Cowrie + CRYSTAL alert decisions** over a 30-day window, not whole-platform traffic. Recompute:

```bash
TESTING=1 python3 -c "from recalibration import load_labeled_sessions; ..."
```

Do **not** cite 8% for honeypot byte-level signal — that layer has no legitimate traffic.

---

## 3. API response time

**Definition:** P50/P95 latency for `/api/public/stats` and authenticated tool endpoints.

**Measurement:** Reverse-proxy access logs or `curl -w '%{time_total}'` from edge. Redis-backed public stats typically &lt;50ms when Redis warm.

---

## 4. Cost per finding

**Definition:** Total infra spend in window ÷ actionable findings delivered.

**Numerator:** VPS + DB + Redis + API spend (Paystack/Railway/hosting invoices) for the period.

**Denominator:** Count of:

- Breach monitor confirmed alerts
- Cowrie sessions with `intelligence.threat_score >= threshold` and alert sent
- Canary triggers with webhook delivery

**Historical “$0.02” claim:** Operator-reported 30-day ratio using self-hosted stack (no commercial SIEM seat licenses). Recompute from actual billing before republishing.

---

## 5. Uptime

**Measurement:** External HTTP check on `https://wraithwall.online/api/public/stats` or `/api/platform/health` (authenticated). Service restart events tracked in system journal.

---

## 6. Public dashboard numbers (not precision metrics)

`/api/public/stats` aggregates:

```
total_threats = sessions + campaigns + active_lures + llm_attempts
```

See `public_api.py`. These are **volume counters** for the landing page — not FP rate or detection SLA.

---

## Publishing rules

1. Always state **which subsystem** and **which window** (e.g. "Cowrie labeled sessions, 90 days").
2. Never blend honeypot volume with breach-monitor FP.
3. Run `recalibration.py` report before updating any FP headline.
4. Archive raw calculation inputs alongside the claim (CSV export, date range, label counts).

---

*Maintainer-confirmed: MIT license yes · audit docs stay internal · disclosure 72h ack · portfolio at wraithwall.online/niffy*