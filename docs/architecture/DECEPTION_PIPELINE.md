# Deception Pipeline — Telemetry and Data Flow

**Date:** 2026-07-09
**Status:** Proposed Architecture (Pre-Implementation)

This document defines the event flow, correlation paths, and integration points connecting all 7 layers of the deception architecture.

---

## 1. SYSTEM OVERVIEW

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           DECEPTION GRID                                        │
│                                                                                  │
│  ┌─────────────────────┐          ┌─────────────────────────────┐               │
│  │  COWRIE VPS          │          │  MAIN SERVER                 │               │
│  │  COWRIE_VPS_IP        │          │  SERVER_IP              │               │
│  │                      │          │                             │               │
│  │  ┌─────────────────┐ │          │  ┌─────────────────────────┐ │               │
│  │  │ Cowrie Honeypot  │ │  logs   │  │ WraithWall Flask App    │ │               │
│  │  │ SSH:2222         │─┼────────┼─>│ cowrie_intelligence.py   │ │               │
│  │  │ Telnet:2223      │ │  JSON   │  │ campaign_correlator.py  │ │               │
│  │  └────────┬────────┘ │  +      │  │ fingerprint_corpus.py   │ │               │
│  │           │          │  Redis  │  │ asn_intelligence.py     │ │               │
│  │  ┌────────┴────────┐ │  pubsub │  │ bgp_monitor.py          │ │               │
│  │  │ Cowrie Analyzer  │ │         │  └───────────┬─────────────┘ │               │
│  │  │ Redis:6379       │ │         │              │               │               │
│  │  │ MongoDB:27017    │ │         │  ┌───────────┴─────────────┐ │               │
│  │  │ Worker:VT scan   │ │         │  │ Deception Modules       │ │               │
│  │  │ Dashboard:5555   │ │         │  │ canary_service.py       │ │               │
│  │  └────────┬────────┘ │         │  │ supply_chain_canary.py  │ │               │
│  │           │          │         │  │ credential_propagation  │ │               │
│  │  ┌────────┴────────┐ │         │  │ reverse_canary (main)   │ │               │
│  │  │ Shipper          │ │         │  │ dns_canary (main)       │ │               │
│  │  │ JSON→ProdRedis   │─┼────────┼─>│ honey_token_check       │ │               │
│  │  └─────────────────┘ │  list   │  └───────────┬─────────────┘ │               │
│  └─────────────────────┘          │              │               │               │
│                                    │  ┌───────────┴─────────────┐ │               │
│  ┌─────────────────────┐          │  │ DECEPTION EVENT BUS     │ │               │
│  │ COWRIE VPS NGINX     │          │  │ deception:events (Redis) │ │               │
│  │ Fake .env, backup    │─ HTTP ──┼─>│ Immutable Audit Log     │ │               │
│  │ Fake admin panels    │          │  │ (hash chain)             │ │               │
│  └─────────────────────┘          │  └───────────┬─────────────┘ │               │
│                                    │              │               │               │
│  ┌─────────────────────┐          │  ┌───────────┴─────────────┐ │               │
│  │ ATTACKER             │          │  │ UNIFIED ALERT ROUTER   │ │               │
│  │ SSH→Cowrie:2222      │──HTTP───┼─>│ Telegram + Discord     │ │               │
│  │ Curl→VPS Nginx:443  │          │  │ + Email                 │ │               │
│  │ DNS queries          │          │  └─────────────────────────┘ │               │
│  └─────────────────────┘          └─────────────────────────────┘               │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. EVENT SCHEMA

All deception events follow a unified schema for correlation.

```json
{
  "event_id": "evt_2f8a1c3e9b0d4f5a6c7b8d9e0f1a2b3c",
  "timestamp": 1751996805.123,
  "source": "cowrie_honeyfs",
  "bait_id": "bait_c_05_ssh_key_v2",
  "bait_type": "credential",
  "bait_layer": 2,
  "trigger_type": "file_read",
  "attacker_ip": "185.220.101.45",
  "attacker_metadata": {
    "hassh": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d",
    "hasshAlgorithms": "curve25519-sha256,...",
    "asn": 12345,
    "asn_org": "Example Hosting",
    "country": "DE",
    "is_tor": true,
    "threat_score": 72
  },
  "context": {
    "session_id": "cowrie-session-abc123",
    "file_path": "/root/.ssh/id_rsa",
    "command": "cat /root/.ssh/id_rsa",
    "credential_type": "ssh_private_key",
    "credential_hash": "sha256$<hash>"
  }
}
```

---

## 3. EVENT GENERATORS (Sources)

### 3.1 Cowrie Session Events

| Trigger | Event Source | Fields |
|---------|-------------|--------|
| SSH connection | `cowrie_intelligence.py` | attacker_ip, session_id, HASSH, protocol |
| Successful login | `cowrie_intelligence.py` | attacker_ip, username, password, lure_match |
| Command executed | `cowrie_intelligence.py` | attacker_ip, command, session_id, timing |
| File downloaded | `cowrie_intelligence.py` | attacker_ip, url, sha256, session_id |
| Session closed | `cowrie_intelligence.py` | attacker_ip, session_id, duration, commands[] |

### 3.2 Honeyfs File Access Events

| Trigger | Detection Method | Notes |
|---------|-----------------|-------|
| File read via `cat` | Cowrie command log (string matching) | Standard Cowrie behavior logging |
| File copied via `scp` | No direct detection | Beacon in file may trigger when opened at destination |
| File exfiltrated | No direct detection | Beacon at destination is only hope |
| Directory listing | Cowrie command log | `ls -la` shows file exists, no beacon trigger |

**Key limitation:** Cowrie logs commands but not file read results. We cannot distinguish "attacker ran `ls`" from "attacker read the file content." Beacons (1x1 GIF, reverse canary URLs) are the primary exfil detection mechanism.

### 3.3 Canary Service Events

| Trigger | Event Source | Detection |
|---------|-------------|-----------|
| `/c/<token>` accessed | `canary_service.py` | HTTP request to main server |
| Beacon rendered | `canary_service.py` | Same as above (GIF returned) |
| Redirect followed | `canary_service.py` | 302 redirect, attacker browser follows |

### 3.4 Reverse Canary Events

| Trigger | Event Source | Detection |
|---------|-------------|-----------|
| `/hidden/<token>` accessed | `main.py` | HTTP request + full forensic capture |
| Competing attacker narrative served | `main.py` | Psychological trap + IP auto-block |

### 3.5 Credential Lure Events

| Trigger | Event Source | Detection |
|---------|-------------|-----------|
| Credential posted to platform | `credential_propagation.py` | Outbound API call |
| Credential used against Cowrie | `cowrie_intelligence.py` | Login match against lure database |
| Credential used against main server | `honey_token_check()` | HTTP request with matching credential |

### 3.6 DNS Canary Events

| Trigger | Event Source | Detection |
|---------|-------------|-----------|
| DNS query for canary domain | `check_canarytokens_alerts()` | canarytokens.org polling |
| DNS query for `.internal.example.com` | Custom DNS server (future) | DNS log analysis |

---

## 4. EVENT CONSUMERS (Sinks)

### 4.1 Campaign Correlator (`campaign_correlator.py`)

**Current:** Only ingests Cowrie sessions via `ingest_session()`.
**Target:** Ingest all `DeceptionEvents` with `trigger_type` in ('login_attempt', 'credential_use', 'pivot').

**Integration:**
```python
def ingest_deception_event(event: DeceptionEvent):
    """Feed non-Cowrie deception events into campaign correlation."""
    key = f"deception:{event.attacker_ip}:events"
    redis.rpush(key, json.dumps(asdict(event)))
    redis.expire(key, 86400)  # 24h window
    
    # Check for pivot detection
    event_types = redis.lrange(key, 0, -1)
    unique_sources = set(json.loads(e)['source'] for e in event_types)
    if len(unique_sources) >= 2:
        dispatch_alert(event, 'PIVOT', severity='HIGH')
```

### 4.2 Fingerprint Corpus (`fingerprint_corpus.py`)

**Current:** Collects JA3, HASSH, User-Agent from HTTP requests and Cowrie sessions.
**Target:** Cross-reference fingerprint data against event triggers.

**Integration:** Already functional — `fingerprint_corpus.py` is integrated into `main.py`'s `before_request` middleware. All HTTP-based deception triggers (canary tokens, reverse canaries, fake API endpoints) will automatically be fingerprinted.

### 4.3 ASN Intelligence (`asn_intelligence.py`)

**Current:** Enriches IPs with ASN, hosting/VPN/Tor detection, risk scoring.
**Target:** Called by every deception event during enrichment.

**Integration:** Already functional for canary service triggers (`_enrich_and_alert()` in `canary_service.py`). Extend to all event types in the unified alert router.

### 4.4 Immutable Audit Log

**Current:** Logs canary events, reverse canary events, honey token events.
**Target:** Log every `DeceptionEvent` to the hash chain.

**Integration:**
```python
def log_deception_event(event: DeceptionEvent):
    log_audit(
        event_type=f"deception_{event.trigger_type}",
        data={
            'event_id': event.event_id,
            'bait_id': event.bait_id,
            'attacker_ip': event.attacker_ip,
            'severity': event.severity,
            'context': event.context
        }
    )
```

### 4.5 Unified Alert Router (New)

**Input:** DeceptionEvent + severity level.
**Output:** Formatted alerts to Telegram, Discord, Email.

**Routing rules:**
| Severity | Channels | Example |
|----------|----------|---------|
| INFO | Telegram (optional channel) | Honeyfs file beacon triggered |
| LOW | Telegram | Credential lure posted to Pastebin |
| MEDIUM | Telegram + Discord | Credential lure used, reverse canary hit |
| HIGH | Telegram + Discord + Email | Pivot detected, campaign confirmed |
| CRITICAL | Telegram + Discord + Email + SMS (future) | Multiple pivots, active exploitation |

---

## 5. CORRELATION PIPELINE

```
                    ┌─────────────────────┐
                    │  RAW EVENTS          │
                    │  (Redis:deception:   │
                    │   events list)       │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  STAGE 1: DEDUP     │
                    │  Per (ip, bait_type) │
                    │  300s dedup window   │
                    └──────────┬──────────┘
                               │
                    ┌──────────┴──────────┐
                    │                     │
                    ▼                     ▼
        ┌──────────────────┐   ┌──────────────────┐
        │ STAGE 2: ENRICH  │   │ STAGE 2: CLASSIFY│
        │ ASN + Geo + DNS  │   │ Severity + Type  │
        │ + Cowrie history │   │ + Layer mapping  │
        └────────┬─────────┘   └────────┬─────────┘
                 │                      │
                 └──────────┬───────────┘
                            │
                            ▼
                    ┌─────────────────────┐
                    │  STAGE 3: CORRELATE  │
                    │  Cross-layer pivot?  │
                    │  Campaign match?     │
                    │  Actor DNA match?    │
                    └──────────┬──────────┘
                               │
                    ┌──────────┴──────────┐
                    │                     │
                    ▼                     ▼
        ┌──────────────────┐   ┌──────────────────┐
        │ STAGE 4: ALERT   │   │ STAGE 4: STORE   │
        │ Unified Router   │   │ Immutable Log    │
        │ + Dedup check    │   │ + Redis TTL      │
        └──────────────────┘   └──────────────────┘
```

---

## 6. INTEGRATION POINTS WITH EXISTING SYSTEMS

### 6.1 With WraithWall

| Component | Integration Type | Existing? | New Work Required |
|-----------|-----------------|-----------|-------------------|
| `canary_service.py` | Alert enrichment, token creation | Yes | Embed beacons in honeyfs (manual) |
| `reverse_canary` in `main.py` | HTTP route, forensics, auto-block | Yes | Add more `/hidden/` paths |
| `honey_token_check` in `main.py` | Credential use detection | Yes | Register honeyfs credentials as HoneyTokens |
| `campaign_correlator.py` | Session correlation | Partial | Add non-Cowrie event ingestion |
| `fingerprint_corpus.py` | Tool/UA fingerprinting | Yes | Automatic via `before_request` |
| `asn_intelligence.py` | IP enrichment | Yes | Call from alert router |
| `immutable_log` | Audit trail | Yes | Add `deception_event` type |
| `credential_propagation.py` | Platform posting | Yes | Increase frequency + platforms |
| `supply_chain_canary.py` | Package injection | Yes | Not used for honeyfs (different mechanism) |
| `dml_engine.py` | DML deployment | Yes | Can describe honeyfs traps in DML format |
| `gateway.py` | IP blocking | Partial | Add reverse canary auto-block (exists) |

### 6.2 With Cowrie Analyzer (cowrie-analyzer/)

| Component | Integration Type | Existing? | New Work Required |
|-----------|-----------------|-----------|-------------------|
| Cowrie JSON logs | Flow to `cowrie_intelligence.py` | Yes | Already via shipper |
| Cowrie Redis pub/sub | Flow to worker | Yes | Already via `redisevents.py` |
| Honeyfs bind mount | Static files | Yes | Add new files, restart container |
| Cowrie config | `cowrie.cfg` | Yes | May tune latency/behavior |
| Dashboard | MongoDB reports | Yes | No changes needed |

### 6.3 With Raven (Ravenscan)

**Note:** No existing Raven integration with the deception pipeline. Raven operates on a separate codebase (`ravenscan/`) focused on operational intelligence.

| Integration | Status | Notes |
|-------------|--------|-------|
| Deception event feed to Raven | Future | Raven could consume deception events as operational intelligence |
| Credential propagation via Raven | None | Raven's Phase 6 was deferred — no current integration path |
| Raven threat scoring using deception data | Future | Deception triggers could feed Raven's operational health scoring |

---

## 7. TELEMETRY STORAGE

| Data | Storage | TTL | Size Estimate |
|------|---------|-----|---------------|
| Deception events (raw) | Redis `deception:events` | 30 days | ~1KB/event, ~1000/day = ~30MB |
| Deception event chains | Redis `deception:chain:<ip>` | 24 hours | ~100B/chain, ~100/day = ~10KB |
| CanaryServiceHit | PostgreSQL | Permanent | ~500B/hit, ~50/day |
| HoneyTokenEvent | PostgreSQL | Permanent | ~1KB/event, ~10/day |
| CanaryAlert | PostgreSQL | Permanent | ~500B/alert, ~30/day |
| Cowrie session data | Redis `cowrie_completed:*` | 30 days | ~5KB/session, ~20/day |
| Immutable audit log | PostgreSQL | Permanent | ~1KB/entry, ~200/day |
| Beacon trigger records | Redis `sc:{token}` | 365 days | ~200B/token |

---

## 8. ALERT FORMAT (Unified)

### Telegram Template
```
🔴 DECEPTION ALERT — PIVOT DETECTED
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Event:         Credential Use
Attacker IP:   185.220.101.45
Bait:          AWS Key from /root/.aws/credentials (v2)
Layer:         2 → Credential Lures
Server:        Cowrie VPS (COWRIE_VPS_IP)
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Attacker Context:
  ASN:         12345 (Example Hosting, DE)
  Tor Exit:    Yes
  Threat:      72/100 (HIGH)
  Cowrie:      3 prior sessions (48h, 12h, 1h ago)
  Campaign:    CAM-20260708-004 (5 sessions, 3 IPs)
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Chain History:
  2026-07-09 10:23:  Cowrie login (root:x) - 185.220.101.45
  2026-07-09 10:25:  `cat /root/.aws/credentials` - 185.220.101.45
  2026-07-09 10:27:  🔥 AWS Key beacon triggered - 185.220.101.45
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Action Taken:  IP blocked via gateway | Alert sent | Immutable log updated
```

### Discord Template
```yaml
**Deception Alert — Pivot Detected**
Event: Credential Use
Attacker IP: `185.220.101.45` | ASN: `12345` (Example Hosting)
Bait: AWS Key (`/root/.aws/credentials`) | Layer: 2
Threat Score: **72/100** | Campaign: `CAM-20260708-004`
Chain: Cowrie login → File access → Beacon trigger
Action: IP blocked | Immutable log updated
```

### Email Template
Subject: `[WraithWall] DECEPTION ALERT — Pivot from 185.220.101.45`

Body: Full attacker dossier including ASN enrichment, Cowrie history, campaign membership, chain timeline, and automated response taken.
