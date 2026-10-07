# WraithWall Intelligence Collector — Safe Autonomous OSINT Architecture

**Status:** Planning phase — do NOT implement until approved
**Date:** 2026-07-18

---

## Table of Contents

1. [Deployment Recommendation](#1-deployment-recommendation)
2. [Sandbox Technology Evaluation](#2-sandbox-technology-evaluation)
3. [Architecture Overview](#3-architecture-overview)
4. [Data Flow](#4-data-flow)
5. [Security Model](#5-security-model)
6. [Trusted Source Catalog](#6-trusted-source-catalog)
7. [Intelligence Scoring Model](#7-intelligence-scoring-model)
8. [Storage Design](#8-storage-design)
9. [Scaling Strategy](#9-scaling-strategy)
10. [Implementation Roadmap](#10-implementation-roadmap)
11. [Infrastructure Summary](#11-infrastructure-summary)

---

## 1. Deployment Recommendation

### The Decision: Cowrie VPS (217.76.55.55) as rootless Docker container

**Analysis of each option:**

| Option | Safety | Simplicity | Performance | Verdict |
|--------|--------|------------|-------------|---------|
| Inside production gunicorn | ❌ | ✅ | ✅ | **Rejected** — violates "never browse from production" |
| Cowrie VPS — regular Docker | ⚠️ | ✅ | ✅ | Acceptable but can be improved |
| Cowrie VPS — rootless Docker + Firejail | ✅ | ✅ | ✅ | **Recommended** |
| Dedicated VPS | ✅✅ | ⚠️ | ✅ | Ideal long-term, adds cost |
| Kubernetes CronJob | ✅✅ | ❌ | ✅ | Overkill for single collector |
| gVisor/Kata Containers | ✅✅ | ⚠️ | ⚠️ | Best isolation, more complex |

### Why the Cowrie VPS?

1. **Already a security boundary** — the Cowrie honeypot server is deliberately separate from the production WraithWall app (62.171.139.164). It is expected to be untrusted. Adding the collector here satisfies "never browse from production."

2. **Existing Docker infrastructure** — Docker Compose already manages 6 containers (redis, mongo, cowrie, malware-analyzer, dashboard, shipper). Adding a 7th with dedicated network isolation is trivial.

3. **Existing data flow to production** — the `cowrie-shipper` already pushes Cowrie logs to the main WraithWall Redis (`PROD_REDIS_PORT=16379`). The collector can use the same pattern: push intel items to a dedicated Redis key or API endpoint on the main app.

4. **No shared attack surface** — the collector runs in a separate Docker bridge network (`intel-collector-net`), has no access to the cowrie network, mounts no shared volumes, and makes outbound requests only to whitelisted IP ranges.

5. **Resource headroom** — the collector's workload is scheduled, lightweight HTTP fetches at configurable intervals (1h–12h). CPU/memory footprint is under 256MB.

### The mitigation for "Cowrie IP may be blocklisted"

Most Tier 1 sources (CISA, NVD, GitHub, CERT) do not blocklist aggressively. If a source does block the Cowrie IP, the collector falls back to making requests through the main WraithWall server's API proxy (`https://wraithwall.online/api/intel/proxy`), which routes the request and returns the raw response. The source sees the production IP, not the Cowrie IP.

### Alternative: Both VPSs in tandem

For sources that require clean IP reputation (e.g., commercial APIs), the collector routes through the WraithWall origin. For open feeds (CISA, NVD, AlienVault), it fetches directly from the Cowrie VPS. This is configurable per-source.

---

## 2. Sandbox Technology Evaluation

| Technology | Isolation Level | Performance | Complexity | Maturity | Verdict |
|------------|-----------------|-------------|------------|----------|---------|
| **Rootless Docker** | Medium (user namespaces, no host root access) | Near-native | Low — `dockerd-rootless-setuptool.sh install` | Stable since Docker 20.10 | ✅ **Baseline** |
| **Firejail** | Medium (seccomp, capabilities, private /tmp, net namespaces) | Near-native | Low — `firejail --net=none --caps.drop=all python3 collector.py` | Stable, battle-tested | ✅ **Layer 2** |
| **Docker security_opt** | Medium (no-new-privileges, cap_drop ALL, read_only, seccomp profiles) | Near-native | Low — Docker Compose directives | Stable | ✅ **Layer 1** |
| **gVisor (runsc)** | High (user-space kernel, syscall filtering) | 10-20% overhead for network-heavy workloads | Medium — `docker run --runtime=runsc` | Production at Google, mature | ✅ **Phase 3 upgrade** |
| **Kata Containers** | Maximum (VM-level isolation per container) | 20-30% overhead | High — requires hypervisor | Production at AWS/Azure | ⚠️ Overkill |
| **Firecracker** | Maximum (microVM) | Near-native | High — custom runtime | Used by AWS Lambda/Fargate | ⚠️ Overkill |
| **Bubblewrap (bwrap)** | Medium (user namespaces, like Flatpak) | Near-native | Low — `bwrap --ro-bind /usr /usr ...` | Stable, ships with systemd | ✅ Phase 2 alternative |

### Recommended Stack (layered)

```
Layer 1: Docker security options
  - no-new-privileges: true
  - cap_drop: ALL
  - read_only: true (root filesystem)
  - tmpfs: /tmp (writable scratch)
  - security_opt: seccomp=path/to/custom-profile.json
  - cgroup_parent: /intel-collector.slice  (CPU/memory limits)

Layer 2: Rootless Docker
  - Container runs under a non-root user on the host
  - User namespace remapping: container root ≠ host root

Layer 3: Firejail (optional, Phase 2)
  - Entrypoint wraps the collector with Firejail:
    firejail --net=none --private-tmp --caps.drop=all
  - Whitelist outbound IP ranges per source

Layer 4 (Phase 3): gVisor
  - Replace Docker runtime with runsc
  - System call interception prevents kernel attack surface
```

### Daily Rebuild Policy

The container is rebuilt from a trusted base image daily (`docker compose up --force-recreate --build intel-collector` via cron or systemd timer). State persists only in Redis (sent to production immediately). This ensures:
- No persistent compromise survives >24h
- Base image security patches are applied daily
- Any leaked credentials in the container are stale within 24h
- The source code is always the latest trusted version

---

## 3. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                  COWRIE VPS (217.76.55.55)                           │
│                                                                      │
│  ┌──────────────────────────────────────┐                           │
│  │    Cowrie Docker Compose Stack       │                           │
│  │  redis│mongo│cowrie│analyzer│db│ship │ ← existing, unchanged    │
│  └──────────────────────────────────────┘                           │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  intel-collector  (rootless Docker + security hardening)     │   │
│  │                                                               │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐ │   │
│  │  │ SCHEDULER│  │  FETCHER │  │VERIFIER  │  │ NORMALIZER   │ │   │
│  │  │ (cron)   │  │  (per-   │  │(checksum │  │ (→ IntelItem │ │   │
│  │  │          │  │   source)│  │ +signing)│  │    schema)   │ │   │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬───────┘ │   │
│  │       │             │              │               │         │   │
│  │       ▼             ▼              ▼               ▼         │   │
│  │  ┌──────────────────────────────────────────────────────┐    │   │
│  │  │                  PIPELINE ENGINE                      │    │   │
│  │  │                                                      │    │   │
│  │  │  DEDUP → EXTRACT ENTITIES → CLASSIFY → SCORE →      │    │   │
│  │  │  CORRELATE → REGION TAG → RECOMMEND                  │    │   │
│  │  └──────────────────────┬───────────────────────────────┘    │   │
│  │                         │                                     │   │
│  │  ┌──────────────────────┴───────────────────────────────┐    │   │
│  │  │                    SHIPPER                             │    │   │
│  │  │  Redis PUBLISH / HTTP POST → WraithWall production    │    │   │
│  │  └──────────────────────────────────────────────────────┘    │   │
│  │                                                               │   │
│  │  Network: intel-collector-net (isolated bridge)              │   │
│  │  Outbound: whitelist-only → CISA, NVD, GitHub, CERT, etc    │   │
│  │             + WraithWall Redis (217.76.55.55 → 62.171.139.164│   │
│  │             :16379) via SSH tunnel or TLS                    │   │
│  │                                                               │   │
│  │  Volumes: data:/data (rw), config:/app/config (ro)           │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘

                          │  Redis PUBLISH / HTTPS POST
                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│              WRAITHWALL PRODUCTION (62.171.139.164)                  │
│                                                                      │
│  Redis (port 16379) ← receives intel items from collector           │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │ main.py: IntelItem model (PG) + intel_dashboard_bp (API)  │     │
│  │                                                            │     │
│  │ IntelIngestionAPI:                                          │     │
│  │   POST /api/intel/ingest — collector pushes intel items    │     │
│  │   GET  /api/intel/proxy — collector proxies through origin │     │
│  └────────────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 4. Data Flow

```
Scheduler triggers (e.g., every 6 hours for CISA KEV)
        │
        ▼
Fetcher.pull("cisa_kev")
        │
        ├── 1. GET https://www.cisa.gov/.../known_exploited_vulnerabilities.json
        │       Headers: User-Agent: WraithWall-IntelCollector/1.0 (+https://wraithwall.online)
        │       Timeout: 30s, retry: 3x with exponential backoff (1s, 2s, 4s)
        │
        ├── 2. Response → raw JSON saved to /data/raw/cisa_kev/2026-07-18/{uuid}.json
        │       (Audit trail: proves what we received and when)
        │
        ├── 3. Integrity check:
        │       - HTTP 200?
        │       - Content-Type is application/json?
        │       - Body is valid JSON?
        │       - If the source provides ETag/Last-Modified, compare to last fetch
        │         (no change → skip processing)
        │       - If the source signs responses (e.g., PGP-signed advisory),
        │         verify signature against known public key
        │
        ├── 4. Normalize → IntelItem dict:
        │       {
        │         "source": "cisa_kev",
        │         "intel_type": "vulnerability",
        │         "severity": "critical",  # CISA KEV = known-exploited = critical
        │         "title": "CVE-2026-XXXXX — Vendor Product RCE",
        │         "description": "...",
        │         "cvss_score": null,  # CISA KEV doesn't include CVSS
        │         "cves": ["CVE-2026-XXXXX"],
        │         "entities": {"vendors": ["Vendor"], "products": ["Product"]},
        │         ...
        │       }
        │
        ├── 5. Dedup check against Redis:
        │       - Content hash in dedup:bloom filter → seen → skip
        │       - CVE already known → merge source + increment corroboration
        │
        ├── 6. Extract entities:
        │       - CVE pattern: CVE-\d{4}-\d{4,}
        │       - Vendor/product names (from title + CPE data)
        │       - References URLs to vendor advisories
        │
        ├── 7. Classify:
        │       - Category: vulnerability
        │       - Subcategory: known_exploited (because it's from CISA KEV)
        │       - Keywords: ["actively exploited", "known exploited", "ransomware"]
        │
        ├── 8. Score:
        │       - Source trust: 0.95 (CISA KEV baseline)
        │       - Freshness: 1.0 (just fetched)
        │       - Confidence: 0.95 * 0.35 + 0.0 * 0.25 + 1.0 * 0.15 + 0.9 * 0.15 + 0.8 * 0.10 = 0.67
        │       - This is LOW because no corroboration yet — that's correct for
        │         a sole-source item. It will increase when NVD reports the same CVE.
        │
        ├── 9. Region tag:
        │       - CISA KEV targets US organizations primarily → country=US, region=north-america
        │       - If vendor is widely deployed globally → add global tag
        │
        ├── 10. Recommend:
        │       - Template: "CISA KEV: Patch CVE-2026-XXXXX immediately.
        │         This vulnerability is known to be actively exploited.
        │         Vendor: [link to advisory]"
        │
        └── 11. Ship to production:
                POST https://wraithwall.online/api/intel/ingest
                Body: {item: {...}, shipper_token: "..."}
                → main.py stores in PG + pushes to Redis per-user feeds
```

---

## 5. Security Model

### Threat Model

| Threat | Likelihood | Impact | Mitigation |
|--------|-----------|--------|------------|
| Malicious page delivers drive-by download | Low | Medium | Container has no browser. Only `requests` library fetches JSON/XML/RSS. No JavaScript execution. |
| Poisoned feed (fake CVE injected) | Medium | Medium | Source trust scoring. Corroboration requirement (≥2 sources for high confidence). Signature verification where available. |
| Collector exploited via HTTP parsing bug | Low | High | Rootless Docker + no-new-privileges + cap_drop ALL + read_only FS. Attacker gets an unprivileged user in a disposable container. |
| Container escape via kernel exploit | Very Low | Critical | gVisor (Phase 3). Daily rebuild. No host volume mounts. |
| API key leaked from collector env | Low | Medium | Keys are read-only for public APIs. GitHub token: public_repo scope only. No production credentials in collector. |
| Infinite crawling loop | Low | Low | Per-source rate limits. Global max_items_per_run. Timeout per fetch (30s). Concurrency limit. |
| Bandwidth exhaustion | Low | Medium | cgroups v2 limits. Per-source schedule spacing. No recursive following. |
| Cross-contamination from cowrie compromise | Low | High | Separate Docker network. No shared volumes. Collector doesn't trust cowrie Redis/mongo. |

### Network Isolation

```
Collector outbound whitelist (iptables/nftables at the Docker network level):

Allow outbound TCP 443 to:
  - 104.18.0.0/20, 104.16.0.0/12     → Cloudflare (CISA, NVD, GitHub, etc.)
  - 151.101.0.0/16                    → Fastly (CERT feeds)
  - 185.199.108.0/22                  → GitHub Pages (vendor advisories)
  - 62.171.139.164:16379              → WraithWall Redis (production)
  - 62.171.139.164:443                → WraithWall API (for proxy + ingest)

Allow outbound TCP 53 (DNS) to:
  - 1.1.1.1, 9.9.9.9                 → DNS resolution only

Deny ALL other outbound.
Deny ALL inbound (except established/related).

No access to cowrie-network (172.x.x.x).
No access to host network.
No access to Docker socket.
```

### Credential Isolation

| Credential | Scope | Stored In | Rotated |
|-----------|-------|-----------|---------|
| `GITHUB_TOKEN` | `public_repo` only | Docker secret / env | Monthly |
| `IPINFO_TOKEN` | Read-only IP lookup | Docker secret / env | — |
| `ABUSEIPDB_API_KEY` | Read-only queries | Docker secret / env | — |
| `SHIPPER_TOKEN` | POST to `/api/intel/ingest` | Docker secret | Weekly |
| Production Redis password | Read-write to `intel:*` keys only | NEVER in collector | N/A |

**No production credentials. No database passwords. No API keys with write access. No SSH keys.**

---

## 6. Trusted Source Catalog

### Tier 1 — Immediately Collected (structured, high-trust, government/authority)

| # | Source | Type | Format | Encryption | Schedule | Trust |
|---|--------|------|--------|------------|----------|-------|
| 1 | **CISA KEV Catalog** | Vulnerability (actively exploited) | JSON | HTTPS | 6h | 0.95 |
| 2 | **NVD API 2.0** | Vulnerability database | JSON | HTTPS | 2h | 0.92 |
| 3 | **GitHub Security Advisories (GHSA)** | Vulnerability/advisory | GraphQL JSON | HTTPS | 1h | 0.88 |
| 4 | **CERT-Bund (BSI Germany)** | Advisory/warning | JSON Feed | HTTPS | 12h | 0.90 |
| 5 | **US-CERT Alerts (CISA)** | Advisory/alert | RSS | HTTPS | 12h | 0.90 |
| 6 | **NCSC-UK Advisories** | Advisory | RSS | HTTPS | 12h | 0.90 |
| 7 | **ENISA Threat Landscape** | Research/report | HTML (scraped)/PDF | HTTPS | 24h | 0.85 |

### Tier 2 — Threat Intelligence (structured, community/industry)

| # | Source | Type | Format | Encryption | Schedule | Trust |
|---|--------|------|--------|------------|----------|-------|
| 8 | **Abuse.ch URLhaus** | IOC feed (malware URLs) | CSV/JSON API | HTTPS | 3h | 0.85 |
| 9 | **Abuse.ch ThreatFox** | IOC feed (malware IPs/hashes) | JSON API | HTTPS | 3h | 0.85 |
| 10 | **Abuse.ch SSL Blacklist** | IOC feed (malicious certs) | CSV | HTTPS | 6h | 0.80 |
| 11 | **AlienVault OTX Pulses** | Community threat intel | JSON API | HTTPS (key) | 3h | 0.70 |
| 12 | **Spamhaus DROP/EDROP** | IOC feed (spam/botnet IPs) | Text | HTTPS | 6h | 0.85 |
| 13 | **PhishTank** | IOC feed (phishing URLs) | JSON API | HTTPS | 2h | 0.75 |
| 14 | **Tor Exit Node List** | Infrastructure (anonymity) | Text | HTTPS | 1h | 0.90 |

### Tier 3 — Infrastructure / Routing

| # | Source | Type | Format | Encryption | Schedule | Trust |
|---|--------|------|--------|------------|----------|-------|
| 15 | **RIPE RIS** | BGP route data | WebSocket (existing bgp_monitor) | WSS | Real-time | 0.95 |
| 16 | **BGPStream** | BGP route/hijack data | JSON API | HTTPS | 15m | 0.90 |
| 17 | **Cloudflare Radar BGP** | BGP hijack events | JSON API | HTTPS (token) | 1h | 0.90 |
| 18 | **RouteViews** | BGP routing table snapshots | MRT/binary | HTTP | 2h | 0.90 |
| 19 | **Shadowserver Reports** | Internet-wide scan data | Email/JSON | HTTPS | Daily | 0.92 |

### Tier 4 — Vendor Bulletins

| # | Source | Type | Format | Encryption | Schedule | Trust |
|---|--------|------|--------|------------|----------|-------|
| 20 | **Microsoft Security Response Center** | Advisory/patch | RSS | HTTPS | 4h | 0.90 |
| 21 | **Google Security Blog** | Advisory/research | RSS | HTTPS | 4h | 0.85 |
| 22 | **Apple Security Updates** | Advisory/patch | JSON (kPHAsset) | HTTPS | 6h | 0.90 |
| 23 | **Cisco Security Advisories** | Advisory/patch | RSS | HTTPS | 6h | 0.90 |
| 24 | **AWS Security Bulletins** | Advisory | RSS | HTTPS | 6h | 0.85 |
| 25 | **Azure Security Updates** | Advisory | RSS | HTTPS | 6h | 0.85 |
| 26 | **Cloudflare Security Advisories** | Advisory/research | RSS | HTTPS | 6h | 0.85 |
| 27 | **Oracle Critical Patch Updates** | Advisory/patch | RSS | HTTPS | Monthly | 0.88 |

### Tier 5 — Research (NLP + controlled browsing)

| # | Source | Type | Format | Encryption | Schedule | Trust |
|---|--------|------|--------|------------|----------|-------|
| 28 | **SANS Internet Storm Center** | Threat research | RSS | HTTPS | 6h | 0.70 |
| 29 | **Krebs on Security** | Investigative | RSS | HTTPS | 4h | 0.65 |
| 30 | **Unit 42 (Palo Alto)** | Threat research | RSS | HTTPS | 4h | 0.75 |
| 31 | **Talos (Cisco)** | Threat research | RSS | HTTPS | 4h | 0.75 |
| 32 | **BleepingComputer** | News/analysis | RSS | HTTPS | 4h | 0.55 |
| 33 | **The Hacker News** | News | RSS | HTTPS | 4h | 0.50 |
| 34 | **MITRE ATT&CK Updates** | Reference framework | STIX/TAXII | HTTPS | 24h | 0.95 |
| 35 | **MITRE CWE Top 25** | Reference | JSON | HTTPS | Monthly | 0.90 |

### Controlled Web Visits (only when necessary)

If an article must be visited (e.g., a CERT advisory links to a vendor page with patch details):

1. **Sub-process, not browser** — Use `httpx` or `requests` client, not a headless browser, for 95% of visits
2. **Headless Chromium** only for JavaScript-required pages — launched with `--no-sandbox --disable-gpu --disable-dev-shm-usage --disable-setuid-sandbox --disable-web-security` flags disabled, plus `--headless=new`
3. **Disposable container per visit** — a temporary container is launched with `--rm`, fetches the page, extracts text with `html2text` or `trafilatura`, and is immediately destroyed
4. **No persistent storage** — all article data is stored in memory, processed, and shipped to production Redis before the container exits
5. **No credential storage** — no browser profile, no cookies, no localStorage
6. **Network recording** — all HTTP requests made during the visit are logged to `/data/audit/visits/{timestamp}.har`
7. **Timeout: 15 seconds** — any page taking longer is aborted

---

## 7. Intelligence Scoring Model

### Per-Item Scoring

```python
class IntelScorer:
    """
    Produces a confidence score 0.0–1.0 for every intel item.
    Used for prioritization in the dashboard and for source trust
    auto-calibration.
    """

    def score(self, item: dict) -> dict:
        # ── Source reliability (0.0–1.0) ──────────────────────
        # Pre-configured per source. Auto-adjusted over time:
        #   - Increases when items are corroborated by other sources
        #   - Decreases when items are flagged as false positives
        source_trust = SOURCE_TRUST_DEFAULTS[item['source']]

        # ── Corroboration (0.0–1.0) ───────────────────────────
        # Count of independent sources reporting the same event.
        # 1 source = 0.1, 2 = 0.4, 3 = 0.7, 5+ = 1.0
        corr_count = item.get('corroboration_count', 1)
        corroboration = min(corr_count / 5, 1.0) ** 0.5  # sqrt scaling

        # ── Freshness (0.0–1.0) ───────────────────────────────
        # Linear decay: full score until 24h, decays to 0 at 14d
        age_hours = (now - item['published_at']).total_seconds() / 3600
        freshness = max(0, 1.0 - (age_hours / 336))  # 14 days

        # ── Completeness (0.0–1.0) ────────────────────────────
        # How many relevant fields were populated by the source?
        fields = ['title', 'description', 'cves', 'entities', 'severity', 'cvss_score']
        completeness = sum(1 for f in fields if item.get(f)) / len(fields)

        # ── Evidence score (0.0–1.0) ──────────────────────────
        # Does this item link to primary evidence?
        #   - Has source_url → +0.3
        #   - Has cve reference → +0.3
        #   - Has vendor advisory URL → +0.2
        #   - Has raw data preserved → +0.2
        evidence = 0.0
        if item.get('source_url'): evidence += 0.3
        if item.get('cves'): evidence += 0.3
        if item.get('references'): evidence += 0.2
        if item.get('raw_path'): evidence += 0.2

        # ── Weighted aggregate ────────────────────────────────
        confidence = (
            source_trust    * 0.30 +
            corroboration   * 0.25 +
            freshness       * 0.15 +
            completeness    * 0.15 +
            evidence        * 0.15
        )

        # ── False positive risk ───────────────────────────────
        # Inverse of confidence, weighted by source history
        fp_risk = max(0.01, (1.0 - confidence) * 1.2)
        if item['source'].startswith('rss_'):
            fp_risk *= 1.4  # RSS blogs have higher FP rate
        if corroboration >= 0.6:
            fp_risk *= 0.5  # Multi-source corroboration halves FP risk

        # ── Staleness ─────────────────────────────────────────
        stale_days = 30 if item['type'] == 'vulnerability' else 7
        stale_after = item['published_at'] + timedelta(days=stale_days)

        return {
            'source_trust': round(source_trust, 3),
            'corroboration_count': corr_count,
            'freshness': round(freshness, 3),
            'completeness': round(completeness, 3),
            'evidence_score': round(evidence, 3),
            'confidence': round(confidence, 3),
            'false_positive_risk': round(fp_risk, 3),
            'stale_after': stale_after.isoformat(),
        }
```

### Campaign Relevance Scoring

```python
def campaign_relevance(item: IntelItem, campaign: Campaign) -> float:
    """How relevant is this intel item to a tracked campaign?"""
    score = 0.0

    # Shared IPs → strong signal
    item_ips = set(item.entities.get('ips', []))
    campaign_ips = set(campaign.get('ips', []))
    if item_ips & campaign_ips:
        score += 0.40 * (len(item_ips & campaign_ips) / max(len(campaign_ips), 1))

    # Shared domains
    item_domains = set(item.entities.get('domains', []))
    campaign_domains = set(campaign.get('domains', []))
    if item_domains & campaign_domains:
        score += 0.30

    # Shared malware families
    item_malware = set(item.entities.get('malware_families', []))
    campaign_tools = set(campaign.get('tool_signatures', []))
    if item_malware & campaign_tools:
        score += 0.20

    # Temporal proximity
    campaign_last = campaign.get('last_seen')
    item_published = item.published_at
    if abs((item_published - campaign_last).days) <= 7:
        score += 0.10

    return min(score, 1.0)
```

---

## 8. Storage Design

### Collector-side (Cowrie VPS — temporary)

```
/data/
├── raw/                          # Raw source payloads (audit trail)
│   └── {source}/
│       └── {YYYY-MM-DD}/
│           └── {uuid}.json       # Original response, byte-for-byte
│
├── cache/                        # ETags, Last-Modified, fetch state
│   └── {source}/
│       └── state.json            # {last_etag, last_modified, last_fetch}
│
├── audit/                        # Network activity logs
│   └── visits/
│       └── {timestamp}.har       # HTTP Archive for controlled visits
│
└── collector.db                  # SQLite for local state (dedup bloom,
                                  #   fetch history, error log)
                                  #   Wiped on daily rebuild
```

Raw data retained for 7 days, then pruned. Already shipped to production.

### Production-side (WraithWall PostgreSQL + Redis)

```
PostgreSQL:
  intel_items table (full schema — see previous architecture doc)
  Indexes on: source, published_at, intel_type, severity, cves (JSONB)

Redis:
  intel:dedup:bloom         Bloom filter (hashes of all processed items)
  intel:feed:global         Sorted set (time-sorted, all items)
  intel:feed:region:{r}     Sorted set (per-region)
  intel:feed:user:{id}      Sorted set (per-user, personalized)
  intel:cve:{cve}           Set (items referencing this CVE)
  intel:campaign:{cid}      Set (intel items linked to campaign)
  intel:source:{name}:trust Float (tracked source trust score)
  intel:stats:daily:{date}  Hash (counts per type/severity/source)
```

---

## 9. Scaling Strategy

### Phase 1: Single collector, 7 sources (MVP)
- One Docker container on Cowrie VPS
- Fetches CISA KEV, NVD, GHSA, CERT-Bund, US-CERT, Abuse.ch URLhaus/ThreatFox
- Schedules staggered: CISA(6h), NVD(2h), GHSA(1h), CERT(12h), Abuse.ch(3h)
- Ships via HTTP POST to `/api/intel/ingest`
- Memory: <128MB, CPU: <0.2 cores avg

### Phase 2: Add Tier 3/4 sources (15-20 total)
- Same container, more fetch intervals
- RSS fetchers for vendor bulletins + research blogs
- Controlled web visits via disposable containers
- Proxy fallback for rate-limited sources
- Memory: <256MB, CPU: <0.5 cores

### Phase 3: Horizontal scaling
- Multiple collector containers per source group:
  - `intel-collector-vuln` (CISA, NVD, GHSA, CERT)
  - `intel-collector-ioc` (Abuse.ch, OTX, Spamhaus, PhishTank)
  - `intel-collector-research` (RSS blogs, controlled visits)
- Shared Redis for dedup coordination
- gVisor runtime for research collector (handles arbitrary HTML)

### Phase 4: Multi-VPS federation
- Additional collector instances on separate IPs for geo-diverse scheduled fetching
- Centralized dedup via production Redis

---

## 10. Implementation Roadmap

### Phase 1 — Foundation (Week 1-2)
**Goal:** Single collector running, shipping intel to production.

**Day 1-3: Collector scaffold**
- [ ] `intel_collector/` repo directory with Dockerfile, requirements.txt, docker-compose.collector.yml
- [ ] Base collector class (`collectors/base.py`): abstract `fetch()`, `normalize()`, `_validate()` methods
- [ ] Scheduler: simple `time.sleep()` loop + per-source interval config (no APScheduler in the container — keep it minimal)
- [ ] Shipper: HTTP POST to production `/api/intel/ingest` with HMAC token

**Day 4-7: Tier 1 sources**
- [ ] CISA KEV fetcher
- [ ] NVD API 2.0 fetcher (incremental via `lastModStartDate`/`lastModEndDate`)
- [ ] GitHub Advisory fetcher (GraphQL)
- [ ] CERT-Bund JSON feed fetcher
- [ ] US-CERT RSS fetcher

**Day 8-10: Production ingestion endpoint**
- [ ] `POST /api/intel/ingest` in `intel_dashboard.py` (authenticated via shared secret)
- [ ] `IntelItem` model + `db.create_all()` migration
- [ ] Redis push: `intel:feed:global`, per-region sorted sets
- [ ] Dedup bloom filter integration

**Day 11-14: Testing + hardening**
- [ ] Docker security profile (cap_drop ALL, read_only, no-new-privileges)
- [ ] Network egress whitelist (iptables rules in compose)
- [ ] Daily rebuild cron job
- [ ] Integration test: collector → production end-to-end
- [ ] Source failure recovery tests (NVD down → collector retries next cycle)

### Phase 2 — Expansion (Week 3-4)
**Goal:** 20+ sources, controlled web visits, source trust scoring.

- [ ] AlienVault OTX, Spamhaus, PhishTank, Tor exit nodes
- [ ] Vendor bulletins (MS, Google, Apple, Cisco, AWS, Azure, Cloudflare, Oracle)
- [ ] Research RSS fetchers (SANS ISC, Krebs, Unit 42, Talos, BleepingComputer)
- [ ] Controlled web visit engine (disposable httpx + optional headless Chromium)
- [ ] Source trust auto-calibration (corroboration tracking → adjust trust)
- [ ] Campaign relevance scoring integration
- [ ] Rootless Docker + Firejail hardening

### Phase 3 — Maturing (Week 5-6)
**Goal:** Advanced isolation, monitoring, resilience.

- [ ] gVisor runtime for research containers
- [ ] Collector health monitoring (Prometheus metrics: items_collected, fetch_errors, latency_p95)
- [ ] Self-healing: auto-restart on crash, exponential backoff on source failure
- [ ] Multi-container split (vuln container, IOC container, research container)
- [ ] Archive pipeline: raw data > 7d → compress → archive to R2

---

## 11. Infrastructure Summary

### What runs where

| Component | Location | Runtime | Isolation |
|-----------|----------|---------|-----------|
| **WraithWall production app** | 62.171.139.164 | gunicorn (systemd) | Main production |
| **WraithWall PostgreSQL** | 62.171.139.164 | systemd | Main production |
| **WraithWall Redis** | 62.171.139.164:6379 (internal) :16379 (external) | systemd | Main production |
| **Cowrie Honeypot** | 217.76.55.55 | Docker Compose | Separate VPS |
| **Cowrie Redis/Mongo** | 217.76.55.55 | Docker Compose | Internal to cowrie-net |
| **Cowrie Shipper** | 217.76.55.55 | Docker (host network) | Ships logs → prod Redis |
| **Breach Monitor** | 62.171.139.164:5000 (internal) | systemd | Monitors paste/leaks |
| **Intel Collector (NEW)** | 217.76.55.55 | Rootless Docker | Isolated container |
| **Intel Dashboard (future)** | 62.171.139.164 | gunicorn (part of main app) | Existing production |

### Network flow
```
[Cowrie VPS]                                     [WraithWall VPS]
                                                
 intel-collector ──HTTPS POST──►  /api/intel/ingest  →  PostgreSQL
       │                                             →  Redis feeds
       │                                             →  Dashboard API
       │
       └──HTTPS GET──►  CISA, NVD, GitHub, CERT, etc.
                    (whitelisted outbound only)
```

### SSH Note

SSH to 217.76.55.55 (Cowrie VPS) requires key setup on the deploy server. To enable:

```bash
# On the Cowrie VPS:
ssh-copy-id root@217.76.55.55
# Or manually add ~/.ssh/authorized_keys from the deploy machine
```

Once SSH is working, the collector can be deployed via `scp` + `docker compose` on the Cowrie VPS, or managed remotely from here.

---

## Appendix A: Collector Docker Compose Template

```yaml
# docker-compose.collector.yml (deployed on Cowrie VPS)

services:
  intel-collector:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: intel-collector
    hostname: ww-intel-collector
    user: "1000:1000"  # non-root user
    networks:
      - intel-net
    volumes:
      - collector-data:/data
      - ./config:/app/config:ro
    environment:
      - SHIPPER_TOKEN=${SHIPPER_TOKEN}
      - PROD_INGEST_URL=https://wraithwall.online/api/intel/ingest
      - PROD_PROXY_URL=https://wraithwall.online/api/intel/proxy
      - GITHUB_TOKEN=${GITHUB_TOKEN}
      - IPINFO_TOKEN=${IPINFO_TOKEN}
      - ABUSEIPDB_API_KEY=${ABUSEIPDB_API_KEY}
      - TZ=UTC
    security_opt:
      - no-new-privileges:true
      - seccomp:./seccomp-profiles/collector.json
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE  # only if needed for health check
    read_only: true
    tmpfs:
      - /tmp:size=128M,noexec,nosuid
    cpus: "1.0"
    mem_limit: "256m"
    restart: unless-stopped
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

networks:
  intel-net:
    driver: bridge
    internal: false  # needs outbound internet
    driver_opts:
      com.docker.network.bridge.name: br-intel
    ipam:
      config:
        - subnet: 172.30.0.0/24

volumes:
  collector-data:
```

## Appendix B: Source Registry Format

```yaml
# config/sources.yaml (mounted read-only into collector)

sources:
  cisa_kev:
    name: "CISA Known Exploited Vulnerabilities"
    type: "vulnerability"
    trust: 0.95
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    method: GET
    format: json
    headers:
      User-Agent: "WraithWall-IntelCollector/1.0 (+https://wraithwall.online)"
    schedule: 21600  # every 6 hours
    timeout: 30
    retry: 3
    retry_backoff: [1, 2, 4]
    proxy_fallback: true  # use production proxy if direct fetch fails
    jitter: 300

  nvd:
    name: "NVD CVE Database (NIST)"
    type: "vulnerability"
    trust: 0.92
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0"
    method: GET
    format: json
    params:
      lastModStartDate: "{last_fetch_iso}"
      lastModEndDate: "{now_iso}"
      resultsPerPage: 200
    headers:
      User-Agent: "WraithWall-IntelCollector/1.0"
    schedule: 7200  # every 2 hours
    timeout: 60
    retry: 3
    # NVD rate limit: 5 req/30s without API key, 50 req/30s with key
    rate_limit_rps: 0.15
    incremental: true
```

---

## Appendix C: Keyword Groups Configuration

```yaml
# config/keywords.yaml

keyword_groups:

  deception:
    - deception
    - honeypot
    - canary
    - canarytoken
    - honey token
    - lure
    - credential propagation
    - active defense
    - cyber deception
    - digital decoy

  routing:
    - BGP
    - route leak
    - route hijack
    - prefix hijack
    - BGP hijack
    - BGP incident
    - routing anomaly
    - RPKI
    - ROA
    - BGPStream
    - route injection
    - AS path manipulation

  threats:
    - ransomware
    - malware
    - botnet
    - phishing
    - spear-phishing
    - credential theft
    - credential stuffing
    - brute force
    - zero-day
    - 0day
    - exploit
    - ransomware as a service
    - RaaS
    - initial access broker
    - IAB
    - data extortion
    - double extortion
    - DDoS

  infrastructure:
    - cloud security
    - VPS security
    - Kubernetes security
    - Docker security
    - container escape
    - supply chain
    - software supply chain
    - dependency confusion
    - package hijack
    - CI/CD pipeline
    - DevSecOps

  threat_intelligence:
    - CVE
    - CVSS
    - IOC
    - indicator of compromise
    - TTP
    - tactics techniques procedures
    - MITRE ATT&CK
    - threat actor
    - APT
    - advanced persistent threat
    - nation-state
    - cybercrime group
    - ransomware group

  data:
    - breach
    - data breach
    - data leak
    - exposed database
    - misconfigured bucket
    - S3 bucket leak
    - credential leak
    - leaked credentials
    - PII exposure
    - personal data leak
```

---

*End of architecture document.*
