# WraithWall Adaptive Intelligence Experience & Global Threat Feed Architecture

**Status:** Design (do not implement yet)
**Date:** 2026-07-18
**Author:** Architecture session

---

## Table of Contents

1. [Part A — Personalized User Experience](#part-a--personalized-user-experience)
2. [Part B — Global Threat Intelligence Pipeline](#part-b--global-threat-intelligence-pipeline)
3. [Data Flow](#data-flow)
4. [Integration with Existing Systems](#integration-with-existing-systems)
5. [Source Recommendations](#source-recommendations)
6. [Scaling Strategy](#scaling-strategy)
7. [Implementation Roadmap](#implementation-roadmap)
8. [Security & Ethical Constraints](#security--ethical-constraints)

---

## Part A — Personalized User Experience

### Design Philosophy

This is **operational security intelligence**, not marketing personalization.
Every user sees different threat data based on their region, infrastructure,
industry, deployed sensors, and monitored threat landscape. The goal is
**relevant, actionable, and not overwhelming** — a SOC analyst in Lagos
should see West African BGP hijacks and ransomware campaigns targeting
Nigerian financial institutions, not generic global noise.

### User Intelligence Profile

Each authenticated user has a profile that drives what intelligence they see.
Some fields are **auto-detected**, others are **self-declared**.

```python
# SQLAlchemy model — new table `user_intel_profiles`
class UserIntelProfile(db.Model):
    __tablename__ = 'user_intel_profiles'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), unique=True)

    # Auto-detected (from login IP, updated periodically)
    detected_country = Column(String(2))        # ISO 3166-1 alpha-2
    detected_asn = Column(Integer)
    detected_asn_name = Column(String(200))
    detected_cloud_provider = Column(String(50))  # aws/gcp/azure/oracle/do/hetzner/none

    # Self-declared (onboarding wizard, editable in settings)
    organization_industry = Column(String(50))   # finance/healthcare/tech/gov/education/other
    org_name = Column(String(200))
    org_country = Column(String(2))

    # Sensor configuration
    deployed_honeypots = Column(Integer, default=0)
    deployed_canaries = Column(Integer, default=0)
    honeypot_types = Column(Text)   # JSON list: ["ssh","http","mysql","rdp"]
    canary_types = Column(Text)     # JSON list: ["dns","aws_key","slack_webhook"]

    # Monitoring preferences
    monitored_regions = Column(Text)     # JSON list: ["west-africa","south-asia"]
    monitored_countries = Column(Text)   # JSON list: ["NG","GH","ZA","KE"]
    monitored_keywords = Column(Text)    # JSON list: ["ransomware","phishing","bgp"]
    monitored_industries = Column(Text)  # JSON list: ["finance","healthcare"]

    # Alerting preferences
    alert_severity_threshold = Column(String(10), default='high')  # low/medium/high/critical
    digest_frequency = Column(String(10), default='daily')         # realtime/daily/weekly/none
    digest_email = Column(String(1), default='1')                  # boolean

    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    user = relationship('User', backref='intel_profile')
```

### Personalization Scoring Engine

For every intelligence item, compute a relevance score against each user profile.
Items scoring above a configured threshold appear in that user's feed.

```python
class PersonalizationEngine:
    """Scores intel items against a user profile. Returns 0.0–1.0."""

    WEIGHTS = {
        'geo_match': 0.25,        # intel country/region matches user's location
        'asn_proximity': 0.15,    # intel ASN is in same country or neighbor AS
        'industry_match': 0.20,   # intel targets same industry as user
        'sensor_relevance': 0.15, # intel type matches user's deployed sensors
        'keyword_match': 0.10,    # intel text contains user's monitored keywords
        'temporal_decay': 0.05,   # recency boost (newer = higher)
        'severity_boost': 0.10,   # critical alerts get a bonus multiplier
    }

    def score(self, intel_item: 'IntelItem', profile: UserIntelProfile) -> float:
        score = 0.0

        # Geo: intel countries ∩ user countries
        user_countries = _resolve_user_countries(profile)
        intel_countries = intel_item.geo_tags.get('countries', [])
        if set(intel_countries) & set(user_countries):
            score += self.WEIGHTS['geo_match']
        elif _same_region(intel_countries, user_countries):
            score += self.WEIGHTS['geo_match'] * 0.5

        # ASN proximity: same country or same ASN
        if intel_item.entities.get('asns'):
            user_asn_country = _asn_to_country(profile.detected_asn)
            for asn in intel_item.entities['asns']:
                if _asn_to_country(asn) == user_asn_country:
                    score += self.WEIGHTS['asn_proximity']
                    break

        # Industry: if intel targets an industry matching the user's
        intel_industries = intel_item.geo_tags.get('targeted_industries', [])
        if profile.organization_industry in intel_industries:
            score += self.WEIGHTS['industry_match']

        # Sensors: if intel type is honeypot-related and user has honeypots
        if profile.deployed_honeypots > 0 and intel_item.classification.get('category') in (
            'honeypot_activity', 'credential_theft', 'brute_force'
        ):
            score += self.WEIGHTS['sensor_relevance']

        # Keywords: TF-IDF-inspired match against monitored keywords
        if profile.monitored_keywords:
            intel_text = f"{intel_item.title} {intel_item.description}"
            matches = sum(1 for kw in profile.monitored_keywords
                         if kw.lower() in intel_text.lower())
            score += self.WEIGHTS['keyword_match'] * min(matches / 3, 1.0)

        # Temporal: linear decay over 7 days
        age_hours = (datetime.utcnow() - intel_item.published_at).total_seconds() / 3600
        decay = max(0, 1 - age_hours / 168)  # 168 = 7 days
        score += self.WEIGHTS['temporal_decay'] * decay

        # Severity boost: multiply partial score by severity factor
        sev_map = {'critical': 1.5, 'high': 1.0, 'medium': 0.7, 'low': 0.3, 'info': 0.1}
        factor = sev_map.get(intel_item.normalized.get('severity', 'medium'), 0.5)

        return min(score * factor, 1.0)
```

### Dashboard Widgets

Each widget is an independent data endpoint that the frontend composes.
Design for lazy load — only fetch widgets the user has active.

| # | Widget | Data Source | Refresh | Description |
|---|--------|-------------|---------|-------------|
| 1 | **Regional Threat Map** | Intel items with geo coordinates → aggregated counts per country | 60s | Leaflet/Mapbox heatmap of campaigns, BGP anomalies, honeypot attacks in user's regions |
| 2 | **Active Campaigns Near You** | Campaign correlator filtered by user's countries/ASNs | 30s | Card list: campaign name, threat level, stage progress, active since, targeted industry |
| 3 | **Trending Techniques** | Cowrie intelligence + MITRE ATT&CK tag counts, filtered by region | 300s | Bar chart: top 5 ATT&CK techniques observed in user's region this week |
| 4 | **Attacker Activity Feed** | Live Cowrie sessions on user's sensors + canary triggers | Push (WebSocket) | Real-time event stream: login attempt, command execution, canary tripped |
| 5 | **Recent Advisories** | Intel items classified as advisory/vulnerability, scored for user | 600s | Card list: CISA KEV, NVD CVSS ≥7.0 hitting user's tech stack/industry |
| 6 | **Recommended Actions** | Advisory intel with rule-based action generation | 600s | Prioritized checklist: "Patch CVE-X in product Y", "Investigate campaign Z", "Review BGP prefix" |
| 7 | **ASN Health** | ASN intelligence KARMA scores for ASNs in user's region | 300s | Leaderboard: worst-offending ASNs near the user, with abuse report one-click |
| 8 | **Sensor Status** | Own canaries/honeypots health + trigger count | 30s | Green/yellow/red indicators per sensor, last trigger timestamp |

### Dashboard API Endpoints

```python
# New blueprint: intel_dashboard_bp

GET  /api/intel/dashboard/profile          # Get/set user intel profile
POST /api/intel/dashboard/profile

GET  /api/intel/dashboard/feed             # Personalized feed (paginated, scored)
     ?page=1&per_page=20&min_score=0.3

GET  /api/intel/dashboard/widget/<name>    # Single widget data
     Available: threat_map, campaigns, techniques, activity_feed,
                advisories, recommended_actions, asn_health, sensor_status

GET  /api/intel/dashboard/widgets          # All active widgets (batched)

GET  /api/intel/dashboard/summary          # Daily/weekly summary text

WS   /api/intel/dashboard/live             # WebSocket for real-time push
     Events: campaign.updated, advisory.published, sensor.triggered,
             bgp.anomaly, attack.active
```

### Default vs. Personalized Distribution

| User State | What They See |
|------------|---------------|
| New user, no profile set | Global critical/high items + onboarding prompt |
| Country auto-detected only | National + continental intel |
| Full profile configured | Fully personalized feed |
| Admin | All intel + ability to see any user's feed |

The feed algorithm must never serve **zero** items — fall back to global
critical intel if the personalized score returns an empty set.

### Frontend Components

New Vue components for `frontend/` (SOC console, already dark-themed):

```
frontend/src/components/intel/
├── IntelDashboard.vue          # Main dashboard layout (grid of widgets)
├── ThreatMapWidget.vue         # Leaflet map with campaign markers
├── CampaignCard.vue            # Single campaign summary card
├── CampaignList.vue            # Active campaigns widget
├── TechniqueChart.vue          # Trending techniques bar chart
├── ActivityFeed.vue            # Real-time attack event stream
├── AdvisoryCard.vue            # CVE/advisory card with CVE badge
├── AdvisoryList.vue            # Recent advisories widget
├── RecommendedActions.vue      # Prioritized checklist
├── AsnHealthWidget.vue         # ASN KARMA leaderboard
├── SensorStatusWidget.vue      # Own sensor health grid
├── FeedFilters.vue             # Sidebar: region/category/severity filters
└── ProfileWizard.vue           # Onboarding: set industry, sensors, keywords
```

---

## Part B — Global Threat Intelligence Pipeline

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        COLLECTION LAYER                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │ CISA KEV │ │ NVD API  │ │ GitHub   │ │ CERT/RSS │  ...      │
│  │ Fetcher  │ │ Fetcher  │ │ Advisory │ │ Fetcher  │           │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘           │
│       │             │            │            │                  │
│       ▼             ▼            ▼            ▼                  │
│  ┌──────────────────────────────────────────────────────┐       │
│  │              RAW STORAGE (filesystem)                 │       │
│  │     intel_raw/{source}/{YYYY-MM-DD}/{uuid}.json       │       │
│  └──────────────────────┬───────────────────────────────┘       │
└─────────────────────────┼──────────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                      PROCESSING PIPELINE                         │
│                                                                  │
│  ┌─────────┐   ┌───────────┐   ┌───────────┐   ┌────────────┐  │
│  │  FETCH  │──▶│ NORMALIZE │──▶│ DEDUPLICATE│──▶│  EXTRACT   │  │
│  │         │   │  (schema) │   │(hash+sim) │   │  ENTITIES  │  │
│  └─────────┘   └───────────┘   └───────────┘   └─────┬──────┘  │
│                                                       │         │
│  ┌────────────┐   ┌───────────┐   ┌───────────┐       │         │
│  │  STORE ◄── │   │ RECOMMEND │◄──│   SCORE   │◄──────┘         │
│  │ (PG+Redis) │   │ GENERATE  │   │(confidence│                  │
│  └─────┬──────┘   └───────────┘   │ +quality) │                  │
│        │                          └─────┬─────┘                  │
│        │         ┌───────────┐   ┌──────┴──────┐                │
│        │         │  REGION   │◄──│  CLASSIFY   │                │
│        │         │   TAG     │   │(category+   │                │
│        │         └───────────┘   │ subcategory)│                │
│        │                         └──────┬──────┘                │
│        │         ┌───────────────────────┘                      │
│        │         ▼                                              │
│        │  ┌────────────────┐                                    │
│        │  │   CORRELATE    │  ← existing CampaignCorrelator    │
│        │  │ (campaign id)  │     extended with intel input     │
│        │  └────────┬───────┘                                    │
└────────┼──────────┼────────────────────────────────────────────┘
         │          │
         ▼          ▼
┌─────────────────────────────────────────────────────────────────┐
│                      DELIVERY LAYER                              │
│                                                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │ REST API │ │WebSocket │ │  Email   │ │ Dashboard Vue    │   │
│  │  /feed   │ │  /live   │ │  Digest  │ │ Components       │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Stage 1: Fetch

**Scheduler:** APScheduler jobs (already used in main.py for BGP monitoring).
Per-source schedule with jitter to avoid thundering herd.

```python
# New module: intel_collectors/ (one file per source)

SCHEDULE = {
    'cisa_kev':        {'interval': 6 * 3600,  'jitter': 300},
    'nvd_recent':      {'interval': 2 * 3600,  'jitter': 120},   # NVD API 2.0: lastModStartDate
    'github_advisories':{'interval': 1 * 3600, 'jitter': 60},
    'cert_bund':       {'interval': 12 * 3600, 'jitter': 600},
    'cert_us':         {'interval': 12 * 3600, 'jitter': 600},
    'rss_blogs':       {'interval': 4 * 3600,  'jitter': 180},
    'alienvault_otx':  {'interval': 3 * 3600,  'jitter': 300},
    'abuse_ch_feeds':  {'interval': 3 * 3600,  'jitter': 300},
}
```

**Collector interface:** Each collector is a function `collect(since: datetime) -> List[RawIntel]`.
Rate limits respected via per-source `ratelimit_lock` (Redis-based distributed lock so
two gunicorn workers don't both fetch).

**Raw storage:** `intel_raw/{source}/{YYYY-MM-DD}/{uuid4}.json` — preserves original
payload for audit/retrospective analysis. Compressed after 30 days, archived to R2
at 90 days.

### Stage 2: Normalize

Convert source-specific schemas into the unified `IntelItem` model:

```python
# SQLAlchemy model — new table `intel_items`

class IntelItem(db.Model):
    __tablename__ = 'intel_items'

    id = Column(String(36), primary_key=True)          # UUID4
    source = Column(String(50), index=True)             # cisa-kev, nvd, github-advisory, ...
    source_url = Column(Text)
    source_reference_id = Column(String(200), index=True)  # e.g., CVE-2026-12345

    title = Column(Text)
    description = Column(Text)

    published_at = Column(DateTime, index=True)
    fetched_at = Column(DateTime)
    processed_at = Column(DateTime)

    # Normalized fields
    intel_type = Column(String(30), index=True)
        # vulnerability | advisory | campaign | breach | bgp_event |
        # threat_report | ioc_feed | malware_analysis | research

    severity = Column(String(10), index=True)
        # critical | high | medium | low | info

    cvss_score = Column(Float)
    cvss_vector = Column(String(100))

    # JSON columns (PostgreSQL JSONB preferred, Text fallback for SQLite compat)
    impacted_vendors = Column(Text)        # JSON list
    impacted_products = Column(Text)       # JSON list
    cves = Column(Text)                    # JSON list: ["CVE-2026-...", ...]
    entities = Column(Text)                # JSON: {ips, domains, hashes, emails, asns, ...}
    classification = Column(Text)          # JSON: {category, subcategory, keywords_matched}
    geo_tags = Column(Text)                # JSON: {regions, countries, targeted_industries}
    quality = Column(Text)                 # JSON: {source_trust, corroboration_count, ...}
    recommendation = Column(Text)          # JSON: {action, priority, description}
    raw_path = Column(Text)                # Path to raw JSON in filesystem

    # Campaign linkage (optional FK)
    campaign_id = Column(String(36), nullable=True, index=True)

    # Indexes for personalized queries
    __table_args__ = (
        Index('idx_intel_type_severity', 'intel_type', 'severity'),
        Index('idx_intel_published', 'published_at'),
    )
```

### Stage 3: Deduplicate

Three-tier dedup to handle the fact that the same CVE/Vulnerability/Advisory
appears across multiple sources:

```python
class IntelDeduplicator:
    def is_duplicate(self, item: dict, existing_items: List[dict]) -> bool:
        # Tier 1: Exact content hash (SHA-256 of title + description)
        content_hash = sha256(f"{item['title']}|{item['description']}".encode()).hexdigest()
        if content_hash in self._bloom_filter:
            return True

        # Tier 2: CVE-based merge (same CVE from different sources)
        item_cves = set(item.get('cves', []))
        for existing in existing_items:
            existing_cves = set(existing.get('cves', []))
            if item_cves & existing_cves:
                # Merge: increment corroboration_count, append source
                existing['quality']['corroboration_count'] += 1
                existing['sources'].append(item['source'])
                return True

        # Tier 3: Title similarity (TF-IDF cosine > 0.85)
        for existing in existing_items:
            if cosine_similarity(
                self._vectorize(item['title']),
                self._vectorize(existing['title'])
            ) > 0.85:
                return True

        return False
```

### Stage 4: Extract Entities

Regex-based extraction with validation lookups against existing services:

```python
class EntityExtractor:
    PATTERNS = {
        'ips':          r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        'ipv6':         r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b',
        'domains':      r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        'emails':       r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'cves':         r'\bCVE-\d{4}-\d{4,}\b',
        'md5':          r'\b[a-fA-F0-9]{32}\b',
        'sha1':         r'\b[a-fA-F0-9]{40}\b',
        'sha256':       r'\b[a-fA-F0-9]{64}\b',
    }

    def extract(self, text: str) -> dict:
        entities = {'ips': [], 'domains': [], 'hashes': [], 'emails': [],
                     'cves': [], 'asns': [], 'malware_families': [],
                     'threat_actors': [], 'mitre_techniques': []}
        for kind, pattern in self.PATTERNS.items():
            entities[kind] = list(set(re.findall(pattern, text, re.IGNORECASE)))

        # Enrich IPs → ASN/country (leverage existing asn_intelligence.py)
        for ip in entities['ips']:
            enriched = asn_intelligence.get_service().enrich_and_track(ip, None)
            entities['asns'].append(enriched.asn)
            entities['countries'].append(enriched.country)

        # Match malware family names against curated list
        # Match MITRE ATT&CK technique IDs (TXXXX)
        return entities
```

### Stage 5: Classify

Rule-based classification → category + subcategory. ML optional in Phase 3.

```python
CLASSIFICATION_RULES = {
    'vulnerability': {
        'keywords': ['CVE-', 'vulnerability', 'exploit', 'patch', 'CVSS', 'zero-day', '0day'],
        'subcategories': {
            'ransomware_exploit': ['ransomware', 'lockbit', 'blackcat', 'alphv', 'clop'],
            'supply_chain': ['supply chain', 'dependency', 'third-party', 'solarwinds'],
            'remote_code': ['rce', 'remote code execution', 'arbitrary code'],
            'privilege_escalation': ['privilege escalation', 'eop', 'lpe'],
            'zero_day': ['zero-day', '0day', 'in the wild', 'actively exploited'],
        }
    },
    'campaign': {
        'keywords': ['campaign', 'operation', 'group', 'APT', 'threat actor',
                     'targeting', 'spear-phishing', 'intrusion set'],
    },
    'breach': {
        'keywords': ['breach', 'data leak', 'exposed', 'compromised', 'unauthorized access',
                     'data breach', 'ransomware attack', 'stolen data'],
    },
    'bgp_event': {
        'keywords': ['BGP', 'route leak', 'hijack', 'prefix hijack', 'route hijack',
                     'bgp hijack', 'route injection', 'rpki', 'roa'],
    },
    'advisory': {
        'keywords': ['advisory', 'alert', 'bulletin', 'guidance', 'recommend',
                     'best practice', 'mitigation', 'workaround'],
    },
    'ioc_feed': {
        'keywords': ['IOC', 'indicator', 'malicious IP', 'malicious domain',
                     'C2 server', 'command and control', 'phishing domain'],
    },
}
```

### Stage 6: Confidence & Quality Scoring

```python
class QualityScorer:
    def score(self, item: dict) -> dict:
        # Source trust: per-source reliability score (bootstrapped, updated over time)
        source_trust = self._get_source_trust(item['source'])
        # Default values for known trusted sources:
        TRUST_DEFAULTS = {
            'cisa_kev': 0.95, 'nvd': 0.92, 'cert_bund': 0.90,
            'github_advisory': 0.88, 'cert_us': 0.90, 'alienvault_otx': 0.70,
            'rss_blog_*': 0.60,  # blogs: lower trust until corroborated
        }

        # Corroboration: how many independent sources reported this
        corroboration = item.get('corroboration_count', 1)

        # Freshness: 0-24h = 1.0, 24-72h = 0.8, 72h-7d = 0.5, >7d = 0.2
        age_hours = (datetime.utcnow() - item['published_at']).total_seconds() / 3600
        freshness = {age_hours <= 24: 1.0, age_hours <= 72: 0.8,
                     age_hours <= 168: 0.5}.get(True, 0.2)

        # Completeness: % of IntelItem fields populated
        completeness = self._field_completeness(item)

        # Entity validation: did we successfully resolve extracted IPs/domains?
        entity_validation = self._validate_entities(item.get('entities', {}))

        # Weighted final score
        confidence = (
            source_trust * 0.35 +
            min(corroboration / 3, 1.0) * 0.25 +
            freshness * 0.15 +
            completeness * 0.15 +
            entity_validation * 0.10
        )

        # False positive risk: inverse of confidence + source-specific risk
        fp_risk = max(0.01, 1.0 - confidence)
        if item['source'].startswith('rss_blog'):
            fp_risk *= 1.5  # blogs are higher FP risk

        # Staleness: when should this item be removed from feeds?
        stale_after_days = 30 if item.get('type') == 'vulnerability' else 7
        stale_after = item['published_at'] + timedelta(days=stale_after_days)

        return {
            'source_trust': source_trust,
            'corroboration_count': corroboration,
            'confidence': round(confidence, 3),
            'false_positive_risk': round(fp_risk, 3),
            'stale_after': stale_after.isoformat(),
            'evidence_urls': item.get('evidence_urls', []),
        }
```

### Stage 7: Campaign Correlation

Feed extracted entities into the existing `campaign_correlator.py` as a **new
input path**. The correlator already clusters Cowrie sessions into campaigns.
Extend it to also accept `IntelItem` objects with shared entities.

```python
# New method on CampaignCorrelator
def ingest_intel_item(self, item: IntelItem) -> Optional[str]:
    """Try to associate this intel item with an existing campaign,
    or seed a new campaign if entities overlap with recent Cowrie activity."""
    entities = item.entities

    # Check if any IP/domain/hash matches an existing campaign
    for ip in entities.get('ips', []):
        for cid, campaign in self._list_active_campaigns():
            if ip in campaign.get('ips', []):
                self._link_intel_to_campaign(item.id, cid)
                return cid

    # Check if threat actor / malware family matches
    for actor in entities.get('threat_actors', []):
        for cid, campaign in self._list_active_campaigns():
            if actor in campaign.get('threat_actors', []):
                self._link_intel_to_campaign(item.id, cid)
                return cid

    return None  # Standalone intel, no campaign link
```

### Stage 8: Region Tagging

```python
class RegionTagger:
    # Continent mapping for ISO country codes
    CONTINENTS = {
        'NG': 'africa', 'GH': 'africa', 'ZA': 'africa', 'KE': 'africa',
        'EG': 'africa', 'MA': 'africa', 'CI': 'africa', 'SN': 'africa',
        # ... full mapping
    }

    def tag(self, item: dict) -> dict:
        countries = set()
        regions = set()

        # From extracted IPs → geo-lookup (leverage existing IP enrichment)
        for ip in item.get('entities', {}).get('ips', []):
            intel = asn_intelligence.get_service().enrich(ip)
            if intel and intel.country:
                countries.add(intel.country)
                regions.add(self.CONTINENTS.get(intel.country, 'unknown'))

        # From text mentions: "targets Nigerian banks" → NG
        for country_name, code in COUNTRY_NAMES.items():
            if country_name.lower() in item.get('description', '').lower():
                countries.add(code)
                regions.add(self.CONTINENTS.get(code, 'unknown'))

        # From source geographic focus (e.g., CERT-Bund → DE)
        source_country = SOURCE_COUNTRY.get(item['source'])
        if source_country:
            countries.add(source_country)

        return {
            'regions': list(regions),
            'countries': list(countries),
            'targeted_industries': self._extract_industries(item),
        }
```

### Stage 9: Recommendation Generation

```python
RECOMMENDATION_RULES = [
    # (condition, action_template, priority)
    {
        'condition': lambda i: i.intel_type == 'vulnerability' and i.cvss_score >= 9.0,
        'action': 'Patch immediately — {cves[0]} (CVSS {cvss_score}) affects {impacted_products[0]}',
        'priority': 1,
    },
    {
        'condition': lambda i: i.intel_type == 'vulnerability' and i.cvss_score >= 7.0,
        'action': 'Patch within 72 hours — {cves[0]} (CVSS {cvss_score})',
        'priority': 2,
    },
    {
        'condition': lambda i: i.classification['category'] == 'ransomware' and i.severity == 'critical',
        'action': 'Immediate action — review backup integrity, isolate affected systems, review IOCs',
        'priority': 1,
    },
    {
        'condition': lambda i: i.intel_type == 'bgp_event' and i.severity in ('critical', 'high'),
        'action': 'Verify your prefix announcements — {title}',
        'priority': 2,
    },
    {
        'condition': lambda i: 'credential' in i.title.lower() and 'leak' in i.title.lower(),
        'action': 'Force password resets for affected accounts. Review authentication logs.',
        'priority': 2,
    },
    {
        'condition': lambda i: i.intel_type == 'campaign' and i.severity in ('critical', 'high'),
        'action': 'Review campaign IOCs against your SIEM/firewall logs. Deploy detection rules.',
        'priority': 2,
    },
]
```

### Stage 10: Storage

**PostgreSQL** (`intel_items` table):
- Primary store for structured intel (queryable, indexable)
- Used for dashboard queries, personalized feeds, search

**Redis** (transient/cache):
- Per-user personalized feed (sorted set: `feed:{user_id}` scored by relevance + time)
- Raw feed sorted set (global, time-sorted): `intel:feed:global`
- Region-specific sorted sets: `intel:feed:region:{region}`
- Campaign-to-intel index: `intel:campaign:{campaign_id}` (set)
- CVE-to-item index: `intel:cve:{cve_id}` (set)
- Daily intel count: `intel:stats:daily:{date}` (hash)
- Dedup bloom filter: `intel:dedup:bloom`

**Filesystem** (`intel_raw/`):
- Raw source data for audit, retro processing, source trust calibration

**R2/S3** (archive):
- Gzip-compressed raw data older than 90 days

### Stage 11: Delivery

Daily/weekly digests via Resend (existing `services/email_service.py`):

```python
def generate_daily_digest(user_id):
    profile = UserIntelProfile.query.filter_by(user_id=user_id).first()
    items = get_personalized_feed(profile, min_score=0.5, limit=10)

    sections = {
        'Critical Alerts': [i for i in items if i.severity == 'critical'],
        'Vulnerabilities to Patch': [i for i in items if i.intel_type == 'vulnerability'],
        'Active Campaigns': [i for i in items if i.intel_type == 'campaign'],
        'Regional Activity': [i for i in items if _geo_matches(i, profile)],
    }
    return render_email_template('intel_digest.html', sections=sections)
```

---

## Data Flow

```
User opens dashboard
        │
        ▼
 Vue Dashboard loads widgets
        │
        ├── GET /api/intel/dashboard/widget/threat_map
        │       └─► Redis: intel:geo:{region} → JSON counts per country
        │
        ├── GET /api/intel/dashboard/widget/campaigns
        │       └─► CampaignCorrelator.get_active_campaigns(region=profile.regions)
        │
        ├── GET /api/intel/dashboard/widget/advisories
        │       └─► IntelItem.query.filter(intel_type='advisory').order_by(score.desc()).limit(10)
        │
        ├── GET /api/intel/dashboard/widget/activity_feed
        │       └─► Redis stream: cowrie:events:{user_sensors} + canary:triggers:{user_id}
        │
        └── WS /api/intel/dashboard/live
                └─► Push events: campaign.updated, bgp.anomaly, sensor.triggered
```

```
Collection scheduler fires every N hours
        │
        ▼
Fetcher pulls source API
        │
        ▼
Raw JSON saved to intel_raw/{source}/{date}/{uuid}.json
        │
        ▼
Normalize → IntelItem dict
        │
        ├── Dedup check: hash bloom → CVE merge → title similarity
        │
        ├── Extract entities: IPs, domains, CVEs, hashes, ASNs
        │       └─► ASN enrichment via existing IPEnrichmentEngine
        │
        ├── Classify: category + subcategory
        │
        ├── Score: confidence + quality (source trust, corroboration, freshness)
        │
        ├── Correlate: campaign_correlator.ingest_intel_item(item)
        │       └─► Link to existing campaign or seed new one
        │
        ├── Tag: geo-tag countries/regions/industries
        │
        ├── Recommend: rule-based action generation
        │
        └── Store:
                ├── PostgreSQL: INSERT INTO intel_items
                ├── Redis: ZADD intel:feed:global {score} {id}
                ├── Redis: ZADD intel:feed:region:{region} {score} {id}
                ├── Redis: ZADD feed:{user_id} {relevance_score} {id}
                └── Redis: SADD intel:cve:{cve} {id}
```

---

## Integration with Existing Systems

| Existing Module | How the Intel Pipeline Integrates |
|-----------------|-----------------------------------|
| `campaign_correlator.py` | New `ingest_intel_item()` method. Intel items with shared IPs/domains/actors get linked to existing campaigns or seed new ones. |
| `asn_intelligence.py` | Entity extraction calls `IPEnrichmentEngine.enrich()` for every extracted IP. Region tagging uses ASN → country mapping. ASN Health widget reads from existing `asn:leaderboard:*` Redis keys. |
| `bgp_monitor.py` | BGP hijack events feed directly into the pipeline as `intel_type='bgp_event'`. No new BGP sources needed — the existing real-time monitor is sufficient. |
| `cowrie_intelligence.py` | Cowrie session intel (attack stages, tools, MITRE techniques) feeds the Trending Techniques widget. Sensor activity feed shows live Cowrie events filtered to user's sensors. |
| `fingerprint_corpus.py` | Attacker fingerprint data (JA3, HASSH, User-Agent patterns) enriches campaign profiles. Cross-references intel IOCs with corpus entries. |
| `credential_propagation.py` | Credential propagation events create intel items when lures are accessed from new regions/ASNs. |
| `canary_service.py` | Canary trigger events feed the Sensor Status widget and appear in the activity feed. |
| `webhooks.py` | New webhook event types: `intel.item.published`, `intel.campaign.linked`, `intel.advisory.critical`. |
| `services/email_service.py` | Daily/weekly digest generation using existing Resend integration. |
| `main.py` | New blueprint `intel_dashboard_bp` registered. New APScheduler jobs for fetchers. New `IntelItem` model in SQLAlchemy. |

**No changes needed to existing modules** — the pipeline is additive, consuming
existing intelligence sources alongside new OSINT feeds.

---

## Source Recommendations

### Tier 1 — Immediate (high trust, structured, easy to parse)

| Source | Type | API/RSS | Schedule | Trust |
|--------|------|---------|----------|-------|
| CISA Known Exploited Vulnerabilities | Vulnerability | [JSON API](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | 6h | 0.95 |
| NVD (NIST) | Vulnerability | [REST API 2.0](https://services.nvd.nist.gov/rest/json/cves/2.0) | 2h | 0.92 |
| GitHub Security Advisories | Advisory | [GraphQL API](https://api.github.com/graphql) (GHSA) | 1h | 0.88 |
| CERT-Bund (BSI) | Advisory | [RSS/JSON](https://wid.cert-bund.de/content/public/rss/feed-json) | 12h | 0.90 |
| US-CERT (CISA alerts) | Advisory | [RSS](https://www.cisa.gov/uscert/ncas/alerts.xml) | 12h | 0.90 |
| Abuse.ch URLhaus | IOC feed | [CSV/API](https://urlhaus-api.abuse.ch/v1/) | 3h | 0.85 |
| Abuse.ch ThreatFox | IOC feed | [API](https://threatfox-api.abuse.ch/api/v1/) | 3h | 0.85 |

### Tier 2 — Expand (medium trust, semi-structured)

| Source | Type | Schedule | Trust |
|--------|------|----------|-------|
| AlienVault OTX Pulses | Threat intel | 3h | 0.70 |
| ENISA Threat Landscape | Research | 24h | 0.80 |
| MITRE ATT&CK (STIX/TAXII) | Reference | 24h | 0.95 |
| RIS (RIPE) BGP data | Infrastructure | Already covered by bgp_monitor | — |
| Cloudflare Radar BGP | Infrastructure | Already covered by bgp_monitor | — |

### Tier 3 — Enrichment (lower trust, NLP-heavy)

| Source | Type | Schedule | Trust |
|--------|------|----------|-------|
| SANS ISC Diary | Research/blog | 6h (RSS) | 0.70 |
| Krebs on Security | Blog | 4h (RSS) | 0.65 |
| Unit 42 (Palo Alto) | Blog | 4h (RSS) | 0.75 |
| Talos (Cisco) | Blog | 4h (RSS) | 0.75 |
| The Hacker News | Blog | 4h (RSS) | 0.50 |
| BleepingComputer | Blog | 4h (RSS) | 0.55 |
| DarkReading | Blog | 4h (RSS) | 0.55 |
| Vendor bulletins (MS, Apple, Google, Cisco) | Advisory | 12h (RSS) | 0.80 |

### Tier 4 — Optional / Feature-flagged

| Source | Notes |
|--------|-------|
| Shodan InternetDB | Enrichment only — not a primary feed |
| GreyNoise | Background noise filtering for IOCs |
| VirusTotal Intelligence | Premium — key-dependent |
| Recorded Future / Mandiant | Enterprise — not in MVP |

---

## Scaling Strategy

### Phase 1 — MVP (Weeks 1-2)

**Scope:** Core pipeline + basic personalization + dashboard.

- 5 Tier-1 sources: CISA KEV, NVD, GitHub Advisories, CERT-Bund, Abuse.ch URLhaus
- PostgreSQL-only storage (no Redis feed caches yet)
- Simple geo personalization (country only, no industry/sensor)
- 4 dashboard widgets: threat map, campaigns, advisories, activity feed
- Rules engine for classification (no ML)
- No email digests yet

**Tech delivered:**
- `IntelItem` SQLAlchemy model + migration
- `intel_collectors/` package with 5 fetchers
- `intel_pipeline.py` orchestrator (fetch → normalize → dedup → extract → classify → score → tag → store)
- `UserIntelProfile` model + profile API
- `PersonalizationEngine` with geo-only scoring
- `intel_dashboard_bp` blueprint + 4 widget endpoints
- Vue threat map + campaign card components

### Phase 2 — Expansion (Weeks 3-4)

**Scope:** More sources, richer personalization, campaign correlation.

- Add 10-15 Tier-2/3 sources (blogs, vendor bulletins, OTX)
- Redis feed caches (per-user sorted sets, region-specific feeds)
- Full personalization: industry, sensor, keyword matching
- Campaign correlation integration
- Email digest (daily, template-based)
- 4 more widgets: techniques chart, recommended actions, ASN health, sensor status
- Source trust scoring (bootstrapped from defaults, adjusted via feedback)

**Tech delivered:**
- `IntelDeduplicator` with bloom filter + CVE merge
- `QualityScorer` with source trust and freshness
- CampaignCorrelator.ingest_intel_item()
- Resend email digest templates
- Additional Vue components

### Phase 3 — Advanced (Weeks 5-6)

**Scope:** ML, advanced delivery, optimization.

- Optional ML classifier (train on labeled items from Phases 1-2)
- WebSocket real-time push for critical intel
- Natural language summarization for weekly digests
- Confidence calibration (A/B test source trust defaults)
- R2 archival for raw data > 90 days
- Bulk API for SIEM/SOAR integration
- Performance: query optimization, Redis pipelining

### Phase 4 — Continuous (Ongoing)

- Source trust auto-calibration (compare intel items against ground truth)
- New source onboarding (plugin-style collector registration)
- User feedback loop: "Was this intel useful?" → adjust scoring
- Multi-language support for region-specific blogs

---

## Security & Ethical Constraints

### Collection Ethics

1. **No uncontrolled crawling** — every source is explicitly configured with rate limits, API keys, and terms-of-service compliance.
2. **Only public, authorized sources** — no scraping behind logins, no dark web crawling, no purchased breach data without explicit user opt-in.
3. **Source attribution preserved** — every intel item carries `source_url` and `source_reference_id` back to the original publication.
4. **Data retention policy** — raw files auto-expire: 30d in hot storage, 90d in R2 archive, permanent deletion at 365d unless linked to an active investigation.

### Operational Security

1. **No user data leaves the server** — personalization profiles are stored locally; no telemetry to third parties.
2. **Feed scores are transparent** — the dashboard shows *why* an item was recommended (e.g., "Matches your industry: finance", "Affects ASN in your country: NG").
3. **Admin override** — admins can suppress false positives, boost critical items, and blacklist sources.
4. **API key isolation** — each collector uses its own API key from environment variables; failure of one source never blocks others.

### Implementation Constraints

1. **Fails open on source failure** — if NVD API is down, the pipeline continues with other sources; stale NVD data decays in scoring but is never deleted.
2. **No circular imports** — new modules follow the existing import pattern: blueprints imported at the top of `main.py`, registered after `app` creation, rate limits applied after `limiter` creation.
3. **Tested independently** — each pipeline stage is testable in isolation with mock source data.
4. **No downtime on deploy** — new models use `db.create_all()` idempotency (existing pattern in `main.py`); new APScheduler jobs register in `start_intel_pipeline()` only if feature flag `ENABLE_INTEL_PIPELINE` is set.

---

## Feature Flag

```bash
# .env
ENABLE_INTEL_PIPELINE=false   # Off by default until Phase 1 is complete
```

Registration in `main.py`:

```python
ENABLE_INTEL_PIPELINE = os.getenv('ENABLE_INTEL_PIPELINE', 'false').lower() == 'true'
if ENABLE_INTEL_PIPELINE:
    from intel_pipeline import intel_dashboard_bp, start_intel_pipeline
    app.register_blueprint(intel_dashboard_bp)
    start_intel_pipeline(app)  # starts APScheduler jobs
```

---

## File Structure (new files only)

```
intel_pipeline.py                  # Pipeline orchestrator + feature flag guard
intel_collectors/
├── __init__.py                    # Registry: COLLECTORS dict
├── base.py                        # AbstractCollector base class
├── cisa_kev.py                    # CISA KEV fetcher
├── nvd.py                         # NVD API 2.0 fetcher
├── github_advisories.py           # GHSA GraphQL fetcher
├── cert_bund.py                   # CERT-Bund RSS/JSON fetcher
├── cert_us.py                     # US-CERT RSS fetcher
├── rss_blogs.py                   # Generic RSS blog fetcher (configurable URL list)
├── alienvault_otx.py              # OTX pulse fetcher
├── abuse_ch.py                    # Abuse.ch URLhaus + ThreatFox fetcher
├── vendor_bulletins.py            # MS/Apple/Google/Cisco RSS aggregator
└── (future) ...                   # Plugin-style: drop new collector file, register in __init__

intel_normalizer.py                # Schema normalization (source-specific → IntelItem)
intel_dedup.py                     # Content hash, CVE merge, title similarity
intel_entity_extractor.py          # Regex + IP/domain validation + ASN enrichment
intel_classifier.py                # Rule-based category/subcategory classification
intel_scorer.py                    # Confidence + quality scoring (source trust, corroboration)
intel_region_tagger.py             # Geo-tagging via IP enrichment + text extraction
intel_recommender.py               # Rule-based action recommendation generation

models/
└── intel_models.py                # IntelItem + UserIntelProfile SQLAlchemy models

intel_dashboard.py                 # Blueprint: dashboard widgets, feed, profile, WebSocket

services/
└── intel_digest.py                # Daily/weekly email digest generation (reuses Resend)

frontend/src/components/intel/     # Vue components (13 files — listed above)

tests/
├── test_intel_pipeline.py         # Pipeline unit tests
├── test_intel_dedup.py            # Dedup unit tests
├── test_intel_classifier.py       # Classification tests
├── test_intel_personalization.py  # Personalization scoring tests
└── test_intel_dashboard.py        # Dashboard API integration tests
```

---

## Summary

This architecture delivers:

1. **Personalized operational intelligence** — every user sees threats relevant to their geography, infrastructure, industry, and deployed sensors. Not marketing. Not generic.

2. **Automated OSINT pipeline** — multi-source collection → normalize → dedup → extract → classify → score → correlate → tag → recommend → store → deliver. Trusted sources only. Scheduled, not crawling.

3. **Quality controls** — duplicate detection, source trust scoring, false-positive reduction, staleness expiration, corroboration tracking, evidence URLs.

4. **Actionable outputs** — analyst summaries, daily digests, weekly reviews, regional alerts, REST API, WebSocket, dashboard widgets, email delivery.

5. **Incremental deployment** — 4-phase rollout over 6 weeks, feature-flagged, independently testable, zero impact on existing systems.

6. **Ethical collection** — only public authorized sources, attribution preserved, data retention policy, transparent scoring.
