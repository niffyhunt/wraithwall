# WraithWall API Evolution — Endpoint Schema Review & Upgrade

**Status:** Audit complete — design phase  
**Date:** 2026-07-18  
**Endpoints audited:** 450+ across 39 files  

---

## 1. Endpoint Audit Summary

| Domain | Files | Endpoints | Auth Model |
|--------|-------|-----------|------------|
| Authentication | `main.py` | 35 | Session + public |
| Intelligence | `cowrie_intelligence.py`, `intelligence_layer.py`, `intel_core.py`, `campaign_correlator.py`, `fingerprint_corpus.py`, `asn_intelligence.py`, `intel_ingestion.py` | 55 | Mixed (public/anonymized/dual) |
| Deception | `canary_service.py`, `llm_honeypot.py`, `sandbox.py`, `deception_event_bus.py`, `credential_propagation.py`, `supply_chain_canary.py`, `web_honeypot.py` | 50 | Mixed |
| SOAR | `soar_engine.py`, `incident_response.py` | 12 | Dual |
| SaaS | `saas_platform.py` | 25 | Org RBAC |
| Mesh | `deception_mesh.py` | 9 | Dual |
| Gateway | `gateway.py`, `gateway_v3.py` | 6 | HMAC token |
| Tools | `link_checker.py`, `detonate.py`, `llm_firewall.py`, `dml_engine.py`, `upload_service.py` | 30 | Mixed |
| Webhooks | `webhooks.py` | 15 | Dual |
| Public | `public_api.py`, `main.py` (pages) | 40 | Public |
| Admin | `main.py` (admin routes) | 35 | Session + admin |
| Infrastructure | `bgp_monitor.py`, `live_events.py`, `architecture_viz.py`, `knowledge_docs.py` | 15 | Mixed |
| Standalone apps | `breach-monitor/`, `ops-dashboard/`, `cowrie-analyzer/` | 60 | Per-app |

---

## 2. Schema Consistency Report

### 2.1 Top 10 Inconsistencies Found

| # | Issue | Severity | Count |
|---|-------|----------|-------|
| 1 | **Timestamp field naming**: 12+ different key names (`timestamp`, `created_at`, `ts`, `time`, `date`, `generated_at`, etc.) | HIGH | 100+ occurrences |
| 2 | **Error key names**: 3 competing patterns (`"error"`, `"message"`, dual `error+message`) | HIGH | 80+ locations |
| 3 | **Collection count keys**: `"count"` vs `"total"` vs `"results"` vs `"items"` vs `"entries"` | HIGH | 50+ locations |
| 4 | **Pagination**: Only 1 endpoint in entire codebase implements pagination (playbook history). All others use hard limits (50, 100) with no metadata. | CRITICAL | 400+ endpoints |
| 5 | **ID field names**: `"id"` (DB PK), `"public_id"`, `"uuid"` — mixed even within same module | MEDIUM | 30+ locations |
| 6 | **Boolean flags**: `"ok"` vs `"success"` — `incident_response.py` uses `"success"` while every other module uses `"ok"` | MEDIUM | 1 file |
| 7 | **Status codes**: 401/403 swapped in multiple blueprints (`bgp_monitor`, `asn_intelligence` return 403 for "Login required") | HIGH | 8+ locations |
| 8 | **Response wrapping**: Flat vs `"data":` wrapped — inconsistent even within same file | LOW | 5+ locations |
| 9 | **Auth gaps**: `fingerprint_corpus.py` (7 routes), `link_checker.py` (5 routes), `incident_response.py` (1 route) have NO auth | CRITICAL | 13 routes |
| 10 | **API key vs session**: Raven endpoints are split — `/api/raven/whoami` supports API keys but `/api/raven/campaigns` does not | MEDIUM | 2 routes |

### 2.2 Detailed Examples

**Timestamp inconsistency (same module, same domain):**
```json
// main.py canary list (line 11366):
{"ok": true, "canaries": [{"id": 1, "created_at": "2026-...", ...}], "total": 3}

// main.py canary alerts (line 11389):
{"ok": true, "alerts": [{"id": 1, "timestamp": "2026-...", ...}], "count": 5}
```
Key names: `created_at` vs `timestamp`, `total` vs `count` — same domain, both in canary endpoints.

**Error response inconsistency (same file, 20 lines apart):**
```json
// supply_chain_canary.py line 502:
{"ok": false, "error": "Missing token"}

// supply_chain_canary.py line 557:
{"error": "Token not found"}
```
No `"ok"` wrapper on the second response — clients parsing `data.ok` will crash.

---

## 3. Recommended API Standards

### 3.1 Unified Response Envelope

All JSON API responses MUST use this envelope:

```json
{
  "ok": true,
  "data": { ... },
  "metadata": {
    "request_id": "req_abc123",
    "trace_id": "trace_xyz789",
    "timestamp": "2026-07-18T12:00:00Z",
    "elapsed_ms": 42
  },
  "pagination": {
    "page": 1,
    "per_page": 50,
    "total": 487,
    "pages": 10,
    "has_next": true,
    "has_prev": false
  },
  "warnings": [],
  "deprecations": []
}
```

**Rules:**
- `ok`: Boolean — `true` for 2xx, omitted for errors
- `data`: The response payload — always present, `null` if empty
- `metadata.request_id`: UUIDv7 for every response
- `metadata.timestamp`: ISO 8601 UTC always
- `pagination`: Present on ALL collection endpoints (omitted for single-resource)
- `warnings`: Non-blocking issues (e.g., "ASN enrichment unavailable, results may be incomplete")
- `deprecations`: Per-field deprecation notices

### 3.2 Unified Error Envelope

```json
{
  "ok": false,
  "error": {
    "code": "auth_required",
    "message": "Login required to access this resource.",
    "details": null,
    "request_id": "req_abc123"
  }
}
```

**Error codes** (standardized):
| Code | HTTP | Meaning |
|------|------|---------|
| `auth_required` | 401 | No valid authentication |
| `permission_denied` | 403 | Authenticated but insufficient scope |
| `not_found` | 404 | Resource does not exist |
| `validation_error` | 400 | Invalid input |
| `rate_limited` | 429 | Too many requests |
| `quota_exceeded` | 402 | Usage limit reached |
| `conflict` | 409 | Resource state conflict |
| `unsupported_media` | 415 | Invalid content type |
| `payload_too_large` | 413 | Request body too large |
| `service_unavailable` | 503 | Dependency unavailable |
| `internal_error` | 500 | Unexpected server error |

### 3.3 Field Naming Convention

| Concern | Standard | Legacy (migrate from) |
|---------|----------|----------------------|
| Timestamps | `created_at`, `updated_at`, `deleted_at` (ISO 8601 UTC) | `timestamp`, `ts`, `time`, `date`, `generated_at`, `queried_at`, `scanned_at` |
| Entity ID | `id` (opaque string, not DB PK) | `public_id`, `uuid`, raw integer PKs |
| Collection size | `pagination.total` | `count`, `total`, `results`, `items`, `entries` |
| Success flag | `ok` (boolean) | `success` |
| Error | `error.code` + `error.message` | Raw `"error"`, `"message"`, dual error+message |
| User reference | `user_id` | `owner_user_id`, `user` |

### 3.4 Pagination Standard

ALL collection/list endpoints MUST support pagination:

```
GET /api/cowrie/sessions?page=1&per_page=50&sort=connected_at&order=desc
```

Query parameters:
- `page` (int, default 1)
- `per_page` (int, default 50, max 200)
- `sort` (string, field name)
- `order` (asc/desc, default desc)
- `before` / `after` (ISO timestamp, cursor-based alternative)

Response includes `pagination` block with `has_next`, `has_prev`, `total`, `pages`.

### 3.5 Filtering Standard

```
GET /api/campaigns?status=active&severity=critical&region=west-africa
GET /api/intel/items?source=cisa_kev&intel_type=vulnerability&since=2026-07-01
```

### 3.6 Authentication Headers

| Auth Type | Header | Usage |
|-----------|--------|-------|
| Session | Cookie: `ezm_session=<token>` | Browser clients |
| API Key | `Authorization: Bearer ezm_<key>:<secret>` | CLI, SDK |
| HMAC (server-to-server) | `X-Shipper-Signature: <hmac>` | Intel collector |

---

## 4. Intelligence API Schema Design

### 4.1 Campaign

```json
GET /api/v2/campaigns/:id

{
  "ok": true,
  "data": {
    "id": "camp_a1b2c3d4",
    "status": "active",
    "threat_level": "high",
    "unison_score": 78,
    "unison_verdict": "HIGH",
    "first_seen": "2026-07-10T08:00:00Z",
    "last_seen": "2026-07-18T12:00:00Z",
    "session_count": 47,
    "unique_ips": 12,
    "unique_asns": 5,
    "countries": ["NG", "GH", "ZA"],
    "regions": ["west-africa", "southern-africa"],
    "mitre_tactics": ["TA0002", "TA0004", "TA0006"],
    "mitre_techniques": ["T1059", "T1082", "T1003"],
    "tools": ["masscan", "hydra", "busybox"],
    "malware_families": ["mirai"],
    "active_periods": [
      {"start": "2026-07-10T08:00:00Z", "end": "2026-07-12T14:00:00Z"},
      {"start": "2026-07-15T02:00:00Z", "end": null}
    ],
    "evidence": {
      "similarity_score": 0.82,
      "corroboration_count": 3,
      "confidence": 0.78,
      "false_positive_risk": 0.12,
      "evidence_urls": ["/api/v2/evidence/ev_001", "/api/v2/evidence/ev_002"]
    },
    "actors": [
      {"id": "actor_x1y2z3", "role": "primary", "confidence": 0.92}
    ],
    "linked_intel": [
      {"id": "intel_abc123", "source": "cisa_kev", "title": "CVE-2026-..."}
    ],
    "graph": {
      "nodes": 23,
      "edges": 41,
      "density": 0.15,
      "url": "/api/v2/campaigns/camp_a1b2c3d4/graph"
    }
  }
}
```

### 4.2 Attacker Profile

```json
GET /api/v2/actors/:id

{
  "ok": true,
  "data": {
    "id": "actor_x1y2z3",
    "first_seen": "2026-06-01T00:00:00Z",
    "last_seen": "2026-07-18T11:00:00Z",
    "session_count": 128,
    "ips": ["45.x.x.x", "103.x.x.x"],
    "asns": [12345, 67890],
    "countries": ["NG", "GH"],
    "hasshes": ["abc123...", "def456..."],
    "ja3_hashes": ["ghi789..."],
    "sophistication": 0.72,
    "persistence": 0.85,
    "reputation_risk": 76,
    "unison_average": 62,
    "preferred_tactics": [
      {"tactic": "TA0004", "frequency": 0.85, "confidence": 0.90},
      {"tactic": "TA0006", "frequency": 0.72, "confidence": 0.85}
    ],
    "tool_signature": ["masscan", "busybox", "hydra"],
    "campaigns": [
      {"id": "camp_a1b2c3d4", "role": "primary"},
      {"id": "camp_e5f6g7h8", "role": "participant"}
    ],
    "deception_engagement": {
      "events": 5,
      "baits_deployed": 3,
      "baits_triggered": 2,
      "engagement_score": 0.65
    },
    "temporal_pattern": {
      "active_hours_utc": [2, 3, 4, 5, 6],
      "avg_session_duration": 184,
      "return_probability": 0.72,
      "typical_inter_arrival_hours": 48
    },
    "confidence": 0.88,
    "uncertainty_factors": [
      "IP diversity may indicate shared infrastructure",
      "HASSH rotation suggests multiple SSH clients"
    ],
    "graph": {
      "nodes": 8,
      "edges": 15,
      "url": "/api/v2/actors/actor_x1y2z3/graph"
    }
  }
}
```

### 4.3 Prediction

```json
GET /api/v2/actors/:id/prediction

{
  "ok": true,
  "data": {
    "actor_id": "actor_x1y2z3",
    "generated_at": "2026-07-18T12:00:00Z",
    "predicted_next_tactic": {
      "technique": "T1003",
      "name": "OS Credential Dumping",
      "probability": 0.72,
      "evidence": ["Observed T1082 in 85% of prior sessions", "T1003 follows T1082 in 65% of similar actors"],
      "confidence": 0.68
    },
    "predicted_next_tool": {
      "tool": "hydra",
      "probability": 0.55
    },
    "recommended_bait": {
      "type": "credential_canary",
      "reason": "Actor shows credential_access intent in prior sessions",
      "deployment_priority": 1
    },
    "return_probability": 0.72,
    "estimated_dwell_hours": 48
  }
}
```

---

## 5. Developer Experience

### 5.1 Versioning Strategy

```
/api/v1/*  — current (2024-2026), all existing endpoints
/api/v2/*  — next generation (2026+), unified schema, pagination, richer intel

Migration path:
  Phase 1: Deploy /api/v2/* alongside /api/v1/* (dual running)
  Phase 2: Add deprecation headers to /api/v1/* (Sunset: Sat, 01 Jan 2027)
  Phase 3: Remove /api/v1/* after 6-month deprecation window
```

### 5.2 Deprecation Strategy

```http
GET /api/v1/campaigns HTTP/1.1

HTTP/1.1 200 OK
Deprecation: true
Sunset: Sat, 01 Jan 2027 00:00:00 GMT
Link: </api/v2/campaigns>; rel="successor-version"
```

Response body includes `deprecations` array with per-field migration guidance.

### 5.3 Webhook Event Schema

```json
{
  "event_id": "evt_uuid",
  "event_type": "campaign.created",
  "version": "2.0",
  "timestamp": "2026-07-18T12:00:00Z",
  "actor": {
    "id": "actor_x1y2z3",
    "type": "attacker"
  },
  "data": {
    "campaign_id": "camp_a1b2c3d4",
    "threat_level": "high",
    "unison_score": 78,
    "session_count": 3,
    "initial_techniques": ["T1082", "T1059"]
  },
  "links": {
    "campaign": "/api/v2/campaigns/camp_a1b2c3d4",
    "actor": "/api/v2/actors/actor_x1y2z3"
  }
}
```

### 5.4 OpenAPI Improvements

- Generate from type annotations + docstrings
- Publish at `/api/openapi.json` and `/api/openapi.yaml`
- Include all v2 endpoints with full request/response examples
- Redoc/Swagger UI at `/api/docs`

### 5.5 SDK Generation

- Python SDK (`sdks/python/`) already exists — needs v2 schema update
- TypeScript SDK for frontend Vue apps
- Auto-generated from OpenAPI spec using `openapi-generator`

---

## 6. Migration Strategy

### Phase 1 — Foundation (Week 1-2)
- [ ] Deploy unified response envelope middleware
- [ ] Standardize error codes and error envelope
- [ ] Add `request_id`/`trace_id` to all responses
- [ ] Fix 401/403 status code semantics
- [ ] Add auth to unprotected endpoints (fingerprint_corpus, link_checker, incident_response)
- [ ] Add pagination to top-10 most-trafficked collection endpoints

### Phase 2 — Intelligence APIs (Week 3-4)
- [ ] Deploy `/api/v2/campaigns/:id` with full evidence/actor/intel linkage
- [ ] Deploy `/api/v2/actors/:id` with graph, temporal, deception data
- [ ] Deploy `/api/v2/actors/:id/prediction` with UNISON-driven probabilities
- [ ] Deploy `/api/v2/campaigns/:id/evolution` with merge/split history
- [ ] Add filtering to intel item list (`?source=&intel_type=&severity=&since=`)

### Phase 3 — Consistency (Week 5-6)
- [ ] Standardize timestamp field names across all modules
- [ ] Standardize ID fields (replace DB PKs with opaque strings)
- [ ] Standardize collection count keys to `pagination.total`
- [ ] Add pagination to ALL remaining collection endpoints
- [ ] Add deprecation headers to v1 endpoints slated for sunset

### Phase 4 — Developer Experience (Week 7-8)
- [ ] Publish full OpenAPI 3.1 spec for v1 + v2
- [ ] Generate updated Python SDK
- [ ] Deploy TypeScript SDK for frontend
- [ ] Webhook event schema catalog
- [ ] Migration guide + changelog

---

## 7. Auth Gap Remediation Priority

| Priority | Endpoint Group | Current State | Fix |
|----------|---------------|---------------|-----|
| P0 | `fingerprint_corpus.py` (7 routes) | No auth, no rate limits | Add `require_auth` + rate limits |
| P0 | `link_checker.py` (5 routes) | No auth, Redis budget only | Add `require_auth` or dual |
| P0 | `incident_response.py` (1 route) | No auth | Add `require_permission('playbook:write')` |
| P1 | Cowrie intel (12 routes) | Public/anonymized | Consistent auth model |
| P1 | Sandbox (5 routes) | Cookie-only | Add session/API-key |
| P1 | `/api/raven/campaigns`, `/api/raven/bgp-alerts` | Session-only | Add API key support |
| P2 | `/api/ip-reputation` | No rate limit | Add `10/min` |
| P2 | `/api/bulk-scan` | No rate limit | Add `5/min` |
| P2 | `/api/urlscan-result` | No rate limit | Add `10/min` |

---

*End of API audit and upgrade design.*
