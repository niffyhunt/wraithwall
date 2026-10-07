# Customer sensor contract (Phase 2)

**Status:** implemented. Phase 3 not started.

**Route:** `POST /api/dossier/sensor/ingest`

**Flag:** `DOSSIER_SENSOR_ENABLED` (`0`/`false`/`off` turns the route into 404). Default `1`.

This is the documented customer-sensor protocol. It is **not** the admin dump at `POST /api/campaigns/ingest`. Converting that path in place would have required editing `campaign_correlator.py`, which Phase 2 forbids (linker checksum freeze).

---

## Path reconstruction (before the new route)

```
POST /api/campaigns/ingest
  origin gate (Authorization or XHR)
  _require_admin()          session is_logged_in AND is_admin → 403
  _raven_auth_context()     User.tenant_id or user:{id} → 403
  data['tenant_id'] = tenant_id   (overwrite)
  CampaignCorrelator.ingest_session(data)
    _strict_tenant_id required else tenant_rejected
    Fingerprinter.build
    SimilarityEngine.compute against recent fingerprints
    HIGH_CONFIDENCE_THRESHOLD → _update_campaign
    MIN_SIMILARITY_SCORE → _consider_new_campaign (count ≥ CAMPAIGN_ALERT_THRESHOLD)
    else _track_for_future
  _create_campaign / _update_campaign persist Redis campaign:{tenant}:{id}
  emit_safe campaign.created / campaign.updated (thin payload)
  Telegram notify on create / every 5th session
```

Callers of `ingest_session()` today:

| Caller | Transport | tenant_id | Notes |
|---|---|---|---|
| `cowrie_intelligence._cross_module_enrich` | in-process thread | **absent** | fail-closed; unchanged |
| `intelligence_layer` | in-process | usually absent | fail-closed; writes old `campaign:{cid}` if it ever succeeds |
| `detonate.py` | in-process sync | **absent** | fail-closed; unchanged |
| SDK `campaign_ingest()` | HTTP `/api/campaigns/ingest` | client JSON, overwritten if admin session | admin/session only |
| Tests | none previously | | |

No Flask limiter was on `/api/campaigns/ingest`. Global `MAX_CONTENT_LENGTH` is 16MB. No idempotency. Retries can double-ingest. Admin ingest returns the full campaign dict (including internal fields).

Cowrie path was **not** modified.

---

## Authentication

Machine sensors, not browser sessions.

```
Authorization: Bearer <api_key>:<api_secret>
X-API-Timestamp: <unix seconds>
X-API-Nonce: <id charset>
X-API-Signature: HMAC-SHA256
```

HMAC reuses `main.generate_raven_api_signature` (existing primitive, not a new construction):

```
HMAC-SHA256(utf8(secret), utf8("{timestamp}\\n{nonce}\\n{METHOD}\\n{path}\\n{body}"))
```

`\\n` is the two-character sequence backslash + n, matching the live Raven helper.

Replay window: **300 seconds**. Nonce is `SETNX` for 300 seconds. Redis unavailable → **503**, not allow.

Tenant: `APIKey.tenant_id` or `user:{user_id}`. Then `CampaignCorrelator._strict_tenant_id`. Never from JSON.

Scope: `sensor:ingest` (or `admin:all`). Created through existing `/api/keys` now that the scope is in `VALID_SCOPES`.

Revoke: `APIKey.is_active = False` via existing `/api/keys/<id>/revoke`.

**Rotation limitation:** there is no dual-secret window on `APIKey`. Rotation is create a new key, then revoke the old one. `last_rotated` is unused for verification. Sensor ingest does **not** apply the 30-day HTTP 402 billing gate used by `require_permission`.

Secrets: `api_secret_hash` (bcrypt) plus `api_secret_enc` (Fernet, already used by Raven). Secret is not logged, not in URLs, not in campaign JSON, not in error bodies.

No session-cookie shortcut on this route.

---

## JSON allow-list

Required:

| field | rule |
|---|---|
| `session_id` | `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}` |
| `sensor` | same charset, max 64 |
| `commands` | non-empty array of strings |

Optional (linker actually reads these): `src_ip`, `src_port`, `connected_at`, `duration`, `login_attempts`, `command_timestamps`, `credential_attack`.

Rejected (400 `FORBIDDEN_FIELD` / `UNKNOWN_FIELD`): `tenant_id`, `campaign_id`, `threat_level`, `campaign_confidence`, `correlation_evidence`, `status`, fingerprint/identity/MITRE/tools/assignment fields, and any other key.

Hostile strings inside `commands` are **data**. They are length-checked, not HTML-escaped at ingest.

Content-Type must be `application/json`. Signature is over the **raw body**, not a re-serialized object.

---

## Idempotency

Key: `Idempotency-Key` header, or `session_id` if omitted. Scoped as:

`dossier:sensor:idem:{tenant}:{sha256(key)}`

Atomic `SETNX`, TTL 7 days.

| case | result |
|---|---|
| first submit | ingest, 200 `duplicate: false` |
| same tenant + same key + same body | 200 `duplicate: true`, **no** second `ingest_session` |
| same tenant + same key + different body | 409 `IDEMPOTENCY_CONFLICT`, no ingest |
| same session_id, different tenant | isolated (different Redis key) |
| same HMAC nonce | 401 `AUTH_REPLAY` |
| linker exception after SETNX | key deleted, client may retry |

Concurrent SETNX: one winner.

This is not a second matcher. The linker still decides campaigns.

---

## Limits

| limit | value |
|---|---|
| body | 256 KiB (before parse; 413) |
| commands | 500 |
| command length | 8192 |
| login_attempts | 50 |
| per-key | 60 / minute (429, not 500) |
| per-tenant | 180 / minute |
| Flask limiter wrap | 120 / minute additional |

Oversized / malformed requests do not call `ingest_session`.

---

## Success body

```
{"ok": true, "duplicate": false, "accepted": true, "session_id": "...", "campaign_id": "..."}
```

`campaign_id` only if the linker actually created/updated a campaign. One observation often returns no campaign (threshold 3). Internal campaign JSON is not returned.

---

## Existing sensors

`POST /api/campaigns/ingest` still admin/session. Cowrie still calls `ingest_session(session)` with no tenant_id and still fail-closes. Detonate unchanged.

---

## Not implemented (Phase 3+)

Dossier packets, `dossier.created` / `dossier.updated`, webhook HMAC delivery, operator UI, Phase 5 e2e TEST sensor against production Redis.
