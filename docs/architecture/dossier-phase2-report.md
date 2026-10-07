# PHASE 2 STATUS: DONE (stopped). Phase 3 not started.

Customer-sensor protocol feeds the existing linker. Cowrie path untouched. Linker checksums match Phase 1.

## AUTHENTICATION

`POST /api/dossier/sensor/ingest`

Bearer `api_key:api_secret` plus HMAC headers. Scope `sensor:ingest`. No session shortcut. Fail-closed if key lookup, HMAC, nonce store, or tenant strict-check fails.

Existing `POST /api/campaigns/ingest` remains admin/session (`_require_admin` + `_raven_auth_context`). Not documented as the sensor protocol.

## TENANT BINDING

Tenant is `APIKey.tenant_id` or `user:{user_id}`, then `_strict_tenant_id`. JSON `tenant_id` is a forbidden field (400), not overwritten-and-accepted.

## CUSTOMER SENSOR CONTRACT

Allow-list Cowrie-shaped session fields the linker already consumes. Linker-owned intelligence fields rejected. Spec: `docs/architecture/dossier-sensor-contract.md`.

## IDEMPOTENCY

`SETNX dossier:sensor:idem:{tenant}:{sha256(session_id|Idempotency-Key)}` TTL 7d. Same body → 200 duplicate, no second ingest. Different body → 409. Concurrent SETNX: one winner (tested).

## REPLAY DEFENSE

HMAC over raw body via `generate_raven_api_signature`. Timestamp window 300s. Nonce SETNX 300s. Capture replay of the same nonce → 401 AUTH_REPLAY.

## RATE LIMITS / RESOURCE LIMITS

256 KiB body, 500 commands, 8192 command length, 60/min per key, 180/min per tenant. Burst test: 61st request is 429, not 500, and does not ingest.

## EXISTING SENSOR COMPATIBILITY

Cowrie still calls `ingest_session(session)` with no tenant_id and still fail-closes. Admin ingest still 403 without admin. Detonate untouched.

## OFFENSIVE TEST RESULTS

`tests/test_dossier_sensor.py` + mapper tests: **47 passed**.

AUTH-01..08, REPLAY-01..05, INPUT-01..10, TENANT-01..04, RESOURCE-01..04, REGRESSION-01..06 (weights/checksums/Cowrie source/admin ingest/linker reject-without-tenant), flag-off 404.

AUTH-04: keys have no `expires_at`. Test records that a 400-day-old key still works. That is a limitation, not expiry support.

## DEFENSIVE STATE-INTEGRITY RESULTS

Rejected auth/schema/replay/cross-tenant requests: `fake_corr.calls == []`. Oversized body: no ingest. Duplicate: one ingest. Conflict: first payload kept.

## REGRESSION RESULTS

Linker WEIGHTS / MIN_SIMILARITY_SCORE / HIGH_CONFIDENCE_THRESHOLD / CAMPAIGN_ALERT_THRESHOLD unchanged. `campaign.created` / `campaign.updated` still the only campaign events in the linker file.

## LINKER IMMUTABILITY RESULTS

sha256 identical to Phase 1 capture:

- campaign_correlator.py `f47f8ba30532f70b6d78e41894c92c36ff5f71fe2162b8170f2e77dafedb494f`
- src/wraithwall/campaign_correlator.py `2db9128cbd5752466933718622904a63158759f3898343ed44322a89c0e84f89`
- campaign_intel.py `5f0d526558d8e3dd8d4da5e1ed85e1ad5157cc52a892199d7c8719226a810143`
- webhooks.py `e0a1a420bff94381ba0c4777ab4967d7bb92a02f2e653c7a1d28a27faeaa53c9`

## FILES CHANGED

- `dossier_sensor.py` (new) — protocol, auth, schema, idempotency, limits
- `main.py` — register blueprint, `sensor:ingest` scope, origin-gate exempt, limiter wrap
- `tests/test_dossier_sensor.py` (new)
- `docs/architecture/dossier-sensor-contract.md` (new)
- `docs/architecture/dossier-phase2-report.md` (this file)
- `docs/architecture/dossier-rollback/correlator-checksums-before-phase2.json`
- `docs/architecture/dossier-rollback/correlator-checksums-after-phase2.json`

Unchanged: `campaign_correlator.py`, Cowrie, detonate, webhooks catalog, dossier packets, UI.

## ROUTES CHANGED

Added `POST /api/dossier/sensor/ingest`. Did not convert `/api/campaigns/ingest` in place (would mutate the frozen linker module).

## DATABASE / REDIS CHANGES

No new tables. Reuses `api_key` (hashed secret, `is_active`, `tenant_id`). Redis keys: `dossier:sensor:idem:*`, `dossier:sensor:nonce:*`, `dossier:sensor:rate:*`. Tests use an in-memory store when `TESTING=1` and Redis is absent.

## KNOWN LIMITATIONS

- API keys have no expiry timestamp; revoke is `is_active=False`.
- No dual-secret rotation window on API keys (create new + revoke old).
- HMAC canonicalization uses the existing Raven helper including its `\\n` literal.
- Sensor path does not apply the 30-day HTTP 402 billing gate.
- Idempotency/nonce in tests is process-local because pytest unsets REDIS_URL.
- One observation still does not force a campaign (linker threshold 3).
- Cowrie tenant gap remains (intentional).

## NOT IMPLEMENTED

Phase 3 packet download, `dossier.*` webhooks, SSRF-checked webhook URLs, operator UI, Phase 5 production e2e TEST sensor.
