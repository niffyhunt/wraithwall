# DOSSIER_CONTRACT (Phase 1)

**Status:** FROZEN as a mapping of linker campaign JSON. No packet route, no ingest change, no webhook, no UI.

**Date:** 2026-09-02

**Code:** `dossier_contract.py` (`campaign_to_dossier`), `docs/architecture/dossier-contract.schema.json`

Dossier reads what the linker already decided. It does not re-score, re-cluster, or invent threat buckets.

---

## Contradictions vs the brief (not silently reconciled)

### 1. Live campaign store is empty

Redis db0 has ~111k keys and 500+ `cowrie_completed:*` sessions.

Campaign bodies: **0**. `SCAN campaign:*` returned nothing. Postgres `campaign_snapshot`: **0** rows.

Legacy un-tenanted indexes still hold two orphan ids (bodies expired with TTL):

| key | type | contents |
|---|---|---|
| `campaigns:active` | list | `62c057c254806ae8`, `7eeecfc2c9de7f48` |
| `active_campaigns` | zset | same two ids |

Current linker keys are `campaign:{tenant}:{id}`, `active_campaigns:{tenant}`, `campaigns:{tenant}:active` (`campaign_correlator.py` `_campaign_key` / `_active_key` / `_active_list_key`). The orphan ids sit on the pre-tenant names used by `src/wraithwall/campaign_correlator.py` and by `intelligence_layer.py` (`setex("campaign:{cid}", ...)`).

**Done-check impact:** there are no stored live campaign JSON documents to 1:1 against. Phase 1 sampled the **emit shape** from `_create_campaign` by dry-running five real `cowrie_completed` sessions with `correlator.redis = None` (confirmed `campaign:*` still 0 afterwards).

### 2. Cowrie does not set `tenant_id` before ingest

`cowrie_intelligence.py` `_cross_module_enrich` (around 1259-1263) starts:

```python
get_correlator().ingest_session(session)
```

The session dict from `cowrie_completed` has **no** `tenant_id` (400 sessions scanned; 0 had the field).

`CampaignCorrelator.ingest_session` (812-820) fail-closes:

```python
if not session.get('commands') or not self._strict_tenant_id(session.get('tenant_id')):
    self.metrics['tenant_rejected'] += 1
    return None
```

That is why the live linker is not filling `campaign:{tenant}:*`. **Cowrie path was not changed** (forbidden).

`detonate.py` synthetic ingest also omits `tenant_id`.

### 3. Webhook catalog vs live emit

Catalog `payload_example` for `campaign.created` / `campaign.updated` is `{campaign_id, threat_level, session_count}` (`webhooks.py` 199-223). No `dossier.*`.

Live emit is slightly richer, still not a case file:

- `campaign.created` (`_create_campaign` 1104-1110): `campaign_id`, `threat_level`, `session_count`, `unique_ips[:20]`, `status`
- `campaign.updated` (`_update_campaign` 1022-1027): `campaign_id`, `session_count`, `threat_level`, `campaign_confidence`

Go catalog (`backend-go/internal/webhookapi/api.go`) matches the Python `data_schema`, not the three-field example.

### 4. `backend-go/internal/tenant` is BGP, not campaigns

`tenant.Strict` / `AlertsKey` / `StateKey` build `bgp_monitor:*:{tenant}` keys. Campaign fail-closed scoping is Python: `_strict_tenant_id` and `campaign:{tenant}:{id}`.

Verified fact ("linker output is the source of truth") wins. Phase 2 must reuse the **campaign** tenant pattern, not BGP Redis keys.

### 5. Ingest "admin + tenant" (evidence for Phase 2; not implemented this phase)

`POST /api/campaigns/ingest` (`campaign_correlator.py` 1362-1381):

1. `_require_admin()` (1305-1312): session `is_logged_in() and is_admin()` else **403** `Admin authentication required`. On `ImportError`, it **returns None** (fail-open). It does **not** accept an API key.
2. `_raven_auth_context()` (`main.py` 5549-5554): tenant from `User.tenant_id` or `user:{id}` for a session user. Else **403** `Tenant authorization required`.
3. Server overwrites `data['tenant_id'] = tenant_id` then `ingest_session(data)`.

Cowrie-shaped JSON, not a documented customer sensor protocol. Not a hashed tenant sensor key.

---

## Sample method

| # | Source | threat_level on create | threat_level if `_assess_threat` run now | session_count | notes |
|---|---|---|---|---|---|
| 1-5 | dry-run `_create_campaign` on five real `cowrie_completed` sessions (1 command each) | `medium` | `low` | 1 | redis=None; no persist |
| stored | Redis `campaign:{tenant}:{id}` | n/a | n/a | n/a | 0 bodies |
| stored | Postgres `campaign_snapshot` | n/a | n/a | n/a | 0 rows |

All five dry-runs shared the same **25** top-level keys (union listed below). Create path never writes `low` or `critical`; those appear only after `_assess_threat` on update (`score>=60 critical`, `>=40 high`, `>=20 medium`, else `low`). Single-session dry-runs assess `low` because `session_count=1` and `human_confidence` is null.

**Spanning low/medium/high from stored live records: not possible today.** Contract still surfaces the linker enum as-is. No new bucket scheme.

---

## Linker campaign JSON (emit)

Source: `CampaignCorrelator._create_campaign` (1056-1094) plus fields `_update_campaign` mutates in place (last_seen, session_count, sensors_hit, unique_ips, session_ids, correlation_evidence, campaign_confidence, tools, threat_level).

GET `/api/campaigns/<id>` pops `representative_fingerprint` before returning (1359). Dossier may read it internally to project `normalized_commands`, then drop the blob.

### Union of top-level keys (5/5 dry-runs)

`actor_uuids`, `asns`, `campaign_confidence`, `campaign_id`, `command_pattern_hash`, `correlation_evidence`, `countries`, `deception_events`, `first_seen`, `human_confidence`, `last_seen`, `mitre_stages`, `mitre_techniques`, `representative_fingerprint`, `sensors_hit`, `session_count`, `session_ids`, `session_pacing`, `status`, `tenant_id`, `threat_level`, `tool_sequence`, `tool_signatures`, `tools`, `unique_ips`

`correlation_evidence[]` keys: `session_id`, `score`, `confidence`, `dims`, `evidence`, `ts`

`representative_fingerprint` keys include `src_ip`, `src_port`, `sensor_id`, `feature_vector`, `normalized_commands`, `command_ngrams`, `inter_command_timing` (internal).

---

## Field-provenance table

| DOSSIER_CONTRACT field | Kind | Exact linker source path |
|---|---|---|
| `schema_version` | contract metadata | not a linker field; const `"1"` |
| `campaign_id` | as-is | `campaign.campaign_id` |
| `status` | as-is | `campaign.status` |
| `threat_level` | as-is | `campaign.threat_level` (create: medium/high; update: `_assess_threat` low/medium/high/critical) |
| `campaign_confidence` | as-is | `campaign.campaign_confidence` |
| `session_count` | as-is | `campaign.session_count` |
| `first_seen` | as-is | `campaign.first_seen` |
| `last_seen` | as-is | `campaign.last_seen` |
| `identity.command_pattern_hash` | as-is | `campaign.command_pattern_hash` |
| `identity.tools` | as-is | `campaign.tools` |
| `identity.tool_sequence` | as-is | `campaign.tool_sequence` |
| `identity.session_pacing` | as-is | `campaign.session_pacing` |
| `identity.human_confidence` | as-is | `campaign.human_confidence` |
| `identity.normalized_commands` | derived | `campaign.representative_fingerprint.normalized_commands` (projection; fingerprint blob is not in the packet) |
| `identity.actor_uuids` | as-is | `campaign.actor_uuids` |
| `evidence.session_ids` | derived | `campaign.session_ids` union `campaign.correlation_evidence[].session_id` |
| `mitre_techniques` | as-is | `campaign.mitre_techniques` |
| `mitre_stages` | as-is | `campaign.mitre_stages` |
| `deception_events` | as-is | `campaign.deception_events` |

### Excluded (present on linker JSON, must not leave the building)

| Linker path | Why |
|---|---|
| `unique_ips` | attacker network identifiers; spec: not IP-as-identity |
| `sensors_hit` | infra / sensor hostnames |
| `asns` | attacker/infra network |
| `countries` | coarse geo of attacker IPs |
| `tenant_id` | ownership is server-side; not a case-file field |
| `representative_fingerprint` (whole) | src_ip, feature_vector, timing, sensor_id |
| `correlation_evidence[].dims` / `.score` / `.confidence` / `.evidence` | raw scorer internals |
| `tool_signatures` | per-tool scorer confidences; names already in `tools` |

No field in the contract is a new scorer output.

---

## Correlator checksums (before Phase 1 writes)

See `docs/architecture/dossier-rollback/correlator-checksums-before-phase1.json`.

| path | sha256 |
|---|---|
| `campaign_correlator.py` | `f47f8ba30532f70b6d78e41894c92c36ff5f71fe2162b8170f2e77dafedb494f` |
| `src/wraithwall/campaign_correlator.py` | `2db9128cbd5752466933718622904a63158759f3898343ed44322a89c0e84f89` |
| `campaign_intel.py` | `5f0d526558d8e3dd8d4da5e1ed85e1ad5157cc52a892199d7c8719226a810143` |
| `webhooks.py` | `e0a1a420bff94381ba0c4777ab4967d7bb92a02f2e653c7a1d28a27faeaa53c9` |

`SimilarityEngine.WEIGHTS` left untouched. Env thresholds match source defaults (`MIN_SIMILARITY_SCORE=0.60`, `HIGH_CONFIDENCE_THRESHOLD=0.85`, `CAMPAIGN_ALERT_THRESHOLD=3`).

---

## Phase 1 Done checks

| Check | Result |
|---|---|
| Contract fields map 1:1 onto linker emit keys (or marked derived) | PASS, table above |
| Five samples, same key union | PASS on dry-run emit; FAIL on stored live JSON (0 bodies) |
| Samples spanning low/medium/high stored threat_level | FAIL (create=medium, assess=low; no stored campaigns) |
| No new scorer fields | PASS |
| No clustering modules | PASS |
| Cowrie linker path unchanged | PASS |

**Phase 2 is not started.** Stored-record spanning and live 1:1 against Redis bodies need either campaigns the linker already persisted, or an operator decision to allow a later-phase TEST ingest (Phase 5) to populate them. Populating them in Phase 1 would run ahead of the documented sensor contract.
