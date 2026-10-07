# API overview

WraithWall exposes JSON APIs under `/api/...` from the Flask monolith and subsystem blueprints. This is an index — not an OpenAPI spec.

## Public (unauthenticated)

| Endpoint | Purpose |
| -------- | ------- |
| `GET /api/public/stats` | Aggregated public telemetry for landing page |
| `GET /api/health` | Basic health (may require auth in production — check deployment) |

Rate limits apply. See `public_api.py`.

## Authentication

Session cookie (`ezm_session`) for browser clients. API keys (`Authorization: Bearer key:secret`) for programmatic access with scoped permissions.

State-changing JSON requests to `/api/...` require `X-Requested-With: XMLHttpRequest` or same-origin `Sec-Fetch-Site` (origin gate in `main.py`).

## Major API groups

| Area | Module | Examples |
| ---- | ------ | -------- |
| Link / URL intelligence | `link_checker.py` | `/api/link/scan/stream`, `/api/link/detonate` |
| Cowrie intelligence | `cowrie_intelligence.py` | `/api/cowrie/sessions`, `/api/cowrie/stats`, `/api/cowrie/stream` |
| Campaigns | `campaign_correlator.py` | `/api/campaigns/stats` |
| **Phase 3 adversary intelligence** | `intelligence_layer.py` | `/api/intelligence/session/<id>/brief`, `/api/intelligence/attacker/<id>`, `/api/intelligence/correlate` |
| Gateway | `gateway.py` | `/gateway/solve` |
| Canary service | `canary_service.py` | `/api/canary-service/*` |
| Architecture corpus | `architecture_viz.py` | `/api/architecture/corpus`, `/api/architecture/graph/<view_id>` |
| Platform health | `main.py` | `/api/platform/health` |

Full intelligence design: [docs/intelligence.md](intelligence.md). OpenAPI tag **Intelligence** in `static/api_dist/openapi.json`.

## Architecture visualization API

Authenticated session required. Serves allowlisted files from `docs/architecture/` — see `architecture_viz.py` `CORPUS_ALLOWLIST`.

## Breach monitor (separate app)

Proxied via `BREACH_MONITOR_INTERNAL_URL` when configured — not part of the main app's route table.

## Developer webhooks (platform v2.1)

Outbound Stripe/GitHub-style webhooks live in `webhooks.py`.

| Endpoint | Purpose |
| -------- | ------- |
| `GET /api/webhooks/events` | Event catalog, signature/retry/KMS/worker metadata |
| `GET /api/webhooks/events/<type>/schema` | JSON Schema for envelope + data |
| `GET /api/webhooks/openapi.json` | OpenAPI 3 fragment |
| `GET /api/webhooks/health` | Queue depth, KMS backend, platform version |
| `CRUD /api/webhooks/endpoints…` | Session or `Authorization: Bearer key:secret` |

**Signing:** `X-WraithWall-Signature: t=<unix>,v1=<hex>[,v1=<hex>]` over `{timestamp}.{raw_body}`. Dual-active rotation keeps the previous secret valid for 24h.

**Secrets at rest (KMS):** `WEBHOOK_KMS_BACKEND=fernet` (default, `enc:v1:`), `aws` (`enc:aws:`, needs `WEBHOOK_AWS_KMS_KEY_ID` + boto3), or `vault` (`enc:vault:`, transit HTTP). Optional rewrap: `WEBHOOK_KMS_REWRAP=1`.

**Delivery workers:** scheduler drains every minute; multi-worker via Redis BRPOP + soft claim. Scale with:

```bash
python3 scripts/webhook_worker.py --concurrency 8
# WEBHOOK_WORKER_CONCURRENCY=4
```

**Local DX CLI:**

```bash
python3 scripts/wraithwall_webhooks.py listen --tunnel --register --teardown \
  --events webhook.test,canary.triggered
```

**v2.1 intelligence events:** `dna.actor.created`, `dna.actor.merged`, `ioc.discovered` (platform-scoped; produced by behavioral DNA + Spectra IOC engines).

Portal: `/webhooks` (authenticated) and API docs under `#/webhooks`.

## Conventions

- Admin routes: `login_required` + `is_admin()`
- White-label: third-party vendor names stripped from user-facing output where policy applies
- SSRF guards on user-supplied URLs in scanning/detonation paths

## Full route map

For exhaustive route discovery, search `main.py` and blueprint modules, or inspect `docs/architecture/api_surface.json` in the Phase 8 corpus.