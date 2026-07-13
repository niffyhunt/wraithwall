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
| Gateway | `gateway.py` | `/gateway/solve` |
| Canary service | `canary_service.py` | `/api/canary-service/*` |
| Architecture corpus | `architecture_viz.py` | `/api/architecture/corpus`, `/api/architecture/graph/<view_id>` |
| Platform health | `main.py` | `/api/platform/health` |

## Architecture visualization API

Authenticated session required. Serves allowlisted files from `docs/architecture/` — see `architecture_viz.py` `CORPUS_ALLOWLIST`.

## Breach monitor (separate app)

Proxied via `BREACH_MONITOR_INTERNAL_URL` when configured — not part of the main app's route table.

## Conventions

- Admin routes: `login_required` + `is_admin()`
- White-label: third-party vendor names stripped from user-facing output where policy applies
- SSRF guards on user-supplied URLs in scanning/detonation paths

## Full route map

For exhaustive route discovery, search `main.py` and blueprint modules, or inspect `docs/architecture/api_surface.json` in the Phase 8 corpus.