# Architecture Visualization — Integration Plan

**Generated:** 2026-07-09  
**Source commit:** `0b8d520492767ee067c6ea33350cc7ba24a30164`  
**Phase:** 8 — Visualization Implementation

## 1. Integration Surface

| Layer | Path | Auth | Purpose |
|-------|------|------|---------|
| SPA route | `/console#/architecture` | `login_required` (console gate) | Operator visualization hub |
| Corpus API | `GET /api/architecture/corpus` | `@login_required` | List allowlisted corpus files |
| Corpus file | `GET /api/architecture/corpus/<file>` | `@login_required` + rate limit | Serve single JSON artifact |
| Graph query | `GET /api/architecture/graph/<view_id>` | `@login_required` + depth/node caps | Pre-transformed graph for view |
| Runtime health | `GET /api/platform/health` | `@login_required` | Existing — health overlay |
| Cowrie stats | `GET /api/cowrie/stats` | `@login_required` | Existing — pipeline overlay |
| Cowrie SSE | `GET /api/cowrie/stream` | `@login_required` | Existing — event pulse (5s poll SSE) |
| Live multiplex | `GET /api/live/events?streams=` | `@login_required` | SSE cowrie/deception/detections/bgp/system |
| Campaigns | `GET /api/campaigns/stats` | `@login_required` | Existing — campaign overlay |

No new public endpoints. Corpus never served from `/static/` unauthenticated.

## 2. Module Boundaries

```
architecture_viz.py          # Flask blueprint — corpus + graph query only
frontend/src/views/ArchitectureView.vue
frontend/src/architecture/   # corpus loaders, graph transforms, view configs
frontend/src/components/architecture/
```

Production deception modules (`canary_service.py`, `credential_propagation.py`, etc.) are **not modified**. Visualization reads corpus + existing APIs only.

## 3. Data Flow

```
docs/architecture/*.json
        ↓ (authenticated API)
useCorpus.js → view-specific transform → GraphCanvas
        ↓
RuntimeOverlay ← usePoll(/api/platform/health) ← live values
              ← useSSE(/api/cowrie/stream)     ← optional pulse
```

**Tie-break:** structure from corpus; runtime values from live API.

## 4. Degradation Chain

1. SSE (`/api/cowrie/stream`) for cowrie_pipeline pulse
2. Polling (`usePoll`) for health/stats when SSE unavailable
3. Corpus snapshot only — no fake real-time

## 5. Environment Separation

- `VITE_ARCHITECTURE_LIVE=1` — enable live telemetry overlay (default off in dev)
- Dev builds without flag use corpus `visualization_state.json` only
- Prod console always enables live overlay for authenticated operators

## 6. Registration

1. `architecture_viz.py` registered in `main.py` blueprint block
2. `frontend` route `/architecture` added to `router.js`
3. NavRail entry under Console section
4. `npm run build` in `frontend/` → `static/app/`

## 7. Tests Required

- `sanitize.test.js` — XSS payload inert
- `accessTier.test.js` — Tier 3 fields blocked
- `corpusLoader.test.js` — manifest + allowlist

## 8. Assumptions

- Entire visualization is internal/authenticated (Step 2.1 default)
- Executive Overview uses same tier as other views unless separate redacted API is built later