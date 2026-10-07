# Phase 3 — Intelligence Layer

WraithWall Phase 3 transforms event detection into **adversary analysis**.

Module: `intelligence_layer.py` (deployment module — not part of the published package)

## Goals

| Goal | Mechanism |
| ---- | --------- |
| Attribution | Multi-signal correlation + durable attacker memory |
| Campaign understanding | Evolving campaign records with evidence trails |
| Explainability | Every score/conclusion cites evidence + confidence + uncertainty |
| Automation | Async enrichment worker; never blocks request traffic |
| Analyst speed | Investigation brief (who / what / why / how / when / next) |

## Architecture

```
Cowrie session close
        │
        ▼
_cross_module_enrich (cowrie_intelligence)
        │
        ├── campaign_correlator.ingest_session (thread)
        ├── behavioral_dna.process_session
        ├── intel_core.run_intel_core_enrichment
        └── intelligence_layer.run_intelligence_enrichment
                 │  (enqueue only on hot path)
                 ▼
           Redis queue / local deque
                 │
                 ▼
        enrich_session_sync (background worker)
                 │
                 ├── AttackerMemory.update_from_session
                 ├── multi-signal campaign update
                 ├── compute_adaptive_risk
                 ├── ThreatReasoner.reason_about_session
                 ├── predict_attacker
                 └── IntelligenceGraph.record_session
```

## Correlation signals

Weighted multi-signal model (`SIGNAL_WEIGHTS`):

- Source IP, ASN, country
- HASSH / JA3 / User-Agent
- Command simhash, tool overlap, credential reuse
- MITRE technique overlap
- Behavioral DNA hash
- Timing window
- Deception bus engagement

Campaigns accumulate: `session_ids`, `tools`, `mitre_*`, `correlation_evidence`, `campaign_confidence`.

## Attacker memory

Redis key `intel:attacker:{actor_id}` (default TTL 90 days).

Tracks reputation, sophistication, persistence, objectives, techniques, infrastructure history, campaign membership. Evolves on every enriched session; does not reset per session.

Actor ID resolution order: DNA `actor_uuid` → HASSH → IP → session fallback.

## Threat reasoning

`ThreatReasoner` is **not** a chatbot. It produces deterministic conclusions:

- Seen before?
- Automation vs interactive?
- Credential harvesting?
- Lateral movement / privilege escalation?
- Campaign relatedness?

Rules:

1. Every claim has evidence
2. Never invent related session IDs without Redis proof
3. Always expose confidence and uncertainty text

Optional LLM narrative may be added later **only** as presentation over these conclusions.

## Adaptive risk

`compute_adaptive_risk` blends:

- UNISON base fusion (`unison_score.py`)
- Attacker memory (reputation / persistence / sophistication)
- Campaign confidence
- Deception engagement
- MITRE progression depth
- Recurrence

Critical scores without multi-signal corroboration are capped (stability guard).

## Intelligence graph

Node types: `attacker`, `infrastructure`, `session`, `credential`, `technique`, `campaign`, `victim`, `deception`, `evidence`.

Export via `/api/intelligence/graph/{type}/{id}?depth=2` for future visualization.

## Prediction

Evidence-backed estimates (with uncertainty):

- Next MITRE stage (kill-chain transition model)
- Likelihood of return (memory + optional Chronos)
- Escalation probability
- Infrastructure / credential reuse
- Campaign expansion

## API surface

| Endpoint | Purpose |
| -------- | ------- |
| `GET /api/intelligence/health` | Worker + queue |
| `GET /api/intelligence/session/<id>/brief` | Analyst package |
| `GET /api/intelligence/session/<id>/reason` | Reasoning |
| `GET /api/intelligence/session/<id>/risk` | Adaptive risk |
| `GET /api/intelligence/session/<id>/predict` | Predictions |
| `POST /api/intelligence/session/<id>/enrich` | Queue enrich (`?sync=1`) |
| `GET /api/intelligence/attacker/<id>` | Memory profile |
| `GET /api/intelligence/attacker/by-ip/<ip>` | IP → actor |
| `GET /api/intelligence/campaign/<id>/summary` | Campaign intel |
| `GET /api/intelligence/campaign/<id>/graph` | Campaign graph |
| `GET /api/intelligence/graph/<type>/<id>` | Graph export |
| `POST /api/intelligence/correlate` | Session correlation |
| `POST /api/intelligence/attribution` | Attribute session |

SDKs: Python `WraithWallClient.investigation_brief` / JS `investigationBrief`, etc.

OpenAPI: `static/api_dist/openapi.json` tag **Intelligence**.

## Performance

| Control | Default |
| ------- | ------- |
| Hot path | enqueue only |
| Worker | daemon thread per engine-leader process |
| Queue | Redis `intel:enrich_queue` + in-process fallback |
| Result cache | `intel:session:{id}` |
| Memory TTL | 90 days (`INTEL_MEMORY_TTL`) |
| Graceful degrade | No Redis → ephemeral profiles; APIs return 503/empty where needed |

## Tests

```bash
PYTHONPATH=. TESTING=1 FLASK_ENV=development SECRET_KEY=test pytest tests/test_intelligence_layer.py -v
```

## Competitive stance (design notes)

| Capability | Commodity SIEM/XDR | WraithWall Phase 3 |
| ---------- | ------------------ | ------------------ |
| Alert volume | High, session-local | Campaign + actor dossiers |
| Deception feedback | Rare | First-class correlation signal |
| Explainability | Opaque ML scores | Mandatory evidence + uncertainty |
| Honeypot kill-chain | Often siloed | MITRE + intent + DNA fused |
| Operator cost | Heavy triage | Investigation brief compresses 6 questions |

Prioritize strengths: deception-aware multi-signal correlation, long-horizon attacker memory, and non-blocking enrichment — not chatbot wrappers.
