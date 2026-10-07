# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is the **WraithWall Security Operations Hub** (`wraithwall.online`) — a production Flask
monolith serving public-facing security tools, an authenticated user dashboard, and a
large suite of active-defense / deception subsystems (honeypots, canaries, threat
correlation). It is deployed behind a reverse proxy (ProxyFix is configured for
`X-Forwarded-*`) and run under gunicorn; there is **no `__main__` block** — the WSGI
entrypoint is the module-level `app` object in `main.py`.

`breach-monitor/` is a **separate, standalone Flask application** with its own
`Procfile`, `Dockerfile`, requirements, and SQLite DB — it is not imported by the main
app. Treat it as an independent project.

## Commands

```bash
# Install deps (Python 3.12.8)
pip install -r requirements.txt

# Run the main app locally (dev mode disables HTTPS-only cookies / origin checks)
FLASK_ENV=development gunicorn main:app --bind 0.0.0.0:8000 --workers 1 --timeout 120

# Production-style run
gunicorn main:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120

# Run the standalone breach-monitor sub-app
cd breach-monitor && gunicorn app:app --bind 0.0.0.0:5000   # or: python app.py
#   worker:   python monitor.py      (background scanners)
#   telegram: python telegram_service.py
```

Tests live in `tests/` and use pytest fixtures. Run with `TESTING=1 FLASK_ENV=development SECRET_KEY=test-secret pytest`.

## Architecture

### The monolith (`main.py`, ~10k lines)
`main.py` holds the Flask `app`, **all ~30 SQLAlchemy models** (`db.Model` subclasses:
`User`, `APIKey`, `AuditLog`, `SessionDNA`, `CanaryRecord`, `HoneyToken`, etc.), the
auth system, server-rendered page routes, the `/api/...` JSON routes, and the scheduler
wiring. New models and core routes generally go here.

- **DB**: `db = SQLAlchemy(app)` using `DATABASE_URL` (Postgres in prod, falls back to
  `sqlite:///demo_requests.db`). Tables are created at startup via `db.create_all()` in
  an `app.app_context()` block at the bottom of the file; Alembic is available but the
  live path is create_all + idempotent seed functions (honey tokens, canary records).
- **Auth**: session-cookie based (`ezm_session`), `Flask-Bcrypt`, 2FA via `pyotp`,
  trusted devices, backup codes. Protect routes with the `login_required` decorator
  (defined in `main.py`).
- **Background work**: a single `APScheduler` `BackgroundScheduler` (bottom of `main.py`)
  runs periodic jobs (model retraining, breach/paste/github scans, BGP monitor, daily
  digest, canary checks). Separately, `start_cowrie_watcher()`,
  `start_campaign_engine()`, `start_propagation_network()`, `start_asn_engine()`, and
  `start_bgp_monitor()` spin up long-running engine threads at import time. **These run
  in every gunicorn worker** — be mindful when changing worker count.

### Subsystem blueprints
Each major feature is a Flask Blueprint in its own top-level module, imported and
registered in `main.py` (~lines 751–764). They share `main.py`'s DB/Redis but keep their
routes and logic isolated:

| Module | Blueprint | Purpose |
|---|---|---|
| `link_checker.py` | `link_checker_bp` | Suspicious URL/domain reputation scanning |
| `llm_honeypot.py` | `llm_honeypot_bp` | LLM-driven honeypot responses to attackers |
| `cowrie_intelligence.py` | `cowrie_intel_bp` | Parses Cowrie SSH/Telnet honeypot logs (MITRE mapping, HASSH, EIDETIC dedup, VANISH geo, MIRAGE fidelity, CRED-STORM, REVERB, CRYSTAL triage, SPECTRA IOCs, LLM enrichment with daily budget) |
| `campaign_correlator.py` | `campaign_bp` | Correlates attacks into campaigns (uses scipy) |
| `credential_propagation.py` | `cred_prop_bp` | Tracks planted-credential propagation (deterministic canary generation) |
| `asn_intelligence.py` | `asn_intel_bp` | ASN/abuse intelligence + AbuseIPDB reporting |
| `bgp_monitor.py` | `bgp_bp` | BGP hijack/route monitoring |
| `supply_chain_canary.py` | `supply_chain_bp` | Canary tokens for supply-chain detection |
| `fingerprint_corpus.py` | `corpus_bp` | Request fingerprint collection (`fingerprint_request` runs as a `before_request`) |
| `dml_engine.py` | (routes via `register_dml_routes(app)`) | Deception Markup Language — trap/canary config validation & execution |
| `incident_response.py` | `incident_response_bp` | Incident playbooks |
| `deception_event_bus.py` | `deception_bus_bp` | Unified deception telemetry (events, per-IP index, pivot + cowrie→beacon→reverse chain alerts, immutable log) |
| `intelligence_layer.py` | (helpers + intel API) | Evidence/Conclusion reasoning, AttackerMemory, IntelligenceGraph, ThreatReasoner, adaptive risk |
| `behavioral_dna.py` / `botmind_classifier.py` / `chronos_temporal.py` / `vector_transitions.py` / `echo_intent.py` / `spectra_ioc.py` / `forge_infra.py` | (helpers) | Persistent actor identity, keystroke bot/human classification, temporal patterns, command-transition Markov, intent classification, IOC store, infra reuse graph |
| `detonate.py` | `detonate_bp` | URL detonation sandbox (ephemeral Docker, mitmproxy egress, async queue, STIX export) |
| `replay_tty.py` | `replay_bp` | TTY replay of Cowrie sessions |
| `payment_engine.py` | `payment_bp` | Paystack/BTCPay payments + SSE events |
| `public_api.py` | `public_bp` | Unauthenticated public stats (reads from Redis) |
| `gateway.py` / `gateway_v3.py` / `gateway_v3_engine.py` | `gateway_bp` / `gateway_v3_bp` | Proof-of-work / scoring challenge gate + IP blocklist (Redis-backed) |

`gateway.py` exposes helpers (`_has_valid_gateway_cookie`, `is_ip_blocked`,
`_client_ip`, `_audit`) used directly by `main.py`'s request pipeline.

There is also `src/wraithwall/` — an importable package mirroring the top-level
modules (blueprint factory `create_app`, `Client` SDK) with vendored copies of the
same blueprints plus `fusion_stix`, `live_events`, `recalibration`, `unison_score`.
Prefer editing top-level modules unless a task explicitly targets the package.

### Red-team harness (`harness/`)

Autonomous hunting framework for authorized red-team/bug-bounty work, wired to
`hunt.py` (codex scan → nuclei → Buzz alert) and `core/harness.py` (full hunt
loop: recon → test generation → execution → analysis → chain → report). The AI
brain is `agent/deepseek_backend.py` / `agent/codex_adapter.py` — an
OpenAI-compatible chat endpoint configured via `DEEPSEEK_API_KEY`,
`DEEPSEEK_BASE_URL`, `AGENT_MODEL` (defaults: `deepseek-v4-pro` or Qwen MaaS
`qwen3.7-max`). Exploit engines live in `exploit/`; guardrails in
`core/ethical_governor.py` (no destructive ops, scope enforcement, rate limits)
and `core/stealth_engine.py` (header rotation, jitter, WAF backoff); VPN is
enforced at startup (`_verify_vpn`).

### External services (via env)
Redis (caching, gateway state, public stats), PostgreSQL, and a wide set of APIs keyed
through `.env`: Groq / OpenAI / Anthropic / DeepSeek / HuggingFace (LLM), VirusTotal,
AbuseIPDB, URLScan, WhoisXML, Resend (email), Telegram + Discord (alerts), AWS/S3 (audit
log archival). All secrets live in `.env` (gitignored — see below); there are **no
hardcoded fallback secrets** for real credentials, so missing keys degrade features
gracefully rather than crashing.

### Frontend
Jinja templates in `templates/` handle legacy/public pages. Five Vue 3 + Vite applications
(`frontend/`, `frontend-home/`, `frontend-auth/`, `frontend-landing/`, `frontend-blog/`)
build into Flask-served static directories (`static/app/`, `static/home_dist/`, etc.).
Landing and blog are SSG (vite-ssg) for SEO; auth and console are SPAs.

## Conventions that affect how you write code

- **Origin gate**: a `before_request` (`check_xhr_for_state_change` in `main.py`) rejects
  state-changing (`POST/PUT/DELETE/PATCH`) JSON requests to `/api/...` with
  `403 {"error": "Invalid request origin"}` unless they carry `X-Requested-With`,
  a same-origin `Sec-Fetch-Site`, or an `Authorization` header. First-party `fetch`
  calls must send `X-Requested-With`. To exempt an endpoint, add its path to the
  `exempt` list in that function. (See memory: `origin-gate-xhr-header`.)
- **`IS_PRODUCTION`** = `os.getenv('FLASK_ENV') != 'development'`. Production forces HTTPS
  and secure cookies; set `FLASK_ENV=development` for local work.
- **White-labeling**: third-party vendor names (VirusTotal, AbuseIPDB, etc.) are stripped
  from user-facing UI/output and only named in the privacy policy. (See memory:
  `white-label-policy`.)
- **UI theme split**: public pages use a light cream+white theme; authenticated app
  dashboards use a dark theme. (See memory: `ui-design-direction`, `light-theme-token-set`.)
- Adding a subsystem: create a module exposing a `*_bp` Blueprint (or a `register_*`
  function), import it near the top of `main.py`, and register it in the blueprint block.

## Secrets / git hygiene

`.env`, `*.env`, `.env.*`, DB files, ML models, logs, and `.canary*` files are all
gitignored. **Never commit secrets** — the `.gitignore` is deliberately aggressive about
`.env` backups (e.g. `.env.save`) for this reason. The default branch is `main`.
