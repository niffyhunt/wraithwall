[![PyPI](https://img.shields.io/pypi/v/wraithwall?style=flat-square)](https://pypi.org/project/wraithwall/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](https://github.com/niffyhunt/wraithwall/blob/main/LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/wraithwall?style=flat-square)](https://pypi.org/project/wraithwall/)
[![Donate](https://img.shields.io/badge/Support-Open%20Collective-7FADF2?style=flat-square&logo=opencollective&logoColor=white)](https://opencollective.com/wraithwall)

# WraithWall

**Deception-and-threat-intelligence platform.** Honeypots, attacker identity,
MITRE ATT&CK mapping, incident-response playbooks, active-defense gateway and
a public intelligence API — deployed as one Flask application you run yourself.

WraithWall takes hostile traffic at the perimeter (SSH/SHTTP honeypots, canary
tokens, lures), turns it into scored, correlated intelligence (behavioural
fingerprinting, campaign clustering, ATT&CK technique mapping), and hands an
operator the response (playbooks, deception deployment, immutable audit trail).
Everything is self-hosted: no SaaS dependency, no telemetry leaves your host.

- **Live deployment:** https://wraithwall.online
- **Source:** https://github.com/niffyhunt/wraithwall
- **PyPI:** `pip install wraithwall`

## What is in this package

`pip install wraithwall` installs the platform as a library and a CLI:

| Component | Modules | What it does |
|---|---|---|
| **Active-defense gateway** | `gateway` | Proof-of-work and behavioural challenge, IP blocklist, bot scoring, request fingerprinting |
| **URL / domain / IP intelligence** | `link_checker`, `public_api` | Reputation, WHOIS, DNS and abuse lookup behind one API |
| **Honeypot intelligence** | `cowrie_intelligence`, `replay_tty`, `botmind_classifier` | Cowrie session ingest, terminal replay, bot-vs-human classification |
| **Attacker identity** | `behavioral_dna`, `chronos_temporal`, `vector_transitions`, `echo_intent`, `recalibration`, `unison_score` | Persistent behavioural fingerprint, temporal patterns, command-transition models, canonical threat score |
| **Campaign correlation** | `campaign_correlator`, `deception_event_bus` | Similarity scoring, clustering, unified deception telemetry bus |
| **Deception & canaries** | `canary_service`, `supply_chain_canary`, `credential_propagation`, `llm_honeypot`, `dml_engine` | Canary tokens, supply-chain beacons, planted-credential lures, LLM honeypot, signed Deception Markup Language |
| **Threat intel** | `asn_intelligence`, `bgp_monitor`, `spectra_ioc`, `sigil_yara`, `fingerprint_corpus` | ASN abuse enrichment, route monitoring, IOC store, YARA analysis, request-fingerprint corpus |
| **Incident response** | `incident_response` | Playbook catalogue, context-aware actions, checklist persistence, export |
| **LLM runtime security** | `llm_firewall`, `ai_runtime_security`, `llm_cache` | Prompt/agent firewall, optional AI runtime checks, shared response cache |
| **Ingestion pipeline** | `dossier_*` (7 modules) | Auth, packet, events, store, destinations, webhook, pipeline |
| **Runtime** | `live_events`, `tor_egress`, `thread_utils`, `shared`, `database` | SSE streams, Tor egress, background workers, app factory, SQLAlchemy models |
| **Local sandbox** | `sandbox_kit` (17 modules), `sandbox.sh`, `compose.sandbox.yml` | Fail-closed hardened local environment with synthetic telemetry |
| **Client SDK** | `client` | Typed HTTP client for the platform's API |

Entry points: `create_app()` (application factory), `Client` (API client),
`wraithwall` (CLI).

## Quick start

```bash
pip install wraithwall
wraithwall check          # routes + blueprints sanity check
wraithwall serve          # gunicorn-backed server on :8000
```

From source:

```bash
git clone https://github.com/niffyhunt/wraithwall.git
cd wraithwall
./install.sh
cp .env.example .env
docker compose up -d
wraithwall check
wraithwall serve
```

## Ecosystem

| Package | Install | Purpose | Status |
|---------|---------|---------|--------|
| **wraithwall** | `pip install wraithwall` | Flask platform — gateway, intel, honeypots, deception, playbooks | PyPI 0.2.1 |
| **ravenscan** | `pip install ravenscan` | Engineering intelligence CLI (`raven`) and library | PyPI 0.1.1 |
| **canary-kit** | `pip install canary-kit` | Supply-chain canary token minting and detection | PyPI 0.1.0 |
| **honeypot-mitre** | `pip install honeypot-mitre` | Cowrie logs → MITRE ATT&CK scoring | PyPI 0.1.0 |
| **dml-spec** | `pip install dml-spec` | Signed deception markup language validator | PyPI 1.0.0 |
| **wraithmesh** | `pip install packages/wraithmesh` (local) | Distributed sensor mesh / signed observations | **v2 ready** 0.2.0 (not on PyPI yet) |
| **wraithwall-sdk** | source only | Official HTTP API client | Not published yet |

Packages are independent — none imports another.

## Python API

```python
from wraithwall import create_app, Client
from wraithwall.link_checker import analyze
from wraithwall.gateway import Gateway

app = create_app()
client = Client("http://localhost:8000", api_key="...")
print(client.health())
result = analyze("https://example.com")
blocked = Gateway.is_ip_blocked("203.0.113.1")
```

```python
from ravenscan import scan
from canary_kit import create_canary

profile = scan(".")
token = create_canary("my-sdk", "1.0.0")
```

## CLI

```bash
wraithwall check                 # validate routes and blueprints
wraithwall serve --port 8000     # run the server
wraithwall routes                # print the route table
wraithwall sandbox up --profile app-only   # local sandbox launcher
raven scan .
canary-kit mint my-pkg 1.0.0 --type runtime
honeypot-mitre sample.json
dml validate traps.yaml
```

## Configuration

All secrets and infrastructure endpoints come from environment variables
(see `.env.example`). Nothing is hardcoded to a specific deployment.

## Documentation

**Platform**

- **[LAUNCH.md](https://github.com/niffyhunt/wraithwall/blob/main/LAUNCH.md)** — Field guide and platform tour
- **[docs/architecture.md](https://github.com/niffyhunt/wraithwall/blob/main/docs/architecture.md)** — Architecture overview
- **[docs/deployment.md](https://github.com/niffyhunt/wraithwall/blob/main/docs/deployment.md)** — Deployment guide
- **[docs/api.md](https://github.com/niffyhunt/wraithwall/blob/main/docs/api.md)** — API surface
- **[ROADMAP.md](https://github.com/niffyhunt/wraithwall/blob/main/ROADMAP.md)** — Direction and priorities
- **[docs/COMMUNITY_ROADMAP.md](https://github.com/niffyhunt/wraithwall/blob/main/docs/COMMUNITY_ROADMAP.md)** — Community roadmap
- **[docs/knowledge-pipeline/](https://github.com/niffyhunt/wraithwall/tree/main/docs/knowledge-pipeline)** — Technical knowledge articles
- **[CHANGELOG.md](https://github.com/niffyhunt/wraithwall/blob/main/CHANGELOG.md)** — Version history
- **[SECURITY.md](https://github.com/niffyhunt/wraithwall/blob/main/SECURITY.md)** — Vulnerability reporting

**Local sandbox** — the optional hardened environment for running the platform
on your own machine with synthetic telemetry:

```bash
./sandbox.sh up --profile app-only       # T0: gates + state only, no containers
./sandbox.sh destroy --yes               # profiles don't switch in place — clean T0 first
./sandbox.sh up --profile local-sandbox  # T1: build, boot, self-check (one-time ack)
./sandbox.sh verify                      # score the RUNNING sandbox against the checklist
./sandbox.sh destroy --yes               # stop services and delete all sandbox state
```

Read **[docs/sandbox/security-model.md](https://github.com/niffyhunt/wraithwall/blob/main/docs/sandbox/security-model.md)**
first — it states what the sandbox does **not** isolate. The local sandbox is
not a malware-containment environment and not a production deployment; the
uplink is a convenience, not an isolation boundary. Hostile content belongs in
the T2 `research-sandbox` profile only (see CONTRIBUTING.md § local sandbox).

Sandbox docs:

- **[docs/sandbox/quickstart.md](https://github.com/niffyhunt/wraithwall/blob/main/docs/sandbox/quickstart.md)** — Local sandbox in five minutes
- **[docs/sandbox/security-model.md](https://github.com/niffyhunt/wraithwall/blob/main/docs/sandbox/security-model.md)** — What is isolated, what is not (read this first)
- **[docs/sandbox/profiles.md](https://github.com/niffyhunt/wraithwall/blob/main/docs/sandbox/profiles.md)** — Profiles T0–T3 and confirmation gates
- **[docs/sandbox/lifecycle.md](https://github.com/niffyhunt/wraithwall/blob/main/docs/sandbox/lifecycle.md)** — up / status / verify / replay / reset / destroy
- **[docs/sandbox/troubleshooting.md](https://github.com/niffyhunt/wraithwall/blob/main/docs/sandbox/troubleshooting.md)** — E-code catalog → cause → fix
- **[docs/sandbox/network.md](https://github.com/niffyhunt/wraithwall/blob/main/docs/sandbox/network.md)** — Zones, default-deny, how to verify nothing leaves
- **[docs/sandbox/data-policy.md](https://github.com/niffyhunt/wraithwall/blob/main/docs/sandbox/data-policy.md)** — What may enter or leave, synthetic marking
- **[docs/sandbox/vs-production.md](https://github.com/niffyhunt/wraithwall/blob/main/docs/sandbox/vs-production.md)** — How the sandbox differs from the production deployment
- **[docs/sandbox/platforms.md](https://github.com/niffyhunt/wraithwall/blob/main/docs/sandbox/platforms.md)** — Platform support matrix
- **[DEVELOPER_DOCUMENTATION_PLAN.md](https://github.com/niffyhunt/wraithwall/blob/main/DEVELOPER_DOCUMENTATION_PLAN.md)** — Documentation contracts and freshness rules

## Contributing

Install the full stack with `./install.sh`, run `pytest`, then open a PR. Each
package under `packages/` has its own README and examples. See
[CONTRIBUTING.md](https://github.com/niffyhunt/wraithwall/blob/main/CONTRIBUTING.md)
for details.

Working on the local sandbox? Read CONTRIBUTING.md § local sandbox first — it
states which profile to test hostile content against.

## License

MIT — © 2026 Niffyhunt. See [LICENSE](https://github.com/niffyhunt/wraithwall/blob/main/LICENSE).
