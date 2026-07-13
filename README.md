# WraithWall OSS

[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Donate](https://img.shields.io/badge/Support-Open%20Collective-7FADF2?style=flat-square&logo=opencollective&logoColor=white)](https://opencollective.com/wraithwall)

Production deception-and-threat-intelligence platform and companion packages.

## Ecosystem

| Package | Install | Purpose |
|---------|---------|---------|
| **wraithwall** | `pip install .` | Flask platform — gateway, link intel, cowrie, BGP, canaries |
| **ravenscan** | `pip install packages/ravenscan` | Engineering intelligence CLI (`raven`) and library |
| **canary-kit** | `pip install packages/canary-kit` | Supply-chain canary token minting and detection |
| **honeypot-mitre** | `pip install packages/honeypot-mitre` | Cowrie logs → MITRE ATT&CK scoring |
| **dml-spec** | `pip install packages/dml-spec` | Signed deception markup language validator |

Packages are independent — none imports another.

## Quick start

```bash
git clone https://github.com/niffyhunt/wraithwall.git
cd wraithwall
./install.sh
cp .env.example .env
docker compose up -d
wraithwall check
wraithwall serve
```

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
wraithwall check
wraithwall serve --port 8000
wraithwall routes
raven scan .
canary-kit mint my-pkg 1.0.0 --type runtime
honeypot-mitre sample.json
dml validate traps.yaml
```

## Configuration

All secrets and infrastructure endpoints come from environment variables (see `.env.example`). Nothing is hardcoded to a specific deployment.

## Documentation

- **[LAUNCH.md](LAUNCH.md)** — Field guide and platform tour
- **[docs/architecture.md](docs/architecture.md)** — Architecture overview
- **[docs/deployment.md](docs/deployment.md)** — Deployment guide
- **[docs/api.md](docs/api.md)** — API surface
- **[ROADMAP.md](ROADMAP.md)** — Direction and priorities
- **[CHANGELOG.md](CHANGELOG.md)** — Version history
- **[docs/COMMUNITY_ROADMAP.md](docs/COMMUNITY_ROADMAP.md)** — Community roadmap
- **[docs/knowledge-pipeline/](docs/knowledge-pipeline/)** — Technical knowledge articles

## Contributing

Install the full stack with `./install.sh`, run `pytest`, then open a PR. Each package under `packages/` has its own README and examples. See [CONTRIBUTING.md](CONTRIBUTING.md) for details.