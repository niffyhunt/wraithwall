# Raven — Engineering Intelligence Agent

[![PyPI](https://img.shields.io/pypi/v/ravenscan)](https://pypi.org/project/ravenscan/)
[![Python](https://img.shields.io/pypi/pyversions/ravenscan)](https://pypi.org/project/ravenscan/)
[![License](https://img.shields.io/pypi/l/ravenscan)](LICENSE)

**Raven** is an open-source engineering intelligence agent. It learns a software project over time, detects architectural and security change, correlates it across revisions, and produces evidence-backed intelligence reports. Every report explains *why* something matters, not just *what* changed.

> Evidence first. Engineering second. Opinion last.

## Install

```bash
pip install .
```

## Quick Start

```bash
raven init           # scaffold .raven directory
raven scan .         # run full analysis
raven score .        # compute risk score
raven report         # render existing artifacts
raven doctor         # environment sanity check
raven version        # show version info
```

## SDK Usage

```python
from ravenscan import scan, Raven
from raven.core.config import RavenConfig

profile = scan(".")
client = Raven(RavenConfig(path="."))

profile = client.scan()          # RepositoryProfile
arch = client.architecture()     # ArchitectureGraph
security = client.security()     # SecurityReport
risk = client.score()            # RiskScore
daily = client.daily_report()    # DailyReport

print(f"Score: {risk.overall}/100 — Grade {risk.grade}")
```

## Output

All commands support `--format json` and `--format markdown` (default).

Artifacts are written to `.raven/`:
- `RepositoryProfile.{json,md}`
- `ArchitectureGraph.{json,md}`
- `SecurityReport.{json,md}`
- `RiskScore.{json,md}`
- `DailyReport.{json,md}`

JSON is canonical — Markdown is rendered *from* the JSON model, never independently.

## Exit Codes (CI Integration)

| Code | Meaning |
|------|---------|
| 0 | Clean — no findings or score above threshold |
| 1 | Score below `--fail-under` threshold |
| 2 | Execution error |
| 3 | Configuration error |

```bash
raven score --fail-under 70   # CI gate: exit 1 if score < 70
```

## WraithWall Connected Mode (remote)

Raven now supports connected mode with live WraithWall even from outside the server:

```bash
# anyone with a raven:use API key can use this before open source
raven wraith campaigns --api-key YOURKEY --api-secret YOURSECRET
raven wraith whoami --api-key ... --api-secret ...
raven wraith submit . --api-key ... --api-secret ...
```

- Defaults to https://wraithwall.online
- Public reads for campaigns/bgp (no key needed)
- Write/submit and whoami require key with `raven:use` scope (create in WraithWall UI)
- Works from laptop, CI, anywhere.

## What Raven Is Not

Raven is a **local CLI/SDK analyzer** for repositories you point it at. It does **not**:

| Limitation | Detail |
|------------|--------|
| **Live website integration (new)** | `raven wraith` subcommands now connect to live WraithWall at https://wraithwall.online using API keys (raven:use scope). Campaigns, BGP alerts (public), whoami, submit-scan supported remotely. |
| **No runtime telemetry** | Raven analyzes static source trees and git history — not Redis keys, honeypot sessions, BGP feeds, or APScheduler state. |
| **No WraithWall operator console** | Phase 8 live architecture visualization (`/console#/architecture`) is a separate corpus-driven system in the main Flask app (`architecture_viz.py`), not Raven output. |
| **No deception mesh modeling** | Cowrie pipelines, canary propagation, sandbox flows, and campaign correlation are documented in `docs/architecture/` and rendered by `scripts/generate_wraithwall_diagrams.py` — Raven does not ingest those runtime graphs. |
| **No autonomous alerting** | Raven writes local `.raven/` artifacts only. It does not send Telegram, Discord, or email notifications. |
| **No multi-repo fleet view** | One `raven scan` per working tree. No cross-deployment correlation across VPS hosts. |
| **No guaranteed supply-chain audit** | Security plugins cover common languages; unknown frameworks, generated bundles, and vendored binaries may be skipped. |

### WraithWall vs Raven

| Capability | WraithWall (production) | Raven (CLI) |
|------------|-------------------------|-------------|
| Architecture diagrams on website | Yes — `/#architecture` scroll gallery + authenticated console | No — local `.raven/ArchitectureGraph.md` only |
| Source of truth | `docs/architecture/*.json` (Phase 8 corpus) | Repository static analysis |
| Live honeypot / deception data | Yes | No |
| CI risk gate | Via custom integration | `raven score --fail-under` |

To regenerate WraithWall publication diagrams from the validated corpus:

```bash
python3 scripts/generate_wraithwall_diagrams.py
# → static/img/architecture/*.svg + *.png
```

To deploy Cowrie without config-mount regressions:

```bash
chmod +x cowrie-analyzer/scripts/deploy-cowrie.sh
cowrie-analyzer/scripts/deploy-cowrie.sh
```

## Development

```bash
pip install ".[all]"
pytest
```

## License

MIT