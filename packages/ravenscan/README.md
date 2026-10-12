# Raven — Engineering Intelligence Agent

[![PyPI](https://img.shields.io/pypi/v/ravenscan)](https://pypi.org/project/ravenscan/)
[![Python](https://img.shields.io/pypi/pyversions/ravenscan)](https://pypi.org/project/ravenscan/)
[![License](https://img.shields.io/pypi/l/ravenscan)](https://github.com/niffyhunt/wraithwall/blob/main/packages/ravenscan/LICENSE)

Raven learns how a codebase is put together, watches it change, and tells you
what changed and **why it matters** — as plain JSON and Markdown, on your own
machine. No account, no cloud upload, no telemetry.

Point it at a repository and it produces five artifacts: a repository profile,
an architecture graph, a security report, a risk score, and a daily-style
summary. Run it again later and it tells you what got better, what got worse,
and what it learned in between.

> Evidence first. Engineering second. Opinion last.

## Install

```bash
pip install ravenscan
```

## Quick start

```bash
raven scan .          # analyze the repository → .raven/ artifacts
raven score .         # risk score with grade (A–F)
raven diff            # what changed since the previous scan
raven report          # re-render existing artifacts
raven score --fail-under 70   # CI gate: exit 1 below threshold
```

Every command supports `--format json` and `--format markdown`.

## What you get

Artifacts are written to `.raven/` in the scanned repository:

| Artifact | Contents |
|----------|----------|
| `RepositoryProfile` | Languages, frameworks, dependencies, structure, CI/CD and container setup |
| `ArchitectureGraph` | Components and how they connect, with evidence for every edge |
| `SecurityReport` | Findings with severity, explainable priority, and attack-path membership |
| `RiskScore` | Overall score /100, letter grade, per-category breakdown |
| `DailyReport` | What changed, why it matters, and concrete action items |

JSON is canonical — Markdown is rendered *from* the JSON model, never
assembled separately, so machine and human outputs can never disagree.

## Memory that stays trustworthy (new in 0.2)

Raven remembers what it learns between runs, under your control:

```bash
raven memory list       # everything Raven has learned about this project
raven memory delete ... # correct or remove a record
raven memory export ... # take your data with you
raven memory wipe       # start clean
```

Every write passes a single gate that rejects secrets and credentials, keeps
records scoped to the repository they came from, and logs an append-only audit
trail. Scan output can never quietly write to memory.

Also new in 0.2: **run summaries** (a since-last-run narrative in every
report), **run-vs-run changes** (new / resolved / recurring findings and score
delta), **decision traces** (which analyzers ran and which ruleset version
applied), and **project preferences** (`raven prefs set format json` — set
once, applied everywhere).

## Consistency you can prove

Same repository in, same bytes out — Raven ships with a golden evaluation
harness that scans fixture repositories twice and asserts byte-identical
output. Releases don't quietly change your reports, and `raven diff` between
versions shows exactly what moved and why (version-drift detection).

## CI integration

| Exit code | Meaning |
|-----------|---------|
| 0 | Clean, or score above threshold |
| 1 | Score below `--fail-under` |
| 2 | Execution error |
| 3 | Configuration error |

```yaml
# GitHub Actions example
- run: pip install ravenscan
- run: raven scan . && raven score --fail-under 70
```

## Python SDK

```python
from raven import Raven
from raven.core.config import RavenConfig

client = Raven(RavenConfig(path="."))

profile = client.scan()          # RepositoryProfile
arch = client.architecture()     # ArchitectureGraph
security = client.security()     # SecurityReport
risk = client.score()            # RiskScore
daily = client.daily_report()    # DailyReport

print(f"Score: {risk.overall}/100 — Grade {risk.grade}")
```

See [docs/SDK_REFERENCE.md](https://github.com/niffyhunt/wraithwall/blob/main/packages/ravenscan/docs/SDK_REFERENCE.md)
for the full typed API.

## Optional: connected mode

If you use [WraithWall](https://wraithwall.online), Raven can talk to it with
your own API key (scope `raven:use`):

```bash
raven wraith campaigns --api-key KEY --api-secret SECRET
raven wraith whoami    --api-key KEY --api-secret SECRET
raven wraith submit .  --api-key KEY --api-secret SECRET
```

Requests use HTTPS, timestamp/nonce HMAC with replay protection, and
public-key-only bearer transport — the secret is never sent as a header or URL
value. This is entirely optional; Raven is fully useful offline.

## What Raven is not

- **Not a runtime monitor.** It analyzes source trees and git history — not
  live servers, databases, or network traffic.
- **Not an alerting service.** It writes local files; it never sends email,
  chat, or phone notifications on its own.
- **Not a fleet scanner.** One `raven scan` per repository; no cross-machine
  correlation.
- **Not a replacement for dedicated rule engines.** Security plugins cover
  common languages and common mistakes; exotic frameworks and vendored
  binaries may be skipped. Treat Raven's report as a prioritized briefing,
  not an exhaustive audit.
- **Not a SaaS.** Nothing leaves your machine unless you run an explicit
  `raven wraith` command with your own credentials.

## Development

```bash
git clone https://github.com/niffyhunt/wraithwall.git
cd wraithwall/packages/ravenscan
pip install -e ".[all]" pytest
pytest tests/ -q
```

Contributions welcome — see
[CONTRIBUTING.md](https://github.com/niffyhunt/wraithwall/blob/main/packages/ravenscan/CONTRIBUTING.md).
Security reports:
[SECURITY.md](https://github.com/niffyhunt/wraithwall/blob/main/packages/ravenscan/SECURITY.md).
Release history:
[CHANGELOG.md](https://github.com/niffyhunt/wraithwall/blob/main/packages/ravenscan/CHANGELOG.md).

## License

MIT
