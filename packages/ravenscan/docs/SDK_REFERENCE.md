# RavenScan SDK Reference

```python
from raven import Raven
from raven.core.config import RavenConfig
```

All methods are synchronous and deterministic for a given repository state.
Artifacts are written under `.raven/` in the scanned working tree.

## Client

| Method | Returns | Description |
|--------|---------|-------------|
| `Raven(RavenConfig(path="."))` | `Raven` | Client bound to one working tree. |
| `client.scan()` | `RepositoryProfile` | Structure, languages, frameworks, dependencies. |
| `client.architecture()` | `ArchitectureGraph` | Module/component graph with edges and evidence. |
| `client.security()` | `SecurityReport` | Findings with severity, priority, attack paths. |
| `client.score()` | `RiskScore` | Overall 0–100, grade, per-category breakdown. |
| `client.daily_report()` | `DailyReport` | What changed, why it matters, action items. |
| `client.report(format="json")` | `dict` | All current artifacts in one payload. |

## Configuration (`RavenConfig`)

| Field | Type | Default | Purpose |
|-------|------|---------|---------|
| `path` | `Path` | `"."` | Working tree to analyze. |
| `output` | `Path` | `.raven` | Artifact directory. |
| `format` | `str` | `"markdown"` | Render format for `.md` artifacts; JSON is always written. |

Environment-aware constructor: `RavenConfig.from_env()`.

## Exit codes (CLI contract, stable)

| Code | Meaning |
|------|---------|
| 0 | Clean / above threshold |
| 1 | Score below `--fail-under` |
| 2 | Execution error |
| 3 | Configuration error |

## Notes

- Schema versions live on each model (`schema_version`); pin your parser to them.
- Typed Pydantic returns — no string scraping required.
- Memory writes from feedback features pass the MemoryGate; see
  `src/raven/memory/gate.py` and ADR 0001.
