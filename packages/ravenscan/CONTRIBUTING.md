# Contributing to RavenScan

Thanks for considering a contribution. Raven is a deterministic, local-first
engineering-intelligence tool — contributions should keep it that way.

## Development setup

```bash
git clone https://github.com/niffyhunt/wraithwall.git
cd wraithwall/packages/ravenscan
python -m venv .venv && source .venv/bin/activate
pip install -e ".[all]" pytest mypy
```

## Running tests

```bash
pytest tests/ -q          # full suite (must stay green)
pytest tests/golden -q    # golden harness: double-run byte-identity
```

The golden harness is the proof layer: if your change alters output bytes for
the fixture repos, the golden files must be regenerated deliberately and the
diff explained in the PR.

## Ground rules

- **Determinism first.** Same repository state in, same bytes out. No wall-clock
  or unordered-set leakage into artifacts.
- **JSON is canonical.** Models serialize to JSON; Markdown is rendered *from*
  the JSON model, never hand-assembled. Add/extend a Pydantic model in
  `src/raven/core/models.py` rather than string-building reports.
- **All memory writes go through the MemoryGate** (`src/raven/memory/gate.py`).
  New features that persist anything must not add a second write path.
- **No execution of scanned code.** Analysis stays static.
- **No network by default.** Only `raven wraith` subcommands with explicit
  credentials may make requests.

## Style

- Type annotations on all new functions; keep `mypy src/raven` from getting worse.
- Inline `#` comments only where the *why* is non-obvious.
- Tests accompany every behavior change; security-relevant changes need a
  regression test that fails without the fix.

## Pull requests

1. One concern per PR; include *why* in the description.
2. Full suite green; golden tests updated deliberately.
3. Changelog entry under "Unreleased" in `CHANGELOG.md`.

## Security issues

See [SECURITY.md](https://github.com/niffyhunt/wraithwall/blob/main/packages/ravenscan/SECURITY.md)
— report vulnerabilities privately, never in a
public issue.
