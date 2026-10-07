# Contributing

Thanks for helping improve WraithWall OSS.

## Getting started

```bash
git clone https://github.com/niffyhunt/wraithwall.git
cd wraithwall
./install.sh
cp .env.example .env
pytest
```

## Development workflow

1. Create a branch from `main`
2. Make focused changes with tests where applicable
3. Run `pytest` from the repo root
4. Open a pull request with a clear description of what changed and why

## Package layout

| Path | Purpose |
|------|---------|
| `src/wraithwall/` | Flask platform |
| `sandbox_kit/` | Local sandbox launcher (`./sandbox.sh`) |
| `compose.sandbox.yml`, `Dockerfile.sandbox*` | Digest-pinned sandbox containers |
| `detonate_sandbox/` | URL detonation sidecar (T2 profile) |
| `docs/sandbox/` | Sandbox documentation set |
| `packages/canary-kit/` | Canary token toolkit |
| `packages/honeypot-mitre/` | Cowrie → MITRE scoring |
| `packages/dml-spec/` | Deception markup language |
| `packages/ravenscan/` | Engineering intelligence CLI |
| `cli/`, `sdk/` | Unified entrypoints |

## Code standards

- Match existing style in the file you edit
- No hardcoded secrets or production URLs
- Prefer graceful degradation when optional API keys are missing
- Keep packages independent — no cross-package imports unless explicitly designed

## Working on the local sandbox

The sandbox (`./sandbox.sh`, `sandbox_kit/`) ships in this repo and its test
suite runs in CI, so most changes never need Docker at all:

```bash
python -m pytest tests/test_sandbox_*.py       # launcher, gates, docs, seed
python -m sandbox_kit up --profile app-only    # T0: gates + state, no containers
python -m sandbox_kit verify                   # fail-closed self-check
```

Rules when changing anything under `sandbox_kit/`, `compose.sandbox.yml` or the
sandbox Dockerfiles:

1. **Never test hostile content against T0/T1.** Those profiles are for the
   launcher and the app's own surface. Point real hostile samples at T2
   (`research-sandbox`) inside an isolated VM or a dedicated host — the
   default local sandbox is not a malware-containment environment.
2. **Fail closed.** A missing prerequisite, digest mismatch, or unconfirmed
   destructive action must stop the launcher, never fall through to a partial
   start.
3. **Every recorded event stays LOCAL-marked** and derived from
   `sandbox_kit/seed/corpus.py`; bump `SEED_VERSION` when the corpus bytes
   change so receipts stay honest.
4. **Docs are part of the change.** Any change to profiles, gates, the CLI
   surface, or failure codes must update `docs/sandbox/` in the same commit —
   `tests/test_sandbox_docs.py` fails CI otherwise.
5. **Do not pin a floating image tag.** Digest bumps go through the E206
   provenance gate (see [docs/sandbox/image-updates.md](docs/sandbox/image-updates.md)
   contract in [DEVELOPER_DOCUMENTATION_PLAN.md](DEVELOPER_DOCUMENTATION_PLAN.md)).

## Questions

Open a GitHub discussion or email contact@wraithwall.online.