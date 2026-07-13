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

## Questions

Open a GitHub discussion or email contact@wraithwall.online.