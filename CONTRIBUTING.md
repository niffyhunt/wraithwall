# Contributing to WraithWall

Thank you for your interest. This project is **primarily solo-maintained** — contributions are welcome, but review bandwidth is limited and response times are best-effort.

## Before you start

1. Check [ROADMAP.md](ROADMAP.md) for current direction.
2. For security issues, read [SECURITY.md](SECURITY.md) (`contact@wraithwall.online`, 72h acknowledgement).

## Getting started

```bash
git clone https://github.com/niffyhunt/wraithwall.git
cd wraithwall
./install.sh
cp .env.example .env
pytest
```

## How to contribute

1. **Fork** the repository (`niffyhunt/wraithwall`).
2. Create a **focused branch** — one concern per PR.
3. **Test** what you change: run `pytest` from the repo root.
4. Open a **pull request** with a clear description.

## What we merge

- Bug fixes with a clear reproduction path
- Documentation corrections tied to the live architecture
- Tests for existing behaviour
- Small, reviewable features aligned with [ROADMAP.md](ROADMAP.md)

## What is slow or unlikely

- Large refactors without prior discussion
- New dependencies without justification
- Changes that weaken security boundaries
- Features that imply 24/7 community support infrastructure

## Code style

Match the surrounding file. No drive-by refactors. Never commit secrets, `.env` files, or generated credentials.

## Response expectations

| Item | Expectation |
| ---- | ----------- |
| PR review | Days to weeks (solo maintainer) |
| Issue triage | Best effort |
| Security reports | See [SECURITY.md](SECURITY.md) — 72h SLA |

This is intentional honesty, not discouragement. Small, high-quality PRs are more likely to land than large unsolicited rewrites.

## Related packages

Changes to `packages/canary-kit`, `packages/honeypot-mitre`, `packages/dml-spec`, and `packages/ravenscan` may be released independently — note which package your PR affects.
