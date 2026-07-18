# Contributing

Thanks for helping improve the WraithWall toolkit.

## Getting started

```bash
git clone https://github.com/niffyhunt/wraithwall-toolkit.git
cd wraithwall-toolkit
```

Each package is independent. Pick one and install locally:

```bash
cd canary-kit && pip install . && pytest
cd ../honeypot-mitre && pip install . && pytest
cd ../dml-spec && pip install . && pytest
```

## Pull requests

1. Fork and branch from `main`
2. Keep changes focused to one package when possible
3. Run `pytest` in the affected package
4. Open a PR with what changed and why

## Publishing

Maintainers: see `publish.sh` and `.github/workflows/publish.yml`. Do not commit secrets or `.env` files.

## Questions

Open a [GitHub issue](https://github.com/niffyhunt/wraithwall-toolkit/issues) or email contact@wraithwall.online.