# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a vulnerability

Email **contact@wraithwall.online** with:

- A description of the issue and affected component
- Steps to reproduce
- Impact assessment (if known)

We aim to acknowledge reports within **72 hours** and provide a remediation timeline for confirmed issues.

Please do **not** open public GitHub issues for undisclosed security vulnerabilities.

## Scope

This policy covers the `wraithwall` platform, CLI, SDK, and bundled packages under `packages/`.

## Safe defaults

- Set a strong `SECRET_KEY` in production
- Use `FLASK_ENV=development` only for local work
- Keep `ENABLE_WEB_TERMINAL` disabled in production unless you explicitly need it
- Do not commit `.env` files or signing keys