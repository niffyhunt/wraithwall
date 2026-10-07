# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| 0.1.x   | Security fixes only |

## Reporting a vulnerability

Email **contact@wraithwall.online** with:

- A description of the issue and affected component
- Steps to reproduce
- Impact assessment (if known)

We aim to acknowledge reports within **72 hours** and provide a remediation timeline for confirmed issues.

Please do **not** open public GitHub issues for undisclosed security vulnerabilities.

## Scope

This policy covers the `wraithwall` platform, CLI, SDK, the local sandbox in
`sandbox_kit/`, and bundled packages under `packages/`.

## Local sandbox scope

The local sandbox ships with this package and is **in scope** for reporting:

- container/network escapes from the sandbox's default-deny zones
- the synthetic seed emitting unmarked data, or unmarked non-synthetic data
- bypasses of the fail-closed gates (a launcher that starts something inert
  instead of refusing)
- `WRAITHWALL_SANDBOX=1` failing to suppress an external alert transport or to
  keep the rate limiter self-contained

**Out of scope** (by design, not by oversight): the sandbox is explicitly *not*
a guaranteed malware-containment environment. Findings that require running
hostile code outside an isolated VM to reproduce belong to the operator's own
isolation boundary, not to this project. See
[docs/sandbox/security-model.md](docs/sandbox/security-model.md).

## Safe defaults

- Set a strong `SECRET_KEY` in production
- Use `FLASK_ENV=development` only for local work
- The published package registers no interactive terminal endpoint and no
  user/auth stack; bind auth explicitly via `wraithwall.host_auth.bind(...)`
- Arm the sandbox with `WRAITHWALL_SANDBOX=1` whenever you run the local
  sandbox: it stubs alert transports and forces a memory-backed rate limiter
- Do not commit `.env` files or signing keys