# Security Policy

## Reporting a vulnerability

Please report security issues in RavenScan **privately** via GitHub security advisories on the repository (`niffyhunt/ezmcyber`), or open a private disclosure with the maintainer. Do not file public issues for exploitable vulnerabilities.

We aim to acknowledge reports within 72 hours and to ship fixes for confirmed issues in a patch release.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | ✅ actively maintained |
| < 0.2   | ❌ upgrade to 0.2.x |

## Security model (what Raven does and does not do)

- **Static only.** Raven analyzes source trees and git history. It never executes the code of the repository it scans.
- **Local by default.** Artifacts are written to `.raven/` in the working tree. Raven sends nothing anywhere unless you explicitly run `raven wraith` subcommands with your own API credentials.
- **Memory safety.** Everything written to Raven's memory store passes the MemoryGate: secret/entropy detection rejects credentials, scope enforcement binds records to the scanned repository, and every decision is recorded in an append-only audit chain. `raven memory export` / `wipe` give the operator full control.
- **Connected mode.** `raven wraith` uses HTTPS, timestamp/nonce HMAC with replay protection, and public-key-only bearer transport; API secrets are never sent as headers or URL values.
- **No plugin sandboxing.** Plugins run in-process with the privileges of the Raven process. Only install plugins you trust.
