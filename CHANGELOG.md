# Changelog

All notable changes to this repository are documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] — 2026-10-02 — "PyPI release: Tor egress, tenant isolation, hardened replay"

First release of the `wraithwall` distribution since 0.1.0 (2026-07-15). The published
package version is independent of the platform delivery series.

### Added
- **Local sandbox ships with the package.** `sandbox_kit/`, `sandbox.sh`,
  `compose.sandbox.yml`, the four digest-pinned sandbox Dockerfiles,
  `detonate_sandbox/`, the 13 `docs/sandbox/` guides and the 11 `tests/test_sandbox_*.py`
  gate suites are now part of the distribution. A `pip install wraithwall` is a
  complete, runnable local sandbox: `wraithwall sandbox up --profile local-sandbox`,
  `… status --security`, `… verify`, `… destroy --yes`.
  - `sandbox_kit.assets` resolves deployment assets in **both** supported layouts —
    a repository checkout (assets beside the package) and a pip install (assets under
    `<prefix>/share/wraithwall/`) — and stages the same Docker build context either
    way, so both layouts boot the same image.
  - `wraithwall.sandbox_mode` — the `WRAITHWALL_SANDBOX` flag as a shipped contract:
    strict allowlist (`'1'` only, everything else fails closed to default mode), a
    malformed-value marker, and one startup line per process stating the posture.
    In sandbox mode `create_app()` keeps the rate limiter memory-backed even when an
    ambient `REDIS_URL` is present (a host Redis that rejects auth turns every limited
    route into a 500) while the data-plane Redis still attaches for telemetry.
  - `wraithwall.cowrie_ship` — the signed `POST /api/v1/cowrie/ship` ingest endpoint
    the seed ships to, HMAC-verified over the exact body, content-hash deduplicated.
  - `GET /api/health` — returns `{status, version, redis}` with 200 even when Redis is
    unreachable, for container healthchecks and the `Client` SDK.
  - `wraithwall.host_auth` — explicit binding point for the account/auth stack the
    package deliberately does not ship. Optional modules that need it raise
    `AUTH_RUNTIME_ERROR` before touching data instead of degrading silently.
- **Operator dossier pipeline** (new) — `dossier_auth`, `dossier_packet`,
  `dossier_store`, `dossier_events`, `dossier_webhook`, `dossier_destinations`,
  `dossier_pipeline`: authenticated ingest → packet → store → webhook fan-out,
  importable as a library.
- `tor_egress.py` — fail-closed Tor-routed egress for public scanners. Link-intelligence
  vendor calls and hostname resolution leave through Tor by default
  (`PUBLIC_EGRESS_MODE=direct` to override), so third-party vendors and the local
  resolver cannot correlate what visitors scan or learn the platform's origin.
- `knowledge_docs` — new `/docs/knowledge` index route.

### Changed
- `link_checker` — VirusTotal / URLScan lookups routed through `tor_egress`; host
  resolution uses Tor remote DNS instead of `socket.gethostbyname`.
- `campaign_correlator` — strict tenant isolation (`_strict_tenant_id` rejects empty or
  `global` tenants), so deception events never fall back into a shared namespace.
- `behavioral_dna` — Cowrie-watcher DB writes now run inside an explicit Flask app
  context; model registration is cached and uses `extend_existing` (fixes "Working
  outside of application context" and repeated-table-definition errors).
- `replay_tty` — `generate_playback_html()` sandboxed xterm.js playback; captured
  terminal output is injected via Jinja `tojson`, so hostile honeypot output cannot break
  out of the script tag.
- `cowrie_intelligence`, `llm_firewall`, `llm_honeypot` — Groq model updated to
  `openai/gpt-oss-120b`.
- `canary_service` — display price is configurable via `CANARY_PRICE`.

### Fixed
- `llm_honeypot` — removed the undefined legacy model-org variables that raised
  `NameError` on `GET /api/ai/v1/models` (present in 0.1.0).
- **Cross-module imports inside the package now resolve.** 25 late imports still
  pointed at monolith-root module names (`from cowrie_intelligence import …`),
  so every enrichment path — campaign correlation, behavioral DNA, ASN enrichment,
  spectra IOC extraction, unison scoring, HASSH fingerprints, deception-bus publishing,
  credential-lure checks — silently no-opped in an installed package. All are now
  package-relative.
- **`replay_tty.parse_ttylog` reads the real Cowrie ttylog format.** The packaged copy
  parsed a fictional `[ts:u32 BE][len:u32 BE]` header and returned garbage on every
  genuine ttylog; it now uses cowrie's 24-byte little-endian `<iLiiLL` frame header and
  keeps only attacker INPUT write frames, as cowrie's own input hash does. The sandbox
  seed was writing the same fiction, and now writes real frames — a new test round-trips
  seed output through the production parser so neither side can drift again.
- `replay_tty` admin/login gates fail closed when no auth stack is bound, instead of
  silently serving TTY replay to anonymous callers.
- Undeclared runtime dependencies declared: `pyyaml` (required — `dml_engine` is
  registered by `create_app()`), `numpy` (`campaign_correlator`). The `anthropic` SDK is
  now imported lazily so `llm_honeypot` imports without it and falls back to static
  responses.
- `requirements.txt` regenerated as an exact mirror of `[project.dependencies]`; it had
  drifted to a 10-entry subset, so `Dockerfile.sandbox` was building images missing most
  of the platform's dependencies. A gate test fails CI on any future divergence.
- De-branding: internal platform identifiers replaced with the neutral decoy brand across
  `llm_honeypot`, `dml_engine`, the gateway cookie name, and the deception-bus decoy
  paths.

### Release engineering
- Version 0.1.0 → 0.2.0.
- Sdist target switched from `include` to `only-include` — the bare `tests` pattern
  matched any nested `tests/` directory (gitignore-style) and dragged the whole monorepo,
  compiled binaries included, into the sdist.
- `flask-cors` bound widened to `<7`.
- **Upload tooling**: the built artifacts declare `Metadata-Version: 2.5` (hatchling
  1.32+), which `twine` < 7 refuses. `twine check` passes under `twine` 7.0.0.
- Wheel now ships `sandbox_kit` plus shared data under `<prefix>/share/wraithwall/`;
  sdist carries the full sandbox source tree, docs and tests.
- CI (`.github/workflows/ci.yml`) added for the public repository: package build +
  metadata gate, full test suite, and the sandbox platform matrix (linux reference,
  macOS, arm64) plus SBOM/supply-chain scan.

## [Unreleased]

### Added
- Phase 9 launch preparation: `/docs` and `/launch` public pages, launch audit reports in `docs/launch/`
- Blog posts: runtime visualization, Cowrie pipeline intelligence
- `scripts/send_phase9_report.py` — completion notifications
- Repository messaging pass: project-first README, governance files (CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, LICENSE)
- `docs/architecture.md`, `docs/deployment.md`, `docs/api.md` entry points
- Embedded links to `LAUNCH.md`, incident report, and existing `docs/diagrams/*.svg`
- [docs/METRICS_METHODOLOGY.md](docs/METRICS_METHODOLOGY.md) — per-subsystem measurement definitions
- Phase 11 open-source cleanup: IP redaction, domain replacement, key sanitization, missing pages
- Phase X architecture review: 10 audit/review documents in repo root

### Changed
- README, LAUNCH.md, docs/architecture.md — public vs operator architecture, docs hub links
- Landing nav/footer — Documentation, Launch, Architecture entry points
- `solo-deception-platform-audit` blog post — Phase 9 additions section
- README restructured around WraithWall (removed personal-resume framing, age narrative, incorrect ASCII architecture diagram)
- Personal/portfolio narrative relocated to [wraithwall.online/niffy](https://wraithwall.online/niffy)
- Origin narrative approved and added to README Maintainer section
- [SECURITY.md](SECURITY.md) finalized — 72h acknowledgement, contact@wraithwall.online
- MIT license confirmed at repo root
- GitHub links updated: Ethwebsite → wraithwall across templates, blog, and docs
- CLAUDE.md updated with correct frontend build system description

### Removed
- Unsubstantiated metrics table from README (replaced by methodology doc + scoped guidance)
- POSTS/ directory (5 draft marketing files)
- Internal deployment IPs replaced with placeholders (COWRIE_VPS_IP, SERVER_IP)
- Honeyfs SSH private key replaced with placeholder

### Security
- Raw audit documents not promoted in README until sensitivity review complete
- Production IPs and internal domains redacted from all files
- 6 internal audit files flagged for removal before public push

## [Prior history]

This project evolved as a production monolith without semver releases. Tagged releases and detailed historical notes will be added when the maintainer adopts a release cadence.
