# Changelog

All notable changes to this repository are documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
