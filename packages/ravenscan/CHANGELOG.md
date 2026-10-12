# Changelog

All notable changes to RavenScan are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/); versioning: SemVer.

## [0.2.1] — 2026-10-12

Release hygiene: links and metadata.

### Changed
- README links (`docs/SDK_REFERENCE.md`, `CONTRIBUTING.md`, `SECURITY.md`,
  `CHANGELOG.md`, `LICENSE`) now point at absolute GitHub URLs under
  `niffyhunt/wraithwall/packages/ravenscan` so they resolve on PyPI.
- Development clone instructions now use the public `niffyhunt/wraithwall`
  repository.
- Package metadata: author set to Niffyhunt; `Repository` and `Changelog`
  URLs added.

## [0.2.0] — 2026-10-11

Memory, continuity, and consistency release, plus release hygiene.

### Added
- **Run summaries** — dated since-last-run narrative artifact per scan.
- **Decision traces** — per-scan record of which analyzers ran and why; ruleset/template version keys with drift detection after upgrades.
- **Project-scoped preferences** — set output format / fail-under once per project; scan content can never write preferences.
- **Run-vs-run changes view** — new / resolved / recurring findings and score delta between scans.
- **MemoryGate** — single choke point for all memory writes: secret/entropy rejection, scope enforcement, append-only audit chain.
- **`raven memory` command group** — view/correct/delete/disable/export over learned state, with provenance.
- **Golden evaluation harness** — synthetic fixture repos, double-run byte-identity tests; releases provably do not churn outputs.
- **CLI device-authorization grant** — log in via browser, continue in terminal.

### Changed
- Classification raised to Development Status 4 — Beta.
- Metadata links now point at the canonical repository.
- Empty `telemetry/` and `history/` placeholder packages removed (nothing imported them).

### Fixed
- Misplaced monolith regression test (`test_tenant_isolation`) removed from the package test suite — it only runs inside the platform repository and broke clean installs/CI.

## [0.1.1] — 2026-08

- Packaging-only release: PyPI metadata links point at GitHub.

## [0.1.0]

- First public release: `raven init/scan/score/report/diff/doctor/version`, SDK facade, JSON-canonical artifacts with Markdown rendered from JSON, multi-language security analysis, architecture graph, risk scoring with CI exit-code gate, WraithWall connected mode (`raven wraith campaigns/whoami/submit`, `raven:use` API-key scope).
