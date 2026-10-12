# ADR 0001: Phase pipeline with JSON-canonical artifacts

## Status

Accepted (2026). Applies to all RavenScan releases.

## Context

Raven analyzes a repository through independent phases (structure, dependencies,
architecture graph, security plugins, scoring, daily report) and must produce
reports that are comparable across runs and releases. Operators use the output
in CI gates and security reviews, so churn and non-determinism are defects, not
nits.

## Decision

1. **Phases are independent and typed.** Each phase reads the repository
   context and emits a Pydantic model with an explicit `schema_version`.
2. **JSON is the canonical artifact.** Every phase writes
   `<Artifact>.json` to `.raven/` via `.model_dump_json()`. Markdown is
   rendered *from* the JSON model, never assembled independently. Tooling that
   disagrees with the JSON is a bug in the tooling.
3. **Determinism is a test, not a hope.** The golden harness
   (`tests/golden/`) runs scans against synthetic fixture repos twice and
   asserts byte-identical output. Any change that alters golden bytes must
   regenerate fixtures deliberately and justify the diff.
4. **SQLite for memory, one write path.** Learned state lives in one local
   SQLite file. Every write passes the MemoryGate (secret/entropy rejection,
   scope enforcement, append-only audit chain). Features must not add a second
   persistence path.
5. **Static analysis only.** Raven never executes scanned code; network is
   used only by explicit `raven wraith` commands with operator credentials.

## Consequences

- Reports are diffable across versions; CI gates are stable.
- Schema changes require a version bump and a changelog entry.
- New output fields are additive; renaming/removing fields is a breaking change.
- Operators can audit exactly what Raven learned (`raven memory list`) and
  wipe it (`raven memory wipe`).
