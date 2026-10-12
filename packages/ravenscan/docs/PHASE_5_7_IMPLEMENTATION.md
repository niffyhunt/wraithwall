# Raven Phase 5–7 Implementation Notes

This document records behavior that is implemented and tested. It does not claim
that Raven performs complete exploitability analysis, attribution, or automatic
remediation.

## Phase 5 — Context-aware prioritization

`Raven.security()` computes an explainable, local priority from severity,
confidence, evidence-based exposure, recurrence, reintroduction, and explicit
operator feedback. Feedback (`confirmed`, `false_positive`, and
`accepted_risk`) changes advisory priority reasons only; findings remain visible
and are never suppressed from one label.

Attack-path membership adds context only when the conservative taint analyzer
has produced an evidence-backed path. Repository evidence and any external
intelligence remain separate fields.

WraithWall context is opt-in with `client.security(include_wraithwall=True)` or
`raven scan/score/diff --include-wraithwall`. When authorized and validated
campaign/BGP context matches, Raven adds an `IntelligencePrioritization` record
and provenance; it does not change the original severity or repository evidence.

## Phase 6 — Diff and developer feedback

`raven diff --format json` exposes security-focused entries with stable finding
identity, historical state, priority, attack-path membership, security summary,
change risk, risk reasons, and score delta. Reintroduced findings are reported
as regressions when the current artifact carries `historical_state=reintroduced`.

`raven record-feedback <finding-id> <detector> <outcome>` stores auditable
operator feedback in `.raven/history.db`. Valid outcomes are `confirmed`,
`false_positive`, `accepted_risk`, `unresolved`, `recurring`, `fixed`, and
`reintroduced`. Calibration is advisory and reports `insufficient-data` until
there are labeled outcomes.

The existing `score --fail-under` exit contract remains unchanged: below the
threshold exits 1, execution errors exit 2, and successful runs exit 0. The
score gate does not silently ignore accepted risk; policy-specific gate behavior
is not claimed by this release.

## Phase 7 — WraithWall intelligence fusion

The Raven client uses the existing tenant-scoped WraithWall endpoints:

- `GET /api/raven/whoami`
- `GET /api/raven/campaigns`
- `GET /api/raven/bgp-alerts`
- `POST /api/raven/submit-scan`

The client validates HTTPS, an explicit host allowlist, DNS destination safety,
redirect absence, response bounds, response JSON shape, tenant scope, and
per-item tenant identity. Requests use a timestamp/nonce HMAC over method, path,
and body. Only the public API key is sent in `Authorization`; the signing secret
is never sent in a header, URL, or bearer token. The server decrypts the
server-side Raven secret for HMAC verification. Replay protection fails closed
when Redis is unavailable.

WraithWall server-side campaign, BGP, and deception Redis reads/writes require a
validated tenant. Missing or malformed tenant context is rejected and never
mapped to the shared `global` namespace. Missing BGP Redis state returns 503,
not an authorized empty feed. Submission requires the signed API-key transport;
logged-in browser sessions cannot bypass it.

## Known limitations

- Hostname validation occurs before the HTTP library connects; controlled DNS and
  network egress are still required to eliminate time-of-check/time-of-use DNS
  changes.
- Campaign matching is conservative schema-tolerant token/context matching, not
  attacker attribution.
- BGP data is validated and exposed as contextual intelligence; it is not proof
  that a repository vulnerability is exploitable.
- CI policy does not yet implement accepted-risk baselines or a separate
  regression-only fail mode; the existing score threshold and exit codes remain
  authoritative.
- Direct SDK scans do not persist history unless the caller uses `MemoryStore`;
  the CLI scan path performs reconciliation and calibration persistence.
- The duplicate `wraithwall-oss/` tree is not the root package target; the active
  root package is `src/wraithwall`.
- BGP correlation reads only tenant-prefixed Cowrie/canary telemetry. Legacy
  global producer keys are intentionally not read, so correlation fails closed
  rather than risking cross-tenant data exposure. Those producers must be
  migrated to tenant-prefixed keys before this signal is available in production.
