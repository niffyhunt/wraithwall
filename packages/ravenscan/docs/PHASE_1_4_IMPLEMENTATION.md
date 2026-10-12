# RavenScan Phase 1–4 Intelligence Layer

This document describes behavior implemented in the additive intelligence layer.
Existing JSON/Markdown schemas and CLI commands remain available; new fields
are optional and old artifacts remain readable.

## Phase 1: finding intelligence

`SecurityFinding.finding_id` is derived from normalized detector/CWE rule
context and evidence. Volatile file paths, line numbers, timestamps, and
entropy measurements are removed from the identity input. Scanner and
infrastructure findings provide canonical rule/context fields; explicitly
supplied historical IDs are preserved when artifacts are loaded. Plugin
findings receive a stable detector/CWE fallback identity, but the fallback can
collide for multiple findings from the same analyzer/CWE and does not claim
complete semantic identity.

`.raven/history.db` adds `finding_observations`. Each scan records `new`,
`existing`, `changed`, `resolved`, or `reintroduced` state, revision metadata,
and recurrence/resolution/reintroduction counters. `MemoryStore.recurring_debt`
exposes repeated findings. Existing `scan_records` and `false_positives` tables
are preserved. CLI persistence updates the saved security snapshot after
reconciliation, so JSON/SARIF artifacts and history carry the final state.

Because materially changed evidence can produce a new stable identity, such a
change may appear as a new finding rather than `changed`; the `changed` state
applies when the same identity remains while evidence/severity differs.

`raven diff --format json` now includes a documented `change_risk` score and
risk reasons. It weights security, routes, dependencies, imports, architecture,
symbols, configuration, and evolution changes by category and confidence. It is
advisory and does not change CI exit codes.

## Phase 2: conservative flow intelligence

`raven.security.taint` represents source → propagation → transformation → sink
flows and emits only direct, local Python AST evidence. `SecurityReport` can
carry `taint_flows`, `attack_paths`, and `dependency_reachability`.

Attack paths are emitted only when a proven flow sink is within two lines of an
existing security finding in the same file. Dependency reachability uses actual
import/use statements. Declared-but-unmatched dependencies remain
`unknown_reachability`; this is not a vulnerability database, vulnerable-symbol
reachability proof, or proof of safety.

## Phase 3: evidence and outputs

Every finding includes an optional `EvidenceBundle`, analyzer, stable ID,
historical state, and related identity fields. JSON remains canonical and
Markdown remains supported. `raven scan --format sarif` writes:

```text
SecurityReport.sarif.json
```

Non-security artifacts remain JSON in SARIF mode. The SARIF renderer emits
SARIF 2.1.0 rule IDs, CWE metadata, locations, confidence, historical state,
and stable result fingerprints. `score --format sarif` is rejected explicitly
because SARIF is only defined for security findings.

Detector calibration is advisory. Explicit outcomes (`confirmed`,
`false_positive`, `unresolved`, `recurring`, `fixed`) are stored in
`detector_outcomes`; false-positive marking records feedback but does not cause
automatic suppression from insufficient data. Calibration reports sample size
and false-positive rate when labeled data exists, otherwise
`insufficient-data`.

## Phase 4: WraithWall context

`raven.wraithwall.client.WraithWallIntelClient` uses the existing
`/api/raven/campaigns` endpoint for prioritization and exposes a separately
validated `bgp_alerts()` reader for `/api/raven/bgp-alerts`. BGP alerts are not
currently folded into prioritization. Both endpoints use the hardened public-key Bearer plus timestamp/nonce HMAC
contract. The client requires the public key, signing secret, and tenant ID,
validates HTTP
and JSON response shape, rejects unauthorized/unavailable responses, requires
an HTTPS allowlisted host, disables redirects, times out quickly, and never
sends source code.

The server endpoints require `raven:use`, resolve the tenant from the
validated session/API key (never request JSON), namespace campaign and BGP
Redis keys by tenant, and return `scope: tenant-threat-intelligence` plus the
validated `tenant_id`. Legacy users/API keys are isolated to deterministic
`user:<id>` tenants until explicitly assigned an organization tenant. A
missing Redis feed returns HTTP 503 with `status: unavailable`; it is never
interpreted as an empty authorized feed.

WraithWall context is represented separately as
`IntelligencePrioritization`. It does not mutate a finding's severity or
repository evidence. No enrichment is performed unless the SDK caller opts in
with `client.security(include_wraithwall=True)`. Authorization and transport
failures are surfaced as `intelligence_status=unavailable` and a safe error
message rather than being treated as an active-threat match.

## Limitations and security boundaries

- Taint analysis is local/direct-assignment Python AST analysis; it does not
  claim complete interprocedural or framework-aware coverage.
- Dependency reachability is import evidence, not CVE/OSV vulnerability
  resolution and not proof that a vulnerable symbol is executed.
- WraithWall campaign matching is schema-tolerant contextual matching, not
  attacker attribution.
- The WraithWall client enforces HTTPS/host allowlisting, rejects private or
  loopback DNS destinations, blocks redirects, bounds responses, signs Raven
  requests with timestamp/nonce HMAC, and fails closed when Redis replay
  protection is unavailable. DNS can still change after validation, so deploy
  with controlled DNS/network egress.
- Existing non-Raven API callers retain the legacy optional-signature contract;
  Raven campaign/BGP reads specifically require tenant, freshness, integrity,
  and replay checks.
- Historical reconciliation is wired to CLI scans. Direct SDK calls do not
  write history unless the caller uses `MemoryStore` explicitly.
- Infrastructure checks inspect Docker/Kubernetes/Terraform/YAML text and do
  not validate a live cluster or cloud account.
