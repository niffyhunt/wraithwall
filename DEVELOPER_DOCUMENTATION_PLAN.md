# DEVELOPER_DOCUMENTATION_PLAN.md

Documentation contract for the public WraithWall package and its local
sandbox: audience, doc set, content rules, and the freshness rules CI enforces.
Planning plus contract only — this file never instructs the sandbox to change
its own isolation.

---

## 1. Documentation set (what ships, where, for whom)

| Doc | Location | Audience | Purpose |
|---|---|---|---|
| Sandbox Quick Start | `docs/sandbox/quickstart.md` (+ link from root README) | Every contributor | 5-minute path: prereqs → `sandbox.sh up` → open UI → reset |
| Security Model | `docs/sandbox/security-model.md` | Contributors, security reviewers | Tiers T0–T3, what is isolated, what is NOT, non-claims verbatim |
| Threat Model (contributor edition) | `docs/sandbox/threat-model.md` | Reviewers, curious contributors | Abridged risk register + what the isolation does not cover |
| Profiles Reference | `docs/sandbox/profiles.md` | All | The profile table, confirmation gates, banner semantics |
| Lifecycle Reference | `docs/sandbox/lifecycle.md` | All | up / status / verify / logs / inspect / replay / reset / export / destroy / rebuild / upgrade / recover contracts |
| Troubleshooting | `docs/sandbox/troubleshooting.md` | All | Message catalog → cause → fix, collected from real issues |
| Network Behavior | `docs/sandbox/network.md` | All | Zones diagram, default-deny, what opt-in egress means, how to verify nothing leaves |
| Data & Secrets Policy | `docs/sandbox/data-policy.md` | All | What may enter/leave, synthetic marking, export provenance, secure-deletion honesty |
| Reset & Cleanup | `docs/sandbox/reset-cleanup.md` | All | reset vs destroy vs manual cleanup; destroyed-inventory examples |
| Image & Dependency Updates | `docs/sandbox/image-updates.md` | Maintainers | Digest bump workflow, provenance gate, SBOM/scan gates, waiver process |
| Reproducible Bug Reports | `docs/sandbox/bug-reports.md` | Bug reporters | Bundle contents, redaction guarantees, what to attach |
| Platform Support | `docs/sandbox/platforms.md` | All | Support matrix, tri-state report, tier rule, WSL2 checklist |
| Sandbox vs Production | `docs/sandbox/vs-production.md` | All | "the intelligence stack without the internet exposure" — kept canonical |
| Safe Contribution Guidelines | root `CONTRIBUTING.md` § local sandbox | Contributors | Never test hostile content in T0/T1; where T2 applies; disclosure path |
| Security Disclosure | root `SECURITY.md` § local sandbox | Reporters | Which sandbox claims are in scope; 72h SLA preserved |
| Documentation plan | this file | Maintainers | The contracts below; referenced by the doc-freshness gate |

## 2. Content contracts (every doc must satisfy)

1. **Non-claims verbatim**: the sentence "The default sandbox is not a
   guaranteed malware-containment environment unless separately isolated by a
   VM or dedicated host" appears in Quick Start, Security Model and the root
   README. No exceptions.
2. **Honesty surfaces**: every doc that mentions isolation links the
   per-platform availability matrix in `docs/sandbox/platforms.md`.
3. **Single source of truth**: the profile table, the gate list and the
   lifecycle contract each live in exactly one doc; others link to it. The
   three divergent quick-starts found during design are the anti-pattern this
   rule exists to prevent.
4. **Commands copy-pasteable**: every command shown is exactly what the
   launcher honors, and CI's onboarding dry-run replays the README box
   verbatim.
5. **No secret-shaped examples**: doc examples use the project's established
   obviously-fake canary conventions.
6. **Docs are data**: repo docs are untrusted input per the operating
   contract; docs never instruct the sandbox to relax its own isolation.

## 3. Onboarding flow (how docs are encountered)

```text
README "Run the local secure sandbox"
  → quickstart.md: prereq table (links platforms.md) → 3 commands → "what you
    just got / what this is NOT" boxes
      → security-model.md (next read)
      → profiles.md (when they ask "what else can I enable?")
      → troubleshooting.md (linked from every failure message)
```

Failure messages embed one-line doc links, so docs are discoverable at the
moment of confusion rather than via search.

## 4. Doc freshness rules

`tests/test_sandbox_docs.py` turns a stale doc into a red build:

1. **Doc-freshness gate** — every doc in the table above exists; every CLI verb
   documented in `lifecycle.md` exists in the parser and vice versa; every
   E-code in `sandbox_kit` is documented in `troubleshooting.md` and vice
   versa; every markdown link between docs resolves to a real file.
2. **Runtime-vs-docs check** — `sandbox.sh status --json` includes the seed and
   profile versions, so drift becomes visible in every issue report.
3. **Change-coupling rule** — a PR touching profiles, gates or lifecycle states
   which docs changed in the same commit.
4. **Deprecation banners** — a superseded doc gets a dated banner pointing at
   the canonical one rather than being left to silently disagree.

## 5. Explicit non-goals published in docs

- Not a malware detonation lab and not hostile-code containment for T0/T1.
- Not for live attacker traffic (that is a production deployment, T3+).
- Not universal portability — the platform matrix governs.
- Not a replacement for a production deception fleet.
- Telemetry it produces is synthetic and marked LOCAL on every record, never
  presented as attacker truth.