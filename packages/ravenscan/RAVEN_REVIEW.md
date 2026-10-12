# RAVEN COMPREHENSIVE ARCHITECTURE REVIEW

**Review date:** 2026-07-09
**Repository:** `packages/ravenscan/` (monorepo of `niffyhunt/wraithwall`)
**Version:** 0.1.0.dev0 (hatch-vcs: `0.1.1.dev0+gbb60b5bc0.d20260630`)
**License:** MIT
**Package:** `ravenscan` (published on PyPI)
**Status:** Development Status 3 - Alpha

---

## TABLE OF CONTENTS

1. [CURRENT STATE: Architecture and Components](#1-current-state)
2. [MISSING COMPONENTS](#2-missing-components)
3. [INTEGRATION OPPORTUNITIES WITH WRAITHWALL](#3-integration-opportunities)
4. [FEATURE ROADMAP FOR v1.0](#4-feature-roadmap-for-v10)
5. [RELATIONSHIP TO WRAITHWALL](#5-relationship-to-wraithwall)
6. [MAJOR UPGRADES NEEDED BEFORE PUBLIC OPEN-SOURCE RELEASE](#6-major-upgrades)

---

## 1. CURRENT STATE

### 1.1 What Raven Does

Raven is an **open-source engineering intelligence agent** — a local CLI/SDK tool that analyzes source code repositories to produce evidence-backed intelligence reports. It discovers a project's structure, architecture, security posture, and risk score, and tracks how those change over time.

### 1.2 Component Inventory (42 source files)

#### Package Structure

```
ravenscan/
  pyproject.toml           # Hatchling build, PEP 621 metadata
  README.md                # Usage documentation
  LICENSE                  # MIT
  PHASE2_AUDIT.md          # Detailed audit against spec (dated 2026-06-30)
  docs/                    # Empty directory (placeholder)

  src/raven/
    __init__.py            # Public SDK: exports Raven, __version__
    __about__.py           # __version__ = "0.1.0.dev0"
    py.typed               # PEP 561 marker

    core/
      config.py            # RavenConfig dataclass (env-aware, typed)
      context.py           # RepositoryContext, ParsedFile, DependencyInfo
      models.py            # 20+ Pydantic output models with schema_version
      errors.py            # 4 error types with exit codes (0-3)

    cli/
      main.py              # Typer CLI: 10 commands (546 lines)

    sdk/
      client.py            # Raven sync client facade (193 lines)

    repository/
      intel.py             # Phase 1: repo intelligence (484 lines)

    architecture/
      graph.py             # Phase 2: module graph with import analysis (289 lines)

    security/
      scanner.py           # Phase 3: 13 CWE-mapped security scanners (662 lines)
      entropy.py           # Shannon entropy for secret FP reduction
      contextual.py        # Test/file-based suppression
      calibration.py       # Confidence calibration per analyzer

    drift/
      analyzer.py          # Phase 5: engineering drift measurement (288 lines)
      tracker.py           # Phase 4: semantic change tracking (486 lines)

    delta/
      base.py              # Delta dataclasses (DeltaEntry, RevisionDelta)
      analyzers.py         # Cross-revision comparison: arch, security, deps, symbols, imports, routes, evolution

    reporting/
      scoring.py           # Phase 9: 8-category risk scoring (364 lines)
      daily_report.py      # Phase 7: daily engineering forensics (144 lines)
      graph_builder.py     # GraphData structures for visualization (199 lines)
      visualization.py     # DOT/SVG graphviz rendering (208 lines)
      renderers/
        json_renderer.py   # Canonical JSON output
        markdown.py        # Markdown rendered FROM JSON models

    memory/
      store.py             # SQLite-backed history and FP tracking (179 lines)

    plugins/
      base.py              # RavenPlugin Protocol + PluginRegistry (115 lines)
      registry.py          # SecurityAnalyzerRegistry (71 lines)
      security/
        base.py            # SecurityAnalyzer ABC (112 lines)
        python/analyzer.py # Wrapper for Phase 3 scanner
        go/analyzer.py     # Go security checks (98 lines)
        javascript/analyzer.py # JS/TS security checks (104 lines)
        rust/analyzer.py   # Rust security checks (97 lines)
        java/analyzer.py   # Java/Kotlin/Scala checks (100 lines)

    operational/
      inspector.py         # Phase 6: Docker, systemd, psutil health (354 lines)

    telemetry/             # Empty __init__.py (placeholder)
    history/               # Empty __init__.py (placeholder)
    utils/
      logging.py           # Centralized logging config (50 lines)

  tests/
    test_models.py, test_repository.py, test_architecture.py
    test_security.py, test_scoring.py, test_sdk.py
    test_cli.py, test_memory.py, test_plugins.py
    test_plugins_security.py, test_rendering.py
    test_drift.py, test_operational.py
    test_integration.py, test_edge_cases.py
```

### 1.3 Implemented Phases

| Phase | Name | Status | Details |
|-------|------|--------|---------|
| 1 | Repository Intelligence | DONE | Languages, frameworks, deps, Docker, CI/CD, routes, workers, DB |
| 2 | Architecture Graph | DONE | Module graph, circular imports, god modules, dead code, coupling |
| 3 | Security Intelligence | DONE | 13 CWE-mapped Python scanners; multi-language plugins for Go, JS/TS, Rust, Java |
| 4 | Change Intelligence | DONE | Auth, authorization, API endpoints, shell exec, filesystem, Docker, env vars, Redis, DB migrations, permissions, infrastructure |
| 5 | Engineering Drift | DONE | Complexity, coupling, duplication, TODOs, comment ratio |
| 6 | Operational Intelligence | PARTIAL | Docker containers, systemd, CPU/memory/disk (via psutil) |
| 7 | Daily Engineering Forensics | DONE | Summary, changes, risk trend, action items |
| 8 | Repository Memory | SIMPLIFIED | SQLite store exists; no regression detection |
| 9 | Intelligence Scoring | DONE | 8 categories: arch, sec, maintainability, ops, docs, testing, tech debt, DX |
| 10 | Full Reporting/Diagrams | PARTIAL | Graphviz visualization exists but no advanced diagram export |

### 1.4 CLI Commands (10 total)

| Command | Purpose |
|---------|---------|
| `init` | Scaffold `.raven/` directory |
| `scan` | Full analysis (all phases), writes artifacts |
| `report` | Render existing artifacts |
| `score` | Compute risk score (CI gate with `--fail-under`) |
| `doctor` | Environment sanity check |
| `version` | Show version info |
| `config-show` | Show active configuration |
| `diff` | Semantic diff against prior scan |
| `graph` | Generate architecture/dependency graphs (Graphviz) |
| `mark-false-positive` / `unmark-false-positive` / `list-false-positives` | FP management |

### 1.5 Output Artifacts (written to `.raven/`)

1. `RepositoryProfile.{json,md}` — Project structure, deps, languages
2. `ArchitectureGraph.{json,md}` — Module graph, architectural findings
3. `SecurityReport.{json,md}` — CWE-mapped security findings
4. `RiskScore.{json,md}` — 8-category risk score with grade (A-F)
5. `DailyReport.{json,md}` — Daily forensics summary

### 1.6 SDK Surface

```python
from raven import Raven
client = Raven(RavenConfig(path="."))

profile = client.scan()              # -> RepositoryProfile
arch = client.architecture()         # -> ArchitectureGraph
security = client.security()         # -> SecurityReport
risk = client.score(...)             # -> RiskScore
daily = client.daily_report(...)     # -> DailyReport
drift = client.drift_snapshot(...)   # -> DriftSnapshot
changes = client.track_changes(...)  # -> ChangeReport
ops = client.operational()           # -> OperationalHealth
report = client.report(fmt="json")   # -> dict (combined)
findings = client.ai_findings(...)   # -> list[AIFinding]
```

### 1.7 Known Issues (from PHASE2_AUDIT.md)

**BLOCKING:**
1. 10 security scanner functions lack type annotations (mypy `--strict` failure)
2. 40 inline `#` comment violations of the no-inline-comment policy
3. `ActionItem.priority` type mismatch: `str("low")` passed where `Severity` enum expected

**MEDIUM:**
- 32 mypy errors total
- `datetime.utcnow()` deprecated (113 pytest warnings)
- `telemetry/` and `history/` are empty placeholders

---

## 2. MISSING COMPONENTS

### 2.1 Critical Gaps

| Component | Impact | Priority |
|-----------|--------|----------|
| **No CI/CD pipeline** | No GitHub Actions, no automated testing, no release automation | HIGH |
| **No cross-platform testing matrix** | Linux-only testing; macOS/Windows untested | HIGH |
| **No PyPI OIDC trusted publishing** | Cannot publish releases securely | HIGH |
| **No ADR documentation** | No architectural decision records for design choices | HIGH |
| **Phase 8 regression detection** | SQLite store exists but no pattern-matching against history | MEDIUM |
| **Plugin sandboxing** | Third-party plugins run in-process with no isolation | MEDIUM |
| **No dependency pinning/lockfile** | No lockfile for reproducible installs | MEDIUM |

### 2.2 Feature Gaps (v0.1 scope but deferred)

| Feature | Status | Notes |
|---------|--------|-------|
| Async SDK (`raven.aio.AsyncRaven`) | Not built | Spec says "decide now" — defaulted to sync |
| `raven config set` (write config) | Not built | Only `config-show` exists |
| Third-party plugin marketplace | Not started | Entry-point discovery exists, no marketplace |
| `raven plugins list\|enable\|disable` | Not started | Plugin discovery exists, management deferred |
| `raven history` command | Not started | Depends on Phase 8 |
| Cross-revision regression alerts | Not started | Store exists; no auto-alerting |
| Multi-format visualization export | Partial | Graphviz support exists but limited |

### 2.3 Language Coverage Gaps

| Language | Phase 1 | Phase 2 | Phase 3 | Notes |
|----------|---------|---------|---------|-------|
| Python | FULL | FULL | FULL | AST-parsed, all 13 checkers |
| JavaScript/TypeScript | FULL | NONE | FULL | Regex-based security only |
| Go | FULL | NONE | FULL | Regex-based security only |
| Rust | FULL | NONE | FULL | Regex-based security only |
| Java/Kotlin/Scala | FULL | NONE | FULL | Regex-based security only |
| Ruby, PHP, C#, C/C++ | PARTIAL | NONE | NONE | Language detection only |
| Shell, Docker, YAML | PARTIAL | NONE | NONE | File classification only |

Phase 2 (architecture graph) and Phase 5 (drift) are Python-only. Multi-language architecture analysis would require AST parsers for each language.

### 2.4 Documentation Gaps

| Document | Status |
|----------|--------|
| README.md | EXISTS (basic usage) |
| API reference | MISSING |
| Plugin development guide | MISSING |
| Architecture guide | MISSING |
| Contributing guide | MISSING |
| ADR records | MISSING (0 ADRs) |
| Security model / threat model | MISSING |
| Changelog | MISSING |

---

## 3. INTEGRATION OPPORTUNITIES WITH WRAITHWALL

### 3.1 Current Integration Status: NONE

Raven has **zero references** from the main WraithWall application. It is a completely independent project with its own build system, its own PyPI package, and its own test suite. There is no `import raven` anywhere in the main `main.py` or any WraithWall module.

### 3.2 Why This Makes Sense

The README explicitly states this separation:
> "Raven is a local CLI/SDK analyzer for repositories you point it at. It does NOT serve diagrams on wraithwall.online. There is no /api/raven/ingest on the production app."

This is a **correct design decision**. Raven is a standalone engineering intelligence tool meant for general-purpose codebase analysis. WraithWall is a production security operations platform. They serve different audiences and use cases.

### 3.3 Potential Integration Points

Despite the intentional separation, there are natural integration opportunities:

#### A. CI Pipeline Integration (Highest Value)
```python
# In WraithWall's CI/CD or deployment pipeline:
raven scan --output .raven --format json
raven score --fail-under 70
```
Use Raven as a pre-deployment gate in WraithWall's CI. This requires no code changes — just adding Raven to the CI environment.

#### B. Breach-Monitor / Cowrie-Analyzer Post-Mortems
```python
# After a Cowrie incident, run Raven on the cowrie-analyzer repo:
from raven import Raven
client = Raven(RavenConfig(path="/path/to/cowrie-analyzer"))
report = client.daily_report()
# Include Raven findings in incident playbook output
```
Use Raven to assess security posture of the breach-monitor and cowrie-analyzer subprojects after incidents.

#### C. API Endpoint for On-Demand Scanning
Add a `/api/raven/scan` endpoint in WraithWall that:
1. Accepts a git repository URL
2. Clones it to a temp directory
3. Runs Raven analysis
4. Returns the JSON report

This would enable the operator console to run Raven scans on arbitrary repos without installing the CLI.

#### D. Cross-Correlation with Canary/Threat Intel
Raven's `AIFinding` model (confidence, CWE, evidence, affected files) could feed into:
- `campaign_correlator.py` — correlate Raven findings with campaign activity
- `canary_service.py` — flag repos with hardcoded secrets matching canary tokens
- `incident_response.py` — include Raven architecture/security findings in playbook evidence

#### E. Operator Dashboard Widget
Add a Raven widget to the Vue operator console (`frontend/`) showing:
- Overall risk score and grade
- Security finding counts by severity
- Architecture health indicators
- Trend chart from `.raven/` history

### 3.4 Integration Architecture Recommendation

```
WraithWall (main.py)
  |
  |-- /api/raven/scan [new]  -->  subprocess.run(["raven", "scan", ...])
  |                                   |
  |                                   v
  |                              .raven/*.json  (read and return)
  |
  |-- /api/raven/score [new]  -->  subprocess.run(["raven", "score", ...])
  |
  |-- CI pipeline             -->  raven score --fail-under 70 (pre-deploy gate)
```

Use subprocess-based invocation rather than the SDK to maintain clean separation of concerns. The SDK can be used for tighter integration if needed.

---

## 4. FEATURE ROADMAP FOR v1.0

### 4.1 Immediate Blockers (pre-v0.2)

| # | Item | Effort | Impact |
|---|------|--------|--------|
| 1 | Fix 10 untyped scanner functions | Small | Removes mypy blocker |
| 2 | Fix 40 inline comment violations | Small | Removes policy violation |
| 3 | Fix `ActionItem.priority` type bug | Tiny | Removes type safety hole |
| 4 | Fix `datetime.utcnow()` deprecation | Tiny | Removes 113 warnings |
| 5 | Add GitHub Actions CI workflow | Medium | Enables automated testing |
| 6 | Add mypy `--strict` to CI | Small | Prevents regression |
| 7 | Add PyPI OIDC publishing workflow | Medium | Enables secure releases |
| 8 | Fix all 32 mypy errors | Medium | Type safety completeness |

### 4.2 v0.2 (Next Release)

| # | Feature | Priority |
|---|---------|----------|
| 1 | Phase 8 regression detection (compare against historical patterns) | HIGH |
| 2 | `raven history` command (score timeline, trend visualization) | HIGH |
| 3 | `raven plugins list\|enable\|disable` commands | MEDIUM |
| 4 | Multi-language Phase 2 (architecture graphs for JS/TS, Go, Rust) | MEDIUM |
| 5 | Plugin sandbox (subprocess/container isolation) | MEDIUM |
| 6 | Async SDK (`raven.aio.AsyncRaven`) | LOW |
| 7 | `raven config set/get` commands | LOW |
| 8 | Cross-platform CI (macOS, Windows) | LOW |

### 4.3 v1.0 Target

| # | Feature | Priority |
|---|---------|----------|
| 1 | GA-quality documentation (API ref, plugin guide, contributing) | HIGH |
| 2 | ADR documentation for all major design decisions | HIGH |
| 3 | Plugin marketplace (registry + `raven plugins search`) | MEDIUM |
| 4 | Stable SDK API (no breaking changes without deprecation cycle) | HIGH |
| 5 | Multi-repo fleet scan (`raven fleet scan --all`) | MEDIUM |
| 6 | Full cross-language AST analysis (Phases 1-3 for all supported languages) | MEDIUM |
| 7 | Trigger-based alerting (webhook, email, Slack when score drops) | LOW |
| 8 | WraithWall integration endpoints | LOW |

---

## 5. RELATIONSHIP TO WRAITHWALL

### 5.1 Current State: Fully Independent

**Raven is a standalone PyPI package** (`ravenscan`) with:
- Its own `pyproject.toml` and build system (hatchling)
- Its own test suite (59+ tests, pytest)
- Its own CLI (`raven` command via Typer)
- Its own SDK (`from raven import Raven`)
- Its own output directory (`.raven/`)
- Its own dependency tree (typer, rich, pydantic, pyyaml, sqlalchemy)
- Its own license (MIT — while WraithWall has no explicit license)
- Its own git history (single initial commit, no shared history with WraithWall)
- Zero imports from WraithWall or any WraithWall module

**WraithWall has zero references to Raven.** There is no:
- `import raven` in any WraithWall file
- `/api/raven/` endpoint in the Flask app
- Raven integration in `requirements.txt` or `main.py`
- Raven-related code in any WraithWall frontend or template

### 5.2 Recommended Relationship: Maintained Separation

**Keep Raven fully independent.** Here is the rationale:

| Aspect | Recommendation | Reason |
|--------|---------------|--------|
| Repository | **Separate** | Different audience, different lifecycle |
| PyPI package | **Maintain** | Already published; general-purpose tool |
| Source tree | **Keep in subdirectory** | Co-location for WraithWall developers, separate for consumers |
| Build system | **Separate** | Different dependencies, different versioning |
| CI/CD | **Separate workflows** | Different release cadence |
| Documentation | **Separate** | Different user personas |
| SDK | **Do not deprecate** | Already the primary consumption method |
| Integration | **Subprocess-based** | Avoid tight coupling; use CLI for CI, SDK for Python programs |

### 5.3 When to Use the SDK vs CLI

| Use Case | Method | Example |
|----------|--------|---------|
| CI/CD gate | CLI | `raven score --fail-under 70` |
| WraithWall API endpoint | subprocess | `subprocess.run(["raven", "scan", ...])` |
| Python programmatic | SDK | `Raven(RavenConfig(path=".")).scan()` |
| Pre-commit hook | CLI | `raven scan --format json --quiet` |

### 5.4 Versioning Strategy

```
WraithWall (no formal version)        Ravenscan v0.1.x (pre-GA dev)

WraithWall v1.x                        Ravenscan v1.x (stable API)

WraithWall integrates via              Independent project
subprocess/CLI                         with its own roadmap
```

Raven should maintain semantic versioning independently. WraithWall should pin a specific Raven version in its CI if it uses Raven as a pre-deployment gate.

---

## 6. MAJOR UPGRADES NEEDED BEFORE PUBLIC OPEN-SOURCE RELEASE

### 6.1 API Cleanup

| Issue | Severity | Fix |
|-------|----------|-----|
| `Raven.report()` returns untyped `dict` | MEDIUM | Add typed return model or TypedDict |
| `ActionItem.priority` typed as `Severity` but passed as `str` | HIGH | Use string union or fix all call sites |
| `MemoryStore.save()` uses untyped `dict` params | MEDIUM | Add `dict[str, Any]` type annotations |
| Scanner 10 private functions lack annotations | CRITICAL | Add `-> None` return types |
| `render_json()` declares `-> str` but returns `Any` | LOW | Fix return type |
| `DailyReport` variable `f` reused as different types (line 58) | MEDIUM | Rename loop variables |
| `entry_points()` fallback in `plugins/base.py` | LOW | Remove Python 3.8 fallback (3.10+ only) |
| `tomllib`/`tomli` try/except import | MEDIUM | Use tomllib only (3.11+), add to deps for 3.10 |

### 6.2 Documentation Needs

| Document | Status | Priority | Effort |
|----------|--------|----------|--------|
| **README.md** | EXISTS but minimal | MEDIUM | Add full usage examples, CI config, plugin docs |
| **API Reference** | MISSING | HIGH | Auto-generate from docstrings; publish to ReadTheDocs |
| **Plugin Development Guide** | MISSING | HIGH | Document `RavenPlugin` Protocol, registry, testing |
| **Architecture Guide** | MISSING | MEDIUM | Explain phase architecture, output models, extension points |
| **Contributing Guide** | MISSING | HIGH | PR process, coding standards, test expectations |
| **Changelog** | MISSING | HIGH | Track breaking changes between versions |
| **Security Model** | MISSING | MEDIUM | Document how Raven avoids executing target code |
| **ADR Records** | MISSING | HIGH | Formalize design decisions (why phases, why Pydantic, why SQLite) |
| **CLI Reference** | PARTIAL | MEDIUM | Document all flags, exit codes, and format options |
| **SDK Reference** | MISSING | HIGH | Document all methods, parameters, return types |

### 6.3 Testing Requirements

| Area | Current | Target | Priority |
|------|---------|--------|----------|
| Unit tests | 59+ passing | 100+ | MEDIUM |
| Integration tests | 6 tests | 15+ | HIGH |
| Edge case tests | 14 tests | 25+ | MEDIUM |
| Plugin security analyzer tests | 15+ | 30+ | HIGH |
| Cross-language analyzer tests | Minimal per language | 10+ per language | HIGH |
| CLI tests | 10 smoke tests | Full coverage of all flags | MEDIUM |
| Delta/diff tests | Minimal | Full cross-revision comparison | MEDIUM |
| Memory store tests | 4 tests | 10+ with concurrent access | LOW |
| Performance benchmarks | NONE | 5+ (timeouts, memory, large repos) | LOW |
| Security tests for Raven itself | NONE | SAST scan of Raven codebase | MEDIUM |

### 6.4 Integration Patterns (Recommended)

#### A. WraithWall CI Integration (copy-paste ready)

```yaml
# .github/workflows/raven-gate.yml
name: Raven CI Gate
on: [push, pull_request]
jobs:
  raven-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install ravenscan
      - run: raven scan --format json --quiet
      - run: raven score --fail-under 70
```

#### B. WraithWall API Endpoint (new blueprint)

```python
# raven_integration.py — a new Blueprint for WraithWall
import subprocess, json, tempfile
from flask import Blueprint, request, jsonify

raven_bp = Blueprint("raven", __name__)

@raven_bp.route("/api/raven/scan", methods=["POST"])
def raven_scan():
    repo_url = request.json.get("repo_url")
    with tempfile.TemporaryDirectory() as tmpdir:
        subprocess.run(["git", "clone", repo_url, tmpdir], check=True)
        result = subprocess.run(
            ["raven", "scan", "--format", "json", "--output", tmpdir],
            capture_output=True, text=True
        )
        artifacts = {}
        for f in ["RepositoryProfile", "ArchitectureGraph", "SecurityReport",
                   "RiskScore", "DailyReport"]:
            p = Path(tmpdir) / ".raven" / f"{f}.json"
            if p.exists():
                artifacts[f] = json.loads(p.read_text())
        return jsonify(artifacts)
```

#### C. Canary/Secrets Cross-Correlation

```python
# In canary_service.py integration
raven_findings = client.ai_findings()
for finding in raven_findings:
    if finding.cwe_id == "CWE-798" and finding.confidence > 0.8:
        for file_path in finding.affected_files:
            log_canary_trigger("raven_hardcoded_secret",
                               file=file_path,
                               line=finding.affected_lines[0])
```

### 6.5 Missing Features for Public Release

| Feature | Priority | Reason |
|---------|----------|--------|
| **GitHub Actions CI workflow** | CRITICAL | Cannot merge PRs without automated testing |
| **mypy --strict in CI** | HIGH | Prevents type regression |
| **PyPI OIDC publishing** | HIGH | Cannot publish releases without secure auth |
| **Changelog (CHANGELOG.md)** | HIGH | Required for semver compliance |
| **Security policy (SECURITY.md)** | HIGH | Required for vulnerability reporting |
| **Contributing guide (CONTRIBUTING.md)** | HIGH | Required for external contributors |
| **Code of Conduct** | MEDIUM | Standard for open-source projects |
| **Issue and PR templates** | MEDIUM | Standardizes contributions |
| **Lockfile** (requirements-dev.lock) | MEDIUM | Reproducible development environment |
| **pyproject.toml classifiers update** | MEDIUM | Add Development Status 4 - Beta for v0.2 |
| **Multi-arch testing (macOS, Windows)** | MEDIUM | Cross-platform compatibility |

### 6.6 Code Quality Improvements

| Area | Current State | Target State |
|------|---------------|--------------|
| Type annotations (mypy strict) | 32 errors | 0 errors |
| Inline comments | 40 violations | 0 violations |
| Docstrings | Inconsistent style | Google/NumPy consistent |
| Test coverage | ~60% (estimated) | >85% |
| Code complexity | Some modules >400 lines | Max 400 lines per module |
| Import safety | Never executes target code | Documented threat model |
| Dependency management | Compatible-release ranges | Pinned dev dependencies with lockfile |
| Python version support | 3.10-3.13 | Test against all supported versions |

### 6.7 Security Hardening for Raven Itself

| Concern | Current | Recommendation |
|---------|---------|----------------|
| Plugin code execution | In-process, no isolation | Subprocess sandbox or container |
| AST parsing safety | `ast.parse()` only, safe | Add SyntaxError timeout guard |
| File reading | UTF-8 with errors=replace | Add binary file heuristics |
| Large repository DoS | 2MB file size limit | Add total file count and time limits |
| Symlink traversal | Not checked | Add symlink detection |
| `.raven/` output safety | No validation | Add output path sanitization |
| Dependency supply chain | No lockfile | Add pip freeze or lock file |

---

## SUMMARY

Raven v0.1 is a **well-architected, functional alpha** with a clear separation of concerns, a modular phase-based architecture, and a usable CLI/SDK. It has significant strengths:

- **Strong data model**: Pydantic models with schema_version for forward compatibility
- **Clean architecture**: Repository pattern, plugin system, registry pattern
- **Evidence-first output**: JSON canonical, Markdown rendered from models
- **Good test coverage**: 59+ tests, all passing
- **Multi-language support**: 5 languages for security analysis
- **Already published**: PyPI package exists

However, it has **critical gaps** before public open-source release:

1. **Type safety**: 32 mypy errors including 10 untyped functions in the security scanner
2. **No CI/CD**: No automated testing, no release pipeline, no PyPI publishing automation
3. **Policy violations**: 40 inline comments, 1 wrapped import, 1 type mismatch
4. **No integration with WraithWall**: Zero cross-references (intentional but limiting)
5. **Incomplete implementations**: telemetry/ and history/ are empty shells
6. **Missing documentation**: No ADRs, no API reference, no contributing guide, no changelog
7. **No plugin sandboxing**: Third-party plugins run in-process with no isolation

### Recommended Next Steps (Ordered)

1. **Fix all type errors** (32 mypy issues) — priority because they block CI
2. **Fix inline comment policy violations** (or amend the policy)
3. **Fix ActionItem type bug** (2-minute fix, removes a real type hole)
4. **Add GitHub Actions CI** with mypy --strict, pytest, and Python 3.10-3.13 matrix
5. **Add PyPI OIDC publishing workflow**
6. **Write ADR documentation** for the phase architecture
7. **Add plugin development guide** and API reference
8. **Implement Phase 8 regression detection** (leverage existing SQLite store)
9. **Add `raven history` command** (leverage existing score_history query)
10. **Release v0.2** with all blockers fixed
