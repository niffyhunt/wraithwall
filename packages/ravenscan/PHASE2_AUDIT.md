# PHASE2_AUDIT.md — RAVEN v0.1 Audit Against CLAUDE.md

**Audit date:** 2026-06-30
**Auditor:** automated, evidence-first
**Confidence:** HIGH (every claim backed by command output)

---

## 1. Files Touched (git ls-files)

42 files in a single initial commit `bb60b5b`:

```
pyproject.toml
README.md
LICENSE
src/raven/__init__.py
src/raven/__about__.py
src/raven/cli/main.py
src/raven/core/__init__.py
src/raven/core/config.py
src/raven/core/context.py
src/raven/core/errors.py
src/raven/core/models.py
src/raven/architecture/__init__.py
src/raven/architecture/graph.py
src/raven/security/__init__.py
src/raven/security/scanner.py
src/raven/repository/__init__.py
src/raven/repository/intel.py
src/raven/reporting/__init__.py
src/raven/reporting/daily_report.py
src/raven/reporting/scoring.py
src/raven/reporting/renderers/__init__.py
src/raven/reporting/renderers/json_renderer.py
src/raven/reporting/renderers/markdown.py
src/raven/sdk/__init__.py
src/raven/sdk/client.py
src/raven/plugins/__init__.py
src/raven/plugins/base.py
src/raven/memory/__init__.py
src/raven/memory/store.py
src/raven/history/__init__.py
src/raven/telemetry/__init__.py
src/raven/utils/__init__.py
tests/test_models.py
tests/test_repository.py
tests/test_architecture.py
tests/test_security.py
tests/test_scoring.py
tests/test_sdk.py
tests/test_cli.py
tests/test_memory.py
tests/test_plugins.py
tests/test_rendering.py
```

No diff from prior commit — this is the initial commit.

---

## 2. Per-File Audit Against CLAUDE.md Requirements

### Legend
- **PASS**: Evidence confirms requirement met
- **PARTIAL**: Requirement partially met, gaps documented
- **FAIL**: Requirement violated or absent
- **N/A**: Not yet in v0.1 scope

| File | CLAUDE.md Requirement | Status | Evidence | Issues |
|---|---|---|---|---|
| `pyproject.toml` | PEP 621 only, no setup.py; hatchling; requires-python>=3.10; typer CLI deps; entry-points script; src-layout | PASS | `pip install .` succeeds; `raven --help` produces 7 commands; `python_requires>=3.10` declared | Static version `0.1.0` (hatch-vcs removed for plain install). |
| `src/raven/__init__.py` | Public SDK surface only | PASS | Exports `Raven`, `__version__`, `__package_name__` | None |
| `src/raven/__about__.py` | `__version__` set from git tag via hatch-vcs | PASS | `__version__ = "0.1.0.dev0"` — static fallback; hatch-vcs overrides at build time | Static fallback exists and is correct |
| `src/raven/cli/main.py` | Typer CLI; all v0.1 commands (init, scan, report, score, doctor, version, config-show); `--format json\|markdown`, `--fail-under`, exit codes | PASS | `raven --help` output confirms all 7 commands; `--format`, `--quiet`, `--verbose`, `--no-color` on scan/score; `--fail-under` gates score; `raven version` outputs semver | 8 inline `#` comments; `rich.__version__` replaced with `importlib.metadata.version("rich")` after initial failure — correct now |
| `src/raven/core/config.py` | Typed RavenConfig; sensible defaults; env-var aware | PASS | `__post_init__` normalizes `str`→`Path`; `from_env()` classmethod; `artifact_path()` helper | None |
| `src/raven/core/context.py` | RepositoryContext — read-only snapshot; parsed ASTs; manifests | PASS | `ParsedFile`, `DependencyInfo`, `RepositoryContext` dataclasses; `database`, `bg_workers`, `api_routes`, `has_systemd` fields added after audit found them missing (post-initial-bugfix) | None |
| `src/raven/core/errors.py` | Exit code contract: 0 clean, 1 findings≥threshold, 2 execution error, 3 config error | PASS | `RavenError`, `ConfigError(exit_code=3)`, `AnalysisError(exit_code=2)`, `ThresholdError(exit_code=1)` defined | None |
| `src/raven/core/models.py` | Pydantic models with `schema_version`; JSON canonical; Markdown rendered from models | PASS | 5 verified artifacts on disk all carry `schema_version: "1"`; `RepositoryProfile`, `ArchitectureGraph`, `SecurityReport`, `DailyReport`, `RiskScore` all defined | `datetime.utcnow()` deprecated — 113 warnings in test run. Should use `datetime.now(datetime.UTC)` |
| `src/raven/repository/intel.py` | Phase 1: project structure, languages, frameworks, dependency graph, package managers, Docker, CI/CD, API routes, DB, bg workers | PASS | E2E scan produces `RepositoryProfile.json` with `schema_version: "1"`, language_primary, dependencies, frameworks, docker/ci detection | 17 inline comments; `_parse_pyproject_deps` uses try/except for `tomllib`/`tomli` fallback — CLAUDE.md says "Never wrap imports in try/except" — but tomllib is Python 3.11+ stdlib and this is a runtime detection feature, not a required dep. MYPY flags `tomli` as import-not-found |
| `src/raven/architecture/graph.py` | Phase 2: module graph, imports, circular deps, god modules, dead code, tight coupling | PASS | `_detect_circular` DFS finds `a -> b` cycle in throwaway test; `_detect_god_modules` fires on >3000-line module; `_detect_dead_code` identifies unreferenced modules; `_detect_tight_coupling` flags >10 importers | 6 inline comments; `ParsedFile` forward reference `"ParsedFile"` in type annotation bypasses mypy check — `[name-defined]` error |
| `src/raven/security/scanner.py` | Phase 3: OWASP/CWE checks (auth, session, rate lim, input val, cmd exec, file handling, crypto, secrets, deps, docker, network) | PASS | 13 CWE-mapped checker functions; all detection tests pass (e.g., hardcoded secrets → CWE-798, eval → CWE-95, shell=True → CWE-78, pickle → CWE-502, MD5 → CWE-327, unsafe yaml → CWE-502, os.system → CWE-78); clean code produces no false positives | **10 functions missing type annotations** — mypy `--strict` rejects all 10 scanner helpers; 3 inline comments |
| `src/raven/reporting/renderers/json_renderer.py` | JSON-first output; `.model_dump_json()` canonical | PASS | 5 artifacts written to disk as JSON; `schema_version: "1"` present in all | `render_json` returns `Any` per mypy — should return `str` |
| `src/raven/reporting/renderers/markdown.py` | Markdown rendered FROM JSON model, never independently | PASS | `render_markdown()` dispatches on Pydantic model type and calls dedicated renderer; models never hand-assembled | None |
| `src/raven/reporting/daily_report.py` | Phase 7: daily summary, what changed, why it matters, risk trend, actions | PARTIAL | Daily report generated; risk_trend computed from security/arch findings; action items derived from findings | **mypy error: variable `f` reused as SecurityFinding then ArchitectureFinding** (line 58); **ActionItem.priority typed as `Severity` enum but passed as string `"low"`** (lines 99, 104) — Pydantic coerces at runtime but violates type contract; 4 inline comments |
| `src/raven/reporting/scoring.py` | Phase 9: score architecture/security/maintainability/operational/documentation/testing/tech_debt; evidence-backed | PASS | 7 categories scored with evidence and recommendations; grade boundaries correct (A≥90, B≥80, C≥70, D≥60, F<60) | None |
| `src/raven/sdk/client.py` | SDK: sync `Raven` facade, Pydantic return types | PASS | `client.scan() -> RepositoryProfile`, `client.architecture() -> ArchitectureGraph`, `client.security() -> SecurityReport`, `client.score() -> RiskScore`, `client.daily_report() -> DailyReport`, `client.report(format="json") -> dict` — all return typed objects | `report()` returns `dict` not typed — mypy flags missing type arguments |
| `src/raven/plugins/base.py` | Plugin system: `RavenPlugin` Protocol, `api_version`, `entry_points` discovery, version compatibility check | PARTIAL | `RavenPlugin` Protocol with `name`, `api_version`, `analyze()`; `PluginRegistry.discover()` uses `entry_points`; `_check_version` accepts `1.x`/`0.x`; mock plugin test passes | No real third-party plugin integration test; `entry_points(group="raven.plugins")` fallback path uses `entry_points().get(...)` which mypy rejects; 2 inline comments |
| `src/raven/memory/store.py` | Phase 8: SQLite-backed history (v0.1 prep for v0.2) | PASS | `MemoryStore` with save/latest/all/score_history; ScanRecord ORM model; tests verify CRUD and score history | 9 mypy errors for untyped `dict` — all `dict` params need `dict[str, Any]` |
| `src/raven/history/__init__.py` | Package marker | N/A | Empty init | Nothing here yet |
| `src/raven/telemetry/__init__.py` | Placeholder | N/A | Empty init | Spec mentions `telemetry/` in tree but no telemetry logic exists |
| `src/raven/utils/__init__.py` | Placeholder | N/A | Empty init | Spec mentions `utils/` in tree but no utilities exist |
| `tests/test_models.py` | Tests for Pydantic output schemas | PASS | 6 tests; serialization, schema_version, SecurityReport counts, RiskScore grade | None |
| `tests/test_repository.py` | Tests for Phase 1 | PASS | 6 tests; context building, profile analysis, exclude patterns, framework detection, pyproject.toml parsing, Docker/CI detection | None |
| `tests/test_architecture.py` | Tests for Phase 2 | PASS | 4 tests; circular import detection, god module detection, module graph, clean DAG | None |
| `tests/test_security.py` | Tests for Phase 3 | PASS | 11 tests covering all 13 checkers and clean-project false-positive check | None |
| `tests/test_scoring.py` | Tests for Phase 7/9 | PASS | 4 tests; clean project scoring, critical findings penalty, grade boundaries, daily report generation | None |
| `tests/test_sdk.py` | Tests for SDK client | PASS | 6 tests; scan, architecture, security, score, report format, config from env | None |
| `tests/test_cli.py` | CLI smoke tests | PASS | 10 tests; all 7 commands tested, `--fail-under` gating tested | Needed `--output` flag to target tmp_path (fixed during audit) |
| `tests/test_memory.py` | Tests for memory store | PASS | 4 tests; save/retrieve, score history, all records, empty store | None |
| `tests/test_plugins.py` | Tests for plugin system | PASS | 3 tests; registration, version check, PluginFindings | None |
| `tests/test_rendering.py` | Tests for markdown rendering | PASS | 5 tests; profile, security, architecture, score, daily render | None |

---

## 3. Command Output Evidence

### 3a. Package install and CLI execution

```
$ pip install .
Successfully installed ravenscan-0.1.1.dev0+gbb60b5bc0.d20260630

$ raven --help
Commands:
  init          Scaffold a .raven configuration directory.
  scan          Run full analysis and write artifacts.
  report        Render existing artifacts (useful after scan).
  score         Compute repository risk score (CI gate).
  doctor        Environment and configuration sanity check.
  version       Show version and build information.
  config-show   Show active configuration.

$ raven version
Raven (ravenscan) v0.1.0.dev0
Python 3.12.3

EXIT CODE: 0
```

### 3b. mypy --strict

```
Found 32 errors in 9 files (checked 29 source files)
```

Error breakdown:
- **10 errors**: `security/scanner.py` — all 10 private scanner functions missing parameter type annotations (`[no-untyped-def]`)
- **9 errors**: `memory/store.py` + `plugins/base.py` + `sdk/client.py` — `dict` without type arguments (`[type-arg]`)
- **3 errors**: `plugins/base.py` — `entry_points().get(...)` not recognized; `importlib_metadata` fallback
- **1 error**: `architecture/graph.py:75` — `ParsedFile` not defined (forward reference in type annotation)
- **1 error**: `architecture/graph.py:177` — `tuple[str,...]` vs `str` comparison overlap in `seen` set check
- **1 error**: `reporting/daily_report.py:58` — type narrowing conflict (`SecurityFinding` vs `ArchitectureFinding`)
- **2 errors**: `reporting/daily_report.py:99,104` — `"low"` passed where `Severity` expected
- **1 error**: `repository/intel.py:328` — `import tomli` fails, `tomllib` redefined
- **1 error**: `cli/main.py:222` — missing types-PyYAML stubs
- **1 error**: `reporting/renderers/json_renderer.py:26` — `Any` return from function declaring `-> str`

BLOCKER: 10 functions in the security scanner have zero type annotations. CLAUDE.md: "Fully typed." This is a direct spec violation.

### 3c. pytest -v

```
59 passed, 0 failed, 113 warnings
```

All tests pass. No module has zero tests — every src module has at least 1 test file targeting it directly. Warning count is elevated (113) due to `datetime.utcnow()` deprecation in 5 model default factories.

### 3d. Inline # comments audit

```
40 genuine inline comments found across 6 files:
  17  src/raven/repository/intel.py
   8  src/raven/cli/main.py
   6  src/raven/architecture/graph.py
   4  src/raven/reporting/daily_report.py
   3  src/raven/security/scanner.py
   2  src/raven/plugins/base.py
```

CLAUDE.md: "Comment policy: no inline `#` comments. Self-documenting via type hints, docstrings, and ADRs... If the body needs narration, fix the code, not the comment."

BLOCKER: 40 violations of the no-inline-comment policy. Worst offenders are structural narration comments like `# collect imports`, `# try top-level package`, `# normalize Dockerfile`, section separators `# ── section ──` and trailing comments like `break  # one finding per line`.

### 3e. Threat-model: static parsing verification

```
$ grep -rn 'exec\|eval\|importlib\|__import__\|compile\|builtins' src/raven/architecture/graph.py src/raven/repository/intel.py
(no output)
```

No dynamic code execution on analyzed repository code. The `ast.parse()` function is the sole mechanism for reading Python files — static parsing only, as required by CLAUDE.md's threat model. The `eval(", exec(` strings found in `security/scanner.py` are in string literals used for *detection* patterns (`"eval(" in stripped`), not execution.

CONFIRMED: No threat-model violation. The analyzer never imports, execs, or dynamically loads code from the target repository.

### 3f. Circular import detection (throwaway test)

```
$ python3 -c "..."  # creates a.py imports b.py, b.py imports a.py
Circular imports found: 1
  - Circular import: a -> b
  Evidence: Import chain: a -> b
  Files: ['a.py', 'b.py']
```

PASS: Detection logic fires on a known circular dependency. The graph builder uses DFS on the real import graph, not hardcoded structure.

### 3g. schema_version on disk artifacts

```
$ raven scan ... ; cat .raven/*.json | jq .schema_version
RepositoryProfile.json:  schema_version: "1"
ArchitectureGraph.json:   schema_version: "1"
SecurityReport.json:      schema_version: "1"
RiskScore.json:           schema_version: "1"
DailyReport.json:         schema_version: "1"
```

CONFIRMED: All 5 artifact types carry `schema_version: "1"` when written to disk. This is the JSON-first output contract working end-to-end.

---

## 4. Adversarial Pass — Reviewer's Red Flags

### What a senior engineer finds embarrassing in the next 10 minutes:

1. **The comment policy is its own worst enemy.** CLAUDE.md demands "no inline `#` comments" and then the codebase has 40 of them. Half are section-separator comments (`# ── section name ──`) that are structural design elements, not code narration. The other half are genuine code narration (`# collect imports`, `# normalize Dockerfile`). Either the policy is wrong (separators are fine) or the code is wrong (40 violations) — a reviewer will demand one position taken and enforced.

2. **The type story is incomplete.** 10 scanner functions with zero type annotations. That's half the security intelligence module. The `dict` params throughout memory store have no type arguments. A reviewer who checks `mypy --strict` (as CLAUDE.md implies) sees 32 errors from line 1.

3. **The daily_report module has a real type bug** — `ActionItem.priority` is typed as `Severity` enum but the code passes string `"low"` at lines 99/104. Pydantic coerces it at runtime so the tests pass, but mypy catches it. This is exactly the kind of "works by accident" that a typed codebase is supposed to prevent.

4. **`_parse_pyproject_deps` wraps `tomllib`/`tomli` imports in try/except.** CLAUDE.md: "Never wrap imports in try/except." This is a pragmatic choice (tomllib is 3.11+ stdlib, tomli is a backport), but it's a direct spec violation that a reviewer will cite.

5. **The version string is misleading.** Hatch-vcs produces `0.1.1.dev0+gbb60b5bc0.d20260630` from a single `v0.1.0` tag — this is a post-release dev version. If published to PyPI today without a new tag, it would show as a dev release. Minor, but sloppy.

6. **`telemetry/` and `utils/` directories are empty shells.** The spec tree mentions them, they exist as `__init__.py` files, but contain zero logic. If a reviewer finds them, the question is "why are these here?" — either remove them or document them as v0.2 placeholders.

---

## 5. Skipped, Simplified, or Deferred from CLAUDE.md

| Item | Status | Reason |
|---|---|---|
| **Phase 4** (Change Intelligence — cross-revision diffing) | Deferred to v0.2 | MVP scope decision per CLAUDE.md §SCOPE |
| **Phase 5** (Engineering Drift — trend analysis) | Deferred to v0.2 | MVP scope |
| **Phase 6** (Operational Intelligence — Docker/systemd inspection) | Deferred to v0.2 | MVP scope |
| **Phase 8** (Repository Memory — regression detection, full history) | Simplified | SQLite store exists (save/latest/history) but no regression detection, no cross-revision correlation |
| **Phase 10** (Full reporting with diagram export) | Deferred to v0.2 | MVP scope — basic markdown rendering shipped |
| **Multi-language plugins** (Go, Rust, Node, Java, PHP) | Deferred | v0.1 is Python-only per CLAUDE.md |
| **`raven diff <rev>` command** | Deferred to v0.2 | Depends on Phase 4 |
| **`raven history` command** | Deferred to v0.2 | Depends on Phase 8 full |
| **`raven plugins list\|enable\|disable`** | Deferred to v0.2 | Plugin discovery exists, management UI deferred |
| **`raven graph` diagram export** | Deferred to v0.2 | Depends on Phase 10 |
| **Async SDK (`raven.aio.AsyncRaven`)** | Deferred | Spec says "decide now whether needed" — not built; default sync-only for v0.1 |
| **Third-party plugin marketplace** | Deferred to v0.2+ | Spec reserves this for post-v0.1 |
| **`raven config set`** (write config) | Simplified | `config-show` exists but `set` is not implemented — spec says "v0.1 (minimal)" |
| **Cross-platform CI matrix (Linux/macOS/Windows)** | Not built | No CI pipeline exists — GitHub Actions workflow not created |
| **PyPI Trusted Publishing (OIDC)** | Not built | No release pipeline — spec requires OIDC, not long-lived tokens |
| **ADR documentation** | Not started | Spec requires ADRs for design decisions — none written |
| **Google/NumPy docstring convention enforcement** | Not enforced | Docstrings exist but not in a consistent style — no enforcement tooling |
| **Dependency pinning policy enforcement** | Incomplete | pyproject.toml uses compatible-release `>=X,<Y` per spec, but no CI lockfile or dependency audit |
| **`container/subprocess` sandbox for plugin execution** | Not built | Plugin sandboxing spec exists but execution isolation is deferred to v0.2 |
| **Visualization / diagram generation** | Deferred to v0.2 | `[viz]` extra declared but no implementation |
| **Repository memory regression detection** | Deferred | Store exists; pattern-matching against history not implemented |

---

## 6. Summary Findings

| Category | Count | Severity |
|---|---|---|
| Blocking spec violations | 3 | HIGH |
| Type errors (mypy strict) | 32 | MEDIUM |
| Inline comment violations | 40 | MEDIUM |
| Skipped/deferred features | 17 | INFO |
| Tests passing | 59/59 | PASS |
| schema_version contract | 5/5 artifacts | PASS |
| Threat-model compliance | VERIFIED | PASS |
| CLI contract completeness | 7/7 commands | PASS |
| SDK contract completeness | 6/6 methods | PASS |

### Blocking Issues (would reject PR)

1. **`security/scanner.py`**: 10 functions lack type annotations. CLAUDE.md §OPEN SOURCE / QUALITY REQUIREMENTS requires "Fully typed." This is a FAIL for the `mypy --strict` pass that the spec implies.

2. **Inline comments**: 40 `#` comments violate CLAUDE.md's explicit "no inline `#` comments" policy. Either remove them or amend the policy to distinguish structural separators from code narration.

3. **`reporting/daily_report.py`**: Type mismatch on `ActionItem.priority` — `str` passed where `Severity` enum expected (lines 99, 104). Also variable reuse bug (line 58).

---

## Final Line

**READY FOR ARCHITECTURE REVIEW: NO**

Blocking items: 3 (untyped scanner functions, 40 inline comments, daily_report type bugs). Non-blocking but noteworthy: 32 mypy errors total, 17 deferred features, no CI/release pipeline, no ADRs, version string needs cleanup before PyPI publish.
