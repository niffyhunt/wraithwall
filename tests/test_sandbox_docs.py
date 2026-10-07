"""Phase 9 doc-freshness gates: the sandbox documentation set cannot rot.

Roadmap Phase 9 acceptance: "stale doc ⇒ CI red". These tests enforce:

  1. every doc in the Stage 3 doc plan exists (image-updates.md is Phase 10's,
     excluded until that phase ships),
  2. every E-code in sandbox_kit is documented in troubleshooting.md, and every
     E-code documented there exists in code (both directions),
  3. every CLI verb documented in lifecycle.md exists in the parser,
  4. every markdown link between sandbox docs (and from root integrations)
     resolves to a real file,
  5. the root README / CONTRIBUTING / SECURITY integrations exist and reference
     real paths,
  6. the non-claims sentence (security-model) stays in quickstart.md — the G13
     placement rule.

Pure text/codebase checks; no Docker, no app import, fast by design.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DOCS = REPO / "docs" / "sandbox"

# Stage 3 doc plan; image-updates.md is authored in Phase 10 (roadmap).
EXPECTED_DOCS = {
    "quickstart.md",
    "security-model.md",
    "threat-model.md",
    "profiles.md",
    "lifecycle.md",
    "troubleshooting.md",
    "network.md",
    "data-policy.md",
    "reset-cleanup.md",
    "bug-reports.md",
    "vs-production.md",
    "platforms.md",
}
PHASE_10_DOCS = {"image-updates.md"}

SANDBOX_VERBS = {
    "up", "status", "profiles", "platform", "stop", "destroy", "replay",
    "logs", "inspect", "export", "reset", "recover", "verify",
    "rebuild-images", "upgrade",
}


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


# ── 1. the doc set exists ────────────────────────────────────────────────────

def test_stage3_doc_set_complete():
    missing = [d for d in sorted(EXPECTED_DOCS) if not (DOCS / d).exists()]
    assert not missing, f"missing sandbox docs: {missing}"


def test_doc_plan_files_referenced_by_the_plan_exist():
    plan = (REPO / "DEVELOPER_DOCUMENTATION_PLAN.md").read_text(encoding="utf-8")
    for name in sorted(EXPECTED_DOCS | PHASE_10_DOCS):
        assert f"`docs/sandbox/{name}`" in plan, f"plan no longer references {name}"


# ── 2. E-codes: code ↔ docs agreement, both directions ──────────────────────

def _codes_in_code() -> set[str]:
    codes: set[str] = set()
    for py in (REPO / "sandbox_kit").glob("*.py"):
        codes |= set(re.findall(r"\bE\d{3}\b", py.read_text(encoding="utf-8")))
    return codes


def _codes_in_troubleshooting() -> set[str]:
    text = _read(DOCS / "troubleshooting.md")
    # table rows look like: | **E104** | ...
    return set(re.findall(r"\*\*(E\d{3})\*\*", text))


def test_every_code_e_code_is_documented():
    real = {c for c in _codes_in_code() if c[1] != "0"}  # drop 0x constants noise
    undocumented = real - _codes_in_troubleshooting()
    assert not undocumented, f"E-codes in code but not in troubleshooting.md: {sorted(undocumented)}"


def test_every_documented_e_code_exists_in_code():
    phantom = _codes_in_troubleshooting() - _codes_in_code()
    assert not phantom, f"E-codes documented but not in code: {sorted(phantom)}"


# ── 3. documented verbs exist in the parser ─────────────────────────────────

def test_lifecycle_docs_only_reference_real_cli_verbs():
    text = _read(DOCS / "lifecycle.md")
    for verb in SANDBOX_VERBS:
        if verb in text:  # it mentions it at all
            assert (REPO / "sandbox_kit" / "cli.py").read_text(encoding="utf-8").count(
                f'add_parser("{verb}"'
            ) >= 1, f"lifecycle.md documents '{verb}' but the CLI has no such subcommand"


def test_cli_has_no_undocumented_sandbox_verbs():
    cli = _read(REPO / "sandbox_kit" / "cli.py")
    verbs = set(re.findall(r'add_parser\("([a-z-]+)"', cli))
    documented = set()
    for name in ("lifecycle.md", "quickstart.md", "bug-reports.md",
                 "reset-cleanup.md", "troubleshooting.md", "platforms.md"):
        documented |= set(re.findall(r"sandbox\.sh ([a-z-]+)", _read(DOCS / name)))
    undocumented = verbs - documented - {"ps"}  # ps is internal/legacy surface
    assert not undocumented, f"CLI verbs with no sandbox.sh doc mention: {sorted(undocumented)}"


# ── 4. markdown links resolve ────────────────────────────────────────────────

_MD_LINK = re.compile(r"\[[^\]]+\]\(([^)#\s]+)(?:#[^)]*)?\)")


def test_sandbox_doc_links_resolve():
    broken: list[str] = []
    for md in DOCS.glob("*.md"):
        base = md.parent
        for target in _MD_LINK.findall(_read(md)):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            resolved = (base / target).resolve()
            if not resolved.exists():
                broken.append(f"{md.name} -> {target}")
    assert not broken, f"broken doc links: {broken}"


def test_root_integration_links_resolve():
    broken: list[str] = []
    for root_doc, base in (("README.md", REPO), ("CONTRIBUTING.md", REPO),
                           ("SECURITY.md", REPO)):
        text = _read(REPO / root_doc)
        for target in _MD_LINK.findall(text):
            if target.startswith(("http", "mailto:")) or not target.startswith("docs/sandbox"):
                continue
            if not (REPO / target).exists():
                broken.append(f"{root_doc} -> {target}")
    assert not broken, f"root docs link to missing sandbox docs: {broken}"


# ── 5. root integrations exist and are truthful ──────────────────────────────

def test_readme_sandbox_box_is_truthful():
    readme = _read(REPO / "README.md")
    assert "./sandbox.sh up --profile app-only" in readme
    assert "./sandbox.sh verify" in readme
    # the non-claims pointer is mandatory wherever startup is advertised
    assert "security-model.md" in readme
    assert "not" in readme.lower()  # sanity: the box must contain hedging language


def test_contributing_has_sandbox_section():
    text = _read(REPO / "CONTRIBUTING.md")
    assert "Working on the local sandbox" in text
    assert "Never test hostile content against T0/T1" in text


def test_security_md_has_sandbox_scope():
    text = _read(REPO / "SECURITY.md")
    assert "Local sandbox scope" in text
    assert "in scope" in text


# ── 6. non-claims placement (G13) ────────────────────────────────────────────

def test_quickstart_carries_the_non_claims_sentence():
    text = _read(DOCS / "quickstart.md")
    assert "security-model.md" in text
    assert "not" in text.lower()


def test_vs_production_doc_keeps_the_canonical_framing():
    text = _read(DOCS / "vs-production.md")
    assert "synthetic telemetry" in text
    assert "Not a honeypot" in text


# ── 7. CI integrity (Phase 11 lesson) ─────────────────────────────────────

# Phase 11 red-teaming caught a real corruption: an inserted CI job silently
# converted an existing *step* into a duplicate job key, and YAML last-wins
# discarded the original step without any error — the onboarding dry-run
# would have vanished from CI with every validation passing. This block
# makes that failure mode structurally impossible to reintroduce.

_CI_PATH = REPO / ".github" / "workflows" / "ci.yml"


def _load_ci_strict():
    """Parse ci.yml raising on ANY duplicate mapping key (PyYAML default
    silently keeps the last). Returns a dict keyed by plain strings."""
    import yaml

    class StrictLoader(yaml.SafeLoader):
        pass

    def no_dupes(loader, node, deep=False):
        mapping = {}
        for k_node, v_node in node.value:
            key = loader.construct_object(k_node, deep=deep)
            marker = (k_node.tag, str(key))
            if marker in mapping:
                raise AssertionError(f"duplicate YAML key in ci.yml: {key!r}")
            mapping[marker] = loader.construct_object(v_node, deep=deep)
        return mapping

    StrictLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, no_dupes)

    def plain(node):
        if isinstance(node, dict):
            return {str(k[1]): plain(v) for k, v in node.items()}
        if isinstance(node, list):
            return [plain(v) for v in node]
        if isinstance(node, tuple):
            return node[1]
        return node

    text = _CI_PATH.read_text()
    # known pre-existing quirk: an unquoted sqlite URL (GitHub-tolerated,
    # documented since Phase 8) — neutralized ONLY for parsing here.
    text = text.replace('DATABASE_URL: sqlite:///:memory:',
                        'DATABASE_URL: "sqlite:///:memory:"')
    return plain(yaml.load(text, Loader=StrictLoader))


def test_ci_has_no_duplicate_yaml_keys():
    _load_ci_strict()  # raises on any duplicate key anywhere in the file


def test_ci_onboarding_dry_run_survived_as_a_step():
    doc = _load_ci_strict()
    steps = []
    for job in doc["jobs"].values():
        for s in (job or {}).get("steps") or []:
            if isinstance(s, dict):
                steps.append((str(s.get("name", "")), str(s.get("run", ""))))
    # the README-replay step exists, with the honest-refusal commands inside
    assert any("Onboarding dry-run" in n for n, _ in steps)
    joined = "\n".join(r for _, r in steps)
    assert "research-sandbox --yes --allow-host 169.254.169.254" in joined
    assert "app-only --allow-host example.com" in joined
    assert "detonate --url" in joined


def test_ci_sandbox_matrix_rows_are_unique():
    doc = _load_ci_strict()
    names = [n for n in doc["jobs"].keys()]
    assert len(names) == len(set(names))
    for expect in ("backend", "sandbox-platform-linux", "sandbox-supply-chain",
                   "sandbox-platform-macos", "sandbox-platform-arm64"):
        assert expect in names, names
