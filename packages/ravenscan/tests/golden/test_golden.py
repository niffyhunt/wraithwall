"""R-08 golden evaluation harness.

Fixed synthetic fixtures + normalized baselines: any unintended engine-output
change is caught, and double-run identity is enforced (test plan §1 gates 4/5).
Regenerate baselines only for intended changes: RAVEN_GOLDEN_UPDATE=1 pytest tests/golden -q
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

GOLDEN_DIR = Path(__file__).resolve().parent
FIXTURES = GOLDEN_DIR.parent / "fixtures"
BASELINE = GOLDEN_DIR / "baseline"
ARTIFACTS = (
    "RepositoryProfile.md",
    "ArchitectureGraph.md",
    "RiskScore.md",
    "DailyReport.md",
    "SecurityReport.md",
    "RunSummary.md",        # R-01
    "decision_trace.json",   # R-02
)
_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?")
_REV = re.compile(r"\*\*Commit:\*\*.*")  # repo HEAD/branch of the test runner, not the fixture


def _run_scan(fixture: Path, out_dir: Path, hash_seed: str) -> dict[str, str]:
    """Scan fixture into out_dir; return normalized artifact text by filename."""
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = hash_seed
    src = GOLDEN_DIR.parents[1] / "src"  # ravenscan/src
    if src.is_dir():
        env["PYTHONPATH"] = str(src) + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "raven.cli.main",
            "scan",
            str(fixture),
            "-o",
            str(out_dir),
            "--quiet",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, f"scan failed rc={proc.returncode}\n{proc.stdout}\n{proc.stderr}"
    arts: dict[str, str] = {}
    for name in ARTIFACTS:
        path = out_dir / name
        assert path.is_file(), f"missing artifact {name}"
        text = path.read_text(encoding="utf-8")  # strict: invalid utf-8 fails loudly
        text = _TS.sub("<TS>", text)
        text = _REV.sub("**Commit:** <REV>", text)
        text = text.replace(str(fixture.resolve()), "<PROJECT>")
        text = text.replace(str(out_dir), "<OUT>")
        text = text.replace(str(out_dir.parent), "<TMP>")  # scope = store parent.parent
        arts[name] = text
    return arts


def _control_bytes(text: str) -> list[str]:
    return [f"0x{ord(ch):02x}" for ch in text if ord(ch) < 32 and ch not in "\n\t"]


def test_double_run_identity(tmp_path):
    """Gate: two runs on the fixture are identical modulo timestamps/paths."""
    first = _run_scan(FIXTURES / "golden_repo", tmp_path / "a", "0")
    second = _run_scan(FIXTURES / "golden_repo", tmp_path / "b", "12345")
    assert first == second


def test_matches_committed_baseline(tmp_path):
    """Golden regression gate: current output == committed normalized baseline."""
    got = _run_scan(FIXTURES / "golden_repo", tmp_path / "base", "0")
    if os.getenv("RAVEN_GOLDEN_UPDATE") == "1":
        BASELINE.mkdir(parents=True, exist_ok=True)
        for name, text in got.items():
            (BASELINE / name).write_text(text, encoding="utf-8")
        pytest.skip("golden baseline regenerated")
    assert BASELINE.is_dir(), "baseline missing - run RAVEN_GOLDEN_UPDATE=1 once"
    for name, text in got.items():
        expected = (BASELINE / name).read_text(encoding="utf-8")
        assert text == expected, (
            f"golden mismatch in {name} - if intended, regen with RAVEN_GOLDEN_UPDATE=1"
        )


def test_malicious_corpus_stable_and_clean(tmp_path):
    """Malicious-input corpus: scan survives, stays deterministic, no C0 leaks."""
    fixture = FIXTURES / "golden_repo_malicious"
    first = _run_scan(fixture, tmp_path / "m1", "0")
    second = _run_scan(fixture, tmp_path / "m2", "777")
    assert first == second, "adversarial fixture is nondeterministic"
    for name, text in first.items():
        leaked = _control_bytes(text)
        assert not leaked, f"control bytes leaked into {name}: {leaked[:5]}"
