"""Contextual analysis for reducing false positives in security scanning.

Adds file-level and project-level context to raw pattern matches, enabling
the scanner to suppress findings that are irrelevant in context (test files,
example code, documentation, configuration templates).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

FP_FILE_PATTERNS: set[str] = {
    "conftest.py",
    "setup.py",
    "setup.cfg",
    "__init__.py",
    "example.py",
    "sample.py",
    "mock.py",
    "stub.py",
}

FP_DIR_PATTERNS: set[str] = {
    "tests",
    "test",
    "fixtures",
    "examples",
    "docs",
    "documentation",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    "node_modules",
}

FP_CONTEXT_MARKERS: list[str] = [
    "# noqa",
    "# nosec",
    "# pragma: no cover",
    "# no-raven",
    "# raven: skip",
]


def is_test_or_fixture(filepath: str) -> bool:
    """Check if a file is in a test, fixture, or example directory."""
    parts = Path(filepath).parts
    return any(part in FP_DIR_PATTERNS for part in parts)


def is_excluded_file(filename: str) -> bool:
    """Check if a file matches known false-positive filenames."""
    return Path(filename).name in FP_FILE_PATTERNS


def has_suppression_marker(lines: list[str], affected_line: int) -> bool:
    """Check if the affected line or surrounding context has a suppression marker.

    Looks at the line itself and one line above for safety annotations like
    '# nosec', '# noqa', '# no-raven', '# raven: skip'.
    """
    for offset in (0, -1):
        idx = affected_line - 1 + offset
        if 0 <= idx < len(lines):
            line = lines[idx].strip()
            for marker in FP_CONTEXT_MARKERS:
                if marker in line:
                    return True
    return False


def should_suppress(
    filepath: str,
    affected_line: int,
    lines: Optional[list[str]] = None,
) -> bool:
    """Determine whether a finding should be suppressed based on context.

    Returns True if the finding is likely a false positive due to:
    - Being in a test/fixture/example directory
    - Being in an excluded file (conftest, setup, etc.)
    - Having an explicit suppression marker on or above the affected line

    Args:
        filepath: Relative path of the file containing the finding.
        affected_line: 1-indexed line number of the finding.
        lines: Full file content as list of strings. Required for suppression
               marker checks. Optional to allow callers who don't have lines.
    """
    if is_test_or_fixture(filepath):
        return True
    if is_excluded_file(filepath):
        return True
    if lines and has_suppression_marker(lines, affected_line):
        return True
    return False
