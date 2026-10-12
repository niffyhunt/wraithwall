"""Read-only Git metadata helpers used for scan provenance."""

from __future__ import annotations

import subprocess
from pathlib import Path


def _git(root: Path, *args: str) -> str | None:
    """Run a fixed Git subcommand without invoking a shell."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = result.stdout.strip()
    return value or None


def revision_metadata(root: Path) -> tuple[str | None, str | None]:
    """Return (commit SHA, branch) or (None, None) outside a Git worktree."""
    return _git(root, "rev-parse", "HEAD"), _git(root, "branch", "--show-current")
