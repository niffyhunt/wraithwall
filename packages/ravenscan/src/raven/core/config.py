"""Raven configuration — typed, environment-aware.

Configuration is the single source of truth for all analysis parameters
and artifact output paths.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class RavenConfig:
    """Configuration for a Raven analysis run.

    Sensible defaults for every field.  CLI flags override these.
    """

    path: Path = field(default_factory=Path.cwd)
    """Root path of the repository to analyze."""

    output_dir: Path = field(default_factory=lambda: Path.cwd() / ".raven")
    """Directory where scan artifacts are written."""

    format: str = "markdown"
    """Output format: 'json' or 'markdown'."""

    fail_under: Optional[float] = None
    """If set, `raven score` exits non-zero when overall score < this value.
    Must be between 0 and 100."""

    quiet: bool = False
    verbose: bool = False
    no_color: bool = False

    enable_phases: list[str] = field(
        default_factory=lambda: ["1", "2", "3", "7", "9"]
    )
    """Phases to run during scan. Default is MVP set."""

    max_file_size_bytes: int = 2 * 1024 * 1024
    """Skip files larger than this. Default 2 MiB."""

    exclude_patterns: list[str] = field(
        default_factory=lambda: [
            ".git",
            ".venv",
            "venv",
            "node_modules",
            "__pycache__",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            "dist",
            "build",
            ".eggs",
            "*.egg-info",
            ".raven",
        ]
    )

    plugin_paths: list[str] = field(default_factory=list)
    """Reserved for future third-party plugin directories."""

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self.output_dir = Path(self.output_dir)
        if self.format not in ("json", "markdown"):
            raise ValueError(f"format must be 'json' or 'markdown', got '{self.format}'")
        if self.fail_under is not None and not (0 <= self.fail_under <= 100):
            raise ValueError(f"fail_under must be between 0 and 100, got {self.fail_under}")

    @classmethod
    def from_env(cls, path: Optional[Path] = None) -> "RavenConfig":
        """Build config from environment and optional overrides."""
        return cls(
            path=path or Path(os.getenv("RAVEN_PATH", ".")),
            format=os.getenv("RAVEN_FORMAT", "markdown"),
            quiet=os.getenv("RAVEN_QUIET", "0") == "1",
            verbose=os.getenv("RAVEN_VERBOSE", "0") == "1",
        )

    def artifact_path(self, name: str) -> Path:
        """Return full path for an artifact inside output_dir."""
        return self.output_dir / name
