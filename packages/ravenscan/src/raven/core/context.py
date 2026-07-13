"""RepositoryContext — the read-only snapshot passed to every plugin.

Plugins receive this and must not mutate it.  The context is built once
per scan and shared across all phases.
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ParsedFile:
    """A single file with its AST (Python only for v0.1)."""

    path: Path
    relative_path: str
    language: str
    content: str
    ast_tree: Optional[ast.AST] = None
    size_bytes: int = 0
    lines: list[str] = field(default_factory=list)


@dataclass
class DependencyInfo:
    """A resolved dependency entry."""

    name: str
    version: str
    source: str  # "requirements.txt", "pyproject.toml", etc.
    is_dev: bool = False


@dataclass
class RepositoryContext:
    """Read-only snapshot of the repository under analysis."""

    root: Path
    files: list[ParsedFile] = field(default_factory=list)
    dependencies: list[DependencyInfo] = field(default_factory=list)

    language_primary: str = "unknown"
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    package_manager: str = "unknown"

    has_docker: bool = False
    has_ci: bool = False
    ci_provider: str = "unknown"
    has_systemd: bool = False

    bg_workers: list[str] = field(default_factory=list)
    api_routes: list[str] = field(default_factory=list)
    database: str = "unknown"

    total_files: int = 0
    total_python_files: int = 0
    total_lines: int = 0

    def relative(self, filepath: Path) -> str:
        """Return path relative to repo root."""
        try:
            return str(filepath.relative_to(self.root))
        except ValueError:
            return str(filepath)
