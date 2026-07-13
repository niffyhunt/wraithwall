"""Raven core error types.

Exit codes are part of the public contract:
    0 — clean, no findings meeting threshold
    1 — findings >= threshold
    2 — execution error
    3 — config error
"""

from __future__ import annotations


class RavenError(Exception):
    """Base exception for all Raven errors.

    Attributes:
        exit_code: Integer exit code for CLI (2 = execution error).
        detail: Optional structured detail dict for programmatic consumers.
    """

    exit_code: int = 2

    def __init__(self, message: str = "", *, detail: dict[str, object] | None = None):
        super().__init__(message)
        self.detail = detail or {}


class ConfigError(RavenError):
    """Configuration is missing or invalid. Exit code 3."""

    exit_code = 3


class AnalysisError(RavenError):
    """Analysis could not complete. Exit code 2."""

    exit_code = 2


class PluginError(RavenError):
    """A plugin failed to load or execute. Exit code 2."""

    exit_code = 2


class ThresholdError(RavenError):
    """Score is below the configured fail-under threshold. Exit code 1."""

    exit_code = 1
