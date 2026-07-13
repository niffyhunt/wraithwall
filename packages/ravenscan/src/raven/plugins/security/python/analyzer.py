"""Python security analyzer — wraps the existing Phase 3 scanner.

This adapter makes the Python static analysis engine available through
the SecurityAnalyzer plugin interface.
"""

from __future__ import annotations

from raven.plugins.security.base import AbstractSecurityAnalyzer
from raven.core.context import RepositoryContext
from raven.core.models import SecurityReport
from raven.security.scanner import analyze as py_analyze


class PythonSecurityAnalyzer(AbstractSecurityAnalyzer):
    """Wraps the core Python security scanner as a plugin-compatible analyzer."""

    language = "python"
    display_name = "Python Security Analyzer"

    @property
    def supported_file_extensions(self) -> list[str]:
        return [".py", ".pyi", ".pyw"]

    def analyze(self, ctx: RepositoryContext) -> SecurityReport:
        return py_analyze(ctx)

    @property
    def is_available(self) -> bool:
        return True
