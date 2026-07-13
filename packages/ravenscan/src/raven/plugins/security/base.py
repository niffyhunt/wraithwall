"""SecurityAnalyzer base class for multi-language security analysis.

Language-specific analyzers implement this protocol and register
with SecurityAnalyzerRegistry. The registry dispatches analysis
to the correct analyzer based on detected file language.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol, runtime_checkable

from raven.core.context import RepositoryContext
from raven.core.models import SecurityFinding, SecurityReport


@runtime_checkable
class SecurityAnalyzer(Protocol):
    """Protocol for language-specific security analyzers.

    Attributes:
        language: The language this analyzer handles (e.g., 'python', 'javascript').
        display_name: Human-readable name for CLI/report display.
    """

    @property
    def language(self) -> str: ...

    @property
    def display_name(self) -> str: ...

    def analyze(self, ctx: RepositoryContext) -> SecurityReport:
        """Analyze all files of this language in the repository context.

        Returns a SecurityReport with findings. Returns an empty report
        if no findings or the analyzer is not applicable.
        """
        ...

    def analyze_file(self, filepath: str, content: str) -> list[SecurityFinding]:
        """Analyze a single file of this language.

        Returns a list of SecurityFinding objects. Used for incremental
        and single-file analysis modes.
        """
        ...

    @property
    def supported_file_extensions(self) -> list[str]:
        """File extensions this analyzer handles."""
        ...

    @property
    def is_available(self) -> bool:
        """Whether this analyzer can run (dependencies installed, configured)."""
        ...


class AbstractSecurityAnalyzer(ABC):
    """Base class for concrete security analyzer implementations.

    Provides default implementations for analyze_file (delegates to analyze
    on a single-file context) and is_available (True by default).
    """

    @property
    @abstractmethod
    def language(self) -> str:
        ...

    @property
    @abstractmethod
    def display_name(self) -> str:
        ...

    @property
    @abstractmethod
    def supported_file_extensions(self) -> list[str]:
        ...

    @abstractmethod
    def analyze(self, ctx: RepositoryContext) -> SecurityReport:
        ...

    def analyze_file(self, filepath: str, content: str) -> list[SecurityFinding]:
        from pathlib import Path
        from raven.core.context import ParsedFile, RepositoryContext

        pf = ParsedFile(
            path=Path(filepath),
            relative_path=filepath,
            language=self.language,
            content=content,
            lines=content.splitlines(),
            size_bytes=len(content.encode()),
        )

        mini_ctx = RepositoryContext(
            root=Path(filepath).parent,
            files=[pf],
            language_primary=self.language,
            languages=[self.language],
        )
        mini_ctx.total_files = 1
        mini_ctx.total_lines = len(pf.lines)

        report = self.analyze(mini_ctx)
        return report.findings

    @property
    def is_available(self) -> bool:
        return True
