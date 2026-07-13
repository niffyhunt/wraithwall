"""SecurityAnalyzerRegistry — dispatches security analysis to language-specific analyzers."""

from __future__ import annotations

from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from raven.plugins.security.base import SecurityAnalyzer
    from raven.core.context import RepositoryContext
    from raven.core.models import SecurityReport


class SecurityAnalyzerRegistry:
    """Registry of language-specific security analyzers.

    Uses file extension mapping to dispatch analysis to the correct
    analyzer for each file type.
    """

    def __init__(self) -> None:
        self._analyzers: dict[str, SecurityAnalyzer] = {}
        self._ext_map: dict[str, SecurityAnalyzer] = {}

    def register(self, analyzer: SecurityAnalyzer) -> None:
        """Register a security analyzer.

        Maps all file extensions the analyzer handles to this instance.
        """
        self._analyzers[analyzer.language] = analyzer
        for ext in analyzer.supported_file_extensions:
            self._ext_map[ext] = analyzer

    def get(self, language: str) -> Optional[SecurityAnalyzer]:
        """Get an analyzer by language name."""
        return self._analyzers.get(language)

    def get_by_extension(self, extension: str) -> Optional[SecurityAnalyzer]:
        """Get an analyzer by file extension."""
        return self._ext_map.get(extension.lower())

    def list_languages(self) -> list[str]:
        """Return list of registered language names."""
        return sorted(self._analyzers.keys())

    def list_available(self) -> list[str]:
        """Return list of languages with available analyzers."""
        return sorted(k for k, v in self._analyzers.items() if v.is_available)

    def analyze_all(self, ctx: RepositoryContext) -> SecurityReport:
        """Run all registered analyzers against the repository context.

        Each analyzer receives the full context and filters to its own
        file types internally.
        """
        from raven.core.models import SecurityReport, SecurityFinding

        all_findings: list[SecurityFinding] = []
        for analyzer in self._analyzers.values():
            if not analyzer.is_available:
                continue
            try:
                report = analyzer.analyze(ctx)
                all_findings.extend(report.findings)
            except Exception:
                pass

        return SecurityReport(findings=all_findings)

    def analyze_all_except(self, ctx: RepositoryContext, skip_language: str) -> SecurityReport:
        """Run all registered analyzers except the named language.

        Used when the primary scanner already handles a language with richer
        analysis (e.g., Python scanner handles Python, registry handles the rest).
        """
        from raven.core.models import SecurityReport, SecurityFinding

        all_findings: list[SecurityFinding] = []
        for lang, analyzer in self._analyzers.items():
            if lang == skip_language:
                continue
            if not analyzer.is_available:
                continue
            try:
                report = analyzer.analyze(ctx)
                all_findings.extend(report.findings)
            except Exception:
                pass

        return SecurityReport(findings=all_findings)


registry = SecurityAnalyzerRegistry()
"""Global security analyzer registry singleton."""
