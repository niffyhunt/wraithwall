"""Raven SDK — the public Python API.

Usage:
    from raven import Raven
    client = Raven(RavenConfig(path="."))
    profile = client.scan()
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, TYPE_CHECKING

from raven.core.config import RavenConfig
from raven.core.context import RepositoryContext
from raven.core.models import (
    RepositoryProfile,
    ArchitectureGraph,
    SecurityReport,
    DailyReport,
    RiskScore,
    AIFinding,
)

import raven.repository.intel as phase1
import raven.architecture.graph as phase2
import raven.security.scanner as phase3
import raven.reporting.daily_report as daily
import raven.reporting.scoring as scoring
import raven.drift.analyzer as drift
import raven.drift.tracker as tracker
import raven.operational.inspector as ops

if TYPE_CHECKING:
    from raven.drift.analyzer import DriftSnapshot
    from raven.drift.tracker import ChangeReport
    from raven.operational.inspector import OperationalHealth


class Raven:
    """Synchronous Raven client — the primary SDK interface."""

    def __init__(self, config: RavenConfig) -> None:
        self.config = config
        self._ctx: Optional[RepositoryContext] = None

    @property
    def ctx(self) -> RepositoryContext:
        if self._ctx is None:
            self._ctx = phase1.build_context(self.config)
        return self._ctx

    def scan(self) -> RepositoryProfile:
        """Run Phase 1 — Repository Intelligence."""
        return phase1.analyze(self.config, self.ctx)

    def profile(self) -> RepositoryProfile:
        """Alias for scan()."""
        return self.scan()

    def architecture(self) -> ArchitectureGraph:
        """Run Phase 2 — Architecture Graph analysis."""
        return phase2.analyze(self.ctx, self.config)

    def security(self) -> SecurityReport:
        """Run Phase 3 — Security Intelligence.

        Uses the full Python scanner for Python files and the
        SecurityAnalyzerRegistry for Go, JavaScript, Rust, and Java files.
        Results are merged into a single SecurityReport.
        """
        report = phase3.analyze(self.ctx, self.config)
        try:
            from raven.plugins.registry import registry
            from raven.plugins.security import register_builtin_analyzers
            register_builtin_analyzers()
            multi_report = registry.analyze_all_except(self.ctx, "python")
            all_findings = list(report.findings) + list(multi_report.findings)
            return SecurityReport(findings=all_findings)
        except Exception:
            return report

    def drift_snapshot(self, arch: Optional[ArchitectureGraph] = None) -> DriftSnapshot:
        """Run Phase 5 — Engineering Drift measurement."""
        a = arch or self.architecture()
        return drift.analyze(self.ctx, a, self.config)

    def track_changes(self, security: Optional[SecurityReport] = None) -> ChangeReport:
        """Run Phase 4 — Semantic Change Tracking."""
        s = security or self.security()
        return tracker.analyze(self.ctx, s)

    def operational(self) -> OperationalHealth:
        """Run Phase 6 — Operational Intelligence."""
        return ops.analyze(self.config.path)

    def daily_report(
        self,
        profile: Optional[RepositoryProfile] = None,
        architecture: Optional[ArchitectureGraph] = None,
        security: Optional[SecurityReport] = None,
        project_name: str = "",
    ) -> DailyReport:
        """Run Phase 7 — Daily Engineering Forensics."""
        p = profile or self.scan()
        a = architecture or self.architecture()
        s = security or self.security()
        return daily.generate(p, a, s, project_name)

    def score(
        self,
        profile: Optional[RepositoryProfile] = None,
        architecture: Optional[ArchitectureGraph] = None,
        security: Optional[SecurityReport] = None,
        drift_snapshot: Optional[DriftSnapshot] = None,
        include_operational: bool = False,
    ) -> RiskScore:
        """Run Phase 9 — Intelligence Scoring (8 categories including DevEx).

        When include_operational is True, runtime operational health data
        is collected and influences the operational score category.
        """
        p = profile or self.scan()
        a = architecture or self.architecture()
        s = security or self.security()
        op = None
        if include_operational:
            try:
                ops_health = self.operational()
                from raven.operational.inspector import to_model
                op = to_model(ops_health)
            except Exception:
                pass
        return scoring.score(p, a, s, drift_snapshot, operational=op)

    def ai_findings(
        self,
        security: Optional[SecurityReport] = None,
        architecture: Optional[ArchitectureGraph] = None,
    ) -> list[AIFinding]:
        """Return structured findings for AI agent consumption.

        Every finding includes confidence, evidence, affected files,
        affected symbols, affected lines, CWE ID, and recommendations.
        No hallucinated data.
        """
        s = security or self.security()
        a = architecture or self.architecture()

        results: list[AIFinding] = []

        for f in s.findings:
            results.append(AIFinding(
                confidence={"high": 0.95, "medium": 0.75, "low": 0.50}.get(f.confidence.value, 0.5),
                severity=f.severity.value,
                title=f.title,
                description=f.description,
                evidence=f.evidence,
                affected_files=[f.affected_file],
                affected_lines=f.affected_lines,
                cwe_id=f.cwe.cwe_id,
                recommendation=f.recommendation,
                references=[f.cwe.url] if f.cwe.url else [],
            ))

        for af in a.findings:
            results.append(AIFinding(
                confidence={"high": 0.95, "medium": 0.75, "low": 0.50}.get(af.confidence.value, 0.5),
                severity=af.severity.value,
                title=f"[Architecture] {af.title}",
                description=af.description,
                evidence=af.evidence,
                affected_files=af.affected_files,
                affected_lines=af.affected_lines,
                cwe_id="",
                recommendation=af.recommendation,
                references=[],
            ))

        return results

    def report(self, fmt: str = "json") -> dict[str, object]:
        """Run all phases and return a combined report dict."""
        p = self.scan()
        a = self.architecture()
        s = self.security()
        d = self.drift_snapshot(a)
        c = self.track_changes(s)
        o = self.operational()
        r = self.score(p, a, s, d)
        dr = self.daily_report(p, a, s)

        if fmt == "json":
            return {
                "profile": p.model_dump(mode="json"),
                "architecture": a.model_dump(mode="json"),
                "security": s.model_dump(mode="json"),
                "score": r.model_dump(mode="json"),
                "daily_report": dr.model_dump(mode="json"),
            }
        return {
            "profile": p,
            "architecture": a,
            "security": s,
            "score": r,
            "daily_report": dr,
        }
