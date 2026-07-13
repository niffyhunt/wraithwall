"""Canonical Pydantic output schemas for every Raven report.

Every model carries a `schema_version` field.  JSON output is generated
via `.model_dump_json()` and Markdown is rendered from that same model —
never hand-assembled independently.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── shared enums & primitives ──────────────────────────────────────────


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ScoreCategory(str, Enum):
    ARCHITECTURE = "architecture"
    SECURITY = "security"
    MAINTAINABILITY = "maintainability"
    OPERATIONAL = "operational"
    DOCUMENTATION = "documentation"
    TESTING = "testing"
    TECHNICAL_DEBT = "technical_debt"
    DEVELOPER_EXPERIENCE = "developer_experience"


# ── Phase 1: Repository Intelligence ──────────────────────────────────


class FrameworkInfo(BaseModel):
    name: str
    version: str = "unknown"
    source_file: str = ""


class DependencyEntry(BaseModel):
    name: str
    version: str
    source: str
    is_dev: bool = False


class RepoStructure(BaseModel):
    root: str
    total_files: int
    total_lines: int
    total_python_files: int
    directory_count: int


class RepositoryProfile(BaseModel):
    schema_version: str = "1"
    scanned_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    structure: Optional[RepoStructure] = None
    language_primary: str = "unknown"
    languages: list[str] = Field(default_factory=list)
    frameworks: list[FrameworkInfo] = Field(default_factory=list)
    package_manager: str = "unknown"
    dependencies: list[DependencyEntry] = Field(default_factory=list)
    has_docker: bool = False
    has_ci: bool = False
    ci_provider: str = "unknown"
    has_systemd: bool = False
    bg_workers: list[str] = Field(default_factory=list)
    api_routes: list[str] = Field(default_factory=list)
    database: str = "unknown"

    def summary(self) -> str:
        return (
            f"{self.language_primary} project, "
            f"{self.structure and self.structure.total_files or 0} files, "
            f"{len(self.dependencies)} dependencies"
        )


# ── Phase 2: Architecture Graph ───────────────────────────────────────


class ModuleNode(BaseModel):
    name: str
    path: str
    imports: list[str] = Field(default_factory=list)
    imported_by: list[str] = Field(default_factory=list)
    lines: int = 0
    classes: int = 0
    functions: int = 0


class ArchitectureFinding(BaseModel):
    """A structural issue: circular import, god module, dead code, etc."""

    severity: Severity
    category: str
    title: str
    description: str
    evidence: str
    affected_files: list[str] = Field(default_factory=list)
    affected_lines: list[int] = Field(default_factory=list)
    recommendation: str = ""
    confidence: Confidence = Confidence.MEDIUM


class ArchitectureGraph(BaseModel):
    schema_version: str = "1"
    scanned_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    modules: list[ModuleNode] = Field(default_factory=list)
    findings: list[ArchitectureFinding] = Field(default_factory=list)

    @property
    def circular_imports(self) -> list[ArchitectureFinding]:
        return [f for f in self.findings if f.category == "circular_import"]

    @property
    def god_modules(self) -> list[ArchitectureFinding]:
        return [f for f in self.findings if f.category == "god_module"]

    @property
    def dead_code(self) -> list[ArchitectureFinding]:
        return [f for f in self.findings if f.category == "dead_code"]


# ── Phase 3: Security Intelligence ────────────────────────────────────


class CweReference(BaseModel):
    cwe_id: str
    name: str
    url: str = ""


class SecurityFinding(BaseModel):
    """A security issue mapped to CWE, with evidence and fix guidance."""

    severity: Severity
    cwe: CweReference
    title: str
    description: str
    evidence: str
    affected_file: str
    affected_lines: list[int] = Field(default_factory=list)
    exploitation_scenario: str = ""
    recommendation: str = ""
    confidence: Confidence = Confidence.MEDIUM
    found_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class SecurityReport(BaseModel):
    schema_version: str = "1"
    scanned_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: list[SecurityFinding] = Field(default_factory=list)
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    def model_post_init(self, __context: Any) -> None:
        self.total_findings = len(self.findings)
        self.critical_count = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        self.high_count = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        self.medium_count = sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        self.low_count = sum(1 for f in self.findings if f.severity == Severity.LOW)
        self.info_count = sum(1 for f in self.findings if f.severity == Severity.INFO)


# ── Phase 7: Daily Report ─────────────────────────────────────────────


class ChangeSummary(BaseModel):
    category: str
    description: str
    impact: str
    affected_files: list[str] = Field(default_factory=list)


class ActionItem(BaseModel):
    """A recommended action item with priority and timeframe.

    Attributes:
        priority: Action severity (CRITICAL/HIGH = immediate, MEDIUM = short-term, LOW/INFO = long-term).
        description: What action to take.
        timeframe: Expected resolution window ('immediate', 'short-term', 'long-term').
    """

    priority: Severity
    description: str
    timeframe: str


class DailyReport(BaseModel):
    schema_version: str = "1"
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    project: str = ""
    summary: str = ""
    changes: list[ChangeSummary] = Field(default_factory=list)
    security_impact: str = ""
    architecture_impact: str = ""
    operational_impact: str = ""
    risk_trend: str = "stable"
    immediate_actions: list[ActionItem] = Field(default_factory=list)
    long_term_actions: list[ActionItem] = Field(default_factory=list)
    interesting_observations: list[str] = Field(default_factory=list)


# ── Phase 9: Scoring ──────────────────────────────────────────────────


class CategoryScore(BaseModel):
    category: ScoreCategory
    score: float
    max_score: float = 100.0
    why: str = ""
    evidence: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    trend_vs_previous: Optional[float] = None


class RiskScore(BaseModel):
    schema_version: str = "1"
    scored_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    overall: float
    categories: list[CategoryScore] = Field(default_factory=list)

    @property
    def grade(self) -> str:
        if self.overall >= 90:
            return "A"
        if self.overall >= 80:
            return "B"
        if self.overall >= 70:
            return "C"
        if self.overall >= 60:
            return "D"
        return "F"


class DriftMetrics(BaseModel):
    """Serializable engineering drift snapshot."""

    schema_version: str = "1"
    scanned_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_files: int = 0
    total_lines: int = 0
    avg_lines_per_file: float = 0.0
    max_lines_per_file: int = 0
    avg_functions_per_file: float = 0.0
    comment_to_code_ratio: float = 0.0
    total_todos: int = 0
    total_fixmes: int = 0
    avg_instability: float = 0.0
    duplicate_blocks: int = 0
    god_module_count: int = 0
    circular_import_count: int = 0
    dead_code_count: int = 0


class TrendPoint(BaseModel):
    """A single data point for trend analysis."""

    scanned_at: str
    value: float
    label: str = ""


class DriftTrend(BaseModel):
    """Historical drift trend across multiple scans."""

    schema_version: str = "1"
    metric: str
    points: list[TrendPoint] = Field(default_factory=list)
    trend_direction: str = "stable"
    trend_pct: float = 0.0


class OperationalHealthModel(BaseModel):
    """Serializable operational health report."""

    schema_version: str = "1"
    scanned_at: str
    overall_status: str = "unknown"
    container_count: int = 0
    containers_running: int = 0
    containers_exited: int = 0
    service_count: int = 0
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    disk_percent: float = 0.0
    anomalies: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class HistoricalTimeline(BaseModel):
    """Repository history timeline entry."""

    schema_version: str = "1"
    scanned_at: str
    score: float
    grade: str
    findings_critical: int = 0
    findings_high: int = 0
    total_files: int = 0
    total_lines: int = 0
    deps_count: int = 0
    risk_trend: str = "stable"
    drift_snapshot: Optional[DriftMetrics] = None


class AIFinding(BaseModel):
    """Structured finding for AI agent consumption."""

    confidence: float
    severity: str
    title: str
    description: str
    evidence: str
    affected_files: list[str] = Field(default_factory=list)
    affected_symbols: list[str] = Field(default_factory=list)
    affected_lines: list[int] = Field(default_factory=list)
    cwe_id: str = ""
    recommendation: str = ""
    references: list[str] = Field(default_factory=list)
