"""Semantic cross-revision delta dataclasses and shared utilities.

Every delta carries a confidence score (0.0-1.0) indicating how reliable
the comparison is given the available data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class DeltaCategory(str, Enum):
    ARCHITECTURE = "architecture"
    SECURITY = "security"
    SYMBOLS = "symbols"
    IMPORTS = "imports"
    ROUTES = "routes"
    DEPENDENCIES = "dependencies"
    EVOLUTION = "evolution"
    CONFIG = "config"


class ChangeType(str, Enum):
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    RENAMED = "renamed"
    UNCHANGED = "unchanged"


@dataclass
class DeltaEntry:
    """A single change detected between two revisions."""

    category: DeltaCategory
    change_type: ChangeType
    entity: str
    description: str
    confidence: float = 1.0
    before: Optional[Any] = None
    after: Optional[Any] = None
    affected_files: list[str] = field(default_factory=list)
    severity: str = "info"


@dataclass
class RevisionDelta:
    """Aggregated delta between two repository revisions."""

    base_revision: str
    head_revision: str
    scanned_at: str
    entries: list[DeltaEntry] = field(default_factory=list)
    summary: str = ""

    @property
    def total_changes(self) -> int:
        return len(self.entries)

    @property
    def added(self) -> int:
        return sum(1 for e in self.entries if e.change_type == ChangeType.ADDED)

    @property
    def removed(self) -> int:
        return sum(1 for e in self.entries if e.change_type == ChangeType.REMOVED)

    @property
    def modified(self) -> int:
        return sum(1 for e in self.entries if e.change_type == ChangeType.MODIFIED)

    @property
    def high_confidence_changes(self) -> int:
        return sum(1 for e in self.entries if e.confidence >= 0.8)
