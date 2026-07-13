"""Semantic cross-revision delta.

Compares analysis artifacts between revisions and produces structured
change intelligence with confidence scoring.
"""

from raven.delta.base import (
    DeltaEntry,
    DeltaCategory,
    ChangeType,
    RevisionDelta,
)
from raven.delta.analyzers import (
    build_delta,
    compare_architecture,
    compare_security,
    compare_dependencies,
    compare_routes,
    compare_symbols,
    compare_imports,
    compare_evolution,
)

__all__ = [
    "DeltaEntry",
    "DeltaCategory",
    "ChangeType",
    "RevisionDelta",
    "build_delta",
    "compare_architecture",
    "compare_security",
    "compare_dependencies",
    "compare_routes",
    "compare_symbols",
    "compare_imports",
    "compare_evolution",
]
