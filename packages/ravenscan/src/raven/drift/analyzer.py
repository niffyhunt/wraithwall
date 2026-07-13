"""Engineering Drift — continuous measurement of codebase evolution metrics.

Measures complexity, maintainability, cohesion, coupling, duplication,
technical debt, file growth, function growth, and architecture erosion.
Shows trends over time — never produces isolated snapshots.
"""

from __future__ import annotations

import ast
import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from raven.core.config import RavenConfig
from raven.core.context import RepositoryContext
from raven.core.models import (
    ArchitectureGraph,
    ArchitectureFinding,
    Severity,
    Confidence,
)


@dataclass
class ComplexityMetrics:
    """Per-module complexity measurements."""

    module_path: str
    total_lines: int
    code_lines: int
    comment_lines: int
    blank_lines: int
    functions: int
    classes: int
    avg_function_lines: float = 0.0
    max_function_lines: int = 0
    cyclomatic_complexity: int = 0
    import_count: int = 0
    todo_count: int = 0
    fixme_count: int = 0
    hack_count: int = 0


@dataclass
class CouplingMetrics:
    """Module-level coupling measurements."""

    module_path: str
    afferent_coupling: int = 0  # Ca — modules depending on this one
    efferent_coupling: int = 0  # Ce — modules this one depends on
    instability: float = 0.0    # I = Ce / (Ca + Ce), 1.0 if Ca+Ce == 0

    def __post_init__(self) -> None:
        total = self.afferent_coupling + self.efferent_coupling
        self.instability = self.efferent_coupling / total if total > 0 else 0.0


@dataclass
class DuplicationReport:
    """Detected duplicate code blocks."""

    hash_value: str
    block_size: int
    files: list[str]
    lines: list[tuple[str, int]]


@dataclass
class DriftSnapshot:
    """A complete engineering drift measurement at one point in time."""

    scanned_at: str
    total_files: int
    total_lines: int
    total_python_files: int
    avg_lines_per_file: float = 0.0
    max_lines_per_file: int = 0
    avg_functions_per_file: float = 0.0
    max_functions_per_file: int = 0
    avg_classes_per_file: float = 0.0
    comment_to_code_ratio: float = 0.0
    total_todos: int = 0
    total_fixmes: int = 0
    total_hacks: int = 0
    avg_instability: float = 0.0
    modules_with_high_instability: int = 0
    duplicate_blocks: int = 0
    god_module_count: int = 0
    circular_import_count: int = 0
    dead_code_count: int = 0
    complexity: list[ComplexityMetrics] = field(default_factory=list)
    coupling: list[CouplingMetrics] = field(default_factory=list)
    duplications: list[DuplicationReport] = field(default_factory=list)


def analyze(
    ctx: RepositoryContext,
    arch: ArchitectureGraph,
    config: Optional[RavenConfig] = None,
) -> DriftSnapshot:
    """Compute a complete engineering drift snapshot from context and architecture graph."""

    import datetime
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    complexity = _measure_complexity(ctx)
    coupling = _measure_coupling(arch)
    duplications = _detect_duplication(ctx)

    python_files = [f for f in ctx.files if f.language == "python"]
    py_count = len(python_files)
    total_lines = sum(c.total_lines for c in complexity)
    total_funcs = sum(c.functions for c in complexity)
    total_classes = sum(c.classes for c in complexity)
    total_comments = sum(c.comment_lines for c in complexity)

    snapshot = DriftSnapshot(
        scanned_at=now,
        total_files=ctx.total_files,
        total_lines=ctx.total_lines,
        total_python_files=ctx.total_python_files,
        avg_lines_per_file=total_lines / max(py_count, 1),
        max_lines_per_file=max((c.total_lines for c in complexity), default=0),
        avg_functions_per_file=total_funcs / max(py_count, 1),
        max_functions_per_file=max((c.functions for c in complexity), default=0),
        avg_classes_per_file=total_classes / max(py_count, 1),
        comment_to_code_ratio=total_comments / max(total_lines, 1),
        total_todos=sum(c.todo_count for c in complexity),
        total_fixmes=sum(c.fixme_count for c in complexity),
        total_hacks=sum(c.hack_count for c in complexity),
        avg_instability=sum(c.instability for c in coupling) / max(len(coupling), 1),
        modules_with_high_instability=sum(1 for c in coupling if c.instability > 0.7),
        duplicate_blocks=len(duplications),
        god_module_count=len(arch.god_modules),
        circular_import_count=len(arch.circular_imports),
        dead_code_count=len(arch.dead_code),
        complexity=complexity,
        coupling=coupling,
        duplications=duplications,
    )
    return snapshot


def delta(previous: Optional[DriftSnapshot], current: DriftSnapshot) -> dict[str, object]:
    """Compute the delta between two drift snapshots for trend analysis."""
    if previous is None:
        return {"status": "first_scan"}

    def _pct(new: float, old: float) -> float:
        if old == 0:
            return 100.0 if new > 0 else 0.0
        return round(((new - old) / old) * 100, 1)

    return {
        "status": "delta_computed",
        "total_files": _pct(current.total_files, previous.total_files),
        "total_lines": _pct(current.total_lines, previous.total_lines),
        "avg_lines_per_file": _pct(current.avg_lines_per_file, previous.avg_lines_per_file),
        "avg_functions_per_file": _pct(current.avg_functions_per_file, previous.avg_functions_per_file),
        "total_todos": _pct(current.total_todos, previous.total_todos),
        "avg_instability": _pct(current.avg_instability, previous.avg_instability),
        "duplicate_blocks": _pct(current.duplicate_blocks, previous.duplicate_blocks),
        "god_module_count": _pct(current.god_module_count, previous.god_module_count),
        "circular_import_count": _pct(current.circular_import_count, previous.circular_import_count),
        "dead_code_count": _pct(current.dead_code_count, previous.dead_code_count),
        "comment_to_code_ratio": _pct(current.comment_to_code_ratio, previous.comment_to_code_ratio),
    }


def _measure_complexity(ctx: RepositoryContext) -> list[ComplexityMetrics]:
    """Measure complexity metrics for every Python file."""
    results: list[ComplexityMetrics] = []

    for f in ctx.files:
        if f.language != "python":
            continue

        total = len(f.lines)
        blank = sum(1 for line in f.lines if not line.strip())
        comment = sum(1 for line in f.lines if line.strip().startswith("#"))
        code = total - blank - comment

        funcs = 0
        func_lines: list[int] = []
        classes = 0
        cc_total = 1

        if f.ast_tree:
            classes, funcs, func_lines, cc_total = _walk_ast(f.ast_tree)

        avg_func = sum(func_lines) / max(len(func_lines), 1) if func_lines else 0.0
        max_func = max(func_lines) if func_lines else 0

        todo = sum(1 for line in f.lines if "TODO" in line)
        fixme = sum(1 for line in f.lines if "FIXME" in line)
        hack = sum(1 for line in f.lines if "HACK" in line)

        import_count = 0
        if f.ast_tree:
            import_count = sum(1 for node in ast.walk(f.ast_tree) if isinstance(node, (ast.Import, ast.ImportFrom)))

        results.append(ComplexityMetrics(
            module_path=f.relative_path,
            total_lines=total,
            code_lines=code,
            comment_lines=comment,
            blank_lines=blank,
            functions=funcs,
            classes=classes,
            avg_function_lines=round(avg_func, 1),
            max_function_lines=max_func,
            cyclomatic_complexity=cc_total,
            import_count=import_count,
            todo_count=todo,
            fixme_count=fixme,
            hack_count=hack,
        ))

    return results


def _walk_ast(tree: ast.AST) -> tuple[int, int, list[int], int]:
    """Walk an AST and count classes, functions, function line lengths, and cyclomatic complexity in a single pass."""
    classes = 0
    funcs = 0
    func_lines: list[int] = []
    cc = 1

    for node in ast.walk(tree):
        cc += sum(1 for _ in ast.iter_child_nodes(node))
        if isinstance(node, ast.ClassDef):
            classes += 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs += 1
            if node.end_lineno and node.lineno:
                func_lines.append(node.end_lineno - node.lineno + 1)

    return classes, funcs, func_lines, cc


def _measure_coupling(arch: ArchitectureGraph) -> list[CouplingMetrics]:
    """Compute afferent/efferent coupling and instability for every module."""
    results: list[CouplingMetrics] = []
    for mod in arch.modules:
        ca = len(mod.imported_by)
        ce = len(mod.imports)
        total = ca + ce
        i = ce / total if total > 0 else 0.0
        results.append(CouplingMetrics(
            module_path=mod.path,
            afferent_coupling=ca,
            efferent_coupling=ce,
            instability=round(i, 2),
        ))
    return results


def _detect_duplication(ctx: RepositoryContext, min_lines: int = 6) -> list[DuplicationReport]:
    """Detect duplicate code blocks across files using hashing."""
    seen: dict[str, list[tuple[str, int, str]]] = defaultdict(list)
    results: list[DuplicationReport] = []

    for f in ctx.files:
        if f.language != "python":
            continue
        for i in range(len(f.lines) - min_lines + 1):
            block_text = "\n".join(line.strip() for line in f.lines[i:i + min_lines] if line.strip())
            if len(block_text) < 20:
                continue
            h = hashlib.sha256(block_text.encode()).hexdigest()
            seen[h].append((f.relative_path, i + 1, block_text))

    for h, occurrences in seen.items():
        if len(occurrences) >= 2:
            files = list({o[0] for o in occurrences})
            if len(files) >= 2:
                results.append(DuplicationReport(
                    hash_value=h[:12],
                    block_size=min_lines,
                    files=files,
                    lines=[(o[0], o[1]) for o in occurrences],
                ))

    return results[:30]
