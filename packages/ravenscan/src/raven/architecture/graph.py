"""Phase 2 — Architecture Graph.

Builds module graph, detects:
- Circular imports
- God modules (excessive size or responsibilities)
- Dead code (unused imports, unreferenced modules)
- Tight coupling (modules with too many dependents)

Produces: ArchitectureGraph
"""

from __future__ import annotations

import ast
from collections import defaultdict
from typing import TYPE_CHECKING, Optional

from raven.core.context import RepositoryContext
from raven.core.config import RavenConfig
from raven.core.models import (
    ModuleNode,
    ArchitectureGraph,
    ArchitectureFinding,
    Severity,
    Confidence,
)
from raven.utils.logging import get_logger

logger = get_logger(__name__)

if TYPE_CHECKING:
    from raven.core.context import ParsedFile

GOD_MODULE_LINES = 3000
GOD_MODULE_FUNCTIONS = 50
GOD_MODULE_CLASSES = 20
HIGH_COUPLING_IMPORTED_BY = 10
CIRCULAR_DEPTH_MAX = 10
DEAD_CODE_RESULT_CAP = 20


def analyze(ctx: RepositoryContext, config: Optional[RavenConfig] = None) -> ArchitectureGraph:
    """Run Phase 2 analysis on the repository context."""
    modules = _build_modules(ctx)
    findings = _detect_findings(modules, ctx)
    return ArchitectureGraph(modules=modules, findings=findings)


def _build_modules(ctx: RepositoryContext) -> list[ModuleNode]:
    """Construct a module graph from all Python files in context.

    Each module node captures metadata (lines, classes, functions) and
    import relationships. The graph is used by all downstream detectors.
    """
    nodes: dict[str, ModuleNode] = {}
    imports_graph: dict[str, list[str]] = defaultdict(list)

    for f in ctx.files:
        if f.language != "python":
            continue
        mod = _module_from_file(f)
        nodes[mod.name] = mod
        if f.ast_tree:
            import_names = _extract_imports(f.ast_tree)
            imports_graph[mod.name] = import_names

    module_names = set(nodes.keys())
    for mod_name, imports in imports_graph.items():
        resolved: list[str] = []
        for imp in imports:
            target = _resolve_import(imp, module_names)
            if target and target != mod_name and target in nodes:
                resolved.append(target)
                nodes[target].imported_by.append(mod_name)
        nodes[mod_name].imports = sorted(set(resolved))

    return list(nodes.values())


def _module_from_file(f: ParsedFile) -> ModuleNode:
    """Extract a ModuleNode from a single parsed file."""
    name = _file_to_module_name(f.relative_path)
    classes = 0
    functions = 0
    if f.ast_tree:
        for node in ast.walk(f.ast_tree):
            if isinstance(node, ast.ClassDef):
                classes += 1
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions += 1
    return ModuleNode(
        name=name,
        path=f.relative_path,
        lines=len(f.lines),
        classes=classes,
        functions=functions,
    )


def _file_to_module_name(relative_path: str) -> str:
    """Convert a file path to a Python module name."""
    name = relative_path.replace("/", ".").replace("\\", ".")
    for ext in (".py", ".pyi", ".pyx"):
        if name.endswith(ext):
            name = name[: -len(ext)]
            break
    if name.endswith(".__init__"):
        name = name[: -len(".__init__")]
    return name


def _extract_imports(tree: ast.AST) -> list[str]:
    """Extract all imported module names from a Python AST."""
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)
    return imports


def _resolve_import(import_name: str, module_names: set[str]) -> Optional[str]:
    """Resolve an import name to a known module in the repository.

    Attempts exact match first, then top-level package match, then
    strips common suffixes for fuzzy matching.
    """
    if import_name in module_names:
        return import_name
    for mn in module_names:
        if mn == import_name or mn.startswith(import_name + ".") or import_name.startswith(mn + "."):
            return mn
    parts = import_name.split(".")
    while parts:
        candidate = ".".join(parts)
        if candidate in module_names:
            return candidate
        parts.pop()
    return None


def _detect_findings(modules: list[ModuleNode], ctx: RepositoryContext) -> list[ArchitectureFinding]:
    """Run all architecture detectors and collect findings."""
    findings: list[ArchitectureFinding] = []
    findings.extend(_detect_circular(modules))
    findings.extend(_detect_god_modules(modules))
    findings.extend(_detect_dead_code(modules, ctx))
    findings.extend(_detect_tight_coupling(modules))
    return findings


def _detect_circular(modules: list[ModuleNode]) -> list[ArchitectureFinding]:
    """Detect circular import chains using depth-first search.

    A cycle exists if a module is reachable from itself through the import graph.
    """
    results: list[ArchitectureFinding] = []
    mod_map = {m.name: m for m in modules}
    visited: set[str] = set()
    in_stack: set[str] = set()
    cycles: list[list[str]] = []

    def dfs(name: str, path: list[str]) -> None:
        if name in in_stack:
            cycle_start = path.index(name)
            cycles.append(path[cycle_start:])
            return
        if name in visited:
            return
        visited.add(name)
        in_stack.add(name)
        path.append(name)
        for imp in mod_map.get(name, ModuleNode(name=name, path="")).imports:
            if imp in mod_map:
                dfs(imp, list(path))
        in_stack.discard(name)

    for mod in modules:
        if mod.name not in visited:
            dfs(mod.name, [])

    seen: set[tuple[str, ...]] = set()
    for cycle in cycles:
        key = tuple(sorted(cycle))
        if key in seen:
            continue
        seen.add(key)
        cycle_str = " -> ".join(cycle)
        results.append(
            ArchitectureFinding(
                severity=Severity.HIGH,
                category="circular_import",
                title=f"Circular import: {cycle_str}",
                description=f"Modules {', '.join(cycle)} form a circular dependency chain.",
                evidence=f"Import chain: {cycle_str}",
                affected_files=[mod_map[m].path for m in cycle],
                recommendation="Break the cycle by extracting shared dependencies into a separate module or using dependency inversion.",
                confidence=Confidence.HIGH,
            )
        )
    return results


def _detect_god_modules(modules: list[ModuleNode]) -> list[ArchitectureFinding]:
    """Detect modules exceeding line, function, or class count thresholds."""
    results: list[ArchitectureFinding] = []
    for mod in modules:
        reasons: list[str] = []
        if mod.lines > GOD_MODULE_LINES:
            reasons.append(f"exceeds {GOD_MODULE_LINES} lines ({mod.lines} lines)")
        if mod.functions > GOD_MODULE_FUNCTIONS:
            reasons.append(f"exceeds {GOD_MODULE_FUNCTIONS} functions ({mod.functions} functions)")
        if mod.classes > GOD_MODULE_CLASSES:
            reasons.append(f"exceeds {GOD_MODULE_CLASSES} classes ({mod.classes} classes)")
        if reasons:
            results.append(
                ArchitectureFinding(
                    severity=Severity.MEDIUM if len(reasons) == 1 else Severity.HIGH,
                    category="god_module",
                    title=f"God module: {mod.name}",
                    description=f"{mod.name} is too large: {'; '.join(reasons)}.",
                    evidence=f"Module has {mod.lines} lines, {mod.functions} functions, {mod.classes} classes.",
                    affected_files=[mod.path],
                    recommendation="Split the module into smaller, focused modules by responsibility.",
                    confidence=Confidence.HIGH,
                )
            )
    return results


def _detect_dead_code(modules: list[ModuleNode], ctx: RepositoryContext) -> list[ArchitectureFinding]:
    """Detect modules not imported by any other module in the project.

    A module is considered potentially dead if it has no importers and is
    not a root-level module that other modules might depend on by prefix.
    """
    results: list[ArchitectureFinding] = []
    referenced: set[str] = set()

    for mod in modules:
        for imp in mod.imports:
            referenced.add(imp)

    unused: list[ModuleNode] = []
    for mod in modules:
        if mod.imported_by:
            continue
        if mod.name in ("__main__", "main"):
            continue
        if not any(mod.name.startswith(m.name + ".") for m in modules if m != mod):
            unused.append(mod)

    for mod in unused[:DEAD_CODE_RESULT_CAP]:
        results.append(
            ArchitectureFinding(
                severity=Severity.LOW,
                category="dead_code",
                title=f"Potentially dead module: {mod.name}",
                description=f"{mod.name} is not imported by any other module in the project.",
                evidence=f"No modules import {mod.name}.",
                affected_files=[mod.path],
                recommendation="Verify if this module is an entry point or still needed, otherwise remove it.",
                confidence=Confidence.LOW,
            )
        )
    return results


def _detect_tight_coupling(modules: list[ModuleNode]) -> list[ArchitectureFinding]:
    """Detect modules imported by more than HIGH_COUPLING_IMPORTED_BY other modules."""
    results: list[ArchitectureFinding] = []
    for mod in modules:
        if len(mod.imported_by) > HIGH_COUPLING_IMPORTED_BY:
            results.append(
                ArchitectureFinding(
                    severity=Severity.MEDIUM,
                    category="tight_coupling",
                    title=f"Tight coupling: {mod.name}",
                    description=f"{mod.name} is imported by {len(mod.imported_by)} other modules.",
                    evidence=f"Imported by: {', '.join(sorted(mod.imported_by)[:15])}",
                    affected_files=[mod.path],
                    recommendation="Consider splitting or introducing an interface to reduce coupling.",
                    confidence=Confidence.MEDIUM,
                )
            )
    return results
