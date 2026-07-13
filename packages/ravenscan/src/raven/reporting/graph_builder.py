"""Graph builder — constructs DOT graph data from architecture and dependency analysis.

Produces graph data structures consumed by the Graphviz renderer.
All output is deterministic: same input produces the same graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from raven.core.models import ArchitectureGraph, RepositoryProfile


@dataclass
class GraphNode:
    """A node in a graph visualization."""

    id: str
    label: str
    node_type: str = "module"
    size: float = 1.0
    color: str = "#3B82F6"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """An edge in a graph visualization."""

    source: str
    target: str
    label: str = ""
    weight: float = 1.0
    style: str = "solid"
    color: str = "#71717A"


@dataclass
class GraphData:
    """Complete graph description consumed by the Graphviz renderer."""

    title: str
    graph_type: str
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    rankdir: str = "TB"


def build_architecture_graph(
    arch: ArchitectureGraph,
    title: str = "Architecture Graph",
) -> GraphData:
    """Build a module dependency graph from ArchitectureGraph.

    Nodes are modules; edges are imports. Node size is proportional
    to module line count. Color indicates coupling risk.
    """
    max_lines = max((m.lines for m in arch.modules), default=1)
    max_coupling = max((len(m.imported_by) for m in arch.modules), default=1)

    def _node_color(imported_by_count: int) -> str:
        if imported_by_count > 10:
            return "#D00000"
        if imported_by_count > 5:
            return "#F59E0B"
        return "#3B82F6"

    nodes = []
    for m in arch.modules:
        size = 0.5 + (m.lines / max(max_lines, 1)) * 2.0
        nodes.append(GraphNode(
            id=m.name,
            label=f"{m.name}\\n({m.lines}L, {m.functions}f, {m.classes}c)",
            node_type="module",
            size=size,
            color=_node_color(len(m.imported_by)),
            metadata={"lines": m.lines, "functions": m.functions, "classes": m.classes, "imported_by": len(m.imported_by)},
        ))

    edges = []
    for m in arch.modules:
        for imp in m.imports:
            edges.append(GraphEdge(
                source=m.name,
                target=imp,
                label="",
                weight=0.5,
                style="dashed" if len(m.imported_by) <= 2 else "solid",
                color="#52525B" if len(m.imported_by) <= 2 else "#A1A1AA",
            ))

    return GraphData(
        title=title,
        graph_type="architecture",
        nodes=nodes,
        edges=edges,
        rankdir="TB",
    )


def build_dependency_graph(
    profile: RepositoryProfile,
    title: str = "Dependency Graph",
) -> GraphData:
    """Build a dependency graph from RepositoryProfile.

    Top-level project node showing all dependencies with version info.
    """
    project_name = profile.structure.root if profile.structure else "project"
    nodes = [
        GraphNode(
            id="project",
            label=project_name.split("/")[-1] if "/" in project_name else project_name,
            node_type="project",
            size=2.0,
            color="#22C55E",
        )
    ]

    for dep in profile.dependencies:
        node_id = f"dep_{dep.name}"
        nodes.append(GraphNode(
            id=node_id,
            label=f"{dep.name}\\n{dep.version}" if dep.version != "unknown" else dep.name,
            node_type="dependency",
            size=0.7,
            color="#F59E0B" if dep.is_dev else "#3B82F6",
            metadata={"version": dep.version, "source": dep.source, "is_dev": dep.is_dev},
        ))
    edges: list[GraphEdge] = [GraphEdge(source="project", target=f"dep_{dep.name}", label="depends", weight=1.0, style="solid") for dep in profile.dependencies]

    return GraphData(
        title=title,
        graph_type="dependencies",
        nodes=nodes,
        edges=edges,
        rankdir="LR",
    )


def build_module_relationship_graph(
    arch: ArchitectureGraph,
    title: str = "Module Relationships",
) -> GraphData:
    """Build a module relationship graph focusing on coupling clusters.

    Only shows modules with significant coupling (imported_by > 2 or
    imports > 2) to avoid visual noise.
    """
    nodes = []
    edges = []
    significant_modules = {m.name for m in arch.modules if len(m.imported_by) > 2 or len(m.imports) > 2}

    if not significant_modules:
        significant_modules = {m.name for m in arch.modules[:20]}

    for m in arch.modules:
        if m.name not in significant_modules:
            continue
        coupling = len(m.imported_by)
        nodes.append(GraphNode(
            id=m.name,
            label=m.name,
            node_type="module",
            size=0.5 + min(coupling * 0.3, 3.0),
            color="#D00000" if coupling > 10 else "#F59E0B" if coupling > 5 else "#3B82F6",
        ))

    seen_edges: set[tuple[str, str]] = set()
    for m in arch.modules:
        if m.name not in significant_modules:
            continue
        for imp in m.imports:
            if imp not in significant_modules:
                continue
            key = (m.name, imp)
            if key in seen_edges:
                continue
            seen_edges.add(key)
            edges.append(GraphEdge(
                source=m.name,
                target=imp,
                label="imports",
                weight=0.5,
                style="solid",
                color="#A1A1AA",
            ))

    return GraphData(
        title=title,
        graph_type="module_relationships",
        nodes=nodes,
        edges=edges,
        rankdir="TB",
    )
