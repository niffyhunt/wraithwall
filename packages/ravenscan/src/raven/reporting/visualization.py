"""Graphviz renderer — generates architecture and dependency diagrams.

Produces SVG with accessibility metadata from GraphData structures.
All output is deterministic: same input always produces the same DOT/SVG.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from raven.reporting.graph_builder import GraphData


BASE_GRAPH_ATTRS: dict[str, str] = {
    "bgcolor": "#09090B",
    "fontname": "IBM Plex Mono,monospace",
    "fontcolor": "#FAFAFA",
    "fontsize": "10",
    "labeljust": "l",
    "labelloc": "t",
    "rankdir": "TB",
    "splines": "polyline",
    "nodesep": "0.6",
    "ranksep": "1.0",
    "dpi": "96",
}

BASE_NODE_ATTRS: dict[str, str] = {
    "shape": "box",
    "style": "rounded,filled",
    "fontname": "IBM Plex Mono,monospace",
    "fontsize": "9",
    "margin": "0.15,0.08",
}

BASE_EDGE_ATTRS: dict[str, str] = {
    "fontname": "IBM Plex Mono,monospace",
    "fontsize": "8",
    "arrowsize": "0.6",
}


def _escape_dot_label(text: str) -> str:
    """Escape a string for safe DOT label usage."""
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _attr_line(attrs: dict[str, str]) -> str:
    return "  " + " ".join(f'{k}="{_escape_dot_label(v)}"' for k, v in attrs.items())


def render_dot(graph: GraphData, output_path: Optional[str] = None) -> str:
    """Render a GraphData structure to a DOT format string.

    Args:
        graph: The graph data to render.
        output_path: If provided, also writes the DOT file to disk.

    Returns:
        The DOT source string.
    """
    lines = [f'digraph "{_escape_dot_label(graph.title)}" {{']

    attrs = dict(BASE_GRAPH_ATTRS)
    attrs["rankdir"] = graph.rankdir
    attrs["label"] = graph.title
    lines.append(_attr_line(attrs))
    lines.append("")

    lines.append(f"  // {len(graph.nodes)} nodes")
    for node in graph.nodes:
        node_attrs = dict(BASE_NODE_ATTRS)
        node_attrs["fillcolor"] = node.color
        node_attrs["fontcolor"] = "#FFFFFF" if _is_dark(node.color) else "#09090B"
        node_attrs["width"] = str(round(node.size, 1))
        node_attrs["label"] = node.label
        if node.node_type == "project":
            node_attrs["shape"] = "component"
            node_attrs["style"] = "filled"
        lines.append(f'  "{_escape_dot_label(node.id)}" [{_attr_line(node_attrs)}]')

    if edges := graph.edges:
        lines.append("")
        lines.append(f"  // {len(edges)} edges")
        for edge in edges:
            edge_attrs = dict(BASE_EDGE_ATTRS)
            edge_attrs["color"] = edge.color + "80"
            edge_attrs["fontcolor"] = edge.color
            if edge.style == "dashed":
                edge_attrs["style"] = "dashed"
            if edge.label:
                edge_attrs["label"] = edge.label
            lines.append(f'  "{_escape_dot_label(edge.source)}" -> "{_escape_dot_label(edge.target)}" [{_attr_line(edge_attrs)}]')

    lines.append("}")
    dot_source = "\n".join(lines)

    if output_path:
        Path(output_path).write_text(dot_source)

    return dot_source


def render_svg(graph: GraphData, output_path: str) -> bool:
    """Render a GraphData structure to an SVG file.

    Requires the `graphviz` Python package to be installed.

    Args:
        graph: The graph data to render.
        output_path: Path to write the SVG file.

    Returns:
        True if rendering succeeded, False if graphviz is not available.
    """
    try:
        import graphviz as gv  # type: ignore[import-not-found,import-untyped,unused-ignore]
    except ImportError:
        return False

    dot = gv.Digraph(
        name=graph.title,
        format="svg",
        engine="dot",
    )
    dot.attr(**BASE_GRAPH_ATTRS)
    dot.attr("node", **BASE_NODE_ATTRS)
    dot.attr("edge", **BASE_EDGE_ATTRS)

    for node in graph.nodes:
        dot.node(
            node.id,
            label=node.label,
            shape="component" if node.node_type == "project" else "box",
            style="rounded,filled",
            fillcolor=node.color,
            fontcolor="#FFFFFF" if _is_dark(node.color) else "#09090B",
            width=str(round(node.size, 1)),
        )

    for edge in graph.edges:
        dot.edge(
            edge.source,
            edge.target,
            label=edge.label,
            color=edge.color + "80",
            style=edge.style,
        )

    try:
        dot.render(filename=Path(output_path).stem, directory=str(Path(output_path).parent), cleanup=True)
        return True
    except Exception:
        return False


def write_visualization(
    graph: GraphData,
    basename: str,
    output_dir: str | Path,
    format: str = "svg",
) -> dict[str, str]:
    """Write a graph visualization to disk in the requested format.

    Args:
        graph: The graph data to render.
        basename: Base filename without extension.
        output_dir: Output directory.
        format: Output format: 'dot', 'svg', or 'png'.

    Returns:
        Dict mapping format to output path.
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    result: dict[str, str] = {}

    if format == "dot":
        dot_path = str(output_path / f"{basename}.dot")
        render_dot(graph, dot_path)
        result["dot"] = dot_path

    elif format == "svg":
        dot_path = str(output_path / f"{basename}.dot")
        render_dot(graph, dot_path)
        svg_path = str(output_path / f"{basename}.svg")
        if render_svg(graph, svg_path):
            result["svg"] = svg_path
        result["dot"] = dot_path

    elif format == "png":
        dot_path = str(output_path / f"{basename}.dot")
        render_dot(graph, dot_path)
        result["dot"] = dot_path

    return result


def _is_dark(hex_color: str) -> bool:
    """Determine if a hex color is dark (for font color selection)."""
    hex_color = hex_color.lstrip("#")
    if len(hex_color) != 6:
        return True
    r, g, b = int(hex_color[0:2], 16), int(hex_color[2:4], 16), int(hex_color[4:6], 16)
    luminance = 0.299 * r + 0.587 * g + 0.114 * b
    return luminance < 128
