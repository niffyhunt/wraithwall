"""Evidence-backed security flow analysis.

This module deliberately reports only local, syntactically proven flows. It
never infers exploitability from names alone and returns unknown reachability
when import evidence is insufficient.
"""

from __future__ import annotations

import ast
import re
from hashlib import sha256
from typing import Iterable

from raven.core.context import RepositoryContext, ParsedFile
from raven.core.models import (
    AttackPath,
    Confidence,
    DependencyReachability,
    DependencyEntry,
    SecurityFinding,
    TaintFlow,
    TaintNode,
)

SOURCE_CALLS = {
    "request.args.get", "request.form.get", "request.json.get", "request.get_json",
    "input", "os.getenv", "os.environ.get",
}
SINK_CALLS = {
    "os.system", "os.popen", "subprocess.run", "subprocess.call", "subprocess.Popen",
    "eval", "exec", "open", "requests.get", "requests.post", "cursor.execute",
}
TRANSFORMS = {"str", "format", "join", "quote", "replace", "strip"}


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        parts: list[str] = []
        cur: ast.AST = node.func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def _node(file: ParsedFile, kind: str, label: str, line: int) -> TaintNode:
    return TaintNode(kind=kind, label=label, file=file.relative_path, line=line)


def _value_names(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def analyze_taint(ctx: RepositoryContext) -> list[TaintFlow]:
    """Find source-to-sink flows through direct assignments in one file."""
    flows: list[TaintFlow] = []
    for pf in ctx.files:
        if pf.language != "python" or pf.ast_tree is None:
            continue
        source_vars: dict[str, TaintNode] = {}
        transform_vars: dict[str, list[TaintNode]] = {}
        for statement in ast.walk(pf.ast_tree):
            if isinstance(statement, ast.Assign):
                value = statement.value
                if isinstance(value, ast.Call) and _call_name(value) in SOURCE_CALLS:
                    source = _node(pf, "source", _call_name(value), statement.lineno)
                    for target in statement.targets:
                        if isinstance(target, ast.Name):
                            source_vars[target.id] = source
                elif isinstance(value, ast.Call) and _call_name(value) in TRANSFORMS:
                    names = _value_names(value)
                    inherited = [source_vars[n] for n in names if n in source_vars]
                    if inherited:
                        for target in statement.targets:
                            if isinstance(target, ast.Name):
                                transform_vars[target.id] = inherited + [_node(pf, "transformation", _call_name(value), statement.lineno)]
            elif isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
                call = statement.value
                sink_name = _call_name(call)
                if sink_name not in SINK_CALLS:
                    continue
                names = _value_names(call)
                inherited_sources = [source_vars[n] for n in names if n in source_vars]
                transformations = [node for n in names for node in transform_vars.get(n, [])]
                if not inherited_sources:
                    continue
                source = inherited_sources[0]
                sink = _node(pf, "sink", sink_name, statement.lineno)
                propagation = [_node(pf, "propagation", name, statement.lineno) for name in sorted(names) if name in source_vars]
                key = f"{pf.relative_path}:{source.line}:{sink.line}:{sink_name}"
                flows.append(TaintFlow(
                    flow_id="flow-" + sha256(key.encode()).hexdigest()[:20],
                    source=source,
                    propagation=propagation,
                    transformation=transformations,
                    sink=sink,
                    evidence=f"AST data flow: {source.label} at {source.file}:{source.line} reaches {sink.label} at {sink.file}:{sink.line}",
                    confidence=Confidence.HIGH if not transformations else Confidence.MEDIUM,
                ))
    return flows


def build_attack_paths(flows: Iterable[TaintFlow], findings: Iterable[SecurityFinding]) -> list[AttackPath]:
    """Correlate flow sinks with findings at the same file/line evidence."""
    findings_list = list(findings)
    paths: list[AttackPath] = []
    for flow in flows:
        related = [f for f in findings_list if f.affected_file == flow.sink.file and any(abs(line - flow.sink.line) <= 2 for line in f.affected_lines)]
        if not related:
            continue
        ids = [f.finding_id for f in related]
        steps = [flow.source, *flow.propagation, *flow.transformation, flow.sink]
        paths.append(AttackPath(
            path_id="path-" + sha256(flow.flow_id.encode()).hexdigest()[:20],
            steps=steps,
            finding_ids=ids,
            evidence=f"Proven flow and finding correlation at {flow.sink.file}:{flow.sink.line}; " + "; ".join(f.title for f in related),
            confidence=Confidence.HIGH if flow.confidence == Confidence.HIGH else Confidence.MEDIUM,
        ))
    return paths


def _dependency_is_imported(dep_name: str, pf: ParsedFile) -> bool:
    """Require import/use evidence, excluding manifests and comments."""
    normalized = dep_name.lower().replace("-", "_")
    if pf.relative_path.endswith(("requirements.txt", "requirements.in", "pyproject.toml", "package.json", "Pipfile", "Cargo.toml", "go.mod")):
        return False
    if pf.language == "python" and pf.ast_tree is not None:
        for node in ast.walk(pf.ast_tree):
            if isinstance(node, ast.Import) and any(alias.name.split(".")[0].lower().replace("-", "_") == normalized for alias in node.names):
                return True
            if isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[0].lower().replace("-", "_") == normalized:
                return True
        return False
    import_pattern = rf"(?im)^\s*(?:import|from|use|require\s*\()\s+[\"']?{re.escape(normalized)}(?:[\"'/;\s]|$)"
    return bool(re.search(import_pattern, pf.content))


def dependency_reachability(ctx: RepositoryContext) -> list[DependencyReachability]:
    """Classify dependency usage from import evidence without vulnerability claims."""

    results: list[DependencyReachability] = []
    for dep in ctx.dependencies:
        imports = [pf for pf in ctx.files if _dependency_is_imported(dep.name, pf)]
        if imports:
            results.append(DependencyReachability(
                dependency=dep.name,
                status="demonstrated_reachability",
                imported_modules=[pf.relative_path for pf in imports[:20]],
                evidence=[f"Import/use statement for {dep.name} found in {pf.relative_path}" for pf in imports[:20]],
                confidence=Confidence.MEDIUM,
            ))
        else:
            results.append(DependencyReachability(
                dependency=dep.name,
                status="unknown_reachability",
                evidence=[f"Declared in {dep.source}; no matching import evidence found"],
                confidence=Confidence.LOW,
            ))
    return results
