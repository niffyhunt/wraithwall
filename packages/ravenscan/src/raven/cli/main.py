"""CLI entry point — Typer app.

Every command supports global flags: --format, --quiet, --verbose, --no-color.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import requests
import typer
from rich.console import Console
from rich.table import Table

from raven import __version__
from raven.core.config import RavenConfig
from raven.core.errors import ThresholdError
from raven.sdk.client import Raven
from raven.reporting.renderers.json_renderer import write_artifact
from raven.utils.logging import configure_root

app = typer.Typer(
    name="raven",
    help="Engineering intelligence agent — learn your codebase over time.",
    no_args_is_help=True,
)

console = Console(highlight=False)


def _build_config(
    path: Path,
    output_dir: str,
    fmt: str,
    quiet: bool,
    verbose: bool,
    no_color: bool,
) -> RavenConfig:
    configure_root(verbose=verbose, quiet=quiet)
    return RavenConfig(
        path=path.resolve(),
        output_dir=Path(output_dir),
        format=fmt,
        quiet=quiet,
        verbose=verbose,
        no_color=no_color,
    )


def _phase_status(quiet: bool, label: str) -> None:
    """Print a phase progress line if not in quiet mode."""
    if not quiet:
        console.print(f"  {label}...")


def _phase_check(quiet: bool, message: str) -> None:
    """Print a phase completion checkmark if not in quiet mode."""
    if not quiet:
        console.print(f"    [green]\u2713[/green] {message}")


def _emoji_for_score(score: float) -> str:
    if score >= 80:
        return "\u2705"
    if score >= 50:
        return "\u26a0\ufe0f"
    return "\u274c"


@app.command()
def init(
    path: str = typer.Argument(".", help="Repository path to initialize"),
) -> None:
    """Scaffold a .raven configuration directory."""
    target = Path(path).resolve()
    raven_dir = target / ".raven"
    raven_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[green]\u2713[/green] Initialized .raven directory at {raven_dir}")
    console.print("  Run [bold]raven scan[/bold] to analyze this repository.")


@app.command()
def scan(
    path: str = typer.Argument(".", help="Repository path to scan"),
    output_dir: str = typer.Option(".raven", "--output", "-o", help="Output directory for artifacts"),
    output_format: str = typer.Option("markdown", "--format", "-f", help="Output format: json or markdown"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
    include_operational: bool = typer.Option(False, "--include-operational", help="Include runtime operational health data"),
) -> None:
    """Run full analysis and write artifacts."""
    cfg = _build_config(Path(path), output_dir, output_format, quiet, verbose, no_color)

    try:
        client = Raven(cfg)

        if not quiet:
            console.print("[bold]Raven[/bold] — scanning repository...", style="cyan")

        _phase_status(quiet, "Phase 1: Repository Intelligence...")
        profile = client.scan()
        write_artifact(profile, "RepositoryProfile", cfg, output_format)
        _phase_check(
            quiet,
            f"{profile.language_primary} — {profile.structure.total_files if profile.structure else 0} files, {len(profile.dependencies)} dependencies",
        )

        _phase_status(quiet, "Phase 2: Architecture Graph...")
        arch = client.architecture()
        write_artifact(arch, "ArchitectureGraph", cfg, output_format)
        _phase_check(quiet, f"{len(arch.modules)} modules, {len(arch.findings)} findings")

        _phase_status(quiet, "Phase 3: Security Intelligence...")
        sec = client.security()
        write_artifact(sec, "SecurityReport", cfg, output_format)
        _phase_check(quiet, f"{sec.total_findings} findings ({sec.critical_count} critical, {sec.high_count} high)")

        _phase_status(quiet, "Phase 9: Scoring...")
        risk = client.score(profile, arch, sec, include_operational=include_operational)
        write_artifact(risk, "RiskScore", cfg, output_format)
        _phase_check(quiet, f"Overall: {risk.overall}/100 — Grade {risk.grade}")

        _phase_status(quiet, "Phase 7: Daily Report...")
        daily_rpt = client.daily_report(profile, arch, sec)
        write_artifact(daily_rpt, "DailyReport", cfg, output_format)
        _phase_check(quiet, f"Risk trend: {daily_rpt.risk_trend}")

        if not quiet:
            console.print(f"\n[green bold]\u2713 Scan complete[/green bold] — artifacts written to {cfg.output_dir}/")
    except Exception as exc:
        console.print(f"\n[red bold]Scan failed:[/red bold] {exc}")
        if verbose:
            import traceback
            traceback.print_exc()
        raise typer.Exit(code=2)


@app.command()
def report(
    output_format: str = typer.Option("markdown", "--format", "-f", help="Output format: json, markdown, or graphviz"),
    output_dir: str = typer.Option(".raven", "--output", "-o", help="Output directory for artifacts"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Render existing artifacts (useful after scan)."""
    od = Path(output_dir)
    if output_format == "json":
        artifacts = sorted(od.glob("*.json"))
        for a in artifacts:
            console.print(a.read_text())
            console.print()
    else:
        md = sorted(od.glob("*.md"))
        for a in md:
            console.print(a.read_text())
            console.print()
    if not (list(od.glob("*.json")) or list(od.glob("*.md"))):
        console.print("[yellow]No artifacts found.[/yellow] Run [bold]raven scan[/bold] first.")


@app.command()
def score(
    path: str = typer.Argument(".", help="Repository path to analyze"),
    fail_under: Optional[float] = typer.Option(None, "--fail-under", help="Exit code 1 if overall score < N"),
    output_format: str = typer.Option("markdown", "--format", "-f"),
    output_dir: str = typer.Option(".raven", "--output", "-o"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    no_color: bool = typer.Option(False, "--no-color"),
    include_operational: bool = typer.Option(False, "--include-operational", help="Include runtime operational health in score"),
) -> None:
    """Compute repository risk score (CI gate)."""
    cfg = _build_config(Path(path), output_dir, output_format, quiet, verbose, no_color)
    client = Raven(cfg)

    if not quiet:
        console.print("[bold]Raven[/bold] — computing risk score...", style="cyan")

    profile = client.scan()
    arch = client.architecture()
    sec = client.security()
    risk = client.score(profile, arch, sec, include_operational=include_operational)

    write_artifact(risk, "RiskScore", cfg, output_format)

    table = Table(title=f"Risk Score — {risk.grade}")
    table.add_column("Category", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("Health", justify="center")
    for c in risk.categories:
        table.add_row(c.category.value, f"{c.score:.1f}/100", _emoji_for_score(c.score))
    table.add_row("[bold]OVERALL[/bold]", f"[bold]{risk.overall:.1f}/100[/bold]", "")
    console.print(table)

    if fail_under is not None and risk.overall < fail_under:
        console.print(f"\n[red]Score {risk.overall:.1f} is below threshold {fail_under}[/red]")
        raise typer.Exit(code=1)


# --- WraithWall Connected Mode (official CLI integration) ---
wraith_app = typer.Typer(help="WraithWall connected commands (requires running WraithWall instance)")

@wraith_app.command()
def whoami(
    base_url: str = typer.Option("https://wraithwall.online", "--url", help="WraithWall base URL (use https://wraithwall.online for remote)"),
    api_key: Optional[str] = typer.Option(None, "--api-key", envvar="WRAITH_API_KEY", help="API key for auth (for remote use)"),
    api_secret: Optional[str] = typer.Option(None, "--api-secret", envvar="WRAITH_API_SECRET", help="API secret for auth"),
):
    """Check connected identity. Works with session (local) or API key (remote)."""
    headers = {}
    if api_key and api_secret:
        headers["Authorization"] = f"Bearer {api_key}:{api_secret}"
    try:
        r = requests.get(f"{base_url}/api/raven/whoami", headers=headers, timeout=10)
        if r.status_code == 200:
            console.print(r.json())
        else:
            console.print(f"[red]Error: {r.status_code} {r.text}[/red]")
    except Exception as e:
        console.print(f"[red]Failed to connect to {base_url}: {e}[/red]")

@wraith_app.command()
def campaigns(
    base_url: str = typer.Option("https://wraithwall.online", "--url", help="WraithWall base URL (use https://wraithwall.online for remote)"),
    api_key: Optional[str] = typer.Option(None, "--api-key", envvar="WRAITH_API_KEY", help="API key for auth (for remote use)"),
    api_secret: Optional[str] = typer.Option(None, "--api-secret", envvar="WRAITH_API_SECRET", help="API secret for auth"),
):
    """List active campaigns from WraithWall."""
    headers = {}
    if api_key and api_secret:
        headers["Authorization"] = f"Bearer {api_key}:{api_secret}"
    try:
        r = requests.get(f"{base_url}/api/raven/campaigns", headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            console.print(f"Active campaigns: {len(data.get('campaigns', []))}")
            for c in data.get('campaigns', [])[:5]:
                console.print(f"  - {c.get('id', 'unknown')}")
        else:
            console.print(f"[red]Error: {r.status_code}[/red]")
    except Exception as e:
        console.print(f"[red]Failed: {e}[/red]")

@wraith_app.command()
def submit(
    path: str = typer.Argument(".", help="Path to scan and submit"),
    base_url: str = typer.Option("https://wraithwall.online", "--url", help="WraithWall base URL (use https://wraithwall.online for remote)"),
    api_key: Optional[str] = typer.Option(None, "--api-key", envvar="WRAITH_API_KEY", help="API key for auth (for remote use)"),
    api_secret: Optional[str] = typer.Option(None, "--api-secret", envvar="WRAITH_API_SECRET", help="API secret for auth"),
):
    """Scan locally and submit result to WraithWall (demo connected)."""
    headers = {"Content-Type": "application/json"}
    if api_key and api_secret:
        headers["Authorization"] = f"Bearer {api_key}:{api_secret}"
    cfg = _build_config(Path(path), ".raven", "json", True, False, False)
    client = Raven(cfg)
    profile = client.scan()
    try:
        profile_data = profile.model_dump() if hasattr(profile, 'model_dump') else str(profile)
        r = requests.post(f"{base_url}/api/raven/submit-scan", headers=headers, json={"profile": profile_data}, timeout=10)
        console.print(r.json() if r.status_code == 200 else f"Error {r.status_code}")
    except Exception as e:
        console.print(f"[red]Submit failed: {e}[/red]")


app.add_typer(wraith_app, name="wraith")


def _try_version(module_name: str, package_name: str | None = None) -> tuple[bool, str]:
    """Attempt to import a module and get its version."""
    try:
        import importlib.metadata
        pkg = package_name or module_name
        return True, importlib.metadata.version(pkg)
    except Exception:
        return False, "not installed"


def _build_doctor_checks() -> list[tuple[str, bool, str]]:
    """Collect all environment sanity checks."""
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    return [
        ("Python >= 3.10", sys.version_info >= (3, 10), py_ver),
        ("Pydantic", *_try_version("pydantic")),
        ("Typer", *_try_version("typer")),
        ("Rich", *_try_version("rich")),
        ("PyYAML", *_try_version("yaml", "pyyaml")),
        ("SQLAlchemy", *_try_version("sqlalchemy")),
        ("ast (stdlib)", True, "available"),
    ]


@app.command()
def doctor(
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Environment and configuration sanity check."""
    checks = _build_doctor_checks()

    all_ok = all(ok for _, ok, _ in checks)
    table = Table(title="Raven Doctor")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Detail")
    for name, ok, detail in checks:
        table.add_row(name, "\u2705" if ok else "\u274c", detail)
    console.print(table)

    if not all_ok:
        raise typer.Exit(code=2)


@app.command()
def version() -> None:
    """Show version and build information."""
    console.print(f"Raven (ravenscan) v{__version__}")
    console.print(f"Python {sys.version}")


@app.command()
def mark_false_positive(
    filepath: str = typer.Argument(..., help="File path of the finding"),
    line: int = typer.Argument(..., help="Line number of the finding"),
    analyzer: str = typer.Argument(..., help="Analyzer name (e.g., hardcoded_secret, missing_auth)"),
    reason: str = typer.Option("", "--reason", "-r", help="Why this is a false positive"),
    output_dir: str = typer.Option(".raven", "--output", "-o", help="Output directory"),
) -> None:
    """Mark a security finding as a false positive to suppress it in future scans."""
    from raven.memory.store import MemoryStore

    store = MemoryStore(Path(output_dir) / "history.db")
    fingerprint = f"{filepath}:{line}:{analyzer}"
    created = store.mark_false_positive(fingerprint, filepath, line, analyzer, reason)
    if created:
        console.print(f"[green]\u2713[/green] Marked as false positive: {fingerprint}")
    else:
        console.print(f"[yellow]Already marked: {fingerprint}[/yellow]")


@app.command()
def unmark_false_positive(
    filepath: str = typer.Argument(..., help="File path of the finding"),
    line: int = typer.Argument(..., help="Line number of the finding"),
    analyzer: str = typer.Argument(..., help="Analyzer name"),
    output_dir: str = typer.Option(".raven", "--output", "-o", help="Output directory"),
) -> None:
    """Remove a false-positive mark, restoring the finding in future scans."""
    from raven.memory.store import MemoryStore

    store = MemoryStore(Path(output_dir) / "history.db")
    fingerprint = f"{filepath}:{line}:{analyzer}"
    removed = store.remove_false_positive(fingerprint)
    if removed:
        console.print(f"[green]\u2713[/green] Removed false-positive mark: {fingerprint}")
    else:
        console.print(f"[yellow]No false-positive mark found: {fingerprint}[/yellow]")


@app.command()
def list_false_positives(
    output_dir: str = typer.Option(".raven", "--output", "-o", help="Output directory"),
) -> None:
    """List all marked false positives."""
    from raven.memory.store import MemoryStore

    store = MemoryStore(Path(output_dir) / "history.db")
    fps = store.get_false_positives()
    if not fps:
        console.print("[dim]No false positives recorded.[/dim]")
        return
    table = Table(title="False Positives")
    table.add_column("File")
    table.add_column("Line", justify="right")
    table.add_column("Analyzer")
    table.add_column("Reason")
    for fp in fps:
        table.add_row(str(fp["filepath"]), str(fp["line"]), str(fp["analyzer"]), str(fp.get("reason", "")))
    console.print(table)


@app.command()
def config_show(
    path: str = typer.Argument(".", help="Repository path"),
) -> None:
    """Show active configuration."""
    cfg = _build_config(Path(path), ".raven", "markdown", False, False, False)
    rows = [
        ("Path", str(cfg.path)),
        ("Output dir", str(cfg.output_dir)),
        ("Format", cfg.format),
        ("Max file size", f"{cfg.max_file_size_bytes} bytes"),
        ("Enabled phases", ", ".join(cfg.enable_phases)),
        ("Exclude patterns", ", ".join(cfg.exclude_patterns[:8])),
    ]
    table = Table(title="Configuration")
    table.add_column("Key", style="cyan")
    table.add_column("Value")
    for key, val in rows:
        table.add_row(key, val)
    console.print(table)


@app.command()
def diff(
    path: str = typer.Argument(".", help="Repository path to analyze"),
    base: Optional[str] = typer.Option(None, "--base", help="Base revision (scan ID, empty for previous)"),
    head: Optional[str] = typer.Option(None, "--head", help="Head revision (scan ID, empty for current)"),
    output_format: str = typer.Option("markdown", "--format", "-f", help="Output format: json or markdown"),
    output_dir: str = typer.Option(".raven", "--output", "-o"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    no_color: bool = typer.Option(False, "--no-color"),
) -> None:
    """Compare current state against a prior scan with semantic delta analysis.

    By default compares the current repository state against the most recent
    stored scan. Use --base and --head to compare specific historical snapshots.

    Produces architecture, security, dependency, symbol, import, route, and
    evolution deltas with confidence scoring.
    """
    import json
    cfg = _build_config(Path(path), output_dir, output_format, quiet, verbose, no_color)
    client = Raven(cfg)

    from raven.memory.store import MemoryStore
    store = MemoryStore(cfg.output_dir / "history.db")

    prev = store.latest()
    if prev is None:
        console.print("[yellow]No previous scan found in history. Run [bold]raven scan[/bold] first to establish a baseline.[/yellow]")
        raise typer.Exit(code=0)

    if not quiet:
        console.print(f"[bold]Raven[/bold] — semantic diff against scan from {prev.scanned_at}", style="cyan")

    curr_profile = client.scan()
    curr_arch = client.architecture()
    curr_sec = client.security()
    curr_score = client.score(curr_profile, curr_arch, curr_sec)

    prev_score_data = None
    if prev.score_json:
        try:
            prev_score_data = json.loads(str(prev.score_json))
        except Exception:
            pass

    prev_profile_data = None
    if prev.profile_json:
        try:
            prev_profile_data = json.loads(str(prev.profile_json))
        except Exception:
            pass

    prev_arch_data = None
    if prev.architecture_json:
        try:
            prev_arch_data = json.loads(str(prev.architecture_json))
        except Exception:
            pass

    prev_sec_data = None
    if prev.security_json:
        try:
            prev_sec_data = json.loads(str(prev.security_json))
        except Exception:
            pass

    from raven.delta.analyzers import build_delta
    delta = build_delta(
        prev_profile=prev_profile_data,
        prev_arch=prev_arch_data,
        prev_sec=prev_sec_data,
        prev_score=prev_score_data,
        curr_profile=curr_profile.model_dump(mode="json"),
        curr_arch=curr_arch.model_dump(mode="json"),
        curr_sec=curr_sec.model_dump(mode="json"),
        curr_score=curr_score.model_dump(mode="json"),
        base_ref=base or f"scan_{prev.id}",
        head_ref=head or "current",
    )

    if output_format == "json":
        import json as _json
        console.print(_json.dumps({
            "base": delta.base_revision,
            "head": delta.head_revision,
            "scanned_at": delta.scanned_at,
            "summary": delta.summary,
            "totals": {
                "changes": delta.total_changes,
                "added": delta.added,
                "removed": delta.removed,
                "modified": delta.modified,
                "high_confidence": delta.high_confidence_changes,
            },
            "changes": [
                {
                    "category": e.category.value,
                    "type": e.change_type.value,
                    "entity": e.entity,
                    "description": e.description,
                    "confidence": e.confidence,
                    "severity": e.severity,
                }
                for e in delta.entries
            ],
        }, indent=2))
        return

    table = Table(title=f"Engineering Diff — {delta.base_revision} → {delta.head_revision}")
    table.add_column("Category", style="cyan")
    table.add_column("Type")
    table.add_column("Confidence", justify="right")
    table.add_column("Change")

    for e in delta.entries[:40]:
        cat_icon = {
            "security": "\u274c",
            "architecture": "\U0001f3d7",
            "dependencies": "\U0001f4e6",
            "symbols": "\U0001f522",
            "imports": "\u27a1",
            "routes": "\U0001f310",
            "evolution": "\U0001f4c8",
        }.get(e.category.value, "\u25cf")
        type_icon = {
            "added": "[green]+[/green]",
            "removed": "[red]-[/red]",
            "modified": "[yellow]~[/yellow]",
        }.get(e.change_type.value, "?")
        conf_val = f"{e.confidence:.0%}"
        table.add_row(f"{cat_icon} {e.category.value}", type_icon, conf_val, e.description[:100])

    console.print(table)
    console.print(f"\n[bold]{delta.summary}[/bold]")

    if not quiet:
        prev_score_val = prev_score_data.get("overall") if prev_score_data else None
        curr_score_val = curr_score.overall
        if prev_score_val is not None:
            diff_val = curr_score_val - prev_score_val
            if diff_val < -2:
                console.print(f"\n[red]Score: {prev_score_val:.1f} -> {curr_score_val:.1f} ({diff_val:+.1f})[/red]")
            elif diff_val > 2:
                console.print(f"\n[green]Score: {prev_score_val:.1f} -> {curr_score_val:.1f} ({diff_val:+.1f})[/green]")
            else:
                console.print(f"\nScore: {prev_score_val:.1f} -> {curr_score_val:.1f} ({diff_val:+.1f})")


def main() -> None:
    app()


@app.command()
def graph(
    path: str = typer.Argument(".", help="Repository path to analyze"),
    output_dir: str = typer.Option(".raven", "--output", "-o", help="Output directory for diagrams"),
    graph_type: str = typer.Option("all", "--type", "-t", help="Graph type: architecture, dependencies, modules, or all"),
) -> None:
    """Generate architecture and dependency graphs.

    Produces DOT and SVG files in the output directory.
    Requires 'graphviz' Python package: pip install ravenscan[viz]
    """
    cfg = RavenConfig(path=Path(path).resolve(), output_dir=Path(output_dir), format="json")
    client = Raven(cfg)

    profile = client.scan()
    arch = client.architecture()

    from raven.reporting.graph_builder import (
        build_architecture_graph,
        build_dependency_graph,
        build_module_relationship_graph,
    )
    from raven.reporting.visualization import write_visualization

    types = ["architecture", "dependencies", "modules"] if graph_type == "all" else [graph_type]
    results: list[str] = []

    for gt in types:
        if gt not in ("architecture", "dependencies", "modules"):
            console.print(f"[red]Unknown graph type: {gt}[/red]")
            continue

        if gt == "architecture":
            g = build_architecture_graph(arch)
            paths = write_visualization(g, "ArchitectureGraph", cfg.output_dir)
        elif gt == "dependencies":
            g = build_dependency_graph(profile)
            paths = write_visualization(g, "DependencyGraph", cfg.output_dir)
        elif gt == "modules":
            g = build_module_relationship_graph(arch)
            paths = write_visualization(g, "ModuleRelationships", cfg.output_dir)
        else:
            continue

        results.extend(paths.values())

    if results:
        console.print(f"[green]\u2713[/green] Generated {len(results)} diagram(s) in {cfg.output_dir}/:")
        for r in results:
            console.print(f"  {r}")
    else:
        console.print("[yellow]No diagrams generated. Install graphviz: pip install ravenscan[viz][/yellow]")


if __name__ == "__main__":
    main()
