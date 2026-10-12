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


def _artifact_format(fmt: str, name: str) -> str:
    """Keep non-security artifacts readable when SARIF is selected."""
    return "json" if fmt == "sarif" and name != "SecurityReport" else fmt


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


def _load_prefs(output_dir: str, disabled: bool) -> dict[str, str]:
    """R-03: read project-scoped operator preferences (inert on any failure).

    Prefs live in the project memory store, so the memory kill switch also
    silences them. Preferences never fail a scan — degraded means empty.
    """
    if disabled:
        return {}
    try:
        from raven.memory.store import MemoryStore
        return MemoryStore(Path(output_dir) / "history.db").preferences()
    except Exception:
        return {}


@app.command()
def scan(
    path: str = typer.Argument(".", help="Repository path to scan"),
    output_dir: str = typer.Option(".raven", "--output", "-o", help="Output directory for artifacts"),
    output_format: Optional[str] = typer.Option(None, "--format", "-f", help="Output format: json, markdown, or sarif (default: operator preference or markdown)"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
    include_operational: bool = typer.Option(False, "--include-operational", help="Include runtime operational health data"),
    include_wraithwall: bool = typer.Option(False, "--include-wraithwall", help="Use authorized tenant-scoped WraithWall context"),
    no_summary: bool = typer.Option(False, "--no-summary", help="Skip the RunSummary.md artifact (R-01 rollback)"),
    no_trace: bool = typer.Option(False, "--no-trace", help="Skip writing decision_trace.json (R-02 rollback)"),
    no_prefs: bool = typer.Option(False, "--no-prefs", help="Ignore operator preferences (R-03 rollback)"),
) -> None:
    """Run full analysis and write artifacts."""
    # R-03: explicit flag > operator preference > default. Prefs are inert
    # when memory is off and never override an explicit CLI flag.
    prefs = _load_prefs(output_dir, no_prefs)
    output_format = output_format or prefs.get("format") or "markdown"
    cfg = _build_config(Path(path), output_dir, output_format, quiet, verbose, no_color)

    try:
        client = Raven(cfg)

        from raven.core.trace import DecisionTrace
        from raven.core.versions import RULESET_VERSION, TEMPLATE_VERSION

        trace = DecisionTrace()
        trace.add(
            "config",
            f"phases={','.join(cfg.enable_phases)} format={output_format}",
            "startup configuration from CLI flags and operator preferences",
            {"phases": list(cfg.enable_phases), "format": output_format},
        )
        if prefs:
            trace.add(
                "preferences",
                f"applied={'+'.join(sorted(prefs))}",
                "operator preferences from project memory (explicit flags take precedence)",
                {"keys": sorted(prefs)},
            )

        if not quiet:
            console.print("[bold]Raven[/bold] — scanning repository...", style="cyan")

        _phase_status(quiet, "Phase 1: Repository Intelligence...")
        profile = client.scan()
        write_artifact(profile, "RepositoryProfile", cfg, _artifact_format(output_format, "RepositoryProfile"))
        _phase_check(
            quiet,
            f"{profile.language_primary} — {profile.structure.total_files if profile.structure else 0} files, {len(profile.dependencies)} dependencies",
        )
        trace.add(
            "repository",
            f"language={profile.language_primary}",
            "primary language detected from repository content",
            {
                "language": profile.language_primary,
                "files": profile.structure.total_files if profile.structure else 0,
            },
        )

        _phase_status(quiet, "Phase 2: Architecture Graph...")
        arch = client.architecture()
        write_artifact(arch, "ArchitectureGraph", cfg, _artifact_format(output_format, "ArchitectureGraph"))
        _phase_check(quiet, f"{len(arch.modules)} modules, {len(arch.findings)} findings")
        trace.add(
            "architecture",
            f"modules={len(arch.modules)}",
            "import graph derived from parsed sources",
            {"modules": len(arch.modules), "findings": len(arch.findings)},
        )

        _phase_status(quiet, "Phase 3: Security Intelligence...")
        sec = client.security(include_wraithwall=include_wraithwall)
        _phase_check(quiet, f"{sec.total_findings} findings ({sec.critical_count} critical, {sec.high_count} high)")
        from raven.plugins.registry import registry as security_registry
        trace.add(
            "security_plugins",
            f"analyzers={'+'.join(security_registry.list_languages()) or 'none'}",
            "registry analyzers for non-primary languages; primary scanner owns its language",
            {"languages": security_registry.list_languages(), "primary": profile.language_primary},
        )

        _phase_status(quiet, "Phase 9: Scoring...")
        risk = client.score(profile, arch, sec, include_operational=include_operational)
        write_artifact(risk, "RiskScore", cfg, _artifact_format(output_format, "RiskScore"))
        _phase_check(quiet, f"Overall: {risk.overall}/100 — Grade {risk.grade}")
        trace.add(
            "scoring",
            "weighted-risk-model",
            "deterministic scoring from profile, architecture, and security inputs",
            {"overall": risk.overall, "grade": risk.grade},
        )

        _phase_status(quiet, "Phase 7: Daily Report...")
        daily_rpt = client.daily_report(profile, arch, sec)
        if output_format != "sarif":
            write_artifact(daily_rpt, "DailyReport", cfg, output_format)
        _phase_check(quiet, f"Risk trend: {daily_rpt.risk_trend}")
        trace.add(
            "report",
            f"format={output_format}",
            "artifact format from CLI configuration",
            {"format": output_format},
        )

        from raven.memory.store import MemoryStore
        from raven.security.calibration import outcome_calibration
        from raven.utils.git import revision_metadata
        commit_sha, branch = revision_metadata(cfg.path)
        # Memory must never be able to fail a scan: unavailable or disabled ⇒
        # degraded notice + engine-only run (deliverable 6 invariant 7).
        memory_ok = True
        store = None
        try:
            store = MemoryStore(cfg.output_dir / "history.db")
            if not store.enabled:
                memory_ok = False
                if not quiet:
                    console.print("[yellow]! memory disabled — scan continues without memory reads/writes[/yellow]")
        except Exception as exc:
            memory_ok = False
            if not quiet:
                console.print(f"[yellow]! memory unavailable ({exc}) — continuing degraded[/yellow]")
        scan_id = 0
        finding_states: dict[str, int] = {}
        if memory_ok:
            try:
                prev_versions = store.latest_versions()
                change = trace.note_version_change(prev_versions)
                if change and not quiet:
                    for key, item in change.items():
                        console.print(
                            f"[yellow]! {key} version changed {item['was']} → {item['now']} "
                            "— review decision_trace.json[/yellow]"
                        )
            except Exception:
                change = {}
            try:
                scan_id = store.save(
                    profile=profile.model_dump(mode="json"),
                    architecture=arch.model_dump(mode="json"),
                    security=sec.model_dump(mode="json"),
                    score=risk.model_dump(mode="json"),
                    commit_sha=commit_sha,
                    branch=branch,
                    ruleset_version=RULESET_VERSION,
                    template_version=TEMPLATE_VERSION,
                )
                reconciled = store.reconcile_findings(sec.findings, scan_id=scan_id, commit_sha=commit_sha, branch=branch)
                for observed in reconciled:
                    state = observed.historical_state
                    finding_states[state] = finding_states.get(state, 0) + 1
                store.apply_feedback(sec.findings)
            except Exception as exc:
                memory_ok = False
                if not quiet:
                    console.print(f"[yellow]! memory write failed ({exc}) — continuing degraded[/yellow]")
        for finding in sec.findings:
            from raven.security.prioritization import prioritize_finding
            finding.priority, finding.priority_score, finding.priority_reasons = prioritize_finding(finding)
        if memory_ok:
            try:
                sec.detector_calibration = {
                    detector: outcome_calibration(detector, calibration)
                    for detector, calibration in store.detector_calibration().items()
                }
                store.update_security_snapshot(scan_id, sec.model_dump(mode="json"))
            except Exception as exc:
                if not quiet:
                    console.print(f"[yellow]! memory finalize failed ({exc}) — continuing degraded[/yellow]")
        write_artifact(sec, "SecurityReport", cfg, _artifact_format(output_format, "SecurityReport"))

        # R-02: decision trace — presence per scan, rollback via --no-trace.
        if not no_trace:
            try:
                trace.write(cfg.output_dir / "decision_trace.json")
            except Exception as exc:
                if not quiet:
                    console.print(f"[yellow]! decision trace write failed ({exc})[/yellow]")
        # R-01: run reflection — memory-derived, never written when memory is off.
        if memory_ok and scan_id and not no_summary:
            try:
                summary = store.build_run_summary(
                    scan_id,
                    commit_sha=commit_sha,
                    branch=branch,
                    finding_states=finding_states,
                    total_findings=sec.total_findings,
                    critical=sec.critical_count,
                    high=sec.high_count,
                    ruleset_version=RULESET_VERSION,
                    template_version=TEMPLATE_VERSION,
                )
                if summary is not None:
                    from raven.reporting.renderers.run_summary import render_run_summary
                    (cfg.output_dir / "RunSummary.md").write_text(
                        render_run_summary(summary), encoding="utf-8"
                    )
            except Exception as exc:
                if not quiet:
                    console.print(f"[yellow]! run summary write failed ({exc}) — continuing[/yellow]")

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
    if output_format in ("json", "sarif"):
        pattern = "*.sarif.json" if output_format == "sarif" else "*.json"
        artifacts = sorted(od.glob(pattern))
        for a in artifacts:
            console.print(a.read_text())
            console.print()
    else:
        md = sorted(od.glob("*.md"))
        for a in md:
            console.print(a.read_text())
            console.print()
    if not (list(od.glob("*.json")) or list(od.glob("*.sarif.json")) or list(od.glob("*.md"))):
        console.print("[yellow]No artifacts found.[/yellow] Run [bold]raven scan[/bold] first.")


@app.command()
def score(
    path: str = typer.Argument(".", help="Repository path to analyze"),
    fail_under: Optional[float] = typer.Option(None, "--fail-under", help="Exit code 1 if overall score < N"),
    output_format: Optional[str] = typer.Option(None, "--format", "-f", help="Output format: json, markdown, or sarif (default: operator preference or markdown)"),
    output_dir: str = typer.Option(".raven", "--output", "-o"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    no_color: bool = typer.Option(False, "--no-color"),
    include_operational: bool = typer.Option(False, "--include-operational", help="Include runtime operational health in score"),
    include_wraithwall: bool = typer.Option(False, "--include-wraithwall", help="Use authorized tenant-scoped WraithWall context"),
    no_prefs: bool = typer.Option(False, "--no-prefs", help="Ignore operator preferences (R-03 rollback)"),
) -> None:
    """Compute repository risk score (CI gate)."""
    # R-03: --fail-under flag > operator preference > no gate.
    prefs = _load_prefs(output_dir, no_prefs)
    if fail_under is None and "fail_under" in prefs:
        fail_under = float(prefs["fail_under"])
    output_format = output_format or prefs.get("format") or "markdown"
    cfg = _build_config(Path(path), output_dir, output_format, quiet, verbose, no_color)
    client = Raven(cfg)

    if not quiet:
        console.print("[bold]Raven[/bold] — computing risk score...", style="cyan")

    profile = client.scan()
    arch = client.architecture()
    sec = client.security(include_wraithwall=include_wraithwall)
    risk = client.score(profile, arch, sec, include_operational=include_operational)

    if output_format == "sarif":
        raise typer.BadParameter("SARIF output is only supported for `scan --format sarif` SecurityReport artifacts")
    write_artifact(risk, "RiskScore", cfg, output_format)

    table = Table(title=f"Risk Score — {risk.grade}")
    table.add_column("Category", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("Health", justify="center")
    for c in risk.categories:
        table.add_row(c.category.value, f"{c.score:.1f}/100", _emoji_for_score(c.score))
    table.add_row("[bold]OVERALL[/bold]", f"[bold]{risk.overall:.1f}/100[/bold]", "")
    console.print(table)

    # Deterministic CI intelligence: report whether the gate is evaluating
    # existing state or a newly observed/regressed finding. Legacy exit codes
    # remain unchanged.
    if fail_under is not None and risk.overall < fail_under:
        console.print(f"\n[red]Score {risk.overall:.1f} is below threshold {fail_under}[/red]")
        raise typer.Exit(code=1)


# --- WraithWall Connected Mode (official CLI integration) ---
wraith_app = typer.Typer(help="WraithWall connected commands (requires running WraithWall instance)")

@wraith_app.command()
def whoami(
    base_url: str = typer.Option("https://wraithwall.online", "--url"),
    api_key: Optional[str] = typer.Option(None, "--api-key", envvar="WRAITH_API_KEY"),
    api_secret: Optional[str] = typer.Option(None, "--api-secret", envvar="WRAITH_API_SECRET"),
    tenant_id: Optional[str] = typer.Option(None, "--tenant-id", envvar="WRAITH_TENANT_ID"),
):
    """Check connected tenant identity through the hardened client."""
    from raven.wraithwall.client import WraithWallIntelClient, WraithWallIntelError
    try:
        console.print(WraithWallIntelClient(base_url, api_key, api_secret, tenant_id).whoami())
    except WraithWallIntelError as exc:
        console.print(f"[red]WraithWall unavailable: {exc}[/red]")

@wraith_app.command()
def campaigns(
    base_url: str = typer.Option("https://wraithwall.online", "--url"),
    api_key: Optional[str] = typer.Option(None, "--api-key", envvar="WRAITH_API_KEY"),
    api_secret: Optional[str] = typer.Option(None, "--api-secret", envvar="WRAITH_API_SECRET"),
    tenant_id: Optional[str] = typer.Option(None, "--tenant-id", envvar="WRAITH_TENANT_ID"),
):
    """List tenant-scoped campaigns through the hardened client."""
    from raven.wraithwall.client import WraithWallIntelClient, WraithWallIntelError
    try:
        campaigns_data = WraithWallIntelClient(base_url, api_key, api_secret, tenant_id).campaigns()
        console.print(f"Active campaigns: {len(campaigns_data)}")
        for campaign in campaigns_data[:5]:
            console.print(f"  - {campaign.get('campaign_id', campaign.get('id', 'unknown'))}")
    except WraithWallIntelError as exc:
        console.print(f"[red]WraithWall unavailable: {exc}[/red]")

@wraith_app.command()
def submit(
    path: str = typer.Argument(".", help="Path to scan and submit"),
    base_url: str = typer.Option("https://wraithwall.online", "--url", help="WraithWall base URL (use https://wraithwall.online for remote)"),
    api_key: Optional[str] = typer.Option(None, "--api-key", envvar="WRAITH_API_KEY", help="API key for auth (for remote use)"),
    api_secret: Optional[str] = typer.Option(None, "--api-secret", envvar="WRAITH_API_SECRET", help="API secret for auth"),
    tenant_id: Optional[str] = typer.Option(None, "--tenant-id", envvar="WRAITH_TENANT_ID"),
):
    """Scan locally and submit only through an explicitly allowed HTTPS endpoint."""
    from raven.wraithwall.client import WraithWallIntelClient, WraithWallIntelError
    if not base_url.startswith("https://"):
        console.print("[red]Submit requires HTTPS[/red]")
        raise typer.Exit(code=2)
    cfg = _build_config(Path(path), ".raven", "json", True, False, False)
    profile = Raven(cfg).scan()
    try:
        client = WraithWallIntelClient(base_url, api_key, api_secret, tenant_id)
        console.print(client.submit_scan(profile.model_dump(mode="json")))
    except WraithWallIntelError as exc:
        console.print(f"[red]Submit failed: {exc}[/red]")


app.add_typer(wraith_app, name="wraith")


# ---------------------------------------------------------------------------
# Device login — authenticate in the browser, continue in the terminal.
# Credentials land in ~/.raven/credentials.json (0600) and are picked up by
# the WraithWall client when env vars are absent; env vars still win.

@app.command()
def login(
    url: str = typer.Option("https://wraithwall.online", "--url", help="WraithWall base URL (HTTPS, allowlisted)"),
    no_browser: bool = typer.Option(False, "--no-browser", help="Print the URL instead of opening a browser"),
) -> None:
    """Link this terminal to your WraithWall account (no API keys to copy)."""
    import webbrowser
    from raven.wraithwall.login import DeviceLoginError, device_login, save_credentials
    opener = None if no_browser else (lambda u: webbrowser.open(u))
    try:
        creds = device_login(url, open_browser=opener)
    except DeviceLoginError as exc:
        console.print(f"[red]✗ login failed:[/red] {exc}")
        raise typer.Exit(code=1)
    path = save_credentials(creds)
    console.print(f"[green]✓ logged in[/green] — credentials stored at {path} (mode 600)")
    console.print(f"  tenant: {creds['tenant_id']}  key: {creds['api_key'][:12]}…")
    console.print("  Secret is not shown again. Revoke anytime from the console, or run [bold]raven logout[/bold].")


@app.command()
def logout() -> None:
    """Remove locally stored WraithWall credentials."""
    from raven.wraithwall.login import DeviceLoginError, logout as _logout
    try:
        removed = _logout()
    except DeviceLoginError as exc:
        console.print(f"[red]✗ logout failed:[/red] {exc}")
        raise typer.Exit(code=1)
    if removed:
        console.print("[green]✓ logged out[/green] — local credentials removed")
    else:
        console.print("No stored credentials (nothing to do).")


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


# ---------------------------------------------------------------------------
# R-09: operator memory controls — see / correct / delete / disable / export
# Everything below writes through MemoryGate inside MemoryStore; the CLI only
# presents results and surfaces gate refusals verbatim (reason codes, not text).

memory_app = typer.Typer(help="Review, correct, delete, disable, and export RavenScan memory.")
app.add_typer(memory_app, name="memory")


def _memory_store(output_dir: str):
    from raven.memory.store import MemoryStore
    return MemoryStore(Path(output_dir) / "history.db")


def _refuse(exc) -> None:
    from raven.memory import gate
    assert isinstance(exc, gate.GateRejected)
    console.print(f"[red]✗ write refused by MemoryGate:[/red] {exc.reason_code}")
    raise typer.Exit(code=1)


@memory_app.command("list")
def memory_list(
    output_dir: str = typer.Option(".raven", "--output", "-o", help="Output directory"),
) -> None:
    """See what RavenScan remembers — typed listing with provenance."""
    store = _memory_store(output_dir)
    console.print(f"[bold]Scope:[/bold] {store.scope}")
    console.print(f"[bold]State:[/bold] {'enabled' if store.enabled else 'DISABLED (reads fail closed)'}")
    fps = store.get_false_positives()
    outcomes = store.list_detector_outcomes()
    if not fps and not outcomes:
        console.print("No memory records.")
        return
    if fps:
        console.print(f"\n[bold]VERIFIED_EVIDENCE — false positives ({len(fps)}):[/bold]")
        for rec in fps:
            console.print(
                f"  {rec['fingerprint']} — reason={rec['reason']!r} "
                f"marked={rec['marked_at']} source={rec['source']}"
            )
    if outcomes:
        console.print(f"\n[bold]VERIFIED_EVIDENCE — detector outcomes ({len(outcomes)}):[/bold]")
        for rec in outcomes[:20]:
            console.print(
                f"  #{rec['id']} {rec['detector']} → {rec['outcome']} "
                f"finding={rec['finding_id']} at={rec['recorded_at']}"
            )


@memory_app.command("show")
def memory_show(
    ref: str = typer.Argument(..., help="False-positive fingerprint or outcome #id"),
    output_dir: str = typer.Option(".raven", "--output", "-o", help="Output directory"),
) -> None:
    """Show one record with source, timestamp, scope, and its audit entries."""
    store = _memory_store(output_dir)
    fp = next((r for r in store.get_false_positives(include_deleted=True) if r["fingerprint"] == ref), None)
    if fp is not None:
        console.print(f"[bold]false_positive[/bold] {fp['fingerprint']}")
        for key in ("filepath", "line", "analyzer", "reason", "marked_at", "deleted_at", "scope", "source"):
            console.print(f"  {key}: {fp[key]}")
        rows = [r for r in store.audit_log(limit=200) if r["record_ref"] == ref]
        for row in rows:
            console.print(f"  audit #{row['id']} {row['ts']} {row['action']} {row['reason_code'] or ''}")
        return
    if ref.startswith("#") and ref[1:].isdigit():
        wanted = int(ref[1:])
        outcome = next((r for r in store.list_detector_outcomes() if r["id"] == wanted), None)
        if outcome is not None:
            console.print(f"[bold]detector_outcome[/bold] #{outcome['id']}")
            for key in ("detector", "outcome", "finding_id", "reason", "recorded_at"):
                console.print(f"  {key}: {outcome[key]}")
            console.print(f"  scope: {store.scope}  source: operator")
            return
    console.print(f"[yellow]No memory record for {ref!r}[/yellow]")
    raise typer.Exit(code=1)


@memory_app.command("edit")
def memory_edit(
    fingerprint: str = typer.Argument(..., help="False-positive fingerprint to correct"),
    reason: str = typer.Option(..., "--reason", "-r", help="Corrected reason (audited, before/after hashed)"),
    output_dir: str = typer.Option(".raven", "--output", "-o", help="Output directory"),
) -> None:
    """Correct a memory entry — the change is audited, rollback stays possible."""
    from raven.memory import gate
    store = _memory_store(output_dir)
    try:
        ok = store.edit_false_positive(fingerprint, reason=reason)
    except gate.GateRejected as exc:
        _refuse(exc)
        return
    if ok:
        console.print(f"[green]✓ corrected {fingerprint}[/green]")
    else:
        console.print(f"[yellow]No active record for {fingerprint} (missing or tombstoned)[/yellow]")
        raise typer.Exit(code=1)


@memory_app.command("delete")
def memory_delete(
    fingerprint: str = typer.Argument(..., help="False-positive fingerprint to delete"),
    hard: bool = typer.Option(False, "--hard", help="Purge a tombstoned entry (soft delete must come first)"),
    output_dir: str = typer.Option(".raven", "--output", "-o", help="Output directory"),
) -> None:
    """Delete a memory entry: soft tombstone by default, audited either way."""
    from raven.memory import gate
    store = _memory_store(output_dir)
    try:
        ok = store.remove_false_positive(fingerprint, hard=hard)
    except gate.GateRejected as exc:
        _refuse(exc)
        return
    if ok:
        console.print(f"[green]✓ {'purged' if hard else 'tombstoned'} {fingerprint}[/green]")
    else:
        console.print(f"[yellow]Not deleted ({'missing' if not hard else 'missing or not tombstoned yet'})[/yellow]")
        raise typer.Exit(code=1)


@memory_app.command("verify")
def memory_verify(
    finding_id: str = typer.Argument(..., help="Stable finding identity"),
    detector: str = typer.Option(..., "--detector", "-d", help="Detector name"),
    state: str = typer.Option("verified", "--state", help="verified (confirmed) or unverified (unresolved)"),
    reason: str = typer.Option("", "--reason", "-r", help="Why"),
    output_dir: str = typer.Option(".raven", "--output", "-o", help="Output directory"),
) -> None:
    """Mark a fact verified/unverified — explicit state, never inferred."""
    from raven.memory import gate
    outcome = {"verified": "confirmed", "unverified": "unresolved"}.get(state)
    if outcome is None:
        console.print("[red]--state must be verified or unverified[/red]")
        raise typer.Exit(code=2)
    store = _memory_store(output_dir)
    try:
        store.record_detector_outcome(detector, outcome, finding_id=finding_id, reason=reason)
    except gate.GateRejected as exc:
        _refuse(exc)
        return
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"[green]✓ {finding_id} marked {state}[/green]")


@memory_app.command("disable")
def memory_disable(
    output_dir: str = typer.Option(".raven", "--output", "-o", help="Output directory"),
) -> None:
    """Kill switch: reads fail closed, writes refuse; engine runs degraded."""
    store = _memory_store(output_dir)
    store.disable()
    console.print("[yellow]✗ memory disabled for this project (audited).[/yellow] Re-enable: raven memory enable")


@memory_app.command("enable")
def memory_enable(
    output_dir: str = typer.Option(".raven", "--output", "-o", help="Output directory"),
) -> None:
    """Re-enable memory (blocked while the RAVEN_MEMORY env kill switch is set)."""
    store = _memory_store(output_dir)
    if store.enable():
        console.print("[green]✓ memory enabled[/green]")
    else:
        console.print("[yellow]still disabled — RAVEN_MEMORY env kill switch is active[/yellow]")
        raise typer.Exit(code=1)


@memory_app.command("export")
def memory_export(
    output: str = typer.Option("", "--output", "-o", help="Write JSON to this file (default: stdout)"),
    output_dir: str = typer.Option(".raven", "--output-dir", help="Output directory"),
) -> None:
    """Export memory as class-labeled JSON; secrets are impossible by construction."""
    import json as _json
    from raven.memory import gate
    store = _memory_store(output_dir)
    try:
        payload = store.export_memory()
    except gate.GateRejected as exc:
        _refuse(exc)
        return
    text = _json.dumps(payload, indent=2, sort_keys=True)
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
        console.print(f"[green]✓ exported to {output}[/green]")
    else:
        console.print(text, markup=False, highlight=False)


@memory_app.command("audit")
def memory_audit(
    limit: int = typer.Option(20, "--limit", "-n", help="Rows to show (newest first)"),
    verify: bool = typer.Option(False, "--verify", help="Recompute record hashes vs audit chain"),
    output_dir: str = typer.Option(".raven", "--output", "-o", help="Output directory"),
) -> None:
    """Show the audit chain; --verify flags tampered records by hash mismatch."""
    store = _memory_store(output_dir)
    rows = store.audit_log(limit=limit)
    if not rows:
        console.print("Audit chain empty.")
    for row in rows:
        console.print(
            f"  #{row['id']} {row['ts']} {row['action']:<8} {row['record_type']:<18} "
            f"{row['record_ref'] or '-'} {row['reason_code'] or ''}"
        )
    if verify:
        mismatches = store.verify_integrity()
        if mismatches:
            for item in mismatches:
                console.print(f"[red]✗ TAMPERED:[/red] {item['fingerprint']}")
            raise typer.Exit(code=1)
        console.print("[green]✓ integrity: all active records match their audit hashes[/green]")


# ---------------------------------------------------------------------------
# R-03: project-scoped operator preferences — set once per project.
# Explicit key/value only; keys are allow-listed in the store; policy keys
# (kill switch, scope, phases, gate) are never preference-addressable.

prefs_app = typer.Typer(help="Set once per project: format and fail_under preferences.")
app.add_typer(prefs_app, name="prefs")


@prefs_app.command("list")
def prefs_list(
    output_dir: str = typer.Option(".raven", "--output", "-o", help="Output directory"),
) -> None:
    """List operator preferences for this project scope."""
    store = _memory_store(output_dir)
    prefs = store.preferences()
    console.print(f"[bold]Scope:[/bold] {store.scope}")
    if not prefs:
        console.print("No preferences set (defaults apply).")
        return
    for key, value in prefs.items():
        console.print(f"  {key} = {value}")


@prefs_app.command("set")
def prefs_set(
    key: str = typer.Argument(..., help="Preference key: format or fail_under"),
    value: str = typer.Argument(..., help="Preference value"),
    output_dir: str = typer.Option(".raven", "--output", "-o", help="Output directory"),
) -> None:
    """Set a project preference (audited; explicit CLI flags still win)."""
    from raven.memory import gate
    store = _memory_store(output_dir)
    try:
        store.set_preference(key, value)
    except gate.GateRejected as exc:
        _refuse(exc)
        return
    except ValueError as exc:
        console.print(f"[red]✗ invalid value:[/red] {exc}")
        raise typer.Exit(code=2)
    console.print(f"[green]✓ {key} = {value}[/green] (scoped to {store.scope})")


@prefs_app.command("unset")
def prefs_unset(
    key: str = typer.Argument(..., help="Preference key to remove"),
    output_dir: str = typer.Option(".raven", "--output", "-o", help="Output directory"),
) -> None:
    """Remove a project preference (rollback is first-class)."""
    from raven.memory import gate
    store = _memory_store(output_dir)
    try:
        ok = store.unset_preference(key)
    except gate.GateRejected as exc:
        _refuse(exc)
        return
    if ok:
        console.print(f"[green]✓ removed {key}[/green]")
    else:
        console.print(f"[yellow]No preference stored for {key}[/yellow]")
        raise typer.Exit(code=1)


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
    from raven.memory import gate
    from raven.memory.store import MemoryStore

    store = MemoryStore(Path(output_dir) / "history.db")
    fingerprint = f"{filepath}:{line}:{analyzer}"
    try:
        created = store.mark_false_positive(fingerprint, filepath, line, analyzer, reason)
    except gate.GateRejected as exc:
        console.print(f"[red]✗ refused by MemoryGate:[/red] {exc.reason_code}")
        raise typer.Exit(code=1)
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
    from raven.memory import gate
    from raven.memory.store import MemoryStore

    store = MemoryStore(Path(output_dir) / "history.db")
    fingerprint = f"{filepath}:{line}:{analyzer}"
    try:
        removed = store.remove_false_positive(fingerprint)
    except gate.GateRejected as exc:
        console.print(f"[red]✗ refused by MemoryGate:[/red] {exc.reason_code}")
        raise typer.Exit(code=1)
    if removed:
        console.print(f"[green]\u2713[/green] Removed false-positive mark: {fingerprint}")
    else:
        console.print(f"[yellow]No false-positive mark found: {fingerprint}[/yellow]")


@app.command()
def record_feedback(
    finding_id: str = typer.Argument(..., help="Stable Raven finding identity"),
    detector: str = typer.Argument(..., help="Detector or analyzer name"),
    outcome: str = typer.Argument(..., help="confirmed, false_positive, accepted_risk, unresolved, recurring, fixed, or reintroduced"),
    reason: str = typer.Option("", "--reason", "-r", help="Reason for the outcome"),
    output_dir: str = typer.Option(".raven", "--output", "-o", help="Output directory"),
) -> None:
    """Record auditable developer feedback without suppressing a finding."""
    from raven.memory.store import MemoryStore

    store = MemoryStore(Path(output_dir) / "history.db")
    try:
        store.record_detector_outcome(detector, outcome, finding_id=finding_id, reason=reason)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"[green]Recorded {outcome} for {finding_id}[/green]")


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
    output_format: str = typer.Option("markdown", "--format", "-f", help="Output format: json, markdown, or sarif"),
    output_dir: str = typer.Option(".raven", "--output", "-o"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    no_color: bool = typer.Option(False, "--no-color"),
    include_wraithwall: bool = typer.Option(False, "--include-wraithwall", help="Use authorized tenant-scoped WraithWall context"),
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
    curr_sec = client.security(include_wraithwall=include_wraithwall)
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
                "change_risk": delta.change_risk,
                "risk_reasons": delta.risk_reasons,
                "security_summary": delta.security_summary,
                "score_delta": delta.score_delta,
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
    console.print(f"Change risk: {delta.change_risk:.1f}/100")
    if delta.score_delta is not None:
        console.print(f"Security score delta: {delta.score_delta:+.1f}")

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
def changes(
    base: Optional[int] = typer.Option(None, "--base", help="Base scan ID (default: previous scan)"),
    head: Optional[int] = typer.Option(None, "--head", help="Head scan ID (default: latest scan)"),
    output_format: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown or json"),
    output_dir: str = typer.Option(".raven", "--output", "-o"),
) -> None:
    """Show what changed since the last run — new/resolved/recurring findings.

    R-04: deterministic comparison of two stored scans (same stored rows ⇒
    same output). Reads memory only; never re-scans the repository.
    """
    import json as _json
    store = _memory_store(output_dir)
    if not store.enabled:
        console.print("[yellow]Memory disabled — no comparison available (reads fail closed).[/yellow]")
        raise typer.Exit(code=1)
    comparison = store.compare_scans(base_id=base, head_id=head)
    if comparison is None:
        console.print("[yellow]Need two stored scans to compare. Run [bold]raven scan[/bold] at least twice.[/yellow]")
        raise typer.Exit(code=0)
    if output_format == "json":
        console.print(_json.dumps(comparison, indent=2, sort_keys=True))
        return
    from raven.reporting.renderers.changes import render_changes
    console.print(render_changes(comparison), markup=False)


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
