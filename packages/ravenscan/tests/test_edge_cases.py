"""Edge case tests — boundary conditions, error handling, corner cases."""

from pathlib import Path
from raven.core.config import RavenConfig
from raven.core.errors import ConfigError, AnalysisError, ThresholdError
from raven.repository.intel import build_context
from raven.architecture.graph import analyze as arch_analyze
from raven.security.scanner import analyze as sec_analyze
from raven.drift.analyzer import analyze as drift_analyze, delta
from raven.drift.tracker import analyze as track_analyze
from raven.sdk.client import Raven


def test_config_path_normalization(tmp_path: Path):
    """Config should accept string paths and normalize them."""
    cfg = RavenConfig(path=str(tmp_path))
    assert isinstance(cfg.path, Path)
    assert cfg.path == tmp_path.resolve()


def test_config_defaults():
    """Default config should have sensible values."""
    cfg = RavenConfig()
    assert cfg.format == "markdown"
    assert cfg.max_file_size_bytes == 2 * 1024 * 1024
    assert cfg.fail_under is None
    assert cfg.quiet is False
    assert len(cfg.exclude_patterns) > 5
    assert ".git" in cfg.exclude_patterns


def test_security_report_only_counts_critical(tmp_path: Path):
    """SecurityReport with only critical findings should have correct counts."""
    (tmp_path / "danger.py").write_text("API_KEY = 'xj4Kp9mN2vL8qW5yR3aF7hB1cE0dG6'\n")
    ctx = build_context(RavenConfig(path=tmp_path))
    report = sec_analyze(ctx)
    assert report.critical_count >= 1
    assert report.high_count >= 0
    assert report.total_findings == report.critical_count + report.high_count + report.medium_count + report.low_count + report.info_count


def test_architecture_graph_with_no_imports(tmp_path: Path):
    """Modules with no imports should still appear in the graph."""
    (tmp_path / "a.py").write_text("print('hello')\n")
    (tmp_path / "b.py").write_text("x = 1\n")
    ctx = build_context(RavenConfig(path=tmp_path))
    arch = arch_analyze(ctx)
    assert len(arch.modules) == 2
    for m in arch.modules:
        assert isinstance(m.name, str)
        assert isinstance(m.lines, int)


def test_drift_delta_zero_lines(tmp_path: Path):
    """Delta should handle zero-line previous state."""
    (tmp_path / "main.py").write_text("x = 1\n")
    ctx = build_context(RavenConfig(path=tmp_path))
    arch = arch_analyze(ctx)

    import datetime
    from raven.drift.analyzer import DriftSnapshot

    prev = DriftSnapshot(
        scanned_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        total_files=0, total_lines=0, total_python_files=0,
    )
    current = drift_analyze(ctx, arch)
    result = delta(prev, current)
    assert result["status"] == "delta_computed"
    assert result["total_lines"] == 100.0  # from 0 to N = 100%


def test_drift_empty_coupling(tmp_path: Path):
    """Coupling metrics should handle empty module list."""
    (tmp_path / "main.py").write_text("x = 1\n")
    ctx = build_context(RavenConfig(path=tmp_path))
    arch = arch_analyze(ctx)
    snap = drift_analyze(ctx, arch)
    assert snap.avg_instability >= 0.0


def test_tracker_empty_files(tmp_path: Path):
    """Change tracker should not crash on zero files."""
    import datetime
    from raven.drift.tracker import ChangeReport

    report = ChangeReport(
        scanned_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        revision="empty",
    )
    assert report.total_changes == 0
    assert report.critical_count == 0


def test_tracked_change_defaults():
    """TrackedChange should have sensible defaults."""
    from raven.drift.tracker import TrackedChange
    from raven.core.models import Severity

    tc = TrackedChange(
        category="test",
        title="test change",
        description="test",
        severity=Severity.INFO,
        evidence="none",
    )
    assert tc.confidence == 1.0
    assert tc.affected_files == []
    assert tc.recommendation == ""


def test_operational_health_anomaly_none(tmp_path: Path):
    """Operational health should handle None config path."""
    from raven.operational.inspector import analyze
    health = analyze()
    assert health.scanned_at is not None
    assert health.overall_status in ("healthy", "unknown", "degraded", "warning")


def test_errors_exit_codes():
    """Error types should have correct exit codes."""
    assert ConfigError().exit_code == 3
    assert AnalysisError().exit_code == 2
    assert ThresholdError().exit_code == 1


def test_errors_with_message():
    """Errors should support messages."""
    err = ConfigError("Missing SECRET_KEY")
    assert str(err) == "Missing SECRET_KEY"
    assert err.exit_code == 3


def test_parsed_file_attributes():
    """ParsedFile should have correct attributes for Python files."""
    from raven.core.context import ParsedFile
    import ast

    pf = ParsedFile(
        path=Path("/test/main.py"),
        relative_path="main.py",
        language="python",
        content="def foo(): pass\n",
        lines=["def foo(): pass", ""],
    )
    assert pf.ast_tree is None  # not parsed automatically
    pf.ast_tree = ast.parse(pf.content)
    assert pf.ast_tree is not None
    assert pf.size_bytes == 0
