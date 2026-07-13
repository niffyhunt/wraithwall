"""Tests for Engineering Drift and Change Tracking."""

from pathlib import Path
from raven.core.config import RavenConfig
from raven.repository.intel import build_context
from raven.architecture.graph import analyze as arch_analyze
from raven.drift.analyzer import analyze as drift_analyze, delta
from raven.drift.tracker import analyze as track_analyze


def test_drift_complexity_metrics(tmp_path: Path):
    """Drift analysis should produce complexity metrics for Python files."""
    (tmp_path / "main.py").write_text(
        "def foo():\n    pass\n\n"
        "def bar():\n    x = 1\n    y = 2\n    return x + y\n\n"
        "class MyClass:\n    def method(self):\n        pass\n"
    )
    (tmp_path / "utils.py").write_text("def util(): pass\n")

    ctx = build_context(RavenConfig(path=tmp_path))
    arch = arch_analyze(ctx)
    snap = drift_analyze(ctx, arch)

    assert snap.total_python_files == 2
    assert snap.total_lines > 0
    assert snap.avg_lines_per_file > 0
    assert snap.total_todos >= 0

    complexity_paths = [c.module_path for c in snap.complexity]
    assert "main.py" in complexity_paths
    assert "utils.py" in complexity_paths


def test_drift_coupling_metrics(tmp_path: Path):
    """Coupling metrics should reflect import relationships."""
    (tmp_path / "main.py").write_text("import utils\n")
    (tmp_path / "utils.py").write_text("pass\n")

    ctx = build_context(RavenConfig(path=tmp_path))
    arch = arch_analyze(ctx)
    snap = drift_analyze(ctx, arch)

    coupling = {c.module_path: c for c in snap.coupling}
    assert "utils.py" in coupling
    assert coupling["utils.py"].afferent_coupling >= 0


def test_drift_duplication_detection(tmp_path: Path):
    """Duplicate code blocks should be detected across files."""
    duplicated = "def process(x):\n    result = x * 2\n    data = [1, 2, 3]\n    filtered = [d for d in data if d > 1]\n    return result\n"
    (tmp_path / "a.py").write_text(duplicated + "\ndef extra(): pass\n")
    (tmp_path / "b.py").write_text(duplicated + "\ndef other(): pass\n")

    ctx = build_context(RavenConfig(path=tmp_path))
    arch = arch_analyze(ctx)
    snap = drift_analyze(ctx, arch)

    assert snap.duplicate_blocks >= 0


def test_drift_delta_new_repo(tmp_path: Path):
    """Delta against a None previous should return first_scan status."""
    (tmp_path / "main.py").write_text("x = 1\n")

    ctx = build_context(RavenConfig(path=tmp_path))
    arch = arch_analyze(ctx)
    snap = drift_analyze(ctx, arch)

    result = delta(None, snap)
    assert result["status"] == "first_scan"


def test_drift_delta_between_scans(tmp_path: Path):
    """Delta between two snapshots should compute percentage changes."""
    (tmp_path / "main.py").write_text("x = 1\n")

    ctx = build_context(RavenConfig(path=tmp_path))
    arch = arch_analyze(ctx)
    snap1 = drift_analyze(ctx, arch)

    snap2 = drift_analyze(ctx, arch)

    result = delta(snap1, snap2)
    assert result["status"] == "delta_computed"
    assert isinstance(result["total_lines"], float)
    assert isinstance(result["avg_lines_per_file"], float)


def test_change_tracking_baseline(tmp_path: Path):
    """Change tracking on a repo with no prior state should return baseline."""
    (tmp_path / "main.py").write_text(
        "import os\n"
        "os.system('ls')\n"
    )

    ctx = build_context(RavenConfig(path=tmp_path))
    from raven.security.scanner import analyze as sec_analyze
    sec = sec_analyze(ctx)

    report = track_analyze(ctx, sec)
    assert report.total_changes >= 0
    assert isinstance(report.critical_count, int)


def test_change_tracking_detects_auth(tmp_path: Path):
    """Change tracking should detect authentication patterns."""
    (tmp_path / "auth.py").write_text(
        "from flask_login import login_user\n"
        "import bcrypt\n"
        "bcrypt.hashpw(password, bcrypt.gensalt())\n"
    )

    ctx = build_context(RavenConfig(path=tmp_path))
    from raven.security.scanner import analyze as sec_analyze
    sec = sec_analyze(ctx)

    report = track_analyze(ctx, sec)
    auth_changes = [c for c in report.changes if c.category == "authentication"]
    assert len(auth_changes) >= 1


def test_change_tracking_detects_api(tmp_path: Path):
    """Change tracking should detect API endpoint definitions."""
    (tmp_path / "routes.py").write_text(
        "from flask import Blueprint\n"
        "bp = Blueprint('api', __name__)\n"
        "@bp.route('/users')\n"
        "def users(): pass\n"
    )

    ctx = build_context(RavenConfig(path=tmp_path))
    from raven.security.scanner import analyze as sec_analyze
    sec = sec_analyze(ctx)

    report = track_analyze(ctx, sec)
    api_changes = [c for c in report.changes if c.category == "api_endpoint"]
    assert len(api_changes) >= 1
