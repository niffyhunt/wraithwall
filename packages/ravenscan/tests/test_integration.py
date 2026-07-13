"""Integration tests — end-to-end pipeline through all phases."""

from pathlib import Path
from raven import Raven
from raven.core.config import RavenConfig


def test_full_pipeline_on_flask_app(tmp_path: Path):
    """Simulate a realistic Flask application."""

    (tmp_path / "requirements.txt").write_text("flask==3.0.0\nsqlalchemy==2.0\n")
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nCOPY . /app\n")
    (tmp_path / "app.py").write_text("""import os
from flask import Flask, request
from sqlalchemy import create_engine

app = Flask(__name__)
db = create_engine(os.environ.get('DATABASE_URL', 'sqlite:///db.sqlite'))

@app.route('/health')
def health():
    return {'status': 'ok'}

@app.route('/data')
def data():
    user_input = request.args.get('id')
    result = db.execute(f"SELECT * FROM items WHERE id = {user_input}")
    return {'result': list(result)}
""")
    (tmp_path / "utils.py").write_text("""import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def helper(x):
    return x * 2
""")

    client = Raven(RavenConfig(path=tmp_path, output_dir=tmp_path / ".raven"))

    profile = client.scan()
    assert profile.language_primary == "python"
    assert profile.has_docker is True
    assert any(f.name == "Flask" for f in profile.frameworks)
    assert any(f.name == "SQLAlchemy" for f in profile.frameworks)
    assert len(profile.dependencies) >= 2

    arch = client.architecture()
    assert len(arch.modules) >= 2
    assert any(m.name in ("app", "utils") for m in arch.modules)

    sec = client.security()
    assert sec.total_findings > 0
    assert any("sql" in f.title.lower() for f in sec.findings)
    assert any("md5" in f.title.lower() for f in sec.findings)

    drift_snap = client.drift_snapshot(arch)
    assert drift_snap.total_python_files >= 2
    assert drift_snap.total_todos >= 0

    changes = client.track_changes(sec)
    assert changes.total_changes > 0, f"Total changes: {changes.total_changes}"
    assert any(c.category == "api_endpoint" for c in changes.changes)
    assert any(c.category in ("dependency", "authentication", "environment") for c in changes.changes), f"Categories: {[c.category for c in changes.changes[:10]]}"

    risk = client.score(profile, arch, sec, drift_snap)
    assert risk.overall > 0
    assert len(risk.categories) == 8
    assert risk.grade in ("A", "B", "C", "D", "F")

    daily = client.daily_report(profile, arch, sec)
    assert daily.risk_trend != "unknown"

    report = client.report(fmt="json")
    assert "profile" in report
    assert "score" in report


def test_pipeline_on_empty_repo(tmp_path: Path):
    """Should not crash on an empty directory."""
    client = Raven(RavenConfig(path=tmp_path))
    profile = client.scan()
    assert profile.language_primary == "unknown"
    assert profile.structure.total_files == 0

    arch = client.architecture()
    assert len(arch.modules) == 0
    assert len(arch.findings) == 0

    sec = client.security()
    assert sec.total_findings == 0

    drift_snap = client.drift_snapshot(arch)
    assert drift_snap is not None

    risk = client.score(profile, arch, sec, drift_snap)
    assert risk.overall > 0


def test_pipeline_handles_binary_files(tmp_path: Path):
    """Binary files should be skipped gracefully."""
    (tmp_path / "main.py").write_text("x = 1\n")
    (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100 + b"IEND\xaeB`\x82")

    client = Raven(RavenConfig(path=tmp_path))
    profile = client.scan()
    assert profile.structure.total_files >= 1
    assert profile.structure.total_python_files == 1


def test_pipeline_handles_syntax_errors(tmp_path: Path):
    """Python files with syntax errors should be parsed (not crash)."""
    (tmp_path / "broken.py").write_text("def foo(\n    x = 1\n")  # incomplete

    client = Raven(RavenConfig(path=tmp_path))
    profile = client.scan()
    assert profile.structure.total_files == 1
    assert profile.structure.total_python_files == 1

    arch = client.architecture()
    assert len(arch.modules) == 1

    sec = client.security()
    assert sec.total_findings >= 0


def test_pipeline_large_file_truncation(tmp_path: Path):
    """Files exceeding max_file_size_bytes should be skipped."""
    (tmp_path / "small.py").write_text("x = 1\n")
    (tmp_path / "huge.py").write_text("x = 1\n" * 500_000)

    client = Raven(RavenConfig(path=tmp_path, max_file_size_bytes=1024))
    profile = client.scan()
    assert profile.structure.total_files == 1, f"Expected 1 (only small.py), got {profile.structure.total_files}"
    assert profile.structure.total_python_files == 1


def test_memory_store_integration(tmp_path: Path):
    """Memory store should persist and retrieve history across scans."""
    from raven.memory.store import MemoryStore

    store = MemoryStore(tmp_path / "hist.db")
    rid = store.save(
        profile={"lang": "python"},
        architecture={"modules": 5},
        security={"findings": 3},
        score={"overall": 85.0},
        commit_sha="def456",
        branch="dev",
    )
    assert rid > 0

    latest = store.latest()
    assert latest.overall_score == 85.0
    assert latest.commit_sha == "def456"

    history = store.score_history()
    assert len(history) == 1
    assert history[0]["score"] == 85.0


def test_plugin_registry_integration(tmp_path: Path):
    """Plugin discovery should work with manually registered plugins."""
    from raven.plugins.base import RavenPlugin, PluginRegistry, PluginFindings
    from raven.core.context import RepositoryContext

    class TestPlugin(RavenPlugin):
        name = "test_integration"
        api_version = "1.0"

        def analyze(self, ctx: RepositoryContext) -> PluginFindings:
            pf = PluginFindings()
            pf.findings.append({"lang": ctx.language_primary})
            return pf

    registry = PluginRegistry()
    registry.register(TestPlugin())

    plugin = registry.get("test_integration")
    assert plugin is not None

    ctx = RepositoryContext(root=tmp_path, language_primary="python")
    result = plugin.analyze(ctx)
    assert len(result.findings) == 1
    assert result.findings[0]["lang"] == "python"
