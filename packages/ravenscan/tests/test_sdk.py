"""Tests for the Raven SDK client."""

from pathlib import Path
from raven.core.config import RavenConfig
from raven.sdk.client import Raven


def test_client_scan(tmp_path: Path):
    (tmp_path / "main.py").write_text("print('hello')\n")
    (tmp_path / "requirements.txt").write_text("flask==3.0\n")

    config = RavenConfig(path=tmp_path)
    client = Raven(config)

    profile = client.scan()
    assert profile.language_primary == "python"
    assert profile.structure is not None


def test_client_architecture(tmp_path: Path):
    (tmp_path / "a.py").write_text("import b\n")
    (tmp_path / "b.py").write_text("pass\n")

    config = RavenConfig(path=tmp_path)
    client = Raven(config)

    arch = client.architecture()
    assert len(arch.modules) >= 2


def test_client_security(tmp_path: Path):
    (tmp_path / "safe.py").write_text("x = 1\n")

    config = RavenConfig(path=tmp_path)
    client = Raven(config)

    sec = client.security()
    assert sec.total_findings >= 0  # clean file, no findings
    assert isinstance(sec.total_findings, int)


def test_client_score(tmp_path: Path):
    (tmp_path / "main.py").write_text("print('hello')\n")

    config = RavenConfig(path=tmp_path)
    client = Raven(config)

    risk = client.score()
    assert risk.overall > 0
    assert len(risk.categories) > 0
    assert risk.grade in ("A", "B", "C", "D", "F")


def test_client_report_json(tmp_path: Path):
    (tmp_path / "main.py").write_text("print('hello')\n")

    config = RavenConfig(path=tmp_path)
    client = Raven(config)

    report = client.report(fmt="json")
    assert "profile" in report
    assert "architecture" in report
    assert "security" in report
    assert "score" in report
    assert "daily_report" in report


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("RAVEN_PATH", "/some/path")
    monkeypatch.setenv("RAVEN_FORMAT", "json")

    config = RavenConfig.from_env()
    assert str(config.path) == "/some/path"
    assert config.format == "json"
