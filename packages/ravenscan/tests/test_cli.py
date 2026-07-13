"""Smoke tests for CLI commands via the SDK (Typer app testing)."""

from pathlib import Path
from typer.testing import CliRunner
from raven.cli.main import app

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "Raven" in result.stdout or "ravenscan" in result.stdout


def test_init(tmp_path: Path):
    result = runner.invoke(app, ["init", str(tmp_path)])
    assert result.exit_code == 0
    assert (tmp_path / ".raven").exists()


def test_scan_empty_dir(tmp_path: Path):
    output = tmp_path / ".raven"
    result = runner.invoke(app, ["scan", str(tmp_path), "--output", str(output), "--quiet"])
    assert result.exit_code == 0
    assert output.exists()


def test_scan_with_python_files(tmp_path: Path):
    (tmp_path / "main.py").write_text("print('hello')\n")
    output = tmp_path / ".raven"
    result = runner.invoke(app, ["scan", str(tmp_path), "--output", str(output), "--quiet"])
    assert result.exit_code == 0
    assert (output / "RepositoryProfile.md").exists()


def test_score_clean_project(tmp_path: Path):
    (tmp_path / "main.py").write_text("x = 1\n")
    result = runner.invoke(app, ["score", str(tmp_path), "--quiet"])
    assert result.exit_code == 0


def test_score_fail_under(tmp_path: Path):
    (tmp_path / "main.py").write_text("x = 1\n")
    result = runner.invoke(app, ["score", str(tmp_path), "--fail-under", "100", "--quiet"])
    # Score is likely below 100, so should fail
    assert result.exit_code == 1


def test_doctor():
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "Python" in result.stdout
    assert "Pydantic" in result.stdout


def test_config_show(tmp_path: Path):
    result = runner.invoke(app, ["config-show", str(tmp_path)])
    assert result.exit_code == 0
    assert "Configuration" in result.stdout


def test_scan_json_format(tmp_path: Path):
    (tmp_path / "main.py").write_text("print('hello')\n")
    output = tmp_path / ".raven"
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json", "--output", str(output), "--quiet"])
    assert result.exit_code == 0
    assert (output / "RepositoryProfile.json").exists()


def test_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.stdout
    assert "score" in result.stdout
    assert "doctor" in result.stdout
