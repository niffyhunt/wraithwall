"""Tests for Phase 1 — Repository Intelligence."""

import textwrap
from pathlib import Path
from raven.core.config import RavenConfig
from raven.repository.intel import build_context, analyze


def test_build_context_python_project(tmp_path: Path):
    """Build context for a minimal Python project."""
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\nrequests>=2.28\n")
    (tmp_path / "app.py").write_text("import flask\napp = flask.Flask(__name__)\n")
    (tmp_path / "utils.py").write_text("def helper():\n    pass\n")
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\n")

    config = RavenConfig(path=tmp_path)
    ctx = build_context(config)

    assert ctx.language_primary == "python"
    assert ctx.total_files >= 3
    assert ctx.total_python_files >= 2
    assert ctx.has_docker is True
    assert len(ctx.dependencies) >= 2
    assert any(d.name == "flask" for d in ctx.dependencies)
    assert any(d.name == "requests" for d in ctx.dependencies)


def test_analyze_returns_profile(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("pydantic==2.5.0\n")
    (tmp_path / "main.py").write_text("print('hello')\n")

    config = RavenConfig(path=tmp_path)
    profile = analyze(config)

    assert profile.schema_version == "1"
    assert profile.language_primary == "python"
    assert profile.structure is not None
    assert profile.structure.total_files >= 1
    assert len(profile.dependencies) >= 1


def test_exclude_patterns(tmp_path: Path):
    """Excluded directories should be skipped."""
    (tmp_path / "main.py").write_text("x = 1\n")
    venv_dir = tmp_path / ".venv"
    venv_dir.mkdir()
    (venv_dir / "ignored.py").write_text("y = 2\n")
    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    (node_modules / "lib.js").write_text("// ignored\n")

    config = RavenConfig(path=tmp_path)
    ctx = build_context(config)

    assert any(f.relative_path == "main.py" for f in ctx.files)
    assert not any(".venv" in f.relative_path for f in ctx.files)
    assert not any("node_modules" in f.relative_path for f in ctx.files)


def test_detect_frameworks(tmp_path: Path):
    """Framework detection from dependencies."""
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\nsqlalchemy==2.0\n")
    (tmp_path / "app.py").write_text("from flask import Flask\nfrom sqlalchemy import create_engine\n")

    config = RavenConfig(path=tmp_path)
    ctx = build_context(config)

    assert "Flask" in ctx.frameworks
    assert "SQLAlchemy" in ctx.frameworks


def test_pyproject_toml_deps(tmp_path: Path):
    """Parse dependencies from pyproject.toml."""
    (tmp_path / "pyproject.toml").write_text(
        textwrap.dedent("""\
        [project]
        name = "test"
        dependencies = [
            "fastapi>=0.100",
            "uvicorn[standard]>=0.23",
        ]
        [project.optional-dependencies]
        dev = ["pytest>=7"]
        """)
    )
    (tmp_path / "src" / "test").mkdir(parents=True)
    (tmp_path / "src" / "test" / "__init__.py").write_text("")

    config = RavenConfig(path=tmp_path)
    ctx = build_context(config)

    names = {d.name for d in ctx.dependencies}
    assert "fastapi" in names
    assert "uvicorn" in names


def test_detect_docker_ci(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\n")
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("name: CI\n")

    config = RavenConfig(path=tmp_path)
    ctx = build_context(config)

    assert ctx.has_docker is True
    assert ctx.has_ci is True
    assert ctx.ci_provider == "GitHub Actions"
