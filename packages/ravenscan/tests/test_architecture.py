"""Tests for Phase 2 — Architecture Graph."""

from pathlib import Path
from raven.core.config import RavenConfig
from raven.repository.intel import build_context
from raven.architecture.graph import analyze


def test_detect_circular_import(tmp_path: Path):
    """Detect a circular dependency between two modules."""
    (tmp_path / "a.py").write_text("import b\n")
    (tmp_path / "b.py").write_text("import a\n")

    config = RavenConfig(path=tmp_path)
    ctx = build_context(config)
    arch = analyze(ctx)

    circular = arch.circular_imports
    assert len(circular) >= 1
    finding = circular[0]
    assert finding.category == "circular_import"
    assert "a" in str(finding.affected_files) or "b" in str(finding.affected_files)


def test_detect_god_module(tmp_path: Path):
    """Module with > GOD_MODULE_LINES lines should be flagged."""
    lines = ["def func_{}(): pass\n".format(i) for i in range(3001)]
    (tmp_path / "big_module.py").write_text("".join(lines))

    config = RavenConfig(path=tmp_path)
    ctx = build_context(config)
    arch = analyze(ctx)

    god = arch.god_modules
    assert len(god) >= 1
    assert any("big_module" in f.title for f in god)


def test_module_graph(tmp_path: Path):
    """Modules should capture import relationships."""
    (tmp_path / "main.py").write_text("import utils\nfrom helpers import helper\n")
    (tmp_path / "utils.py").write_text("def util(): pass\n")
    (tmp_path / "helpers.py").write_text("def helper(): pass\n")

    config = RavenConfig(path=tmp_path)
    ctx = build_context(config)
    arch = analyze(ctx)

    mod_map = {m.name: m for m in arch.modules}
    assert "main" in mod_map
    assert "utils" in mod_map
    assert "helpers" in mod_map

    main_mod = mod_map["main"]
    assert "utils" in main_mod.imports
    # helpers.py contains "helper" function, "from helpers import helper"
    assert "helpers" in main_mod.imports

    # utils should be imported_by main
    utils_mod = mod_map["utils"]
    assert "main" in utils_mod.imported_by


def test_no_circular_in_clean_project(tmp_path: Path):
    """A clean DAG should produce no circular import findings."""
    (tmp_path / "main.py").write_text("import utils\nimport models\n")
    (tmp_path / "utils.py").write_text("import models\n")
    (tmp_path / "models.py").write_text("pass\n")

    config = RavenConfig(path=tmp_path)
    ctx = build_context(config)
    arch = analyze(ctx)

    assert len(arch.circular_imports) == 0
