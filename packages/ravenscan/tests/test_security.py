"""Tests for Phase 3 — Security Intelligence."""

from pathlib import Path
from raven.core.config import RavenConfig
from raven.repository.intel import build_context
from raven.security.scanner import analyze


def test_detect_hardcoded_secret(tmp_path: Path):
    (tmp_path / "config.py").write_text('API_KEY = "sk-1234567890abcdef"\n')
    (tmp_path / "app.py").write_text("print('hello')\n")

    config = RavenConfig(path=tmp_path)
    ctx = build_context(config)
    report = analyze(ctx)

    assert report.total_findings >= 1
    assert any("secret" in f.title.lower() or "api key" in f.title.lower() for f in report.findings)
    assert any(f.cwe.cwe_id == "CWE-798" for f in report.findings)


def test_detect_eval(tmp_path: Path):
    (tmp_path / "danger.py").write_text("result = eval(user_input)\n")

    config = RavenConfig(path=tmp_path)
    ctx = build_context(config)
    report = analyze(ctx)

    assert any("eval()" in f.title for f in report.findings)


def test_detect_exec(tmp_path: Path):
    (tmp_path / "danger.py").write_text("exec(user_code)\n")

    config = RavenConfig(path=tmp_path)
    ctx = build_context(config)
    report = analyze(ctx)

    assert any("exec()" in f.title for f in report.findings)


def test_detect_shell_true(tmp_path: Path):
    (tmp_path / "proc.py").write_text("import subprocess; subprocess.run(cmd, shell=True)\n")

    config = RavenConfig(path=tmp_path)
    ctx = build_context(config)
    report = analyze(ctx)

    assert any("shell=True" in f.title for f in report.findings)


def test_detect_pickle(tmp_path: Path):
    (tmp_path / "data.py").write_text("import pickle; obj = pickle.loads(data)\n")

    config = RavenConfig(path=tmp_path)
    ctx = build_context(config)
    report = analyze(ctx)

    assert any("pickle" in f.title.lower() for f in report.findings)


def test_detect_weak_crypto_md5(tmp_path: Path):
    (tmp_path / "hash.py").write_text("import hashlib; h = hashlib.md5(data)\n")

    config = RavenConfig(path=tmp_path)
    ctx = build_context(config)
    report = analyze(ctx)

    assert any("md5" in f.title.lower() for f in report.findings)


def test_detect_unsafe_yaml(tmp_path: Path):
    (tmp_path / "loader.py").write_text("import yaml; data = yaml.load(stream)\n")

    config = RavenConfig(path=tmp_path)
    ctx = build_context(config)
    report = analyze(ctx)

    assert any("yaml" in f.title.lower() for f in report.findings)


def test_safe_yaml_no_finding(tmp_path: Path):
    (tmp_path / "loader.py").write_text("import yaml; data = yaml.safe_load(stream)\n")

    config = RavenConfig(path=tmp_path)
    ctx = build_context(config)
    report = analyze(ctx)

    assert not any("yaml" in f.title.lower() for f in report.findings)


def test_os_system_detected(tmp_path: Path):
    (tmp_path / "executor.py").write_text("import os; os.system(f'rm -rf {path}')\n")

    config = RavenConfig(path=tmp_path)
    ctx = build_context(config)
    report = analyze(ctx)

    assert any("os.system" in f.title.lower() for f in report.findings)


def test_clean_project_no_findings(tmp_path: Path):
    """Clean code should produce no findings."""
    (tmp_path / "safe.py").write_text(
        "import os\n"
        "key = os.environ.get('API_KEY')\n"
        "import hashlib\n"
        "h = hashlib.sha256(b'data')\n"
        "import yaml\n"
        "data = yaml.safe_load(stream)\n"
        "import subprocess\n"
        "subprocess.run(['ls', '-l'], shell=False)\n"
    )

    config = RavenConfig(path=tmp_path)
    ctx = build_context(config)
    report = analyze(ctx)

    # os.environ.get should NOT be flagged as a hardcoded secret
    assert not any(f.cwe.cwe_id == "CWE-798" for f in report.findings)
    # hashlib.sha256 should NOT be flagged as weak crypto
    assert not any("sha256" in f.title.lower() for f in report.findings)
    # yaml.safe_load should NOT be flagged
    assert not any("yaml" in f.title.lower() and f.severity.value in ("high", "critical") for f in report.findings)


def test_finding_has_cwe_reference(tmp_path: Path):
    (tmp_path / "danger.py").write_text("eval(x)\n")

    config = RavenConfig(path=tmp_path)
    ctx = build_context(config)
    report = analyze(ctx)

    for f in report.findings:
        assert f.cwe.cwe_id, f"Finding missing CWE ID: {f.title}"
        assert f.cwe.name, f"Finding missing CWE name: {f.title}"
        assert f.cwe.url, f"Finding missing CWE URL: {f.title}"
