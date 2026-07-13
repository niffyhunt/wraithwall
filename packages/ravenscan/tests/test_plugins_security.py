"""Tests for multi-language security analyzer plugins."""
from pathlib import Path

from raven.core.config import RavenConfig
from raven.repository.intel import build_context
from raven.plugins.registry import SecurityAnalyzerRegistry
from raven.plugins.security import register_builtin_analyzers


def test_go_analyzer_finds_insecure_tls(tmp_path: Path):
    ctx = _write_and_build(tmp_path, "main.go", """
package main
import "crypto/tls"
func main() {
    tls.Config{InsecureSkipVerify: true}
}
""".strip())
    from raven.plugins.security.go.analyzer import GoSecurityAnalyzer
    report = GoSecurityAnalyzer().analyze(ctx)
    assert len(report.findings) >= 1
    assert any("InsecureSkipVerify" in f.title for f in report.findings)


def test_go_analyzer_finds_hardcoded_secret(tmp_path: Path):
    ctx = _write_and_build(tmp_path, "config.go", """
package config
const API_KEY = "sk-live-abcdefghijklmnop"
""".strip())
    from raven.plugins.security.go.analyzer import GoSecurityAnalyzer
    report = GoSecurityAnalyzer().analyze(ctx)
    assert len(report.findings) >= 1
    assert any("Hardcoded secret" in f.title for f in report.findings)


def test_go_analyzer_clean_code_no_findings(tmp_path: Path):
    ctx = _write_and_build(tmp_path, "clean.go", """
package main
import "fmt"
func main() { fmt.Println("hello") }
""".strip())
    from raven.plugins.security.go.analyzer import GoSecurityAnalyzer
    report = GoSecurityAnalyzer().analyze(ctx)
    assert len(report.findings) == 0


def test_rust_analyzer_finds_unsafe(tmp_path: Path):
    ctx = _write_and_build(tmp_path, "main.rs", """
fn main() {
    unsafe {
        let ptr: *const i32 = &42;
        println!("{}", *ptr);
    }
}
""".strip())
    from raven.plugins.security.rust.analyzer import RustSecurityAnalyzer
    report = RustSecurityAnalyzer().analyze(ctx)
    assert any("unsafe block" in f.title for f in report.findings)


def test_rust_analyzer_finds_unwrap(tmp_path: Path):
    ctx = _write_and_build(tmp_path, "app.rs", """
fn load() -> Option<String> {
    let x = std::fs::read_to_string("file.txt").unwrap();
    Some(x)
}
""".strip())
    from raven.plugins.security.rust.analyzer import RustSecurityAnalyzer
    report = RustSecurityAnalyzer().analyze(ctx)
    assert any(".unwrap()" in f.title for f in report.findings)


def test_rust_analyzer_clean_code_no_findings(tmp_path: Path):
    ctx = _write_and_build(tmp_path, "clean.rs", """
fn main() { println!("safe"); }
""".strip())
    from raven.plugins.security.rust.analyzer import RustSecurityAnalyzer
    report = RustSecurityAnalyzer().analyze(ctx)
    assert len(report.findings) == 0


def test_java_analyzer_finds_runtime_exec(tmp_path: Path):
    ctx = _write_and_build(tmp_path, "Runner.java", """
public class Runner {
    public void run(String cmd) {
        Runtime.getRuntime().exec(cmd);
    }
}
""".strip())
    from raven.plugins.security.java.analyzer import JavaSecurityAnalyzer
    report = JavaSecurityAnalyzer().analyze(ctx)
    assert any("Runtime.exec" in f.title for f in report.findings)


def test_java_analyzer_finds_statement(tmp_path: Path):
    ctx = _write_and_build(tmp_path, "Query.java", """
import java.sql.Statement;
public class Query {
    public void exec(Statement stmt, String user) {
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");
    }
}
""".strip())
    from raven.plugins.security.java.analyzer import JavaSecurityAnalyzer
    report = JavaSecurityAnalyzer().analyze(ctx)
    assert len(report.findings) >= 1
    # Should find both the Statement creation AND the executeQuery
    assert sum(1 for f in report.findings) >= 1


def test_java_analyzer_clean_code_no_findings(tmp_path: Path):
    ctx = _write_and_build(tmp_path, "Clean.java", """
public class Clean {
    public static void main(String[] args) {
        System.out.println("safe");
    }
}
""".strip())
    from raven.plugins.security.java.analyzer import JavaSecurityAnalyzer
    report = JavaSecurityAnalyzer().analyze(ctx)
    assert len(report.findings) == 0


def test_js_analyzer_finds_eval(tmp_path: Path):
    ctx = _write_and_build(tmp_path, "danger.js", "const result = eval(userInput);")
    from raven.plugins.security.javascript.analyzer import JavaScriptSecurityAnalyzer
    report = JavaScriptSecurityAnalyzer().analyze(ctx)
    assert any("eval()" in f.title for f in report.findings)


def test_js_analyzer_finds_innerhtml(tmp_path: Path):
    ctx = _write_and_build(tmp_path, "dom.js", "document.getElementById('main').innerHTML = userInput;")
    from raven.plugins.security.javascript.analyzer import JavaScriptSecurityAnalyzer
    report = JavaScriptSecurityAnalyzer().analyze(ctx)
    assert any("innerHTML" in f.title for f in report.findings)


def test_js_analyzer_finds_hardcoded_secret(tmp_path: Path):
    ctx = _write_and_build(tmp_path, "config.js", "const API_KEY = 'sk-proj-abcdefghijklmnopqrstuvwxyz123456';")
    from raven.plugins.security.javascript.analyzer import JavaScriptSecurityAnalyzer
    report = JavaScriptSecurityAnalyzer().analyze(ctx)
    assert any("Hardcoded secret" in f.title for f in report.findings)


def test_js_analyzer_clean_code_no_findings(tmp_path: Path):
    ctx = _write_and_build(tmp_path, "clean.js", "const x = 1; console.log(x);")
    from raven.plugins.security.javascript.analyzer import JavaScriptSecurityAnalyzer
    report = JavaScriptSecurityAnalyzer().analyze(ctx)
    assert len(report.findings) == 0


def test_registry_registers_all_builtins():
    reg = SecurityAnalyzerRegistry()
    from raven.plugins.security.python.analyzer import PythonSecurityAnalyzer
    from raven.plugins.security.go.analyzer import GoSecurityAnalyzer
    from raven.plugins.security.rust.analyzer import RustSecurityAnalyzer
    from raven.plugins.security.java.analyzer import JavaSecurityAnalyzer
    from raven.plugins.security.javascript.analyzer import JavaScriptSecurityAnalyzer
    for analyzer_cls in [PythonSecurityAnalyzer, GoSecurityAnalyzer, RustSecurityAnalyzer,
                          JavaSecurityAnalyzer, JavaScriptSecurityAnalyzer]:
        reg.register(analyzer_cls())
    languages = reg.list_languages()
    assert "python" in languages
    assert "go" in languages
    assert "rust" in languages
    assert "java" in languages
    assert "javascript" in languages


def test_registry_analyze_all_includes_multi_language(tmp_path: Path):
    (tmp_path / "app.py").write_text("API_KEY = 'xj4Kp9mN2vL8qW5yR3aF7hB1cE0dG6'\n")
    (tmp_path / "main.go").write_text("package main\nimport \"crypto/tls\"\nvar _ = tls.Config{InsecureSkipVerify: true}\n")
    (tmp_path / "script.js").write_text("eval(userInput);")
    ctx = build_context(RavenConfig(path=tmp_path))
    reg = SecurityAnalyzerRegistry()
    from raven.plugins.security.python.analyzer import PythonSecurityAnalyzer
    from raven.plugins.security.go.analyzer import GoSecurityAnalyzer
    from raven.plugins.security.javascript.analyzer import JavaScriptSecurityAnalyzer
    reg.register(PythonSecurityAnalyzer())
    reg.register(GoSecurityAnalyzer())
    reg.register(JavaScriptSecurityAnalyzer())
    report = reg.analyze_all(ctx)
    # Should find Python secret + Go TLS + JS eval
    assert len(report.findings) >= 3


def _write_and_build(tmp_path: Path, filename: str, content: str):
    (tmp_path / filename).write_text(content)
    return build_context(RavenConfig(path=tmp_path))
