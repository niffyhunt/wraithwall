"""Multi-language security analyzer plugins.

Language-specific analyzers registered through SecurityAnalyzerRegistry.
Built-in: Python, JavaScript/TypeScript, Go, Rust, Java/Kotlin/Scala.
"""

from raven.plugins.security.base import SecurityAnalyzer, AbstractSecurityAnalyzer
from raven.plugins.registry import SecurityAnalyzerRegistry, registry as security_registry
from raven.plugins.security.python.analyzer import PythonSecurityAnalyzer
from raven.plugins.security.go.analyzer import GoSecurityAnalyzer
from raven.plugins.security.rust.analyzer import RustSecurityAnalyzer
from raven.plugins.security.java.analyzer import JavaSecurityAnalyzer
from raven.plugins.security.javascript.analyzer import JavaScriptSecurityAnalyzer


def register_builtin_analyzers() -> None:
    """Register all built-in security analyzers in the global registry.

    Called once at module load. External plugins discovered through
    entry_points can be registered afterward.
    """
    builtins = [
        PythonSecurityAnalyzer(),
        JavaScriptSecurityAnalyzer(),
        GoSecurityAnalyzer(),
        RustSecurityAnalyzer(),
        JavaSecurityAnalyzer(),
    ]
    for analyzer in builtins:
        if analyzer.language not in security_registry.list_languages():
            security_registry.register(analyzer)
