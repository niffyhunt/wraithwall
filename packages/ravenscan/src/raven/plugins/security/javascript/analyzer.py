"""JavaScript / TypeScript security analyzer.

Detects: eval/innerHTML XSS, prototype pollution, hardcoded secrets,
insecure crypto, command injection via child_process, open redirects.
"""

from __future__ import annotations

import re

from raven.plugins.security.base import AbstractSecurityAnalyzer
from raven.core.context import RepositoryContext
from raven.core.models import (
    SecurityFinding,
    SecurityReport,
    CweReference,
    Severity,
    Confidence,
)

CWE = {
    "hardcoded_secret": CweReference(cwe_id="CWE-798", name="Hardcoded Credentials", url="https://cwe.mitre.org/data/definitions/798.html"),
    "command_injection": CweReference(cwe_id="CWE-78", name="Improper Neutralization of Special Elements used in an OS Command", url="https://cwe.mitre.org/data/definitions/78.html"),
    "xss": CweReference(cwe_id="CWE-79", name="Improper Neutralization of Input During Web Page Generation", url="https://cwe.mitre.org/data/definitions/79.html"),
    "code_injection": CweReference(cwe_id="CWE-94", name="Improper Control of Generation of Code", url="https://cwe.mitre.org/data/definitions/94.html"),
    "weak_crypto": CweReference(cwe_id="CWE-327", name="Use of a Broken or Risky Cryptographic Algorithm", url="https://cwe.mitre.org/data/definitions/327.html"),
    "open_redirect": CweReference(cwe_id="CWE-601", name="URL Redirection to Untrusted Site", url="https://cwe.mitre.org/data/definitions/601.html"),
    "path_traversal": CweReference(cwe_id="CWE-22", name="Path Traversal", url="https://cwe.mitre.org/data/definitions/22.html"),
}

_SECRET_PATTERNS: list[tuple[str, str]] = [
    (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\'][A-Za-z0-9_\-]{8,}["\']', "API key literal"),
    (r'(?i)(secret[_-]?key|secretkey)\s*[:=]\s*["\'][A-Za-z0-9_\-+/]{8,}["\']', "Secret key literal"),
    (r'(?i)(password|passwd)\s*[:=]\s*["\'][^"\']{4,}["\']', "Hardcoded password"),
    (r'(?i)(token)\s*[:=]\s*["\'][A-Za-z0-9_\-\.]{12,}["\']', "Token literal"),
    (r'(?i)(private[_-]?key)\s*[:=]\s*["\'][A-Za-z0-9_\-+/]{20,}["\']', "Private key literal"),
    (r'(?i)(database[_-]?url|db[_-]?url)\s*[:=]\s*["\'][^"\']{10,}["\']', "Database URL with credentials"),
    (r'(?i)(aws[_-]?(access|secret)|AZURE_STORAGE|GOOGLE_APPLICATION_CREDENTIALS|FIREBASE)', "Cloud credential pattern"),
]

_CHECKS: list[tuple[str, str, str, Severity, str]] = [
    (r'\beval\(', "eval() call", "eval() executes arbitrary JavaScript code. Use JSON.parse() for data or avoid dynamic code execution entirely.", Severity.CRITICAL, "code_injection"),
    (r'\bnew\s+Function\s*\(', "new Function() constructor", "new Function() is equivalent to eval() and enables arbitrary code execution.", Severity.CRITICAL, "code_injection"),
    (r'\.innerHTML\s*=', ".innerHTML assignment", "Unsanitized innerHTML can lead to XSS. Use textContent or DOM APIs with sanitization.", Severity.HIGH, "xss"),
    (r'document\.write\(', "document.write() call", "document.write() with untrusted input can inject malicious scripts.", Severity.HIGH, "xss"),
    (r'setTimeout\(\s*["\'`]|setInterval\(\s*["\'`]', "setTimeout/setInterval with string argument", "String argument to setTimeout/setInterval is evaluated as code (like eval).", Severity.HIGH, "code_injection"),
    (r'window\.location\s*=.*\+|window\.location\.href\s*=.*\+', "Open redirect via window.location", "User input concatenated into window.location may enable open redirects.", Severity.MEDIUM, "open_redirect"),
    (r'child_process\.exec\(|\.exec\(\s*["\'`].*\$', "child_process.exec with interpolation", "Shell command with user input via string interpolation may lead to command injection.", Severity.CRITICAL, "command_injection"),
    (r'require\(\s*["\']child_process["\']\s*\)\.exec\(.*\+', "child_process.exec with concatenation", "Concatenating user input into shell command is command injection.", Severity.CRITICAL, "command_injection"),
    (r'\b(?:__proto__|prototype)\[[^\]]*\]\s*=', "Prototype pollution via __proto__", "Direct assignment to __proto__ or constructor.prototype may enable prototype pollution attacks.", Severity.HIGH, "code_injection"),
    (r'crypto\.create(?:Hash|Hmac)\(\s*["\']md5["\']\s*\)', "MD5 hashing via crypto", "MD5 is cryptographically broken. Use SHA-256 via crypto.createHash('sha256').", Severity.HIGH, "weak_crypto"),
    (r'crypto\.createCipher\b', "Insecure cipher usage", "crypto.createCipher is deprecated (uses weak key derivation). Use crypto.createCipheriv.", Severity.HIGH, "weak_crypto"),
    (r'path\.join\([^)]*\$\{|path\.resolve\([^)]*\+', "Path traversal via user input", "User input in file path construction may enable path traversal attacks.", Severity.HIGH, "path_traversal"),
]

class JavaScriptSecurityAnalyzer(AbstractSecurityAnalyzer):
    language = "javascript"
    display_name = "JavaScript/TypeScript Security Analyzer"

    @property
    def supported_file_extensions(self) -> list[str]:
        return [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]

    def analyze(self, ctx: RepositoryContext) -> SecurityReport:
        findings: list[SecurityFinding] = []
        js_files = [f for f in ctx.files if f.language in ("javascript", "typescript")]
        for pf in js_files:
            for i, line in enumerate(pf.lines):
                if line.strip().startswith("//") or line.strip().startswith("*"):
                    continue
                for pattern, name, desc, sev, cwe_key in _CHECKS:
                    if re.search(pattern, line):
                        cwe_ref = CWE[cwe_key]
                        findings.append(SecurityFinding(
                            severity=sev,
                            cwe=cwe_ref,
                            title=f"[JS/TS] {name}",
                            description=desc,
                            evidence=f"Pattern '{name}' matched at {pf.relative_path}:{i + 1}",
                            affected_file=pf.relative_path,
                            affected_lines=[i + 1],
                            exploitation_scenario=cwe_ref.url,
                            recommendation="Apply secure coding practices for JavaScript/Node.js.",
                            confidence=Confidence.HIGH,
                        ))
                for pattern, name in _SECRET_PATTERNS:
                    if re.search(pattern, line) and "process.env" not in line and "import.meta.env" not in line:
                        findings.append(SecurityFinding(
                            severity=Severity.CRITICAL,
                            cwe=CWE["hardcoded_secret"],
                            title=f"[JS/TS] Hardcoded secret: {name}",
                            description=f"Hardcoded {name.lower()} detected in JavaScript/TypeScript source.",
                            evidence=f"Pattern '{name}' matched at {pf.relative_path}:{i + 1}",
                            affected_file=pf.relative_path,
                            affected_lines=[i + 1],
                            exploitation_scenario="If committed, anyone with repository access can extract this credential.",
                            recommendation="Use process.env.VAR_NAME or a .env file (gitignored) with dotenv.",
                            confidence=Confidence.MEDIUM,
                        ))
        return SecurityReport(findings=findings)

    @property
    def is_available(self) -> bool:
        return True
