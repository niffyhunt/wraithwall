"""Go security analyzer.

Detects: hardcoded secrets, insecure TLS, command injection via exec.Command,
SQL injection, weak crypto, unsafe package usage.
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
    "sql_injection": CweReference(cwe_id="CWE-89", name="Improper Neutralization of Special Elements used in an SQL Command", url="https://cwe.mitre.org/data/definitions/89.html"),
    "weak_crypto": CweReference(cwe_id="CWE-327", name="Use of a Broken or Risky Cryptographic Algorithm", url="https://cwe.mitre.org/data/definitions/327.html"),
    "insecure_tls": CweReference(cwe_id="CWE-295", name="Improper Certificate Validation", url="https://cwe.mitre.org/data/definitions/295.html"),
    "unsafe_memory": CweReference(cwe_id="CWE-242", name="Use of Inherently Dangerous Function", url="https://cwe.mitre.org/data/definitions/242.html"),
}

_SECRET_PATTERNS: list[tuple[str, str]] = [
    (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\'][A-Za-z0-9_\-]{8,}["\']', "API key literal"),
    (r'(?i)(secret[_-]?key|secretkey)\s*[:=]\s*["\'][A-Za-z0-9_\-+/]{8,}["\']', "Secret key literal"),
    (r'(?i)(password|passwd)\s*[:=]\s*["\'][^"\']{4,}["\']', "Hardcoded password"),
    (r'(?i)(token)\s*[:=]\s*["\'][A-Za-z0-9_\-\.]{12,}["\']', "Token literal"),
    (r'(?i)(private[_-]?key)\s*[:=]\s*["\'][A-Za-z0-9_\-+/]{20,}["\']', "Private key literal"),
]

_CHECKS: list[tuple[str, str, str, Severity, str]] = [
    (r'InsecureSkipVerify\s*:\s*true', "InsecureSkipVerify enabled", "TLS certificate validation is disabled. This allows man-in-the-middle attacks.", Severity.CRITICAL, "insecure_tls"),
    (r'exec\.Command\([^)]*\+', "exec.Command with string concatenation", "User input appears to be concatenated into a shell command. This is command injection.", Severity.CRITICAL, "command_injection"),
    (r'exec\.CommandContext\([^)]*\+', "exec.CommandContext with string concatenation", "User input concatenated into a shell command.", Severity.CRITICAL, "command_injection"),
    (r'fmt\.Sprintf\([^)]*?(?:INSERT|UPDATE|DELETE|SELECT|DROP|CREATE|ALTER)\b', "SQL via fmt.Sprintf", "SQL statement built with fmt.Sprintf is vulnerable to SQL injection.", Severity.HIGH, "sql_injection"),
    (r'\b(?:"|\x60)SELECT\b.*?\+', "SQL with concatenation", "SQL query built with string concatenation is vulnerable to SQL injection.", Severity.HIGH, "sql_injection"),
    (r'\bmd5\.(?:New|Sum)\b', "MD5 hashing", "MD5 is cryptographically broken. Use SHA-256 or bcrypt.", Severity.HIGH, "weak_crypto"),
    (r'\bsha1\.(?:New|Sum)\b', "SHA-1 hashing", "SHA-1 is deprecated and vulnerable to collision attacks.", Severity.MEDIUM, "weak_crypto"),
    (r'\bdes\.NewCipher\b', "DES encryption", "DES uses a 56-bit key and is trivially broken.", Severity.CRITICAL, "weak_crypto"),
    (r'import\s+"unsafe"', "unsafe package imported", "The unsafe package bypasses Go's type safety. Review carefully for memory corruption risks.", Severity.MEDIUM, "unsafe_memory"),
]

class GoSecurityAnalyzer(AbstractSecurityAnalyzer):
    language = "go"
    display_name = "Go Security Analyzer"

    @property
    def supported_file_extensions(self) -> list[str]:
        return [".go"]

    def analyze(self, ctx: RepositoryContext) -> SecurityReport:
        findings: list[SecurityFinding] = []
        go_files = [f for f in ctx.files if f.language == "go"]
        for pf in go_files:
            for i, line in enumerate(pf.lines):
                if line.strip().startswith("//"):
                    continue
                for pattern, name, desc, sev, cwe_key in _CHECKS:
                    if re.search(pattern, line):
                        cwe_ref = CWE[cwe_key]
                        findings.append(SecurityFinding(
                            severity=sev,
                            cwe=cwe_ref,
                            title=f"[Go] {name}",
                            description=desc,
                            evidence=f"Pattern '{name}' matched at {pf.relative_path}:{i + 1}",
                            affected_file=pf.relative_path,
                            affected_lines=[i + 1],
                            exploitation_scenario=cwe_ref.url,
                            recommendation="Review this code and apply secure alternatives.",
                            confidence=Confidence.HIGH,
                        ))
                for pattern, name in _SECRET_PATTERNS:
                    if re.search(pattern, line) and "os.Getenv" not in line:
                        findings.append(SecurityFinding(
                            severity=Severity.CRITICAL,
                            cwe=CWE["hardcoded_secret"],
                            title=f"[Go] Hardcoded secret: {name}",
                            description=f"Hardcoded {name.lower()} detected in Go source.",
                            evidence=f"Pattern '{name}' matched at {pf.relative_path}:{i + 1}",
                            affected_file=pf.relative_path,
                            affected_lines=[i + 1],
                            exploitation_scenario="If committed, anyone with repository access can extract this credential.",
                            recommendation="Use os.Getenv() or a configuration file that is gitignored.",
                            confidence=Confidence.MEDIUM,
                        ))
        return SecurityReport(findings=findings)

    @property
    def is_available(self) -> bool:
        return True
