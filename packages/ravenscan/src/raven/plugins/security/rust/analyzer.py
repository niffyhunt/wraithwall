"""Rust security analyzer.

Detects: unsafe blocks, unwrap/expect misuse, command injection via
std::process::Command, hardcoded secrets, weak crypto crate usage.
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
    "unsafe_memory": CweReference(cwe_id="CWE-242", name="Use of Inherently Dangerous Function", url="https://cwe.mitre.org/data/definitions/242.html"),
    "weak_crypto": CweReference(cwe_id="CWE-327", name="Use of a Broken or Risky Cryptographic Algorithm", url="https://cwe.mitre.org/data/definitions/327.html"),
    "panic_exposure": CweReference(cwe_id="CWE-248", name="Uncaught Exception", url="https://cwe.mitre.org/data/definitions/248.html"),
}

_SECRET_PATTERNS: list[tuple[str, str]] = [
    (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\'][A-Za-z0-9_\-]{8,}["\']', "API key literal"),
    (r'(?i)(secret[_-]?key|secretkey)\s*[:=]\s*["\'][A-Za-z0-9_\-+/]{8,}["\']', "Secret key literal"),
    (r'(?i)(password|passwd)\s*[:=]\s*["\'][^"\']{4,}["\']', "Hardcoded password"),
    (r'(?i)(token)\s*[:=]\s*["\'][A-Za-z0-9_\-\.]{12,}["\']', "Token literal"),
    (r'(?i)(private[_-]?key)\s*[:=]\s*["\'][A-Za-z0-9_\-+/]{20,}["\']', "Private key literal"),
    (r'(?i)(database[_-]?url|db[_-]?url)\s*[:=]\s*["\'][^"\']{10,}["\']', "Database URL with credentials"),
    (r'(?i)(aws[_-]?(access|secret)|AZURE_STORAGE|GOOGLE_APPLICATION_CREDENTIALS)', "Cloud credential pattern"),
]

_CHECKS: list[tuple[str, str, str, Severity, str]] = [
    (r'\bunsafe\s*\{', "unsafe block", "unsafe code bypasses Rust's memory safety guarantees. Review carefully.", Severity.MEDIUM, "unsafe_memory"),
    (r'\.unwrap\(\)', ".unwrap() call", "unwrap() panics on None/Err. In production, prefer match or ? operator with proper error handling.", Severity.LOW, "panic_exposure"),
    (r'\.expect\("[^"]*"\)', ".expect() call", "expect() panics if the value is None/Err. Ensure the message is helpful and panic is acceptable.", Severity.LOW, "panic_exposure"),
    (r'std::process::Command::new\(.*\+', "Command::new with concatenation", "User input concatenated into a shell command. Use Command::arg() instead.", Severity.CRITICAL, "command_injection"),
    (r'Command::new\(\s*"sh"\s*\)|Command::new\(\s*"bash"\s*\)', "Shell invocation via Command", "Invoking sh/bash via Command bypasses argument escaping. Prefer direct binary invocation.", Severity.HIGH, "command_injection"),
    (r'(?i)(md-5|md5)_crate', "MD5 crate usage", "MD5 is cryptographically broken. Use sha2 crate instead.", Severity.HIGH, "weak_crypto"),
    (r'(?i)(sha-?1|sha1)_crate(?:\s*=\s*"[^"]*")', "SHA-1 crate usage", "SHA-1 is deprecated. Use sha2 crate with SHA-256 or stronger.", Severity.MEDIUM, "weak_crypto"),
]

class RustSecurityAnalyzer(AbstractSecurityAnalyzer):
    language = "rust"
    display_name = "Rust Security Analyzer"

    @property
    def supported_file_extensions(self) -> list[str]:
        return [".rs"]

    def analyze(self, ctx: RepositoryContext) -> SecurityReport:
        findings: list[SecurityFinding] = []
        rust_files = [f for f in ctx.files if f.language == "rust"]
        for pf in rust_files:
            for i, line in enumerate(pf.lines):
                if line.strip().startswith("//"):
                    continue
                for pattern, name, desc, sev, cwe_key in _CHECKS:
                    if re.search(pattern, line):
                        cwe_ref = CWE[cwe_key]
                        findings.append(SecurityFinding(
                            severity=sev,
                            cwe=cwe_ref,
                            title=f"[Rust] {name}",
                            description=desc,
                            evidence=f"Pattern '{name}' matched at {pf.relative_path}:{i + 1}",
                            affected_file=pf.relative_path,
                            affected_lines=[i + 1],
                            exploitation_scenario=cwe_ref.url,
                            recommendation="Review this code and apply secure alternatives.",
                            confidence=Confidence.HIGH,
                        ))
                for pattern, name in _SECRET_PATTERNS:
                    if re.search(pattern, line) and "env::var" not in line and "std::env" not in line:
                        findings.append(SecurityFinding(
                            severity=Severity.CRITICAL,
                            cwe=CWE["hardcoded_secret"],
                            title=f"[Rust] Hardcoded secret: {name}",
                            description=f"Hardcoded {name.lower()} detected in Rust source.",
                            evidence=f"Pattern '{name}' matched at {pf.relative_path}:{i + 1}",
                            affected_file=pf.relative_path,
                            affected_lines=[i + 1],
                            exploitation_scenario="If committed, anyone with repository access can extract this credential.",
                            recommendation="Use std::env::var() or a configuration crate like dotenvy with a gitignored .env file.",
                            confidence=Confidence.MEDIUM,
                        ))
        return SecurityReport(findings=findings)

    @property
    def is_available(self) -> bool:
        return True
