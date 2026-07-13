"""Java / Kotlin / Scala security analyzer.

Detects: SQL injection via Statement misuse, XXE, insecure deserialization,
hardcoded secrets, command injection via Runtime.exec, weak crypto.
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
    "xxe": CweReference(cwe_id="CWE-611", name="Improper Restriction of XML External Entity Reference", url="https://cwe.mitre.org/data/definitions/611.html"),
    "weak_crypto": CweReference(cwe_id="CWE-327", name="Use of a Broken or Risky Cryptographic Algorithm", url="https://cwe.mitre.org/data/definitions/327.html"),
    "unsafe_deserialization": CweReference(cwe_id="CWE-502", name="Deserialization of Untrusted Data", url="https://cwe.mitre.org/data/definitions/502.html"),
    "insecure_tls": CweReference(cwe_id="CWE-295", name="Improper Certificate Validation", url="https://cwe.mitre.org/data/definitions/295.html"),
}

_SECRET_PATTERNS: list[tuple[str, str]] = [
    (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\'][A-Za-z0-9_\-]{8,}["\']', "API key literal"),
    (r'(?i)(secret[_-]?key|secretkey)\s*[:=]\s*["\'][A-Za-z0-9_\-+/]{8,}["\']', "Secret key literal"),
    (r'(?i)(password|passwd)\s*[:=]\s*["\'][^"\']{4,}["\']', "Hardcoded password"),
    (r'(?i)(token)\s*[:=]\s*["\'][A-Za-z0-9_\-\.]{12,}["\']', "Token literal"),
    (r'(?i)(private[_-]?key)\s*[:=]\s*["\'][A-Za-z0-9_\-+/]{20,}["\']', "Private key literal"),
]

_CHECKS: list[tuple[str, str, str, Severity, str]] = [
    (r'Statement\s+\w+\s*=.*createStatement\(\)', "Statement without PreparedStatement", "java.sql.Statement is vulnerable to SQL injection. Use PreparedStatement with parameterized queries.", Severity.HIGH, "sql_injection"),
    (r'\.execute(?:Query|Update)\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE)', "Literal SQL in execute", "SQL query string in executeQuery/executeUpdate may indicate injection vulnerability.", Severity.HIGH, "sql_injection"),
    (r'Runtime\.getRuntime\(\)\.exec\(', "Runtime.exec()", "Runtime.exec() can lead to command injection if input is not sanitized. Use ProcessBuilder with argument arrays.", Severity.CRITICAL, "command_injection"),
    (r'DocumentBuilderFactory\.newInstance\(\)', "DocumentBuilderFactory without XXE protection", "XML parsing may be vulnerable to XXE. Disable external entities and DTD processing.", Severity.HIGH, "xxe"),
    (r'new\s+ObjectInputStream\(', "ObjectInputStream deserialization", "Java deserialization is dangerous with untrusted data. Validate input source.", Severity.CRITICAL, "unsafe_deserialization"),
    (r'(?i)MessageDigest\.getInstance\(\s*"MD5"\s*\)', "MD5 hashing", "MD5 is cryptographically broken. Use SHA-256.", Severity.HIGH, "weak_crypto"),
    (r'(?i)MessageDigest\.getInstance\(\s*"SHA-?1"\s*\)', "SHA-1 hashing", "SHA-1 is deprecated. Use SHA-256.", Severity.MEDIUM, "weak_crypto"),
    (r'(?i)Cipher\.getInstance\(\s*"DES\b', "DES encryption", "DES is trivially broken. Use AES-GCM.", Severity.CRITICAL, "weak_crypto"),
    (r'TrustManager.*\{.*return\s*null', "TrustAll TrustManager", "Certificate validation is disabled. This allows MITM attacks.", Severity.CRITICAL, "insecure_tls"),
    (r'new\s+X509TrustManager\(\).*checkClientTrusted|checkServerTrusted', "Custom TrustManager", "Custom TrustManager may weaken TLS validation. Review carefully.", Severity.HIGH, "insecure_tls"),
]

class JavaSecurityAnalyzer(AbstractSecurityAnalyzer):
    language = "java"
    display_name = "Java Security Analyzer"

    @property
    def supported_file_extensions(self) -> list[str]:
        return [".java", ".kt", ".scala"]

    def analyze(self, ctx: RepositoryContext) -> SecurityReport:
        findings: list[SecurityFinding] = []
        jvm_files = [f for f in ctx.files if f.language in ("java", "kotlin", "scala")]
        for pf in jvm_files:
            for i, line in enumerate(pf.lines):
                if line.strip().startswith("//"):
                    continue
                for pattern, name, desc, sev, cwe_key in _CHECKS:
                    if re.search(pattern, line):
                        cwe_ref = CWE[cwe_key]
                        findings.append(SecurityFinding(
                            severity=sev,
                            cwe=cwe_ref,
                            title=f"[Java/Kotlin] {name}",
                            description=desc,
                            evidence=f"Pattern '{name}' matched at {pf.relative_path}:{i + 1}",
                            affected_file=pf.relative_path,
                            affected_lines=[i + 1],
                            exploitation_scenario=cwe_ref.url,
                            recommendation="Refactor using secure coding practices for Java/JVM platform.",
                            confidence=Confidence.HIGH,
                        ))
                for pattern, name in _SECRET_PATTERNS:
                    if re.search(pattern, line) and "System.getenv" not in line and "System.getProperty" not in line:
                        findings.append(SecurityFinding(
                            severity=Severity.CRITICAL,
                            cwe=CWE["hardcoded_secret"],
                            title=f"[Java/Kotlin] Hardcoded secret: {name}",
                            description=f"Hardcoded {name.lower()} detected in JVM source.",
                            evidence=f"Pattern '{name}' matched at {pf.relative_path}:{i + 1}",
                            affected_file=pf.relative_path,
                            affected_lines=[i + 1],
                            exploitation_scenario="If committed, anyone with repository access can extract this credential.",
                            recommendation="Use environment variables via System.getenv() or a vault service.",
                            confidence=Confidence.MEDIUM,
                        ))
        return SecurityReport(findings=findings)

    @property
    def is_available(self) -> bool:
        return True
