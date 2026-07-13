"""Phase 3 — Security Intelligence.

Static analysis for security issues mapped to CWE:
- Hardcoded secrets / credentials (with entropy-based FP reduction)
- Weak cryptography
- Command injection patterns
- SQL injection patterns
- Unsafe deserialization
- Missing auth checks on sensitive routes (with contextual suppression)
- Dangerous file operations
- Insecure random number generation
- SSRF patterns
- Unsafe YAML loading

v0.1: Python only.
"""

from __future__ import annotations

import ast
import re
from typing import Optional, TYPE_CHECKING

from raven.core.config import RavenConfig
from raven.core.context import ParsedFile, RepositoryContext
from raven.core.models import (
    SecurityFinding,
    SecurityReport,
    CweReference,
    Severity,
    Confidence,
)
from raven.security.entropy import shannon_entropy, classify_secret_strength, ENTROPY_THRESHOLD
from raven.security.contextual import should_suppress
from raven.security.calibration import calibrate_confidence, should_report
from raven.utils.logging import get_logger

if TYPE_CHECKING:
    from raven.memory.store import MemoryStore

logger = get_logger(__name__)

CWE = {
    "hardcoded_secret": CweReference(cwe_id="CWE-798", name="Hardcoded Credentials", url="https://cwe.mitre.org/data/definitions/798.html"),
    "weak_crypto": CweReference(cwe_id="CWE-327", name="Use of a Broken or Risky Cryptographic Algorithm", url="https://cwe.mitre.org/data/definitions/327.html"),
    "command_injection": CweReference(cwe_id="CWE-78", name="Improper Neutralization of Special Elements used in an OS Command", url="https://cwe.mitre.org/data/definitions/78.html"),
    "sql_injection": CweReference(cwe_id="CWE-89", name="Improper Neutralization of Special Elements used in an SQL Command", url="https://cwe.mitre.org/data/definitions/89.html"),
    "unsafe_deserialization": CweReference(cwe_id="CWE-502", name="Deserialization of Untrusted Data", url="https://cwe.mitre.org/data/definitions/502.html"),
    "missing_auth": CweReference(cwe_id="CWE-306", name="Missing Authentication for Critical Function", url="https://cwe.mitre.org/data/definitions/306.html"),
    "path_traversal": CweReference(cwe_id="CWE-22", name="Path Traversal", url="https://cwe.mitre.org/data/definitions/22.html"),
    "insecure_random": CweReference(cwe_id="CWE-338", name="Use of Cryptographically Weak PRNG", url="https://cwe.mitre.org/data/definitions/338.html"),
    "ssrf": CweReference(cwe_id="CWE-918", name="Server-Side Request Forgery", url="https://cwe.mitre.org/data/definitions/918.html"),
    "unsafe_yaml": CweReference(cwe_id="CWE-502", name="Deserialization of Untrusted Data (YAML)", url="https://cwe.mitre.org/data/definitions/502.html"),
    "xss": CweReference(cwe_id="CWE-79", name="Improper Neutralization of Input During Web Page Generation", url="https://cwe.mitre.org/data/definitions/79.html"),
    "open_redirect": CweReference(cwe_id="CWE-601", name="URL Redirection to Untrusted Site", url="https://cwe.mitre.org/data/definitions/601.html"),
    "debug_enabled": CweReference(cwe_id="CWE-489", name="Active Debug Code", url="https://cwe.mitre.org/data/definitions/489.html"),
    "disabled_csrf": CweReference(cwe_id="CWE-352", name="Cross-Site Request Forgery", url="https://cwe.mitre.org/data/definitions/352.html"),
    "eval_exec": CweReference(cwe_id="CWE-95", name="Improper Neutralization of Directives in Dynamically Evaluated Code", url="https://cwe.mitre.org/data/definitions/95.html"),
}


_known_false_positives: set[str] = set()
"""Fingerprints of findings marked as false positives by the operator.

Each entry is 'filepath:line:analyzer' (e.g., 'src/app.py:42:hardcoded_secret').
Findings matching an entry are suppressed entirely.
"""


def load_false_positives(memory_store: Optional[MemoryStore] = None) -> None:
    """Load known false positives from the memory store into the suppression set.

    Called once before analysis to populate _known_false_positives.
    """
    if memory_store is None:
        return
    _known_false_positives.clear()
    try:
        for fp in memory_store.get_false_positives():
            fingerprint = fp.get("fingerprint", "")
            if fingerprint:
                _known_false_positives.add(str(fingerprint))
    except Exception:
        pass

ANALYZER_CATEGORY_MAP: dict[str, str] = {
    "hardcoded_secret": "hardcoded_secret",
    "weak_crypto": "weak_crypto",
    "command_injection": "command_injection",
    "sql_injection": "sql_injection",
    "unsafe_deserialization": "unsafe_deserialization",
    "eval_exec": "eval_exec",
    "path_traversal": "path_traversal",
    "insecure_random": "insecure_random",
    "ssrf": "ssrf",
    "unsafe_yaml": "unsafe_yaml",
    "debug_enabled": "debug_enabled",
    "disabled_csrf": "disabled_csrf",
    "missing_auth": "missing_auth",
    "xss": "xss",
    "open_redirect": "open_redirect",
}


def _category_for_cwe(cwe: CweReference) -> str:
    """Map a CWE reference back to its analyzer category name."""
    reverse: dict[str, str] = {}
    for cat_name, ref in CWE.items():
        reverse[ref.cwe_id] = cat_name
    return reverse.get(cwe.cwe_id, "unknown")


def _fp_fingerprint(filepath: str, line: int, analyzer: str) -> str:
    """Create a stable fingerprint for false-positive tracking."""
    return f"{filepath}:{line}:{analyzer}"


def analyze(ctx: RepositoryContext, config: Optional[RavenConfig] = None) -> SecurityReport:
    """Run Phase 3 security analysis across all Python files in context.

    Post-processes findings through:
    - Entropy-based secret strength classification
    - Contextual suppression (test files, fixtures, docs)
    - Confidence calibration per analyzer type
    - Known false-positive exclusion list
    """
    raw_findings: list[SecurityFinding] = []

    for f in ctx.files:
        if f.language != "python" or not f.ast_tree:
            continue
        _scan_hardcoded_secrets(f, raw_findings)
        _scan_weak_crypto(f, raw_findings)
        _scan_command_injection(f, raw_findings)
        _scan_sql_injection(f, raw_findings)
        _scan_unsafe_deserialization(f, raw_findings)
        _scan_eval_exec(f, raw_findings)
        _scan_path_traversal(f, raw_findings)
        _scan_insecure_random(f, raw_findings)
        _scan_ssrf(f, raw_findings)
        _scan_unsafe_yaml(f, raw_findings)
        _scan_debug_enabled(f, raw_findings)
        _scan_disabled_csrf(f, raw_findings)
        _scan_missing_auth(f, raw_findings)
        _scan_xss(f, raw_findings)
        _scan_open_redirect(f, raw_findings)

    return _post_process(ctx, raw_findings)


def _post_process(
    ctx: RepositoryContext,
    raw_findings: list[SecurityFinding],
) -> SecurityReport:
    """Apply contextual suppression, calibration, and FP exclusion to raw findings."""
    filtered: list[SecurityFinding] = []

    for finding in raw_findings:
        category = _category_for_cwe(finding.cwe)
        fingerprint = _fp_fingerprint(
            finding.affected_file, finding.affected_lines[0] if finding.affected_lines else 0, category
        )

        if fingerprint in _known_false_positives:
            continue

        in_test = should_suppress(finding.affected_file, finding.affected_lines[0] if finding.affected_lines else 0)

        if not should_report(category, in_test_file=in_test):
            continue

        finding.confidence = calibrate_confidence(
            category,
            finding.confidence,
            in_test_file=in_test,
        )

        if in_test:
            max_sev = Severity.LOW
            if finding.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
                finding.severity = max_sev

        filtered.append(finding)

    return SecurityReport(findings=filtered)


_SECRET_PATTERNS: list[tuple[str, str]] = [
    (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\'][A-Za-z0-9_\-]{8,}["\']', "API key literal"),
    (r'(?i)(secret[_-]?key|secretkey)\s*[:=]\s*["\'][A-Za-z0-9_\-+/]{8,}["\']', "Secret key literal"),
    (r'(?i)(password|passwd)\s*[:=]\s*["\'][^"\']{4,}["\']', "Hardcoded password"),
    (r'(?i)(token)\s*[:=]\s*["\'][A-Za-z0-9_\-\.]{20,}["\']', "Token literal"),
    (r'(?i)(database[_-]?url|db[_-]?url)\s*[:=]\s*["\'][^"\']{10,}["\']', "Database URL with credentials"),
    (r'(?i)(private[_-]?key)\s*[:=]\s*["\'][A-Za-z0-9_\-+/]{20,}["\']', "Private key literal"),
    (r'(?i)(aws[_-]?(access|secret)|AZURE_STORAGE|GOOGLE_APPLICATION_CREDENTIALS)', "Cloud credential pattern"),
]


def _scan_hardcoded_secrets(pf: ParsedFile, findings: list[SecurityFinding]) -> None:
    """Detect hardcoded API keys, tokens, passwords, and other credentials in source code.

    Skips lines referencing os.environ or os.getenv since those are safe env-var reads.
    Uses Shannon entropy to suppress low-quality matches (test keys, placeholders).
    """
    for i, line in enumerate(pf.lines):
        for pattern, name in _SECRET_PATTERNS:
            match = re.search(pattern, line)
            if not match:
                continue
            if "os.getenv" in line or "os.environ" in line:
                continue
            if line.strip().startswith("#"):
                continue

            matched_value = match.group(0)
            if "=" in matched_value or ":" in matched_value:
                parts = re.split(r'[=:]\s*', matched_value, maxsplit=1)
                value_part = parts[1].strip().strip("\"'") if len(parts) > 1 else matched_value
            else:
                value_part = matched_value
            entropy = shannon_entropy(value_part)
            if entropy < ENTROPY_THRESHOLD:
                continue

            findings.append(
                SecurityFinding(
                    severity=Severity.CRITICAL,
                    cwe=CWE["hardcoded_secret"],
                    title=f"Hardcoded secret detected: {name}",
                    description=f"A potential {name} was detected in source code. Shannon entropy: {entropy:.1f}. Secrets in source code can be exposed through version control.",
                    evidence=f"Pattern '{name}' matched at {pf.relative_path}:{i + 1} (entropy {entropy:.1f})",
                    affected_file=pf.relative_path,
                    affected_lines=[i + 1],
                    exploitation_scenario="If this code is committed to a repository, anyone with access can extract the credential.",
                    recommendation="Move the secret to an environment variable or a secrets manager. Use os.environ.get() or a .env file that is gitignored.",
                    confidence=Confidence.MEDIUM,
                )
            )
            break


def _scan_weak_crypto(pf: ParsedFile, findings: list[SecurityFinding]) -> None:
    """Detect use of broken or risky cryptographic algorithms (MD5, SHA-1, DES, RC4, ECB mode)."""
    weak_indicators: list[tuple[str, str, Severity]] = [
        (r'\bhashlib\.md5\b', "MD5 hashing", Severity.HIGH),
        (r'\bhashlib\.sha1\b', "SHA-1 hashing", Severity.MEDIUM),
        (r'\brandom\.(random|choice|randint|shuffle|sample)\b', "Insecure random via random module", Severity.HIGH),
        (r'\bDES\b|\b3DES\b', "DES/3DES encryption", Severity.HIGH),
        (r'\bRC4\b', "RC4 encryption", Severity.CRITICAL),
        (r'\bECB\b', "ECB cipher mode", Severity.HIGH),
    ]
    for i, line in enumerate(pf.lines):
        for pattern, name, severity in weak_indicators:
            if not re.search(pattern, line):
                continue
            if line.strip().startswith("#"):
                continue
            findings.append(
                SecurityFinding(
                    severity=severity,
                    cwe=CWE["weak_crypto"],
                    title=f"Weak cryptography: {name}",
                    description=f"Usage of {name} detected. This is cryptographically weak or broken.",
                    evidence=f"Found in {pf.relative_path}:{i + 1}",
                    affected_file=pf.relative_path,
                    affected_lines=[i + 1],
                    exploitation_scenario="Attackers can exploit weak hashing to perform collision attacks or brute-force hashed values.",
                    recommendation=f"Replace {name} with a modern alternative (e.g., hashlib.sha256, secrets module, AES-GCM).",
                    confidence=Confidence.HIGH,
                )
            )


def _scan_command_injection(pf: ParsedFile, findings: list[SecurityFinding]) -> None:
    """Detect os.system, os.popen, and subprocess calls with shell=True."""
    for i, line in enumerate(pf.lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "os.system(" in stripped or "os.popen(" in stripped:
            findings.append(
                SecurityFinding(
                    severity=Severity.HIGH,
                    cwe=CWE["command_injection"],
                    title="Potential command injection via os.system/os.popen",
                    description="Using os.system() or os.popen() with unsanitized input can lead to command injection.",
                    evidence=f"Found at {pf.relative_path}:{i + 1}",
                    affected_file=pf.relative_path,
                    affected_lines=[i + 1],
                    exploitation_scenario="If user input reaches os.system(), an attacker can inject arbitrary shell commands.",
                    recommendation="Use subprocess.run() with a list of arguments and shell=False instead.",
                    confidence=Confidence.MEDIUM,
                )
            )
        if "shell=True" in stripped and "subprocess" in stripped:
            findings.append(
                SecurityFinding(
                    severity=Severity.HIGH,
                    cwe=CWE["command_injection"],
                    title="Command injection risk: subprocess with shell=True",
                    description="subprocess calls with shell=True are vulnerable to command injection if any argument is user-controlled.",
                    evidence=f"Found at {pf.relative_path}:{i + 1}",
                    affected_file=pf.relative_path,
                    affected_lines=[i + 1],
                    exploitation_scenario="shell=True passes the command string to the system shell, enabling injection if input is not properly sanitized.",
                    recommendation="Use shell=False and pass arguments as a list. If shell=True is unavoidable, use shlex.quote() on all user-supplied arguments.",
                    confidence=Confidence.HIGH,
                )
            )


def _scan_sql_injection(pf: ParsedFile, findings: list[SecurityFinding]) -> None:
    """Detect f-strings, %-formatting, and .format() used in SQL execute calls."""
    for i, line in enumerate(pf.lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if re.search(r'(execute|cursor\.execute)\(f["\']', stripped):
            findings.append(
                SecurityFinding(
                    severity=Severity.CRITICAL,
                    cwe=CWE["sql_injection"],
                    title="Potential SQL injection: f-string in SQL query",
                    description="Using f-strings or string formatting to build SQL queries can lead to SQL injection.",
                    evidence=f"Found at {pf.relative_path}:{i + 1}",
                    affected_file=pf.relative_path,
                    affected_lines=[i + 1],
                    exploitation_scenario="User input interpolated directly into SQL queries allows attackers to read, modify, or delete database contents.",
                    recommendation="Use parameterized queries with placeholders (e.g., cursor.execute('SELECT ... WHERE id = %s', (user_id,))).",
                    confidence=Confidence.MEDIUM,
                )
            )
        if re.search(r'(execute|cursor\.execute)\(.*%s.*%\s', stripped) or re.search(r'(execute|cursor\.execute)\(.*\.format\(', stripped):
            findings.append(
                SecurityFinding(
                    severity=Severity.HIGH,
                    cwe=CWE["sql_injection"],
                    title="Potential SQL injection: string formatting in SQL query",
                    description="Using % formatting or .format() to build SQL queries can lead to SQL injection.",
                    evidence=f"Found at {pf.relative_path}:{i + 1}",
                    affected_file=pf.relative_path,
                    affected_lines=[i + 1],
                    exploitation_scenario="User input interpolated directly into SQL queries allows attackers to execute arbitrary SQL.",
                    recommendation="Use parameterized queries instead of string interpolation.",
                    confidence=Confidence.MEDIUM,
                )
            )


def _scan_unsafe_deserialization(pf: ParsedFile, findings: list[SecurityFinding]) -> None:
    """Detect pickle.loads, pickle.load, and marshal.loads on potentially untrusted data."""
    for i, line in enumerate(pf.lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "pickle.loads(" in stripped or "pickle.load(" in stripped:
            findings.append(
                SecurityFinding(
                    severity=Severity.CRITICAL,
                    cwe=CWE["unsafe_deserialization"],
                    title="Unsafe deserialization: pickle.load/loads",
                    description="pickle.loads() on untrusted data can lead to arbitrary code execution.",
                    evidence=f"Found at {pf.relative_path}:{i + 1}",
                    affected_file=pf.relative_path,
                    affected_lines=[i + 1],
                    exploitation_scenario="An attacker can craft a malicious pickle payload that executes arbitrary Python code when unpickled.",
                    recommendation="Never unpickle untrusted data. Use JSON, msgpack, or another safe serialization format instead.",
                    confidence=Confidence.HIGH,
                )
            )
        if "marshal.loads(" in stripped or "marshal.load(" in stripped:
            findings.append(
                SecurityFinding(
                    severity=Severity.HIGH,
                    cwe=CWE["unsafe_deserialization"],
                    title="Unsafe deserialization: marshal.load/loads",
                    description="marshal.loads() is not secure against malicious data.",
                    evidence=f"Found at {pf.relative_path}:{i + 1}",
                    affected_file=pf.relative_path,
                    affected_lines=[i + 1],
                    recommendation="Use a safe serialization format instead.",
                    confidence=Confidence.MEDIUM,
                )
            )


def _scan_eval_exec(pf: ParsedFile, findings: list[SecurityFinding]) -> None:
    """Detect eval() and exec() calls which can enable arbitrary code execution (CWE-95)."""
    for i, line in enumerate(pf.lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "eval(" in stripped:
            findings.append(
                SecurityFinding(
                    severity=Severity.CRITICAL,
                    cwe=CWE["eval_exec"],
                    title="Dangerous eval() call",
                    description="eval() can execute arbitrary Python code. If any part of the input is user-controlled, this is a critical vulnerability.",
                    evidence=f"Found at {pf.relative_path}:{i + 1}",
                    affected_file=pf.relative_path,
                    affected_lines=[i + 1],
                    exploitation_scenario="An attacker can supply a malicious string to eval() and achieve arbitrary code execution.",
                    recommendation="Remove eval() entirely. If dynamic evaluation is needed, use ast.literal_eval() for safe data structures, or a domain-specific parser.",
                    confidence=Confidence.HIGH,
                )
            )
        if "exec(" in stripped:
            findings.append(
                SecurityFinding(
                    severity=Severity.CRITICAL,
                    cwe=CWE["eval_exec"],
                    title="Dangerous exec() call",
                    description="exec() can execute arbitrary Python code with full access to the process.",
                    evidence=f"Found at {pf.relative_path}:{i + 1}",
                    affected_file=pf.relative_path,
                    affected_lines=[i + 1],
                    exploitation_scenario="Piggybacking DML, config injection, or template injection could feed attacker-controlled code into exec().",
                    recommendation="Remove exec(). Use safe alternatives like importlib for dynamic imports or a domain-specific configuration format.",
                    confidence=Confidence.HIGH,
                )
            )


def _scan_path_traversal(pf: ParsedFile, findings: list[SecurityFinding]) -> None:
    """Detect file open calls using unsanitized request parameters (path traversal)."""
    for i, line in enumerate(pf.lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if re.search(r'open\(.*request\.(args|form|json|get_json)', stripped):
            findings.append(
                SecurityFinding(
                    severity=Severity.HIGH,
                    cwe=CWE["path_traversal"],
                    title="Potential path traversal in file open",
                    description="Opening files using request parameters without path sanitization can lead to path traversal.",
                    evidence=f"Found at {pf.relative_path}:{i + 1}",
                    affected_file=pf.relative_path,
                    affected_lines=[i + 1],
                    exploitation_scenario="An attacker can use '../' sequences to read arbitrary files on the server.",
                    recommendation="Validate and sanitize file paths. Use os.path.basename() or a whitelist of allowed paths.",
                    confidence=Confidence.MEDIUM,
                )
            )


def _scan_insecure_random(pf: ParsedFile, findings: list[SecurityFinding]) -> None:
    """Detect random module usage in security-sensitive contexts (token, key, password generation)."""
    for i, line in enumerate(pf.lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if re.search(r'random\.(choice|choices|sample|shuffle)\s*\(', stripped):
            context_window = "\n".join(pf.lines[max(0, i - 2):min(len(pf.lines), i + 3)])
            if any(sec_word in context_window.lower() for sec_word in ("token", "secret", "password", "key", "auth", "session", "csrf")):
                findings.append(
                    SecurityFinding(
                        severity=Severity.HIGH,
                        cwe=CWE["insecure_random"],
                        title="Insecure randomness for security context",
                        description="random.choice/sample is not cryptographically secure. Use the secrets module instead.",
                        evidence=f"Found at {pf.relative_path}:{i + 1}",
                        affected_file=pf.relative_path,
                        affected_lines=[i + 1],
                        exploitation_scenario="Predictable random values weaken token, key, or session generation.",
                        recommendation="Use secrets.choice(), secrets.token_hex(), or secrets.token_urlsafe() for security-sensitive randomness.",
                        confidence=Confidence.MEDIUM,
                    )
                )


def _scan_ssrf(pf: ParsedFile, findings: list[SecurityFinding]) -> None:
    """Detect HTTP requests to user-controlled URLs (SSRF risk)."""
    for i, line in enumerate(pf.lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if re.search(r'requests\.(get|post|put|delete|head|patch)\s*\(.*request\.(args|form|json)', stripped):
            findings.append(
                SecurityFinding(
                    severity=Severity.HIGH,
                    cwe=CWE["ssrf"],
                    title="Potential SSRF: user-controlled URL in HTTP request",
                    description="Making HTTP requests to URLs provided by the user can lead to SSRF attacks.",
                    evidence=f"Found at {pf.relative_path}:{i + 1}",
                    affected_file=pf.relative_path,
                    affected_lines=[i + 1],
                    exploitation_scenario="An attacker can make the server request internal services, cloud metadata endpoints, or other sensitive resources.",
                    recommendation="Validate and restrict target URLs. Use an allowlist of permitted domains. Block private and loopback IP ranges.",
                    confidence=Confidence.MEDIUM,
                )
            )


def _scan_unsafe_yaml(pf: ParsedFile, findings: list[SecurityFinding]) -> None:
    """Detect yaml.load() without SafeLoader, which enables arbitrary object deserialization."""
    for i, line in enumerate(pf.lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "yaml.load(" in stripped and "SafeLoader" not in stripped and "CSafeLoader" not in stripped:
            findings.append(
                SecurityFinding(
                    severity=Severity.HIGH,
                    cwe=CWE["unsafe_yaml"],
                    title="Unsafe YAML loading",
                    description="yaml.load() without SafeLoader can deserialize arbitrary Python objects, enabling code execution.",
                    evidence=f"Found at {pf.relative_path}:{i + 1}",
                    affected_file=pf.relative_path,
                    affected_lines=[i + 1],
                    exploitation_scenario="An attacker can craft a YAML payload that executes arbitrary Python objects when loaded.",
                    recommendation="Use yaml.safe_load() or yaml.load(..., Loader=yaml.SafeLoader) instead.",
                    confidence=Confidence.HIGH,
                )
            )


def _scan_debug_enabled(pf: ParsedFile, findings: list[SecurityFinding]) -> None:
    """Detect unconditional debug mode enabling (CWE-489)."""
    for i, line in enumerate(pf.lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if re.search(r'(debug|DEBUG)\s*=\s*True', stripped) and "if" not in stripped.lower():
            findings.append(
                SecurityFinding(
                    severity=Severity.MEDIUM,
                    cwe=CWE["debug_enabled"],
                    title="Debug mode enabled",
                    description="Debug mode appears to be unconditionally enabled. This can expose stack traces, configuration, and internal state.",
                    evidence=f"Found at {pf.relative_path}:{i + 1}",
                    affected_file=pf.relative_path,
                    affected_lines=[i + 1],
                    exploitation_scenario="Debug mode can leak sensitive information such as environment variables, file paths, and database queries in error pages.",
                    recommendation="Set debug=False in production. Use an environment variable to control debug mode.",
                    confidence=Confidence.MEDIUM,
                )
            )


def _scan_disabled_csrf(pf: ParsedFile, findings: list[SecurityFinding]) -> None:
    """Detect explicit CSRF exemption on application-wide routes."""
    for i, line in enumerate(pf.lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "csrf.exempt" in stripped.lower() and "app" in stripped:
            findings.append(
                SecurityFinding(
                    severity=Severity.HIGH,
                    cwe=CWE["disabled_csrf"],
                    title="CSRF protection explicitly disabled",
                    description="CSRF exemption was detected. Verify that this is intentional and the endpoint has alternative protections.",
                    evidence=f"Found at {pf.relative_path}:{i + 1}",
                    affected_file=pf.relative_path,
                    affected_lines=[i + 1],
                    exploitation_scenario="If CSRF is disabled on a sensitive endpoint, attackers can perform state-changing actions on behalf of authenticated users.",
                    recommendation="Only exempt endpoints that genuinely need it (e.g., API webhooks). Add alternative protections like token validation.",
                    confidence=Confidence.MEDIUM,
                )
            )


def _scan_missing_auth(pf: ParsedFile, findings: list[SecurityFinding]) -> None:
    """Detect route handlers that may lack authentication decorators (CWE-306)."""
    has_route = False
    has_auth = False
    auth_patterns = [r'@login_required', r'@jwt_required', r'@auth\.require', r'require_auth',
                     r'@admin_required', r'@permission_required', r'@roles_required']
    route_patterns = [r'@app\.route\(', r'@bp\.route\(', r'@blueprint\.route\(',
                      r'@router\.(get|post|put|delete|patch)\(', r'@app\.(get|post|put|delete)\(', r'@app\.websocket\(']
    for i, line in enumerate(pf.lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for rp in route_patterns:
            if re.search(rp, stripped):
                has_route = True
                break
        for ap in auth_patterns:
            if re.search(ap, stripped):
                has_auth = True
                break
        if has_route and not has_auth:
            findings.append(
                SecurityFinding(
                    severity=Severity.MEDIUM,
                    cwe=CWE["missing_auth"],
                    title="Route may lack authentication",
                    description=f"A route is defined at {pf.relative_path}:{i + 1} without a visible authentication decorator.",
                    evidence=f"Found at {pf.relative_path}:{i + 1}",
                    affected_file=pf.relative_path,
                    affected_lines=[i + 1],
                    exploitation_scenario="Unauthenticated users may access sensitive endpoints if no auth guard is applied globally.",
                    recommendation="Apply an authentication decorator (e.g., @login_required) or enforce auth at the middleware/blueprint level.",
                    confidence=Confidence.LOW,
                )
            )
            has_route = False
            has_auth = False


def _scan_xss(pf: ParsedFile, findings: list[SecurityFinding]) -> None:
    """Detect potential XSS vectors: unescaped user input in HTML responses (CWE-79)."""
    xss_patterns = [
        (r'render_template_string\(.*request\.(args|form|json)', "Unescaped template rendering with user input"),
        (r'Markup\(.*request\.(args|form|json)', "Markup() with user input bypasses escaping"),
        (r'\.html\s*=\s*.*request\.(args|form|json)', "Direct HTML assignment from user input"),
        (r'innerHTML|dangerouslySetInnerHTML', "Unsafe DOM manipulation"),
    ]
    for i, line in enumerate(pf.lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for pattern, label in xss_patterns:
            if re.search(pattern, stripped):
                findings.append(
                    SecurityFinding(
                        severity=Severity.HIGH,
                        cwe=CWE["xss"],
                        title=f"Potential XSS: {label}",
                        description=f"Unescaped user input may enable cross-site scripting at {pf.relative_path}:{i + 1}.",
                        evidence=f"Found at {pf.relative_path}:{i + 1}",
                        affected_file=pf.relative_path,
                        affected_lines=[i + 1],
                        exploitation_scenario="An attacker can inject malicious scripts that execute in victims' browsers.",
                        recommendation="Always escape user input before rendering in HTML. Use template auto-escaping or sanitization libraries.",
                        confidence=Confidence.MEDIUM,
                    )
                )
                break


def _scan_open_redirect(pf: ParsedFile, findings: list[SecurityFinding]) -> None:
    """Detect potential open redirect vulnerabilities (CWE-601)."""
    redirect_patterns = [
        (r'redirect\(.*request\.(args|form|json)', "User-controlled redirect target"),
        (r'flask\.redirect\(.*request\.(args|form|json)', "Flask redirect with user input"),
        (r'HttpResponseRedirect\(.*request\.(args|form|json)', "Django redirect with user input"),
    ]
    for i, line in enumerate(pf.lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for pattern, label in redirect_patterns:
            if re.search(pattern, stripped):
                findings.append(
                    SecurityFinding(
                        severity=Severity.MEDIUM,
                        cwe=CWE["open_redirect"],
                        title=f"Potential open redirect: {label}",
                        description=f"User-controlled input used in redirect at {pf.relative_path}:{i + 1}.",
                        evidence=f"Found at {pf.relative_path}:{i + 1}",
                        affected_file=pf.relative_path,
                        affected_lines=[i + 1],
                        exploitation_scenario="Attackers can craft URLs that redirect victims to malicious sites while appearing to come from a trusted domain.",
                        recommendation="Validate redirect URLs against a whitelist of allowed domains. Use urlparse to check the netloc.",
                        confidence=Confidence.MEDIUM,
                    )
                )
                break
