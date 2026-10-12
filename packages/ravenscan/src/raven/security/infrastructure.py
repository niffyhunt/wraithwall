"""Static infrastructure and supply-chain-adjacent checks.

These checks inspect configuration text only. They report concrete risky
configuration, never claim an exploitable deployment, and never execute files.
"""

from __future__ import annotations

import re

from raven.core.context import RepositoryContext, ParsedFile
from raven.core.models import CweReference, Confidence, SecurityFinding, SecurityReport, Severity

CWE = {
    "container_privilege": CweReference(cwe_id="CWE-250", name="Execution with Unnecessary Privileges", url="https://cwe.mitre.org/data/definitions/250.html"),
    "sensitive_data": CweReference(cwe_id="CWE-312", name="Cleartext Storage of Sensitive Information", url="https://cwe.mitre.org/data/definitions/312.html"),
    "network_exposure": CweReference(cwe_id="CWE-668", name="Exposure of Resource to Wrong Sphere", url="https://cwe.mitre.org/data/definitions/668.html"),
    "overly_permissive": CweReference(cwe_id="CWE-732", name="Incorrect Permission Assignment for Critical Resource", url="https://cwe.mitre.org/data/definitions/732.html"),
    "supply_chain": CweReference(cwe_id="CWE-829", name="Inclusion of Functionality from Untrusted Control Sphere", url="https://cwe.mitre.org/data/definitions/829.html"),
}


def _finding(pf: ParsedFile, line: int, cwe_key: str, title: str, description: str, severity: Severity, recommendation: str) -> SecurityFinding:
    cwe = CWE[cwe_key]
    return SecurityFinding(
        severity=severity,
        cwe=cwe,
        title=title,
        description=description,
        evidence=f"Configuration pattern matched at {pf.relative_path}:{line}",
        affected_file=pf.relative_path,
        affected_lines=[line],
        recommendation=recommendation,
        confidence=Confidence.HIGH,
        analyzer="infrastructure",
        rule_id=f"infrastructure:{cwe.cwe_id}",
        identity_context=f"{cwe_key}:{cwe.cwe_id}",
    )


def analyze_infrastructure(ctx: RepositoryContext) -> SecurityReport:
    findings: list[SecurityFinding] = []
    for pf in ctx.files:
        name = pf.relative_path.lower()
        is_docker = pf.relative_path == "Dockerfile" or name.endswith(("docker-compose.yml", "docker-compose.yaml"))
        is_iac = name.endswith((".yaml", ".yml", ".tf", ".tfvars")) or name in {"dockerfile"}
        if not is_iac:
            continue
        for index, line in enumerate(pf.lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//")):
                continue
            lowered = stripped.lower()
            if is_docker and re.search(r"\buser\s+root\b", lowered):
                findings.append(_finding(pf, index, "container_privilege", "Container explicitly runs as root", "The container configuration selects the root user, increasing impact if the process is compromised.", Severity.HIGH, "Create a dedicated non-root user and set USER explicitly."))
            if is_docker and re.search(r"\b(add|copy)\s+https?://", lowered):
                findings.append(_finding(pf, index, "supply_chain", "Container build downloads remote content", "A Docker build instruction downloads content from a remote URL without a repository-pinned integrity check.", Severity.MEDIUM, "Pin trusted artifacts by digest and verify checksums before use."))
            if re.search(r"privileged\s*:\s*true", lowered) or re.search(r"hostnetwork\s*:\s*true", lowered):
                findings.append(_finding(pf, index, "container_privilege", "Privileged or host-network workload", "This workload requests host-level privileges or network access, expanding blast radius.", Severity.HIGH, "Remove privileged/hostNetwork unless required and enforce a restrictive pod security policy."))
            if re.search(r"0\.0\.0\.0/0", lowered) or re.search(r"::/0", lowered):
                findings.append(_finding(pf, index, "network_exposure", "Infrastructure allows unrestricted network exposure", "A security group, firewall, or route rule allows traffic from every IPv4 or IPv6 source.", Severity.HIGH, "Restrict ingress and egress to documented networks and ports."))
            if re.search(r"(password|secret|token|api[_-]?key)\s*:\s*[^$<{\"']\S+", lowered) and not re.search(r"(env|secretkeyref|secret_key_ref|var\.)", lowered):
                findings.append(_finding(pf, index, "sensitive_data", "Potential plaintext infrastructure secret", "A configuration value appears to place a credential directly in an infrastructure file.", Severity.HIGH, "Use a secret reference or external secret manager; do not commit plaintext credentials."))
            if name.endswith((".tf", ".tfvars")) and re.search(r"source\s*=\s*\"https?://", lowered):
                findings.append(_finding(pf, index, "supply_chain", "Terraform module uses an unpinned URL source", "An IaC module source is fetched from a URL without visible immutable pinning.", Severity.MEDIUM, "Pin modules to a version, commit, or digest and verify provenance."))
    return SecurityReport(findings=findings)
