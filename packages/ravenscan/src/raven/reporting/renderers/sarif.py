"""SARIF 2.1.0 rendering for Raven security findings."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from raven.core.models import SecurityReport


def render_sarif(report: SecurityReport, indent: int = 2) -> str:
    """Render a SecurityReport as SARIF JSON without changing Raven JSON output."""
    import json

    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in report.findings:
        rule_id = finding.rule_id or finding.cwe.cwe_id or finding.finding_id
        if rule_id.lower().startswith("cwe-"):
            rule_id = finding.cwe.cwe_id or rule_id.upper()
        rule = rules.setdefault(rule_id, {
            "id": rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "properties": {"analyzer": finding.analyzer, "cwe": finding.cwe.cwe_id},
        })
        if finding.cwe.url:
            rule["helpUri"] = finding.cwe.url
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(finding.severity.value, "warning"),
            "message": {"text": finding.description},
            "fingerprints": {"ravenFindingId": finding.finding_id},
            "properties": {
                "cwe": finding.cwe.cwe_id,
                "confidence": finding.confidence.value,
                "historicalState": finding.historical_state,
                "priority": finding.priority,
                "priorityScore": finding.priority_score,
                "exposure": finding.exposure,
                "attackPathIds": finding.attack_path_ids,
                "provenance": finding.provenance,
                "remediationEvidence": finding.remediation_evidence,
            },
        }
        if finding.affected_file:
            line = finding.affected_lines[0] if finding.affected_lines else 1
            result["locations"] = [{"physicalLocation": {
                "artifactLocation": {"uri": quote(finding.affected_file, safe="/$.-_~")},
                "region": {"startLine": line},
            }}]
        results.append(result)

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "RavenScan",
                "version": "0.1.0",
                "informationUri": "https://github.com/niffyhunt/wraithwall/tree/main/packages/ravenscan",
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {"schemaVersion": report.schema_version},
        }],
    }
    return json.dumps(payload, indent=indent)
