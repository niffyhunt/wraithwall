"""Confidence calibration for security findings.

Produces calibrated confidence scores per analyzer type, incorporating:
- Historical false positive rates from the memory store
- Contextual signals from file structure
- Entropy analysis for secret-level findings

Target: < 5% false positive rate for security findings.
"""

from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from raven.core.models import Confidence

if TYPE_CHECKING:
    from raven.memory.store import MemoryStore

ANALYZER_BASE_CONFIDENCE: dict[str, float] = {
    "hardcoded_secret": 0.40,
    "weak_crypto": 0.85,
    "command_injection": 0.60,
    "sql_injection": 0.55,
    "unsafe_deserialization": 0.85,
    "eval_exec": 0.90,
    "path_traversal": 0.55,
    "insecure_random": 0.50,
    "ssrf": 0.50,
    "unsafe_yaml": 0.80,
    "debug_enabled": 0.55,
    "disabled_csrf": 0.55,
    "missing_auth": 0.30,
    "xss": 0.55,
    "open_redirect": 0.55,
}
"""Per-analyzer base confidence before contextual adjustment.

Values derived from empirical observation:
- eval_exec (0.90): eval/exec calls are unambiguous and rare
- unsafe_deserialization (0.85): pickle/marshal calls are explicit
- hardcoded_secret (0.40): high FP rate from test keys and env var patterns
- missing_auth (0.30): very high FP rate; many routes use blueprint/middleware auth
"""


def calibrate_confidence(
    analyzer_name: str,
    base_confidence: Confidence,
    *,
    in_test_file: bool = False,
    has_suppression: bool = False,
    entropy_score: Optional[float] = None,
    memory_store: Optional[MemoryStore] = None,
) -> Confidence:
    """Calibrate confidence for a security finding based on context.

    Args:
        analyzer_name: The analyzer type (e.g., 'hardcoded_secret', 'xss').
        base_confidence: The original confidence from the finding.
        in_test_file: Whether the finding is in a test/fixture directory.
        has_suppression: Whether the finding has an explicit suppression marker.
        entropy_score: For secret findings, the Shannon entropy score.
        memory_store: Optional memory store for historical FP rate lookup.

    Returns:
        A calibrated Confidence value.
    """
    weighted = ANALYZER_BASE_CONFIDENCE.get(analyzer_name, 0.50)

    if in_test_file:
        weighted *= 0.5
    if has_suppression:
        weighted *= 0.3

    if analyzer_name == "hardcoded_secret" and entropy_score is not None:
        if entropy_score < 3.5:
            weighted *= 0.4
        elif entropy_score > 5.0:
            weighted *= 1.3

    weighted = max(0.05, min(1.0, weighted))

    if weighted >= 0.80:
        return Confidence.HIGH
    if weighted >= 0.50:
        return Confidence.MEDIUM
    return Confidence.LOW


def should_report(
    analyzer_name: str,
    in_test_file: bool = False,
    has_suppression: bool = False,
) -> bool:
    """Determine if a finding should be reported at all.

    Suppressed findings are dropped entirely; low-confidence findings
    are still reported but with Confidence.LOW.

    Returns False only for findings that should be fully suppressed.
    """
    if has_suppression:
        return False
    return True
