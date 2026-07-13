"""Shannon entropy calculator for distinguishing real secrets from coincidental string matches.

High-entropy strings are statistically more likely to be real API keys, tokens,
or cryptographic material. Low-entropy strings matching regex patterns (e.g.,
'password=test', 'api_key=demo') are likely false positives.

Reference: Shannon, C.E. (1948). A Mathematical Theory of Communication.
"""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: str) -> float:
    """Compute the Shannon entropy of a string.

    Returns a value between 0.0 (completely predictable) and ~8.0 (random bytes).
    Real API keys and tokens typically score above 4.5.
    Placeholder/test values ('password=test', 'key=abc123') typically score below 3.0.
    """
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def classify_secret_strength(value: str) -> tuple[float, str]:
    """Classify a secret value based on entropy.

    Returns:
        (entropy_score, classification) where classification is one of:
        'strong' — high entropy, likely real secret
        'moderate' — medium entropy, plausible
        'weak' — low entropy, likely test/debug/placeholder
    """
    score = shannon_entropy(value)
    if score >= 4.5:
        return score, "strong"
    if score >= 3.0:
        return score, "moderate"
    return score, "weak"


ENTROPY_THRESHOLD = 3.5
"""Minimum entropy to treat a regex-matched secret as a genuine finding.

Matches below this threshold are suppressed as false positives (e.g., test keys,
placeholder values in documentation).
"""
