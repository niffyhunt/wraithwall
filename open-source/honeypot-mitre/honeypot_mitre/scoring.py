"""Deterministic technique mapping and threat scoring.

Everything here is pure-function and dependency-free. The two public entry
points are :func:`map_techniques` (command list -> MITRE classification) and
:func:`score_session` (the deterministic threat score).

The score formula is preserved verbatim from the original pipeline::

    score = base_for_stage + (commands * 2) + (distinct_techniques * 3)

capped at 100, where ``base_for_stage`` is taken from
:data:`honeypot_mitre.mitre.DANGER_SCORES` for the *dominant* (most-recently
reached) kill-chain stage, defaulting to ``5`` for an unknown stage.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from .mitre import (
    DANGER_SCORES,
    DEFAULT_BASE_SCORE,
    MITRE_TECHNIQUES,
    TECHNIQUE_CONFIDENCE,
)


def classify_command(command: str) -> Dict[str, Any]:
    """Classify a single command line against the MITRE substring table.

    Iterates stages in table order; the first stage with a substring hit wins
    (one match per command, mirroring the original implementation).

    Args:
        command: A single shell command line.

    Returns:
        A dict with ``stage``, ``tactic_id``, ``techniques``, ``prerequisites``,
        ``confidence`` and ``matched_pattern``. ``stage`` is ``'unknown'`` and
        ``confidence`` is ``0.0`` when nothing matches.
    """
    cmd_lower = command.lower().strip()

    for stage, data in MITRE_TECHNIQUES.items():
        for pattern in data['commands']:
            if pattern.lower() in cmd_lower:
                return {
                    'stage': stage,
                    'tactic_id': data['id'],
                    'techniques': data['techniques'],
                    'prerequisites': data.get('prerequisites', []),
                    'confidence': TECHNIQUE_CONFIDENCE,
                    'matched_pattern': pattern,
                }

    return {
        'stage': 'unknown',
        'tactic_id': None,
        'techniques': [],
        'prerequisites': [],
        'confidence': 0.0,
        'matched_pattern': None,
    }


def map_techniques(commands: List[str]) -> Dict[str, Any]:
    """Map a session's command sequence to MITRE tactics/techniques.

    Args:
        commands: Ordered list of command lines from one session.

    Returns:
        A dict with:

        * ``dominant_stage``: the most-recently reached known stage
          (``'unknown'`` if none matched);
        * ``progression``: de-duplicated run-length-compressed stage sequence;
        * ``techniques_used``: sorted list of distinct technique ids;
        * ``confidence``: average per-match confidence (rounded to 3 dp);
        * ``commands_analyzed``: number of commands that matched a stage.
    """
    stages_seen: List[str] = []
    techniques_seen: Set[str] = set()
    total_confidence = 0.0
    count = 0

    for cmd in commands:
        result = classify_command(cmd)
        if result['stage'] != 'unknown':
            if not stages_seen or stages_seen[-1] != result['stage']:
                stages_seen.append(result['stage'])
            techniques_seen.update(result.get('techniques', []))
            total_confidence += result['confidence']
            count += 1

    dominant_stage = stages_seen[-1] if stages_seen else 'unknown'
    avg_confidence = total_confidence / count if count > 0 else 0.0

    return {
        'dominant_stage': dominant_stage,
        'progression': stages_seen,
        'techniques_used': sorted(techniques_seen),
        'confidence': round(avg_confidence, 3),
        'commands_analyzed': count,
    }


def score_session(commands: List[str], mapping: Optional[Dict[str, Any]] = None) -> int:
    """Compute the deterministic threat score for a session.

    Formula (verbatim, capped at 100)::

        score = DANGER_SCORES[dominant_stage] + len(commands) * 2
                + distinct_techniques * 3

    An empty command list scores ``0``.

    Args:
        commands: Ordered list of command lines from one session.
        mapping: Optional precomputed :func:`map_techniques` result, to avoid
            recomputing it.

    Returns:
        Integer threat score in ``0..100``.
    """
    if not commands:
        return 0

    if mapping is None:
        mapping = map_techniques(commands)

    stage = mapping['dominant_stage']
    technique_count = len(mapping['techniques_used'])
    base_score = DANGER_SCORES.get(stage, DEFAULT_BASE_SCORE)

    return min(base_score + len(commands) * 2 + technique_count * 3, 100)
