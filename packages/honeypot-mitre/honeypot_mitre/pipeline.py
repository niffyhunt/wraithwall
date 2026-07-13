"""High-level convenience: turn a parsed session into a full intelligence record.

This stitches together the deterministic building blocks (mapping, scoring,
actor classification, dedup key) into one record. An optional :class:`Analyzer`
can be passed to layer LLM enrichment on top — but it never affects the
deterministic score.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .actors import classify_actor
from .analyzer import Analyzer
from .dedup import dedup_key
from .parsing import Session
from .scoring import map_techniques, score_session


def analyze_session(session: Any, analyzer: Optional[Analyzer] = None) -> Dict[str, Any]:
    """Produce a full intelligence record for a single session.

    Args:
        session: A :class:`~honeypot_mitre.parsing.Session` or a session dict
            (as produced by :meth:`Session.to_dict`).
        analyzer: Optional :class:`~honeypot_mitre.analyzer.Analyzer`. If given,
            its output is merged under an ``"llm"`` key; it never changes the
            deterministic score or the deterministic actor label.

    Returns:
        A dict with ``session_id``, ``src_ip``, ``commands``, ``techniques``,
        ``dominant_stage``, ``progression``, ``confidence``, ``score``,
        ``actor_label``, ``campaign_indicators``, ``dedup_key`` and (optionally)
        ``llm``.
    """
    data = session.to_dict() if isinstance(session, Session) else dict(session)
    commands = data.get('commands', []) or []

    mapping = map_techniques(commands)
    score = score_session(commands, mapping)
    actor = classify_actor(commands, duration=data.get('duration', 0))

    record: Dict[str, Any] = {
        'session_id': data.get('session_id', ''),
        'src_ip': data.get('src_ip', ''),
        'commands': commands,
        'techniques': mapping['techniques_used'],
        'dominant_stage': mapping['dominant_stage'],
        'progression': mapping['progression'],
        'confidence': mapping['confidence'],
        'score': score,
        'actor_label': actor['actor_label'],
        'campaign_indicators': actor['campaign_indicators'],
        'dedup_key': dedup_key(commands),
    }

    if analyzer is not None:
        enrichment = analyzer.analyze(data)
        if enrichment:
            record['llm'] = enrichment

    return record
