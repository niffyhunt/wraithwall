"""Honeypot -> MITRE: structured ATT&CK, a threat score, and replay dedup from raw honeypot logs.

A small, dependency-free library that turns raw Cowrie SSH/Telnet honeypot JSON
logs into structured intelligence:

* reconstruct per-session command sequences (:func:`parse_sessions`);
* map commands to MITRE ATT&CK tactics/techniques (:func:`map_techniques`);
* compute a deterministic threat score (:func:`score_session`);
* apply behavioral actor overrides (:func:`classify_actor`);
* collapse identical-payload replays into one alert (:func:`dedup_key`,
  :class:`InMemoryDedupStore`).

The default path is fully deterministic and pure-stdlib. An optional LLM
enrichment step is available behind the :class:`Analyzer` protocol (install the
``[llm]`` extra). Nothing here imports a web framework, Redis, or ``anthropic``
at import time.

Part of the WraithWall project — https://wraithwall.online · by niffy_hunt
"""

from __future__ import annotations

from .actors import baseline_actor_label, classify_actor
from .analyzer import (
    ANALYZER_PROMPT_TEMPLATE,
    AnthropicAnalyzer,
    Analyzer,
    NullAnalyzer,
)
from .dedup import (
    DEFAULT_DEDUP_WINDOW,
    DedupStore,
    InMemoryDedupStore,
    RedisDedupStore,
    dedup_key,
)
from .mitre import (
    DANGER_SCORES,
    HIGH_RISK_STAGES,
    MITRE_TECHNIQUES,
    TACTIC_ORDER,
    TECHNIQUE_CONFIDENCE,
)
from .parsing import Session, parse_events, parse_lines, parse_sessions
from .pipeline import analyze_session
from .scoring import classify_command, map_techniques, score_session

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # parsing
    "Session",
    "parse_sessions",
    "parse_events",
    "parse_lines",
    # mapping / scoring
    "classify_command",
    "map_techniques",
    "score_session",
    "MITRE_TECHNIQUES",
    "DANGER_SCORES",
    "HIGH_RISK_STAGES",
    "TACTIC_ORDER",
    "TECHNIQUE_CONFIDENCE",
    # actors
    "classify_actor",
    "baseline_actor_label",
    # dedup
    "dedup_key",
    "DedupStore",
    "InMemoryDedupStore",
    "RedisDedupStore",
    "DEFAULT_DEDUP_WINDOW",
    # analyzer (optional)
    "Analyzer",
    "NullAnalyzer",
    "AnthropicAnalyzer",
    "ANALYZER_PROMPT_TEMPLATE",
    # high-level
    "analyze_session",
]
