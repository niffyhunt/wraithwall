"""
Command Transition Markov Model — vector_transitions.

Builds bigram and trigram Markov models over historical command sequences
from Cowrie sessions. Stores model state in Redis (serialized JSON) with
training metadata. Enforces a minimum-data guard: below a configurable
minimum number of training sessions, all outputs are tagged
insufficient_data=True and must not be surfaced as confident signals
to UNISON/CRYSTAL.
"""

from __future__ import annotations

import json
import logging
import math
import os
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

REDIS_URL: str = os.environ.get("REDIS_URL", "")
VECTOR_MIN_SESSIONS: int = int(os.environ.get("VECTOR_MIN_SESSIONS", "500"))
VECTOR_RETRAIN_SECONDS: int = int(os.environ.get("VECTOR_RETRAIN_SECONDS", "604800"))
REDIS_KEY: str = "vector_transitions_model"

_bigram_matrix: Dict[str, Dict[str, int]] = {}
_trigram_matrix: Dict[str, Dict[str, int]] = {}
_training_session_count: int = 0
_trained_at: float = 0.0
_loaded: bool = False

def _get_redis():
    if not REDIS_URL:
        return None
    try:
        import redis as redis_lib
        return redis_lib.from_url(
            REDIS_URL,
            socket_connect_timeout=3,
            socket_timeout=5,
            decode_responses=True,
        )
    except Exception as e:
        logger.debug(f"Redis unavailable for vector_transitions: {e}")
        return None

def _normalize_command(raw: str) -> str:
    """Strip arguments, normalize paths, lowercase."""
    stripped = raw.strip()
    if not stripped:
        return ""
    first_token = stripped.split(maxsplit=1)[0]
    basename = first_token.rsplit("/", maxsplit=1)[-1]
    return basename.lower()

def _tokenize_session(commands: List[str]) -> List[str]:
    """Normalize a sequence of raw commands into tokens."""
    return [_normalize_command(c) for c in commands if _normalize_command(c)]

def _lazy_load() -> None:
    """Load model from Redis into module globals if not already loaded."""
    global _bigram_matrix, _trigram_matrix, _training_session_count, _trained_at, _loaded
    if _loaded:
        return
    data = load_model()
    if data:
        _bigram_matrix = data.get("bigram_matrix", {})
        _trigram_matrix = data.get("trigram_matrix", {})
        _training_session_count = data.get("training_session_count", 0)
        _trained_at = data.get("trained_at", 0.0)
    _loaded = True

def _bigram_probability(prev_cmd: str, next_cmd: str) -> float:
    """Probability of next_cmd given prev_cmd with add-1 Laplace smoothing.

    Returns 0.0 when prev_cmd is entirely unseen in the model.
    """
    if prev_cmd not in _bigram_matrix:
        return 0.0
    targets = _bigram_matrix[prev_cmd]
    total = sum(targets.values())
    if total == 0:
        return 0.0
    count = targets.get(next_cmd, 0)
    vocab_size = len(_bigram_matrix)
    return (count + 1.0) / (total + vocab_size)

def _trigram_probability(prev_pair: str, next_cmd: str) -> float:
    """Probability of next_cmd given two previous commands with add-1 Laplace smoothing.

    Returns 0.0 when prev_pair is entirely unseen in the model.
    """
    if prev_pair not in _trigram_matrix:
        return 0.0
    targets = _trigram_matrix[prev_pair]
    total = sum(targets.values())
    if total == 0:
        return 0.0
    count = targets.get(next_cmd, 0)
    vocab_size = len(_bigram_matrix) if _bigram_matrix else 1
    return (count + 1.0) / (total + vocab_size)

def train_model(sessions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build bigram and trigram transition matrices from session command sequences.

    Each session dict is expected to contain a "commands" key whose value
    is a list of raw command strings. Sessions with fewer than one
    normalized command are skipped.

    Args:
        sessions: List of session dicts with command history.

    Returns:
        Dict with training summary: session_count, bigram_pairs,
        trigram_pairs, trained_at.
    """
    global _bigram_matrix, _trigram_matrix, _training_session_count, _trained_at

    bigram: Dict[str, Dict[str, int]] = {}
    trigram: Dict[str, Dict[str, int]] = {}
    valid_sessions = 0

    for session in sessions:
        raw_commands: List[str] = session.get("commands", [])
        tokens = _tokenize_session(raw_commands)
        if len(tokens) < 1:
            continue
        valid_sessions += 1

        for i in range(len(tokens) - 1):
            a, b = tokens[i], tokens[i + 1]
            bigram.setdefault(a, {})
            bigram[a][b] = bigram[a].get(b, 0) + 1

            if i < len(tokens) - 2:
                c = tokens[i + 2]
                key = f"{a}||{b}"
                trigram.setdefault(key, {})
                trigram[key][c] = trigram[key].get(c, 0) + 1

    _bigram_matrix = bigram
    _trigram_matrix = trigram
    _training_session_count = valid_sessions
    _trained_at = time.time()

    bigram_pairs = sum(len(targets) for targets in bigram.values())
    trigram_pairs = sum(len(targets) for targets in trigram.values())

    logger.info(
        "vector_transitions trained: sessions=%d bigram_pairs=%d trigram_pairs=%d",
        valid_sessions,
        bigram_pairs,
        trigram_pairs,
    )

    return {
        "session_count": valid_sessions,
        "bigram_pairs": bigram_pairs,
        "trigram_pairs": trigram_pairs,
        "trained_at": _trained_at,
    }

def sequence_likelihood(commands: List[str]) -> Dict[str, Any]:
    """Compute the log-probability of a command sequence given the model.

    Uses trigram transition probabilities with bigram backoff.
    Probability values are computed lazily from stored transition counts
    using add-1 Laplace smoothing.

    Args:
        commands: List of raw command strings.

    Returns:
        Dict with keys:
            log_probability: float — sum of log-probabilities over all transitions.
            per_step: List[float] — individual transition probabilities.
            insufficient_data: bool — True when below VECTOR_MIN_SESSIONS.
            model_stale: bool — True when retraining interval has elapsed.
            session_count: int — sessions used to train the model.
    """
    _lazy_load()

    tokens = _tokenize_session(commands)

    result: Dict[str, Any] = {
        "log_probability": 0.0,
        "per_step": [],
        "insufficient_data": True,
        "model_stale": needs_retraining(),
        "session_count": _training_session_count,
    }

    if _training_session_count < VECTOR_MIN_SESSIONS or not _bigram_matrix:
        return result

    result["insufficient_data"] = False

    if len(tokens) < 2:
        return result

    log_prob = 0.0
    per_step: List[float] = []

    prob = _bigram_probability(tokens[0], tokens[1])
    if prob > 0:
        log_prob += math.log(prob)
    per_step.append(prob)

    for i in range(2, len(tokens)):
        prev_a = tokens[i - 2]
        prev_b = tokens[i - 1]
        current = tokens[i]
        pair_key = f"{prev_a}||{prev_b}"

        tri_prob = _trigram_probability(pair_key, current)
        if tri_prob > 0:
            log_prob += math.log(tri_prob)
            per_step.append(tri_prob)
        else:
            bi_prob = _bigram_probability(prev_b, current)
            if bi_prob > 0:
                log_prob += math.log(bi_prob)
                per_step.append(bi_prob)
            else:
                per_step.append(0.0)

    result["log_probability"] = log_prob
    result["per_step"] = per_step

    return result

def anomalous_step(
    commands: List[str],
    threshold: float = 0.01,
) -> Dict[str, Any]:
    """Find the first command transition whose probability falls below threshold.

    Scans transitions left-to-right. First transition uses bigram;
    subsequent transitions prefer trigram with bigram backoff.

    Args:
        commands: List of raw command strings.
        threshold: Probability below which a transition is flagged anomalous.

    Returns:
        Dict with keys:
            index: Optional[int] — position of the anomalous command (0-based).
            command: Optional[str] — the anomalous normalized command.
            transition: Optional[str] — human-readable transition description.
            probability: Optional[float] — computed transition probability.
            threshold: float — the threshold used.
            is_anomalous: bool — whether an anomaly was detected.
            insufficient_data: bool — True when below VECTOR_MIN_SESSIONS.
    """
    _lazy_load()

    tokens = _tokenize_session(commands)

    result: Dict[str, Any] = {
        "index": None,
        "command": None,
        "transition": None,
        "probability": None,
        "threshold": threshold,
        "is_anomalous": False,
        "insufficient_data": True,
    }

    if _training_session_count < VECTOR_MIN_SESSIONS or not _bigram_matrix:
        return result

    result["insufficient_data"] = False

    if len(tokens) < 2:
        return result

    prob = _bigram_probability(tokens[0], tokens[1])
    if prob < threshold:
        result["index"] = 1
        result["command"] = tokens[1]
        result["transition"] = f"{tokens[0]} -> {tokens[1]}"
        result["probability"] = prob
        result["is_anomalous"] = True
        return result

    for i in range(2, len(tokens)):
        prev_a = tokens[i - 2]
        prev_b = tokens[i - 1]
        current = tokens[i]
        pair_key = f"{prev_a}||{prev_b}"

        prob = _trigram_probability(pair_key, current)
        if prob == 0.0:
            prob = _bigram_probability(prev_b, current)

        if prob < threshold:
            result["index"] = i
            result["command"] = current
            result["transition"] = f"{prev_a} -> {prev_b} -> {current}"
            result["probability"] = prob
            result["is_anomalous"] = True
            return result

    return result

def predict_next_command(commands: List[str]) -> Dict[str, Any]:
    """Predict the most likely next command given a command sequence.

    Uses trigram when at least two previous commands are available;
    falls back to bigram otherwise. Probabilities are computed lazily
    from stored transition counts with add-1 Laplace smoothing.

    Args:
        commands: List of raw command strings.

    Returns:
        Dict with keys:
            next_command: Optional[str] — the most likely next command.
            probability: Optional[float] — its probability.
            candidates: List[Tuple[str, float]] — top 5 candidates ranked.
            order: Optional[str] — "bigram" or "trigram".
            insufficient_data: bool — True when below VECTOR_MIN_SESSIONS.
    """
    _lazy_load()

    result: Dict[str, Any] = {
        "next_command": None,
        "probability": None,
        "candidates": [],
        "order": None,
        "insufficient_data": True,
    }

    if _training_session_count < VECTOR_MIN_SESSIONS or not _bigram_matrix:
        return result

    result["insufficient_data"] = False

    tokens = _tokenize_session(commands)
    if not tokens:
        return result

    candidates: List[Tuple[str, float]] = []

    if len(tokens) >= 2:
        pair_key = f"{tokens[-2]}||{tokens[-1]}"
        if pair_key in _trigram_matrix:
            targets = _trigram_matrix[pair_key]
            total = sum(targets.values())
            vocab_size = len(_bigram_matrix)
            for cmd, count in targets.items():
                prob = (count + 1.0) / (total + vocab_size)
                candidates.append((cmd, prob))
            if candidates:
                candidates.sort(key=lambda x: x[1], reverse=True)
                result["order"] = "trigram"
                result["next_command"] = candidates[0][0]
                result["probability"] = candidates[0][1]
                result["candidates"] = candidates[:5]
                return result

    last_cmd = tokens[-1]
    if last_cmd in _bigram_matrix:
        targets = _bigram_matrix[last_cmd]
        total = sum(targets.values())
        vocab_size = len(_bigram_matrix)
        for cmd, count in targets.items():
            prob = (count + 1.0) / (total + vocab_size)
            candidates.append((cmd, prob))

    if candidates:
        candidates.sort(key=lambda x: x[1], reverse=True)
        result["order"] = "bigram"
        result["next_command"] = candidates[0][0]
        result["probability"] = candidates[0][1]
        result["candidates"] = candidates[:5]

    return result

def save_model() -> bool:
    """Persist the current model state to Redis as serialized JSON.

    Serializes bigram_matrix, trigram_matrix, training_session_count,
    trained_at, and a schema version number under REDIS_KEY.

    Returns:
        True if the model was saved successfully, False otherwise.
    """
    r = _get_redis()
    if r is None:
        logger.warning("vector_transitions: cannot save model — Redis unavailable")
        return False

    payload = {
        "bigram_matrix": _bigram_matrix,
        "trigram_matrix": _trigram_matrix,
        "training_session_count": _training_session_count,
        "trained_at": _trained_at,
        "version": 1,
    }

    try:
        r.set(REDIS_KEY, json.dumps(payload))
        logger.info(
            "vector_transitions model saved to Redis: sessions=%d",
            _training_session_count,
        )
        return True
    except Exception as e:
        logger.error(f"vector_transitions: failed to save model: {e}")
        return False

def load_model() -> Optional[Dict[str, Any]]:
    """Load the model state from Redis.

    Returns:
        The deserialized model dict, or None if no model exists or
        Redis is unavailable.
    """
    r = _get_redis()
    if r is None:
        return None

    try:
        raw = r.get(REDIS_KEY)
        if raw is None:
            return None
        return json.loads(raw)
    except Exception as e:
        logger.error(f"vector_transitions: failed to load model: {e}")
        return None

def is_model_ready() -> Dict[str, Any]:
    """Check whether the model meets minimum data requirements and is not stale.

    A model is ready when it has been trained on at least
    VECTOR_MIN_SESSIONS sessions and the retraining interval
    has not elapsed.

    Returns:
        Dict with keys:
            ready: bool — True when sufficient data and not stale.
            session_count: int — sessions used to train the model.
            trained_at: Optional[float] — epoch timestamp of last training.
            stale: bool — True when retraining interval has elapsed.
            insufficient_data: bool — True when below VECTOR_MIN_SESSIONS.
    """
    _lazy_load()

    stale = needs_retraining()
    sufficient = (
        _training_session_count >= VECTOR_MIN_SESSIONS
        and len(_bigram_matrix) > 0
    )

    return {
        "ready": sufficient and not stale,
        "session_count": _training_session_count,
        "trained_at": _trained_at if _trained_at > 0 else None,
        "stale": stale,
        "insufficient_data": not sufficient,
    }

def needs_retraining() -> bool:
    """Returns True if the model has never been trained or if the retraining
    interval (VECTOR_RETRAIN_SECONDS) has elapsed since the last training."""
    _lazy_load()

    if _trained_at == 0.0:
        return True
    elapsed = time.time() - _trained_at
    return elapsed >= VECTOR_RETRAIN_SECONDS

def reset_model() -> None:
    """Reset all in-memory model state to defaults. Useful for testing."""
    global _bigram_matrix, _trigram_matrix, _training_session_count, _trained_at, _loaded
    _bigram_matrix = {}
    _trigram_matrix = {}
    _training_session_count = 0
    _trained_at = 0.0
    _loaded = False
