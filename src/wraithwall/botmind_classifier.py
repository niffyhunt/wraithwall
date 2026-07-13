"""
BOTMIND — behavioral keystroke analysis for attacker classification.

Layers implemented:
  Layer 1 — keystroke inter-arrival time (IAT) distribution analysis
  Layer 3 — error/correction pattern detection (backspace/delete ratio)
  Layer 4 — curiosity score (exploration vs. execution command ratio)

Layer 2 (command coherence) is explicitly NOT implemented — unreliable
given Cowrie's simulated command output.

Per-session volume impact: ~120KB per interactive session at 20 keys/sec
over 30 seconds (200 bytes per keystroke JSON event). At current traffic
levels (~5 interactive sessions/day), adds ~600KB/day to Redis.
"""

from __future__ import annotations

import json
import logging
import math
import os
import statistics
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

REDIS_URL: str = os.environ.get("REDIS_URL", "")
BOTMIND_MIN_KEYSTROKES: int = int(os.environ.get("BOTMIND_MIN_KEYSTROKES", "20"))
BOTMIND_IAT_HUMAN_MEAN: float = float(os.environ.get("BOTMIND_IAT_HUMAN_MEAN", "0.18"))
BOTMIND_IAT_BOT_MEAN: float = float(os.environ.get("BOTMIND_IAT_BOT_MEAN", "0.02"))
BOTMIND_BACKSPACE_HUMAN_RATIO: float = float(
    os.environ.get("BOTMIND_BACKSPACE_HUMAN_RATIO", "0.03")
)
BOTMIND_BACKSPACE_BOT_RATIO: float = float(
    os.environ.get("BOTMIND_BACKSPACE_BOT_RATIO", "0.001")
)

def _get_redis():
    if not REDIS_URL:
        return None
    try:
        import redis as redis_lib
        return redis_lib.from_url(REDIS_URL, socket_connect_timeout=3,
                                  socket_timeout=5, decode_responses=True)
    except Exception:
        return None

class BotmindAnalyzer:
    """Per-session keystroke behavioral analysis.

    Consumes per-keystroke timing events from the Cowrie plugin
    (redis_output.py extension) stored under botmind:keystrokes:{session_id}.
    """

    def __init__(self) -> None:
        pass

    def _get_keystrokes(self, session_id: str) -> List[Dict]:
        """Fetch keystroke events for a session from Redis."""
        r = _get_redis()
        if not r:
            return []

        key = f"botmind:keystrokes:{session_id}"
        try:
            raw = r.get(key)
            if not raw:
                return []
            return json.loads(raw)
        except (json.JSONDecodeError, Exception):
            return []

    def analyze(self, session_id: str) -> Dict:
        """Run full BOTMIND analysis on a session.

        Returns:
            Dict with layers, scores, classification, and per-layer contributions.
        """
        keystrokes = self._get_keystrokes(session_id)

        if len(keystrokes) < BOTMIND_MIN_KEYSTROKES:
            return {
                "session_id": session_id,
                "insufficient_data": True,
                "keystroke_count": len(keystrokes),
                "min_required": BOTMIND_MIN_KEYSTROKES,
                "classification": "insufficient_data",
                "botmind_score": 0.0,
                "layers": {},
            }

        layer1 = self._layer1_iat(keystrokes)
        layer3 = self._layer3_error_correction(keystrokes)
        layer4 = self._layer4_curiosity(keystrokes)

        layers = {"layer1_iat": layer1, "layer3_error": layer3, "layer4_curiosity": layer4}

        l1_score = layer1.get("confidence_bot", 0.0)
        l3_score = layer3.get("confidence_bot", 0.0)
        l4_score = layer4.get("confidence_bot", 0.0)
        botmind_score = round((l1_score * 0.40 + l3_score * 0.30 + l4_score * 0.30) * 100, 1)

        classification = "human"
        if botmind_score >= 75:
            classification = "bot"
        elif botmind_score >= 45:
            classification = "suspicious"

        return {
            "session_id": session_id,
            "insufficient_data": False,
            "keystroke_count": len(keystrokes),
            "classification": classification,
            "botmind_score": botmind_score,
            "layers": layers,
        }

    def _layer1_iat(self, keystrokes: List[Dict]) -> Dict:
        """Layer 1: Keystroke inter-arrival time distribution.

        Humans type with variable IAT (mean ~180ms, high variance).
        Bots paste or script-type with low IAT (mean ~20ms, near-zero variance).
        """
        if len(keystrokes) < 2:
            return {"confidence_bot": 0.0, "confidence_human": 0.0, "insufficient_data": True}

        iats: List[float] = []
        for i in range(1, len(keystrokes)):
            t0 = keystrokes[i - 1].get("timestamp", 0)
            t1 = keystrokes[i].get("timestamp", 0)
            if isinstance(t0, str):
                try:
                    t0 = datetime.fromisoformat(t0.replace("Z", "+00:00")).timestamp()
                except (ValueError, TypeError):
                    t0 = 0.0
            if isinstance(t1, str):
                try:
                    t1 = datetime.fromisoformat(t1.replace("Z", "+00:00")).timestamp()
                except (ValueError, TypeError):
                    t1 = 0.0
            iat = t1 - t0
            if 0 < iat < 10.0:
                iats.append(iat)

        if len(iats) < 5:
            return {"confidence_bot": 0.0, "confidence_human": 0.0, "insufficient_data": True}

        mean_iat = statistics.mean(iats)
        try:
            stdev_iat = statistics.stdev(iats)
        except statistics.StatisticsError:
            stdev_iat = 0.0

        cv = stdev_iat / mean_iat if mean_iat > 0 else 0.0

        bot_proximity = 1.0 - min(abs(mean_iat - BOTMIND_IAT_BOT_MEAN) / 0.1, 1.0)
        human_proximity = 1.0 - min(abs(mean_iat - BOTMIND_IAT_HUMAN_MEAN) / 0.3, 1.0)
        variance_score = 1.0 / (1.0 + math.exp(-10.0 * (cv - 0.3)))

        confidence_bot = round(bot_proximity * 0.6 + (1.0 - variance_score) * 0.4, 3)
        confidence_human = round(human_proximity * 0.6 + variance_score * 0.4, 3)

        if stdev_iat < 0.005 and mean_iat < 0.05:
            confidence_bot = 0.95

        return {
            "mean_iat_ms": round(mean_iat * 1000, 1),
            "stdev_iat_ms": round(stdev_iat * 1000, 1),
            "coefficient_of_variation": round(cv, 3),
            "keystroke_count": len(iats) + 1,
            "confidence_bot": confidence_bot,
            "confidence_human": confidence_human,
            "insufficient_data": False,
        }

    def _layer3_error_correction(self, keystrokes: List[Dict]) -> Dict:
        """Layer 3: Error/correction pattern detection.

        Humans make typos and backspace ~3% of keystrokes.
        Bots have near-zero backspace ratio.
        """
        total = len(keystrokes)
        backspace_count = sum(
            1 for k in keystrokes
            if k.get("key", "") in ("\x7f", "\b", "BackSpace", "Delete")
        )
        ratio = backspace_count / total if total > 0 else 0.0

        bot_proximity = 1.0 - min(
            abs(ratio - BOTMIND_BACKSPACE_BOT_RATIO) / 0.01, 1.0
        )
        human_proximity = 1.0 - min(
            abs(ratio - BOTMIND_BACKSPACE_HUMAN_RATIO) / 0.05, 1.0
        )

        confidence_bot = round(bot_proximity, 3)
        confidence_human = round(human_proximity, 3)

        return {
            "total_keystrokes": total,
            "backspace_count": backspace_count,
            "backspace_ratio": round(ratio, 4),
            "confidence_bot": confidence_bot,
            "confidence_human": confidence_human,
            "insufficient_data": False,
        }

    def _layer4_curiosity(self, keystrokes: List[Dict]) -> Dict:
        """Layer 4: Curiosity score — exploration vs. execution commands.

        Attackers explore: they run discovery commands across multiple
        system areas. Bots execute: they run a fixed script.
        High unique-command-count relative to total keystrokes = high curiosity.

        Each keystroke event may carry a 'command' field indicating the
        shell command it belongs to.
        """
        commands: List[str] = []
        for k in keystrokes:
            cmd = k.get("command", "")
            if cmd:
                commands.append(cmd)

        unique = len(set(commands))
        total = len(commands)

        if total < 3:
            return {"confidence_bot": 0.5, "confidence_human": 0.5, "insufficient_data": True}

        exploration_ratio = unique / total if total > 0 else 0.0

        confidence_human = min(exploration_ratio * 1.5, 1.0)
        confidence_bot = round(1.0 - confidence_human, 3)
        confidence_human = round(confidence_human, 3)

        return {
            "total_commands": total,
            "unique_commands": unique,
            "exploration_ratio": round(exploration_ratio, 3),
            "confidence_bot": confidence_bot,
            "confidence_human": confidence_human,
            "insufficient_data": False,
        }

_botmind: Optional[BotmindAnalyzer] = None

def get_botmind() -> BotmindAnalyzer:
    global _botmind
    if _botmind is None:
        _botmind = BotmindAnalyzer()
    return _botmind
