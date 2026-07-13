"""
Chronos — temporal pattern analysis for persistent Cowrie actors.

Classifies actors into diurnal / nocturnal / burst / sporadic based on
session-start-time histograms, burst/rest cycle detection, campaign
velocity, and recidivism windows.  Only active actors at or above
CHRONOS_MIN_SESSIONS are analysed; others receive insufficient_data.
"""

from __future__ import annotations

import json
import logging
import math
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

CHRONOS_MIN_SESSIONS: int = int(os.environ.get("CHRONOS_MIN_SESSIONS", "5"))
BURST_WINDOW_MINUTES: int = int(os.environ.get("CHRONOS_BURST_WINDOW", "10"))
BURST_MIN_EVENTS: int = int(os.environ.get("CHRONOS_BURST_MIN", "3"))
REST_GAP_HOURS: float = float(os.environ.get("CHRONOS_REST_GAP_HOURS", "1.0"))
DIURNAL_START_UTC: int = int(os.environ.get("CHRONOS_DIURNAL_START", "6"))
DIURNAL_END_UTC: int = int(os.environ.get("CHRONOS_DIURNAL_END", "18"))

def _get_redis():
    from behavioral_dna import REDIS_URL
    if not REDIS_URL:
        return None
    try:
        import redis as redis_lib
        return redis_lib.from_url(
            REDIS_URL, socket_connect_timeout=3,
            socket_timeout=5, decode_responses=True,
        )
    except Exception as e:
        logger.debug(f"Chronos: Redis unavailable: {e}")
        return None

def _fetch_session_timestamps(actor_uuid: str) -> List[datetime]:
    r = _get_redis()
    if not r:
        return []

    session_ids: List[str]
    try:
        session_ids = list(r.smembers(f"dna:actor_sessions:{actor_uuid}") or [])
    except Exception:
        return []

    if not session_ids:
        return []

    pipe = r.pipeline(transaction=False)
    for sid in session_ids:
        pipe.get(f"cowrie_completed:{sid}")
    try:
        results = pipe.execute()
    except Exception:
        return []

    timestamps: List[datetime] = []
    for raw in results:
        if not raw:
            continue
        try:
            sess = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue
        connected_at: str = sess.get("connected_at", "")
        if not connected_at:
            continue
        try:
            ts = datetime.fromisoformat(connected_at.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            continue
        timestamps.append(ts)

    timestamps.sort()
    return timestamps

# ── Analysis functions ─────────────────────────────────────────────

def diurnal_histogram(actor_uuid: str) -> Dict[str, Any]:
    """24-bin histogram (UTC hour 0–23) of session start times.

    Returns:
        Dict with keys:
            histogram: List[int] (length 24)
            total: int
            day_ratio: float  (fraction in UTC DIURNAL_START – DIURNAL_END)
            night_ratio: float
            peak_hour: int
            peak_count: int
    """
    timestamps = _fetch_session_timestamps(actor_uuid)
    if not timestamps:
        return _empty_histogram_result()

    bins: List[int] = [0] * 24
    for ts in timestamps:
        bins[ts.hour] += 1

    total = len(timestamps)
    day_count = sum(bins[DIURNAL_START_UTC:DIURNAL_END_UTC])
    night_count = total - day_count

    peak_hour = max(range(24), key=lambda h: bins[h])

    return {
        "histogram": bins,
        "total": total,
        "day_ratio": round(day_count / total, 4),
        "night_ratio": round(night_count / total, 4),
        "peak_hour": peak_hour,
        "peak_count": bins[peak_hour],
    }

def _empty_histogram_result() -> Dict[str, Any]:
    return {
        "histogram": [0] * 24,
        "total": 0,
        "day_ratio": 0.0,
        "night_ratio": 0.0,
        "peak_hour": 0,
        "peak_count": 0,
    }

def burst_rest_cycles(actor_uuid: str) -> Dict[str, Any]:
    """Detect burst clusters (≥BURST_MIN_EVENTS within BURST_WINDOW_MINUTES)
    and rest periods (>REST_GAP_HOURS gap between consecutive sessions).

    Returns:
        Dict with keys:
            bursts: List[Dict] each with start, end, count, density
            rest_periods: List[Dict] each with start, end, duration_hours
            burst_session_count: int
            rest_period_count: int
            burst_ratio: float (fraction of sessions in bursts)
    """
    timestamps = _fetch_session_timestamps(actor_uuid)
    if len(timestamps) < BURST_MIN_EVENTS:
        return _empty_burst_result()

    bursts: List[Dict[str, Any]] = []
    i = 0
    while i < len(timestamps) - BURST_MIN_EVENTS + 1:
        window_end = timestamps[i] + timedelta(minutes=BURST_WINDOW_MINUTES)
        cluster: List[datetime] = [timestamps[i]]
        j = i + 1
        while j < len(timestamps) and timestamps[j] <= window_end:
            cluster.append(timestamps[j])
            j += 1
        if len(cluster) >= BURST_MIN_EVENTS:
            start = cluster[0]
            end = cluster[-1]
            span_minutes = (end - start).total_seconds() / 60.0
            density = round(len(cluster) / max(span_minutes, 0.1), 2)
            bursts.append({
                "start": start.isoformat(),
                "end": end.isoformat(),
                "count": len(cluster),
                "density_sessions_per_minute": density,
            })
            i = j
        else:
            i += 1

    burst_session_ids: set = set()
    for burst_idx, ts in enumerate(timestamps):
        for b in bursts:
            b_start = datetime.fromisoformat(b["start"])
            b_end = datetime.fromisoformat(b["end"])
            if b_start <= ts <= b_end:
                burst_session_ids.add(burst_idx)
                break
    burst_session_count = len(burst_session_ids)

    rest_periods: List[Dict[str, Any]] = []
    prev_ts: Optional[datetime] = None
    for ts in timestamps:
        if prev_ts is not None:
            gap = (ts - prev_ts).total_seconds() / 3600.0
            if gap > REST_GAP_HOURS:
                rest_periods.append({
                    "start": prev_ts.isoformat(),
                    "end": ts.isoformat(),
                    "duration_hours": round(gap, 2),
                })
        prev_ts = ts

    total = len(timestamps)
    burst_ratio = round(burst_session_count / total, 4) if total else 0.0

    return {
        "bursts": bursts,
        "rest_periods": rest_periods,
        "burst_session_count": burst_session_count,
        "rest_period_count": len(rest_periods),
        "burst_ratio": burst_ratio,
    }

def _empty_burst_result() -> Dict[str, Any]:
    return {
        "bursts": [],
        "rest_periods": [],
        "burst_session_count": 0,
        "rest_period_count": 0,
        "burst_ratio": 0.0,
    }

def campaign_velocity(actor_uuid: str) -> Dict[str, Any]:
    """Sessions per calendar day with linear-trend estimate.

    Returns:
        Dict with keys:
            daily_counts: Dict[str, int]  (YYYY-MM-DD → count)
            total_days: int
            total_sessions: int
            avg_sessions_per_day: float
            trend_slope: float  (sessions/day/day — positive = accelerating)
            trend_r2: float  (coefficient of determination, 0–1)
            peak_day: str
            peak_count: int
    """
    timestamps = _fetch_session_timestamps(actor_uuid)
    if not timestamps:
        return _empty_velocity_result()

    daily: Dict[str, int] = defaultdict(int)
    for ts in timestamps:
        day_key = ts.strftime("%Y-%m-%d")
        daily[day_key] += 1

    sorted_days = sorted(daily.items())
    total_days = len(sorted_days)
    total_sessions = sum(c for _, c in sorted_days)

    if total_days < 2:
        avg = float(total_sessions)
        peak_day, peak_count = sorted_days[0] if sorted_days else ("", 0)
        return {
            "daily_counts": dict(sorted_days),
            "total_days": total_days,
            "total_sessions": total_sessions,
            "avg_sessions_per_day": round(avg, 2),
            "trend_slope": 0.0,
            "trend_r2": 0.0,
            "peak_day": peak_day,
            "peak_count": peak_count,
        }

    xs = list(range(total_days))
    ys = [c for _, c in sorted_days]

    slope, r_squared = _simple_linear_regression(xs, ys)

    peak_entry = max(daily.items(), key=lambda kv: kv[1])

    return {
        "daily_counts": dict(sorted_days),
        "total_days": total_days,
        "total_sessions": total_sessions,
        "avg_sessions_per_day": round(total_sessions / total_days, 2),
        "trend_slope": round(slope, 4),
        "trend_r2": round(r_squared, 4),
        "peak_day": peak_entry[0],
        "peak_count": peak_entry[1],
    }

def _empty_velocity_result() -> Dict[str, Any]:
    return {
        "daily_counts": {},
        "total_days": 0,
        "total_sessions": 0,
        "avg_sessions_per_day": 0.0,
        "trend_slope": 0.0,
        "trend_r2": 0.0,
        "peak_day": "",
        "peak_count": 0,
    }

def _simple_linear_regression(
    xs: List[int], ys: List[int],
) -> Tuple[float, float]:
    n = len(xs)
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n

    ss_xy = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    ss_xx = sum((x - mean_x) ** 2 for x in xs)
    ss_yy = sum((y - mean_y) ** 2 for y in ys)

    if ss_xx == 0:
        return 0.0, 0.0

    slope = ss_xy / ss_xx

    if ss_yy == 0:
        r_squared = 1.0 if slope == 0.0 else 0.0
    else:
        r_squared = (ss_xy ** 2) / (ss_xx * ss_yy)

    return slope, r_squared

def recidivism_window(actor_uuid: str) -> Dict[str, Any]:
    """Compute the time span between first and last session and the number
    of distinct active calendar days.

    Returns:
        Dict with keys:
            first_session: str | None
            last_session: str | None
            total_span_hours: float
            total_span_days: float
            active_days: int
            sessions_per_active_day: float
            median_inter_session_minutes: float | None
    """
    timestamps = _fetch_session_timestamps(actor_uuid)
    if not timestamps:
        return _empty_recidivism_result()

    first = timestamps[0]
    last = timestamps[-1]
    span_hours = (last - first).total_seconds() / 3600.0
    span_days = span_hours / 24.0

    active_day_set = {ts.strftime("%Y-%m-%d") for ts in timestamps}
    active_days = len(active_day_set)

    total = len(timestamps)
    median_gap: Optional[float] = None
    if total >= 2:
        gaps: List[float] = []
        for i in range(1, total):
            gap = (timestamps[i] - timestamps[i - 1]).total_seconds() / 60.0
            gaps.append(gap)
        gaps.sort()
        mid = len(gaps) // 2
        if len(gaps) % 2 == 0:
            median_gap = round((gaps[mid - 1] + gaps[mid]) / 2.0, 2)
        else:
            median_gap = round(gaps[mid], 2)
    elif total == 1:
        median_gap = 0.0

    return {
        "first_session": first.isoformat(),
        "last_session": last.isoformat(),
        "total_span_hours": round(span_hours, 2),
        "total_span_days": round(span_days, 2),
        "active_days": active_days,
        "sessions_per_active_day": round(total / active_days, 2) if active_days else 0.0,
        "median_inter_session_minutes": median_gap,
    }

def _empty_recidivism_result() -> Dict[str, Any]:
    return {
        "first_session": None,
        "last_session": None,
        "total_span_hours": 0.0,
        "total_span_days": 0.0,
        "active_days": 0,
        "sessions_per_active_day": 0.0,
        "median_inter_session_minutes": None,
    }

# ── Classification ─────────────────────────────────────────────────

def _classify(
    histogram: Dict[str, Any],
    burst: Dict[str, Any],
    velocity: Dict[str, Any],
    window: Dict[str, Any],
    session_count: int,
) -> Tuple[str, float]:
    day_ratio: float = histogram.get("day_ratio", 0.0)
    night_ratio: float = histogram.get("night_ratio", 0.0)
    burst_ratio: float = burst.get("burst_ratio", 0.0)

    if day_ratio >= 0.60:
        return "diurnal", round(day_ratio, 4)
    if night_ratio >= 0.60:
        return "nocturnal", round(night_ratio, 4)
    if burst_ratio >= 0.50:
        return "burst", round(burst_ratio, 4)

    sparsity = 1.0 - max(day_ratio, night_ratio, burst_ratio)
    return "sporadic", round(sparsity, 4)

# ── Main analyzer ──────────────────────────────────────────────────

class ChronosAnalyzer:
    """Temporal behavior classifier for persistent Cowrie actors."""

    def __init__(self) -> None:
        pass

    def analyze_actor(self, actor_uuid: str) -> Dict[str, Any]:
        """Full temporal analysis for a single actor.

        Returns a dict with classification, confidence, histogram,
        burst/rest summary, velocity trend, and recidivism window.
        Actors below CHRONOS_MIN_SESSIONS or non-active receive
        classification 'insufficient_data'.
        """
        from behavioral_dna import get_dna_engine

        actor = get_dna_engine().get_actor(actor_uuid)
        if actor is None:
            return self._insufficient_data(actor_uuid, reason="actor_not_found")

        status = actor.get("status", "")
        if status != "active":
            return self._insufficient_data(actor_uuid, reason=f"status_{status}")

        session_count: int = actor.get("session_count", 0)
        if session_count < CHRONOS_MIN_SESSIONS:
            return self._insufficient_data(
                actor_uuid,
                session_count=session_count,
                reason="below_min_sessions",
            )

        histogram = diurnal_histogram(actor_uuid)
        burst = burst_rest_cycles(actor_uuid)
        velocity = campaign_velocity(actor_uuid)
        window = recidivism_window(actor_uuid)

        classification, confidence = _classify(
            histogram, burst, velocity, window, session_count,
        )

        return {
            "actor_uuid": actor_uuid,
            "session_count": session_count,
            "classification": classification,
            "confidence": confidence,
            "histogram": histogram,
            "burst_rest": burst,
            "velocity": velocity,
            "recidivism": window,
        }

    def batch_analyze(
        self, actor_uuids: Optional[List[str]] = None, limit: int = 0,
    ) -> List[Dict[str, Any]]:
        """Analyse all active actors (or a supplied list)."""
        if actor_uuids is not None:
            return [self.analyze_actor(uid) for uid in actor_uuids]

        from behavioral_dna import get_dna_engine

        engine = get_dna_engine()
        if not engine.ActorModel:
            logger.warning("Chronos: DNA engine not initialized")
            return []

        from behavioral_dna import _get_db_session
        db_sess = _get_db_session()
        if not db_sess:
            return []

        try:
            query = db_sess.query(engine.ActorModel).filter_by(status="active")
            if limit > 0:
                query = query.limit(limit)
            actors = query.all()
        except Exception:
            return []

        results: List[Dict[str, Any]] = []
        for actor in actors:
            results.append(self.analyze_actor(actor.actor_uuid))
        return results

    @staticmethod
    def _insufficient_data(
        actor_uuid: str,
        session_count: int = 0,
        reason: str = "",
    ) -> Dict[str, Any]:
        return {
            "actor_uuid": actor_uuid,
            "session_count": session_count,
            "classification": "insufficient_data",
            "confidence": 0.0,
            "insufficient_data": True,
            "insufficient_reason": reason,
            "histogram": _empty_histogram_result(),
            "burst_rest": _empty_burst_result(),
            "velocity": _empty_velocity_result(),
            "recidivism": _empty_recidivism_result(),
        }

_chronos: Optional[ChronosAnalyzer] = None

def get_chronos() -> ChronosAnalyzer:
    global _chronos
    if _chronos is None:
        _chronos = ChronosAnalyzer()
    return _chronos
