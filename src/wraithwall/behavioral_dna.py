"""
Behavioral DNA — persistent attacker identity tracking.

Correlates Cowrie sessions into persistent actor identities using
post-login latency, error-correction patterns, and command-sequence
similarity as merge-trigger signals. Merge proposals below a confidence
threshold enter a pending-review workflow with full audit trail.

Postgres-backed for merge_log durability; Redis-backed for session→actor
mapping (matching the existing session architecture).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

REDIS_URL: str = os.environ.get("REDIS_URL", "")
ACTOR_TTL_SECONDS: int = int(os.environ.get("DNA_ACTOR_TTL", "7776000"))   # 90 days
MERGE_CONFIDENCE_HIGH: float = float(os.environ.get("DNA_MERGE_HIGH", "0.85"))
MERGE_CONFIDENCE_LOW: float = float(os.environ.get("DNA_MERGE_LOW", "0.55"))
MIN_SESSIONS_FOR_ACTOR: int = int(os.environ.get("DNA_MIN_SESSIONS", "2"))
MIN_COMMANDS_FOR_FINGERPRINT: int = int(os.environ.get("DNA_MIN_COMMANDS", "3"))

def _get_redis():
    if not REDIS_URL:
        return None
    try:
        import redis as redis_lib
        return redis_lib.from_url(REDIS_URL, socket_connect_timeout=3,
                                  socket_timeout=5, decode_responses=True)
    except Exception as e:
        logger.debug(f"Redis unavailable for DNA: {e}")
        return None

def _get_db_session():
    try:

        return db.session
    except Exception:
        return None

# ── Postgres models ─────────────────────────────────────────────

def init_dna_models(db) -> None:
    """Declare BehavioralActor and MergeLog models on the given SQLAlchemy db instance.
    Called at app startup — idempotent via create_all."""
    class BehavioralActor(db.Model):
        __tablename__ = "behavioral_actor"
        id: int = db.Column(db.Integer, primary_key=True)
        actor_uuid: str = db.Column(db.String(36), unique=True, nullable=False, index=True)
        fingerprint_hash: str = db.Column(db.String(64), nullable=False)
        session_count: int = db.Column(db.Integer, default=0)
        first_seen: datetime = db.Column(db.DateTime, nullable=False)
        last_seen: datetime = db.Column(db.DateTime, nullable=False)
        last_fingerprint: str = db.Column(db.Text)
        confidence_score: float = db.Column(db.Float, default=1.0)
        status: str = db.Column(db.String(20), default="active")  # active | merged | retired
        merged_into: str = db.Column(db.String(36), nullable=True)
        created_at: datetime = db.Column(db.DateTime, default=datetime.utcnow)

    class MergeLog(db.Model):
        __tablename__ = "behavioral_merge_log"
        id: int = db.Column(db.Integer, primary_key=True)
        source_actor_uuid: str = db.Column(db.String(36), nullable=False, index=True)
        target_actor_uuid: str = db.Column(db.String(36), nullable=False, index=True)
        confidence: float = db.Column(db.Float, nullable=False)
        triggers: str = db.Column(db.Text)  # JSON list of signal names that triggered
        status: str = db.Column(db.String(20), default="pending")  # pending | approved | rejected
        reviewer: str = db.Column(db.String(120), nullable=True)
        reviewed_at: datetime = db.Column(db.DateTime, nullable=True)
        reason: str = db.Column(db.Text, nullable=True)
        created_at: datetime = db.Column(db.DateTime, default=datetime.utcnow)

    db.BehavioralActor = BehavioralActor
    db.MergeLog = MergeLog
    return BehavioralActor, MergeLog

# ── Behavioral fingerprint computation ──────────────────────────

class BehavioralFingerprint:
    """Computed behavioral signature for a single Cowrie session."""

    def __init__(self, session: Dict) -> None:
        self.session_id: str = session.get("session_id", "")
        self.src_ip: str = session.get("src_ip", "")
        self.commands: List[str] = session.get("commands", [])
        self.login_attempts: List[Dict] = session.get("login_attempts", [])
        self.duration: float = float(session.get("duration", 0))
        self.connected_at: str = session.get("connected_at", "")
        self.closed_at: str = session.get("closed_at", "")
        self.hassh: Optional[str] = session.get("hassh")
        self.transport: Optional[Dict] = session.get("transport")

        self.command_count: int = len(self.commands)
        self.login_latency_ms: float = 0.0
        self.error_ratio: float = 0.0
        self.command_hash: str = ""
        self.typing_speed: float = 0.0

        self._compute()

    def _compute(self) -> None:
        if self.login_attempts:
            first_login = self.login_attempts[0]
            login_ts = first_login.get("timestamp", "")
            if login_ts and self.commands:
                try:
                    lt = datetime.fromisoformat(login_ts.replace("Z", "+00:00"))
                    ct = datetime.fromisoformat(
                        self.connected_at.replace("Z", "+00:00")
                        if self.connected_at else "2000-01-01T00:00:00+00:00"
                    )
                    self.login_latency_ms = (lt - ct).total_seconds() * 1000
                except (ValueError, TypeError):
                    self.login_latency_ms = 0.0

        error_count: int = sum(
            1 for la in self.login_attempts if not la.get("success", False)
        )
        success_count: int = sum(
            1 for la in self.login_attempts if la.get("success", False)
        )
        total = error_count + success_count
        self.error_ratio = error_count / total if total > 0 else 0.0

        if self.commands:
            cmd_text = "\n".join(sorted(self.commands))
            self.command_hash = hashlib.sha256(cmd_text.encode()).hexdigest()[:20]

        if self.duration > 0 and self.command_count > 0:
            self.typing_speed = self.command_count / max(self.duration, 1.0)

    def to_dict(self) -> Dict:
        return {
            "session_id": self.session_id,
            "src_ip": self.src_ip,
            "command_count": self.command_count,
            "login_latency_ms": round(self.login_latency_ms, 1),
            "error_ratio": round(self.error_ratio, 3),
            "command_hash": self.command_hash,
            "typing_speed": round(self.typing_speed, 4),
            "duration": self.duration,
            "hassh": self.hassh,
        }

    def similarity(self, other: "BehavioralFingerprint") -> float:
        """Compute similarity between two behavioral fingerprints (0.0–1.0).

        Uses Jaccard on command sets, weighted by latency/error proximity.
        """
        if not self.commands or not other.commands:
            return 0.0

        set_a: Set[str] = set(self.commands)
        set_b: Set[str] = set(other.commands)
        intersection = len(set_a & set_b)
        union = len(set_a | set_b)
        jaccard: float = intersection / union if union > 0 else 0.0

        latency_diff: float = abs(self.login_latency_ms - other.login_latency_ms)
        latency_score: float = max(0.0, 1.0 - latency_diff / 5000.0)

        error_diff: float = abs(self.error_ratio - other.error_ratio)
        error_score: float = max(0.0, 1.0 - error_diff / 0.5)

        return round(0.4 * jaccard + 0.3 * latency_score + 0.3 * error_score, 4)

# ── DNA Engine ──────────────────────────────────────────────────

class BehavioralDNAEngine:
    """Correlates sessions into persistent actor identities.

    Public API:
        process_session(session) → actor_uuid
        get_actor(actor_uuid) → BehavioralActor | None
        list_pending_merges() → List[MergeLog]
        approve_merge(merge_id, reviewer) → bool
        reject_merge(merge_id, reviewer, reason) → bool
    """

    def __init__(self) -> None:
        self.ActorModel: Optional[type] = None
        self.MergeModel: Optional[type] = None
        self._initialized: bool = False

    def _ensure_models(self) -> None:
        if self._initialized:
            return
        db_sess = _get_db_session()
        if db_sess is not None:
            try:

                Actor, Merge = init_dna_models(app_db)
                self.ActorModel = Actor
                self.MergeModel = Merge
                app_db.create_all()
                self._initialized = True
                logger.info("BehavioralDNA models initialized")
            except Exception as e:
                logger.warning(f"BehavioralDNA model init deferred: {e}")
        else:
            self._initialized = True

    def fingerprint_session(self, session: Dict) -> BehavioralFingerprint:
        return BehavioralFingerprint(session)

    def process_session(self, session: Dict) -> Optional[str]:
        """Process a completed Cowrie session and assign it to an actor identity.

        Returns:
            actor_uuid if assigned, None if insufficient data for fingerprinting.
        """
        self._ensure_models()

        commands = session.get("commands", [])
        if len(commands) < MIN_COMMANDS_FOR_FINGERPRINT:
            return None

        fp = self.fingerprint_session(session)

        existing_actor = self._find_matching_actor(fp)
        if existing_actor:
            actor_uuid = existing_actor.actor_uuid
            self._update_actor(existing_actor, fp)
            self._link_session_to_actor(fp.session_id, actor_uuid)
            return actor_uuid

        actor_uuid = self._create_actor(fp)
        self._link_session_to_actor(fp.session_id, actor_uuid)

        candidates = self._find_merge_candidates(fp, actor_uuid)
        for candidate_actor, confidence in candidates:
            if confidence >= MERGE_CONFIDENCE_HIGH:
                self._auto_merge(candidate_actor.actor_uuid, actor_uuid, confidence, fp)
            elif confidence >= MERGE_CONFIDENCE_LOW:
                self._propose_merge(candidate_actor.actor_uuid, actor_uuid, confidence, fp)

        return actor_uuid

    def _find_matching_actor(self, fp: BehavioralFingerprint) -> Optional[object]:
        r = _get_redis()
        if not r:
            return None

        existing = r.get(f"dna:hassh:{fp.hassh}") if fp.hassh else None
        if existing:
            return self._get_actor_by_uuid(existing)

        if fp.command_hash:
            existing = r.get(f"dna:cmdhash:{fp.command_hash}")
            if existing:
                return self._get_actor_by_uuid(existing)

        return None

    def _get_actor_by_uuid(self, actor_uuid: str) -> Optional[object]:
        if not self.ActorModel:
            return None
        db_sess = _get_db_session()
        if not db_sess:
            return None
        try:
            return db_sess.query(self.ActorModel).filter_by(
                actor_uuid=actor_uuid, status="active"
            ).first()
        except Exception:
            return None

    def _create_actor(self, fp: BehavioralFingerprint) -> str:
        import uuid
        actor_uuid = uuid.uuid4().hex[:12]

        if self.ActorModel:
            db_sess = _get_db_session()
            if db_sess:
                try:
                    actor = self.ActorModel(
                        actor_uuid=actor_uuid,
                        fingerprint_hash=fp.command_hash or "no_commands",
                        session_count=1,
                        first_seen=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc),
                        last_fingerprint=json.dumps(fp.to_dict()),
                        confidence_score=1.0,
                    )
                    db_sess.add(actor)
                    db_sess.commit()
                except Exception as e:
                    logger.error(f"Create actor failed: {e}")
                    db_sess.rollback()

        r = _get_redis()
        if r:
            try:
                if fp.hassh:
                    r.setex(f"dna:hassh:{fp.hassh}", ACTOR_TTL_SECONDS, actor_uuid)
                if fp.command_hash:
                    r.setex(f"dna:cmdhash:{fp.command_hash}", ACTOR_TTL_SECONDS, actor_uuid)
                r.setex(f"dna:actor:{actor_uuid}:ip:{fp.src_ip}", ACTOR_TTL_SECONDS, "1")
            except Exception:
                pass

        return actor_uuid

    def _update_actor(self, actor: object, fp: BehavioralFingerprint) -> None:
        actor.last_seen = datetime.now(timezone.utc)
        actor.session_count = (actor.session_count or 0) + 1
        actor.last_fingerprint = json.dumps(fp.to_dict())

        db_sess = _get_db_session()
        if db_sess:
            try:
                db_sess.commit()
            except Exception:
                db_sess.rollback()

        r = _get_redis()
        if r:
            try:
                r.setex(
                    f"dna:actor:{actor.actor_uuid}:ip:{fp.src_ip}",
                    ACTOR_TTL_SECONDS, "1"
                )
            except Exception:
                pass

    def _link_session_to_actor(self, session_id: str, actor_uuid: str) -> None:
        r = _get_redis()
        if r:
            try:
                r.setex(f"dna:session_actor:{session_id}", ACTOR_TTL_SECONDS, actor_uuid)
                r.sadd(f"dna:actor_sessions:{actor_uuid}", session_id)
                r.expire(f"dna:actor_sessions:{actor_uuid}", ACTOR_TTL_SECONDS)
            except Exception:
                pass

    def _find_merge_candidates(
        self, fp: BehavioralFingerprint, exclude_uuid: str
    ) -> List[Tuple[object, float]]:
        candidates: List[Tuple[object, float]] = []
        r = _get_redis()
        if not r or not self.ActorModel:
            return candidates

        other_uuids: Set[str] = set()
        try:
            for ip_key in r.scan_iter(match=f"dna:actor:*:ip:{fp.src_ip}", count=100):
                parts = ip_key.split(":")
                if len(parts) >= 4:
                    other_uuids.add(parts[2])
        except Exception:
            pass

        db_sess = _get_db_session()
        if not db_sess:
            return candidates

        for other_uuid in other_uuids:
            if other_uuid == exclude_uuid:
                continue
            try:
                other = db_sess.query(self.ActorModel).filter_by(
                    actor_uuid=other_uuid, status="active"
                ).first()
                if not other or not other.last_fingerprint:
                    continue
                other_fp_dict = json.loads(other.last_fingerprint)
                other_fp = BehavioralFingerprint.__new__(BehavioralFingerprint)
                other_fp.commands = other_fp_dict.get("commands", []) if "commands" in other_fp_dict else []
                other_fp.login_latency_ms = other_fp_dict.get("login_latency_ms", 0.0)
                other_fp.error_ratio = other_fp_dict.get("error_ratio", 0.0)
                sim = fp.similarity(other_fp)
                if sim >= MERGE_CONFIDENCE_LOW:
                    candidates.append((other, sim))
            except Exception:
                continue

        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates

    def _auto_merge(
        self, source_uuid: str, target_uuid: str,
        confidence: float, fp: BehavioralFingerprint
    ) -> None:
        self._execute_merge(source_uuid, target_uuid, confidence,
                           fp, status="approved", reviewer="auto")

    def _propose_merge(
        self, source_uuid: str, target_uuid: str,
        confidence: float, fp: BehavioralFingerprint
    ) -> None:
        self._create_merge_log(source_uuid, target_uuid, confidence, fp, status="pending")

    def _execute_merge(
        self, source_uuid: str, target_uuid: str,
        confidence: float, fp: BehavioralFingerprint,
        status: str = "approved", reviewer: Optional[str] = None
    ) -> None:
        r = _get_redis()
        if r:
            try:
                sessions = r.smembers(f"dna:actor_sessions:{source_uuid}") or set()
                for sid in sessions:
                    r.setex(f"dna:session_actor:{sid}", ACTOR_TTL_SECONDS, target_uuid)
                    r.sadd(f"dna:actor_sessions:{target_uuid}", sid)
                r.delete(f"dna:actor_sessions:{source_uuid}")
            except Exception:
                pass

        self._create_merge_log(source_uuid, target_uuid, confidence, fp,
                               status=status, reviewer=reviewer)

        if self.ActorModel:
            db_sess = _get_db_session()
            if db_sess:
                try:
                    source = db_sess.query(self.ActorModel).filter_by(
                        actor_uuid=source_uuid
                    ).first()
                    target = db_sess.query(self.ActorModel).filter_by(
                        actor_uuid=target_uuid
                    ).first()
                    if source and target:
                        target.session_count = (target.session_count or 0) + (source.session_count or 0)
                        source.status = "merged"
                        source.merged_into = target_uuid
                        db_sess.commit()
                except Exception as e:
                    logger.error(f"Merge commit failed: {e}")
                    db_sess.rollback()

        logger.info(
            f"DNA merge: {source_uuid} → {target_uuid} "
            f"(confidence={confidence:.3f}, status={status})"
        )

    def _create_merge_log(
        self, source_uuid: str, target_uuid: str,
        confidence: float, fp: BehavioralFingerprint,
        status: str = "pending", reviewer: Optional[str] = None
    ) -> None:
        if not self.MergeModel:
            return
        db_sess = _get_db_session()
        if not db_sess:
            return
        try:
            log_entry = self.MergeModel(
                source_actor_uuid=source_uuid,
                target_actor_uuid=target_uuid,
                confidence=round(confidence, 4),
                triggers=json.dumps({
                    "command_similarity": round(fp.similarity(
                        BehavioralFingerprint.__new__(BehavioralFingerprint)
                    ), 4) if hasattr(fp, 'similarity') else 0.0,
                    "ip_overlap": True,
                }),
                status=status,
                reviewer=reviewer,
                reviewed_at=datetime.now(timezone.utc) if status != "pending" else None,
            )
            db_sess.add(log_entry)
            db_sess.commit()
        except Exception as e:
            logger.error(f"Merge log failed: {e}")
            db_sess.rollback()

    def list_pending_merges(self) -> List[Dict]:
        if not self.MergeModel:
            return []
        db_sess = _get_db_session()
        if not db_sess:
            return []
        try:
            entries = db_sess.query(self.MergeModel).filter_by(
                status="pending"
            ).order_by(self.MergeModel.created_at.desc()).limit(50).all()
            return [
                {
                    "id": e.id,
                    "source": e.source_actor_uuid,
                    "target": e.target_actor_uuid,
                    "confidence": e.confidence,
                    "triggers": json.loads(e.triggers) if e.triggers else {},
                    "created_at": e.created_at.isoformat() if e.created_at else "",
                }
                for e in entries
            ]
        except Exception:
            return []

    def approve_merge(self, merge_id: int, reviewer: str) -> bool:
        if not self.MergeModel:
            return False
        db_sess = _get_db_session()
        if not db_sess:
            return False
        try:
            entry = db_sess.query(self.MergeModel).filter_by(
                id=merge_id, status="pending"
            ).first()
            if not entry:
                return False
            entry.status = "approved"
            entry.reviewer = reviewer
            entry.reviewed_at = datetime.now(timezone.utc)
            db_sess.commit()
            self._execute_merge(
                entry.source_actor_uuid, entry.target_actor_uuid,
                entry.confidence,
                BehavioralFingerprint.__new__(BehavioralFingerprint),
                status="approved", reviewer=reviewer
            )
            return True
        except Exception:
            db_sess.rollback()
            return False

    def reject_merge(self, merge_id: int, reviewer: str, reason: str = "") -> bool:
        if not self.MergeModel:
            return False
        db_sess = _get_db_session()
        if not db_sess:
            return False
        try:
            entry = db_sess.query(self.MergeModel).filter_by(
                id=merge_id, status="pending"
            ).first()
            if not entry:
                return False
            entry.status = "rejected"
            entry.reviewer = reviewer
            entry.reviewed_at = datetime.now(timezone.utc)
            entry.reason = reason[:500] if reason else None
            db_sess.commit()
            return True
        except Exception:
            db_sess.rollback()
            return False

    def get_actor(self, actor_uuid: str) -> Optional[Dict]:
        if not self.ActorModel:
            return None
        db_sess = _get_db_session()
        if not db_sess:
            return None
        try:
            actor = db_sess.query(self.ActorModel).filter_by(
                actor_uuid=actor_uuid
            ).first()
            if not actor:
                return None

            r = _get_redis()
            sessions: List[str] = []
            if r:
                try:
                    sessions = list(
                        r.smembers(f"dna:actor_sessions:{actor_uuid}") or set()
                    )
                except Exception:
                    pass

            return {
                "actor_uuid": actor.actor_uuid,
                "session_count": actor.session_count or 0,
                "first_seen": actor.first_seen.isoformat() if actor.first_seen else "",
                "last_seen": actor.last_seen.isoformat() if actor.last_seen else "",
                "confidence_score": actor.confidence_score or 0.0,
                "status": actor.status,
                "merged_into": actor.merged_into,
                "sessions": sessions[:100],
                "pending_merges": len(self.list_pending_merges()),
            }
        except Exception:
            return None

    def get_actor_for_session(self, session_id: str) -> Optional[str]:
        r = _get_redis()
        if not r:
            return None
        try:
            return r.get(f"dna:session_actor:{session_id}")
        except Exception:
            return None

_dna_engine: Optional[BehavioralDNAEngine] = None

def get_dna_engine() -> BehavioralDNAEngine:
    global _dna_engine
    if _dna_engine is None:
        _dna_engine = BehavioralDNAEngine()
    return _dna_engine
