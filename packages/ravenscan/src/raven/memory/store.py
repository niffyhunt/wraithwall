"""Repository Memory — SQLite-backed historical storage for v0.1.

Stores architecture snapshots, security posture, scoring history, and
false-positive tracking for confidence calibration.
Phase 8 (v0.2) will extend this for trend analysis and regression detection.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship


class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    __tablename__ = "scan_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scanned_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    schema_version = Column(String(16), default="1")
    profile_json = Column(Text, nullable=True)
    architecture_json = Column(Text, nullable=True)
    security_json = Column(Text, nullable=True)
    score_json = Column(Text, nullable=True)
    overall_score = Column(Float, nullable=True)
    commit_sha = Column(String(64), nullable=True)
    branch = Column(String(128), nullable=True)


class FalsePositiveRecord(Base):
    __tablename__ = "false_positives"

    id = Column(Integer, primary_key=True, autoincrement=True)
    fingerprint = Column(String(512), nullable=False, unique=True, index=True)
    filepath = Column(String(512), nullable=False)
    line = Column(Integer, nullable=False)
    analyzer = Column(String(64), nullable=False)
    reason = Column(Text, nullable=True)
    marked_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class MemoryStore:
    """SQLite-backed store for scan history and false-positive tracking."""

    def __init__(self, db_path: str | Path = ".raven/history.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(
            f"sqlite:///{self.db_path}",
            echo=False,
            connect_args={"check_same_thread": False},
        )
        Base.metadata.create_all(self.engine)
        with self.engine.connect() as conn:
            conn.exec_driver_sql("PRAGMA journal_mode=WAL")
            conn.commit()

    def save(
        self,
        profile: dict[str, object] | None = None,
        architecture: dict[str, object] | None = None,
        security: dict[str, object] | None = None,
        score: dict[str, object] | None = None,
        commit_sha: str | None = None,
        branch: str | None = None,
    ) -> int:
        """Persist a scan snapshot and return the record ID."""
        with Session(self.engine) as session:
            record = ScanRecord(
                profile_json=json.dumps(profile) if profile else None,
                architecture_json=json.dumps(architecture) if architecture else None,
                security_json=json.dumps(security) if security else None,
                score_json=json.dumps(score) if score else None,
                overall_score=score.get("overall") if score else None,
                commit_sha=commit_sha,
                branch=branch,
            )
            session.add(record)
            session.commit()
            return record.id  # type: ignore[return-value]

    def latest(self) -> Optional[ScanRecord]:
        """Return the most recent scan record."""
        with Session(self.engine) as session:
            return session.query(ScanRecord).order_by(ScanRecord.scanned_at.desc()).first()

    def all(self, limit: int = 50) -> list[ScanRecord]:
        """Return recent scan records."""
        with Session(self.engine) as session:
            return (
                session.query(ScanRecord)
                .order_by(ScanRecord.scanned_at.desc())
                .limit(limit)
                .all()
            )

    def score_history(self, limit: int = 50) -> list[dict[str, object]]:
        """Return overall score over time for trend analysis."""
        with Session(self.engine) as session:
            records = (
                session.query(ScanRecord.scanned_at, ScanRecord.overall_score)
                .filter(ScanRecord.overall_score.isnot(None))
                .order_by(ScanRecord.scanned_at.asc())
                .limit(limit)
                .all()
            )
            return [
                {"scanned_at": r.scanned_at.isoformat(), "score": r.overall_score}
                for r in records
            ]

    def mark_false_positive(
        self,
        fingerprint: str,
        filepath: str,
        line: int,
        analyzer: str,
        reason: str = "",
    ) -> bool:
        """Record a finding as a false positive so it is suppressed in future scans.
        Returns True if the record was created, False if it already existed.
        """
        with Session(self.engine) as session:
            existing = session.query(FalsePositiveRecord).filter_by(fingerprint=fingerprint).first()
            if existing:
                return False
            record = FalsePositiveRecord(
                fingerprint=fingerprint,
                filepath=filepath,
                line=line,
                analyzer=analyzer,
                reason=reason,
            )
            session.add(record)
            session.commit()
            return True

    def get_false_positives(self) -> list[dict[str, object]]:
        """Return all recorded false positives for suppression."""
        with Session(self.engine) as session:
            records = session.query(FalsePositiveRecord).all()
            return [
                {
                    "fingerprint": r.fingerprint,
                    "filepath": r.filepath,
                    "line": r.line,
                    "analyzer": r.analyzer,
                    "reason": r.reason,
                    "marked_at": r.marked_at.isoformat() if r.marked_at else None,
                }
                for r in records
            ]

    def remove_false_positive(self, fingerprint: str) -> bool:
        """Remove a false positive record. Returns True if deleted."""
        with Session(self.engine) as session:
            record = session.query(FalsePositiveRecord).filter_by(fingerprint=fingerprint).first()
            if not record:
                return False
            session.delete(record)
            session.commit()
            return True
