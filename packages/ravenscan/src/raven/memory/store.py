"""Repository Memory — SQLite-backed historical storage.

The original scan and false-positive tables remain unchanged. Additive finding
observations provide stable identity, regression state, and recurring debt
without requiring a migration of existing JSON artifacts.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from sqlalchemy import Column, DateTime, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Session

from raven.core.models import SecurityFinding, normalize_finding_evidence
from raven.memory import gate


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
    # R-02: stamped versions of the two inputs that pin report determinism.
    ruleset_version = Column(String(32), nullable=True)
    template_version = Column(String(32), nullable=True)


class RunSummary(Base):
    """R-01: structured post-run reflection, derived only from verified records."""

    __tablename__ = "run_summaries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    scope = Column(String(256), nullable=False)
    scan_id = Column(Integer, nullable=True, index=True)
    prev_scan_id = Column(Integer, nullable=True)
    ruleset_version = Column(String(32), nullable=True)
    template_version = Column(String(32), nullable=True)
    summary_json = Column(Text, nullable=False)
    summary_hash = Column(String(64), nullable=False)


class FalsePositiveRecord(Base):
    __tablename__ = "false_positives"

    id = Column(Integer, primary_key=True, autoincrement=True)
    fingerprint = Column(String(512), nullable=False, unique=True, index=True)
    filepath = Column(String(512), nullable=False)
    line = Column(Integer, nullable=False)
    analyzer = Column(String(64), nullable=False)
    reason = Column(Text, nullable=True)
    marked_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    # Soft-delete tombstone: rows stay until an explicit audited purge.
    deleted_at = Column(DateTime, nullable=True)


class MemoryAuditRecord(Base):
    """Append-only audit chain for every gated memory operation."""

    __tablename__ = "memory_audit"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    action = Column(String(32), nullable=False)
    record_type = Column(String(32), nullable=False)
    record_ref = Column(String(512), nullable=True)
    scope = Column(String(256), nullable=False)
    reason_code = Column(String(128), nullable=True)
    before_hash = Column(String(64), nullable=True)
    after_hash = Column(String(64), nullable=True)


class MemoryConfig(Base):
    """Store-level switches (kill switch: memory disable/enable)."""

    __tablename__ = "memory_config"

    key = Column(String(64), primary_key=True)
    value = Column(String(16), nullable=False)


class OperatorPreference(Base):
    """R-03: explicit operator-owned key/value preferences (class OPERATOR_PREFERENCE).

    Allow-listed keys only — preferences can never become policy (gate
    behavior, kill switch, scope, and phases are not preference-addressable).
    Written only via the operator CLI, never from scan content.
    """

    __tablename__ = "operator_preferences"

    key = Column(String(64), primary_key=True)
    value = Column(String(128), nullable=False)
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class FindingObservation(Base):
    """One finding's state at one scan revision."""

    __tablename__ = "finding_observations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(String(128), nullable=False, index=True)
    scan_id = Column(Integer, nullable=True, index=True)
    observed_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    state = Column(String(32), nullable=False)
    source_file = Column(String(512), nullable=False)
    line_start = Column(Integer, nullable=True)
    severity = Column(String(16), nullable=False)
    cwe_id = Column(String(32), nullable=False)
    evidence = Column(Text, nullable=False)
    commit_sha = Column(String(64), nullable=True)
    branch = Column(String(128), nullable=True)
    recurrence_count = Column(Integer, nullable=False, default=0)
    resolution_count = Column(Integer, nullable=False, default=0)
    reintroduction_count = Column(Integer, nullable=False, default=0)


class DetectorOutcomeRecord(Base):
    """Explicit operator feedback for advisory detector calibration."""

    __tablename__ = "detector_outcomes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    detector = Column(String(128), nullable=False, index=True)
    outcome = Column(String(32), nullable=False)
    finding_id = Column(String(128), nullable=True, index=True)
    reason = Column(Text, nullable=True)
    recorded_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class MemoryStore:
    """SQLite-backed store for scans, findings, and false-positive tracking."""

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
            # Additive migration: tombstone column for pre-existing DBs.
            cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(false_positives)")}
            if "deleted_at" not in cols:
                conn.exec_driver_sql("ALTER TABLE false_positives ADD COLUMN deleted_at DATETIME")
            scan_cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(scan_records)")}
            for col in ("ruleset_version", "template_version"):
                if col not in scan_cols:
                    conn.exec_driver_sql(f"ALTER TABLE scan_records ADD COLUMN {col} VARCHAR(32)")
            conn.commit()
        # Structural scope: one store file per project — never shared, never
        # widened by a flag (deliverable 6: scope is structural, not a flag).
        self.scope = str(self.db_path.resolve().parent.parent)
        self._env_off = os.getenv("RAVEN_MEMORY", "1").strip().lower() in {"0", "off", "false", "no"}
        self._disabled = self._env_off or self._config_off()

    @property
    def enabled(self) -> bool:
        return not self._disabled

    def _admit(self, field: str, value: str | None, record_type: str) -> str:
        """Gate an operator field; rejections are audited with their code."""
        try:
            return gate.admit_operator_text(field, value)
        except gate.GateRejected as exc:
            digest = hashlib.sha256(str(value or "").encode("utf-8", "replace")).hexdigest()[:16]
            self.audit(
                "reject",
                record_type=record_type,
                record_ref=f"sha256:{digest}",
                reason_code=exc.reason_code,
            )
            raise

    def _config_off(self) -> bool:
        with Session(self.engine) as session:
            row = session.get(MemoryConfig, "disabled")
            return row is not None and row.value == "1"

    def _set_config(self, key: str, value: str) -> None:
        with Session(self.engine) as session:
            row = session.get(MemoryConfig, key)
            if row is None:
                session.add(MemoryConfig(key=key, value=value))
            else:
                row.value = value
            session.commit()

    @staticmethod
    def _audit(
        session: Session,
        action: str,
        *,
        record_type: str,
        record_ref: str | None = None,
        reason_code: str | None = None,
        before_hash: str | None = None,
        after_hash: str | None = None,
        scope: str = "",
    ) -> None:
        """Audit entry in the CALLER's session (atomic with the write)."""
        session.add(MemoryAuditRecord(
            action=action,
            record_type=record_type,
            record_ref=record_ref,
            scope=scope,
            reason_code=reason_code,
            before_hash=before_hash,
            after_hash=after_hash,
        ))

    def audit(self, action: str, **kwargs: Any) -> int:
        """Standalone audit entry (rejections and control actions)."""
        with Session(self.engine) as session:
            self._audit(session, action, scope=self.scope, **kwargs)
            session.commit()
            row = session.query(MemoryAuditRecord).order_by(MemoryAuditRecord.id.desc()).first()
            return int(row.id) if row else 0

    def audit_log(self, limit: int = 50) -> list[dict[str, Any]]:
        with Session(self.engine) as session:
            rows = (
                session.query(MemoryAuditRecord)
                .order_by(MemoryAuditRecord.id.desc())
                .limit(limit)
                .all()
            )
        return [{
            "id": r.id,
            "ts": r.ts.isoformat() if r.ts else None,
            "action": r.action,
            "record_type": r.record_type,
            "record_ref": r.record_ref,
            "scope": r.scope,
            "reason_code": r.reason_code,
            "before_hash": r.before_hash,
            "after_hash": r.after_hash,
        } for r in rows]

    def disable(self) -> bool:
        """Kill switch: all reads fail closed, all record writes refuse."""
        self._set_config("disabled", "1")
        self._disabled = True
        with Session(self.engine) as session:
            self._audit(session, "disable", record_type="store",
                        record_ref=str(self.db_path), scope=self.scope,
                        after_hash=gate.record_hash(self.scope, "disabled"))
            session.commit()
        return True

    def enable(self) -> bool:
        """Re-enable unless the RAVEN_MEMORY env kill switch is active."""
        self._set_config("disabled", "0")
        self._disabled = self._env_off
        with Session(self.engine) as session:
            self._audit(
                session,
                "enable" if not self._disabled else "reject",
                record_type="store",
                record_ref=str(self.db_path),
                reason_code="env_kill_switch" if self._disabled else None,
                scope=self.scope,
            )
            session.commit()
        return not self._disabled

    # ------------------------------------------------------------------
    # R-03: project-scoped operator preferences.
    #
    # Explicit key/value only. Keys are allow-listed (POLICY_KEYS can never
    # be written), values pass MemoryGate, and every write is audited with
    # before/after hashes. Writable only through this operator API — no scan
    # content path reaches here. Empty table = inert (rollback by unset).

    PREFERENCE_KEYS = ("format", "fail_under")
    POLICY_KEYS = ("disabled", "scope", "phases", "gate")

    def preferences(self) -> dict[str, str]:
        """Operator preferences for this project scope (inert when empty)."""
        if not self.enabled:
            return {}
        with Session(self.engine) as session:
            rows = session.query(OperatorPreference).order_by(OperatorPreference.key.asc()).all()
            return {row.key: row.value for row in rows}

    def set_preference(self, key: str, value: str) -> bool:
        """Set one allow-listed preference; audited, gated, scope-bound."""
        if not self.enabled:
            self.audit("reject", record_type="operator_preference", record_ref=key, reason_code="disabled")
            raise gate.GateRejected("disabled")
        key = self._admit("pref_key", key, "operator_preference")
        value = self._admit("pref_value", value, "operator_preference")
        if key in self.POLICY_KEYS or key not in self.PREFERENCE_KEYS:
            with Session(self.engine) as session:
                self._audit(session, "reject", record_type="operator_preference",
                            record_ref=key, reason_code="key_not_allowlisted", scope=self.scope)
                session.commit()
            raise gate.GateRejected("key_not_allowlisted")
        # Typed validation per key (deterministic; no free-form values).
        if key == "format" and value not in ("json", "markdown", "sarif"):
            raise ValueError("format preference must be 'json', 'markdown', or 'sarif'")
        if key == "fail_under":
            try:
                number = float(value)
            except ValueError:
                raise ValueError("fail_under preference must be a number 0-100")
            if not (0 <= number <= 100):
                raise ValueError("fail_under preference must be between 0 and 100")
        with Session(self.engine) as session:
            existing = session.get(OperatorPreference, key)
            before = gate.record_hash(existing.value) if existing else None
            if existing is None:
                session.add(OperatorPreference(key=key, value=value))
            else:
                existing.value = value
                existing.updated_at = datetime.now(timezone.utc)
            self._audit(session, "set_pref", record_type="operator_preference",
                        record_ref=key, before_hash=before,
                        after_hash=gate.record_hash(value), scope=self.scope)
            session.commit()
        return True

    def unset_preference(self, key: str) -> bool:
        """Remove a stored preference (rollback is first-class)."""
        if not self.enabled:
            self.audit("reject", record_type="operator_preference", record_ref=key, reason_code="disabled")
            raise gate.GateRejected("disabled")
        with Session(self.engine) as session:
            record = session.get(OperatorPreference, key)
            if record is None:
                self._audit(session, "reject", record_type="operator_preference",
                            record_ref=key, reason_code="missing", scope=self.scope)
                session.commit()
                return False
            before = gate.record_hash(record.value)
            session.delete(record)
            self._audit(session, "unset_pref", record_type="operator_preference",
                        record_ref=key, before_hash=before, scope=self.scope)
            session.commit()
            return True

    def list_detector_outcomes(self, limit: int = 500) -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        with Session(self.engine) as session:
            rows = (
                session.query(DetectorOutcomeRecord)
                .order_by(DetectorOutcomeRecord.recorded_at.desc())
                .limit(limit)
                .all()
            )
        return [{
            "id": r.id,
            "detector": r.detector,
            "outcome": r.outcome,
            "finding_id": r.finding_id,
            "reason": r.reason,
            "recorded_at": r.recorded_at.isoformat() if r.recorded_at else None,
        } for r in rows]

    def export_memory(self) -> dict[str, Any]:
        """Class-labeled export; SECRET_NEVER_STORE has no rows by construction."""
        if not self.enabled:
            raise gate.GateRejected("disabled")
        payload: dict[str, Any] = {
            "scope": self.scope,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "classes": {
                "VERIFIED_EVIDENCE": {
                    "false_positives": self.get_false_positives(include_deleted=True),
                    "detector_outcomes": self.list_detector_outcomes(),
                },
                "OPERATOR_PREFERENCE": [
                    {"key": key, "value": value}
                    for key, value in self.preferences().items()
                ],
            },
        }
        reasons = gate.secret_reasons(json.dumps(payload))
        if reasons:
            raise gate.GateRejected(f"secret:{reasons[0]}@export")
        with Session(self.engine) as session:
            self._audit(session, "export", record_type="store",
                        record_ref=str(self.db_path), scope=self.scope)
            session.commit()
        return payload

    def verify_integrity(self) -> list[dict[str, Any]]:
        """Tamper visibility: current record hash vs last audited after_hash."""
        mismatches: list[dict[str, Any]] = []
        with Session(self.engine) as session:
            rows = (
                session.query(FalsePositiveRecord)
                .filter(FalsePositiveRecord.deleted_at.is_(None))
                .all()
            )
            latest: dict[str, str] = {}
            audited = (
                session.query(MemoryAuditRecord)
                .filter(
                    MemoryAuditRecord.record_type == "false_positive",
                    MemoryAuditRecord.after_hash.isnot(None),
                )
                .order_by(MemoryAuditRecord.id.asc())
                .all()
            )
            for entry in audited:
                if entry.record_ref:
                    latest[entry.record_ref] = entry.after_hash
            for record in rows:
                current = gate.record_hash(
                    record.fingerprint, record.filepath, str(record.line),
                    record.analyzer, record.reason or "",
                )
                expected = latest.get(record.fingerprint)
                if expected is not None and expected != current:
                    mismatches.append({
                        "fingerprint": record.fingerprint,
                        "expected": expected,
                        "current": current,
                    })
        return mismatches

    def save(
        self,
        profile: dict[str, Any] | None = None,
        architecture: dict[str, Any] | None = None,
        security: dict[str, Any] | None = None,
        score: dict[str, Any] | None = None,
        commit_sha: str | None = None,
        branch: str | None = None,
        ruleset_version: str | None = None,
        template_version: str | None = None,
    ) -> int:
        """Persist a scan snapshot and return the record ID."""
        if not self.enabled:
            return 0

        def _safe(payload: dict[str, Any] | None) -> tuple[str | None, list[str]]:
            if not payload:
                return None, []
            return gate.redact_scan_text(json.dumps(payload), truncate=False)

        profile_json, p_codes = _safe(profile)
        architecture_json, a_codes = _safe(architecture)
        security_json, s_codes = _safe(security)
        score_json, sc_codes = _safe(score)
        with Session(self.engine) as session:
            record = ScanRecord(
                profile_json=profile_json,
                architecture_json=architecture_json,
                security_json=security_json,
                score_json=score_json,
                overall_score=score.get("overall") if score else None,
                commit_sha=commit_sha,
                branch=branch,
                ruleset_version=ruleset_version,
                template_version=template_version,
            )
            session.add(record)
            session.flush()
            codes = sorted(set(p_codes + a_codes + s_codes + sc_codes))
            if codes:
                self._audit(
                    session,
                    "admit",
                    record_type="scan_record",
                    record_ref=str(record.id),
                    reason_code="redacted:" + ",".join(codes),
                    scope=self.scope,
                )
            session.commit()
            return int(record.id)

    def update_security_snapshot(self, scan_id: int, security: dict[str, Any]) -> bool:
        """Update a saved scan with post-reconciliation security metadata."""
        if not self.enabled:
            return False
        safe_json, codes = gate.redact_scan_text(json.dumps(security), truncate=False)
        with Session(self.engine) as session:
            record = session.get(ScanRecord, scan_id)
            if record is None:
                return False
            record.security_json = safe_json
            if codes:
                self._audit(
                    session,
                    "admit",
                    record_type="scan_record",
                    record_ref=str(scan_id),
                    reason_code="redacted:" + ",".join(sorted(set(codes))),
                    scope=self.scope,
                )
            session.commit()
            return True

    def reconcile_findings(
        self,
        findings: list[SecurityFinding],
        *,
        scan_id: int | None = None,
        scanned_at: datetime | None = None,
        commit_sha: str | None = None,
        branch: str | None = None,
    ) -> list[SecurityFinding]:
        """Record current findings and mark absent active findings resolved.

        State is derived only from stored observations of the same stable ID:
        new, existing, changed, reintroduced, or resolved. A finding's source
        path and line are retained as evidence but never define its identity.
        """
        now = scanned_at or datetime.now(timezone.utc)
        if not self.enabled:
            return findings
        current_ids = {f.finding_id for f in findings}
        with Session(self.engine) as session:
            latest_by_id: dict[str, FindingObservation] = {}
            first_seen_by_id: dict[str, datetime] = {}
            for row in session.query(FindingObservation).order_by(FindingObservation.observed_at.asc()).all():
                latest_by_id[row.finding_id] = row
                if row.state != "resolved" and row.finding_id not in first_seen_by_id:
                    first_seen_by_id[row.finding_id] = row.observed_at

            for finding in findings:
                safe_evidence, ev_codes = gate.redact_scan_text(finding.evidence)
                if ev_codes:
                    self._audit(
                        session,
                        "admit",
                        record_type="observation",
                        record_ref=finding.finding_id,
                        reason_code="redacted:" + ",".join(sorted(set(ev_codes))),
                        scope=self.scope,
                    )
                previous = latest_by_id.get(finding.finding_id)
                if previous is None:
                    state = "new"
                    recurrence = 0
                    resolutions = 0
                    reintroductions = 0
                    first_seen = now.isoformat()
                else:
                    recurrence = previous.recurrence_count
                    resolutions = previous.resolution_count
                    reintroductions = previous.reintroduction_count
                    first_seen = first_seen_by_id.get(finding.finding_id, previous.observed_at).isoformat()
                    if previous.state == "resolved":
                        state = "reintroduced"
                        reintroductions += 1
                    elif normalize_finding_evidence(safe_evidence) != normalize_finding_evidence(previous.evidence) or previous.severity != finding.severity.value:
                        state = "changed"
                    else:
                        state = "existing"
                    recurrence += 1

                observation = FindingObservation(
                    finding_id=finding.finding_id,
                    scan_id=scan_id,
                    observed_at=now,
                    state=state,
                    source_file=finding.affected_file,
                    line_start=finding.affected_lines[0] if finding.affected_lines else None,
                    severity=finding.severity.value,
                    cwe_id=finding.cwe.cwe_id,
                    evidence=safe_evidence,
                    commit_sha=commit_sha,
                    branch=branch,
                    recurrence_count=recurrence,
                    resolution_count=resolutions,
                    reintroduction_count=reintroductions,
                )
                session.add(observation)
                finding.historical_state = state
                finding.first_seen = first_seen
                finding.last_seen = now.isoformat()
                finding.recurrence_count = recurrence
                finding.resolution_count = resolutions
                finding.reintroduction_count = reintroductions

            for finding_id, previous in latest_by_id.items():
                if finding_id not in current_ids and previous.state not in ("resolved",):
                    session.add(FindingObservation(
                        finding_id=finding_id,
                        scan_id=scan_id,
                        observed_at=now,
                        state="resolved",
                        source_file=previous.source_file,
                        line_start=previous.line_start,
                        severity=previous.severity,
                        cwe_id=previous.cwe_id,
                        evidence=previous.evidence,
                        commit_sha=commit_sha,
                        branch=branch,
                        recurrence_count=previous.recurrence_count,
                        resolution_count=previous.resolution_count + 1,
                        reintroduction_count=previous.reintroduction_count,
                    ))
            session.commit()
        return findings

    def record_detector_outcome(
        self,
        detector: str,
        outcome: str,
        *,
        finding_id: str | None = None,
        reason: str = "",
    ) -> bool:
        """Record explicit detector feedback for advisory calibration.

        Outcomes are intentionally not used to suppress findings automatically.
        """
        if not self.enabled:
            self.audit(
                "reject",
                record_type="detector_outcome",
                record_ref=finding_id or detector,
                reason_code="disabled",
            )
            raise gate.GateRejected("disabled")
        detector = self._admit("detector", detector, "detector_outcome")
        reason = self._admit("reason", reason, "detector_outcome")
        if finding_id:
            finding_id = self._admit("finding_id", finding_id, "detector_outcome")
        allowed = {"confirmed", "false_positive", "accepted_risk", "unresolved", "recurring", "fixed", "reintroduced"}
        if outcome not in allowed:
            raise ValueError(f"outcome must be one of {sorted(allowed)}")
        with Session(self.engine) as session:
            session.add(DetectorOutcomeRecord(
                detector=detector,
                outcome=outcome,
                finding_id=finding_id,
                reason=reason,
            ))
            self._audit(
                session,
                "admit",
                record_type="detector_outcome",
                record_ref=f"{detector}:{finding_id or '-'}",
                after_hash=gate.record_hash(detector, outcome, finding_id or "", reason),
                scope=self.scope,
            )
            session.commit()
        return True

    def latest_feedback(self) -> dict[str, str]:
        """Return the latest explicit outcome for each finding identity."""
        if not self.enabled:
            return {}
        with Session(self.engine) as session:
            rows = session.query(DetectorOutcomeRecord).filter(
                DetectorOutcomeRecord.finding_id.isnot(None)
            ).order_by(DetectorOutcomeRecord.recorded_at.asc()).all()
        latest: dict[str, str] = {}
        for row in rows:
            if row.finding_id:
                latest[row.finding_id] = row.outcome
        return latest

    def apply_feedback(self, findings: list[SecurityFinding]) -> list[SecurityFinding]:
        """Attach advisory operator outcomes without suppressing findings."""
        feedback = self.latest_feedback()
        for finding in findings:
            outcome = feedback.get(finding.finding_id, "")
            if outcome:
                finding.feedback_outcome = outcome
                finding.accepted_risk = outcome == "accepted_risk"
        return findings

    def detector_calibration(self) -> dict[str, dict[str, Any]]:
        """Return advisory outcome counts and rates grouped by detector.

        Historical observations provide unresolved/recurring/fixed signals;
        explicit feedback supplies confirmed/false-positive outcomes.
        """
        if not self.enabled:
            return {}
        with Session(self.engine) as session:
            rows = session.query(DetectorOutcomeRecord).all()
            observations = session.query(FindingObservation).order_by(FindingObservation.observed_at.asc()).all()
        result: dict[str, dict[str, Any]] = {}
        for row in rows:
            bucket = result.setdefault(row.detector, {"confirmed": 0, "false_positive": 0, "accepted_risk": 0, "unresolved": 0, "recurring": 0, "fixed": 0, "reintroduced": 0, "sample_size": 0, "false_positive_rate": None})
            bucket[row.outcome] += 1
        latest: dict[str, FindingObservation] = {}
        for row in observations:
            latest[row.finding_id] = row
        for row in latest.values():
            detector = {
                "CWE-78": "command_injection",
                "CWE-89": "sql_injection",
                "CWE-798": "hardcoded_secret",
                "CWE-327": "weak_crypto",
                "CWE-502": "unsafe_deserialization",
                "CWE-306": "missing_auth",
                "CWE-22": "path_traversal",
                "CWE-338": "insecure_random",
                "CWE-918": "ssrf",
                "CWE-79": "xss",
                "CWE-601": "open_redirect",
            }.get(row.cwe_id, row.cwe_id)
            bucket = result.setdefault(detector, {"confirmed": 0, "false_positive": 0, "accepted_risk": 0, "unresolved": 0, "recurring": 0, "fixed": 0, "reintroduced": 0, "sample_size": 0, "false_positive_rate": None})
            if row.state == "resolved":
                bucket["fixed"] += 1
            else:
                bucket["unresolved"] += 1
            if row.recurrence_count > 0 or row.reintroduction_count > 0:
                bucket["recurring"] += 1
        for bucket in result.values():
            bucket["sample_size"] = bucket["confirmed"] + bucket["false_positive"] + bucket["accepted_risk"] + bucket["unresolved"] + bucket["fixed"] + bucket["reintroduced"]
            labeled = bucket["confirmed"] + bucket["false_positive"]
            bucket["false_positive_rate"] = (bucket["false_positive"] / labeled) if labeled else None
        return result

    def finding_history(self, finding_id: str) -> list[dict[str, Any]]:
        """Return observation history for one stable finding identity."""
        with Session(self.engine) as session:
            rows = session.query(FindingObservation).filter_by(finding_id=finding_id).order_by(FindingObservation.observed_at.asc()).all()
            return [{
                "state": row.state,
                "observed_at": row.observed_at.isoformat(),
                "source_file": row.source_file,
                "severity": row.severity,
                "cwe_id": row.cwe_id,
                "recurrence_count": row.recurrence_count,
                "resolution_count": row.resolution_count,
                "reintroduction_count": row.reintroduction_count,
            } for row in rows]

    def recurring_debt(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return findings with repeated observations or reintroductions."""
        with Session(self.engine) as session:
            rows = session.query(FindingObservation).order_by(FindingObservation.observed_at.desc()).all()
            latest: dict[str, FindingObservation] = {}
            for row in rows:
                latest.setdefault(row.finding_id, row)
            return [{
                "finding_id": row.finding_id,
                "recurrence_count": row.recurrence_count,
                "first_seen": self.finding_history(row.finding_id)[0]["observed_at"],
                "most_recent": row.observed_at.isoformat(),
                "resolution_count": row.resolution_count,
                "reintroduction_count": row.reintroduction_count,
                "file": row.source_file,
                "cwe_id": row.cwe_id,
                "severity": row.severity,
            } for row in list(latest.values())[:limit] if row.recurrence_count > 0 or row.reintroduction_count > 0]

    def latest(self) -> Optional[ScanRecord]:
        with Session(self.engine) as session:
            return session.query(ScanRecord).order_by(ScanRecord.scanned_at.desc()).first()

    def latest_versions(self) -> dict[str, str | None]:
        """Stamped ruleset/template versions of the previous scan (R-02 drift detection)."""
        record = self.latest()
        if record is None:
            return {}
        return {
            "ruleset": record.ruleset_version,
            "template": record.template_version,
        }

    def build_run_summary(
        self,
        scan_id: int,
        *,
        commit_sha: str | None = None,
        branch: str | None = None,
        finding_states: dict[str, int] | None = None,
        total_findings: int = 0,
        critical: int = 0,
        high: int = 0,
        ruleset_version: str | None = None,
        template_version: str | None = None,
    ) -> dict[str, Any] | None:
        """R-01 post-run reflection: derived only from gate-verified records.

        Returns the stored summary dict; None when memory is off or the scan
        record is missing (memory must never fail a scan — callers degrade).
        """
        if not self.enabled:
            return None
        states = dict(finding_states or {})
        with Session(self.engine) as session:
            current = session.get(ScanRecord, scan_id)
            if current is None:
                return None
            prev = (
                session.query(ScanRecord)
                .filter(ScanRecord.id < scan_id)
                .order_by(ScanRecord.id.desc())
                .first()
            )
            resolved = (
                session.query(FindingObservation)
                .filter(FindingObservation.state == "resolved")
                .count()
            )
            fp_count = (
                session.query(FalsePositiveRecord)
                .filter(FalsePositiveRecord.deleted_at.is_(None))
                .count()
            )
            outcome_count = session.query(DetectorOutcomeRecord).count()
            score_now = current.overall_score
            prev_score = prev.overall_score if prev is not None else None
            prev_scan = None
            if prev is not None:
                prev_scan = {
                    "scan_id": int(prev.id),
                    "scanned_at": prev.scanned_at.isoformat(),
                    "commit": prev.commit_sha,
                    "branch": prev.branch,
                    "score": prev.overall_score,
                }
        delta = None
        if score_now is not None and prev_score is not None:
            delta = round(float(score_now) - float(prev_score), 2)
        # Deterministic ordering regardless of observation timestamps.
        debt = sorted(
            self.recurring_debt(limit=20),
            key=lambda d: (-int(d.get("reintroduction_count", 0)), str(d.get("finding_id", ""))),
        )[:5]
        summary: dict[str, Any] = {
            "schema": "run_summary/1",
            "scan_id": int(scan_id),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "scope": self.scope,
            "first_run": prev is None,
            "score": {"current": score_now, "previous": prev_score, "delta": delta},
            "findings": {
                "total": int(total_findings),
                "critical": int(critical),
                "high": int(high),
                "new": int(states.get("new", 0)),
                "existing": int(states.get("existing", 0)),
                "reintroduced": int(states.get("reintroduced", 0)),
                "resolved": int(resolved),
            },
            "recurring_debt": [
                {
                    "finding_id": d.get("finding_id"),
                    "reintroduction_count": d.get("reintroduction_count", 0),
                    "recurrence_count": d.get("recurrence_count", 0),
                    "severity": d.get("severity"),
                }
                for d in debt
            ],
            "memory": {"false_positives": fp_count, "detector_outcomes": outcome_count},
            "revisions": {
                "current": {"commit": commit_sha, "branch": branch},
                "previous": prev_scan,
            },
            "versions": {"ruleset": ruleset_version, "template": template_version},
        }
        # Derived data still passes the choke point (deliverable 6 §3).
        safe_json, codes = gate.redact_scan_text(json.dumps(summary), truncate=False)
        summary = json.loads(safe_json)
        with Session(self.engine) as session:
            session.add(RunSummary(
                scope=self.scope,
                scan_id=int(scan_id),
                prev_scan_id=summary["revisions"]["previous"]["scan_id"] if summary["revisions"]["previous"] else None,
                ruleset_version=ruleset_version,
                template_version=template_version,
                summary_json=safe_json,
                summary_hash=gate.record_hash(self.scope, safe_json),
            ))
            if codes:
                self._audit(
                    session,
                    "admit",
                    record_type="run_summary",
                    record_ref=str(scan_id),
                    reason_code="redacted:" + ",".join(sorted(set(codes))),
                    scope=self.scope,
                )
            session.commit()
        return summary

    def compare_scans(self, base_id: int | None = None, head_id: int | None = None) -> dict[str, Any] | None:
        """R-04: deterministic what-changed view between two stored scans.

        Pure function of gate-verified observations: same stored rows always
        produce the same comparison (ordering by stable finding_id, never by
        timestamp). Returns None when memory is off or either scan is missing.
        """
        if not self.enabled:
            return None
        with Session(self.engine) as session:
            if head_id is None:
                head = session.query(ScanRecord).order_by(ScanRecord.id.desc()).first()
            else:
                head = session.get(ScanRecord, head_id)
            if head is None:
                return None
            if base_id is None:
                base = (
                    session.query(ScanRecord)
                    .filter(ScanRecord.id < head.id)
                    .order_by(ScanRecord.id.desc())
                    .first()
                )
            else:
                base = session.get(ScanRecord, base_id)
            if base is None:
                return None

            def _active(scan_pk: int) -> dict[str, FindingObservation]:
                rows = (
                    session.query(FindingObservation)
                    .filter(FindingObservation.scan_id == scan_pk)
                    .order_by(FindingObservation.id.asc())
                    .all()
                )
                latest: dict[str, FindingObservation] = {}
                for row in rows:
                    latest[row.finding_id] = row
                return {fid: row for fid, row in latest.items() if row.state != "resolved"}

            base_active = _active(base.id)
            head_active = _active(head.id)

            def _entry(row: FindingObservation) -> dict[str, Any]:
                return {
                    "finding_id": row.finding_id,
                    "severity": row.severity,
                    "cwe_id": row.cwe_id,
                    "file": row.source_file,
                    "state": row.state,
                }

            # A reintroduced finding (resolved before, now back) is recurring
            # debt, not a brand-new finding — surface it as such (R-04).
            new = [
                _entry(head_active[fid])
                for fid in sorted(set(head_active) - set(base_active))
                if head_active[fid].state != "reintroduced"
            ]
            resolved = [_entry(base_active[fid]) for fid in sorted(set(base_active) - set(head_active))]
            recurring = [
                _entry(head_active[fid])
                for fid in sorted(set(head_active) - set(base_active))
                if head_active[fid].state == "reintroduced"
            ] + [
                _entry(head_active[fid])
                for fid in sorted(set(base_active) & set(head_active))
                if head_active[fid].reintroduction_count > 0 or head_active[fid].recurrence_count > 1
            ]
            severity_changed = [
                {
                    "finding_id": fid,
                    "from": base_active[fid].severity,
                    "to": head_active[fid].severity,
                }
                for fid in sorted(set(base_active) & set(head_active))
                if base_active[fid].severity != head_active[fid].severity
            ]

            score_now = head.overall_score
            score_prev = base.overall_score
            score_delta = None
            if score_now is not None and score_prev is not None:
                score_delta = round(float(score_now) - float(score_prev), 2)

            comparison: dict[str, Any] = {
                "schema": "run_comparison/1",
                "base": {"scan_id": int(base.id), "scanned_at": base.scanned_at.isoformat()},
                "head": {"scan_id": int(head.id), "scanned_at": head.scanned_at.isoformat()},
                "score": {"current": score_now, "previous": score_prev, "delta": score_delta},
                "new": new,
                "resolved": resolved,
                "recurring": recurring,
                "severity_changed": severity_changed,
            }
        # Derived data still passes the choke point (deliverable 6 §3).
        safe_json, codes = gate.redact_scan_text(json.dumps(comparison), truncate=False)
        comparison = json.loads(safe_json)
        if codes:
            self.audit(
                "admit",
                record_type="run_comparison",
                record_ref=f"{base.id}->{head.id}",
                reason_code="redacted:" + ",".join(sorted(set(codes))),
            )
        return comparison

    def all(self, limit: int = 50) -> list[ScanRecord]:
        with Session(self.engine) as session:
            return session.query(ScanRecord).order_by(ScanRecord.scanned_at.desc()).limit(limit).all()

    def score_history(self, limit: int = 50) -> list[dict[str, object]]:
        with Session(self.engine) as session:
            records = session.query(ScanRecord.scanned_at, ScanRecord.overall_score).filter(ScanRecord.overall_score.isnot(None)).order_by(ScanRecord.scanned_at.asc()).limit(limit).all()
            return [{"scanned_at": r.scanned_at.isoformat(), "score": r.overall_score} for r in records]

    def mark_false_positive(self, fingerprint: str, filepath: str, line: int, analyzer: str, reason: str = "") -> bool:
        if not self.enabled:
            self.audit("reject", record_type="false_positive", record_ref=fingerprint, reason_code="disabled")
            raise gate.GateRejected("disabled")
        fingerprint = self._admit("fingerprint", fingerprint, "false_positive")
        filepath = self._admit("filepath", filepath, "false_positive")
        analyzer = self._admit("analyzer", analyzer, "false_positive")
        reason = self._admit("reason", reason, "false_positive")
        with Session(self.engine) as session:
            existing = session.query(FalsePositiveRecord).filter_by(fingerprint=fingerprint).first()
            if existing is not None:
                if existing.deleted_at is None:
                    # Duplicate: single record stands; rejection is auditable.
                    self._audit(session, "reject", record_type="false_positive",
                                record_ref=fingerprint, reason_code="duplicate",
                                scope=self.scope)
                    session.commit()
                    return False
                # Tombstoned mark re-created by the operator: restore, audited.
                existing.deleted_at = None
                existing.reason = reason
                existing.marked_at = datetime.now(timezone.utc)
                session.add(DetectorOutcomeRecord(detector=analyzer, outcome="false_positive", reason=reason))
                after = gate.record_hash(existing.fingerprint, existing.filepath,
                                         str(existing.line), existing.analyzer, existing.reason or "")
                self._audit(session, "restore", record_type="false_positive",
                            record_ref=fingerprint, scope=self.scope, after_hash=after)
                session.commit()
                return True
            record = FalsePositiveRecord(fingerprint=fingerprint, filepath=filepath, line=line, analyzer=analyzer, reason=reason)
            session.add(record)
            session.add(DetectorOutcomeRecord(
                detector=analyzer,
                outcome="false_positive",
                reason=reason,
            ))
            session.flush()
            after = gate.record_hash(fingerprint, filepath, str(line), analyzer, reason)
            self._audit(session, "admit", record_type="false_positive",
                        record_ref=fingerprint, scope=self.scope, after_hash=after)
            session.commit()
            return True

    def edit_false_positive(self, fingerprint: str, *, reason: str | None = None, line: int | None = None) -> bool:
        """Operator correction with before/after hashes (rollback is first-class)."""
        if not self.enabled:
            self.audit("reject", record_type="false_positive", record_ref=fingerprint, reason_code="disabled")
            raise gate.GateRejected("disabled")
        with Session(self.engine) as session:
            record = session.query(FalsePositiveRecord).filter_by(fingerprint=fingerprint).first()
            if record is None or record.deleted_at is not None:
                self._audit(
                    session,
                    "reject",
                    record_type="false_positive",
                    record_ref=fingerprint,
                    reason_code="missing" if record is None else "tombstoned",
                    scope=self.scope,
                )
                session.commit()
                return False
            try:
                new_reason = gate.admit_operator_text("reason", reason) if reason is not None else (record.reason or "")
            except gate.GateRejected as exc:
                self._audit(session, "reject", record_type="false_positive",
                            record_ref=fingerprint, reason_code=exc.reason_code,
                            scope=self.scope)
                session.commit()
                raise
            before = gate.record_hash(record.fingerprint, record.filepath,
                                      str(record.line), record.analyzer, record.reason or "")
            if reason is not None:
                record.reason = new_reason
            if line is not None:
                record.line = int(line)
            after = gate.record_hash(record.fingerprint, record.filepath,
                                     str(record.line), record.analyzer, record.reason or "")
            self._audit(session, "correct", record_type="false_positive",
                        record_ref=fingerprint, scope=self.scope,
                        before_hash=before, after_hash=after)
            session.commit()
            return True

    def get_false_positives(self, *, include_deleted: bool = False) -> list[dict[str, object]]:
        if not self.enabled:
            return []
        with Session(self.engine) as session:
            query = session.query(FalsePositiveRecord)
            if not include_deleted:
                query = query.filter(FalsePositiveRecord.deleted_at.is_(None))
            records = query.all()
            return [{
                "fingerprint": r.fingerprint, "filepath": r.filepath, "line": r.line,
                "analyzer": r.analyzer, "reason": r.reason,
                "marked_at": r.marked_at.isoformat() if r.marked_at else None,
                "deleted_at": r.deleted_at.isoformat() if r.deleted_at else None,
                "scope": self.scope,
                "source": "operator",
            } for r in records]

    def remove_false_positive(self, fingerprint: str, *, hard: bool = False) -> bool:
        """Soft-delete (tombstone) by default; ``hard=True`` purges tombstones."""
        if not self.enabled:
            self.audit("reject", record_type="false_positive", record_ref=fingerprint, reason_code="disabled")
            raise gate.GateRejected("disabled")
        with Session(self.engine) as session:
            record = session.query(FalsePositiveRecord).filter_by(fingerprint=fingerprint).first()
            if record is None:
                self._audit(session, "reject", record_type="false_positive",
                            record_ref=fingerprint, reason_code="missing", scope=self.scope)
                session.commit()
                return False
            before = gate.record_hash(record.fingerprint, record.filepath,
                                      str(record.line), record.analyzer, record.reason or "")
            if hard:
                if record.deleted_at is None:
                    # Hard delete requires the soft-delete step first (two-step).
                    self._audit(session, "reject", record_type="false_positive",
                                record_ref=fingerprint, reason_code="not_tombstoned",
                                scope=self.scope)
                    session.commit()
                    return False
                session.delete(record)
                self._audit(session, "purge", record_type="false_positive",
                            record_ref=fingerprint, scope=self.scope, before_hash=before)
                session.commit()
                return True
            if record.deleted_at is not None:
                self._audit(session, "reject", record_type="false_positive",
                            record_ref=fingerprint, reason_code="tombstoned", scope=self.scope)
                session.commit()
                return False
            record.deleted_at = datetime.now(timezone.utc)
            self._audit(session, "delete", record_type="false_positive",
                        record_ref=fingerprint, scope=self.scope, before_hash=before)
            session.commit()
            return True
