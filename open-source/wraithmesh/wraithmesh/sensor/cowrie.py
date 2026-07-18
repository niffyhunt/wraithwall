"""Incremental Cowrie JSON log tailer → signed observations."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from honeypot_mitre import analyze_session
from honeypot_mitre.parsing import Session, parse_events

from ..manifest import MeshManifest
from ..models import Observation
from ..signing import load_key
from ..store import LocalStore


class CowrieTailSensor:
    """Tail a Cowrie JSON log, collapse locally, emit signed observations."""

    def __init__(self, manifest: MeshManifest, store: LocalStore | None = None) -> None:
        self.manifest = manifest
        self.store = store or LocalStore(manifest.state_dir)
        self._offset_path = Path(manifest.state_dir) / "cowrie.offset"
        self._sessions: dict[str, Session] = {}
        self._key = load_key(manifest.signing_key_env)

    def _load_offset(self) -> int:
        if not self._offset_path.exists():
            return 0
        try:
            return int(self._offset_path.read_text(encoding="utf-8").strip())
        except ValueError:
            return 0

    def _save_offset(self, offset: int) -> None:
        self._offset_path.write_text(str(offset), encoding="utf-8")

    def _thresholds(self) -> tuple[int, int, bool]:
        thresholds = self.manifest.thresholds
        cooldown = int(thresholds.get("uplink_cooldown_seconds", 86400))
        min_count = int(thresholds.get("min_local_count", 1))
        novel_only = bool(thresholds.get("novel_only", False))
        return cooldown, min_count, novel_only

    def process_event(self, event: dict[str, Any]) -> Optional[Observation]:
        """Process one Cowrie event; return observation when session closes."""
        sid = event.get("session")
        if not sid:
            return None

        if event.get("eventid") == "cowrie.session.connect":
            self._sessions[sid] = Session(session_id=sid)
        session = self._sessions.get(sid)
        if session is None:
            session = Session(session_id=sid)
            self._sessions[sid] = session

        eid = event.get("eventid", "")
        if eid == "cowrie.session.connect":
            session.src_ip = event.get("src_ip", "")
            session.src_port = int(event.get("src_port") or 0)
            session.connected_at = event.get("timestamp", "")
            session.sensor = event.get("sensor", "")
        elif eid == "cowrie.command.input":
            cmd = (event.get("input") or "").strip()
            if cmd:
                session.commands.append(cmd)
        elif eid == "cowrie.session.closed":
            session.closed_at = event.get("timestamp", "")
            session.duration = float(event.get("duration") or 0)
            return self._finalize_session(session)
        return None

    def _finalize_session(self, session: Session) -> Optional[Observation]:
        if not session.commands:
            self._sessions.pop(session.session_id, None)
            return None

        analysis = analyze_session(session)
        analysis.pop("commands", None)
        analysis.pop("src_ip", None)
        analysis.pop("session_id", None)

        now = session.closed_at or session.connected_at
        rollup = self.store.record(
            equivalence_key=analysis["dedup_key"],
            technique_set=analysis.get("techniques") or [],
            confidence=float(analysis.get("confidence") or 0.0),
            first_seen=now,
            last_seen=now,
        )

        cooldown, min_count, novel_only = self._thresholds()
        first_time = rollup.seen_count == 1
        if novel_only and not first_time:
            self._sessions.pop(session.session_id, None)
            return None
        if not self.store.should_uplink(rollup.equivalence_key, cooldown, min_count):
            self._sessions.pop(session.session_id, None)
            return None

        epoch = self.store.bump_epoch()
        obs = Observation.from_session_analysis(
            analysis=analysis,
            node_id=self.manifest.node_id,
            epoch=epoch,
            sensor_class=self.manifest.sensor_class,
            seen_count=rollup.seen_count,
        )
        obs.first_seen = rollup.first_seen
        obs.last_seen = rollup.last_seen
        obs.technique_set = rollup.technique_set
        obs.confidence = rollup.confidence
        obs.sign(self._key)
        self.store.mark_uplinked(rollup.equivalence_key)
        self._sessions.pop(session.session_id, None)
        return obs

    def iter_new_observations(self, log_path: str | Path) -> Iterator[Observation]:
        """Read new bytes from log_path and yield observations."""
        path = Path(log_path)
        if not path.exists():
            raise FileNotFoundError(log_path)

        offset = self._load_offset()
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            while True:
                line = handle.readline()
                if not line:
                    break
                offset = handle.tell()
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                obs = self.process_event(event)
                if obs is not None:
                    yield obs
            self._save_offset(offset)

    def run_once(self, log_path: str | Path | None = None) -> list[Observation]:
        path = log_path or self.manifest.cowrie_log_path
        if not path:
            raise ValueError("cowrie_log_path is required")
        return list(self.iter_new_observations(path))

    def run_forever(
        self,
        log_path: str | Path | None = None,
        *,
        interval: float = 5.0,
        on_observation: Callable[[Observation], None] | None = None,
    ) -> None:
        path = log_path or self.manifest.cowrie_log_path
        if not path:
            raise ValueError("cowrie_log_path is required")
        while True:
            for obs in self.iter_new_observations(path):
                if on_observation:
                    on_observation(obs)
            time.sleep(interval)