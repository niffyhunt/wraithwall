"""Canary beacon inbox sensor — high-weight asymmetric observations."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from ..manifest import MeshManifest
from ..models import Observation
from ..signing import load_key
from ..store import LocalStore


CANARY_TECHNIQUES = ["T1195.002"]


def canary_equivalence_key(package_name: str, version: str) -> str:
    """Privacy-safe campaign key — package + version only, never the token."""
    payload = f"{package_name}:{version}:canary".encode()
    return hashlib.sha256(payload).hexdigest()[:16]


class CanaryInboxSensor:
    """Watch a JSONL beacon inbox and uplink canary-fired observations."""

    def __init__(self, manifest: MeshManifest, store: LocalStore | None = None) -> None:
        self.manifest = manifest
        self.store = store or LocalStore(manifest.state_dir)
        self._offset_path = Path(manifest.state_dir) / "canary.offset"
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

    def process_beacon(self, event: dict[str, Any]) -> Optional[Observation]:
        package = (event.get("package_name") or "").strip()
        version = (event.get("version") or "").strip()
        if not package or not version:
            return None

        eq = canary_equivalence_key(package, version)
        now = event.get("timestamp") or ""
        rollup = self.store.record(
            equivalence_key=eq,
            technique_set=CANARY_TECHNIQUES,
            confidence=1.0,
            first_seen=now,
            last_seen=now,
        )
        epoch = self.store.bump_epoch()
        obs = Observation(
            equivalence_key=eq,
            technique_set=CANARY_TECHNIQUES,
            sensor_class="canary",
            confidence=1.0,
            seen_count=rollup.seen_count,
            node_id=self.manifest.node_id,
            epoch=epoch,
            first_seen=rollup.first_seen,
            last_seen=rollup.last_seen,
        )
        obs.sign(self._key)
        self.store.mark_uplinked(eq)
        return obs

    def iter_new_observations(self, inbox_path: str | Path) -> Iterator[Observation]:
        path = Path(inbox_path)
        if not path.exists():
            path.touch()
        offset = self._load_offset()
        with path.open("r", encoding="utf-8") as handle:
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
                obs = self.process_beacon(event)
                if obs is not None:
                    yield obs
            self._save_offset(offset)

    def run_once(self, inbox_path: str | Path | None = None) -> list[Observation]:
        path = inbox_path or self.manifest.beacon_inbox_path
        if not path:
            raise ValueError("beacon_inbox_path is required for canary sensor")
        return list(self.iter_new_observations(path))

    def run_forever(
        self,
        inbox_path: str | Path | None = None,
        *,
        interval: float = 5.0,
        on_observation: Callable[[Observation], None] | None = None,
    ) -> None:
        path = inbox_path or self.manifest.beacon_inbox_path
        if not path:
            raise ValueError("beacon_inbox_path is required for canary sensor")
        while True:
            for obs in self.iter_new_observations(path):
                if on_observation:
                    on_observation(obs)
            time.sleep(interval)