"""Shared JSONL inbox tailer for canary and gateway sensors."""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from ..manifest import MeshManifest
from ..models import Observation
from ..signing import load_key
from ..store import LocalStore


class JsonlInboxSensor(ABC):
    offset_name: str = "inbox.offset"

    def __init__(self, manifest: MeshManifest, store: LocalStore | None = None) -> None:
        self.manifest = manifest
        self.store = store or LocalStore(manifest.state_dir)
        self._offset_path = Path(manifest.state_dir) / self.offset_name
        self._key = load_key(manifest.signing_key_env)

    def rewind(self) -> None:
        """Reset read offset — useful for demos and replays."""
        if self._offset_path.exists():
            self._offset_path.unlink()

    def _load_offset(self) -> int:
        if not self._offset_path.exists():
            return 0
        try:
            return int(self._offset_path.read_text(encoding="utf-8").strip())
        except ValueError:
            return 0

    def _save_offset(self, offset: int) -> None:
        self._offset_path.write_text(str(offset), encoding="utf-8")

    @abstractmethod
    def process_event(self, event: dict[str, Any]) -> Optional[Observation]:
        ...

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
                obs = self.process_event(event)
                if obs is not None:
                    yield obs
            self._save_offset(offset)

    def run_once(self, inbox_path: str | Path | None = None) -> list[Observation]:
        path = inbox_path or self._default_inbox_path()
        if not path:
            raise ValueError("inbox path is required")
        return list(self.iter_new_observations(path))

    def run_forever(
        self,
        inbox_path: str | Path | None = None,
        *,
        interval: float = 5.0,
        on_observation: Callable[[Observation], None] | None = None,
    ) -> None:
        path = inbox_path or self._default_inbox_path()
        if not path:
            raise ValueError("inbox path is required")
        while True:
            for obs in self.iter_new_observations(path):
                if on_observation:
                    on_observation(obs)
            time.sleep(interval)

    @abstractmethod
    def _default_inbox_path(self) -> str:
        ...