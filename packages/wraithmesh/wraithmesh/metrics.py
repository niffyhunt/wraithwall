"""Local sensor metrics for operational visibility."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class SensorMetrics:
    node_id: str
    sensor_class: str
    sessions_processed: int = 0
    observations_uplinked: int = 0
    observations_suppressed: int = 0
    last_uplink_at: str = ""
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def record_processed(self) -> None:
        self.sessions_processed += 1

    def record_uplink(self) -> None:
        self.observations_uplinked += 1
        self.last_uplink_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    def record_suppressed(self) -> None:
        self.observations_suppressed += 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> SensorMetrics:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(**data)