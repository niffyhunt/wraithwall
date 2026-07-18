"""Sensor factory — route manifest sensor_class to the right adapter."""

from __future__ import annotations

from typing import Any, Protocol

from ..manifest import MeshManifest
from .canary import CanaryInboxSensor
from .cowrie import CowrieTailSensor


class Sensor(Protocol):
    def run_once(self, path: str | None = None) -> list[Any]: ...
    def run_forever(self, path: str | None = None, *, interval: float = 5.0, on_observation: Any = None) -> None: ...


def create_sensor(manifest: MeshManifest) -> Sensor:
    if manifest.sensor_class == "cowrie":
        return CowrieTailSensor(manifest)
    if manifest.sensor_class == "canary":
        return CanaryInboxSensor(manifest)
    raise ValueError(f"unsupported sensor_class: {manifest.sensor_class}")