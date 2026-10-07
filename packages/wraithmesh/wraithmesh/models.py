"""Observation and manifest data structures."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .egress import count_bucket, sanitize_observation
from .equivalence import equivalence_key
from .signing import sign_payload, verify_payload

SCHEMA_VERSION = "0.1"
MESH_VERSION = "0.1"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class Observation:
    equivalence_key: str
    technique_set: list[str]
    sensor_class: str
    confidence: float
    seen_count: int
    node_id: str
    epoch: int
    observation_id: str = field(default_factory=lambda: f"obs_{uuid.uuid4().hex[:12]}")
    schema_version: str = SCHEMA_VERSION
    seen_count_bucket: str = ""
    first_seen: str = ""
    last_seen: str = ""
    signature: str = ""

    def __post_init__(self) -> None:
        if not self.seen_count_bucket:
            self.seen_count_bucket = count_bucket(self.seen_count)
        if not self.first_seen:
            self.first_seen = _utc_now()
        if not self.last_seen:
            self.last_seen = self.first_seen

    def signing_body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "observation_id": self.observation_id,
            "equivalence_key": self.equivalence_key,
            "technique_set": sorted(self.technique_set),
            "sensor_class": self.sensor_class,
            "confidence": round(self.confidence, 4),
            "seen_count_bucket": self.seen_count_bucket,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "node_id": self.node_id,
            "epoch": self.epoch,
        }

    def sign(self, key: str | bytes) -> None:
        self.signature = sign_payload(self.signing_body(), key)

    def to_dict(self, *, allowlist: set[str] | frozenset[str] | None = None) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("seen_count", None)
        payload = sanitize_observation(payload, allowlist)
        return payload

    @classmethod
    def from_session_analysis(
        cls,
        *,
        analysis: dict[str, Any],
        node_id: str,
        epoch: int,
        sensor_class: str = "cowrie",
        seen_count: int = 1,
    ) -> Observation:
        techniques = sorted(set(analysis.get("techniques") or []))
        confidence = float(analysis.get("confidence") or 0.0)
        if confidence > 1:
            confidence = min(confidence / 100.0, 1.0)
        return cls(
            equivalence_key=analysis.get("dedup_key") or equivalence_key(analysis.get("commands") or []),
            technique_set=techniques,
            sensor_class=sensor_class,
            confidence=confidence,
            seen_count=seen_count,
            node_id=node_id,
            epoch=epoch,
        )


def verify_observation(obs: dict[str, Any], key: str | bytes) -> bool:
    signature = obs.get("signature", "")
    body = {k: v for k, v in obs.items() if k != "signature"}
    if "technique_set" in body:
        body["technique_set"] = sorted(body["technique_set"])
    if "confidence" in body:
        body["confidence"] = round(float(body["confidence"]), 4)
    return verify_payload(body, signature, key)