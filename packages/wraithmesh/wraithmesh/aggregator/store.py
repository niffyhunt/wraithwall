"""In-memory corroboration store for regional aggregators."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..reputation import ReputationStore


@dataclass
class CorroborationRecord:
    equivalence_key: str
    technique_set: list[str]
    distinct_nodes: int
    sensor_classes: set[str]
    confidence: float
    first_global_seen: str
    last_global_seen: str
    node_ids: set[str] = field(default_factory=set)
    reputation_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "equivalence_key": self.equivalence_key,
            "technique_set": sorted(self.technique_set),
            "corroboration": {
                "distinct_nodes": self.distinct_nodes,
                "sensor_classes": sorted(self.sensor_classes),
                "first_global_seen": self.first_global_seen,
                "last_global_seen": self.last_global_seen,
                "confidence": round(self.confidence, 4),
                "reputation_score": round(self.reputation_score, 4),
            },
        }


class InMemoryAggregatorStore:
    def __init__(self) -> None:
        self._records: dict[str, CorroborationRecord] = {}
        self.reputation = ReputationStore()

    def get(self, equivalence_key: str) -> CorroborationRecord | None:
        return self._records.get(equivalence_key)

    def upsert(self, record: CorroborationRecord) -> CorroborationRecord:
        self._records[record.equivalence_key] = record
        return record

    def all_records(self) -> list[CorroborationRecord]:
        return list(self._records.values())

    def stats(self) -> dict[str, Any]:
        campaigns = len(self._records)
        node_hits = sum(r.distinct_nodes for r in self._records.values())
        return {
            "campaigns": campaigns,
            "node_hits": node_hits,
            "contributors": len(self.reputation.nodes),
        }