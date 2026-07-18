"""Contributor reputation for Threat Intelligence Exchange."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SENSOR_WEIGHTS = {
    "canary": 2.0,
    "cowrie": 1.0,
    "gateway": 1.2,
    "fingerprint": 1.0,
}

INITIAL_REPUTATION = 0.1
MAX_REPUTATION = 1.0
CORROBORATION_BONUS = 0.08
POISON_PENALTY = 0.5


@dataclass
class NodeReputation:
    node_id: str
    submissions: int = 0
    corroborated: int = 0
    rejected: int = 0
    score: float = INITIAL_REPUTATION

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "submissions": self.submissions,
            "corroborated": self.corroborated,
            "rejected": self.rejected,
            "reputation_score": round(self.score, 4),
        }


@dataclass
class ReputationStore:
    """In-memory reputation ledger."""

    nodes: dict[str, NodeReputation] = field(default_factory=dict)

    def get(self, node_id: str) -> NodeReputation:
        if node_id not in self.nodes:
            self.nodes[node_id] = NodeReputation(node_id=node_id)
        return self.nodes[node_id]

    def record_submission(self, node_id: str, *, sensor_class: str) -> float:
        node = self.get(node_id)
        node.submissions += 1
        weight = SENSOR_WEIGHTS.get(sensor_class, 1.0)
        return min(node.score * weight, MAX_REPUTATION)

    def record_corroboration(self, node_id: str) -> None:
        node = self.get(node_id)
        node.corroborated += 1
        node.score = min(MAX_REPUTATION, node.score + CORROBORATION_BONUS)

    def record_rejection(self, node_id: str) -> None:
        node = self.get(node_id)
        node.rejected += 1
        node.score = max(0.0, node.score - POISON_PENALTY)

    def weighted_confidence(self, base_confidence: float, node_ids: set[str]) -> float:
        if not node_ids:
            return base_confidence
        scores = [self.get(n).score for n in node_ids]
        avg_rep = sum(scores) / len(scores)
        return min(1.0, base_confidence * (0.5 + 0.5 * avg_rep))