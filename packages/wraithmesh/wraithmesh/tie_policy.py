"""TIE publication policy — corroboration gates before high-confidence export."""

from __future__ import annotations

from typing import Any

from .aggregator.store import CorroborationRecord


def apply_corroboration_gate(
    record: CorroborationRecord,
    *,
    min_nodes: int = 2,
) -> dict[str, Any]:
    """Return public record; mask confidence until min_nodes corroborate."""
    payload = record.to_dict()
    nodes = record.distinct_nodes
    corr = payload["corroboration"]
    if nodes < min_nodes:
        corr["status"] = "pending_corroboration"
        corr["confidence"] = round(min(corr["confidence"], 0.25), 4)
        corr["reputation_score"] = round(min(corr.get("reputation_score", 0.0), 0.25), 4)
        corr["publishable"] = False
    else:
        corr["status"] = "corroborated"
        corr["publishable"] = True
    corr["min_nodes_required"] = min_nodes
    return payload