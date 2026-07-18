"""Aggregator ingest — verify signatures, merge corroboration, update reputation."""

from __future__ import annotations

from typing import Any, Protocol

from ..egress import sanitize_observation
from ..models import verify_observation
from ..poisoning import is_trap_key
from ..reputation import ReputationStore
from ..trust import resolve_verification_key
from .store import CorroborationRecord

VerificationKey = str | bytes | dict[str, str]


class AggregatorStore(Protocol):
    reputation: ReputationStore

    def get(self, equivalence_key: str) -> CorroborationRecord | None: ...
    def upsert(self, record: CorroborationRecord) -> CorroborationRecord: ...


def ingest_observation(
    obs: dict[str, Any],
    *,
    key: VerificationKey,
    store: AggregatorStore,
    trap_keys: set[str] | None = None,
) -> CorroborationRecord:
    clean = sanitize_observation(obs)
    verify_key = resolve_verification_key(clean, key)
    if not verify_observation(clean, verify_key):
        node_id = clean.get("node_id", "")
        if node_id:
            store.reputation.record_rejection(node_id)
        raise ValueError("invalid observation signature")

    eq = clean["equivalence_key"]
    node_id = clean["node_id"]
    sensor_class = clean["sensor_class"]
    if trap_keys and is_trap_key(eq, trap_keys):
        store.reputation.record_rejection(node_id)
        raise ValueError(f"poisoning trap key reported: {eq}")
    store.reputation.record_submission(node_id, sensor_class=sensor_class)

    existing = store.get(eq)
    techniques = sorted(set(clean.get("technique_set") or []))
    confidence = float(clean.get("confidence") or 0.0)
    first_seen = clean["first_seen"]
    last_seen = clean["last_seen"]

    if existing is None:
        nodes = {node_id}
        classes = {sensor_class}
        record = CorroborationRecord(
            equivalence_key=eq,
            technique_set=techniques,
            distinct_nodes=1,
            sensor_classes=classes,
            confidence=confidence,
            first_global_seen=first_seen,
            last_global_seen=last_seen,
            node_ids=nodes,
        )
    else:
        nodes = set(existing.node_ids)
        was_new_node = node_id not in nodes
        nodes.add(node_id)
        classes = set(existing.sensor_classes)
        classes.add(sensor_class)
        merged_techniques = sorted(set(existing.technique_set) | set(techniques))
        base_conf = max(existing.confidence, confidence)
        record = CorroborationRecord(
            equivalence_key=eq,
            technique_set=merged_techniques,
            distinct_nodes=len(nodes),
            sensor_classes=classes,
            confidence=base_conf,
            first_global_seen=min(existing.first_global_seen, first_seen),
            last_global_seen=max(existing.last_global_seen, last_seen),
            node_ids=nodes,
        )
        if was_new_node and record.distinct_nodes > 1:
            for nid in nodes:
                store.reputation.record_corroboration(nid)

    record.reputation_score = store.reputation.weighted_confidence(record.confidence, record.node_ids)
    record.confidence = record.reputation_score
    return store.upsert(record)


def ingest_batch(
    batch: list[dict[str, Any]],
    *,
    key: VerificationKey,
    store: AggregatorStore,
    trap_keys: set[str] | None = None,
) -> list[CorroborationRecord]:
    out: list[CorroborationRecord] = []
    for obs in batch:
        out.append(ingest_observation(obs, key=key, store=store, trap_keys=trap_keys))
    return out