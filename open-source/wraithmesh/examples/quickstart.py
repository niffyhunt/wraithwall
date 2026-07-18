#!/usr/bin/env python3
"""Minimal WraithMesh demo: sample Cowrie log -> observation -> aggregator corroboration."""

from __future__ import annotations

import json
import os
from pathlib import Path

from wraithmesh import (
    CowrieTailSensor,
    InMemoryAggregatorStore,
    MeshManifest,
    ingest_observation,
    load_manifest,
    write_manifest,
)
from wraithmesh.signing import load_key, node_id_from_key

ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "honeypot-mitre" / "examples" / "sample_cowrie.json"


def main() -> None:
    os.environ.setdefault("WRAITHMESH_KEY", "demo-signing-key-change-me")
    key = load_key("WRAITHMESH_KEY")
    node_id = node_id_from_key(key)

    manifest = MeshManifest(
        node_id=node_id,
        sensor_class="cowrie",
        signing_key_env="WRAITHMESH_KEY",
        thresholds={"uplink_cooldown_seconds": 0, "min_local_count": 1},
        egress_allowlist=frozenset({
            "schema_version", "observation_id", "equivalence_key", "technique_set",
            "sensor_class", "confidence", "seen_count_bucket", "first_seen",
            "last_seen", "node_id", "epoch", "signature",
        }),
        cowrie_log_path=str(SAMPLE),
        state_dir="/tmp/wraithmesh-demo",
    )
    cfg = Path("/tmp/wraithmesh-demo/mesh.json")
    write_manifest(cfg, manifest, key)

    sensor = CowrieTailSensor(load_manifest(cfg))
    observations = sensor.run_once(SAMPLE)
    print(f"observations: {len(observations)}")
    store = InMemoryAggregatorStore()
    for obs in observations:
        payload = obs.to_dict()
        print(json.dumps(payload, indent=2))
        record = ingest_observation(payload, key=key, store=store)
        print("corroboration:", json.dumps(record.to_dict(), indent=2))


if __name__ == "__main__":
    main()