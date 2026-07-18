import json
import os
from pathlib import Path

from wraithmesh.manifest import MeshManifest, write_manifest
from wraithmesh.sensor import CanaryInboxSensor
from wraithmesh.signing import node_id_from_key


def test_canary_inbox_emits_high_confidence_observation(tmp_path):
    os.environ["WRAITHMESH_KEY"] = "canary-phase1-key"
    key = os.environ["WRAITHMESH_KEY"]
    inbox = tmp_path / "beacons.jsonl"
    inbox.write_text(
        json.dumps({"package_name": "internal-sdk", "version": "2.4.1", "timestamp": "2026-07-12T00:00:00Z"}) + "\n"
    )
    manifest = MeshManifest(
        node_id=node_id_from_key(key),
        sensor_class="canary",
        signing_key_env="WRAITHMESH_KEY",
        thresholds={"uplink_cooldown_seconds": 0, "min_local_count": 1},
        egress_allowlist=frozenset({
            "schema_version", "observation_id", "equivalence_key", "technique_set",
            "sensor_class", "confidence", "seen_count_bucket", "first_seen",
            "last_seen", "node_id", "epoch", "signature",
        }),
        beacon_inbox_path=str(inbox),
        state_dir=str(tmp_path / "state"),
    )
    cfg = tmp_path / "mesh.json"
    write_manifest(cfg, manifest, key)
    sensor = CanaryInboxSensor(manifest)
    obs = sensor.run_once(inbox)
    assert len(obs) == 1
    payload = obs[0].to_dict()
    assert payload["sensor_class"] == "canary"
    assert payload["confidence"] == 1.0
    assert "token" not in str(payload).lower()
    assert "ip" not in payload