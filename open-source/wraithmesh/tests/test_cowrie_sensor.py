import os
from pathlib import Path

from wraithmesh.manifest import MeshManifest, load_manifest, write_manifest
from wraithmesh.sensor import CowrieTailSensor
from wraithmesh.signing import node_id_from_key

SAMPLE = Path(__file__).resolve().parents[2] / "honeypot-mitre" / "examples" / "sample_cowrie.json"


def test_cowrie_tail_emits_observations(tmp_path):
    os.environ["WRAITHMESH_KEY"] = "sensor-test-key"
    key = os.environ["WRAITHMESH_KEY"]
    manifest = MeshManifest(
        node_id=node_id_from_key(key),
        sensor_class="cowrie",
        signing_key_env="WRAITHMESH_KEY",
        thresholds={"uplink_cooldown_seconds": 0, "min_local_count": 1},
        egress_allowlist=frozenset({
            "schema_version", "observation_id", "equivalence_key", "technique_set",
            "sensor_class", "confidence", "seen_count_bucket", "first_seen",
            "last_seen", "node_id", "epoch", "signature",
        }),
        cowrie_log_path=str(SAMPLE),
        state_dir=str(tmp_path / "state"),
    )
    cfg = tmp_path / "mesh.json"
    write_manifest(cfg, manifest, key)
    sensor = CowrieTailSensor(load_manifest(cfg))
    obs = sensor.run_once(SAMPLE)
    assert obs
    assert all(len(o.equivalence_key) == 16 for o in obs)