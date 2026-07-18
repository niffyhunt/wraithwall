import os
from pathlib import Path

from wraithmesh.manifest import MeshManifest, load_manifest, write_manifest
from wraithmesh.signing import node_id_from_key


def test_manifest_round_trip(tmp_path):
    os.environ["WRAITHMESH_KEY"] = "manifest-key"
    key = os.environ["WRAITHMESH_KEY"]
    manifest = MeshManifest(
        node_id=node_id_from_key(key),
        sensor_class="cowrie",
        signing_key_env="WRAITHMESH_KEY",
        thresholds={"uplink_cooldown_seconds": 3600, "min_local_count": 1},
        egress_allowlist=frozenset({"equivalence_key", "signature"}),
        cowrie_log_path="/tmp/cowrie.json",
        state_dir=str(tmp_path),
    )
    path = tmp_path / "mesh.json"
    write_manifest(path, manifest, key)
    loaded = load_manifest(path)
    assert loaded.node_id == manifest.node_id
    assert loaded.verify(key)