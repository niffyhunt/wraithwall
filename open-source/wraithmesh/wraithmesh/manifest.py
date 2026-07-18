"""Signed sensor manifest loading and verification."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .egress import DEFAULT_ALLOWLIST
from .signing import load_key, sign_payload, verify_payload

MESH_VERSION = "0.2"


@dataclass
class MeshManifest:
    node_id: str
    sensor_class: str
    signing_key_env: str
    thresholds: dict[str, Any]
    egress_allowlist: frozenset[str]
    aggregator_url: str = ""
    cowrie_log_path: str = ""
    beacon_inbox_path: str = ""
    state_dir: str = ".wraithmesh"
    mesh_version: str = MESH_VERSION
    manifest_signature: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MeshManifest:
        return cls(
            mesh_version=data.get("mesh_version", MESH_VERSION),
            node_id=data["node_id"],
            sensor_class=data["sensor_class"],
            aggregator_url=data.get("aggregator_url", ""),
            signing_key_env=data.get("signing_key_env", "WRAITHMESH_KEY"),
            thresholds=dict(data.get("thresholds") or {}),
            egress_allowlist=frozenset(data.get("egress_allowlist") or DEFAULT_ALLOWLIST),
            cowrie_log_path=data.get("cowrie_log_path", ""),
            beacon_inbox_path=data.get("beacon_inbox_path", ""),
            state_dir=data.get("state_dir", ".wraithmesh"),
            manifest_signature=data.get("manifest_signature", ""),
        )

    def signing_body(self) -> dict[str, Any]:
        return {
            "mesh_version": self.mesh_version,
            "node_id": self.node_id,
            "sensor_class": self.sensor_class,
            "aggregator_url": self.aggregator_url,
            "signing_key_env": self.signing_key_env,
            "thresholds": self.thresholds,
            "egress_allowlist": sorted(self.egress_allowlist),
            "cowrie_log_path": self.cowrie_log_path,
            "beacon_inbox_path": self.beacon_inbox_path,
            "state_dir": self.state_dir,
        }

    def sign(self, key: str | bytes) -> dict[str, Any]:
        self.manifest_signature = sign_payload(self.signing_body(), key)
        out = self.signing_body()
        out["manifest_signature"] = self.manifest_signature
        return out

    def verify(self, key: str | bytes) -> bool:
        if not self.manifest_signature:
            return False
        return verify_payload(self.signing_body(), self.manifest_signature, key)


def load_manifest(path: str | Path, *, verify: bool = True) -> MeshManifest:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    manifest = MeshManifest.from_dict(data)
    if verify:
        key = load_key(manifest.signing_key_env)
        if not manifest.verify(key):
            raise ValueError("manifest signature mismatch")
    return manifest


def write_manifest(path: str | Path, manifest: MeshManifest, key: str | bytes) -> None:
    payload = manifest.sign(key)
    Path(path).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")