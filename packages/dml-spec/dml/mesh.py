"""Export WraithMesh manifests from signed DML sensor declarations."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .spec import DEFAULT_EGRESS_ALLOWLIST


def node_id_from_key(key: str | bytes) -> str:
    raw = key.encode() if isinstance(key, str) else key
    return hashlib.sha256(raw).hexdigest()[:16]


def export_mesh_manifest(
    doc: dict,
    sensor_id: str,
    *,
    key: str | bytes,
    mesh_version: str = "0.2",
) -> dict[str, Any]:
    """Build a WraithMesh-compatible manifest dict from a DML document sensor.

    The returned dict is unsigned — callers sign with their mesh tooling or
    reuse the DML signing key via HMAC in WraithMesh.
    """
    sensor = _find_sensor(doc, sensor_id)
    node_id = sensor.get("node_id") or node_id_from_key(key)
    thresholds = sensor.get("thresholds") or {}
    egress = sensor.get("egress_allowlist") or list(DEFAULT_EGRESS_ALLOWLIST)
    body = {
        "mesh_version": mesh_version,
        "node_id": node_id,
        "sensor_class": sensor["sensor_class"],
        "aggregator_url": sensor.get("aggregator_url", ""),
        "signing_key_env": sensor.get("signing_key_env", "WRAITHMESH_KEY"),
        "thresholds": {
            "uplink_cooldown_seconds": int(thresholds.get("uplink_cooldown_seconds", 86400)),
            "min_local_count": int(thresholds.get("min_local_count", 1)),
            "novel_only": bool(thresholds.get("novel_only", False)),
        },
        "egress_allowlist": sorted(egress),
        "cowrie_log_path": sensor.get("cowrie_log_path", ""),
        "beacon_inbox_path": sensor.get("beacon_inbox_path", ""),
        "state_dir": sensor.get("state_dir", ".wraithmesh"),
        "dml_sensor_id": sensor_id,
        "dml_namespace": doc.get("namespace", ""),
    }
    return body


def _find_sensor(doc: dict, sensor_id: str) -> dict[str, Any]:
    for sensor in doc.get("sensors", []):
        if sensor.get("id") == sensor_id:
            return sensor
    raise KeyError(f"sensor not found: {sensor_id}")


def export_mesh_manifest_json(doc: dict, sensor_id: str, *, key: str | bytes) -> str:
    return json.dumps(export_mesh_manifest(doc, sensor_id, key=key), indent=2) + "\n"