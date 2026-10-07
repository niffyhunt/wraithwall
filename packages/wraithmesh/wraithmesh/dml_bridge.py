"""Bridge signed DML v0.3.0 documents into WraithMesh manifests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .manifest import MeshManifest, write_manifest
from .signing import load_key, node_id_from_key


def load_dml_document(path: str | Path) -> dict[str, Any]:
    try:
        from dml import DMLSigner, load as dml_load
    except ImportError as exc:
        raise ImportError(
            "dml-spec required: pip install ../dml-spec or pip install wraithmesh[dml]"
        ) from exc
    return dml_load(path)


def verify_dml_document(doc: dict[str, Any], *, dml_key_env: str = "DML_KEY") -> None:
    from dml import DMLSigner

    signer = DMLSigner.from_env(dml_key_env)
    ok, errors = signer.verify_document(doc)
    if not ok:
        raise ValueError("DML signature invalid: " + "; ".join(errors))


def dml_sensor_to_manifest_body(doc: dict[str, Any], sensor_id: str, *, mesh_key: str | bytes) -> dict[str, Any]:
    try:
        from dml.mesh import export_mesh_manifest
    except ImportError as exc:
        raise ImportError(
            "dml-spec required: pip install ../dml-spec or pip install wraithmesh[dml]"
        ) from exc
    return export_mesh_manifest(doc, sensor_id, key=mesh_key)


def manifest_from_dml(
    dml_path: str | Path,
    sensor_id: str,
    *,
    dml_key_env: str = "DML_KEY",
    mesh_key_env: str = "WRAITHMESH_KEY",
    verify_dml: bool = True,
) -> MeshManifest:
    doc = load_dml_document(dml_path)
    if verify_dml:
        verify_dml_document(doc, dml_key_env=dml_key_env)
    mesh_key = load_key(mesh_key_env)
    body = dml_sensor_to_manifest_body(doc, sensor_id, mesh_key=mesh_key)
    manifest = MeshManifest.from_dict(body)
    if not manifest.node_id:
        manifest.node_id = node_id_from_key(mesh_key)
    return manifest


def write_manifest_from_dml(
    dml_path: str | Path,
    sensor_id: str,
    output: str | Path,
    *,
    dml_key_env: str = "DML_KEY",
    mesh_key_env: str = "WRAITHMESH_KEY",
    verify_dml: bool = True,
) -> MeshManifest:
    manifest = manifest_from_dml(
        dml_path,
        sensor_id,
        dml_key_env=dml_key_env,
        mesh_key_env=mesh_key_env,
        verify_dml=verify_dml,
    )
    mesh_key = load_key(mesh_key_env)
    write_manifest(output, manifest, mesh_key)
    return manifest