"""Tests for DML v0.3.0 WraithMesh extensions."""

from __future__ import annotations

import os
from pathlib import Path

from dml import DMLSigner, DMLValidator, export_mesh_manifest, load

MESH_EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "example_mesh.yaml"
KEY = "dml-mesh-test-key"


def test_mesh_example_validates():
    doc = load(MESH_EXAMPLE)
    assert DMLValidator().validate_document(doc) == []


def test_mesh_sign_verify_round_trip():
    doc = load(MESH_EXAMPLE)
    signed = DMLSigner(KEY).sign_document(doc)
    assert all("signature" in s for s in signed["sensors"])
    ok, errors = DMLSigner(KEY).verify_document(signed)
    assert ok, errors


def test_export_mesh_manifest():
    doc = load(MESH_EXAMPLE)
    signed = DMLSigner(KEY).sign_document(doc)
    os.environ["WRAITHMESH_KEY"] = "mesh-node-secret"
    manifest = export_mesh_manifest(signed, "cowrie-east-1", key="mesh-node-secret")
    assert manifest["sensor_class"] == "cowrie"
    assert manifest["cowrie_log_path"]
    assert "src_ip" not in manifest["egress_allowlist"]
    assert manifest["dml_sensor_id"] == "cowrie-east-1"


def test_rejects_forbidden_egress_field():
    doc = load(MESH_EXAMPLE)
    doc["sensors"][0]["egress_allowlist"] = ["equivalence_key", "src_ip"]
    errors = DMLValidator().validate_document(doc)
    assert any("egress_allowlist" in e for e in errors)