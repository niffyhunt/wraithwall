import os
from pathlib import Path

import pytest

DML_EXAMPLE = Path(__file__).resolve().parents[2] / "dml-spec" / "examples" / "example_mesh.yaml"


def test_manifest_from_dml_round_trip(tmp_path):
    dml = pytest.importorskip("dml")
    from wraithmesh.dml_bridge import write_manifest_from_dml

    os.environ["DML_KEY"] = "bridge-dml-key"
    os.environ["WRAITHMESH_KEY"] = "bridge-mesh-key"
    signed = dml.DMLSigner(os.environ["DML_KEY"]).sign_document(dml.load(DML_EXAMPLE))
    signed_path = tmp_path / "signed.yaml"
    dml.dump(signed, signed_path)
    out = tmp_path / "mesh.json"
    manifest = write_manifest_from_dml(signed_path, "cowrie-east-1", out)
    assert manifest.sensor_class == "cowrie"
    assert out.exists()
    assert manifest.node_id