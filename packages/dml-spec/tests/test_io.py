"""Tests for DML load/dump and document building."""

from __future__ import annotations

from pathlib import Path

import pytest

from dml import (
    DML_VERSION,
    DMLTrap,
    DMLTrigger,
    DMLValidator,
    build_document,
    dumps,
    load,
    loads,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "example_traps.yaml"


def test_load_yaml() -> None:
    doc = load(EXAMPLE)
    assert doc["dml_version"] == DML_VERSION
    assert len(doc["traps"]) == 5


def test_yaml_json_round_trip() -> None:
    doc = load(EXAMPLE)
    as_json = dumps(doc, fmt="json")
    reparsed = loads(as_json)
    assert reparsed == doc


def test_dumps_yaml_reparses() -> None:
    doc = load(EXAMPLE)
    text = dumps(doc, fmt="yaml")
    assert loads(text) == doc


def test_dumps_bad_format() -> None:
    with pytest.raises(ValueError):
        dumps({"traps": []}, fmt="toml")


def test_build_document_from_dataclass_traps() -> None:
    trap = DMLTrap(
        id="built-trap",
        name="Built from a dataclass",
        trigger=DMLTrigger(type="http_request", path="/secret"),
    )
    doc = build_document([trap], platform="lib", namespace="test")
    assert doc["dml_version"] == DML_VERSION
    assert doc["platform"] == "lib"
    assert doc["traps"][0]["id"] == "built-trap"
    # And it should validate.
    assert DMLValidator().validate_document(doc) == []


def test_build_document_from_dicts() -> None:
    trap = {
        "id": "dict-trap",
        "name": "From a dict",
        "trigger": {"type": "log_only_placeholder"},
    }
    doc = build_document([trap])
    assert doc["traps"][0] == trap
