"""Tests for the DML validator."""

from __future__ import annotations

from pathlib import Path

from dml import DMLValidator, load

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "example_traps.yaml"


def test_validator_accepts_sample() -> None:
    doc = load(EXAMPLE)
    validator = DMLValidator()
    assert validator.validate_document(doc) == []
    assert validator.is_valid(doc) is True


def test_validator_rejects_empty_document() -> None:
    doc = {"dml_version": "0.3.0", "traps": [], "sensors": []}
    errors = DMLValidator().validate_document(doc)
    assert any("trap or sensor" in e for e in errors)


def test_validator_rejects_wrong_version() -> None:
    doc = {"dml_version": "9.9.9", "traps": [_minimal_trap()]}
    errors = DMLValidator().validate_document(doc)
    assert any("dml_version" in e for e in errors)


def test_validator_rejects_unknown_trigger_type() -> None:
    trap = _minimal_trap()
    trap["trigger"] = {"type": "telepathy"}
    errors = DMLValidator().validate_trap(trap)
    assert any("trigger.type must be one of" in e for e in errors)


def test_validator_rejects_unknown_response_type() -> None:
    trap = _minimal_trap()
    trap["response"] = {"type": "summon_dragon"}
    errors = DMLValidator().validate_trap(trap)
    assert any("response.type must be one of" in e for e in errors)


def test_validator_requires_http_path() -> None:
    trap = _minimal_trap()
    trap["trigger"] = {"type": "http_request"}
    errors = DMLValidator().validate_trap(trap)
    assert any("trigger.path required" in e for e in errors)


def test_validator_requires_delay_ms() -> None:
    trap = _minimal_trap()
    trap["response"] = {"type": "delay_response"}
    errors = DMLValidator().validate_trap(trap)
    assert any("delay_ms required" in e for e in errors)


def test_validator_rejects_bad_id() -> None:
    trap = _minimal_trap()
    trap["id"] = "Bad_ID!"
    errors = DMLValidator().validate_trap(trap)
    assert any("id must be lowercase" in e for e in errors)


def test_validator_rejects_duplicate_fqid() -> None:
    t1 = _minimal_trap()
    t2 = _minimal_trap()
    doc = {"dml_version": "0.2.0", "traps": [t1, t2]}
    errors = DMLValidator().validate_document(doc)
    assert any("duplicate fully-qualified ID" in e for e in errors)


def _minimal_trap() -> dict:
    return {
        "id": "test-trap",
        "name": "Test trap",
        "namespace": "default",
        "trigger": {"type": "http_request", "path": "/x"},
        "response": {"type": "log_only"},
    }
