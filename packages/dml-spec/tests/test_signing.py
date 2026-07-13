"""Tests for the DML signer: round-trip, tamper detection, key handling."""

from __future__ import annotations

from pathlib import Path

import pytest

from dml import DMLSigner, load

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "example_traps.yaml"

KEY = "unit-test-key-abc123"


def _signed_sample() -> dict:
    doc = load(EXAMPLE)
    return DMLSigner(KEY).sign_document(doc)


def test_sign_verify_round_trip() -> None:
    signer = DMLSigner(KEY)
    signed = signer.sign_document(load(EXAMPLE))
    assert "document_signature" in signed
    assert all("signature" in t for t in signed["traps"])
    ok, errors = signer.verify_document(signed)
    assert ok is True
    assert errors == []


def test_sign_does_not_mutate_input() -> None:
    doc = load(EXAMPLE)
    DMLSigner(KEY).sign_document(doc)
    assert "document_signature" not in doc
    assert all("signature" not in t for t in doc["traps"])


def test_tampering_single_trap_fails_whole_doc() -> None:
    signed = _signed_sample()
    # Alter a field in one trap WITHOUT updating its signature.
    signed["traps"][1]["severity"] = "low"
    ok, errors = DMLSigner(KEY).verify_document(signed)
    assert ok is False
    # The whole-document signature must catch it.
    assert any("Document signature mismatch" in e for e in errors)


def test_tampering_with_resigned_trap_still_fails_doc() -> None:
    signer = DMLSigner(KEY)
    signed = _signed_sample()
    # Attacker edits a trap and forges a valid per-trap signature for it.
    signed["traps"][0]["severity"] = "low"
    trap_copy = {k: v for k, v in signed["traps"][0].items() if k != "signature"}
    signed["traps"][0]["signature"] = signer._sign_dict(trap_copy)
    ok, errors = signer.verify_document(signed)
    # Whole-document signature still binds the set of traps together.
    assert ok is False
    assert any("Document signature mismatch" in e for e in errors)


def test_wrong_key_fails_verification() -> None:
    signed = _signed_sample()
    ok, errors = DMLSigner("a-different-key").verify_document(signed)
    assert ok is False
    assert errors


def test_missing_document_signature() -> None:
    doc = load(EXAMPLE)
    ok, errors = DMLSigner(KEY).verify_document(doc)
    assert ok is False
    assert any("Missing document_signature" in e for e in errors)


def test_empty_key_rejected() -> None:
    with pytest.raises(ValueError):
        DMLSigner("")


def test_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DML_KEY", KEY)
    signer = DMLSigner.from_env("DML_KEY")
    signed = signer.sign_document(load(EXAMPLE))
    ok, _ = signer.verify_document(signed)
    assert ok is True


def test_from_env_missing_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DML_KEY", raising=False)
    with pytest.raises(ValueError):
        DMLSigner.from_env("DML_KEY")


def test_signature_is_deterministic() -> None:
    s1 = DMLSigner(KEY).sign_document(load(EXAMPLE))
    s2 = DMLSigner(KEY).sign_document(load(EXAMPLE))
    assert s1["document_signature"] == s2["document_signature"]
