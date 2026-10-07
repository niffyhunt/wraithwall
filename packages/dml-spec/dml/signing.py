"""HMAC-SHA256 signing for DML document tamper detection.

The signer applies signatures at three levels (v0.3.0):

* **Per-trap** — each trap gets a ``signature`` field.
* **Per-sensor** — each WraithMesh sensor gets a ``signature`` field (v0.3.0+).
* **Whole-document** — ``document_signature`` binds traps, sensors, and mesh_policy.

Canonicalization:

    canonical = json.dumps(d, sort_keys=True, separators=(",", ":"))
    sig       = hmac.new(key, canonical.encode(), sha256).hexdigest()[:32]
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os

DEFAULT_KEY_ENV = "DML_KEY"


class DMLSigner:
    """HMAC-SHA256 signer/verifier for DML documents."""

    def __init__(self, key: str | bytes) -> None:
        if not key:
            raise ValueError("DMLSigner requires a non-empty signing key")
        self._key: bytes = key.encode() if isinstance(key, str) else key

    @classmethod
    def from_env(cls, key_env: str = DEFAULT_KEY_ENV) -> "DMLSigner":
        key = os.environ.get(key_env, "")
        if not key:
            raise ValueError(
                f"Signing key not found: set the {key_env} environment variable"
            )
        return cls(key)

    def sign_document(self, doc: dict) -> dict:
        signed = dict(doc)
        signed["traps"] = [dict(t) for t in doc.get("traps", [])]
        for trap in signed["traps"]:
            trap_copy = {k: v for k, v in trap.items() if k != "signature"}
            trap["signature"] = self._sign_dict(trap_copy)

        signed["sensors"] = [dict(s) for s in doc.get("sensors", [])]
        for sensor in signed["sensors"]:
            sensor_copy = {k: v for k, v in sensor.items() if k != "signature"}
            sensor["signature"] = self._sign_dict(sensor_copy)

        signed["document_signature"] = self._sign_dict(self._document_body(signed))
        return signed

    def verify_document(self, doc: dict) -> tuple[bool, list[str]]:
        errors: list[str] = []
        if "document_signature" not in doc:
            errors.append("Missing document_signature")
            return False, errors

        if not hmac.compare_digest(
            str(doc["document_signature"]), self._sign_dict(self._document_body(doc))
        ):
            errors.append("Document signature mismatch — document may be tampered")
            return False, errors

        for i, trap in enumerate(doc.get("traps", [])):
            if "signature" not in trap:
                errors.append(f"traps[{i}]: Missing signature")
                continue
            trap_copy = {k: v for k, v in trap.items() if k != "signature"}
            if not hmac.compare_digest(
                str(trap["signature"]), self._sign_dict(trap_copy)
            ):
                errors.append(
                    f"traps[{i}]: Signature mismatch for '{trap.get('id', 'unknown')}'"
                )

        for i, sensor in enumerate(doc.get("sensors", [])):
            if "signature" not in sensor:
                errors.append(f"sensors[{i}]: Missing signature")
                continue
            sensor_copy = {k: v for k, v in sensor.items() if k != "signature"}
            if not hmac.compare_digest(
                str(sensor["signature"]), self._sign_dict(sensor_copy)
            ):
                errors.append(
                    f"sensors[{i}]: Signature mismatch for '{sensor.get('id', 'unknown')}'"
                )

        return len(errors) == 0, errors

    def _document_body(self, doc: dict) -> dict:
        body = {
            "dml_version": doc.get("dml_version"),
            "platform": doc.get("platform"),
            "namespace": doc.get("namespace"),
            "traps": [
                {k: v for k, v in t.items() if k != "signature"}
                for t in doc.get("traps", [])
            ],
        }
        sensors = doc.get("sensors") or []
        if sensors:
            body["sensors"] = [
                {k: v for k, v in s.items() if k != "signature"}
                for s in sensors
            ]
        if doc.get("mesh_policy") is not None:
            body["mesh_policy"] = doc.get("mesh_policy")
        return body

    def _sign_dict(self, d: dict) -> str:
        canonical = json.dumps(d, sort_keys=True, separators=(",", ":"))
        return hmac.new(
            self._key, canonical.encode(), hashlib.sha256
        ).hexdigest()[:32]