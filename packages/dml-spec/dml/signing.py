"""HMAC-SHA256 signing for DML document tamper detection.

The signer applies signatures at two levels:

* **Per-trap** — each trap gets a ``signature`` field that is an HMAC over
  the trap's contents (excluding the signature field itself). This lets a
  consumer detect tampering with any individual trap.
* **Whole-document** — a ``document_signature`` field is an HMAC over the
  document's identity fields (``dml_version``, ``platform``, ``namespace``)
  plus every trap with its signature stripped. This binds the set of traps
  together, so adding, removing or altering any trap invalidates the
  document signature even if a per-trap signature were forged.

Canonicalization (byte-for-byte faithful to the WraithWall original):

    canonical = json.dumps(d, sort_keys=True, separators=(",", ":"))
    sig       = hmac.new(key, canonical.encode(), sha256).hexdigest()[:32]

The HMAC key is supplied by the **caller** — never hardcoded. Pass it to the
constructor or set the environment variable named by ``key_env`` (default
``DML_KEY``) and use :meth:`DMLSigner.from_env`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os

# Default environment variable consulted by ``DMLSigner.from_env``.
DEFAULT_KEY_ENV = "DML_KEY"


class DMLSigner:
    """HMAC-SHA256 signer/verifier for DML documents.

    The signing key must be provided by the caller. There is no default or
    fallback key: this is a security boundary, so a missing key raises rather
    than silently signing with a guessable value.
    """

    def __init__(self, key: str | bytes) -> None:
        """Create a signer bound to an HMAC key.

        Args:
            key: The shared secret used for HMAC-SHA256. May be ``str`` or
                ``bytes``. Must be non-empty.

        Raises:
            ValueError: If ``key`` is empty.
        """
        if not key:
            raise ValueError("DMLSigner requires a non-empty signing key")
        self._key: bytes = key.encode() if isinstance(key, str) else key

    @classmethod
    def from_env(cls, key_env: str = DEFAULT_KEY_ENV) -> "DMLSigner":
        """Construct a signer from an environment variable.

        Args:
            key_env: Name of the environment variable holding the key.

        Returns:
            A configured :class:`DMLSigner`.

        Raises:
            ValueError: If the environment variable is unset or empty.
        """
        key = os.environ.get(key_env, "")
        if not key:
            raise ValueError(
                f"Signing key not found: set the {key_env} environment variable"
            )
        return cls(key)

    def sign_document(self, doc: dict) -> dict:
        """Return a copy of ``doc`` with per-trap and whole-document signatures.

        Each trap gains a ``signature``; the document gains a
        ``document_signature``. The input dict is not mutated.

        Args:
            doc: The DML document as a plain dict.

        Returns:
            A new dict with signatures populated.
        """
        signed = dict(doc)
        signed["traps"] = [dict(t) for t in doc.get("traps", [])]
        for trap in signed["traps"]:
            trap_copy = {k: v for k, v in trap.items() if k != "signature"}
            trap["signature"] = self._sign_dict(trap_copy)

        doc_copy = {
            "dml_version": signed.get("dml_version"),
            "platform": signed.get("platform"),
            "namespace": signed.get("namespace"),
            "traps": [
                {k: v for k, v in t.items() if k != "signature"}
                for t in signed.get("traps", [])
            ],
        }
        signed["document_signature"] = self._sign_dict(doc_copy)
        return signed

    def verify_document(self, doc: dict) -> tuple[bool, list[str]]:
        """Verify a signed DML document.

        Checks the whole-document signature first, then every per-trap
        signature. Comparison uses a constant-time digest compare.

        Args:
            doc: A signed DML document as a plain dict.

        Returns:
            A ``(ok, errors)`` tuple. ``ok`` is ``True`` only if the document
            signature and all trap signatures verify; ``errors`` lists every
            problem found.
        """
        errors: list[str] = []
        if "document_signature" not in doc:
            errors.append("Missing document_signature")
            return False, errors

        doc_copy = {
            "dml_version": doc.get("dml_version"),
            "platform": doc.get("platform"),
            "namespace": doc.get("namespace"),
            "traps": [
                {k: v for k, v in t.items() if k != "signature"}
                for t in doc.get("traps", [])
            ],
        }
        if not hmac.compare_digest(
            str(doc["document_signature"]), self._sign_dict(doc_copy)
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

        return len(errors) == 0, errors

    def _sign_dict(self, d: dict) -> str:
        """Compute the canonical HMAC-SHA256 signature of a dict.

        Canonicalization is JSON with sorted keys and no whitespace; the
        signature is the first 32 hex chars of the HMAC digest.
        """
        canonical = json.dumps(d, sort_keys=True, separators=(",", ":"))
        return hmac.new(
            self._key, canonical.encode(), hashlib.sha256
        ).hexdigest()[:32]
