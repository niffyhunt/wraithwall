"""Quickstart: validate -> sign -> verify a DML document round-trip.

Run with the signing key supplied via the environment:

    DML_KEY=test-key-123 python examples/quickstart.py

The signing key is read from the DML_KEY environment variable; it is never
hardcoded.
"""

from __future__ import annotations

import sys
from pathlib import Path

from dml import DMLSigner, DMLValidator, load

EXAMPLE = Path(__file__).with_name("example_traps.yaml")


def main() -> int:
    doc = load(EXAMPLE)

    # 1. Validate against the spec.
    errors = DMLValidator().validate_document(doc)
    if errors:
        print("Document is invalid:")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(f"Validated: {len(doc['traps'])} traps OK")

    # 2. Sign (key comes from the DML_KEY env var).
    signer = DMLSigner.from_env("DML_KEY")
    signed = signer.sign_document(doc)
    print(f"Signed: document_signature={signed['document_signature']}")
    for trap in signed["traps"]:
        print(f"  trap {trap['id']:<24} signature={trap['signature']}")

    # 3. Verify.
    ok, verify_errors = signer.verify_document(signed)
    print(f"Verify: ok={ok}")
    if not ok:
        for e in verify_errors:
            print(f"  - {e}")
        return 1

    # 4. Demonstrate tamper detection: flip a field in one trap.
    signed["traps"][0]["severity"] = "info"
    ok_after, tamper_errors = signer.verify_document(signed)
    print(f"After tampering one trap: ok={ok_after} (expected False)")
    for e in tamper_errors:
        print(f"  - {e}")

    print("\nRound-trip complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
