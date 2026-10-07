"""One-shot seed container entrypoint (Phase 4).

Contract: write the deterministic corpus into the shared sandbox volume,
self-verify byte-determinism, exercise the HMAC ship protocol, write a
receipt, exit 0. Any failure exits non-zero with an E304-tagged message so
the launcher marks PARTIAL and rolls back (roadmap Phase 4 failure contract).

Always prints the LOCAL provenance banner so nobody reading container logs
can mistake this traffic for production telemetry.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from . import corpus
from . import shipper

STATE_DIR = Path(os.environ.get("SANDBOX_STATE_DIR", "/state/synthetic"))
RECEIPT = Path(os.environ.get(
    "SANDBOX_SEED_RECEIPT", "/state/synthetic/seed_receipt.json"))


def main() -> int:
    print(corpus.LOCAL_MARKER_TAG
          + " synthetic telemetry seed starting (not production traffic)",
          flush=True)
    try:
        receipt = shipper.run_once(STATE_DIR, receipt_path=RECEIPT)
    except shipper.SeedError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        print(corpus.LOCAL_MARKER_TAG + " seed FAILED", file=sys.stderr,
              flush=True)
        return 1
    except Exception as exc:  # never exit 0 on an unexpected error
        print(f"✗ E304: unexpected seed failure: {exc}", file=sys.stderr,
              flush=True)
        return 1

    print(
        f"✓ seed complete: {receipt['events']} events / "
        f"{receipt['sessions']} sessions / {receipt['tty_logs']} tty logs",
        flush=True)
    print(f"  corpus sha256: {receipt['corpus_sha256']}", flush=True)
    print(f"  receipt:       {receipt.get('receipt_path', RECEIPT)}",
          flush=True)
    for r in receipt.get("shipped", []):
        print(f"  shipped batch {r['batch']}: {r['lines']} lines -> "
              f"{r['response']}", flush=True)
    if not receipt.get("shipped"):
        print("  ship protocol: skipped (SANDBOX_SHIP_URL/KEY not set)",
          flush=True)
    print(corpus.LOCAL_MARKER_TAG + " all records LOCAL-marked", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
