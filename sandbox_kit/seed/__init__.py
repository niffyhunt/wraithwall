"""WraithWall Local Secure Sandbox — synthetic telemetry seed (Phase 4).

Fixed-seed, LOCAL-marked, deterministic telemetry that flows through the
*existing* WraithWall intelligence surfaces. No second telemetry system is
created here:

    sb-seed writes synthetic.jsonl ──▶ app watcher tails COWRIE_LOG_PATH
        ──▶ cowrie_intelligence.process_event (pipeline unchanged)
        ──▶ sessions / campaigns / DNA / MITRE / deception bus / SSE

Modules
    corpus    deterministic session corpus + binary ttylog frames
    shipper   HMAC ship-protocol exercise + JSONL file assembly + receipts
    __main__  one-shot container entrypoint (E304 on failure)

Security properties (verified by tests, not asserted by comments):
    - every record carries ``"sandbox": "LOCAL"`` and a LOCAL sensor name
    - deterministic: same corpus version ⇒ byte-identical output anywhere
    - stdlib only (the seed image installs nothing)
    - no real credentials: every secret-shaped string is repo-canonically fake
"""
from __future__ import annotations

__all__ = ["corpus", "shipper"]
