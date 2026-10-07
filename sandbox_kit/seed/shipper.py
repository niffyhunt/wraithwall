"""Seed shipper (Phase 4): assembles synthetic telemetry, ships it through
the REAL ingest surfaces, verifies determinism, and leaves a receipt.

Two ingest surfaces are exercised, both production code paths, unmodified:

1. **File tail (the intelligence path)** — writes ``synthetic.jsonl`` plus one
   binary ttylog per session into a shared in-project volume. The application
   (already running with ``COWRIE_LOG_PATH`` pointing at that file and
   ``TTYLOG_BASE_PATH`` at the tty directory) tails it with its own watcher and
   runs the unchanged pipeline: sessions, DNA, campaigns, MITRE, deception
   bus, SSE.

2. **HMAC ship endpoint (the wire protocol)** — POSTs the same JSONL to the
   app's ``/api/v1/cowrie/ship`` with a valid ``X-Shipper-Signature``
   (HMAC-SHA256 over the raw body). This proves the authenticated ship
   protocol end-to-end. It is an *exercise* of the protocol, not the
   intelligence path: production consumers of the ``cowrie:log`` list live in
   the external cowrie-analyzer sidecar, which the sandbox deliberately does
   not run.

The HMAC key is generated per-boot by the launcher and delivered to both the
app and the seed container via the compose environment allowlist (H12) — it
never exists on disk and never leaves the sandbox project.

Failure contract: any hard failure raises :class:`SeedError` with an
E304-tagged message; the launcher marks state PARTIAL and rolls back (per the
roadmap: "seed failure ⇒ PARTIAL + E304").
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import corpus

# ── configuration (container env; all injectable for tests) ─────────────────

SHIP_URL = os.environ.get("SANDBOX_SHIP_URL", "")
SHIP_KEY = os.environ.get("SANDBOX_SHIP_KEY", "")
RECEIPT_PATH = os.environ.get(
    "SANDBOX_SEED_RECEIPT", "/state/synthetic_seed_receipt.json")

#: Ship batches must respect the endpoint's MAX_BATCH; keep a margin.
SHIP_BATCH_SIZE = 200

#: Seconds to wait for the app endpoint before giving up (one-shot container).
SHIP_TIMEOUT_S = int(os.environ.get("SANDBOX_SHIP_TIMEOUT_S", "60"))


class SeedError(RuntimeError):
    """Raised for any seed failure (launcher maps this to E304 / PARTIAL)."""


def e304(msg: str) -> SeedError:
    return SeedError("E304: " + msg)


# ── 1. file-tail payload (the intelligence path) ────────────────────────────


def write_log_files(state_dir: Path,
                    seed_version: str = corpus.SEED_VERSION
                    ) -> Tuple[Path, Path, int]:
    """Write ``synthetic.jsonl`` and the tty logs into ``state_dir``.

    Creates ``synthetic.jsonl`` fresh (truncating) and ``tty/`` atomically:
    the directory is written under a temp name and renamed, so the app's
    tailer can never observe a half-written corpus under the final name.

    Returns ``(jsonl_path, tty_dir, line_count)``.
    """
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise e304(f"cannot create state dir {state_dir}: {exc}") from exc

    lines = corpus.event_lines(seed_version)
    if not lines:
        raise e304("corpus generator produced zero events")

    jsonl_path = state_dir / "synthetic.jsonl"
    tmp_path = state_dir / (".synthetic.jsonl.tmp-%d" % os.getpid())
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, jsonl_path)  # atomic final publish
    except OSError as exc:
        raise e304(f"cannot write synthetic.jsonl: {exc}") from exc

    # tty logs: same atomic-directory discipline.
    tty_dir = state_dir / "tty"
    tmp_tty = state_dir / (".tty.tmp-%d" % os.getpid())
    try:
        if tmp_tty.exists():
            for stale in tmp_tty.iterdir():
                stale.unlink()
        else:
            tmp_tty.mkdir(parents=True)
        for sid, blob in corpus.tty_frames(seed_version):
            (tmp_tty / sid).write_bytes(blob)
        if tty_dir.exists():
            for stale in tty_dir.iterdir():
                stale.unlink()
            tty_dir.rmdir()
        os.replace(tmp_tty, tty_dir)  # atomic swap-in
    except OSError as exc:
        raise e304(f"cannot write tty logs: {exc}") from exc

    return jsonl_path, tty_dir, len(lines)


# ── 2. HMAC ship protocol (wire-protocol exercise) ──────────────────────────


def ship_signature(key: str, body: bytes) -> str:
    """Exactly the signature cowrie_ship._verify_signature() computes."""
    return hmac.new(key.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _post_ship(url: str, key: str, body: bytes) -> Tuple[int, str]:
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Shipper-Signature": ship_signature(key, body),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")[:200]
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")[:200]
    except (urllib.error.URLError, OSError) as exc:
        return 0, str(exc)[:200]


def ship_to_app(seed_version: str = corpus.SEED_VERSION,
                url: str = SHIP_URL,
                key: str = SHIP_KEY,
                poster=_post_ship,
                sleep=time.sleep) -> List[Dict[str, Any]]:
    """Ship the corpus through the HMAC endpoint in batches.

    ``poster``/``sleep`` are injectable so unit tests can exercise batching,
    auth rejection and retry logic without any network. Batches are shipped in
    order; a rejected batch aborts (no partial-silence: the receipt records
    exactly what was accepted).
    """
    if not url or not key:
        # Absent config is a *deliberate skip* (launcher may disable the
        # protocol exercise), not a failure — the file-tail path is the
        # intelligence path and does not depend on this.
        return []

    lines = corpus.event_lines(seed_version)
    results: List[Dict[str, Any]] = []
    deadline = time.time() + SHIP_TIMEOUT_S

    for i in range(0, len(lines), SHIP_BATCH_SIZE):
        batch = lines[i:i + SHIP_BATCH_SIZE]
        body = json.dumps({"lines": batch}, separators=(",", ":")).encode()
        status, text = poster(url, key, body)
        if status == 401:
            raise e304("ship endpoint rejected our HMAC signature (401)")
        if status == 0 and time.time() < deadline:
            # app not answering yet: bounded retry for this batch
            while status == 0 and time.time() < deadline:
                sleep(2)
                status, text = poster(url, key, body)
        if status != 200:
            raise e304(
                f"ship endpoint returned {status} for batch "
                f"{i // SHIP_BATCH_SIZE}: {text!r}")
        results.append({
            "batch": i // SHIP_BATCH_SIZE,
            "lines": len(batch),
            "response": json.loads(text) if text.startswith("{") else text,
        })
    return results


# ── 3. receipt ──────────────────────────────────────────────────────────────


def write_receipt(state_dir: Path,
                  jsonl_path: Path,
                  tty_dir: Path,
                  line_count: int,
                  ship_results: List[Dict[str, Any]],
                  seed_version: str = corpus.SEED_VERSION,
                  receipt_path: Path = Path(RECEIPT_PATH)) -> Dict[str, Any]:
    """Write the seed receipt (provenance artifact for export/audit)."""
    receipt: Dict[str, Any] = {
        "seed_version": seed_version,
        "corpus_sha256": corpus.corpus_digest(seed_version),
        "events": line_count,
        "sessions": len(corpus.build_sessions(seed_version)),
        "tty_logs": len(list(tty_dir.glob("*"))) if tty_dir.exists() else 0,
        "synthetic_jsonl": str(jsonl_path),
        "tty_dir": str(tty_dir),
        "shipped": ship_results,
        "generated_at_epoch": int(time.time()),
        "marking": corpus.LOCAL_MARK,
        "sensor": corpus.LOCAL_SENSOR,
        "note": "All records are synthetic and LOCAL-marked; not production telemetry.",
    }
    try:
        rp = Path(receipt_path)
        if not rp.is_absolute():
            rp = state_dir / rp
        rp.parent.mkdir(parents=True, exist_ok=True)
        rp.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
        receipt["receipt_path"] = str(rp)
    except OSError as exc:
        raise e304(f"cannot write seed receipt: {exc}") from exc
    return receipt


# ── 4. determinism self-verify ──────────────────────────────────────────────


def verify_written(jsonl_path: Path,
                   seed_version: str = corpus.SEED_VERSION) -> None:
    """Re-read the written file and require byte-identity with the generator.

    A corpus that claims determinism but writes machine-dependent bytes would
    silently break every downstream hash expectation, so this is checked on
    every run, not in CI only.
    """
    expected = corpus.corpus_digest(seed_version)
    try:
        raw = jsonl_path.read_bytes()
    except OSError as exc:
        raise e304(f"cannot re-read synthetic.jsonl: {exc}") from exc
    got = hashlib.sha256(raw).hexdigest()
    if got != expected:
        raise e304(
            f"written corpus digest {got[:12]}… != expected {expected[:12]}… "
            "(determinism violation — generator output drifted)")
    if not raw.endswith(b"\n"):
        raise e304("written corpus does not end with a newline (tailer may "
                   "drop the last record)")


# ── entrypoint helper ───────────────────────────────────────────────────────


def run_once(state_dir: Path,
             receipt_path: Path = Path(RECEIPT_PATH),
             seed_version: str = corpus.SEED_VERSION,
             url: str = SHIP_URL,
             key: str = SHIP_KEY) -> Dict[str, Any]:
    """One-shot seed run: write files → verify determinism → ship → receipt."""
    jsonl_path, tty_dir, count = write_log_files(state_dir, seed_version)
    verify_written(jsonl_path, seed_version)
    ship_results = ship_to_app(seed_version, url=url, key=key)
    return write_receipt(state_dir, jsonl_path, tty_dir, count,
                         ship_results, seed_version, receipt_path)
