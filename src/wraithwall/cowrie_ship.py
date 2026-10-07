"""Signed ingest endpoint for Cowrie telemetry shippers.

Shippers (including the local sandbox's synthetic seed) push newline-free
JSONL batches with an HMAC-SHA256 signature over the exact request body in
``X-Shipper-Signature``. Accepted batches are appended to the ``cowrie:log``
Redis list that the intelligence pipeline tails, so a shipper never has to
touch the pipeline directly.

Auth is fail-closed: with no ``COWRIE_SHIP_KEY`` configured, or a missing/
wrong signature, the request is rejected with 401 before the body is parsed.
Batches are deduplicated by content hash for ``BATCH_DEDUP_TTL`` seconds, so a
retried batch is accepted exactly once.
"""
import hashlib
import hmac
import os

import redis as redis_lib
from flask import Blueprint, jsonify, request

from wraithwall import shared

cowrie_ship_bp = Blueprint("cowrie_ship", __name__)

COWRIE_SHIP_KEY = os.environ.get("COWRIE_SHIP_KEY", "")
LOG_KEY = "cowrie:log"
MAX_BATCH = 200
BATCH_DEDUP_TTL = 300


def _get_redis():
    """App-scoped Redis client, falling back to REDIS_URL outside an app context."""
    client = shared.get_redis()
    if client is not None:
        return client
    return redis_lib.from_url(
        os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0"),
        socket_connect_timeout=3,
        socket_timeout=5,
        decode_responses=True,
    )


def _verify_signature():
    if not COWRIE_SHIP_KEY:
        return False
    sig = request.headers.get("X-Shipper-Signature", "")
    if not sig:
        return False
    expected = hmac.new(
        COWRIE_SHIP_KEY.encode("utf-8"),
        request.get_data(),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(sig, expected)


@cowrie_ship_bp.route("/api/v1/cowrie/ship", methods=["POST"])
def cowrie_ship():
    if not _verify_signature():
        return jsonify({"error": "unauthorized"}), 401

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "bad request"}), 400

    lines = payload.get("lines")
    if not isinstance(lines, list) or not lines:
        return jsonify({"error": "lines required"}), 400
    if len(lines) > MAX_BATCH:
        return jsonify({"error": "batch too large"}), 413

    cleaned = [line for line in lines if isinstance(line, str) and line.strip()]
    if not cleaned:
        return jsonify({"error": "empty lines"}), 400

    r = _get_redis()
    batch_hash = hashlib.sha256("\n".join(cleaned).encode("utf-8")).hexdigest()
    dedup_key = "cowrie:ship:batch:%s" % batch_hash
    try:
        if r.set(dedup_key, "1", ex=BATCH_DEDUP_TTL, nx=True):
            r.rpush(LOG_KEY, *cleaned)
        else:
            return jsonify({"accepted": 0, "deduplicated": len(cleaned)})
    except Exception:  # noqa: BLE001 — Redis down is a 503, never a 500 trace
        return jsonify({"error": "store unavailable"}), 503

    return jsonify({"accepted": len(cleaned)})


@cowrie_ship_bp.route("/api/v1/cowrie/ship/health", methods=["GET"])
def cowrie_ship_health():
    return jsonify({"status": "ok"})