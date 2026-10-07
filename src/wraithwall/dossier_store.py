"""SQLite dossier store with evidence hash chain. Opaque ids only."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

DB_PATH = Path(os.environ.get("DOSSIER_STORE_PATH", "/opt/wraithwall-secrets/dossier_store.db"))
RETENTION_SEC = 90 * 24 * 3600
# RLock: destinations.register() holds this then calls init() which takes it again.
_lock = threading.RLock()


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(DB_PATH), timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init() -> None:
    with _lock:
        con = _connect()
        try:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS dossier_campaigns (
                  campaign_id TEXT PRIMARY KEY,
                  behavioral_dna_hash TEXT UNIQUE,
                  contract_json TEXT NOT NULL,
                  created_at REAL NOT NULL,
                  updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS dossier_sessions (
                  session_id TEXT NOT NULL,
                  campaign_id TEXT NOT NULL,
                  PRIMARY KEY (session_id, campaign_id),
                  FOREIGN KEY (campaign_id) REFERENCES dossier_campaigns(campaign_id)
                );
                CREATE TABLE IF NOT EXISTS dossier_evidence_chain (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  campaign_id TEXT NOT NULL,
                  previous_hash TEXT NOT NULL,
                  current_hash TEXT NOT NULL,
                  operation TEXT NOT NULL,
                  timestamp REAL NOT NULL,
                  FOREIGN KEY (campaign_id) REFERENCES dossier_campaigns(campaign_id)
                );
                """
            )
            con.commit()
        finally:
            con.close()


def _chain_hash(previous: str, session_json: str) -> str:
    return hashlib.sha256((previous + session_json).encode("utf-8")).hexdigest()


def upsert_packet(packet: Dict[str, Any], session_ids=None) -> Dict[str, Any]:
    init()
    cid = packet["campaign_id"]
    dna = (packet.get("identity") or {}).get("command_pattern_hash") or cid
    now = time.time()
    body = json.dumps(packet, separators=(",", ":"), sort_keys=True)
    session_ids = list(session_ids or (packet.get("evidence") or {}).get("session_ids") or [])
    with _lock:
        con = _connect()
        try:
            row = con.execute("SELECT campaign_id, updated_at FROM dossier_campaigns WHERE campaign_id=?", (cid,)).fetchone()
            created = row is None
            if created:
                con.execute(
                    "INSERT INTO dossier_campaigns (campaign_id, behavioral_dna_hash, contract_json, created_at, updated_at) VALUES (?,?,?,?,?)",
                    (cid, dna, body, now, now),
                )
                prev = "0" * 64
                op = "create"
            else:
                con.execute(
                    "UPDATE dossier_campaigns SET contract_json=?, behavioral_dna_hash=?, updated_at=? WHERE campaign_id=?",
                    (body, dna, now, cid),
                )
                last = con.execute(
                    "SELECT current_hash FROM dossier_evidence_chain WHERE campaign_id=? ORDER BY id DESC LIMIT 1",
                    (cid,),
                ).fetchone()
                prev = last["current_hash"] if last else "0" * 64
                op = "update"
            sess_blob = json.dumps(session_ids, separators=(",", ":"))
            cur = _chain_hash(prev, sess_blob)
            con.execute(
                "INSERT INTO dossier_evidence_chain (campaign_id, previous_hash, current_hash, operation, timestamp) VALUES (?,?,?,?,?)",
                (cid, prev, cur, op, now),
            )
            for sid in session_ids:
                if not sid:
                    continue
                con.execute(
                    "INSERT OR IGNORE INTO dossier_sessions (session_id, campaign_id) VALUES (?,?)",
                    (str(sid), cid),
                )
            cutoff = now - RETENTION_SEC
            con.execute("DELETE FROM dossier_evidence_chain WHERE timestamp < ?", (cutoff,))
            stale = con.execute("SELECT campaign_id FROM dossier_campaigns WHERE updated_at < ?", (cutoff,)).fetchall()
            for s in stale:
                con.execute("DELETE FROM dossier_sessions WHERE campaign_id=?", (s["campaign_id"],))
                con.execute("DELETE FROM dossier_campaigns WHERE campaign_id=?", (s["campaign_id"],))
            con.commit()
            return {"created": created, "chain_hash": cur, "operation": op}
        finally:
            con.close()


def get_packet(campaign_id: str) -> Optional[Dict[str, Any]]:
    init()
    con = _connect()
    try:
        row = con.execute("SELECT contract_json FROM dossier_campaigns WHERE campaign_id=?", (campaign_id,)).fetchone()
        if not row:
            return None
        return json.loads(row["contract_json"])
    finally:
        con.close()
