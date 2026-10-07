"""Tenant webhook destinations for dossier events. SSRF checked at write."""
from __future__ import annotations

import sqlite3
import time
from typing import List

from .dossier_store import DB_PATH, _lock, init as store_init
from .dossier_webhook import validate_webhook_url


def _con():
    store_init()
    con = sqlite3.connect(str(DB_PATH), timeout=10)
    con.row_factory = sqlite3.Row
    con.execute(
        """CREATE TABLE IF NOT EXISTS dossier_destinations (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             tenant_id TEXT NOT NULL,
             url TEXT NOT NULL,
             event TEXT NOT NULL,
             created_at REAL NOT NULL
           )"""
    )
    con.commit()
    return con


def register(tenant_id: str, url: str, event: str) -> str:
    err = validate_webhook_url(url)
    if err:
        return err
    if event not in ("dossier.created", "dossier.updated"):
        return "event"
    store_init()
    with _lock:
        con = sqlite3.connect(str(DB_PATH), timeout=10)
        con.row_factory = sqlite3.Row
        try:
            con.execute(
                """CREATE TABLE IF NOT EXISTS dossier_destinations (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     tenant_id TEXT NOT NULL,
                     url TEXT NOT NULL,
                     event TEXT NOT NULL,
                     created_at REAL NOT NULL
                   )"""
            )
            con.execute(
                "INSERT INTO dossier_destinations (tenant_id, url, event, created_at) VALUES (?,?,?,?)",
                (tenant_id, url, event, time.time()),
            )
            con.commit()
        finally:
            con.close()
    return ""


def urls_for_tenant(tenant_id: str, event: str) -> List[str]:
    if not tenant_id:
        return []
    con = _con()
    try:
        rows = con.execute(
            "SELECT url FROM dossier_destinations WHERE tenant_id=? AND event=?",
            (tenant_id, event),
        ).fetchall()
        return [r["url"] for r in rows]
    finally:
        con.close()
