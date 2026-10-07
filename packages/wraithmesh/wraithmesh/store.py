"""Local observation rollup and uplink cooldown tracking."""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class LocalRollup:
    equivalence_key: str
    seen_count: int
    first_seen: str
    last_seen: str
    technique_set: list[str]
    confidence: float


class LocalStore:
    """SQLite-backed local equivalence rollup with uplink cooldown."""

    def __init__(self, state_dir: str | Path) -> None:
        self.root = Path(state_dir)
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "observations.db"
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rollups (
                equivalence_key TEXT PRIMARY KEY,
                seen_count INTEGER NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                technique_set TEXT NOT NULL,
                confidence REAL NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS uplinks (
                equivalence_key TEXT PRIMARY KEY,
                last_uplink REAL NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def get_epoch(self) -> int:
        row = self._conn.execute("SELECT value FROM meta WHERE key='epoch'").fetchone()
        return int(row["value"]) if row else 0

    def bump_epoch(self) -> int:
        epoch = self.get_epoch() + 1
        self._conn.execute(
            "INSERT INTO meta(key, value) VALUES('epoch', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(epoch),),
        )
        self._conn.commit()
        return epoch

    def record(
        self,
        *,
        equivalence_key: str,
        technique_set: list[str],
        confidence: float,
        first_seen: str,
        last_seen: str,
    ) -> LocalRollup:
        row = self._conn.execute(
            "SELECT * FROM rollups WHERE equivalence_key=?",
            (equivalence_key,),
        ).fetchone()
        techniques = sorted(set(technique_set))
        if row is None:
            seen = 1
            self._conn.execute(
                "INSERT INTO rollups VALUES (?, ?, ?, ?, ?, ?)",
                (equivalence_key, seen, first_seen, last_seen, json.dumps(techniques), confidence),
            )
        else:
            seen = int(row["seen_count"]) + 1
            merged = sorted(set(json.loads(row["technique_set"])) | set(techniques))
            conf = max(float(row["confidence"]), confidence)
            self._conn.execute(
                "UPDATE rollups SET seen_count=?, last_seen=?, technique_set=?, confidence=? "
                "WHERE equivalence_key=?",
                (seen, last_seen, json.dumps(merged), conf, equivalence_key),
            )
        self._conn.commit()
        return LocalRollup(
            equivalence_key=equivalence_key,
            seen_count=seen,
            first_seen=first_seen if row is None else row["first_seen"],
            last_seen=last_seen,
            technique_set=techniques if row is None else sorted(set(json.loads(row["technique_set"])) | set(techniques)),
            confidence=confidence if row is None else max(float(row["confidence"]), confidence),
        )

    def should_uplink(self, equivalence_key: str, cooldown_seconds: int, min_local_count: int) -> bool:
        row = self._conn.execute(
            "SELECT seen_count FROM rollups WHERE equivalence_key=?",
            (equivalence_key,),
        ).fetchone()
        if not row or int(row["seen_count"]) < min_local_count:
            return False
        uplink = self._conn.execute(
            "SELECT last_uplink FROM uplinks WHERE equivalence_key=?",
            (equivalence_key,),
        ).fetchone()
        if uplink is None:
            return True
        return (time.time() - float(uplink["last_uplink"])) >= cooldown_seconds

    def mark_uplinked(self, equivalence_key: str) -> None:
        self._conn.execute(
            "INSERT INTO uplinks VALUES (?, ?) ON CONFLICT(equivalence_key) DO UPDATE SET last_uplink=excluded.last_uplink",
            (equivalence_key, time.time()),
        )
        self._conn.commit()

    def pending_rollups(self) -> list[LocalRollup]:
        rows = self._conn.execute("SELECT * FROM rollups ORDER BY last_seen DESC").fetchall()
        out: list[LocalRollup] = []
        for row in rows:
            out.append(
                LocalRollup(
                    equivalence_key=row["equivalence_key"],
                    seen_count=int(row["seen_count"]),
                    first_seen=row["first_seen"],
                    last_seen=row["last_seen"],
                    technique_set=json.loads(row["technique_set"]),
                    confidence=float(row["confidence"]),
                )
            )
        return out