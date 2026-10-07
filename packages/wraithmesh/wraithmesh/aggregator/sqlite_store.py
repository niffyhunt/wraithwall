"""Persistent SQLite aggregator store for corroboration + reputation."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from ..reputation import NodeReputation, ReputationStore
from .store import CorroborationRecord


class SqliteAggregatorStore:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()
        self.reputation = ReputationStore(nodes=self._load_reputation())

    def _init_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS campaigns (
                equivalence_key TEXT PRIMARY KEY,
                technique_set TEXT NOT NULL,
                distinct_nodes INTEGER NOT NULL,
                sensor_classes TEXT NOT NULL,
                confidence REAL NOT NULL,
                reputation_score REAL NOT NULL,
                first_global_seen TEXT NOT NULL,
                last_global_seen TEXT NOT NULL,
                node_ids TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reputation (
                node_id TEXT PRIMARY KEY,
                submissions INTEGER NOT NULL,
                corroborated INTEGER NOT NULL,
                rejected INTEGER NOT NULL,
                score REAL NOT NULL
            )
            """
        )
        self._conn.commit()

    def close(self) -> None:
        self._save_reputation()
        self._conn.close()

    def _load_reputation(self) -> dict[str, NodeReputation]:
        rows = self._conn.execute("SELECT * FROM reputation").fetchall()
        out: dict[str, NodeReputation] = {}
        for row in rows:
            out[row["node_id"]] = NodeReputation(
                node_id=row["node_id"],
                submissions=int(row["submissions"]),
                corroborated=int(row["corroborated"]),
                rejected=int(row["rejected"]),
                score=float(row["score"]),
            )
        return out

    def _save_reputation(self) -> None:
        for node in self.reputation.nodes.values():
            self._conn.execute(
                """
                INSERT INTO reputation(node_id, submissions, corroborated, rejected, score)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(node_id) DO UPDATE SET
                    submissions=excluded.submissions,
                    corroborated=excluded.corroborated,
                    rejected=excluded.rejected,
                    score=excluded.score
                """,
                (node.node_id, node.submissions, node.corroborated, node.rejected, node.score),
            )
        self._conn.commit()

    def get(self, equivalence_key: str) -> CorroborationRecord | None:
        row = self._conn.execute(
            "SELECT * FROM campaigns WHERE equivalence_key=?",
            (equivalence_key,),
        ).fetchone()
        if row is None:
            return None
        return CorroborationRecord(
            equivalence_key=row["equivalence_key"],
            technique_set=json.loads(row["technique_set"]),
            distinct_nodes=int(row["distinct_nodes"]),
            sensor_classes=set(json.loads(row["sensor_classes"])),
            confidence=float(row["confidence"]),
            reputation_score=float(row["reputation_score"]),
            first_global_seen=row["first_global_seen"],
            last_global_seen=row["last_global_seen"],
            node_ids=set(json.loads(row["node_ids"])),
        )

    def upsert(self, record: CorroborationRecord) -> CorroborationRecord:
        self._conn.execute(
            """
            INSERT INTO campaigns VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(equivalence_key) DO UPDATE SET
                technique_set=excluded.technique_set,
                distinct_nodes=excluded.distinct_nodes,
                sensor_classes=excluded.sensor_classes,
                confidence=excluded.confidence,
                reputation_score=excluded.reputation_score,
                first_global_seen=excluded.first_global_seen,
                last_global_seen=excluded.last_global_seen,
                node_ids=excluded.node_ids
            """,
            (
                record.equivalence_key,
                json.dumps(sorted(record.technique_set)),
                record.distinct_nodes,
                json.dumps(sorted(record.sensor_classes)),
                record.confidence,
                record.reputation_score,
                record.first_global_seen,
                record.last_global_seen,
                json.dumps(sorted(record.node_ids)),
            ),
        )
        self._conn.commit()
        self._save_reputation()
        return record

    def all_records(self) -> list[CorroborationRecord]:
        rows = self._conn.execute("SELECT equivalence_key FROM campaigns ORDER BY last_global_seen DESC").fetchall()
        return [self.get(row["equivalence_key"]) for row in rows if self.get(row["equivalence_key"])]

    def stats(self) -> dict[str, Any]:
        row = self._conn.execute(
            "SELECT COUNT(*) AS campaigns, SUM(distinct_nodes) AS node_hits FROM campaigns"
        ).fetchone()
        return {
            "campaigns": int(row["campaigns"] or 0),
            "node_hits": int(row["node_hits"] or 0),
            "contributors": len(self.reputation.nodes),
        }