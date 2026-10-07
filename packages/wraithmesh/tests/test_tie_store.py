import os
from pathlib import Path

from honeypot_mitre import analyze_session
from honeypot_mitre.parsing import parse_sessions

from wraithmesh.aggregator import SqliteAggregatorStore, ingest_observation
from wraithmesh.models import Observation
from wraithmesh.signing import node_id_from_key

SAMPLE = Path(__file__).resolve().parents[2] / "honeypot-mitre" / "examples" / "sample_cowrie.json"


def _obs(node_suffix: str) -> dict:
    os.environ["WRAITHMESH_KEY"] = "tie-store-key"
    key = os.environ["WRAITHMESH_KEY"]
    sessions = parse_sessions(SAMPLE)
    analysis = analyze_session(sessions[0])
    obs = Observation.from_session_analysis(
        analysis=analysis,
        node_id=node_id_from_key(key + node_suffix),
        epoch=1,
    )
    obs.sign(key)
    return obs.to_dict(), key


def test_sqlite_store_persists_campaigns(tmp_path):
    db = tmp_path / "tie.db"
    store = SqliteAggregatorStore(db)
    payload_a, key = _obs("a")
    payload_b, _ = _obs("b")
    payload_b["equivalence_key"] = payload_a["equivalence_key"]
    trusted = {payload_a["node_id"]: key, payload_b["node_id"]: key}
    ingest_observation(payload_a, key=trusted, store=store)
    ingest_observation(payload_b, key=trusted, store=store)
    record = store.get(payload_a["equivalence_key"])
    store.close()
    assert record is not None
    assert record.distinct_nodes == 2
    assert record.reputation_score > 0

    store2 = SqliteAggregatorStore(db)
    again = store2.get(payload_a["equivalence_key"])
    store2.close()
    assert again is not None
    assert again.distinct_nodes == 2