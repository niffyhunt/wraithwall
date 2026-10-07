import os

from honeypot_mitre import analyze_session
from honeypot_mitre.parsing import parse_sessions
from pathlib import Path

from wraithmesh.aggregator import InMemoryAggregatorStore, ingest_batch, ingest_observation
from wraithmesh.models import Observation
from wraithmesh.signing import node_id_from_key

SAMPLE = Path(__file__).resolve().parents[2] / "honeypot-mitre" / "examples" / "sample_cowrie.json"


def _signed_obs(node_suffix: str) -> dict:
    os.environ["WRAITHMESH_KEY"] = "agg-test-key"
    key = os.environ["WRAITHMESH_KEY"]
    sessions = parse_sessions(SAMPLE)
    analysis = analyze_session(sessions[0])
    obs = Observation.from_session_analysis(
        analysis=analysis,
        node_id=node_id_from_key(key + node_suffix),
        epoch=1,
    )
    obs.sign(key)
    return obs.to_dict()


def test_corroboration_merges_nodes():
    key = "agg-test-key"
    store = InMemoryAggregatorStore()
    first = _signed_obs("a")
    second = _signed_obs("b")
    second["equivalence_key"] = first["equivalence_key"]
    ingest_observation(first, key=key, store=store)
    record = ingest_observation(second, key=key, store=store)
    assert record.distinct_nodes == 2
    assert record.equivalence_key == first["equivalence_key"]
    assert record.reputation_score > 0


def test_batch_ingest():
    key = "agg-test-key"
    store = InMemoryAggregatorStore()
    batch = [_signed_obs("x"), _signed_obs("y")]
    records = ingest_batch(batch, key=key, store=store)
    assert len(records) == 2