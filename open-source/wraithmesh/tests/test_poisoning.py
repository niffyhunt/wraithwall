import os

from honeypot_mitre import analyze_session
from honeypot_mitre.parsing import parse_sessions
from pathlib import Path

from wraithmesh.aggregator import InMemoryAggregatorStore, ingest_observation
from wraithmesh.models import Observation
from wraithmesh.poisoning import generate_trap_keys, is_trap_key, save_trap_keys
from wraithmesh.signing import node_id_from_key

SAMPLE = Path(__file__).resolve().parents[2] / "honeypot-mitre" / "examples" / "sample_cowrie.json"


def test_trap_key_rejects_observation(tmp_path):
    os.environ["WRAITHMESH_KEY"] = "poison-test-key"
    key = os.environ["WRAITHMESH_KEY"]
    trap = generate_trap_keys(1)[0]
    trap_file = tmp_path / "traps.json"
    save_trap_keys(trap_file, [trap])
    assert is_trap_key(trap, {trap})

    sessions = parse_sessions(SAMPLE)
    analysis = analyze_session(sessions[0])
    obs = Observation.from_session_analysis(
        analysis=analysis,
        node_id=node_id_from_key(key),
        epoch=1,
    )
    obs.equivalence_key = trap
    obs.sign(key)
    store = InMemoryAggregatorStore()
    try:
        ingest_observation(obs.to_dict(), key=key, store=store, trap_keys={trap})
        assert False, "expected poisoning rejection"
    except ValueError as exc:
        assert "poisoning" in str(exc).lower()
    assert store.reputation.get(obs.node_id).rejected == 1