import os
from pathlib import Path

from honeypot_mitre import analyze_session
from honeypot_mitre.parsing import parse_sessions

from wraithmesh.models import Observation, verify_observation
from wraithmesh.signing import node_id_from_key

SAMPLE = Path(__file__).resolve().parents[2] / "honeypot-mitre" / "examples" / "sample_cowrie.json"


def test_observation_sign_and_verify():
    os.environ["WRAITHMESH_KEY"] = "test-key"
    key = os.environ["WRAITHMESH_KEY"]
    node_id = node_id_from_key(key)
    sessions = parse_sessions(SAMPLE)
    analysis = analyze_session(sessions[0])
    obs = Observation.from_session_analysis(analysis=analysis, node_id=node_id, epoch=1)
    obs.sign(key)
    payload = obs.to_dict()
    assert "commands" not in payload
    assert "src_ip" not in payload
    assert verify_observation(payload, key)