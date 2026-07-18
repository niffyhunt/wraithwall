"""Tests for Cowrie log parsing and import-without-anthropic."""

from __future__ import annotations

import json
import os

from honeypot_mitre import parse_lines, parse_sessions

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "examples", "sample_cowrie.json")


def test_parse_reconstructs_commands_in_order():
    events = [
        {"eventid": "cowrie.session.connect", "session": "s1", "src_ip": "203.0.113.5"},
        {"eventid": "cowrie.command.input", "session": "s1", "input": "uname -a"},
        {"eventid": "cowrie.command.input", "session": "s1", "input": "whoami"},
        {"eventid": "cowrie.session.closed", "session": "s1", "duration": 5.0},
    ]
    sessions = parse_lines(json.dumps(e) for e in events)
    assert len(sessions) == 1
    s = sessions[0]
    assert s.session_id == "s1"
    assert s.src_ip == "203.0.113.5"
    assert s.commands == ["uname -a", "whoami"]
    assert s.duration == 5.0


def test_malformed_lines_skipped():
    lines = ['{"eventid": "cowrie.command.input", "session": "x", "input": "ls"}',
             "not json at all", ""]
    sessions = parse_lines(lines)
    assert len(sessions) == 1
    assert sessions[0].commands == ["ls"]


def test_parse_sample_file():
    sessions = parse_sessions(SAMPLE)
    ids = {s.session_id for s in sessions}
    assert {"a1b2c3d4", "e5f6a7b8", "c9d0e1f2"} <= ids


def test_import_without_anthropic():
    # The package and its deterministic path must import with no anthropic dep.
    import importlib
    import honeypot_mitre
    importlib.reload(honeypot_mitre)
    assert hasattr(honeypot_mitre, "analyze_session")
