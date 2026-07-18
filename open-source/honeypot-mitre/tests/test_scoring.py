"""Tests for the deterministic scoring formula and technique mapping."""

from __future__ import annotations

from honeypot_mitre import classify_command, map_techniques, score_session
from honeypot_mitre.mitre import DANGER_SCORES


def test_empty_session_scores_zero():
    assert score_session([]) == 0


def test_recon_only_score_formula():
    # 'whoami' -> reconnaissance (base 5). Two recon commands, both map to the
    # same 6 recon techniques (distinct set size = 6).
    commands = ["whoami", "uname -a"]
    mapping = map_techniques(commands)
    assert mapping["dominant_stage"] == "reconnaissance"
    distinct = len(mapping["techniques_used"])
    expected = 5 + len(commands) * 2 + distinct * 3
    assert score_session(commands, mapping) == expected
    # base 5 + 2 commands*2(=4) + 6 techniques*3(=18) = 27
    assert score_session(commands) == 27


def test_dominant_stage_is_last_reached():
    # recon then credential_access; dominant stage = credential_access (base 30).
    # 'mimikatz' is a clean credential_access-only pattern (avoids the verbatim
    # substring collisions, e.g. recon's bare 'w' matching 'cat /etc/shado-w-').
    commands = ["whoami", "mimikatz"]
    mapping = map_techniques(commands)
    assert mapping["dominant_stage"] == "credential_access"
    base = DANGER_SCORES["credential_access"]
    distinct = len(mapping["techniques_used"])
    assert score_session(commands) == min(base + 2 * 2 + distinct * 3, 100)


def test_substring_matching_is_crude_documented_behavior():
    # Faithful to the original: recon's bare 'w' pattern matches 'shadow' as a
    # substring, so 'cat /etc/shadow' classifies as reconnaissance, not
    # credential_access. Documented caveat, preserved verbatim.
    assert classify_command("cat /etc/shadow")["stage"] == "reconnaissance"


def test_score_capped_at_100():
    # Many impact commands -> base 40, lots of commands, should cap at 100.
    commands = ["rm -rf /"] * 50
    assert score_session(commands) == 100


def test_unknown_command_uses_default_base():
    # A command that matches nothing in the table -> stage unknown, base 5.
    commands = ["thisisnotacommand foo bar"]
    mapping = map_techniques(commands)
    assert mapping["dominant_stage"] == "unknown"
    # base 5 + 1*2 + 0 techniques = 7
    assert score_session(commands) == 7
