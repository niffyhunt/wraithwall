"""Tests for the two deterministic actor overrides."""

from __future__ import annotations

from honeypot_mitre import classify_actor


def test_mdrfckr_worm_signature_tags_botnet():
    commands = [
        "rm -rf .ssh",
        "echo 'ssh-rsa AAAA mdrfckr' > .ssh/authorized_keys",
    ]
    # Even with a long duration and a human-looking baseline, the worm signature wins.
    result = classify_actor(commands, duration=300, actor_label="human_operator")
    assert result["actor_label"] == "botnet_node"
    assert "outlaw_mdrfckr_worm" in result["campaign_indicators"]


def test_mdrfckr_requires_both_tokens():
    # mdrfckr present but no authorized_keys -> no worm tag.
    result = classify_actor(["echo mdrfckr"], duration=300, actor_label="human_operator")
    assert "outlaw_mdrfckr_worm" not in result["campaign_indicators"]


def test_sub_15s_session_demotes_human_to_bot():
    commands = ["uname -a", "whoami", "ls", "id", "ps aux", "netstat"]  # >5 -> baseline human
    result = classify_actor(commands, duration=3.0)
    assert result["actor_label"] == "botnet_node"


def test_slow_human_session_kept_human():
    commands = ["uname -a", "whoami", "ls", "id", "ps aux", "netstat"]
    result = classify_actor(commands, duration=120.0)
    assert result["actor_label"] == "human_operator"


def test_zero_duration_does_not_trigger_demotion():
    # The rule requires 0 < duration < 15; exactly 0 (unknown) must not demote.
    commands = ["uname -a", "whoami", "ls", "id", "ps aux", "netstat"]
    result = classify_actor(commands, duration=0)
    assert result["actor_label"] == "human_operator"
