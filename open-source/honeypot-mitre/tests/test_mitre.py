"""Tests for a couple of specific MITRE technique mappings."""

from __future__ import annotations

from honeypot_mitre import classify_command
from honeypot_mitre.mitre import TECHNIQUE_CONFIDENCE


def test_authorized_keys_maps_to_persistence():
    result = classify_command("echo key >> ~/.ssh/authorized_keys")
    assert result["stage"] == "persistence"
    assert result["tactic_id"] == "TA0003"
    assert "T1098" in result["techniques"]
    assert result["matched_pattern"] == "authorized_keys"


def test_chmod_suid_maps_to_privilege_escalation():
    result = classify_command("chmod +s /usr/bin/bash")
    assert result["stage"] == "privilege_escalation"
    assert result["tactic_id"] == "TA0004"
    assert "T1548" in result["techniques"]


def test_uname_whoami_recon():
    for cmd in ("uname -a", "whoami"):
        result = classify_command(cmd)
        assert result["stage"] == "reconnaissance"
        assert "T1082" in result["techniques"]


def test_case_insensitive_match():
    assert classify_command("UNAME -A")["stage"] == "reconnaissance"


def test_confidence_is_hardcoded_constant():
    result = classify_command("whoami")
    assert result["confidence"] == TECHNIQUE_CONFIDENCE


def test_no_match_is_unknown():
    result = classify_command("xyzzy_no_such_tool")
    assert result["stage"] == "unknown"
    assert result["techniques"] == []
    assert result["confidence"] == 0.0
