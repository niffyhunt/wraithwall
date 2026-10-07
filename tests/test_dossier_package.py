"""Shipped dossier modules must stand alone.

The published package has no monolith ``main`` module and no WraithWall
server filesystem layout. These tests fail if a dossier module regresses to
either, or if its auth path stops going through ``wraithwall.host_auth``.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

_PKG_DIR = Path(__file__).resolve().parents[1] / "src" / "wraithwall"


def _campaign(cid="aaaaaaaaaaaaaaaa", tenant="user:1"):
    return {
        "campaign_id": cid,
        "tenant_id": tenant,
        "status": "active",
        "threat_level": "medium",
        "first_seen": "2026-09-01T00:00:00",
        "last_seen": "2026-09-01T01:00:00",
        "session_count": 2,
        "unique_ips": ["203.0.113.9"],
        "sensors_hit": ["honeypot.internal"],
        "session_ids": ["sess-a"],
        "tools": ["nmap"],
        "tool_signatures": {"nmap": 0.9},
        "tool_sequence": ["nmap"],
        "command_pattern_hash": "abcdabcdabcdabcd",
        "human_confidence": None,
        "session_pacing": "unknown",
        "campaign_confidence": 0.7,
        "correlation_evidence": [
            {"session_id": "sess-b", "score": 0.8, "confidence": 0.5,
             "dims": {}, "evidence": [], "ts": "t"}
        ],
        "mitre_techniques": [],
        "mitre_stages": [],
        "asns": [64496],
        "countries": ["US"],
        "actor_uuids": [],
        "deception_events": 0,
        "representative_fingerprint": {
            "normalized_commands": ["uname"],
            "src_ip": "203.0.113.9",
            "feature_vector": [0.0],
        },
    }


def test_dossier_modules_import_without_a_monolith_main():
    """Import succeeds and needs nothing from a WraithWall checkout."""
    from wraithwall import dossier_auth, dossier_contract, dossier_packet, dossier_pipeline  # noqa: F401

    assert dossier_auth.sanitize_campaign_id("aaaaaaaaaaaaaaaa") == "aaaaaaaaaaaaaaaa"
    assert dossier_auth.sanitize_campaign_id("../etc/passwd") is None
    assert dossier_contract.campaign_to_dossier(_campaign())["schema_version"] == "1"
    assert dossier_pipeline._installed is False


def test_no_server_paths_or_monolith_imports_ship():
    """A published module must not reference /home/deploy or import main."""
    offenders = []
    for path in sorted(_PKG_DIR.glob("dossier*.py")):
        text = path.read_text()
        if "/home/deploy" in text:
            offenders.append(f"{path.name}: hardcoded server path")
        if re.search(r"^\s*from main import ", text, re.M):
            offenders.append(f"{path.name}: imports monolith main")
    assert offenders == []


def test_principal_tenant_is_loud_when_auth_is_unbound(monkeypatch):
    from wraithwall import dossier_auth, host_auth

    monkeypatch.setattr(host_auth, "_bound", {})
    with pytest.raises(RuntimeError, match="host_auth.bind"):
        dossier_auth.principal_tenant()


def test_principal_tenant_returns_tenant_when_bound(monkeypatch):
    from wraithwall import dossier_auth, host_auth

    monkeypatch.setattr(host_auth, "_bound", {
        "is_logged_in": lambda: True,
        "verify_api_signature": lambda: (True, object()),
        "auth_context": lambda: ("user:7", "operator@example.com"),
    })
    tenant, err = dossier_auth.principal_tenant()
    assert err is None
    assert tenant == "user:7"


def test_principal_tenant_401_without_session_or_bearer(monkeypatch):
    from flask import Flask

    from wraithwall import dossier_auth, host_auth

    monkeypatch.setattr(host_auth, "_bound", {
        "is_logged_in": lambda: False,
        "verify_api_signature": lambda: (False, "no key"),
        "auth_context": lambda: (None, None),
    })
    with Flask(__name__).test_request_context("/"):
        tenant, err = dossier_auth.principal_tenant()
    assert tenant is None
    assert err == 401


def test_packet_builds_and_validates_from_the_shipped_schema():
    import wraithwall

    from wraithwall import dossier_packet

    assert dossier_packet.SCHEMA_PATH.is_file()
    assert dossier_packet.SCHEMA_PATH.parent == Path(wraithwall.__file__).parent
    pkt = dossier_packet.packet_from_campaign(_campaign())
    dossier_packet.validate_packet(pkt)
    blob = dossier_packet.dumps(pkt)
    assert b'"schema_version"' in blob
    assert b"203.0.113.9" not in blob
    assert b"unique_ips" not in blob


def test_pipeline_loads_campaigns_through_the_package_correlator(monkeypatch):
    """on_campaign_event must reach wraithwall.campaign_correlator — a bare
    monolith-root import used to fail silently inside its try/except."""
    from wraithwall import dossier_pipeline

    class FakeRedis:
        def scan_iter(self, match=None, count=None):
            # campaign not found under the payload tenant: the pipeline falls
            # back to scanning active campaign keys (tenant extraction must
            # work too — a NameError there used to be swallowed by the try).
            yield b"active_campaigns:user:9"

    class FakeCorrelator:
        redis = FakeRedis()

        def __init__(self):
            self.calls = []

        def _get_campaign(self, cid, tenant):
            self.calls.append((cid, tenant))
            return None  # unknown campaign: pipeline returns before any write

    fake = FakeCorrelator()
    monkeypatch.setattr(
        "wraithwall.campaign_correlator.get_correlator", lambda: fake
    )
    dossier_pipeline.on_campaign_event(
        "campaign.created", {"campaign_id": "aaaaaaaaaaaaaaaa", "tenant_id": "user:1"}
    )
    assert fake.calls == [
        ("aaaaaaaaaaaaaaaa", "user:1"),
        ("aaaaaaaaaaaaaaaa", "user:9"),
    ]
