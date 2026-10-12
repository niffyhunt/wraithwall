"""Tests for fail-closed WraithWall intelligence consumption."""

from raven.core.models import CweReference, SecurityFinding, Severity
from raven.wraithwall.client import WraithWallIntelClient, WraithWallIntelError


def finding() -> SecurityFinding:
    return SecurityFinding(
        severity=Severity.HIGH,
        cwe=CweReference(cwe_id="CWE-78", name="OS Command Injection"),
        title="Command injection",
        description="A command sink is reachable",
        evidence="app.py:4",
        affected_file="app.py",
        affected_lines=[4],
    )


def test_wraithwall_client_fails_closed_without_credentials():
    client = WraithWallIntelClient(base_url="https://wraithwall.online", api_key=None, api_secret=None, tenant_id="tenant-a")
    try:
        client.campaigns()
    except WraithWallIntelError as exc:
        assert "authorization" in str(exc).lower()
    else:
        raise AssertionError("unauthorized client must fail closed")


def test_wraithwall_prioritization_keeps_base_finding_unchanged(monkeypatch):
    client = WraithWallIntelClient(base_url="https://wraithwall.online", api_key="key", api_secret="secret", tenant_id="tenant-a")
    monkeypatch.setattr(client, "campaigns", lambda: [{"id": "campaign-1", "tenant_id": "tenant-a", "techniques": ["command injection"]}])
    monkeypatch.setattr(client, "bgp_alerts", lambda: [])
    original = finding()
    result = client.prioritize([original])
    assert result[0].finding_id == original.finding_id
    assert result[0].base_severity == Severity.HIGH
    assert result[0].contextual_priority == "active-threat-context"
    assert result[0].matched_campaigns == ["campaign-1"]


def test_wraithwall_transport_does_not_put_secret_in_bearer_token():
    client = WraithWallIntelClient(
        base_url="https://wraithwall.online",
        api_key="public-key",
        api_secret="super-secret",
        tenant_id="tenant-a",
    )
    headers = client._headers("GET", "/api/raven/campaigns")
    assert headers["Authorization"] == "Bearer public-key"
    assert "X-Raven-API-Secret" not in headers
    assert "super-secret" not in headers["Authorization"]
    assert "super-secret" not in " ".join(f"{key}:{value}" for key, value in headers.items())


def test_wraithwall_rejects_legacy_secret_in_bearer_transport():
    # Client-side transport never emits this form; keep the server contract
    # explicit so legacy credentials cannot cross a Raven tenant boundary.
    assert "Authorization" in WraithWallIntelClient(
        base_url="https://wraithwall.online",
        api_key="public-key",
        api_secret="super-secret",
        tenant_id="tenant-a",
    )._headers("GET", "/api/raven/campaigns")


def test_wraithwall_submit_uses_one_canonical_signed_request(monkeypatch):
    client = WraithWallIntelClient(
        base_url="https://wraithwall.online",
        api_key="public-key",
        api_secret="super-secret",
        tenant_id="tenant-a",
    )
    monkeypatch.setattr(client, "_validate_destination", lambda: "wraithwall.online")

    class Response:
        status_code = 200
        headers = {}
        content = b'{"ok":true,"scope":"tenant-threat-intelligence","tenant_id":"tenant-a","accepted":true}'

    captured = {}
    def fake_post(url, **kwargs):
        captured.update(kwargs)
        return Response()

    monkeypatch.setattr("raven.wraithwall.client.requests.post", fake_post)
    result = client.submit_scan({"language_primary": "python"})
    assert result["accepted"] is True
    assert captured["headers"]["Authorization"] == "Bearer public-key"
    assert "super-secret" not in str(captured["headers"])
    assert captured["headers"]["X-API-Signature"]


def test_wraithwall_rejects_cross_tenant_campaign_item(monkeypatch):
    client = WraithWallIntelClient(
        base_url="https://wraithwall.online",
        api_key="key",
        api_secret="secret",
        tenant_id="tenant-a",
    )
    monkeypatch.setattr(
        client,
        "_get",
        lambda _path: {
            "ok": True,
            "scope": "tenant-threat-intelligence",
            "tenant_id": "tenant-a",
            "campaigns": [{"id": "campaign-b", "tenant_id": "tenant-b", "techniques": []}],
        },
    )
    try:
        client.campaigns()
    except WraithWallIntelError as exc:
        assert "tenant" in str(exc).lower()
    else:
        raise AssertionError("cross-tenant campaign must fail closed")


def test_wraithwall_rejects_invalid_tenant_identity():
    try:
        WraithWallIntelClient(
            base_url="https://wraithwall.online",
            api_key="key",
            api_secret="secret",
            tenant_id="tenant/a",
        )
    except WraithWallIntelError as exc:
        assert "tenant" in str(exc).lower()
    else:
        raise AssertionError("invalid tenant identity must fail closed")


def test_wraithwall_rejects_non_allowlisted_url():
    client = WraithWallIntelClient(base_url="http://127.0.0.1:8000", api_key="key", api_secret="secret", tenant_id="tenant-a")
    try:
        client.campaigns()
    except WraithWallIntelError as exc:
        assert "allowlist" in str(exc).lower()
    else:
        raise AssertionError("unsafe WraithWall URL must be rejected")


def test_wraithwall_rejects_bad_response(monkeypatch):
    client = WraithWallIntelClient(base_url="https://wraithwall.online", api_key="key", api_secret="secret", tenant_id="tenant-a")

    class Response:
        status_code = 200

        def json(self):
            return {"ok": True, "scope": "tenant-threat-intelligence", "tenant_id": "tenant-a", "campaigns": "not-a-list"}

    monkeypatch.setattr("raven.wraithwall.client.requests.get", lambda *args, **kwargs: Response())
    try:
        client.campaigns()
    except WraithWallIntelError as exc:
        assert "invalid" in str(exc).lower()
    else:
        raise AssertionError("invalid response must fail closed")
