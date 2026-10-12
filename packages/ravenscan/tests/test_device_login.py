"""CLI half of the device-login flow (raven login/logout + credential store).

Gates:
- credentials file written 0600 and refused when group/world readable
- env vars take precedence over the stored file
- device_login validates the verification URL against the HTTPS allowlist
- denial/expiry/timeout surface as errors, never as silent success
- secret is never written to stdout
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from raven.wraithwall.login import (
    DeviceLoginError,
    credentials_path,
    device_login,
    load_credentials,
    logout,
    save_credentials,
)


# --- credential store --------------------------------------------------------

def test_save_and_load_roundtrip(tmp_path):
    target = tmp_path / "credentials.json"
    creds = {"api_key": "ezm_abc", "secret": "s3cret", "tenant_id": "user:1", "url": "https://wraithwall.online"}
    save_credentials(creds, target)
    assert oct(target.stat().st_mode & 0o777) == "0o600"
    assert load_credentials(target) == creds


def test_load_missing_returns_none(tmp_path):
    assert load_credentials(tmp_path / "nope.json") is None


def test_load_refuses_world_readable(tmp_path):
    target = tmp_path / "credentials.json"
    target.write_text(json.dumps({"api_key": "a", "secret": "b", "tenant_id": "c"}))
    os.chmod(target, 0o644)
    with pytest.raises(DeviceLoginError, match="group/world readable"):
        load_credentials(target)


def test_load_refuses_malformed(tmp_path):
    target = tmp_path / "credentials.json"
    target.write_text(json.dumps({"api_key": ""}))
    os.chmod(target, 0o600)
    with pytest.raises(DeviceLoginError, match="malformed"):
        load_credentials(target)


def test_logout_removes_and_reports(tmp_path):
    target = tmp_path / "credentials.json"
    save_credentials({"api_key": "a", "secret": "b", "tenant_id": "c"}, target)
    assert logout(target) is True
    assert not target.exists()
    assert logout(target) is False


# --- device_login flow (mocked transport) ------------------------------------

class _FakeResp:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("http error")

    def json(self):
        return self._payload


def _login(monkeypatch, responses, *, allowed_hosts="wraithwall.online"):
    """Drive device_login against a scripted sequence of token polls."""
    import requests as _requests
    calls = {"post": []}
    seq = list(responses)

    def fake_post(url, **kwargs):
        calls["post"].append((url, kwargs.get("json")))
        if url.endswith("/api/device/code"):
            return seq[0]
        return seq.pop(1)

    monkeypatch.setattr(_requests, "post", fake_post)
    monkeypatch.setenv("WRAITHWALL_ALLOWED_HOSTS", allowed_hosts)
    seen = []
    creds = device_login(
        "https://wraithwall.online",
        open_browser=lambda u: seen.append(u),
        sleep=lambda s: None,
        stdout=lambda m: None,
        timeout_total=30,
    )
    return creds, calls, seen


ISSUE = _FakeResp(200, {
    "device_code": "dc-256bit",
    "user_code": "ABCD-EFGH",
    "verification_uri": "https://wraithwall.online/device",
    "verification_uri_complete": "https://wraithwall.online/device?user_code=ABCD-EFGH",
    "interval": 2,
    "expires_in": 600,
})


def test_login_happy_path(monkeypatch):
    grant = _FakeResp(200, {"ok": True, "api_key": "ezm_k", "secret": "shh", "tenant_id": "user:7"})
    creds, calls, seen = _login(monkeypatch, [ISSUE, grant])
    assert creds["api_key"] == "ezm_k" and creds["tenant_id"] == "user:7"
    assert any(u.endswith("user_code=ABCD-EFGH") for u in seen), "browser receives the complete URL"


def test_login_polls_through_pending(monkeypatch):
    pending = _FakeResp(400, {"error": "authorization_pending"})
    grant = _FakeResp(200, {"ok": True, "api_key": "ezm_k", "secret": "shh", "tenant_id": "user:7"})
    creds, calls, _ = _login(monkeypatch, [ISSUE, pending, pending, grant])
    polls = [c for c in calls["post"] if c[0].endswith("/api/device/token")]
    assert len(polls) == 3, "must keep polling through authorization_pending"


def test_login_denied_raises(monkeypatch):
    denied = _FakeResp(400, {"error": "access_denied"})
    with pytest.raises(DeviceLoginError, match="denied"):
        _login(monkeypatch, [ISSUE, denied])


def test_login_expired_raises(monkeypatch):
    expired = _FakeResp(400, {"error": "expired_token"})
    with pytest.raises(DeviceLoginError, match="expired|consumed"):
        _login(monkeypatch, [ISSUE, expired])


def test_login_key_cap_raises(monkeypatch):
    capped = _FakeResp(403, {"error": "key_cap_reached"})
    with pytest.raises(DeviceLoginError, match="cap"):
        _login(monkeypatch, [ISSUE, capped])


def test_login_rejects_non_allowlisted_verification_url(monkeypatch):
    bad_issue = _FakeResp(200, {
        "device_code": "dc", "user_code": "ABCD-EFGH",
        "verification_uri": "https://evil.example.com/device",
        "verification_uri_complete": "https://evil.example.com/device?user_code=X",
        "interval": 2, "expires_in": 600,
    })
    with pytest.raises(DeviceLoginError, match="allowlist"):
        _login(monkeypatch, [bad_issue])


def test_login_rejects_http_base_url(monkeypatch):
    with pytest.raises(DeviceLoginError, match="HTTPS"):
        device_login("http://wraithwall.online", sleep=lambda s: None, stdout=lambda m: None)


def test_login_never_prints_secret(monkeypatch, capsys):
    import requests as _requests
    grant = _FakeResp(200, {"ok": True, "api_key": "ezm_k", "secret": "TOPSECRET-VALUE", "tenant_id": "user:7"})
    printed = []
    monkeypatch.setattr(_requests, "post", lambda url, **kw: ISSUE if url.endswith("/api/device/code") else grant)
    monkeypatch.setenv("WRAITHWALL_ALLOWED_HOSTS", "wraithwall.online")
    device_login("https://wraithwall.online", sleep=lambda s: None, stdout=printed.append)
    joined = " ".join(printed)
    assert "TOPSECRET-VALUE" not in joined, "secret must never reach stdout"


# --- client credential fallback ----------------------------------------------

def test_client_env_beats_stored_file(tmp_path, monkeypatch):
    from raven.wraithwall.client import WraithWallIntelClient
    monkeypatch.setenv("RAVEN_HOME", str(tmp_path))
    save_credentials({"api_key": "from-file", "secret": "file-secret", "tenant_id": "user:file"}, tmp_path / "credentials.json")
    monkeypatch.setenv("WRAITH_API_KEY", "from-env")
    monkeypatch.setenv("WRAITH_API_SECRET", "env-secret")
    monkeypatch.setenv("WRAITH_TENANT_ID", "user:env")
    client = WraithWallIntelClient()
    assert client.api_key == "from-env" and client.expected_tenant == "user:env"


def test_client_falls_back_to_stored_file(tmp_path, monkeypatch):
    from raven.wraithwall.client import WraithWallIntelClient
    monkeypatch.setenv("RAVEN_HOME", str(tmp_path))
    monkeypatch.delenv("WRAITH_API_KEY", raising=False)
    monkeypatch.delenv("WRAITH_API_SECRET", raising=False)
    monkeypatch.delenv("WRAITH_TENANT_ID", raising=False)
    save_credentials({"api_key": "from-file", "secret": "file-secret", "tenant_id": "user:file"}, tmp_path / "credentials.json")
    client = WraithWallIntelClient()
    assert client.api_key == "from-file"
    assert client.expected_tenant == "user:file"


def test_client_refuses_world_readable_store(tmp_path, monkeypatch):
    from raven.wraithwall.client import WraithWallIntelClient, WraithWallIntelError
    monkeypatch.setenv("RAVEN_HOME", str(tmp_path))
    target = tmp_path / "credentials.json"
    save_credentials({"api_key": "a", "secret": "b", "tenant_id": "user:1"}, target)
    os.chmod(target, 0o644)
    with pytest.raises(WraithWallIntelError, match="readable"):
        WraithWallIntelClient()


def test_client_rejects_malformed_tenant_from_file(tmp_path, monkeypatch):
    from raven.wraithwall.client import WraithWallIntelClient, WraithWallIntelError
    monkeypatch.setenv("RAVEN_HOME", str(tmp_path))
    monkeypatch.delenv("WRAITH_TENANT_ID", raising=False)
    monkeypatch.delenv("WRAITH_API_KEY", raising=False)
    monkeypatch.delenv("WRAITH_API_SECRET", raising=False)
    save_credentials({"api_key": "a", "secret": "b", "tenant_id": "bad tenant !!"}, tmp_path / "credentials.json")
    with pytest.raises(WraithWallIntelError, match="tenant"):
        WraithWallIntelClient()
