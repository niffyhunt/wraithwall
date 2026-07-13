"""Core tests: minting determinism, registration, beacon match/no-match."""

from __future__ import annotations

from canary_kit import (
    CanaryRegistry,
    CanaryToken,
    InMemoryStore,
    decode_watermark,
    derive_token,
    encode_watermark,
    mint_token,
)


def test_mint_determinism_with_salt():
    # Same package/version/salt -> identical token; missing salt -> unique.
    a = mint_token("pkg", "1.0.0", salt="fixedsalt")
    b = mint_token("pkg", "1.0.0", salt="fixedsalt")
    assert a == b == derive_token("pkg", "1.0.0", "fixedsalt")
    assert len(a) == 24 and all(c in "0123456789abcdef" for c in a)
    assert mint_token("pkg", "1.0.0") != mint_token("pkg", "1.0.0")


def test_watermark_round_trip():
    token = mint_token("pkg", "2.1.0", salt="s")
    wm = encode_watermark(token)
    # Watermark survives being embedded in surrounding text.
    recovered = decode_watermark("Module docstring." + wm + " rest")
    assert recovered == token[:8]
    assert decode_watermark("no watermark here") is None


def test_registration_persists_metadata():
    reg = CanaryRegistry(store=InMemoryStore())
    rec = reg.register("my-lib", "0.3.0", owner="sec-team")
    assert reg.get(rec.token) is not None
    assert rec.token in reg.list_tokens()
    fetched = reg.get(rec.token)
    assert fetched.package_name == "my-lib"
    assert fetched.extra == {"owner": "sec-team"}
    assert fetched.fired is False


def test_beacon_match_marks_fired():
    reg = CanaryRegistry(store=InMemoryStore())
    rec = reg.register("my-lib", "0.3.0")
    result = reg.detect(rec.token, ip_address="198.51.100.1", env_hash="env1", version="0.3.0")
    assert result.matched is True
    assert result.record.fired is True
    assert result.record.fire_count == 1
    assert result.record.fire_ips == ["198.51.100.1"]
    # Second hit increments.
    again = reg.detect(rec.token, ip_address="198.51.100.2")
    assert again.record.fire_count == 2
    assert again.record.fire_ips == ["198.51.100.1", "198.51.100.2"]


def test_beacon_no_match_for_unknown_token():
    reg = CanaryRegistry(store=InMemoryStore())
    reg.register("my-lib", "0.3.0")
    result = reg.detect("deadbeefdeadbeefdeadbeef", ip_address="203.0.113.5")
    assert result.matched is False
    assert result.reason == "unknown token"
    empty = reg.detect("")
    assert empty.matched is False and empty.reason == "empty token"


def test_token_dict_round_trip():
    rec = CanaryToken(token="abc123", package_name="p", version="1", extra={"k": "v"})
    assert CanaryToken.from_dict(rec.to_dict()).to_dict() == rec.to_dict()
