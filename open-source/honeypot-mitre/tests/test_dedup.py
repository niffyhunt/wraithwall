"""Tests for the dedup key and in-memory dedup store."""

from __future__ import annotations

from honeypot_mitre import InMemoryDedupStore, dedup_key


def test_dedup_key_is_order_independent():
    a = ["uname -a", "whoami", "cat /etc/shadow"]
    b = ["cat /etc/shadow", "uname -a", "whoami"]
    assert dedup_key(a) == dedup_key(b)


def test_dedup_key_is_16_hex_chars():
    key = dedup_key(["whoami"])
    assert len(key) == 16
    int(key, 16)  # raises if not hex


def test_different_payloads_differ():
    assert dedup_key(["whoami"]) != dedup_key(["rm -rf /"])


def test_store_first_occurrence_then_dedup():
    store = InMemoryDedupStore(window=900)
    sig = dedup_key(["whoami", "uname -a"])
    assert store.register(sig, "203.0.113.1") is True   # first -> alert
    assert store.register(sig, "203.0.113.2") is False  # duplicate -> suppress
    assert store.source_ips(sig) == {"203.0.113.1", "203.0.113.2"}


def test_store_expiry_resets_window():
    store = InMemoryDedupStore(window=0)  # everything immediately expired
    sig = dedup_key(["whoami"])
    assert store.register(sig, "203.0.113.1") is True
    # window=0 means the prior entry is already expired -> treated as new again.
    assert store.register(sig, "203.0.113.2") is True
