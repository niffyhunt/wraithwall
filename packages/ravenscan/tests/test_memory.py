"""Tests for the memory store."""

import json
from raven.memory.store import MemoryStore


def test_memory_save_and_retrieve(tmp_path):
    db = tmp_path / "test_history.db"
    store = MemoryStore(db)

    record_id = store.save(
        profile={"language": "python"},
        score={"overall": 85.5},
        commit_sha="abc123",
        branch="main",
    )
    assert record_id > 0

    latest = store.latest()
    assert latest is not None
    assert latest.overall_score == 85.5
    assert latest.commit_sha == "abc123"
    profile_data = json.loads(latest.profile_json)
    assert profile_data["language"] == "python"


def test_memory_score_history(tmp_path):
    db = tmp_path / "test_history.db"
    store = MemoryStore(db)

    store.save(score={"overall": 80.0})
    store.save(score={"overall": 75.0})
    store.save(score={"overall": 90.0})

    history = store.score_history()
    assert len(history) == 3
    scores = [h["score"] for h in history]
    assert scores == [80.0, 75.0, 90.0]


def test_memory_all_records(tmp_path):
    db = tmp_path / "test_history.db"
    store = MemoryStore(db)

    for i in range(5):
        store.save(score={"overall": float(70 + i)})

    records = store.all()
    assert len(records) == 5


def test_memory_empty_store(tmp_path):
    db = tmp_path / "test_empty.db"
    store = MemoryStore(db)

    assert store.latest() is None
    assert store.all() == []
    assert store.score_history() == []
