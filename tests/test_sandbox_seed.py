"""Phase 4 seed tests: corpus determinism/marking/hostile-strings, shipper
HMAC protocol, and the decisive one — the deterministic corpus flowing through
the REAL, unmodified CowrieIntelligencePipeline (in-process, fake Redis).

These tests encode the roadmap's Phase 4 acceptance criteria at unit level:
deterministic corpus, LOCAL marking on every record, hostile strings that stay
data (G12), HMAC auth on the ship path, and pipeline-complete event shapes.
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import pytest

from sandbox_kit.seed import corpus, shipper


# ── corpus: determinism, marking, completeness ──────────────────────────────


def test_corpus_is_deterministic_across_calls():
    a = corpus.corpus_digest()
    b = corpus.corpus_digest()
    assert a == b
    assert corpus.event_lines() == corpus.event_lines()


def test_corpus_digest_matches_written_bytes():
    lines = corpus.event_lines()
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    assert hashlib.sha256(payload).hexdigest() == corpus.corpus_digest()


def test_every_record_is_local_marked():
    for line in corpus.event_lines():
        ev = json.loads(line)
        assert ev.get("sandbox") == "LOCAL", ev
        assert ev.get("sensor") == corpus.LOCAL_SENSOR, ev


def test_source_ips_are_documentation_range():
    allowed = set(corpus.SOURCE_IPS) | {"172.18.0.10", "192.0.2.9", "192.0.2.77"}
    for line in corpus.event_lines():
        ev = json.loads(line)
        for key in ("src_ip", "dst_ip"):
            if key in ev:
                assert ev[key] in allowed, (key, ev[key])


def test_corpus_covers_all_pipeline_eventids():
    seen = {json.loads(l)["eventid"] for l in corpus.event_lines()}
    assert seen == {
        "cowrie.session.connect",
        "cowrie.login.failed",
        "cowrie.login.success",
        "cowrie.command.input",
        "cowrie.session.file_download",
        "cowrie.session.closed",
    }


def test_sessions_have_connect_first_close_last():
    for events in corpus.build_sessions():
        assert events[0]["eventid"] == "cowrie.session.connect"
        assert events[-1]["eventid"] == "cowrie.session.closed"
        sids = {e["session"] for e in events}
        assert len(sids) == 1


def test_seed_version_changes_corpus():
    v1 = corpus.corpus_digest("1")
    v2 = corpus.corpus_digest("2")
    assert v1 != v2


# ── hostile strings: data, never instructions (G12) ─────────────────────────


def test_hostile_strings_present_and_marked():
    hostile = [l for l in corpus.event_lines() if "SEED_INJECTION_TEST" in l]
    assert hostile, "no hostile command records in the corpus"
    for line in hostile:
        ev = json.loads(line)
        # The hostile string must be the *value* of a data field...
        assert ev["eventid"] == "cowrie.command.input"
        assert "SEED_INJECTION_TEST" in ev["input"]
        # ...drawn verbatim from the declared hostile corpus, never synthesized
        # by the random picker (so the corpus stays auditable)...
        assert ev["input"] in corpus.INJECTION_STRINGS
        # ...inside a normally-marked record, never a key or eventid.
        assert ev["sandbox"] == "LOCAL"
        assert "SEED_INJECTION_TEST" not in ev["eventid"]


def test_every_declared_injection_string_is_marked():
    for s in corpus.INJECTION_STRINGS:
        assert "SEED_INJECTION_TEST_" in s, s


def test_hostile_strings_survive_round_trip_as_data():
    for s in corpus.INJECTION_STRINGS:
        line = json.dumps({"input": s}, sort_keys=True, separators=(",", ":"))
        assert json.loads(line)["input"] == s


def test_no_seed_line_contains_real_looking_aws_key():
    # The canonical EXAMPLE keys are allowed (repo-canonically fake); anything
    # else that looks like an AWS access key must not appear.
    import re
    pat = re.compile(r"AKIA[0-9A-Z]{16}")
    for line in corpus.event_lines():
        for m in pat.findall(line):
            assert m == "AKIAIOSFODNN7EXAMPLE", m


# ── ttylog frames ────────────────────────────────────────────────────────────


def test_tty_frames_parse_like_cowrie_ttylogs():
    """Frame-level proof: real Cowrie <iLiiLL frames, byte-aligned, printable."""
    frames = corpus.tty_frames()
    assert len(frames) == len(corpus.build_sessions())
    sid, blob = frames[0]
    assert len(sid) == 16
    hdr = struct.Struct("<iLiiLL")
    off = 0
    count = 0
    while off < len(blob):
        op, _tty, ln, direction, _sec, _usec = hdr.unpack(blob[off:off + hdr.size])
        assert 0 <= ln <= 1024 * 1024
        assert op in (1, 3)
        assert direction in (1, 2, 3)
        if op == 3:  # write frames always carry payload; open frames do not
            assert ln > 0
        data = blob[off + hdr.size:off + hdr.size + ln]
        assert len(data) == ln
        if ln:
            assert data.decode("utf-8")  # printable, utf-8
        off += hdr.size + ln
        count += 1
    assert off == len(blob)  # no trailing bytes: frames tile the file exactly
    assert count >= 2


def test_tty_frames_round_trip_through_the_production_parser(tmp_path: Path):
    """The decisive one: what the seed writes is what the app's replay parser
    reads. Guards the format contract from both sides at once — a fiction
    invented by either side fails here instead of at replay time."""
    from wraithwall.replay_tty import parse_ttylog

    frames = corpus.tty_frames()
    for idx, (sid, blob) in enumerate(frames[:6]):
        path = tmp_path / f"{sid}.ttylog"
        path.write_bytes(blob)
        parsed = parse_ttylog(str(path))
        assert parsed, f"no replay frames parsed for {sid}"
        script = set(corpus._TTY_SCRIPTS[idx % len(corpus._TTY_SCRIPTS)])
        for _ts, text in parsed:
            assert text.strip()
            # replay yields input frames verbatim, sanitized — never raw escapes
            assert "\x1b" not in text
            assert text in script, text


def test_tty_frames_deterministic():
    a = corpus.tty_frames()
    b = corpus.tty_frames()
    assert a == b


# ── shipper: files, HMAC, receipt, determinism self-check ───────────────────


def test_write_log_files_writes_jsonl_and_tty(tmp_path: Path):
    jsonl, tty, n = shipper.write_log_files(tmp_path / "synthetic")
    raw = jsonl.read_bytes()
    assert raw.endswith(b"\n")
    assert len(raw.decode().splitlines()) == n == corpus.record_count()
    ttys = sorted(tty.glob("*"))
    assert len(ttys) == len(corpus.build_sessions())


def test_write_is_atomic_no_tmp_leftover(tmp_path: Path):
    state = tmp_path / "synthetic"
    shipper.write_log_files(state)
    leftovers = [p.name for p in state.iterdir()
                 if p.name.startswith(".synthetic") or p.name.startswith(".tty")]
    assert leftovers == []


def test_verify_written_detects_tampering(tmp_path: Path):
    jsonl, _, _ = shipper.write_log_files(tmp_path / "synthetic")
    shipper.verify_written(jsonl)  # ok
    raw = jsonl.read_bytes()
    jsonl.write_bytes(raw.replace(b"uname -a", b"uname -A", 1))
    with pytest.raises(shipper.SeedError, match="determinism violation"):
        shipper.verify_written(jsonl)


def test_ship_signature_matches_endpoint_scheme():
    body = b'{"lines":["x"]}'
    sig = shipper.ship_signature("k", body)
    import hmac as _h
    assert sig == _h.new(b"k", body, hashlib.sha256).hexdigest()


def test_ship_batches_respect_max_batch():
    calls = []

    def poster(url, key, body):
        payload = json.loads(body)
        calls.append(len(payload["lines"]))
        return 200, json.dumps({"accepted": len(payload["lines"])})

    results = shipper.ship_to_app(
        corpus.SEED_VERSION, url="http://app/api/v1/cowrie/ship", key="k",
        poster=poster, sleep=lambda s: None)
    assert calls and max(calls) <= 200
    assert sum(calls) == corpus.record_count()
    assert all(r["response"]["accepted"] == r["lines"] for r in results)


def test_ship_401_is_seed_error():
    def poster(url, key, body):
        return 401, '{"error":"unauthorized"}'
    with pytest.raises(shipper.SeedError, match="401"):
        shipper.ship_to_app("1", url="http://app/ship", key="k",
                            poster=poster, sleep=lambda s: None)


def test_ship_skips_silently_when_unconfigured():
    # Absent URL/KEY is a deliberate skip, not an error: the file-tail path
    # does not depend on the protocol exercise.
    assert shipper.ship_to_app("1", url="", key="k") == []
    assert shipper.ship_to_app("1", url="http://app/ship", key="") == []


def test_ship_retries_then_gives_up():
    attempts = {"n": 0}

    def poster(url, key, body):
        attempts["n"] += 1
        return 0, "connection refused"

    with pytest.raises(shipper.SeedError, match="returned 0"):
        shipper.ship_to_app("1", url="http://app/ship", key="k",
                            poster=poster, sleep=lambda s: None)
    assert attempts["n"] > 1  # bounded retry happened


def test_receipt_records_provenance(tmp_path: Path):
    state = tmp_path / "synthetic"
    jsonl, tty, n = shipper.write_log_files(state)
    receipt = shipper.write_receipt(
        state, jsonl, tty, n, [], "1", tmp_path / "receipt.json")
    assert receipt["marking"] == "LOCAL"
    assert receipt["corpus_sha256"] == corpus.corpus_digest("1")
    assert receipt["events"] == n
    on_disk = json.loads((tmp_path / "receipt.json").read_text())
    assert on_disk["seed_version"] == "1"


def test_run_once_end_to_end(tmp_path: Path):
    receipt = shipper.run_once(tmp_path / "synthetic",
                               receipt_path=tmp_path / "r.json")
    assert receipt["events"] == corpus.record_count()
    assert (tmp_path / "synthetic" / "synthetic.jsonl").exists()
    assert (tmp_path / "r.json").exists()


# ── THE decisive test: real pipeline, unmodified, over the corpus ───────────


class FakeRedis:
    """Minimal redis client mirroring the operations the pipeline uses."""

    def __init__(self):
        self.kv = {}
        self.lists = {}
        self.sets = {}
        self.hashes = {}
        self.counters = {}

    # string ops
    def get(self, k):
        v = self.kv.get(k)
        return v

    def set(self, k, v, ex=None, nx=False):
        if nx and k in self.kv:
            return False
        self.kv[k] = v
        return True

    def setex(self, k, ttl, v):
        self.kv[k] = v

    def setnx(self, k, v):
        if k in self.kv:
            return False
        self.kv[k] = v
        return True

    def delete(self, *keys):
        n = 0
        for k in keys:
            if k in self.kv:
                del self.kv[k]
                n += 1
        return n

    def incr(self, k):
        self.counters[k] = self.counters.get(k, 0) + 1
        return self.counters[k]

    def hincrby(self, h, f, amount=1):
        self.hashes.setdefault(h, {})
        cur = int(self.hashes[h].get(f, 0)) + amount
        self.hashes[h][f] = str(cur)
        return cur

    def hget(self, h, f):
        return self.hashes.get(h, {}).get(f)

    def hset(self, h, f, v):
        self.hashes.setdefault(h, {})[f] = v
        return 1

    def expire(self, k, ttl):
        return True

    # list/set ops
    def lpush(self, k, *vals):
        self.lists.setdefault(k, [])
        self.lists[k] = list(vals) + self.lists[k]

    def rpush(self, k, *vals):
        self.lists.setdefault(k, [])
        self.lists[k] = self.lists[k] + list(vals)

    def llen(self, k):
        return len(self.lists.get(k, []))

    def ltrim(self, k, start, end):
        return True

    def lrange(self, k, start, end):
        return self.lists.get(k, [])[start:end + 1 if end != -1 else None]

    def sadd(self, k, *vals):
        self.sets.setdefault(k, set()).update(vals)

    def ping(self):
        return True


@pytest.fixture()
def pipeline(monkeypatch):
    """The REAL pipeline, unmodified, with only redis + LLM + bus patched at
    its boundaries (no network, no external services)."""
    import wraithwall.cowrie_intelligence as ci

    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setattr(ci.CowrieIntelligencePipeline, "_connect_redis",
                        lambda self: FakeRedis())
    monkeypatch.setattr(ci, "GROQ_API_KEY", "", raising=False)
    pipe = ci.CowrieIntelligencePipeline()
    bus_calls = []
    import wraithwall.deception_event_bus as bus
    monkeypatch.setattr(bus, "publish_deception_event",
                        lambda *a, **k: bus_calls.append((a, k)) or None)
    return pipe, bus_calls


def test_corpus_flows_through_real_pipeline_end_to_end(pipeline):
    pipe, bus_calls = pipeline
    lines = corpus.event_lines()
    assert lines  # sanity

    for line in lines:
        ev = json.loads(line)
        pipe.process_event(ev)
        pipe._handle_event(ev)  # drain synchronously (workers not started)

    recent = pipe.redis.lists.get("cowrie_sessions:recent", [])
    completed = [k for k in pipe.redis.kv if k.startswith("cowrie_completed:")]
    assert len(completed) == 24, f"expected 24 finalized sessions, got {len(completed)}"
    assert len(recent) == 24

    # Sessions carry the data the dashboards display.
    sample = json.loads(pipe.redis.kv[completed[0]])
    assert sample["src_ip"] in corpus.SOURCE_IPS
    assert sample["sensor"] == corpus.LOCAL_SENSOR
    assert sample["duration"] > 0
    assert sample["login_attempts"]
    assert "intelligence" in sample  # rule-based analysis ran (no LLM key)

    # Bait commands lit up the deception bus via the REAL handler path.
    bait_hits = [c for c in bus_calls
                 if c[0] and c[0][0] == "cowrie_honeyfs"]
    assert bait_hits, "expected HoneyFS bait hits from bait-reading sessions"

    # Session-close deception events also published (W-10 session trigger).
    close_events = [c for c in bus_calls if c[0] and c[0][0] == "cowrie_intelligence"]
    assert close_events


def test_bait_commands_map_to_real_bait_ids(pipeline):
    pipe, bus_calls = pipeline
    for events in corpus.build_sessions():
        for ev in events:
            pipe._handle_event(ev)
    bait_ids = {c[0][1] for c in bus_calls if c[0] and c[0][0] == "cowrie_honeyfs"}
    # Every published bait id must exist in the production bait map.
    from wraithwall.deception_event_bus import HONEYFS_BAIT_MAP
    valid = {v[0] for v in HONEYFS_BAIT_MAP.values()}
    assert bait_ids and bait_ids.issubset(valid)


def test_hostile_commands_reach_classification_as_data(pipeline):
    """The injection-strings session must be processed like any other: its
    strings stay command data and the session finalizes normally (G12)."""
    pipe, _ = pipeline
    hostile_lines = [l for l in corpus.event_lines() if "SEED_INJECTION_TEST" in l]
    sids = {json.loads(l)["session"] for l in hostile_lines}
    assert len(sids) == 3  # archetype plan: three hostile sessions (idx 18-20)

    for line in corpus.event_lines():
        pipe._handle_event(json.loads(line))

    for sid in sids:
        blob = pipe.redis.kv.get(f"cowrie_completed:{sid}")
        assert blob, f"hostile session {sid} did not finalize"
        session = json.loads(blob)
        assert session["sensor"] == corpus.LOCAL_SENSOR
        cmds = " ".join(session["commands"])
        assert "SEED_INJECTION_TEST" in cmds  # preserved verbatim as data
        # and never interpreted: no key/field was created from the payload
        for key in session:
            assert "SEED_INJECTION" not in key


def test_ship_endpoint_auth_end_to_end(pipeline, monkeypatch):
    """The real cowrie_ship blueprint accepts the seed's signed batches and
    rejects tampered ones (wire-protocol proof, in-process)."""
    from flask import Flask
    from wraithwall import cowrie_ship
    pipe, _ = pipeline

    key = "sandbox-test-key"
    # Point the blueprint at the same fake redis and configure its key.
    monkeypatch.setattr(cowrie_ship, "_get_redis", lambda: pipe.redis)
    monkeypatch.setattr(cowrie_ship, "COWRIE_SHIP_KEY", key)
    app = Flask(__name__)
    app.register_blueprint(cowrie_ship.cowrie_ship_bp)

    lines = corpus.event_lines()
    batch = lines[:200]
    body = json.dumps({"lines": batch}, separators=(",", ":")).encode()

    # valid signature → accepted
    client = app.test_client()
    sig = shipper.ship_signature(key, body)
    resp = client.post("/api/v1/cowrie/ship", data=body,
                       headers={"Content-Type": "application/json",
                                "X-Shipper-Signature": sig})
    assert resp.status_code == 200
    assert resp.get_json()["accepted"] == len(batch)
    assert len(pipe.redis.lists.get("cowrie:log", [])) == len(batch)

    # tampered body → 401
    tampered = body[:-1] + b" "
    resp = client.post("/api/v1/cowrie/ship", data=tampered,
                       headers={"Content-Type": "application/json",
                                "X-Shipper-Signature": sig})
    assert resp.status_code == 401

    # no key configured → 401 even with a correct signature
    monkeypatch.setattr(cowrie_ship, "COWRIE_SHIP_KEY", "")
    resp = client.post("/api/v1/cowrie/ship", data=body,
                       headers={"X-Shipper-Signature": sig})
    assert resp.status_code == 401
