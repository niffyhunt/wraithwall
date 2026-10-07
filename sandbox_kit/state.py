"""Sandbox state markers (Phase 2).

State lives under `$WRAITHWALL_SANDBOX_DIR` (tests) or `~/.wraithwall-sandbox/<name>/`.
Marker file `state.json` records: profile, state, ack, created_at, gates.

Phase 2 implements the marker layer and the transitions that exist today:
UNBUILT → PREPARED (gates passed + contract recorded) and → DESTROYED.
RUNNING / STOPPED / PARTIAL become reachable in Phase 5 when compose
orchestration lands; they are declared here so the full Stage 3 state
machine has a single home from day one. We never write a state we cannot
back with reality — `up` in this release does not claim RUNNING.
"""
from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path

STATES = ("UNBUILT", "PREPARED", "RUNNING", "STOPPED", "PARTIAL", "DESTROYED")
# Reachable with the current release. Phase 3 made RUNNING/STOPPED reachable by
# actually starting containers; PARTIAL is reachable when a boot fails and is
# rolled back. Every state below is backed by something observable.
REACHABLE_NOW = ("UNBUILT", "PREPARED", "RUNNING", "STOPPED", "PARTIAL", "DESTROYED")

_NON_CLAIMS = (
    "This sandbox provides bounded local development isolation. It is NOT "
    "guaranteed malware containment, does not run hostile code, and shares "
    "the host kernel (T1). Higher-risk work needs a VM or dedicated host."
)


def root_dir() -> Path:
    base = os.environ.get("WRAITHWALL_SANDBOX_DIR")
    if base:
        return Path(base)
    return Path.home() / ".wraithwall-sandbox"


def sandbox_dir(name: str) -> Path:
    # name is a single path component; refuse traversal.
    if not name or "/" in name or "\\" in name or name.startswith("."):
        raise ValueError(f"invalid sandbox name: {name!r}")
    return root_dir() / name


def read_state(name: str) -> dict | None:
    f = sandbox_dir(name) / "state.json"
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text())
    except Exception:
        return {"state": "PARTIAL", "note": "unreadable marker file"}


def write_state(name: str, data: dict) -> Path:
    d = sandbox_dir(name)
    d.mkdir(parents=True, exist_ok=True)
    f = d / "state.json"
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
    tmp.replace(f)  # atomic marker update
    return f


def destroy(name: str) -> dict:
    """Remove a sandbox dir after recording its inventory (G8 receipt)."""
    d = sandbox_dir(name)
    receipt = {"name": name, "removed_paths": [], "already_absent": True}
    if d.exists():
        receipt["removed_paths"] = sorted(str(p.relative_to(d)) for p in d.rglob("*") if p.is_file())
        shutil.rmtree(d)
        receipt["already_absent"] = False
    receipt["verified_empty"] = not d.exists()
    return receipt


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
