"""Decision trace — records *why* every phase and plugin ran (R-02).

Hermes principle adapted as Raven form: tool-selection explanations +
versioned rulesets/templates as consistency controls. Every trace field is
derived from structured engine/config state; repository free text never
sources a trace field (test plan deliverable 10 §R-02 — "trace fields never
sourced from free text").
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from raven.core.versions import RULESET_VERSION, TEMPLATE_VERSION


def input_fingerprint(payload: Any) -> str:
    """Stable hash of the structured input a decision was based on."""
    blob = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


class DecisionTrace:
    """Accumulates phase/plugin decisions with reasons and input fingerprints."""

    def __init__(self) -> None:
        self.decisions: list[dict[str, str]] = []
        self.version_change: dict[str, dict[str, str]] = {}

    @property
    def versions(self) -> dict[str, str]:
        return {"ruleset": RULESET_VERSION, "template": TEMPLATE_VERSION}

    def add(self, phase: str, decision: str, reason: str, payload: Any = None) -> None:
        """Record one decision. Reasons are fixed phrasing + structured values."""
        self.decisions.append({
            "phase": phase,
            "decision": decision,
            "reason": reason,
            "input_fingerprint": input_fingerprint(payload if payload is not None else {"d": decision}),
        })

    def note_version_change(self, previous: dict[str, str | None] | None) -> dict[str, dict[str, str]]:
        """Compare stamped versions against the previous scan; keep differences."""
        current = self.versions
        change: dict[str, dict[str, str]] = {}
        for key in ("ruleset", "template"):
            was = (previous or {}).get(key)
            if was and was != current[key]:
                change[key] = {"was": str(was), "now": current[key]}
        self.version_change = change
        return change

    def to_dict(self) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "schema": "decision_trace/1",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "versions": self.versions,
            "decisions": self.decisions,
        }
        if self.version_change:
            doc["version_change"] = self.version_change
        return doc

    def write(self, path: Path) -> Path:
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path
