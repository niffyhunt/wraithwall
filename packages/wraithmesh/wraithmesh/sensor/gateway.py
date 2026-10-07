"""Gateway / fingerprint JSONL inbox sensor."""

from __future__ import annotations

import hashlib
from typing import Any, Optional

from ..models import Observation
from .inbox import JsonlInboxSensor

GATEWAY_TECHNIQUES = ["T1071.001"]


def gateway_equivalence_key(fingerprint: str) -> str:
    """Derive a privacy-safe equivalence key from a request fingerprint hash."""
    return hashlib.sha256(fingerprint.encode()).hexdigest()[:16]


class GatewayInboxSensor(JsonlInboxSensor):
    """Watch a JSONL inbox fed by gateway/fingerprint hooks."""

    offset_name = "gateway.offset"

    def _default_inbox_path(self) -> str:
        return self.manifest.gateway_inbox_path

    def process_event(self, event: dict[str, Any]) -> Optional[Observation]:
        eq = (event.get("equivalence_key") or "").strip()
        if not eq:
            fp = (event.get("fingerprint_hash") or event.get("fingerprint") or "").strip()
            if not fp:
                return None
            eq = gateway_equivalence_key(fp)
        if len(eq) != 16:
            return None

        techniques = sorted(set(event.get("technique_set") or GATEWAY_TECHNIQUES))
        confidence = float(event.get("confidence") or 0.75)
        now = event.get("timestamp") or ""

        rollup = self.store.record(
            equivalence_key=eq,
            technique_set=techniques,
            confidence=confidence,
            first_seen=now,
            last_seen=now,
        )
        cooldown = int(self.manifest.thresholds.get("uplink_cooldown_seconds", 86400))
        min_count = int(self.manifest.thresholds.get("min_local_count", 1))
        if not self.store.should_uplink(eq, cooldown, min_count):
            return None

        epoch = self.store.bump_epoch()
        obs = Observation(
            equivalence_key=eq,
            technique_set=techniques,
            sensor_class="gateway",
            confidence=rollup.confidence,
            seen_count=rollup.seen_count,
            node_id=self.manifest.node_id,
            epoch=epoch,
            first_seen=rollup.first_seen,
            last_seen=rollup.last_seen,
        )
        obs.sign(self._key)
        self.store.mark_uplinked(eq)
        return obs