"""Optional HTTP uplink to a regional aggregator."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


def post_observations(url: str, observations: list[dict[str, Any]], *, timeout: int = 15) -> dict[str, Any]:
    payload = json.dumps({"observations": observations}).encode("utf-8")
    req = urllib.request.Request(
        url.rstrip("/") + "/v1/observations",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"aggregator HTTP {exc.code}: {body}") from exc