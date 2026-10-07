"""WraithWall Local Secure Sandbox kit.

Named `sandbox_kit` (not `sandbox`) because a production module `sandbox.py`
already exists at the repo root and is imported by main.py — a root package
named `sandbox` would shadow it and break the app.

Modules
-------
`profiles`      profile model (app-only / local-sandbox; future pointers)
`gates`         fail-closed prerequisite gates E101–E106
`gates_static`  static compose-posture gates G1–G6, G9 (Phase 3)
`compose`       docker/compose orchestration + inspect verification (Phase 3)
`images`        pinned digests, provenance, build-context allowlist (Phase 3)
`seed/`         Phase 4 deterministic synthetic-telemetry generator
`state`         state markers and destroy receipts
`cli`           `wraithwall sandbox` command surface
"""
from sandbox_kit import (  # noqa: F401
    cli,
    compose,
    gates,
    gates_static,
    images,
    profiles,
    state,
)

__all__ = [
    "cli",
    "compose",
    "gates",
    "gates_static",
    "images",
    "profiles",
    "state",
]
