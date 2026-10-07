"""Pinned images, provenance, and the sandbox build-context allowlist (Phase 3).

Two things live here:

1. **Pinned image digests (H10).** Base images and the probe/seed images are
   referenced by digest, never by a floating tag. Digests were resolved on
   2026-09-13 from the registry manifest lists of the tags recorded in
   `PROVENANCE`. Bumping a digest is a reviewable one-line change here plus the
   matching line in `compose.sandbox.yml`; Phase 10 adds SBOM/scan artifacts.

2. **The build-context allowlist (H12/G9).** The sandbox images are built from an
   explicit allowlist of repository paths, not from the repository root. This is
   deliberate and fail-closed: a denylist (`.dockerignore`) can silently start
   shipping a file that a future commit adds — for example a new secret. An
   allowlist cannot: a file that is not named here does not exist as far as the
   build is concerned.A second reason is practical: this repository is far larger on disk than the
   build actually needs (git history, docs, a developer's venv). A root-context
   build would stream all of it to the Docker daemon. The allowlist keeps the
   context small and auditable.
"""
from __future__ import annotations

from pathlib import Path

# ── pinned images (H10) ─────────────────────────────────────────────────────

PINNED_IMAGES = {
    # Python base for the hardened app image and the tiny seed image.
    "python:3.12-slim": (
        "python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea"
    ),
    # Telemetry bus.
    "redis:7-alpine": (
        "redis@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99"
    ),
    # Egress-deny self-check probe.
    "busybox": (
        "busybox@sha256:dc2d74b28e4cf8984fa52af1f39bc7c3d9c73760b41a74d629f5d11b1ab28616"
    ),
    # T2 research-sandbox egress proxy (Phase 11). Digest resolved from the
    # 10.4.1 tag manifest list on 2026-09-15; bumping it follows the same
    # review rule as every other pin (one line here + the compose line).
    "mitmproxy/mitmproxy:10.4.1": (
        "mitmproxy/mitmproxy@sha256:e188f884db90a15259f3a76d27d9a958e88f5781021361281f926e6cc8229882"
    ),
    # T2 research-sandbox detonation image (Phase 11). Digest resolved from
    # the local image's RepoDigests on 2026-09-15 after pulling v1.52.0-noble.
    "mcr.microsoft.com/playwright/python:v1.52.0-noble": (
        "mcr.microsoft.com/playwright/python@sha256:a1d2b48b65f41f34e5e1d7690f385f1376397b7208691cba359e4078edbf86cb"
    ),
}

PROVENANCE = {
    "python": {"source": "docker.io/library/python", "tag": "3.12-slim", "resolved": "2026-09-13"},
    "redis": {"source": "docker.io/library/redis", "tag": "7-alpine", "resolved": "2026-09-13"},
    "busybox": {"source": "docker.io/library/busybox", "tag": "latest", "resolved": "2026-09-13"},
    "mitmproxy": {"source": "docker.io/mitmproxy/mitmproxy", "tag": "10.4.1", "resolved": "2026-09-15"},
    "playwright": {"source": "mcr.microsoft.com/playwright/python", "tag": "v1.52.0-noble", "resolved": "2026-09-15"},
}

# ── locally built images ────────────────────────────────────────────────────

APP_IMAGE = "wraithwall-sandbox-app:local"
SEED_IMAGE = "wraithwall-sandbox-seed:local"
EGRESS_IMAGE = "wraithwall-sandbox-egress:local"
DETONATE_IMAGE = "wraithwall-sandbox-detonate:local"

# Dockerfile per locally built image, relative to the repository root.
DOCKERFILES = {
    APP_IMAGE: "Dockerfile.sandbox",
    SEED_IMAGE: "Dockerfile.seed",
    EGRESS_IMAGE: "Dockerfile.egress",
    DETONATE_IMAGE: "Dockerfile.detonate",
}

# ── build-context allowlist (H12 / G9) ──────────────────────────────────────

#: Repository-relative paths copied into the build context. Directory entries are
#: copied recursively. Nothing else is visible to the build.
#:
#: This list is exactly the set of paths the four sandbox Dockerfiles read:
#:
#:   requirements.txt  -> Dockerfile.sandbox (dependency layer)
#:   src/              -> Dockerfile.sandbox (the `wraithwall` package, via
#:                        PYTHONPATH=/app/src — no editable install in the image)
#:   sandbox_kit/      -> Dockerfile.seed (seed/) and Dockerfile.egress
#:                        (egress_policy/egress_proxy/policy_selftest)
#:   detonate_sandbox/ -> Dockerfile.detonate (entrypoint.sh + detonate.py)
#:
#: Templates ship inside the package (`src/wraithwall/templates`) and are
#: therefore covered by `src`; the OSS slice has no top-level `templates/` or
#: `static/` tree and no monolith import roots, so none are listed.
BUILD_CONTEXT_ALLOWLIST = (
    "requirements.txt",
    "src",
    "sandbox_kit",
    "detonate_sandbox",
)


def allowed_paths(repo_root: Path) -> list:
    """Resolve the allowlist to concrete existing paths, deterministically.

    Returns repository-relative paths sorted for stable, auditable output.
    A missing entry is simply skipped — the Dockerfiles' `COPY` is what fails
    loudly if a required file disappeared.
    """
    resolved = []
    for entry in BUILD_CONTEXT_ALLOWLIST:
        if any(ch in entry for ch in "*?["):
            resolved.extend(
                str(p.relative_to(repo_root))
                for p in sorted(repo_root.glob(entry))
                if p.is_file()
            )
        elif (repo_root / entry).exists():
            resolved.append(entry)
    return sorted(set(resolved))
