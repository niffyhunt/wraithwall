"""Release provenance: digest manifest, SBOM generation, and the waiver
register (Phase 10).

The supply-chain story in one place:

* **Digest manifest.** `build_digest_manifest` records the *actual* image
  identity (repo digest when the daemon knows it, config digest always) per
  service, plus the pinned digest that `compose.sandbox.yml` asked for. The
  manifest lands in the sandbox state at `up` time, so every sandbox can
  prove what it runs, and in release notes at tag time.

* **SBOM.** `sbom_paths` documents where SBOM artifacts belong
  (`sbom/<version>/`), and `sbom_tool_status` reports whether a generator
  (syft) is available. Generation is opt-in and honest about absence: no
  tool, no SBOM, no pretending.

* **Waivers.** `WAIVER_REGISTER` is the single source of truth for accepted
  CRITICAL/HIGH scan findings. A finding is either waived (with reason,
  owner, and expiry — expired waivers count as unwaived) or it blocks
  release. `classify_scan_findings` implements that rule.

Everything is import-time-cheap and daemon-free so static gates and CI can
use it.
"""

from __future__ import annotations

import datetime as _dt
import re

# ── digest manifest ──────────────────────────────────────────────────────────

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def run_provenance_gate(image_rows: list[dict]) -> dict:
    """E206 — the daemon must be running exactly what compose pinned.

    Called by `up` after convergence: builds the digest manifest from live
    image inspect rows and refuses on any pin mismatch. Locally built images
    are provenance by construction (built from the allowlisted context of
    the reviewed Dockerfiles) and always match. Returns the manifest so the
    caller records it in the sandbox state.
    """
    from sandbox_kit.gates import GateFailure

    manifest = build_digest_manifest("sandbox", image_rows)
    bad = pin_mismatches(manifest)
    if bad:
        raise GateFailure("E206", [
            "✗ Running images do not match the pinned supply chain:",
            *bad,
            "  Fix:  ./sandbox.sh rebuild-images, or re-run up (the pinned",
            "        digests are resolved in sandbox_kit/images.py). If you",
            "        cannot explain the drift, treat the environment as",
            "        suspect and investigate before trusting it.",
        ])
    return manifest


def build_digest_manifest(project: str, image_rows: list[dict]) -> dict:
    """Digest manifest from rows shaped ``{"Service", "Image", "ImageID",
    "RepoDigests"}`` (assembled by ``compose.digest_rows`` via docker image
    inspect).

    For each service: what compose asks for (the image ref — a pinned digest
    for pulled images, the local tag for locally built ones), what the daemon
    actually loaded (config ImageID, plus RepoDigests when the image was
    pulled — locally built images have none, recorded honestly as None), and
    whether the loaded digest matches the pinned one.
    """
    from sandbox_kit.images import DOCKERFILES

    manifest = {"project": project, "images": {}}
    for row in image_rows:
        svc = row.get("Service") or ""
        image = row.get("Image") or ""
        image_id = (row.get("ImageID") or "").replace("sha256:", "")[:12]
        repo_digests = row.get("RepoDigests") or []
        local = image in DOCKERFILES
        repo_digest = next((rd for rd in repo_digests
                            if _DIGEST.search(rd)), None)
        pinned_ref = image if ("@sha256:" in image or local) else None
        pin_sha = image.split("@", 1)[1] if "@sha256:" in image else None
        manifest["images"][svc] = {
            "image": image,
            "image_id": image_id,
            "repo_digest": repo_digest,
            "pinned_ref": pinned_ref,
            "locally_built": local,
            "matches_pin": (bool(pin_sha and repo_digest
                                 and repo_digest.endswith(pin_sha))
                            or local),
            "dockerfile": DOCKERFILES.get(image),
        }
    return manifest


def pin_mismatches(manifest: dict) -> list[str]:
    """Services where the daemon loaded a digest other than the pinned one."""
    bad = []
    for svc, im in manifest.get("images", {}).items():
        if not im["locally_built"] and not im["matches_pin"]:
            bad.append(
                f"  • {svc}: asked for {im['pinned_ref'] or '(unpinned ref)'} "
                f"but daemon loaded {im['repo_digest'] or im['image_id'] or 'unknown'}")
    return bad


def manifest_summary(manifest: dict) -> str:
    """One-line-per-image summary for status cards and release notes."""
    lines = []
    for svc in sorted(manifest.get("images", {})):
        im = manifest["images"][svc]
        kind = "local-build" if im["locally_built"] else (im["repo_digest"] or "digest-unavailable")
        pin = f" pin={im['pinned_ref']}" if im.get("pinned_ref") else ""
        match = "" if im["locally_built"] or not im.get("pinned_ref") else (
            " ✓" if im["matches_pin"] else " ✗MISMATCH")
        lines.append(f"  {svc}: {kind}{pin}{match}")
    return "\n".join(lines) if lines else "  (no images recorded)"


# ── SBOM ─────────────────────────────────────────────────────────────────────

def sbom_dir(version: str) -> str:
    """Canonical SBOM artifact location for a release version."""
    return f"sbom/{version}"


def sbom_tool_status() -> dict:
    """Honest availability of an SBOM generator (syft) and a scanner (grype)."""
    import shutil
    return {
        "syft": shutil.which("syft"),
        "grype": shutil.which("grype"),
    }


# ── waivers (G10 release gate) ───────────────────────────────────────────────

#: Accepted findings. Rule: a CRITICAL/HIGH finding blocks release unless it
#: is listed here with a reason, an owner, and an expiry — and the expiry has
#: not passed (expired == unwaived == blocking).
WAIVER_REGISTER: list[dict] = [
    # Intentionally empty. Add entries ONLY with all four fields, e.g.:
    # {
    #     "id": "GHSA-xxxx-xxxx-xxxx",
    #     "reason": "no fixed version; sandbox egress is default-deny and the
    #                vulnerable code path is unreachable in the sandbox profile",
    #     "owner": "maintainer",
    #     "expires": "2026-12-31",   # ISO date; expired == unwaived
    # },
]


def classify_scan_findings(findings: list[dict], today: str | None = None) -> dict:
    """Split scan findings into release-blocking vs waived (fail-closed).

    Each finding: {"id": str|None, "severity": "CRITICAL"|"HIGH"|..., }.
    Blocking = CRITICAL/HIGH without a live waiver. Waived = matched a
    non-expired waiver. Everything else passes on severity alone.
    """
    today = today or _dt.date.today().isoformat()
    blocking, waived, passed = [], [], []
    for f in findings:
        sev = str(f.get("severity", "")).upper()
        fid = f.get("id")
        waiver = next((w for w in WAIVER_REGISTER
                       if w.get("id") == fid and str(w.get("expires", "0000")) >= today),
                      None)
        if sev in ("CRITICAL", "HIGH"):
            if waiver:
                waived.append({"finding": f, "waiver": waiver})
            else:
                blocking.append(f)
        else:
            passed.append(f)
    return {"blocking": blocking, "waived": waived, "passed": passed}
