# Image & dependency updates

For maintainers and anyone auditing what the sandbox runs. The rule of this
phase: **every image identity is either a pinned digest or a local build from
a reviewed Dockerfile — and the launcher refuses to run anything else.**

## The pinning model

| Image | Kind | Identity |
|---|---|---|
| python base (app + seed images) | pinned | `python@sha256:78387b…` (resolved 2026-09-13 from the `3.12-slim` manifest list) |
| redis | pinned | `redis@sha256:6ab0b6…` (`7-alpine`) |
| busybox (egress probes) | pinned | `busybox@sha256:dc2d74…` |
| `wraithwall-sandbox-app:local` | local build | `Dockerfile.sandbox`, allowlisted context |
| `wraithwall-sandbox-seed:local` | local build | `Dockerfile.seed`, allowlisted context |

Pins live in **one place**: `sandbox_kit/images.py` (`PINNED_IMAGES`,
`PROVENANCE` — source registry, tag resolved, resolution date). There is no
`latest` anywhere in the sandbox topology; the H10 static gate refuses one at
boot and the doc gate keeps this page honest.

## The E206 provenance gate

At every `up`, after convergence, the launcher inspects what the daemon is
**actually** running (not what compose declares) and compares it to the pins:

```bash
./sandbox.sh status --json | jq .provenance   # the manifest recorded at start
```

Per service you get: the pinned ref, the daemon's image ID and repo digest,
whether they match, and the Dockerfile for local builds. A mismatch ⇒ **E206**,
rollback, nothing left running. A silently drifted image can never boot.

## Updating a pinned image (the reviewable one-line change)

1. Resolve the new digest: `docker buildx imagetools inspect <image>:<tag>`
   (manifest-list aware) or `docker pull <image>:<tag> && docker image inspect
   <image>:<tag> | jq -r '.RepoDigests[0]'`.
2. Edit `sandbox_kit/images.py`: the `PINNED_IMAGES` entry **and** the
   `PROVENANCE` resolution date.
3. Edit `compose.sandbox.yml` if the service references the digest inline.
4. `pytest tests/test_sandbox_static_gates.py tests/test_sandbox_docs.py` —
   the gates must stay green.
5. `./sandbox.sh rebuild-images && ./sandbox.sh up` — E206 now verifies the
   new pin against the daemon for real.
6. Land it as one commit; the digest bump is the reviewable unit
   (`git revert` of that commit is the rollback).

## SBOMs and scanning (G10)

```bash
./sandbox.sh sbom                 # SBOM per running image + vuln classification
./sandbox.sh sbom --out /tmp/x    # explicit destination
```

- SBOM format: **CycloneDX JSON** via syft, one file per service
  (`sbom/<version>/<service>.cdx.json` for releases, `sbom/local-<name>/`
  for ad-hoc runs).
- **No tool, no artifact**: without syft the command exits 2 and generates
  nothing — an absent SBOM is never dressed up as a pass. A missing grype is
  an honest `scan NOT run` note, never a clean verdict.
- Findings are classified against the **waiver register**
  (`sandbox_kit/provenance.py::WAIVER_REGISTER`): a CRITICAL/HIGH finding
  blocks release unless it has a waiver with a reason, an owner, and an
  unexpired date. **Expired waivers count as unwaived.** The register ships
  empty; add entries only with all fields, and expect every one to be
  challenged in review.
- CI runs the same classification in the supply-chain job (installs syft +
  grype), so a local "looks fine" cannot diverge from what release requires.

## Release checklist (sandbox releases)

1. All gates green locally: `pytest tests/test_sandbox_docs.py
   tests/test_sandbox_platform.py tests/test_sandbox_static_gates.py -q`.
2. `./sandbox.sh sbom` against a fresh boot — zero unwaived CRITICAL/HIGH.
3. Copy the per-service SBOMs to `sbom/<version>/`.
4. Tag the release (**annotated, signed**):
   `git tag -s v0.2.0-sandbox -m "sandbox v0.2.0"`; note that cosign is a
   best-effort later step (roadmap non-goal for this phase) and Docker Hub
   publishing is out of scope — images build locally, digests are the
   contract.
5. Release notes **must** embed: the digest manifest (`status --json →
   .provenance`), the SBOM file list with their sha256s, the scan summary
   (blocking/waived/passed counts), and any waiver IDs with their expiry.
6. `CHANGELOG.md` entry per the repo's existing convention.

## Dependency updates (requirements)

The app and seed images install from the repo-root `requirements.txt` inside
the pinned python base. A dependency bump is therefore: change the pin →
`rebuild-images` → `up` (E206 re-verifies) → `sbom` (G10 re-scores). The
build-context allowlist (`images.py::BUILD_CONTEXT_ALLOWLIST`) means nothing
outside the reviewed paths can ride along into the image.
