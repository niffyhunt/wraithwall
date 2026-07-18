# Open-source package inventory (v2 release prep)

**Policy:** build and sync on disk now. **Push to GitHub + PyPI only with the v2 release OK.**

Canonical toolkit tree: `open-source/`  
Mirror for platform monorepo consumers: `wraithwall-oss/packages/`

## Already on PyPI

| Package | Version | Source | Notes |
|---------|---------|--------|-------|
| `wraithwall` | 0.1.0 | `wraithwall-oss/` | Platform distribution |
| `ravenscan` | 0.1.0 | `ravenscan/` + `wraithwall-oss/packages/ravenscan/` | CLI `raven` |
| `canary-kit` | 0.1.0 | `open-source/canary-kit/` | Published |
| `honeypot-mitre` | 0.1.0 | `open-source/honeypot-mitre/` | Published |

## Remaining for v2 PyPI (ready in tree)

| Package | Version | Source | Notes |
|---------|---------|--------|-------|
| **`dml-spec`** | **0.2.0** | `open-source/dml-spec/` | Was missing on PyPI; includes mesh module |
| **`wraithmesh`** | **0.2.0** | `open-source/wraithmesh/` | Depends on `honeypot-mitre>=0.1.0`; optional `dml-spec>=0.2.0` |

## Still building (not part of first v2 toolkit upload unless approved)

| Package | Planned name | Source |
|---------|--------------|--------|
| HTTP API client (Python) | `wraithwall-sdk` | `sdks/python/` |
| HTTP API client (JS/TS) | `@wraithwall/sdk` | `sdks/javascript/` |

Do **not** publish as `wraithwall` — that name is the platform package.

## Sync rule

When toolkit code changes, update **`open-source/<pkg>` first**, then mirror:

```bash
# From repo root (example)
rsync -a --exclude '__pycache__' --exclude 'dist' --exclude 'build' --exclude '*.egg-info' \
  open-source/dml-spec/ wraithwall-oss/packages/dml-spec/
rsync -a --exclude '__pycache__' --exclude 'dist' --exclude 'build' --exclude '*.egg-info' \
  open-source/wraithmesh/ wraithwall-oss/packages/wraithmesh/
```

## Publish (v2 only — do not run until release OK)

```bash
cd open-source
./publish.sh list                 # inventory
./publish.sh testpypi             # dry-run index: dml-spec + wraithmesh
# after approval:
# ./publish.sh pypi
```

## GitHub targets (when v2 ships)

| Artifact | Likely remote |
|----------|----------------|
| Toolkit packages | `niffyhunt/wraithwall-toolkit` (see package Repository URLs) |
| Platform / monorepo | `niffyhunt/wraithwall` |
| Raven | already published as `ravenscan` |

Exact remotes may be adjusted at release time — packages already declare Repository URLs in `pyproject.toml`.
