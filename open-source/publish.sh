#!/usr/bin/env bash
# Publish WraithWall toolkit packages to PyPI or TestPyPI.
#
# DO NOT run against production PyPI until the v2 release is approved.
# Default target is testpypi for safety.
#
# Canonical sources for toolkit packages: this directory (open-source/).
# Mirror for monorepo distribution: ../wraithwall-oss/packages/
#
# Prerequisites (one-time):
#   1. Push to github.com/niffyhunt/wraithwall-toolkit (or agreed OSS repo)
#   2. PyPI + TestPyPI accounts with 2FA
#   3. API token: Username __token__  Password pypi-Ag...
#   4. Optional: Trusted Publisher for CI (publish.yml)
#
# Usage:
#   ./publish.sh testpypi              # safe (default)
#   ./publish.sh pypi                  # production — only on v2 release OK
#   ./publish.sh testpypi dml-spec     # single package
#   ./publish.sh list                  # show inventory
#
# Env (optional for non-interactive twine):
#   export TWINE_USERNAME=__token__
#   export TWINE_PASSWORD=pypi-Ag...
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
TARGET="${1:-testpypi}"

# Full toolkit set for v2. Order: leaf deps first, then dependents.
# Already on PyPI (skip re-upload unless version bump): canary-kit, honeypot-mitre
# Remaining first-time or bump: dml-spec, wraithmesh
ALL_PACKAGES=(canary-kit honeypot-mitre dml-spec wraithmesh)

# Published today (do not re-upload same version):
#   canary-kit 0.1.0
#   honeypot-mitre 0.1.0
# Remaining for v2:
#   dml-spec 0.2.0
#   wraithmesh 0.2.0

if [[ "$TARGET" == "list" ]]; then
  echo "Package inventory (open-source/)"
  printf '%-16s %-10s %s\n' "PACKAGE" "VERSION" "NOTES"
  for pkg in "${ALL_PACKAGES[@]}"; do
    ver=$(python3 -c "import tomllib; print(tomllib.load(open('$ROOT/$pkg/pyproject.toml','rb'))['project']['version'])")
    case "$pkg" in
      canary-kit|honeypot-mitre) note="on PyPI (bump before re-upload)" ;;
      dml-spec) note="NOT on PyPI yet — v2 publish" ;;
      wraithmesh) note="NOT on PyPI yet — v2 publish (needs honeypot-mitre)" ;;
      *) note="" ;;
    esac
    printf '%-16s %-10s %s\n' "$pkg" "$ver" "$note"
  done
  echo ""
  echo "HTTP API client (separate, still building): ../sdks/python → wraithwall-sdk"
  echo "Platform package (already on PyPI): wraithwall 0.1.0 from wraithwall-oss/"
  echo "Raven: ravenscan 0.1.0 (published)"
  exit 0
fi

if [[ "$TARGET" != "testpypi" && "$TARGET" != "pypi" ]]; then
  echo "Usage: $0 [testpypi|pypi|list] [package...]" >&2
  exit 1
fi

if [[ "$TARGET" == "pypi" ]]; then
  echo "WARNING: production PyPI. Confirm this is an approved v2 release." >&2
  echo "Press Ctrl-C within 5s to abort..." >&2
  sleep 5
fi

shift || true
if [[ $# -gt 0 ]]; then
  PACKAGES=("$@")
else
  # Default v2 remaining set (already-published same versions are skipped by twine if unchanged)
  PACKAGES=(dml-spec wraithmesh)
fi

python3 -m pip install -q --upgrade pip build twine

echo "Publishing ${PACKAGES[*]} → ${TARGET}"
for pkg in "${PACKAGES[@]}"; do
  echo ""
  echo "── $pkg ──"
  if [[ ! -d "$ROOT/$pkg" ]]; then
    echo "Missing package dir: $ROOT/$pkg" >&2
    exit 1
  fi
  cd "$ROOT/$pkg"
  rm -rf dist build *.egg-info
  python3 -m build
  if [[ "$TARGET" == "testpypi" ]]; then
    twine upload --repository testpypi dist/*
  else
    twine upload dist/*
  fi
  echo "✓ $pkg uploaded"
done

echo ""
echo "Done. Verify install:"
if [[ "$TARGET" == "testpypi" ]]; then
  echo "  pip install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ dml-spec wraithmesh"
else
  echo "  pip install canary-kit honeypot-mitre dml-spec wraithmesh"
fi
