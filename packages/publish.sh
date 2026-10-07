#!/usr/bin/env bash
# Publish companion packages from wraithwall-oss/packages/ (mirror of open-source/).
# Prefer ../open-source/publish.sh as the canonical entrypoint.
# Default: testpypi. Production only on approved v2 release.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
TARGET="${1:-testpypi}"
shift || true
if [[ $# -gt 0 ]]; then
  PACKAGES=("$@")
else
  PACKAGES=(dml-spec wraithmesh)
fi

if [[ "$TARGET" != "testpypi" && "$TARGET" != "pypi" ]]; then
  echo "Usage: $0 [testpypi|pypi] [package...]" >&2
  exit 1
fi

python3 -m pip install -q --upgrade pip build twine

for pkg in "${PACKAGES[@]}"; do
  echo "── $pkg ──"
  cd "$ROOT/$pkg"
  rm -rf dist build *.egg-info
  python3 -m build
  if [[ "$TARGET" == "testpypi" ]]; then
    twine upload --repository testpypi dist/*
  else
    twine upload dist/*
  fi
done
