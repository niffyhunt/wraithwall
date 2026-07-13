#!/usr/bin/env bash
set -euo pipefail
echo "WraithWall OSS installer"
PYTHON=${PYTHON:-python3}
ROOT="$(cd "$(dirname "$0")" && pwd)"
$PYTHON -m venv "$ROOT/.venv" 2>/dev/null || true
# shellcheck disable=SC1091
[ -f "$ROOT/.venv/bin/activate" ] && source "$ROOT/.venv/bin/activate"
$PYTHON -m pip install --upgrade pip wheel
$PYTHON -m pip install "$ROOT/packages/canary-kit"
$PYTHON -m pip install "$ROOT/packages/dml-spec"
$PYTHON -m pip install "$ROOT/packages/honeypot-mitre"
$PYTHON -m pip install "$ROOT/packages/ravenscan"
$PYTHON -m pip install "$ROOT[all]"
[ ! -f "$ROOT/.env" ] && cp "$ROOT/.env.example" "$ROOT/.env" && echo "Created .env from .env.example"
echo "Done."
echo "  wraithwall check"
echo "  wraithwall serve"
echo "  docker compose up -d"