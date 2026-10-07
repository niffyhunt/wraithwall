#!/usr/bin/env bash
# WraithWall Local Secure Sandbox wrapper (Phase 2).
# Delegates to the sandbox_kit CLI with the repo's Python.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$DIR/venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"
exec "$PY" -m sandbox_kit --name "${WRAITHWALL_SANDBOX_NAME:-default}" "$@"
