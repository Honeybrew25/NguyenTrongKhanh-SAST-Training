#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
PROFILE="$PROJECT_ROOT/config/codeql-profile-wsl.json"
SCAN_ID="codeql-full-security-extended-wsl-v1-20260806"
STATE_ROOT="${VULNGYM_CODEQL_WSL_ROOT:-$HOME/.cache/vulngym-codeql-wsl-v1}"
PYTHON="$HOME/.local/share/uv/python/cpython-3.11.15-linux-x86_64-gnu/bin/python3.11"

if [[ ! -x "$PYTHON" ]]; then
  echo "Missing pinned Python runtime: $PYTHON" >&2
  exit 1
fi

mkdir -p \
  "$STATE_ROOT/databases" \
  "$STATE_ROOT/git-cache" \
  "$STATE_ROOT/worktrees"

export PYTHONPATH="$PROJECT_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

cd "$PROJECT_ROOT"
exec "$PYTHON" -m vulngym_enrich.codeql_runner \
  --profile "$PROFILE" \
  --scan-root "$PROJECT_ROOT/artifacts/scans/$SCAN_ID" \
  --database-root "$STATE_ROOT/databases" \
  --work-root "$STATE_ROOT/worktrees" \
  --checkout-cache-root "$STATE_ROOT/git-cache" \
  "$@"
