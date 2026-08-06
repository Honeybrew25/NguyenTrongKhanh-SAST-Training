#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
SCAN_ID="codeql-full-security-extended-wsl-v1-20260806"
LOG_DIR="$PROJECT_ROOT/artifacts/logs"
LOG_PATH="$LOG_DIR/codeql-wsl-without-openclaw.log"

mkdir -p "$LOG_DIR"

exec "$SCRIPT_DIR/run_codeql_wsl.sh" \
  --exclude-repo-url "https://github.com/openclaw/openclaw" \
  --plan-output "$PROJECT_ROOT/artifacts/manifests/$SCAN_ID-without-openclaw.json" \
  --runtime-analyze-threads 1 \
  --runtime-analyze-ram-mb 12288 \
  --retry-failed \
  >>"$LOG_PATH" 2>&1
