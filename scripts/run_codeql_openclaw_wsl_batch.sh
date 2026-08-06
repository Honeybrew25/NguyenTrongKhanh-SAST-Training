#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
SCAN_ID="codeql-full-security-extended-wsl-v1-20260806"
PLAN_PATH="$PROJECT_ROOT/artifacts/manifests/$SCAN_ID-openclaw-heavy.json"
LOG_DIR="$PROJECT_ROOT/artifacts/logs"
LOG_PATH="$LOG_DIR/codeql-wsl-openclaw-heavy.log"

mkdir -p "$LOG_DIR"
export PYTHONUNBUFFERED=1

{
  echo "=== OpenClaw CodeQL batch start: $(date --iso-8601=seconds) ==="
  echo "Plan: $PLAN_PATH"
  echo "Resources: sequential jobs; analyze_threads=1; analyze_ram_mb=12288"

  exec "$SCRIPT_DIR/run_codeql_wsl.sh" \
    --repo-url "https://github.com/openclaw/openclaw" \
    --plan-output "$PLAN_PATH" \
    --runtime-analyze-threads 1 \
    --runtime-analyze-ram-mb 12288 \
    --retry-failed
} >>"$LOG_PATH" 2>&1
