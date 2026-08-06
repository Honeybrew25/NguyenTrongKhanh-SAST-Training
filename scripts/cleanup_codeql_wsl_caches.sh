#!/usr/bin/env bash
set -euo pipefail

if pgrep -af \
  'codeql database (analyze|create)|python.*vulngym_enrich\.codeql_runner|run_codeql_wsl_batch\.sh'
then
  echo "Refusing cleanup: a CodeQL batch process is running." >&2
  exit 3
fi

CODEQL="$HOME/.local/share/codeql/2.25.5-linux64/codeql/codeql"
DB_ROOT="$HOME/.cache/vulngym-codeql-wsl-v1/databases/n8n-io__n8n"

if (($# > 0)); then
  COMMITS=("$@")
else
  COMMITS=(
    538181cbe32a92616df5e00d7ffaf4d568557f4f
    6d2e489e54d1d463dcd40e8b9c46fcd36c09f5e1
    732f2a3d3ddba59fb6e51bf2534fd33792a2cde3
    8a5d4d5746f55a2fbb1566508bccfa729a304b60
  )
fi

for commit in "${COMMITS[@]}"; do
  database="$DB_ROOT/$commit/javascript-typescript"
  if [[ ! -d "$database" ]]; then
    echo "Missing database: $database" >&2
    exit 4
  fi

  echo "=== CLEANUP $commit ==="
  "$CODEQL" database cleanup \
    --cache-cleanup=clear \
    -- "$database"
  echo "=== CLEANED $commit ==="
done
