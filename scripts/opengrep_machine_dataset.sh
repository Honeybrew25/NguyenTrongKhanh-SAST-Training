#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON_BIN="${PYTHON_BIN:-.venv-wsl/bin/python}"
REVIEW_DIR="${REVIEW_DIR:-artifacts/llm-review/opengrep-representative-openai-luna-r20-20260814}"
DATASET="data/enriched/opengrep-machine-reviewed-r1.jsonl"
RELEASE="data/releases/opengrep-machine-reviewed-r1-20260814.json"
SPLIT_DIR="data/splits/opengrep-machine-benchmark-r1-20260814"
RUN_DIR="artifacts/baselines/opengrep-machine-benchmark-r1-20260814"
METRICS_DIR="$SPLIT_DIR"
MODEL="${BASELINE_MODEL:-gpt-5.6-luna}"
ACTION="${1:-status}"

build_dataset() {
  "$PYTHON_BIN" -m vulngym_enrich.machine_dataset build \
    --review-dir "$REVIEW_DIR" \
    --entries benchmark/VulnGym/data/entries.jsonl \
    --dataset "$DATASET" \
    --manifest "$RELEASE" \
    --created-at 2026-08-14T18:30:00+07:00
  "$PYTHON_BIN" -m vulngym_enrich.machine_dataset split \
    --dataset "$DATASET" \
    --manifest "$RELEASE" \
    --output-dir "$SPLIT_DIR" \
    --seed opengrep-machine-benchmark-r1-20260814 \
    --created-at 2026-08-14T18:35:00+07:00
  "$PYTHON_BIN" -m vulngym_enrich.machine_dataset raw-baseline \
    --split "$SPLIT_DIR/test.jsonl" \
    --output "$SPLIT_DIR/raw-opengrep-predictions.jsonl"
  "$PYTHON_BIN" -m vulngym_enrich.machine_dataset prepare-agent-input \
    --review-dir "$REVIEW_DIR" \
    --split "$SPLIT_DIR/test.jsonl" \
    --output "$RUN_DIR/blind-verifier-input.jsonl"
}

run_agent() {
  local run_name="$1" profile="$2" prompt="$3"
  "$PYTHON_BIN" -m vulngym_enrich.verifier_agent \
    --input "$RUN_DIR/blind-verifier-input.jsonl" \
    --snapshot-root worktrees/opengrep-linux-lf \
    --run-dir "$RUN_DIR/$run_name" \
    --profile "$profile" \
    --prompt "$prompt" \
    --model "$MODEL" \
    --development-run
}

evaluate_all() {
  "$PYTHON_BIN" -m vulngym_enrich.machine_dataset import-agent-predictions \
    --run-predictions "$RUN_DIR/snippet-only-r2/verifier-predictions.jsonl" \
    --split "$SPLIT_DIR/test.jsonl" \
    --output "$SPLIT_DIR/snippet-only-predictions.jsonl" \
    --baseline-id "$MODEL-snippet-only"
  "$PYTHON_BIN" -m vulngym_enrich.machine_dataset import-agent-predictions \
    --run-predictions "$RUN_DIR/repository-context-run/verifier-predictions.jsonl" \
    --split "$SPLIT_DIR/test.jsonl" \
    --output "$SPLIT_DIR/repository-context-predictions.jsonl" \
    --baseline-id "$MODEL-repository-context" --navigation
  for item in \
    "raw-opengrep-accept-all:raw-opengrep-predictions.jsonl:raw-opengrep-metrics.json" \
    "$MODEL-snippet-only:snippet-only-predictions.jsonl:snippet-only-metrics.json" \
    "$MODEL-repository-context:repository-context-predictions.jsonl:repository-context-metrics.json"
  do
    IFS=: read -r baseline predictions metrics <<<"$item"
    "$PYTHON_BIN" -m vulngym_enrich.machine_dataset evaluate \
      --review-dir "$REVIEW_DIR" \
      --split "$SPLIT_DIR/test.jsonl" \
      --predictions "$SPLIT_DIR/$predictions" \
      --output "$METRICS_DIR/$metrics" \
      --baseline-id "$baseline"
  done
}

case "$ACTION" in
  build) build_dataset ;;
  snippet) run_agent snippet-only-r2 config/verifier-profile-snippet-only-v1.json config/verifier-prompt-snippet-only-v1.md ;;
  context) run_agent repository-context-run config/verifier-profile-v1.json config/verifier-prompt-v1.md ;;
  evaluate) evaluate_all ;;
  all) build_dataset; run_agent snippet-only-r2 config/verifier-profile-snippet-only-v1.json config/verifier-prompt-snippet-only-v1.md; run_agent repository-context-run config/verifier-profile-v1.json config/verifier-prompt-v1.md; evaluate_all ;;
  status)
    "$PYTHON_BIN" -m vulngym_enrich.publication_policy
    "$PYTHON_BIN" - <<'PY'
import json
from pathlib import Path
for path in (
    Path("data/releases/opengrep-machine-reviewed-r1-20260814.json"),
    Path("data/splits/opengrep-machine-benchmark-r1-20260814/split-manifest.json"),
    Path("artifacts/baselines/opengrep-machine-benchmark-r1-20260814/snippet-only-r2/verifier-run.json"),
    Path("artifacts/baselines/opengrep-machine-benchmark-r1-20260814/repository-context-run/verifier-run.json"),
):
    if not path.is_file():
        print(f"{path}: NOT_READY")
        continue
    value = json.loads(path.read_text(encoding="utf-8"))
    print(f"{path}: {value.get('status')} {value.get('case_counts', value.get('counts', value.get('gates', {})))}")
PY
    ;;
  *) echo "usage: $0 {build|snippet|context|evaluate|all|status}" >&2; exit 2 ;;
esac
