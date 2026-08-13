#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

PYTHON_BIN="${PYTHON_BIN:-.venv-wsl/bin/python}"
SAMPLE_DIR="${SAMPLE_DIR:-artifacts/human-review/opengrep-representative-r1-20260812}"
HYBRID_DIR="${HYBRID_DIR:-artifacts/hybrid-review/opengrep-representative-r1-20260812}"
SNAPSHOT_ROOT="${SNAPSHOT_ROOT:-worktrees/opengrep-linux-lf}"
PROFILE="${PROFILE:-config/verifier-profile-v1.json}"
PROMPT="${PROMPT:-config/verifier-prompt-v3.md}"
SCHEMA="${SCHEMA:-schemas/verifier-agent-response.schema.json}"

usage() {
  printf '%s\n' \
    "Usage: bash scripts/opengrep_hybrid_review.sh <prepare|validate|reviewer-a|reviewer-b|reconcile|status>" \
    "" \
    "Required before reviewer runs:" \
    "  export REVIEWER_A_MODEL=<model-a>" \
    "  export REVIEWER_B_MODEL=<model-b>" \
    "  export EVALUATED_AGENT_MODEL=<model-being-tested>" \
    "" \
    "The two reviewer models must differ and neither may equal EVALUATED_AGENT_MODEL."
}

require_independent_models() {
  : "${REVIEWER_A_MODEL:?Set REVIEWER_A_MODEL}"
  : "${REVIEWER_B_MODEL:?Set REVIEWER_B_MODEL}"
  : "${EVALUATED_AGENT_MODEL:?Set EVALUATED_AGENT_MODEL}"
  if [[ "$REVIEWER_A_MODEL" == "$REVIEWER_B_MODEL" ]]; then
    printf 'Refusing: reviewer A and B use the same model.\n' >&2
    exit 2
  fi
  if [[ "$REVIEWER_A_MODEL" == "$EVALUATED_AGENT_MODEL" || "$REVIEWER_B_MODEL" == "$EVALUATED_AGENT_MODEL" ]]; then
    printf 'Refusing: a gold-label reviewer matches the evaluated agent model.\n' >&2
    exit 2
  fi
}

run_reviewer() {
  local reviewer="$1"
  local model="$2"
  "$PYTHON_BIN" -m vulngym_enrich.verifier_agent \
    --input "$HYBRID_DIR/blind-verifier-input.jsonl" \
    --snapshot-root "$SNAPSHOT_ROOT" \
    --run-dir "$HYBRID_DIR/reviewer-$reviewer" \
    --profile "$PROFILE" \
    --prompt "$PROMPT" \
    --response-schema "$SCHEMA" \
    --model "$model" \
    --development-run
}

status_line() {
  "$PYTHON_BIN" - "$HYBRID_DIR" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
parts = []
for reviewer in ("a", "b"):
    path = root / f"reviewer-{reviewer}" / "run-state.json"
    if not path.is_file():
        parts.append(f"reviewer-{reviewer}: NOT_STARTED")
        continue
    state = json.loads(path.read_text(encoding="utf-8"))
    counts = state.get("case_counts", {})
    parts.append(
        f"reviewer-{reviewer}: {state.get('status')} "
        f"success={counts.get('success', 0)}/{counts.get('total', 0)} "
        f"failed={counts.get('failed', 0)} running={counts.get('running', 0)}"
    )
print(" | ".join(parts))
PY
}

command="${1:-}"
case "$command" in
  prepare)
    "$PYTHON_BIN" -m vulngym_enrich.hybrid_review prepare \
      --sample-dir "$SAMPLE_DIR" \
      --snapshot-root "$SNAPSHOT_ROOT" \
      --output-dir "$HYBRID_DIR" \
      --profile "$PROFILE"
    ;;
  validate)
    "$PYTHON_BIN" -m vulngym_enrich.verifier_agent \
      --input "$HYBRID_DIR/blind-verifier-input.jsonl" \
      --snapshot-root "$SNAPSHOT_ROOT" \
      --run-dir "$HYBRID_DIR/validation-only" \
      --profile "$PROFILE" \
      --prompt "$PROMPT" \
      --response-schema "$SCHEMA" \
      --development-run \
      --validate-only
    ;;
  reviewer-a)
    require_independent_models
    run_reviewer "a" "$REVIEWER_A_MODEL"
    ;;
  reviewer-b)
    require_independent_models
    run_reviewer "b" "$REVIEWER_B_MODEL"
    ;;
  reconcile)
    "$PYTHON_BIN" -m vulngym_enrich.hybrid_review reconcile \
      --sample-dir "$SAMPLE_DIR" \
      --reviewer-a "$HYBRID_DIR/reviewer-a/verifier-predictions.jsonl" \
      --reviewer-b "$HYBRID_DIR/reviewer-b/verifier-predictions.jsonl" \
      --output-dir "$HYBRID_DIR/reconciliation" \
      --audit-fraction "${HUMAN_AUDIT_FRACTION:-0.15}"
    ;;
  status)
    status_line
    ;;
  *)
    usage
    exit 2
    ;;
esac
