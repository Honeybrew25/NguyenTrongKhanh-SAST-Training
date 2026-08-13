#!/usr/bin/env bash
set -euo pipefail

# Never let a caller's `bash -x` print commands from a credentialed workflow.
if [[ $- == *x* ]]; then
  set +x
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

PYTHON_BIN="${PYTHON_BIN:-.venv-wsl/bin/python}"
SAMPLE_DIR="${SAMPLE_DIR:-artifacts/human-review/opengrep-representative-r1-20260812}"
EVIDENCE_PACKETS="${EVIDENCE_PACKETS:-artifacts/hybrid-review/opengrep-representative-r1-20260812/evidence-packets.jsonl}"
MACHINE_DIR="${MACHINE_DIR:-artifacts/llm-review/opengrep-representative-gemini-only-r5-20260813}"
SNAPSHOT_ROOT="${SNAPSHOT_ROOT:-worktrees/opengrep-linux-lf}"
PROFILE="${PROFILE:-config/verifier-profile-v1.json}"
PROMPT="${PROMPT:-config/verifier-prompt-local-v1.md}"
RESPONSE_SCHEMA="${RESPONSE_SCHEMA:-schemas/verifier-agent-response.schema.json}"
ADJUDICATOR_PROMPT="${ADJUDICATOR_PROMPT:-config/machine-adjudicator-prompt-v1.md}"
ADJUDICATOR_SCHEMA="${ADJUDICATOR_SCHEMA:-schemas/machine-adjudicator-response.schema.json}"
EXPECTED_RECORDS="${EXPECTED_RECORDS:-400}"
AUDIT_FRACTION="${MACHINE_AUDIT_FRACTION:-0.20}"
AUDIT_FAILURE_THRESHOLD="${MACHINE_AUDIT_FAILURE_THRESHOLD:-0.10}"
AUDIT_SEED="${MACHINE_AUDIT_SEED:-opengrep-machine-fp-audit-r1-20260813}"
REVIEWER_A_ORDER_SEED="${REVIEWER_A_ORDER_SEED:-opengrep-machine-review-a-order-r1-20260813}"
REVIEWER_B_ORDER_SEED="${REVIEWER_B_ORDER_SEED:-opengrep-machine-review-b-order-r1-20260813}"

REVIEWER_A_THINKING="${REVIEWER_A_THINKING:-minimal}"
REVIEWER_B_THINKING="${REVIEWER_B_THINKING:-minimal}"
ADJUDICATOR_THINKING="${ADJUDICATOR_THINKING:-low}"
REVIEWER_A_PROVIDER="${REVIEWER_A_PROVIDER:-gemini-api}"
REVIEWER_B_PROVIDER="${REVIEWER_B_PROVIDER:-gemini-api}"
ADJUDICATOR_PROVIDER="${ADJUDICATOR_PROVIDER:-gemini-api}"
REVIEWER_A_BASE_URL="${REVIEWER_A_BASE_URL:-http://127.0.0.1:1234/v1}"
REVIEWER_B_BASE_URL="${REVIEWER_B_BASE_URL:-http://127.0.0.1:1234/v1}"
REVIEWER_A_MODEL_REVISION_SHA256="${REVIEWER_A_MODEL_REVISION_SHA256:-}"
REVIEWER_B_MODEL_REVISION_SHA256="${REVIEWER_B_MODEL_REVISION_SHA256:-}"
LOCAL_MAX_TOKENS="${LOCAL_MAX_TOKENS:-8192}"
REVIEWER_A_SEED="${REVIEWER_A_SEED:-17011}"
REVIEWER_B_SEED="${REVIEWER_B_SEED:-29023}"
ADJUDICATOR_SEED="${ADJUDICATOR_SEED:-47017}"
GEMINI_TEMPERATURE="${GEMINI_TEMPERATURE:-0}"
GEMINI_MIN_REQUEST_INTERVAL_SECONDS="${GEMINI_MIN_REQUEST_INTERVAL_SECONDS:-4}"
GEMINI_RATE_LIMIT_RETRY_DELAY_SECONDS="${GEMINI_RATE_LIMIT_RETRY_DELAY_SECONDS:-30}"
GEMINI_MAX_RATE_LIMIT_WAIT_SECONDS="${GEMINI_MAX_RATE_LIMIT_WAIT_SECONDS:-90}"

usage() {
  printf '%s\n' \
    "Usage: bash scripts/opengrep_machine_review.sh <validate|reviewer-a|reviewer-b|reconcile|adjudicator-blind|adjudicator-finalize|status>" \
    "" \
    "Required for validate and subsequent workflow commands:" \
    "  export REVIEWER_A_MODEL=<exact-model-id>" \
    "  export REVIEWER_B_MODEL=<exact-model-id>" \
    "  export ADJUDICATOR_MODEL=<exact-model-id>" \
    "  export EVALUATED_AGENT_MODEL=<exact-model-id>" \
    "For local A/B: set REVIEWER_{A,B}_PROVIDER=local-openai, BASE_URL, and MODEL_REVISION_SHA256." \
    "Required only when a command calls Gemini adjudicator C:" \
    "  export GEMINI_API_KEY=<secret>       # or GOOGLE_API_KEY, never both" \
    "" \
    "A, B, C, and the evaluated agent must all use different model IDs." \
    "See docs/opengrep-machine-review.md for gates and publication limits."
}

die() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 2
}

require_file() {
  [[ -f "$1" ]] || die "required file is missing: $1"
}

require_runtime() {
  [[ -x "$PYTHON_BIN" ]] || die "Python is not executable: $PYTHON_BIN"
  require_file "$SAMPLE_DIR/sample-manifest.json"
  require_file "$SAMPLE_DIR/sampled-findings.jsonl"
  require_file "$EVIDENCE_PACKETS"
  require_file "$PROFILE"
  require_file "$PROMPT"
  require_file "$RESPONSE_SCHEMA"
  require_file "$ADJUDICATOR_PROMPT"
  require_file "$ADJUDICATOR_SCHEMA"
  [[ -d "$SNAPSHOT_ROOT" ]] || die "snapshot root is missing: $SNAPSHOT_ROOT"
  "$PYTHON_BIN" -c \
    'import google.genai, jsonschema, vulngym_enrich.gemini_verifier_agent, vulngym_enrich.local_verifier_agent, vulngym_enrich.machine_review' \
    >/dev/null 2>&1 || die "Python dependencies/modules are unavailable; install the project environment first"
}

require_model_environment() {
  : "${REVIEWER_A_MODEL:?Set REVIEWER_A_MODEL to an exact model ID}"
  : "${REVIEWER_B_MODEL:?Set REVIEWER_B_MODEL to an exact model ID}"
  : "${ADJUDICATOR_MODEL:?Set ADJUDICATOR_MODEL to an exact model ID}"
  : "${EVALUATED_AGENT_MODEL:?Set EVALUATED_AGENT_MODEL to an exact model ID}"

  [[ "$ADJUDICATOR_PROVIDER" == "gemini-api" ]] || die "adjudicator C must remain gemini-api"
  local provider
  for provider in "$REVIEWER_A_PROVIDER" "$REVIEWER_B_PROVIDER"; do
    [[ "$provider" == "local-openai" || "$provider" == "gemini-api" ]] || \
      die "reviewer provider must be local-openai or gemini-api"
  done
  if [[ "$REVIEWER_A_PROVIDER" == "local-openai" ]]; then
    [[ "$REVIEWER_A_MODEL_REVISION_SHA256" =~ ^[0-9a-fA-F]{64}$ ]] || \
      die "REVIEWER_A_MODEL_REVISION_SHA256 must identify the exact local model artifact"
  fi
  if [[ "$REVIEWER_B_PROVIDER" == "local-openai" ]]; then
    [[ "$REVIEWER_B_MODEL_REVISION_SHA256" =~ ^[0-9a-fA-F]{64}$ ]] || \
      die "REVIEWER_B_MODEL_REVISION_SHA256 must identify the exact local model artifact"
  fi
  [[ "$LOCAL_MAX_TOKENS" =~ ^[0-9]+$ ]] && ((LOCAL_MAX_TOKENS >= 256 && LOCAL_MAX_TOKENS <= 131072)) || \
    die "LOCAL_MAX_TOKENS must be an integer between 256 and 131072"

  local role model normalized
  for role in REVIEWER_A_MODEL REVIEWER_B_MODEL ADJUDICATOR_MODEL EVALUATED_AGENT_MODEL; do
    model="${!role}"
    [[ "$model" != *$'\n'* && "$model" != *$'\r'* ]] || die "$role contains a newline"
    [[ "$model" != *[[:space:]]* ]] || die "$role must be one exact model ID without whitespace"
    normalized="${model,,}"
    case "$normalized" in
      latest|*/latest|*-latest|*:latest)
        die "$role uses a mutable latest alias: $model"
        ;;
    esac
  done

  local models=(
    "${REVIEWER_A_MODEL,,}"
    "${REVIEWER_B_MODEL,,}"
    "${ADJUDICATOR_MODEL,,}"
    "${EVALUATED_AGENT_MODEL,,}"
  )
  local left right
  for ((left = 0; left < ${#models[@]}; left++)); do
    for ((right = left + 1; right < ${#models[@]}; right++)); do
      [[ "${models[left]}" != "${models[right]}" ]] || \
        die "reviewer A, reviewer B, adjudicator C, and evaluated agent must use four distinct model IDs"
    done
  done

  local thinking
  for thinking in "$REVIEWER_A_THINKING" "$REVIEWER_B_THINKING" "$ADJUDICATOR_THINKING"; do
    case "$thinking" in
      minimal|low|medium|high) ;;
      *) die "thinking level must be one of: minimal, low, medium, high" ;;
    esac
  done

  "$PYTHON_BIN" - \
    "$REVIEWER_A_SEED" "$REVIEWER_B_SEED" "$ADJUDICATOR_SEED" \
    "$GEMINI_TEMPERATURE" "$EXPECTED_RECORDS" "$AUDIT_FRACTION" \
    "$AUDIT_FAILURE_THRESHOLD" "$GEMINI_MIN_REQUEST_INTERVAL_SECONDS" \
    "$GEMINI_RATE_LIMIT_RETRY_DELAY_SECONDS" \
    "$GEMINI_MAX_RATE_LIMIT_WAIT_SECONDS" <<'PY'
import math
import sys

try:
    seeds = [int(value) for value in sys.argv[1:4]]
except ValueError as exc:
    raise SystemExit(f"ERROR: Gemini seeds must be integers: {exc}")
if len(set(seeds)) != 3:
    raise SystemExit("ERROR: reviewer A, reviewer B, and adjudicator C seeds must differ")
if any(not -(2**31) <= seed < 2**31 for seed in seeds):
    raise SystemExit("ERROR: Gemini seeds must be signed 32-bit integers")
try:
    temperature = float(sys.argv[4])
    expected = int(sys.argv[5])
    audit_fraction = float(sys.argv[6])
    audit_failure_threshold = float(sys.argv[7])
    min_request_interval = float(sys.argv[8])
    rate_limit_retry_delay = float(sys.argv[9])
    max_rate_limit_wait = float(sys.argv[10])
except ValueError as exc:
    raise SystemExit(f"ERROR: invalid numeric workflow setting: {exc}")
if not math.isfinite(temperature) or not 0 <= temperature <= 2:
    raise SystemExit("ERROR: GEMINI_TEMPERATURE must be between 0 and 2")
if expected != 400:
    raise SystemExit("ERROR: this release requires EXPECTED_RECORDS=400")
if not math.isfinite(audit_fraction) or not 0 < audit_fraction <= 1:
    raise SystemExit("ERROR: MACHINE_AUDIT_FRACTION must be greater than 0 and at most 1")
if (
    not math.isfinite(audit_failure_threshold)
    or not 0 <= audit_failure_threshold <= 1
):
    raise SystemExit("ERROR: MACHINE_AUDIT_FAILURE_THRESHOLD must be between 0 and 1")
if not math.isfinite(min_request_interval) or not 0 <= min_request_interval <= 60:
    raise SystemExit("ERROR: GEMINI_MIN_REQUEST_INTERVAL_SECONDS must be between 0 and 60")
if not math.isfinite(rate_limit_retry_delay) or not 0 <= rate_limit_retry_delay <= 300:
    raise SystemExit("ERROR: GEMINI_RATE_LIMIT_RETRY_DELAY_SECONDS must be between 0 and 300")
if not math.isfinite(max_rate_limit_wait) or not 0 <= max_rate_limit_wait <= 3600:
    raise SystemExit("ERROR: GEMINI_MAX_RATE_LIMIT_WAIT_SECONDS must be between 0 and 3600")
PY
}

require_api_credential() {
  if [[ -n "${GEMINI_API_KEY:-}" && -n "${GOOGLE_API_KEY:-}" ]]; then
    die "both GEMINI_API_KEY and GOOGLE_API_KEY are set; keep exactly one to avoid ambiguous credentials"
  fi
  if [[ -z "${GEMINI_API_KEY:-}" && -z "${GOOGLE_API_KEY:-}" ]]; then
    die "Gemini API credential is missing; set GEMINI_API_KEY or GOOGLE_API_KEY"
  fi
}

require_reviewer_credential() {
  local provider="$1"
  [[ "$provider" == "local-openai" ]] || require_api_credential
}

with_identity_configs() {
  local temporary_directory callback_status generation_status
  temporary_directory="$(mktemp -d)"
  callback_status=0
  generation_status=0
  "$PYTHON_BIN" - \
    "$temporary_directory" \
    "$REVIEWER_A_PROVIDER" "$REVIEWER_A_MODEL" "$REVIEWER_A_THINKING" "$REVIEWER_A_SEED" \
    "$REVIEWER_A_BASE_URL" "$REVIEWER_A_MODEL_REVISION_SHA256" \
    "$REVIEWER_B_PROVIDER" "$REVIEWER_B_MODEL" "$REVIEWER_B_THINKING" "$REVIEWER_B_SEED" \
    "$REVIEWER_B_BASE_URL" "$REVIEWER_B_MODEL_REVISION_SHA256" \
    "$ADJUDICATOR_PROVIDER" "$ADJUDICATOR_MODEL" "$ADJUDICATOR_THINKING" "$ADJUDICATOR_SEED" \
    "$GEMINI_TEMPERATURE" "$LOCAL_MAX_TOKENS" <<'PY' || generation_status=$?
import importlib.metadata
import json
import sys
from pathlib import Path
from vulngym_enrich.local_verifier_agent import LOCAL_DIALECT_VERSION, LOCAL_PROVIDER_ID

root = Path(sys.argv[1])
gemini_sdk_version = importlib.metadata.version("google-genai")
temperature = float(sys.argv[18])
local_max_tokens = int(sys.argv[19])
roles = (
    ("reviewer-a", "REVIEWER_A", sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]), sys.argv[6], sys.argv[7]),
    ("reviewer-b", "REVIEWER_B", sys.argv[8], sys.argv[9], sys.argv[10], int(sys.argv[11]), sys.argv[12], sys.argv[13]),
    ("adjudicator-c", "ADJUDICATOR_C", sys.argv[14], sys.argv[15], sys.argv[16], int(sys.argv[17]), "", ""),
)
for identifier, role, provider_selector, model, thinking, seed, base_url, revision in roles:
    is_local = provider_selector == "local-openai"
    value = {
        "schema_version": 1,
        "id": identifier,
        "kind": "MODEL",
        "role": role,
        "provider": LOCAL_PROVIDER_ID if is_local else "google-gemini-api-isolated-json",
        "provider_version": LOCAL_DIALECT_VERSION if is_local else gemini_sdk_version,
        "model": model,
        "model_version": None,
        "thinking_level": "SERVER_DEFAULT" if is_local else thinking.upper(),
        "temperature": temperature,
        "seed": seed,
    }
    if is_local:
        value.update({
            "base_url": base_url.rstrip("/"),
            "model_revision_sha256": revision.lower(),
            "max_tokens": local_max_tokens,
        })
    (root / f"{identifier}.json").write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
PY
  if ((generation_status != 0)); then
    rm -rf -- "$temporary_directory"
    return "$generation_status"
  fi
  "$@" \
    "$temporary_directory/reviewer-a.json" \
    "$temporary_directory/reviewer-b.json" \
    "$temporary_directory/adjudicator-c.json" || callback_status=$?
  rm -rf -- "$temporary_directory"
  return "$callback_status"
}

prepare_machine_review() {
  local reviewer_a_config="$1"
  local reviewer_b_config="$2"
  local adjudicator_config="$3"
  "$PYTHON_BIN" -m vulngym_enrich.machine_review prepare \
    --sample-dir "$SAMPLE_DIR" \
    --evidence-packets "$EVIDENCE_PACKETS" \
    --snapshot-root "$SNAPSHOT_ROOT" \
    --output-dir "$MACHINE_DIR" \
    --reviewer-a-config "$reviewer_a_config" \
    --reviewer-b-config "$reviewer_b_config" \
    --adjudicator-config "$adjudicator_config" \
    --evaluated-agent-model "$EVALUATED_AGENT_MODEL" \
    --expected-records "$EXPECTED_RECORDS" \
    --audit-fraction "$AUDIT_FRACTION" \
    --audit-failure-threshold "$AUDIT_FAILURE_THRESHOLD" \
    --audit-seed "$AUDIT_SEED" \
    --reviewer-a-seed "$REVIEWER_A_ORDER_SEED" \
    --reviewer-b-seed "$REVIEWER_B_ORDER_SEED"
}

ensure_prepared() {
  with_identity_configs prepare_machine_review
}

validate_blind_input() {
  local role="$1"
  local model="$2"
  "$PYTHON_BIN" -m vulngym_enrich.gemini_verifier_agent \
    --input "$MACHINE_DIR/reviewer-$role/blind-input.jsonl" \
    --snapshot-root "$SNAPSHOT_ROOT" \
    --run-dir "$MACHINE_DIR/validation/reviewer-$role" \
    --profile "$PROFILE" \
    --prompt "$PROMPT" \
    --response-schema "$RESPONSE_SCHEMA" \
    --model "$model" \
    --development-run \
    --validate-only
}

run_blind_reviewer() {
  local role="$1"
  local model="$2"
  local thinking="$3"
  local seed="$4"
  local provider="$5"
  local base_url="$6"
  local revision="$7"
  if [[ "$provider" == "local-openai" ]]; then
    "$PYTHON_BIN" -m vulngym_enrich.local_verifier_agent \
      --input "$MACHINE_DIR/reviewer-$role/blind-input.jsonl" \
      --snapshot-root "$SNAPSHOT_ROOT" \
      --run-dir "$MACHINE_DIR/reviewer-$role/run" \
      --profile "$PROFILE" \
      --prompt "$PROMPT" \
      --response-schema "$RESPONSE_SCHEMA" \
      --base-url "$base_url" \
      --model "$model" \
      --model-revision-sha256 "$revision" \
      --seed "$seed" \
      --temperature "$GEMINI_TEMPERATURE" \
      --max-tokens "$LOCAL_MAX_TOKENS" \
      --development-run
    return
  fi
  "$PYTHON_BIN" -m vulngym_enrich.gemini_verifier_agent \
    --input "$MACHINE_DIR/reviewer-$role/blind-input.jsonl" \
    --snapshot-root "$SNAPSHOT_ROOT" \
    --run-dir "$MACHINE_DIR/reviewer-$role/run" \
    --profile "$PROFILE" \
    --prompt "$PROMPT" \
    --response-schema "$RESPONSE_SCHEMA" \
    --provider gemini-api \
    --model "$model" \
    --gemini-thinking-level "$thinking" \
    --seed "$seed" \
    --temperature "$GEMINI_TEMPERATURE" \
    --gemini-min-request-interval-seconds "$GEMINI_MIN_REQUEST_INTERVAL_SECONDS" \
    --gemini-rate-limit-retry-delay-seconds "$GEMINI_RATE_LIMIT_RETRY_DELAY_SECONDS" \
    --gemini-max-rate-limit-wait-seconds "$GEMINI_MAX_RATE_LIMIT_WAIT_SECONDS" \
    --development-run
}

run_adjudicator_blind() {
  "$PYTHON_BIN" -m vulngym_enrich.gemini_verifier_agent \
    --input "$MACHINE_DIR/adjudicator-c/blind-input.jsonl" \
    --snapshot-root "$SNAPSHOT_ROOT" \
    --run-dir "$MACHINE_DIR/adjudicator-c/blind" \
    --profile "$PROFILE" \
    --prompt "$PROMPT" \
    --response-schema "$RESPONSE_SCHEMA" \
    --provider gemini-api \
    --model "$ADJUDICATOR_MODEL" \
    --gemini-thinking-level "$ADJUDICATOR_THINKING" \
    --seed "$ADJUDICATOR_SEED" \
    --temperature "$GEMINI_TEMPERATURE" \
    --gemini-min-request-interval-seconds "$GEMINI_MIN_REQUEST_INTERVAL_SECONDS" \
    --gemini-rate-limit-retry-delay-seconds "$GEMINI_RATE_LIMIT_RETRY_DELAY_SECONDS" \
    --gemini-max-rate-limit-wait-seconds "$GEMINI_MAX_RATE_LIMIT_WAIT_SECONDS" \
    --development-run
}

command="${1:-}"
case "$command" in
  validate)
    require_runtime
    require_model_environment
    ensure_prepared
    validate_blind_input a "$REVIEWER_A_MODEL"
    validate_blind_input b "$REVIEWER_B_MODEL"
    ;;
  reviewer-a)
    require_runtime
    require_model_environment
    require_reviewer_credential "$REVIEWER_A_PROVIDER"
    ensure_prepared
    run_blind_reviewer a "$REVIEWER_A_MODEL" "$REVIEWER_A_THINKING" "$REVIEWER_A_SEED" \
      "$REVIEWER_A_PROVIDER" "$REVIEWER_A_BASE_URL" "$REVIEWER_A_MODEL_REVISION_SHA256"
    ;;
  reviewer-b)
    require_runtime
    require_model_environment
    require_reviewer_credential "$REVIEWER_B_PROVIDER"
    ensure_prepared
    run_blind_reviewer b "$REVIEWER_B_MODEL" "$REVIEWER_B_THINKING" "$REVIEWER_B_SEED" \
      "$REVIEWER_B_PROVIDER" "$REVIEWER_B_BASE_URL" "$REVIEWER_B_MODEL_REVISION_SHA256"
    ;;
  reconcile)
    require_runtime
    require_model_environment
    ensure_prepared
    "$PYTHON_BIN" -m vulngym_enrich.machine_review reconcile \
      --review-dir "$MACHINE_DIR" \
      --reviewer-a-run "$MACHINE_DIR/reviewer-a/run" \
      --reviewer-b-run "$MACHINE_DIR/reviewer-b/run"
    ;;
  adjudicator-blind)
    require_runtime
    require_model_environment
    require_api_credential
    ensure_prepared
    run_adjudicator_blind
    "$PYTHON_BIN" -m vulngym_enrich.machine_review prepare-adjudication \
      --review-dir "$MACHINE_DIR" \
      --blind-run "$MACHINE_DIR/adjudicator-c/blind"
    ;;
  adjudicator-finalize)
    require_runtime
    require_model_environment
    require_api_credential
    ensure_prepared
    "$PYTHON_BIN" -m vulngym_enrich.machine_review adjudicate \
      --review-dir "$MACHINE_DIR" \
      --prompt "$ADJUDICATOR_PROMPT" \
      --response-schema "$ADJUDICATOR_SCHEMA" \
      --model "$ADJUDICATOR_MODEL" \
      --thinking-level "$ADJUDICATOR_THINKING" \
      --seed "$ADJUDICATOR_SEED" \
      --temperature "$GEMINI_TEMPERATURE"
    "$PYTHON_BIN" -m vulngym_enrich.machine_review finalize \
      --review-dir "$MACHINE_DIR"
    ;;
  status)
    [[ -x "$PYTHON_BIN" ]] || die "Python is not executable: $PYTHON_BIN"
    "$PYTHON_BIN" -m vulngym_enrich.machine_review status --review-dir "$MACHINE_DIR"
    ;;
  *)
    usage
    exit 2
    ;;
esac
