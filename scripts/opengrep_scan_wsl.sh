#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

OPENGREP_VERSION="1.22.0"
OPENGREP_SHA256="45bcd58440e397ed52c50e953ccf5948909ea77087c9186fc7d277216f62e319"
OPENGREP_URL="https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_manylinux_x86"
OPENGREP_BIN="$PROJECT_ROOT/cache/tools/opengrep/v${OPENGREP_VERSION}/opengrep"
SCAN_CACHE_ROOT="$PROJECT_ROOT/cache/wsl-opengrep"
SCAN_WORK_ROOT="$PROJECT_ROOT/worktrees/opengrep-linux-lf"
MANIFEST="$PROJECT_ROOT/artifacts/manifests/vulngym-v0.1.4.json"
SCANNER_LOCK="${OPENGREP_SCANNER_LOCK:-$PROJECT_ROOT/config/scanners.opengrep-security-wsl.lock.json}"
SCAN_PROFILE="${OPENGREP_SCAN_PROFILE:-$PROJECT_ROOT/config/scan-profile.opengrep-security-wsl-fast.json}"
ENTRIES="$PROJECT_ROOT/benchmark/VulnGym/data/entries.jsonl"
SCAN_ID="${OPENGREP_SCAN_ID:-opengrep-v1.22.0-vulngym-v0.1.4-security-wsl-ext4-r2-20260812}"
SCAN_ROOT="$PROJECT_ROOT/artifacts/scans/$SCAN_ID"
NORMALIZED_ROOT="$PROJECT_ROOT/artifacts/normalized/${SCAN_ID}-opengrep-only"
SMOKE_REPO_URL="https://github.com/czlonkowski/n8n-mcp"
SMOKE_COMMIT="ff486ea04f0b20460141e5ef2be3d518e1772b80"
export UV_PROJECT_ENVIRONMENT="${UV_PROJECT_ENVIRONMENT:-$PROJECT_ROOT/.venv-wsl}"
export UV_LINK_MODE="${UV_LINK_MODE:-copy}"

# Keep every Git process in this Linux-only workflow on LF without touching the
# immutable checkout controller used by the historical Semgrep v1/v5 release.
GIT_CONFIG_INDEX="${GIT_CONFIG_COUNT:-0}"
export "GIT_CONFIG_KEY_${GIT_CONFIG_INDEX}=core.autocrlf"
export "GIT_CONFIG_VALUE_${GIT_CONFIG_INDEX}=false"
export GIT_CONFIG_COUNT="$((GIT_CONFIG_INDEX + 1))"

usage() {
  cat <<'EOF'
Usage: bash scripts/opengrep_scan_wsl.sh ACTION

Actions:
  setup       Create the WSL Python environment and install pinned OpenGrep.
  build-security-rules
              Build the deterministic security-only derived ruleset.
  doctor      Verify WSL architecture, configuration, ruleset and scanner pins.
  smoke       Scan one snapshot under a separate smoke scan-id.
  run         Run or resume the selected batch; successful jobs are reused.
  status      Print read-only coverage for the current scan-id.
  summary     Print a compact, one-shot progress summary.
  monitor     Refresh the compact progress summary until Ctrl+C.
  benchmark   Compare OpenGrep internal jobs 4, 6 and 8 on one snapshot.
  normalize   Normalize, deduplicate and match a complete OpenGrep batch.

Optional environment variables for run:
  OPENGREP_SCAN_ID                 Override the immutable scan id.
  OPENGREP_SCANNER_LOCK            Override the scanner lock path.
  OPENGREP_SCAN_PROFILE            Override the scan profile path.
  OPENGREP_LIMIT                   Select the first N manifest snapshots.
  OPENGREP_REPO_URL                Select one repository URL.
  OPENGREP_COMMIT                  Select one full commit SHA.
  OPENGREP_PREFETCH                Fetch selected commits first (default: 1).
  OPENGREP_PREFETCH_WORKERS        Concurrent repository fetches (default: 4).
  OPENGREP_BATCH_WORKERS           Concurrent snapshot scans (default: 2).
  OPENGREP_REQUIRE_CLEAN_RUNNER    Require committed clean runner (default: 1).
  OPENGREP_JOB_TIMEOUT_SECONDS     Override the per-snapshot job timeout.
  OPENGREP_ALLOW_INCOMPLETE=1      Permit provisional normalization.
  OPENGREP_MONITOR_INTERVAL        Refresh interval in seconds (default: 5).
  OPENGREP_BENCHMARK_ID            Immutable benchmark id prefix.
EOF
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $1" >&2
    exit 2
  fi
}

install_opengrep() {
  require_command curl
  require_command sha256sum
  if [[ "$(uname -m)" != "x86_64" ]]; then
    echo "ERROR: the pinned OpenGrep asset requires x86_64 WSL" >&2
    exit 2
  fi

  mkdir -p "$(dirname "$OPENGREP_BIN")"
  if [[ -f "$OPENGREP_BIN" ]] && printf '%s  %s\n' "$OPENGREP_SHA256" "$OPENGREP_BIN" | sha256sum --check --status; then
    chmod 0755 "$OPENGREP_BIN"
    echo "Pinned OpenGrep is already installed: $OPENGREP_BIN"
    return
  fi

  local temporary
  temporary="$(mktemp "$(dirname "$OPENGREP_BIN")/.opengrep.XXXXXX")"
  trap 'rm -f "$temporary"' RETURN
  curl --fail --location --retry 3 --output "$temporary" "$OPENGREP_URL"
  printf '%s  %s\n' "$OPENGREP_SHA256" "$temporary" | sha256sum --check
  chmod 0755 "$temporary"
  mv --force "$temporary" "$OPENGREP_BIN"
  trap - RETURN
  "$OPENGREP_BIN" --version
}

setup() {
  require_command git
  require_command uv
  git submodule update --init --recursive
  git config --local core.autocrlf false
  git submodule foreach --recursive 'git config --local core.autocrlf false'
  uv sync --extra dev
  install_opengrep
  build_security_rules
  echo "WSL setup complete. Next: bash scripts/opengrep_scan_wsl.sh doctor"
}

build_security_rules() {
  if [[ ! -x "$UV_PROJECT_ENVIRONMENT/bin/python" ]]; then
    echo "ERROR: WSL Python environment is missing; run the setup action" >&2
    exit 2
  fi
  "$UV_PROJECT_ENVIRONMENT/bin/python" scripts/build_opengrep_security_ruleset.py \
    --source-root rules/semgrep-rules \
    --base-profile config/scan-profile.opengrep-wsl-fast.json \
    --output-root rules/semgrep-rules-security
}

doctor() {
  require_command git
  require_command sha256sum
  if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
    echo "ERROR: expected Linux x86_64 (Ubuntu WSL2)" >&2
    exit 2
  fi
  if [[ "$PROJECT_ROOT" == /mnt/* ]]; then
    echo "ERROR: project must live on the WSL Linux filesystem, not under /mnt/*" >&2
    exit 2
  fi
  if command -v findmnt >/dev/null 2>&1; then
    local filesystem_type
    filesystem_type="$(findmnt -n -o FSTYPE -T "$PROJECT_ROOT")"
    if [[ "$filesystem_type" == "9p" || "$filesystem_type" == "drvfs" ]]; then
      echo "ERROR: project filesystem is $filesystem_type; use the WSL ext4 filesystem" >&2
      exit 2
    fi
  fi
  for path in "$MANIFEST" "$SCANNER_LOCK" "$SCAN_PROFILE" "$ENTRIES"; do
    if [[ ! -f "$path" ]]; then
      echo "ERROR: required file is missing: $path" >&2
      exit 2
    fi
  done
  if [[ ! -x "$OPENGREP_BIN" ]]; then
    echo "ERROR: pinned OpenGrep is not installed; run the setup action" >&2
    exit 2
  fi
  if [[ ! -x "$UV_PROJECT_ENVIRONMENT/bin/python" ]]; then
    echo "ERROR: WSL Python environment is missing; run the setup action" >&2
    exit 2
  fi

  "$UV_PROJECT_ENVIRONMENT/bin/python" - \
    "$PROJECT_ROOT" "$MANIFEST" "$SCANNER_LOCK" "$SCAN_PROFILE" \
    "${OPENGREP_BATCH_WORKERS:-2}" <<'PY'
import json
import os
import subprocess
import sys
from pathlib import Path

from vulngym_enrich.scanner import (
    load_configuration,
    scanner_executable,
    verify_ruleset_pin,
    verify_scanner_executable_checksum,
    verify_scanner_version,
)

root = Path(sys.argv[1]).resolve()
manifest_path = Path(sys.argv[2]).resolve()
scanner_lock_path = Path(sys.argv[3]).resolve()
scan_profile_path = Path(sys.argv[4]).resolve()
batch_workers = int(sys.argv[5])
manifest, lock, profile = load_configuration(
    manifest_path,
    scanner_lock_path,
    scan_profile_path,
)
ruleset = verify_ruleset_pin(root / profile["rules"]["root"], lock["ruleset"]["commit"])
executable = scanner_executable("opengrep", lock, root)
scanner = lock["scanners"]["opengrep"]
checksum = verify_scanner_executable_checksum(executable, scanner)
version = verify_scanner_version(executable, scanner["version"])
autocrlf = subprocess.run(
    ["git", "-C", str(root), "config", "--get", "core.autocrlf"],
    check=False, capture_output=True, text=True,
).stdout.strip().casefold()
if autocrlf not in {"false", "input"}:
    raise RuntimeError(
        f"core.autocrlf must be false or input for Linux snapshots, got {autocrlf or 'unset'}"
    )
git_commit = subprocess.run(
    ["git", "-C", str(root), "rev-parse", "HEAD"],
    check=True, capture_output=True, text=True,
).stdout.strip()
git_status = subprocess.run(
    ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"],
    check=True, capture_output=True, text=True,
).stdout.splitlines()
internal_jobs = int(profile["scan"]["jobs"])
max_memory_mb = int(profile["scan"]["max_memory_mb"])
cpu_count = os.cpu_count() or 1
total_memory_mb = 0
for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
    if line.startswith("MemTotal:"):
        total_memory_mb = int(line.split()[1]) // 1024
        break
if batch_workers * internal_jobs > cpu_count:
    raise RuntimeError(
        f"oversubscribed CPU: batch_workers({batch_workers}) * jobs({internal_jobs}) "
        f"> logical CPUs({cpu_count})"
    )
if total_memory_mb and total_memory_mb - batch_workers * max_memory_mb < 2048:
    raise RuntimeError(
        "configured concurrent scanner memory leaves less than 2048 MiB for WSL and the runner"
    )
print(json.dumps({
    "status": "READY",
    "snapshots": len(manifest["snapshots"]),
    "scanner": "opengrep",
    "version": version,
    "executable_sha256": checksum,
    "ruleset_commit": ruleset,
    "jobs": internal_jobs,
    "batch_workers": batch_workers,
    "parallel_job_slots": internal_jobs * batch_workers,
    "max_memory_mb_per_scanner": max_memory_mb,
    "prefetch_workers": int(os.environ.get("OPENGREP_PREFETCH_WORKERS", "4")),
    "runner_git_commit": git_commit,
    "runner_worktree_clean": not git_status,
    "core_autocrlf": autocrlf,
}, indent=2))
PY
}

scan_batch() {
  local selected_scan_id="$1"
  shift
  local args=(
    "$UV_PROJECT_ENVIRONMENT/bin/vulngym-scan"
    --project-root "$PROJECT_ROOT"
    --manifest "$MANIFEST"
    --scanner-lock "$SCANNER_LOCK"
    --scan-profile "$SCAN_PROFILE"
    --scan-id "$selected_scan_id"
    --cache-root "$SCAN_CACHE_ROOT"
    --work-root "$SCAN_WORK_ROOT"
    --output-root "$PROJECT_ROOT/artifacts/scans"
    --scanner opengrep
    --batch-workers "${OPENGREP_BATCH_WORKERS:-2}"
    --prefetch-workers "${OPENGREP_PREFETCH_WORKERS:-4}"
  )
  if [[ "${OPENGREP_PREFETCH:-1}" == "1" ]]; then
    args+=(--prefetch)
  fi
  if [[ "${OPENGREP_REQUIRE_CLEAN_RUNNER:-1}" == "1" ]]; then
    args+=(--require-clean-runner)
  fi
  if [[ -n "${OPENGREP_LIMIT:-}" ]]; then
    args+=(--limit "$OPENGREP_LIMIT")
  fi
  if [[ -n "${OPENGREP_REPO_URL:-}" ]]; then
    args+=(--repo-url "$OPENGREP_REPO_URL")
  fi
  if [[ -n "${OPENGREP_COMMIT:-}" ]]; then
    args+=(--commit "$OPENGREP_COMMIT")
  fi
  if [[ -n "${OPENGREP_JOB_TIMEOUT_SECONDS:-}" ]]; then
    args+=(--job-timeout-seconds "$OPENGREP_JOB_TIMEOUT_SECONDS")
  fi
  args+=("$@")
  "${args[@]}"
}

status() {
  "$UV_PROJECT_ENVIRONMENT/bin/python" - "$SCAN_ROOT" "$MANIFEST" <<'PY'
import json
import sys
from pathlib import Path

from vulngym_enrich.full_pipeline import discover_scan_jobs, validate_scan_coverage

scan_root = Path(sys.argv[1])
manifest = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
jobs = discover_scan_jobs(scan_root) if scan_root.exists() else []
coverage = validate_scan_coverage(jobs, manifest, scanners=["opengrep"])
print(json.dumps(coverage, ensure_ascii=False, indent=2))
PY
}

summary() {
  if [[ ! -x "$UV_PROJECT_ENVIRONMENT/bin/python" ]]; then
    echo "ERROR: WSL Python environment is missing; run the setup action" >&2
    exit 2
  fi

  local process_state="STOPPED"
  if pgrep -af '[v]ulngym-scan' 2>/dev/null | grep -F -- "--scan-id $SCAN_ID" >/dev/null; then
    process_state="ACTIVE"
  fi

  OPENGREP_PROCESS_STATE="$process_state" \
    "$UV_PROJECT_ENVIRONMENT/bin/python" - "$SCAN_ROOT" "$MANIFEST" "$SCAN_ID" <<'PY'
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def duration(seconds: float) -> str:
    total = max(0, int(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


scan_root = Path(sys.argv[1])
manifest = read_json(Path(sys.argv[2]))
scan_id = sys.argv[3]
expected = len(manifest.get("snapshots") or [])
run = read_json(scan_root / "run.json")
job_timeout = float((run.get("execution") or {}).get("job_timeout_seconds") or 7200)

rows = []
if scan_root.exists():
    for pointer_path in scan_root.glob("*/*/opengrep/status.json"):
        pointer = read_json(pointer_path)
        if pointer:
            pointer["_path"] = pointer_path
            attempt_ref = pointer.get("attempt_status")
            pointer["_attempt"] = (
                read_json(pointer_path.parent / attempt_ref)
                if isinstance(attempt_ref, str) and attempt_ref
                else {}
            )
            rows.append(pointer)

counts = Counter(str(row.get("status") or "UNKNOWN") for row in rows)
accounted = len(rows)
percent = (100.0 * accounted / expected) if expected else 0.0

print(f"OpenGrep  {scan_id}")
print(f"Process   {os.environ.get('OPENGREP_PROCESS_STATE', 'UNKNOWN')}")
print(f"Progress  {accounted}/{expected} ({percent:.1f}%)")
print(
    "Jobs      "
    f"SUCCESS={counts['SUCCESS']}  RUNNING={counts['RUNNING']}  "
    f"TIMEOUT={counts['TIMEOUT']}  FAILED={counts['FAILED']}  "
    f"SKIPPED={counts['SKIPPED']}"
)
diagnostic_errors = sum(
    int(((row.get("_attempt") or {}).get("diagnostics") or {}).get("errors_total") or 0)
    for row in rows
)
partial_files = sum(
    len(((row.get("_attempt") or {}).get("diagnostics") or {}).get("partial_parsing_files") or [])
    for row in rows
)
partial_jobs = sum(
    bool(((row.get("_attempt") or {}).get("diagnostics") or {}).get("partial_parsing_files"))
    for row in rows
)
print(
    f"Warnings  scanner_errors={diagnostic_errors}  "
    f"partial_files={partial_files}  jobs_with_partial={partial_jobs}"
)

running = sorted(
    (row for row in rows if row.get("status") == "RUNNING"),
    key=lambda row: str(row.get("updated_at") or ""),
    reverse=True,
)
if running:
    print("Current")
    now = datetime.now(timezone.utc)
    for row in running[:3]:
        pointer_path = row["_path"]
        attempt = row.get("_attempt") or {}
        started_at = attempt.get("started_at")
        elapsed = 0.0
        if isinstance(started_at, str):
            try:
                elapsed = (now - datetime.fromisoformat(started_at)).total_seconds()
            except ValueError:
                pass
        remaining = max(0.0, job_timeout - elapsed)
        repo = str(row.get("repo_url") or "").rstrip("/").rsplit("/", 1)[-1]
        commit = str(row.get("commit") or "")[:8]
        print(
            f"  {repo}@{commit}  elapsed={duration(elapsed)}  "
            f"timeout-in={duration(remaining)}"
        )
elif os.environ.get("OPENGREP_PROCESS_STATE") == "ACTIVE":
    print("Current   preparing checkout/fetch; no scanner job has started yet")
else:
    print("Current   none")

problems = sorted(
    (row for row in rows if row.get("status") in {"TIMEOUT", "FAILED"}),
    key=lambda row: str(row.get("updated_at") or ""),
    reverse=True,
)
if problems:
    print("Recent errors")
    for row in problems[:5]:
        repo = str(row.get("repo_url") or "").rstrip("/").rsplit("/", 1)[-1]
        commit = str(row.get("commit") or "")[:8]
        print(f"  {row.get('status')}  {repo}@{commit}")
PY
}

monitor() {
  require_command pgrep
  local interval="${OPENGREP_MONITOR_INTERVAL:-5}"
  if [[ ! "$interval" =~ ^[1-9][0-9]*$ ]]; then
    echo "ERROR: OPENGREP_MONITOR_INTERVAL must be a positive integer" >&2
    exit 2
  fi
  while true; do
    printf '\033[2J\033[H'
    date '+Updated   %Y-%m-%d %H:%M:%S %Z'
    summary
    printf '\nCtrl+C to stop monitoring; the scan process is not interrupted.\n'
    sleep "$interval"
  done
}

benchmark() {
  doctor
  local benchmark_id="${OPENGREP_BENCHMARK_ID:-opengrep-security-ext4-benchmark-20260812-r1}"
  local benchmark_repo="${OPENGREP_BENCHMARK_REPO_URL:-https://github.com/FlowiseAI/Flowise}"
  local benchmark_commit="${OPENGREP_BENCHMARK_COMMIT:-1ae1638ed972bcc913611ae9268a972d0ae127ec}"
  local benchmark_root="$PROJECT_ROOT/cache/benchmarks/$benchmark_id"
  local original_profile="$SCAN_PROFILE"
  mkdir -p "$benchmark_root"

  for internal_jobs in 4 6 8; do
    local generated_profile="$benchmark_root/scan-profile-j${internal_jobs}.json"
    "$UV_PROJECT_ENVIRONMENT/bin/python" - \
      "$original_profile" "$generated_profile" "$internal_jobs" <<'PY'
import json
import sys
from pathlib import Path

source, destination, jobs = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3])
profile = json.loads(source.read_text(encoding="utf-8"))
profile["scan"]["jobs"] = jobs
destination.write_text(
    json.dumps(profile, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
    SCAN_PROFILE="$generated_profile"
    OPENGREP_BATCH_WORKERS=1 \
      OPENGREP_PREFETCH=1 \
      OPENGREP_REQUIRE_CLEAN_RUNNER=0 \
      OPENGREP_REPO_URL="$benchmark_repo" \
      OPENGREP_COMMIT="$benchmark_commit" \
      scan_batch "${benchmark_id}-j${internal_jobs}"
  done
  SCAN_PROFILE="$original_profile"

  "$UV_PROJECT_ENVIRONMENT/bin/python" - \
    "$PROJECT_ROOT/artifacts/scans" "$benchmark_id" <<'PY'
import json
import sys
from pathlib import Path

scan_root, prefix = Path(sys.argv[1]), sys.argv[2]
print("jobs\tduration_seconds\tfindings\terrors\tpartial_files")
for jobs in (4, 6, 8):
    status_paths = list((scan_root / f"{prefix}-j{jobs}").glob("*/*/opengrep/status.json"))
    if len(status_paths) != 1:
        raise RuntimeError(f"expected one benchmark status for jobs={jobs}")
    pointer = json.loads(status_paths[0].read_text(encoding="utf-8"))
    attempt = json.loads(
        (status_paths[0].parent / pointer["attempt_status"]).read_text(encoding="utf-8")
    )
    diagnostics = attempt.get("diagnostics") or {}
    print(
        f"{jobs}\t{attempt.get('duration_seconds')}\t{diagnostics.get('findings')}\t"
        f"{diagnostics.get('errors_total')}\t"
        f"{len(diagnostics.get('partial_parsing_files') or [])}"
    )
PY
}

normalize() {
  local args=(
    "$UV_PROJECT_ENVIRONMENT/bin/vulngym-full-pipeline"
    --scan-root "$SCAN_ROOT"
    --manifest "$MANIFEST"
    --entries "$ENTRIES"
    --output-dir "$NORMALIZED_ROOT"
    --scanner opengrep
  )
  if [[ "${OPENGREP_ALLOW_INCOMPLETE:-0}" == "1" ]]; then
    args+=(--allow-incomplete)
  fi
  "${args[@]}"
}

action="${1:-}"
case "$action" in
  setup)
    setup
    ;;
  build-security-rules)
    build_security_rules
    ;;
  doctor)
    doctor
    ;;
  smoke)
    doctor
    OPENGREP_LIMIT=1 \
      OPENGREP_REPO_URL="${OPENGREP_REPO_URL:-$SMOKE_REPO_URL}" \
      OPENGREP_COMMIT="${OPENGREP_COMMIT:-$SMOKE_COMMIT}" \
      scan_batch "${SCAN_ID}-smoke"
    ;;
  run)
    doctor
    scan_batch "$SCAN_ID"
    ;;
  status)
    status
    ;;
  summary)
    summary
    ;;
  monitor)
    monitor
    ;;
  benchmark)
    benchmark
    ;;
  normalize)
    doctor
    normalize
    ;;
  *)
    usage
    exit 2
    ;;
esac
