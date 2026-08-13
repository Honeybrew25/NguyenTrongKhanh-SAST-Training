#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

CODEQL_VERSION="2.25.5"
CODEQL_ARCHIVE_SHA256="24717f939f1bef659f893ff4a9c99ba8c056fbaca9640f877c4dc74cf96486d7"
CODEQL_BIN_SHA256="5e459057abea0f2401d8f3a0eb7b4026571b17b8b5bb051ee66496386282dd27"
CODEQL_URL="https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-linux64.tar.gz"
CODEQL_INSTALL_ROOT="$PROJECT_ROOT/cache/tools/codeql/$CODEQL_VERSION"
CODEQL_BIN="$CODEQL_INSTALL_ROOT/codeql/codeql"
CODEQL_ARCHIVE="$PROJECT_ROOT/cache/tools/codeql/downloads/codeql-bundle-linux64-${CODEQL_VERSION}.tar.gz"

GO_VERSION="1.24.11"
GO_ARCHIVE_SHA256="bceca00afaac856bc48b4cc33db7cd9eb383c81811379faed3bdbc80edb0af65"
GO_BIN_SHA256="6728adbfea3a232a1e81270dc23da929258f5daf185422140f68dc081bb52504"
GO_URL="https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
GO_INSTALL_ROOT="$PROJECT_ROOT/cache/tools/go/$GO_VERSION"
GO_BIN="$GO_INSTALL_ROOT/go/bin/go"
GO_ARCHIVE="$PROJECT_ROOT/cache/tools/go/downloads/go${GO_VERSION}.linux-amd64.tar.gz"

PROFILE="${CODEQL_PROFILE:-$PROJECT_ROOT/config/codeql-profile-wsl-fast.json}"
if [[ "$PROFILE" != /* ]]; then
  PROFILE="$PROJECT_ROOT/$PROFILE"
fi
MANIFEST="$PROJECT_ROOT/artifacts/manifests/vulngym-v0.1.4.json"
ENTRIES="$PROJECT_ROOT/benchmark/VulnGym/data/entries.jsonl"
WORK_ROOT="$PROJECT_ROOT/worktrees/opengrep-linux-lf"
OPENCLAW_URL="https://github.com/openclaw/openclaw"
export UV_PROJECT_ENVIRONMENT="${UV_PROJECT_ENVIRONMENT:-$PROJECT_ROOT/.venv-wsl}"
export UV_LINK_MODE="${UV_LINK_MODE:-copy}"

usage() {
  cat <<'EOF'
Usage: bash scripts/codeql_scan_wsl.sh ACTION

Actions:
  setup       Install the pinned CodeQL bundle, Go runtime and Python project.
  doctor      Verify WSL/ext4, checksums, packs, resources and all worktrees.
  plan        Write the complete 169-job plan without scanning.
  pilot       Run/resume the three-language pilot.
  run-main    Run interpreted jobs except the heavy OpenClaw repository.
  run-go      Run the seven Go/autobuild jobs sequentially with a shared cache.
  run-heavy   Run OpenClaw with one larger worker by default.
  run         Run main, Go and heavy queues; returns nonzero if any queue fails.
  status      Print one compact progress snapshot with elapsed time.
  monitor     Refresh status until Ctrl+C; does not interrupt the scan.
  normalize   Normalize/match results after the complete plan succeeds.

Environment:
  CODEQL_PROFILE             fast profile by default; use the full profile for
                             security-extended coverage.
  CODEQL_WORKERS             interpreted workers (default: profile/2).
  CODEQL_GO_WORKERS          Go workers (default: 1).
  CODEQL_MONITOR_INTERVAL    refresh seconds (default: 5).
  CODEQL_RETRY_FAILED        1 to retry failed/time-out jobs (default: 1).
  CODEQL_RUNTIME_RAM_MB      optional per-job analyze RAM override.
  CODEQL_RUNTIME_THREADS     optional per-job analyze thread override.
  CODEQL_RUNTIME_MAX_DISK_CACHE_MB optional per-job disk cache override.
  CODEQL_ANALYZE_TIMEOUT_SECONDS   analyze timeout (default: 7200 / 2 hours).
  CODEQL_HEAVY_WORKERS       OpenClaw workers (default: 1).
  CODEQL_HEAVY_THREADS       threads for each OpenClaw job (default: 6).
  CODEQL_HEAVY_RAM_MB        RAM for each OpenClaw job (default: 10240).
  CODEQL_HEAVY_MAX_DISK_CACHE_MB disk cache/OpenClaw job (default: 8192).
EOF
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $1" >&2
    exit 2
  fi
}

verify_sha256() {
  local expected="$1"
  local path="$2"
  [[ -f "$path" ]] && printf '%s  %s\n' "$expected" "$path" | sha256sum --check --status
}

install_archive() {
  local label="$1" url="$2" archive="$3" archive_sha="$4"
  local install_root="$5" executable_relative="$6" executable_sha="$7"
  local temporary

  if verify_sha256 "$executable_sha" "$install_root/$executable_relative"; then
    echo "$label is already installed: $install_root/$executable_relative"
    return
  fi
  mkdir -p "$(dirname "$archive")" "$(dirname "$install_root")"
  if ! verify_sha256 "$archive_sha" "$archive"; then
    echo "Downloading pinned $label with resume support..."
    curl --fail --location --retry 8 --retry-all-errors --continue-at - \
      --output "$archive" "$url"
  fi
  printf '%s  %s\n' "$archive_sha" "$archive" | sha256sum --check

  temporary="$(mktemp -d "$(dirname "$install_root")/.install.XXXXXX")"
  trap 'rm -rf -- "$temporary"' RETURN
  tar -xzf "$archive" -C "$temporary"
  printf '%s  %s\n' "$executable_sha" "$temporary/$executable_relative" | sha256sum --check
  if [[ -e "$install_root" ]]; then
    mv "$install_root" "${install_root}.invalid-$(date +%Y%m%d%H%M%S)"
  fi
  mv "$temporary" "$install_root"
  trap - RETURN
  echo "Installed $label: $install_root/$executable_relative"
}

setup() {
  require_command curl
  require_command sha256sum
  require_command tar
  require_command uv
  install_archive "CodeQL $CODEQL_VERSION" "$CODEQL_URL" "$CODEQL_ARCHIVE" \
    "$CODEQL_ARCHIVE_SHA256" "$CODEQL_INSTALL_ROOT" "codeql/codeql" "$CODEQL_BIN_SHA256"
  install_archive "Go $GO_VERSION" "$GO_URL" "$GO_ARCHIVE" \
    "$GO_ARCHIVE_SHA256" "$GO_INSTALL_ROOT" "go/bin/go" "$GO_BIN_SHA256"
  uv sync --extra dev
  "$CODEQL_BIN" version
  "$GO_BIN" version
  echo "Setup complete. Next: bash scripts/codeql_scan_wsl.sh doctor"
}

profile_value() {
  "$UV_PROJECT_ENVIRONMENT/bin/python" - "$PROFILE" "$1" <<'PY'
import json, sys
value = json.loads(open(sys.argv[1], encoding="utf-8").read())
for key in sys.argv[2].split("."):
    value = value[key]
print(value)
PY
}

scan_id() {
  profile_value scan_id
}

plan_path() {
  printf '%s/artifacts/manifests/%s.json\n' "$PROJECT_ROOT" "$(scan_id)"
}

runner() {
  local args=(
    "$UV_PROJECT_ENVIRONMENT/bin/python"
    -m vulngym_enrich.codeql_runner
    --manifest "$MANIFEST"
    --entries "$ENTRIES"
    --profile "$PROFILE"
    --work-root "$WORK_ROOT"
    --runtime-go-version "$GO_VERSION"
    --runtime-go-executable "$GO_BIN"
    --runtime-go-executable-sha256 "$GO_BIN_SHA256"
    --runtime-analyze-timeout-seconds "${CODEQL_ANALYZE_TIMEOUT_SECONDS:-7200}"
  )
  if [[ "${CODEQL_RETRY_FAILED:-1}" == "1" ]]; then
    args+=(--retry-failed)
  fi
  if [[ -n "${CODEQL_RUNTIME_RAM_MB:-}" ]]; then
    args+=(--runtime-analyze-ram-mb "$CODEQL_RUNTIME_RAM_MB")
  fi
  if [[ -n "${CODEQL_RUNTIME_THREADS:-}" ]]; then
    args+=(--runtime-analyze-threads "$CODEQL_RUNTIME_THREADS")
  fi
  if [[ -n "${CODEQL_RUNTIME_MAX_DISK_CACHE_MB:-}" ]]; then
    args+=(--runtime-max-disk-cache-mb "$CODEQL_RUNTIME_MAX_DISK_CACHE_MB")
  fi
  "${args[@]}" "$@"
}

doctor() {
  require_command sha256sum
  require_command findmnt
  if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
    echo "ERROR: expected Linux x86_64" >&2
    exit 2
  fi
  if [[ "$PROJECT_ROOT" == /mnt/* ]]; then
    echo "ERROR: move the project from DrvFS/NTFS to the WSL Linux filesystem" >&2
    exit 2
  fi
  local filesystem_type
  filesystem_type="$(findmnt -n -o FSTYPE -T "$PROJECT_ROOT")"
  if [[ "$filesystem_type" == "9p" || "$filesystem_type" == "drvfs" ]]; then
    echo "ERROR: project filesystem is $filesystem_type; ext4 is required" >&2
    exit 2
  fi
  for path in "$PROFILE" "$MANIFEST" "$ENTRIES"; do
    [[ -f "$path" ]] || { echo "ERROR: missing $path" >&2; exit 2; }
  done
  verify_sha256 "$CODEQL_BIN_SHA256" "$CODEQL_BIN" || {
    echo "ERROR: CodeQL pin is missing/invalid; run setup" >&2; exit 2;
  }
  verify_sha256 "$GO_BIN_SHA256" "$GO_BIN" || {
    echo "ERROR: Go pin is missing/invalid; run setup" >&2; exit 2;
  }
  [[ -x "$UV_PROJECT_ENVIRONMENT/bin/python" ]] || {
    echo "ERROR: Python environment is missing; run setup" >&2; exit 2;
  }

  "$UV_PROJECT_ENVIRONMENT/bin/python" - \
    "$PROJECT_ROOT" "$PROFILE" "$MANIFEST" "$ENTRIES" "$WORK_ROOT" \
    "$filesystem_type" <<'PY'
import hashlib, json, os, subprocess, sys
from pathlib import Path
from vulngym_enrich.codeql_runner import build_job_plan

root, profile_path, manifest_path, entries_path, work_root = (Path(value).resolve() for value in sys.argv[1:6])
filesystem = sys.argv[6]
profile = json.loads(profile_path.read_text(encoding="utf-8"))
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
entries = [json.loads(line) for line in entries_path.read_text(encoding="utf-8").splitlines() if line.strip()]
jobs = build_job_plan(manifest, entries)
missing = sorted({str(work_root / job.repo_slug / job.commit) for job in jobs if not (work_root / job.repo_slug / job.commit).is_dir()})
if missing:
    raise RuntimeError(f"missing {len(missing)} materialized worktrees")
resources = profile["resources"]
workers = int(os.environ.get("CODEQL_WORKERS", resources["worker_concurrency"]))
threads = int(os.environ.get("CODEQL_RUNTIME_THREADS", resources["analyze_threads"]))
ram = int(os.environ.get("CODEQL_RUNTIME_RAM_MB", resources["analyze_ram_mb"]))
cpus = os.cpu_count() or 1
mem_mb = next(int(line.split()[1]) // 1024 for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemTotal:"))
if workers * threads > cpus:
    raise RuntimeError(f"CPU oversubscription: {workers} workers x {threads} threads > {cpus} CPUs")
if mem_mb - workers * ram < 3072:
    raise RuntimeError(f"RAM budget leaves under 3072 MiB for WSL: {mem_mb} - {workers}x{ram}")
for language, pack in profile["query_packs"].items():
    pack_path = root / "cache/tools/codeql" / profile["tool"]["version"] / "codeql/qlpacks" / pack["name"] / pack["version"]
    if not pack_path.is_dir():
        raise RuntimeError(f"missing pinned query pack for {language}: {pack_path}")
print(json.dumps({
    "status": "READY",
    "filesystem": filesystem,
    "profile": str(profile_path.relative_to(root)),
    "scan_id": profile["scan_id"],
    "query_suite": profile["query_suite"],
    "jobs": len(jobs),
    "languages": {language: sum(job.language == language for job in jobs) for language in sorted({job.language for job in jobs})},
    "workers": workers,
    "threads_per_worker": threads,
    "ram_mb_per_worker": ram,
    "logical_cpus": cpus,
    "total_memory_mb": mem_mb,
    "missing_worktrees": len(missing),
}, indent=2))
PY
}

plan() {
  doctor
  runner --plan-only --plan-output "$(plan_path)"
}

pilot() {
  doctor
  runner --pilot --worker-concurrency "${CODEQL_WORKERS:-2}" \
    --plan-output "$PROJECT_ROOT/artifacts/manifests/$(scan_id)-pilot.json"
}

run_main() {
  runner --exclude-language go --exclude-repo-url "$OPENCLAW_URL" \
    --worker-concurrency "${CODEQL_WORKERS:-2}" \
    --plan-output "$PROJECT_ROOT/artifacts/manifests/$(scan_id)-main-selection.json"
}

run_go() {
  runner --language go --worker-concurrency "${CODEQL_GO_WORKERS:-1}" \
    --plan-output "$PROJECT_ROOT/artifacts/manifests/$(scan_id)-go-selection.json"
}

run_heavy() {
  local CODEQL_RUNTIME_THREADS="${CODEQL_RUNTIME_THREADS:-${CODEQL_HEAVY_THREADS:-6}}"
  local CODEQL_RUNTIME_RAM_MB="${CODEQL_RUNTIME_RAM_MB:-${CODEQL_HEAVY_RAM_MB:-10240}}"
  local CODEQL_RUNTIME_MAX_DISK_CACHE_MB="${CODEQL_RUNTIME_MAX_DISK_CACHE_MB:-${CODEQL_HEAVY_MAX_DISK_CACHE_MB:-8192}}"
  runner --repo-url "$OPENCLAW_URL" --exclude-language go \
    --worker-concurrency "${CODEQL_HEAVY_WORKERS:-1}" \
    --plan-output "$PROJECT_ROOT/artifacts/manifests/$(scan_id)-openclaw-selection.json"
}

run_all() {
  doctor
  plan
  local result=0
  run_main || result=$?
  run_go || result=$?
  run_heavy || result=$?
  return "$result"
}

status() {
  local selected_scan_id scan_root full_plan
  selected_scan_id="$(scan_id)"
  scan_root="$PROJECT_ROOT/artifacts/scans/$selected_scan_id"
  full_plan="$(plan_path)"
  "$UV_PROJECT_ENVIRONMENT/bin/python" - "$scan_root" "$full_plan" "$selected_scan_id" <<'PY'
import json, os, sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

scan_root, plan_path, scan_id = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
plan = json.loads(plan_path.read_text(encoding="utf-8")) if plan_path.exists() else {"jobs": []}

def subprocess_output():
    import subprocess
    patterns = (
        "[v]ulngym-codeql",
        "[v]ulngym_enrich.codeql_runner",
        "[c]odeql database",
    )
    rows = []
    for pattern in patterns:
        result = subprocess.run(
            ["pgrep", "-af", pattern],
            check=False,
            capture_output=True,
            text=True,
        )
        rows.extend(result.stdout.splitlines())
    return sorted(set(rows))

rows = []
for pointer_path in scan_root.glob("*/*/codeql/**/status.json") if scan_root.exists() else []:
    if "attempts" in pointer_path.parts:
        continue
    try:
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
        attempt = json.loads((pointer_path.parent / pointer["attempt_status"]).read_text(encoding="utf-8"))
    except (OSError, KeyError, json.JSONDecodeError):
        continue
    rows.append((pointer, attempt))
counts = Counter(str(pointer.get("status") or "UNKNOWN") for pointer, _ in rows)
planned = int(plan.get("job_count") or len(plan.get("jobs") or []))
finished = counts["SUCCESS"] + counts["FAILED"] + counts["TIMEOUT"]
active = bool(subprocess_output())
print(f"CodeQL   {scan_id}")
print(f"Process  {'ACTIVE' if active else 'STOPPED'}")
print(f"Progress {finished}/{planned} ({100.0 * finished / planned if planned else 0:.1f}%)")
print(f"Jobs     SUCCESS={counts['SUCCESS']} RUNNING={counts['RUNNING']} FAILED={counts['FAILED']} TIMEOUT={counts['TIMEOUT']}")
now = datetime.now(timezone.utc)
running = [(p, a) for p, a in rows if p.get("status") == "RUNNING"]
if running:
    print("Current")
    for pointer, attempt in running[:4]:
        try:
            elapsed = (now - datetime.fromisoformat(attempt["started_at"])).total_seconds()
        except (KeyError, ValueError):
            elapsed = 0
        hours, rem = divmod(max(0, int(elapsed)), 3600)
        minutes, seconds = divmod(rem, 60)
        print(f"  {pointer.get('repo_url','').rsplit('/',1)[-1]}@{pointer.get('commit','')[:8]} {pointer.get('language')} elapsed={hours:02d}:{minutes:02d}:{seconds:02d}")
PY
}

monitor() {
  local interval="${CODEQL_MONITOR_INTERVAL:-5}"
  [[ "$interval" =~ ^[1-9][0-9]*$ ]] || { echo "ERROR: invalid monitor interval" >&2; exit 2; }
  while true; do
    printf '\033[2J\033[H'
    date '+Updated  %Y-%m-%d %H:%M:%S %Z'
    status
    printf '\nCtrl+C stops monitoring only.\n'
    sleep "$interval"
  done
}

normalize() {
  doctor
  "$UV_PROJECT_ENVIRONMENT/bin/python" -m vulngym_enrich.codeql_pipeline \
    --plan "$(plan_path)" \
    --scan-root "$PROJECT_ROOT/artifacts/scans/$(scan_id)" \
    --entries "$ENTRIES" \
    --output-dir "$PROJECT_ROOT/artifacts/normalized/$(scan_id)"
}

action="${1:-}"
case "$action" in
  setup) setup ;;
  doctor) doctor ;;
  plan) plan ;;
  pilot) pilot ;;
  run-main) doctor; run_main ;;
  run-go) doctor; run_go ;;
  run-heavy) doctor; run_heavy ;;
  run) run_all ;;
  status) status ;;
  monitor) monitor ;;
  normalize) normalize ;;
  *) usage; exit 2 ;;
esac
