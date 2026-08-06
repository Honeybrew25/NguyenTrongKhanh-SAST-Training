#!/usr/bin/env bash
set -euo pipefail

MODE="${1:---dry-run}"
if [[ "$MODE" != "--dry-run" && "$MODE" != "--apply" ]]; then
  echo "usage: $0 [--dry-run|--apply]" >&2
  exit 2
fi

ROOT="$HOME/.cache/vulngym-codeql-wsl-v1/worktrees/milvus-io__milvus"
COMMITS=(
  2fad5b34f7d3cf44cf0436ae7f1f31fabf17b6a0
  5519df6efc738abadf46b23cf63b51a2145146d5
)
AUTOBUILD_TRACKED_PATHS=(
  go.mod
  go.sum
  client/go.mod
  tests/go_client/go.mod
  tests/go_client/go.sum
)

if pgrep -af 'codeql database (analyze|create)|vulngym_enrich\.codeql_runner' >/dev/null; then
  echo "Refusing cleanup while a CodeQL process is running." >&2
  exit 3
fi

for commit in "${COMMITS[@]}"; do
  worktree="$ROOT/$commit"
  resolved_worktree="$(realpath -e -- "$worktree")"
  case "$resolved_worktree" in
    "$ROOT"/*) ;;
    *)
      echo "Unsafe worktree path: $resolved_worktree" >&2
      exit 4
      ;;
  esac

  mapfile -t dirty < <(
    git -C "$resolved_worktree" status \
      --porcelain=v1 \
      --untracked-files=all \
      --ignored=matching
  )
  unexpected=()
  for row in "${dirty[@]}"; do
    if [[ "$row" != "?? .vulngym-snapshot.json" &&
          "$row" != "!! cmake_build/thirdparty/"* &&
          "$row" != " M go.mod" &&
          "$row" != " M go.sum" &&
          "$row" != " M client/go.mod" &&
          "$row" != " M tests/go_client/go.mod" &&
          "$row" != " M tests/go_client/go.sum" ]]; then
      unexpected+=("$row")
    fi
  done
  if ((${#unexpected[@]} > 0)); then
    printf 'Refusing cleanup; unexpected worktree changes in %s:\n' "$commit" >&2
    printf '  %s\n' "${unexpected[@]}" >&2
    exit 5
  fi

  tracked_autobuild_changes=()
  for relative_path in "${AUTOBUILD_TRACKED_PATHS[@]}"; do
    if ! git -C "$resolved_worktree" diff --quiet -- "$relative_path"; then
      tracked_autobuild_changes+=("$relative_path")
    fi
  done
  if ((${#tracked_autobuild_changes[@]} > 0)); then
    if [[ "$MODE" == "--apply" ]]; then
      git -C "$resolved_worktree" restore \
        --source=HEAD \
        --worktree \
        -- "${tracked_autobuild_changes[@]}"
      printf 'Restored CodeQL autobuild changes: %s\n' \
        "${tracked_autobuild_changes[*]}"
    else
      printf 'Would restore CodeQL autobuild changes: %s\n' \
        "${tracked_autobuild_changes[*]}"
    fi
  fi

  target="$resolved_worktree/cmake_build/thirdparty"
  echo "=== $commit ==="
  if [[ ! -e "$target" ]]; then
    echo "Already clean: $target"
    continue
  fi
  resolved_target="$(realpath -e -- "$target")"
  if [[ "$resolved_target" != "$target" ]]; then
    echo "Refusing cleanup; target is redirected: $resolved_target" >&2
    exit 6
  fi
  du -sh -- "$target"
  if [[ "$MODE" == "--apply" ]]; then
    rm -rf -- "$target"
    echo "Removed generated cache: $target"
  else
    echo "Would remove generated cache: $target"
  fi
done

if [[ "$MODE" == "--apply" ]]; then
  for commit in "${COMMITS[@]}"; do
    worktree="$ROOT/$commit"
    remaining="$(
      git -C "$worktree" status \
        --porcelain=v1 \
        --untracked-files=all \
        --ignored=matching |
        grep -vFx '?? .vulngym-snapshot.json' || true
    )"
    if [[ -n "$remaining" ]]; then
      echo "Worktree remains dirty after cleanup: $worktree" >&2
      exit 7
    fi
  done
  echo "Both Milvus worktrees are clean."
fi
