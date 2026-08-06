#!/usr/bin/env bash
set -euo pipefail

UNIT="vulngym-codeql-openclaw-wsl-batch.service"
RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
LOCK_PATH="$RUNTIME_DIR/vulngym-codeql-openclaw-wsl-batch.keepalive.lock"

# Keep one WSL client alive until the dedicated OpenClaw service finishes.
exec 9>"$LOCK_PATH"
if ! flock -n 9; then
  echo "CodeQL OpenClaw WSL keepalive is already running."
  exit 0
fi

systemctl --user start "$UNIT"

while true; do
  state="$(systemctl --user show "$UNIT" -p ActiveState --value)"
  case "$state" in
    active|activating|reloading)
      sleep 30
      ;;
    *)
      break
      ;;
  esac
done

systemctl --user show "$UNIT" \
  -p ActiveState \
  -p SubState \
  -p Result \
  -p ExecMainStatus \
  --no-pager
