#!/usr/bin/env bash
set -euo pipefail

UNIT="vulngym-codeql-wsl-batch.service"
RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
LOCK_PATH="$RUNTIME_DIR/vulngym-codeql-wsl-batch.keepalive.lock"

# A single long-lived WSL client keeps the distro alive while the batch runs.
# flock makes repeated launches harmless: only one keepalive owns the service.
exec 9>"$LOCK_PATH"
if ! flock -n 9; then
  echo "CodeQL WSL keepalive is already running."
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
