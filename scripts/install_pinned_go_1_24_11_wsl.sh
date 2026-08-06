#!/usr/bin/env bash
set -euo pipefail

VERSION="1.24.11"
ARCHIVE="go${VERSION}.linux-amd64.tar.gz"
URL="https://go.dev/dl/${ARCHIVE}"
ARCHIVE_SHA256="bceca00afaac856bc48b4cc33db7cd9eb383c81811379faed3bdbc80edb0af65"
TARGET_ROOT="$HOME/.local/share/vulngym-codeql/tools/go/$VERSION"
GO_EXECUTABLE="$TARGET_ROOT/go/bin/go"

if [[ -x "$GO_EXECUTABLE" ]]; then
  actual_version="$($GO_EXECUTABLE version)"
  if [[ "$actual_version" != go\ version\ go${VERSION}\ linux/amd64 ]]; then
    echo "Existing Go runtime has an unexpected version: $actual_version" >&2
    exit 3
  fi
else
  if [[ -e "$TARGET_ROOT" ]]; then
    echo "Refusing to overwrite incomplete runtime directory: $TARGET_ROOT" >&2
    exit 4
  fi
  temporary="$(mktemp -d)"
  trap 'rm -rf -- "$temporary"' EXIT
  curl -fL --retry 3 --output "$temporary/$ARCHIVE" "$URL"
  echo "$ARCHIVE_SHA256  $temporary/$ARCHIVE" | sha256sum -c -
  mkdir -p "$TARGET_ROOT"
  tar -xzf "$temporary/$ARCHIVE" -C "$TARGET_ROOT"
fi

echo "version=$VERSION"
echo "executable=$GO_EXECUTABLE"
echo "executable_sha256=$(sha256sum "$GO_EXECUTABLE" | cut -d' ' -f1)"
echo "archive_url=$URL"
echo "archive_sha256=$ARCHIVE_SHA256"
