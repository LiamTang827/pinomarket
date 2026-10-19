#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if command -v go >/dev/null 2>&1; then
  exec go "$@"
elif [ -x "$root/.tools/go/bin/go" ]; then
  exec "$root/.tools/go/bin/go" "$@"
fi
printf '%s\n' 'Install Go >=1.23 from https://go.dev/dl/ and retry.' >&2
exit 1
