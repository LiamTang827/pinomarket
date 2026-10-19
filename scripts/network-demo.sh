#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
output=${1:-runs/live-demo}
fault=${2:-offline}
case "$fault" in normal|offline|omission|withhold) ;; *) printf '%s\n' 'Fault must be normal, offline, omission, or withhold.' >&2; exit 1;; esac
if [ -e "$output" ]; then printf '%s\n' 'Choose a new output directory.' >&2; exit 1; fi
mkdir -p bin
./scripts/go.sh build -o bin/pinocchio ./cmd/pinocchio
binary="$root/bin/pinocchio"
"$binary" network init -dir "$output" -window-blocks 30 -block-interval 300ms
pids=""
cleanup() {
  trap - EXIT HUP INT TERM
  for pid in $pids; do kill -TERM "$pid" 2>/dev/null || true; done
  for pid in $pids; do wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT HUP INT TERM
for i in 0 1 2 3 4; do
  extra=""
  if [ "$i" = 0 ] && [ "$fault" = omission ]; then extra="-omit-list"; fi
  if [ "$i" = 0 ] && [ "$fault" = withhold ]; then extra="-withhold-shares"; fi
  "$binary" network node -config "$output/node$i.json" $extra > "$output/node$i.log" 2>&1 &
  pid=$!
  pids="$pids $pid"
  if [ "$i" = 4 ]; then last_pid=$pid; fi
done
"$binary" network ready -dir "$output" -timeout 60s
if [ "$fault" = offline ] || [ "$fault" = omission ]; then
  kill -TERM "$last_pid"
  wait "$last_pid" 2>/dev/null || true
  remaining=""
  for pid in $pids; do if [ "$pid" != "$last_pid" ]; then remaining="$remaining $pid"; fi; done
  pids=$remaining
  printf '%s\n' 'Stopped the fifth validator; four remain.'
fi
"$binary" network open -dir "$output"
"$binary" network submit -dir "$output" -owner alice -quantity 4 -nonce 0 -out "$output/alice-receipt.json"
"$binary" network submit -dir "$output" -owner bob -quantity 3 -nonce 0 -out "$output/bob-receipt.json"
"$binary" network submit -dir "$output" -owner carol -quantity 3 -nonce 0 -out "$output/carol-receipt.json"
"$binary" network wait -dir "$output" -processed 3 -timeout 120s
"$binary" network audit -dir "$output" -out "$output/audit.json" -timeout 120s
printf '\n%s\n' "Actual validator processes completed. Audit and logs: $output"
