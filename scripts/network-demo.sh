#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
output=${1:-runs/aion-demo}
if [ -e "$output" ]; then printf '%s\n' 'Choose a new output directory.' >&2; exit 1; fi
mkdir -p bin
./scripts/go.sh build -o bin/pinocchio ./cmd/pinocchio
binary="$root/bin/pinocchio"
"$binary" network init -dir "$output" -window-blocks 30 -block-interval 300ms -ordering aion -ingress software
pids=""
cleanup() {
  trap - EXIT HUP INT TERM
  for pid in $pids; do kill -TERM "$pid" 2>/dev/null || true; done
  for pid in $pids; do wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT HUP INT TERM
for i in 0 1 2 3 4; do
  "$binary" network node -config "$output/node$i.json" > "$output/node$i.log" 2>&1 &
  pid=$!
  pids="$pids $pid"
done
"$binary" network ready -dir "$output" -timeout 60s
"$binary" network open -dir "$output"
# Send Bob first to distinguish certified time order from alphabetical owner order.
"$binary" network submit -dir "$output" -owner bob -quantity 3 -nonce 0 -out "$output/bob-receipt.json"
"$binary" network submit -dir "$output" -owner alice -quantity 4 -nonce 0 -out "$output/alice-receipt.json"
"$binary" network submit -dir "$output" -owner carol -quantity 3 -nonce 0 -out "$output/carol-receipt.json"
"$binary" network wait -dir "$output" -processed 3 -timeout 120s
"$binary" network audit -dir "$output" -out "$output/audit.json" -timeout 120s
printf '\n%s\n' "Actual validator processes completed. Audit and logs: $output"
