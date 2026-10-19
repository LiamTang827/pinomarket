#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
output=${1:-runs/v02-demo}
if [ -e "$output" ]; then
  printf '%s\n' 'Output already exists. Choose a new directory.' >&2
  exit 1
fi
binary=$(mktemp "${TMPDIR:-/tmp}/pinocchio-demo.XXXXXX")
trap 'rm -f "$binary"' EXIT HUP INT TERM
./scripts/go.sh build -o "$binary" ./cmd/pinocchio
for scenario in normal delay omission refusal equivocation late capacity funds cancel duplicate corrupt drop; do
  "$binary" run -scenario "$scenario" -out "$output/$scenario"
  "$binary" audit -file "$output/$scenario/report.json"
  "$binary" replay -file "$output/$scenario/report.json"
done
printf '\n%s\n' "All 12 scenarios passed artifact auditing and semantic replay. Results: $output"
