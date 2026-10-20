#!/bin/sh
# Paired local functional measurements; never provisions cloud infrastructure.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
output=${1:-runs/ordering-experiment}
fault=${2:-normal}
repetitions=${3:-1}
case "$fault" in normal|offline|omission|withhold|delay) ;; *) printf '%s\n' 'Use normal, offline, omission, withhold or delay.'; exit 1;; esac
case "$repetitions" in 1|2|3|4|5) ;; *) printf '%s\n' 'Use 1 to 5 repetitions.'; exit 1;; esac
if [ -e "$output" ]; then printf '%s\n' 'Choose a new output directory.'; exit 1; fi
command -v python3 >/dev/null 2>&1 || { printf '%s\n' 'Python 3 is required for raw-metrics aggregation.'; exit 1; }
mkdir -p "$(dirname -- "$output")"
mkdir "$output"
if [ -n "${PINOCCHIO_BINARY:-}" ]; then
  binary=$PINOCCHIO_BINARY
else
  mkdir -p bin
  ./scripts/go.sh build -o bin/pinocchio ./cmd/pinocchio
  binary="$root/bin/pinocchio"
fi
pids=""
cleanup() {
  for pid in $pids; do kill -TERM "$pid" 2>/dev/null || true; done
  for pid in $pids; do wait "$pid" 2>/dev/null || true; done
  pids=""
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
failed=0
rep=1
while [ "$rep" -le "$repetitions" ]; do
  # Alternate order to reduce a fixed warm-cache advantage for either mode.
  modes="identity median-receipts"
  if [ $((rep % 2)) -eq 0 ]; then modes="median-receipts identity"; fi
  for mode in $modes; do
    run="$output/$mode-$rep"
    network="$run/network"
    mkdir "$run"
    "$binary" network init -dir "$network" -ordering "$mode" -base-port "${PINOCCHIO_BASE_PORT:-38656}" -api-port "${PINOCCHIO_API_PORT:-39600}" -window-blocks 30 -block-interval 300ms > "$run/init.log"
    for i in 0 1 2 3 4; do
      extra=""
      if [ "$i" = 0 ]; then
        case "$fault" in omission) extra="-omit-list";; withhold) extra="-withhold-shares";; delay) extra="-delay-ms 500";; esac
      fi
      "$binary" network node -config "$network/node$i.json" $extra > "$run/node$i.log" 2>&1 &
      pid=$!
      pids="$pids $pid"
      if [ "$i" = 4 ]; then last_pid=$pid; fi
    done
    "$binary" network ready -dir "$network" -timeout 60s
    if [ "$fault" = offline ] || [ "$fault" = omission ]; then
      kill -TERM "$last_pid"
      wait "$last_pid" 2>/dev/null || true
      remaining=""
      for pid in $pids; do if [ "$pid" != "$last_pid" ]; then remaining="$remaining $pid"; fi; done
      pids=$remaining
    fi
    if "$binary" network measure -dir "$network" -out "$run/measurement" -count 3 -quantity 1 -timeout 120s > "$run/client.log" 2>&1; then
      printf '%s\n' "$mode repetition $rep: measured and audited"
    else
      failed=1
      printf '%s\n' "$mode repetition $rep: failed; raw logs and incomplete metrics retained"
    fi
    cleanup
  done
  rep=$((rep+1))
done
python3 - "$output" "$fault" <<'PY'
import hashlib, json, pathlib, sys
root=pathlib.Path(sys.argv[1])
runs=[]
for run in sorted(p for p in root.iterdir() if p.is_dir()):
    path=run/'measurement'/'metrics.json'
    if path.exists():
        data=json.loads(path.read_text())
        runs.append({'run':run.name,'metrics':data,'metrics_sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    else:
        runs.append({'run':run.name,'error':'no metrics produced; inspect client.log'})
sources={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for folder in ('internal/live','internal/consensus','protocol','threshold') for p in sorted(pathlib.Path(folder).glob('*.go'))}
report={'schema':1,'fault':sys.argv[2],'runs':runs,'source_sha256':sources,'limitations':'Local paired functional measurements, independent randomized keys and consensus schedules. Not AOAB replication, not matched WAN traces or a statistical performance claim. All submitted and incomplete samples retained. Network subdirectories contain private demo keys; share summary and measurement files only.'}
with (root/'summary.json').open('x') as f:
    json.dump(report,f,ensure_ascii=False,indent=2);f.write('\n')
print(root/'summary.json')
PY
exit "$failed"
