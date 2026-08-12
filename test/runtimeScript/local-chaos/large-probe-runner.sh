#!/usr/bin/env bash

set -uo pipefail

: "${ROOT_DIR:?ROOT_DIR is required}"
: "${RUN_DIR:?RUN_DIR is required}"
: "${COMPOSE_FILE:?COMPOSE_FILE is required}"
: "${COMPOSE_PROJECT:?COMPOSE_PROJECT is required}"
: "${RUNNER_PID:?RUNNER_PID is required}"
: "${RUNNER_STARTTIME:?RUNNER_STARTTIME is required}"

RUNTIME_DIR=${RUNTIME_DIR:-$RUN_DIR/runtime}
INTERVAL_SECONDS=${LARGE_PROBE_INTERVAL_SECONDS:-60}
FAILURE_LIMIT=${LARGE_PROBE_FAILURE_LIMIT:-3}
export ROOT_DIR RUN_DIR RUNTIME_DIR COMPOSE_FILE COMPOSE_PROJECT

source "$ROOT_DIR/test/runtimeScript/local-chaos/lib.sh"
source "$RUN_DIR/workload.env"

runner_is_alive() {
  local current_start
  [[ -r /proc/$RUNNER_PID/stat ]] || return 1
  current_start=$(awk '{print $22}' "/proc/$RUNNER_PID/stat" 2>/dev/null || true)
  [[ $current_start == "$RUNNER_STARTTIME" ]]
}

if [[ ! -s $RUN_DIR/large-probes.tsv ]]; then
  printf 'timestamp\tlabel\trequested_mib\trc\tbytes\tseconds\tmib_per_second\tsha256_ok\tclient\texpected_sha\tactual_sha\n' \
    > "$RUN_DIR/large-probes.tsv"
fi

sequence=$(( $(wc -l < "$RUN_DIR/large-probes.tsv") ))
failures=0
printf 'RUNNING started=%s interval_seconds=%s range_mib=100-200\n' \
  "$(date --iso-8601=seconds)" "$INTERVAL_SECONDS" > "$RUN_DIR/large-probe.status"

while runner_is_alive; do
  sequence=$((sequence + 1))
  if large_probe_once "$RUN_DIR" "$server" "$client" "$listen_port" "large_$sequence"; then
    failures=0
  else
    failures=$((failures + 1))
    printf 'DEGRADED timestamp=%s consecutive_failures=%s limit=%s\n' \
      "$(date --iso-8601=seconds)" "$failures" "$FAILURE_LIMIT" > "$RUN_DIR/large-probe.status"
    if (( failures >= FAILURE_LIMIT )); then
      printf 'FAILED\n' > "$RUN_DIR/phase"
      printf 'outcome=FAILED\ndetail=three_consecutive_large_probe_failures\nfinished_epoch=%s\n' \
        "$(date +%s)" > "$RUN_DIR/status.env"
      kill -TERM -- "-$RUNNER_PID" 2>/dev/null || kill -TERM "$RUNNER_PID" 2>/dev/null || true
      exit 1
    fi
  fi

  slept=0
  while (( slept < INTERVAL_SECONDS )) && runner_is_alive; do
    sleep 1
    slept=$((slept + 1))
  done
done

printf 'RUNNER_EXITED timestamp=%s\n' "$(date --iso-8601=seconds)" > "$RUN_DIR/large-probe.status"
