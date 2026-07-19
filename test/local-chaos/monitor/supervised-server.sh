#!/usr/bin/env bash

set -uo pipefail

: "${MONITOR_SERVER:?MONITOR_SERVER is required}"
: "${RUNNER_PID:?RUNNER_PID is required}"
: "${RUNNER_STARTTIME:?RUNNER_STARTTIME is required}"

child_pid=

runner_is_alive() {
  local current_start
  [[ -r /proc/$RUNNER_PID/stat ]] || return 1
  current_start=$(awk '{print $22}' "/proc/$RUNNER_PID/stat" 2>/dev/null || true)
  [[ $current_start == "$RUNNER_STARTTIME" ]]
}

cleanup() {
  trap - EXIT INT TERM HUP
  if [[ -n $child_pid ]] && kill -0 "$child_pid" 2>/dev/null; then
    kill -TERM "$child_pid" 2>/dev/null || true
    for _ in $(seq 1 20); do
      kill -0 "$child_pid" 2>/dev/null || break
      sleep 0.1
    done
    kill -KILL "$child_pid" 2>/dev/null || true
  fi
  [[ -z $child_pid ]] || wait "$child_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM HUP

node "$MONITOR_SERVER" &
child_pid=$!

while runner_is_alive && kill -0 "$child_pid" 2>/dev/null; do
  sleep 5
done
