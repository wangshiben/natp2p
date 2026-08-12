#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
source "$ROOT_DIR/test/runtimeScript/local-chaos-stability.sh"

test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
run_dir=$test_dir/run
mkdir -p "$run_dir"
printf 'timestamp\ttransfer_id\n' > "$run_dir/transfers.tsv"

fail() {
  printf 'failure-watcher gate regression failed: %s\n' "$1" >&2
  exit 1
}

write_status() {
  local status=$1 heartbeat=$2 available=$3 size=$4 offset=$5 failures=$6
  local temporary=$run_dir/failure-watcher.status.tmp
  printf 'schema_version=1\nstatus=%s\nheartbeat_epoch=%s\nsource_available=%s\nsource_size_bytes=%s\nsource_offset_bytes=%s\nnew_failure_records=%s\n' \
    "$status" "$heartbeat" "$available" "$size" "$offset" "$failures" > "$temporary"
  mv "$temporary" "$run_dir/failure-watcher.status"
}

expect_failure() {
  local expected_detail=$1
  shift
  if "$@"; then
    fail "expected $expected_detail but check passed"
  fi
  [[ $FAILURE_WATCHER_DETAIL == "$expected_detail" ]] \
    || fail "expected $expected_detail, got ${FAILURE_WATCHER_DETAIL:-empty}"
}

now_epoch=$(date +%s)
source_size=$(stat -c %s "$run_dir/transfers.tsv")
write_status RUNNING "$now_epoch" 1 "$source_size" "$source_size" 0
inspect_failure_watcher "$run_dir" "$$" "$now_epoch" 0 \
  || fail "healthy watcher was rejected: $FAILURE_WATCHER_DETAIL"

race_stop=$test_dir/status-race-stop
(
  while [[ ! -e $race_stop ]]; do
    write_status RUNNING "$now_epoch" 1 100 100 0
    write_status RUNNING "$now_epoch" 1 200 200 0
  done
) &
race_writer_pid=$!
race_failure=
for _ in $(seq 1 200); do
  if ! inspect_failure_watcher "$run_dir" "$$" "$now_epoch" 0 1; then
    race_failure=$FAILURE_WATCHER_DETAIL
    break
  fi
done
: > "$race_stop"
wait "$race_writer_pid"
[[ -z $race_failure ]] \
  || fail "atomic status replacement produced a mixed snapshot: $race_failure"

write_status RUNNING "$now_epoch" 1 100 200 0
expect_failure failure_watcher_status_invalid \
  inspect_failure_watcher "$run_dir" "$$" "$now_epoch" 0

write_status RUNNING "$now_epoch" 1 "$source_size" "$source_size" 0

printf '{"status":"FAILURE_DETECTED"}\n' > "$run_dir/failure-watcher.alert"
expect_failure transfer_failure_detected \
  inspect_failure_watcher "$run_dir" "$$" "$now_epoch" 0
rm -f "$run_dir/failure-watcher.alert"

write_status RUNNING "$now_epoch" 1 "$source_size" "$source_size" 1
expect_failure transfer_failure_detected \
  inspect_failure_watcher "$run_dir" "$$" "$now_epoch" 0

write_status FAILED "$now_epoch" 1 "$source_size" "$source_size" 0
expect_failure failure_watcher_failed \
  inspect_failure_watcher "$run_dir" "$$" "$now_epoch" 0

write_status STARTING "$now_epoch" 1 "$source_size" "$source_size" 0
expect_failure failure_watcher_unhealthy_status \
  inspect_failure_watcher "$run_dir" "$$" "$now_epoch" 0

write_status RUNNING "$((now_epoch - 16))" 1 "$source_size" "$source_size" 0
expect_failure failure_watcher_heartbeat_stale \
  inspect_failure_watcher "$run_dir" "$$" "$now_epoch" 0

write_status RUNNING "$now_epoch" 0 "$source_size" "$source_size" 0
expect_failure failure_watcher_source_unavailable \
  inspect_failure_watcher "$run_dir" "$$" "$now_epoch" 0

write_status RUNNING "$now_epoch" 1 "$source_size" "$((source_size - 1))" 0
inspect_failure_watcher "$run_dir" "$$" "$now_epoch" 0 \
  || fail "transient source lag was rejected: $FAILURE_WATCHER_DETAIL"
lag_since=$FAILURE_WATCHER_LAG_SINCE
write_status RUNNING "$((now_epoch + 1))" 1 "$source_size" "$source_size" 0
inspect_failure_watcher "$run_dir" "$$" "$((now_epoch + 1))" 0 0 "$lag_since" \
  || fail "recovered source lag was rejected: $FAILURE_WATCHER_DETAIL"
(( FAILURE_WATCHER_LAG_SINCE == 0 )) || fail "recovered source lag did not reset its grace window"
write_status RUNNING "$now_epoch" 1 "$source_size" "$((source_size - 1))" 0
inspect_failure_watcher "$run_dir" "$$" "$now_epoch" 0 \
  || fail "source lag grace period did not start: $FAILURE_WATCHER_DETAIL"
lag_since=$FAILURE_WATCHER_LAG_SINCE
inspect_failure_watcher "$run_dir" "$$" "$((now_epoch + 14))" 0 0 "$lag_since" \
  || fail "source lag grace period ended too early: $FAILURE_WATCHER_DETAIL"
expect_failure failure_watcher_source_lag \
  inspect_failure_watcher "$run_dir" "$$" "$((now_epoch + 15))" 0 0 "$lag_since"

write_status DEGRADED "$now_epoch" 1 "$source_size" "$source_size" 0
inspect_failure_watcher "$run_dir" "$$" "$now_epoch" 0 \
  || fail "transient DEGRADED state was rejected: $FAILURE_WATCHER_DETAIL"
degraded_since=$FAILURE_WATCHER_DEGRADED_SINCE
inspect_failure_watcher "$run_dir" "$$" "$((now_epoch + 14))" "$degraded_since" \
  || fail "DEGRADED grace period ended too early: $FAILURE_WATCHER_DETAIL"
expect_failure failure_watcher_degraded \
  inspect_failure_watcher "$run_dir" "$$" "$((now_epoch + 15))" "$degraded_since"

write_status RUNNING "$now_epoch" 1 0 0 0
(
  sleep 0.1
  final_size=$(stat -c %s "$run_dir/transfers.tsv")
  write_status RUNNING "$(date +%s)" 1 "$final_size" "$final_size" 0
) &
updater_pid=$!
wait_failure_watcher_caught_up "$run_dir" "$$" 2 0 0.02 \
  || fail "final cursor did not catch up: $FAILURE_WATCHER_DETAIL"
wait "$updater_pid"

recovery_marker=$test_dir/watcher-recovered
write_status DEGRADED "$(date +%s)" 1 "$source_size" "$source_size" 0
(
  sleep 0.1
  : > "$recovery_marker"
  write_status RUNNING "$(date +%s)" 1 "$source_size" "$source_size" 0
) &
updater_pid=$!
wait_failure_watcher_caught_up "$run_dir" "$$" 2 0 0.02 \
  || fail "final gate did not recover from transient DEGRADED: $FAILURE_WATCHER_DETAIL"
[[ -f $recovery_marker ]] || fail "final gate accepted DEGRADED before recovery"
wait "$updater_pid"

write_status RUNNING "$(date +%s)" 1 "$source_size" "$source_size" 1
expect_failure transfer_failure_detected \
  wait_failure_watcher_caught_up "$run_dir" "$$" 1 0 0.02

printf 'failure-watcher gate regression passed\n'
