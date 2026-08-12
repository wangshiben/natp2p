#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
source "$ROOT_DIR/test/runtimeScript/local-chaos-stability.sh"
source "$ROOT_DIR/test/runtimeScript/local-chaos/lib.sh"

test_root=$(mktemp -d)
run_dir=$test_root/run
watcher_pid=
blocked_group_pid=
blocked_dc_pid_file=$test_root/blocked-dc.pid
cleanup_group_pids=()

cleanup() {
  local group_pid
  for group_pid in "${cleanup_group_pids[@]}"; do
    [[ $group_pid =~ ^[1-9][0-9]*$ ]] || continue
    kill -KILL -- "-$group_pid" 2>/dev/null || true
    kill -KILL "$group_pid" 2>/dev/null || true
  done
  if [[ $blocked_group_pid =~ ^[1-9][0-9]*$ ]]; then
    kill -KILL -- "-$blocked_group_pid" 2>/dev/null || true
    kill -KILL "$blocked_group_pid" 2>/dev/null || true
  fi
  if [[ -s $blocked_dc_pid_file ]]; then
    kill -KILL "$(cat "$blocked_dc_pid_file")" 2>/dev/null || true
  fi
  if [[ $watcher_pid =~ ^[1-9][0-9]*$ ]]; then
    kill -TERM "$watcher_pid" 2>/dev/null || true
    wait "$watcher_pid" 2>/dev/null || true
  fi
  rm -rf "$test_root"
}
trap cleanup EXIT

fail() {
  printf 'random transfer deadline regression failed: %s\n' "$1" >&2
  exit 1
}

wait_until() {
  local description=$1
  shift
  local attempt
  for attempt in $(seq 1 200); do
    if "$@"; then
      return 0
    fi
    sleep 0.05
  done
  fail "timed out waiting for $description"
}

watcher_running() {
  [[ -s $run_dir/failure-watcher.status ]] \
    && grep -q '^status=RUNNING$' "$run_dir/failure-watcher.status"
}

watcher_caught_up_with_failures() {
  local expected_failures=$1 source_size source_offset actual_size
  [[ -s $run_dir/failure-watcher.status ]] || return 1
  source_size=$(awk -F= '$1 == "source_size_bytes" { print $2 }' "$run_dir/failure-watcher.status")
  source_offset=$(awk -F= '$1 == "source_offset_bytes" { print $2 }' "$run_dir/failure-watcher.status")
  actual_size=$(stat -c %s "$run_dir/transfers.tsv")
  [[ $source_size == "$actual_size" && $source_offset == "$actual_size" ]] || return 1
  grep -q "^new_failure_records=$expected_failures$" "$run_dir/failure-watcher.status"
}

process_exited() {
  ! kill -0 "$1" 2>/dev/null
}

worker_group_exited() {
  local group_id=$1 child_pid=$2
  ! kill -0 -- "-$group_id" 2>/dev/null && ! kill -0 "$child_pid" 2>/dev/null
}

track_test_worker() {
  local pid=$1 token=$2 attempt
  for attempt in $(seq 1 50); do
    if track_random_worker "$pid" "$token"; then
      return 0
    fi
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.02
  done
  fail "unable to track worker process group for PID $pid"
}

mkdir -p "$run_dir/transfer-records" "$run_dir/transfer-errors"
printf 'RUNNING\n' > "$run_dir/phase"
printf 'server\tingress_relay\tnode_id\nnatserver01\trelay02\ttest-node\n' > "$run_dir/server-pool.tsv"
printf 'timestamp\ttransfer_id\tclient\tingress_relay\tserver\trequested_mib\trc\tbytes\tseconds\tmib_per_second\tsha256_ok\texpected_sha\tactual_sha\n' \
  > "$run_dir/transfers.tsv"
printf 'timestamp\tlabel\trequested_mib\trc\tbytes\tseconds\tmib_per_second\tsha256_ok\tclient\texpected_sha\tactual_sha\n' \
  > "$run_dir/large-probes.tsv"

env RUN_DIR="$run_dir" WATCH_PID="$$" POLL_INTERVAL_MS=50 HEARTBEAT_INTERVAL_MS=100 \
  node "$ROOT_DIR/test/runtimeScript/local-chaos/monitor/failure-watcher.mjs" \
  > "$test_root/failure-watcher.log" 2>&1 &
watcher_pid=$!
wait_until 'failure watcher startup' watcher_running

expected_sha=$(printf '%064d' 0)
[[ $(random_worker_drain_timeout_seconds 180) == 185 ]] \
  || fail 'worker drain is not derived from attempt SLA plus stop grace'
[[ $(validation_mode_attempt_timeout_seconds full) == 900 \
  && $(validation_mode_attempt_timeout_seconds smoke) == 180 ]] \
  || fail 'validation modes do not retain their explicit attempt SLAs'

records_before_boundary=$(find "$run_dir/transfer-records" -mindepth 1 -maxdepth 1 -type f | wc -l)
random_client_worker "$run_dir" natclient01 relay01 18101 "$(( $(date +%s) - 1 ))" 1 1 2 \
  || fail 'expired workload admission deadline failed cleanly'
records_after_boundary=$(find "$run_dir/transfer-records" -mindepth 1 -maxdepth 1 -type f | wc -l)
[[ $records_after_boundary == "$records_before_boundary" ]] \
  || fail 'worker created a pending attempt after the workload deadline'

exited_worker_token=$(create_random_worker_token)
setsid env BNFS_RANDOM_WORKER_TOKEN="$exited_worker_token" bash -c 'sleep 0.2' &
exited_worker_pid=$!
track_test_worker "$exited_worker_pid" "$exited_worker_token"
wait_until 'pre-drain worker exit' process_exited "$exited_worker_pid"
drain_random_workers 1 \
  || fail "pre-exited worker was not reaped: ${RANDOM_WORKER_DRAIN_DETAIL:-unknown}"
(( ${#RANDOM_WORKER_PIDS[@]} == 0 && ${#RANDOM_WORKER_STARTTIMES[@]} == 0 \
  && ${#RANDOM_WORKER_PGIDS[@]} == 0 && ${#RANDOM_WORKER_TOKENS[@]} == 0 )) \
  || fail 'pre-exited worker identity was retained after drain'

(
  sleep 0 &
  race_exit_pid=$!
  RANDOM_WORKER_PIDS=("$race_exit_pid")
  RANDOM_WORKER_STARTTIMES=(1)
  RANDOM_WORKER_PGIDS=("$race_exit_pid")
  RANDOM_WORKER_TOKENS=("$(create_random_worker_token)")
  group_checks=0
  random_worker_group_alive() {
    group_checks=$((group_checks + 1))
    (( group_checks == 1 ))
  }
  random_worker_group_identity_valid() { return 1; }
  process_is_alive() { return 1; }
  drain_random_workers 1 \
    || fail "worker group exit race was rejected: ${RANDOM_WORKER_DRAIN_DETAIL:-unknown}"
  (( ${#RANDOM_WORKER_PIDS[@]} == 0 )) \
    || fail 'worker group exit race retained tracking state'
)

timed_out_worker_token=$(create_random_worker_token)
setsid env BNFS_RANDOM_WORKER_TOKEN="$timed_out_worker_token" bash -c 'kill -STOP "$$"; exit 28' &
timed_out_worker_pid=$!
track_test_worker "$timed_out_worker_pid" "$timed_out_worker_token"
kill -CONT "$timed_out_worker_pid"
if drain_random_workers 1; then
  fail 'worker timeout exit was accepted as a clean drain'
fi
[[ $RANDOM_WORKER_DRAIN_DETAIL == random_client_worker_failed ]] \
  || fail "worker timeout exit detail was ${RANDOM_WORKER_DRAIN_DETAIL:-empty}"
(( ${#RANDOM_WORKER_PIDS[@]} == 0 )) \
  || fail 'failed worker identity was retained after it was reaped'

identity_token=$(create_random_worker_token)
setsid env BNFS_RANDOM_WORKER_TOKEN="$identity_token" bash -c 'while :; do sleep 0.1; done' &
identity_group_pid=$!
cleanup_group_pids+=("$identity_group_pid")
track_test_worker "$identity_group_pid" "$identity_token"
identity_start=${RANDOM_WORKER_STARTTIMES[0]}
RANDOM_WORKER_STARTTIMES[0]=$((identity_start + 1))
if stop_random_workers; then
  fail 'worker group with a mismatched leader identity was signaled'
fi
[[ $RANDOM_WORKER_DRAIN_DETAIL == random_worker_identity_invalid ]] \
  || fail "mismatched identity detail was ${RANDOM_WORKER_DRAIN_DETAIL:-empty}"
kill -0 "$identity_group_pid" 2>/dev/null \
  || fail 'identity mismatch terminated the unrelated process group'
RANDOM_WORKER_STARTTIMES[0]=$identity_start
stop_random_workers || fail 'restored worker identity did not permit group cleanup'
wait_until 'identity-safe worker group exit' process_exited "$identity_group_pid"

active_unmatched_child_file=$test_root/active-unmatched-child.pid
active_unmatched_token=$(create_random_worker_token)
setsid env BNFS_RANDOM_WORKER_TOKEN="$active_unmatched_token" bash -c '
  env -u BNFS_RANDOM_WORKER_TOKEN sleep 30 &
  printf "%s\n" "$!" > "$1"
  while :; do sleep 0.1; done
' _ "$active_unmatched_child_file" &
active_unmatched_group_pid=$!
cleanup_group_pids+=("$active_unmatched_group_pid")
track_test_worker "$active_unmatched_group_pid" "$active_unmatched_token"
wait_until 'active unmatched child publication' test -s "$active_unmatched_child_file"
if stop_random_workers; then
  fail 'active worker group containing a tokenless child was signaled'
fi
[[ $RANDOM_WORKER_DRAIN_DETAIL == random_worker_identity_invalid ]] \
  || fail "active unmatched child detail was ${RANDOM_WORKER_DRAIN_DETAIL:-empty}"
active_unmatched_child_pid=$(cat "$active_unmatched_child_file")
kill -0 "$active_unmatched_group_pid" 2>/dev/null \
  || fail 'active group leader was killed despite a tokenless member'
kill -0 "$active_unmatched_child_pid" 2>/dev/null \
  || fail 'tokenless group member was killed despite failed validation'
kill -KILL -- "-$active_unmatched_group_pid" 2>/dev/null || true
wait "$active_unmatched_group_pid" 2>/dev/null || true
wait_until 'manual active unmatched group cleanup' process_exited "$active_unmatched_child_pid"
clear_random_worker_tracking

zombie_child_file=$test_root/zombie-child.pid
zombie_token=$(create_random_worker_token)
setsid env BNFS_RANDOM_WORKER_TOKEN="$zombie_token" bash -c '
  sleep 30 &
  printf "%s\n" "$!" > "$1"
  kill -STOP "$$"
  wait
' _ "$zombie_child_file" &
zombie_group_pid=$!
cleanup_group_pids+=("$zombie_group_pid")
wait_until 'zombie-race child publication' test -s "$zombie_child_file"
zombie_child_pid=$(cat "$zombie_child_file")
kill -KILL "$zombie_child_pid"
wait_until 'zombie-race child transition' bash -c \
  '[[ $(ps -o stat= -p "$1" 2>/dev/null | tr -d "[:space:]") == Z* ]]' \
  _ "$zombie_child_pid"
if random_worker_token_mismatch_is_live "$zombie_child_pid" "$zombie_group_pid"; then
  fail 'exited zombie member was treated as a live token mismatch'
fi
kill -KILL -- "-$zombie_group_pid" 2>/dev/null || true
wait "$zombie_group_pid" 2>/dev/null || true
wait_until 'zombie-race group cleanup' process_exited "$zombie_child_pid"

token_drop_marker=$test_root/token-drop.marker
token_drop_token=$(create_random_worker_token)
setsid env BNFS_RANDOM_WORKER_TOKEN="$token_drop_token" TOKEN_DROP_MARKER="$token_drop_marker" \
  bash -c '
    trap '\''printf "dropped\n" > "$TOKEN_DROP_MARKER"; exec env -u BNFS_RANDOM_WORKER_TOKEN bash -c "trap \"\" TERM; while :; do sleep 0.1; done"'\'' TERM
    while :; do sleep 0.1; done
  ' &
token_drop_group_pid=$!
cleanup_group_pids+=("$token_drop_group_pid")
track_test_worker "$token_drop_group_pid" "$token_drop_token"
saved_stop_timeout=$DEFAULT_RANDOM_WORKER_STOP_TIMEOUT_SECONDS
DEFAULT_RANDOM_WORKER_STOP_TIMEOUT_SECONDS=1
if stop_random_workers; then
  fail 'worker that dropped its token after TERM was killed without KILL revalidation'
fi
DEFAULT_RANDOM_WORKER_STOP_TIMEOUT_SECONDS=$saved_stop_timeout
[[ $RANDOM_WORKER_DRAIN_DETAIL == random_worker_identity_invalid ]] \
  || fail "token-drop detail was ${RANDOM_WORKER_DRAIN_DETAIL:-empty}"
[[ -s $token_drop_marker ]] || fail 'token-drop worker did not receive TERM'
kill -0 "$token_drop_group_pid" 2>/dev/null \
  || fail 'token-drop worker was killed after its KILL identity became invalid'
kill -KILL -- "-$token_drop_group_pid" 2>/dev/null || true
wait "$token_drop_group_pid" 2>/dev/null || true
clear_random_worker_tracking

matching_child_file=$test_root/matching-child.pid
matching_token=$(create_random_worker_token)
setsid env BNFS_RANDOM_WORKER_TOKEN="$matching_token" bash -c '
  sleep 30 &
  printf "%s\n" "$!" > "$1"
  sleep 0.2
' _ "$matching_child_file" &
matching_group_pid=$!
cleanup_group_pids+=("$matching_group_pid")
track_test_worker "$matching_group_pid" "$matching_token"
wait_until 'matching orphan child publication' test -s "$matching_child_file"
wait_until 'matching worker leader exit' process_exited "$matching_group_pid"
if drain_random_workers 1 0; then
  fail 'worker group leak was accepted as a clean drain'
fi
[[ $RANDOM_WORKER_DRAIN_DETAIL == random_worker_drain_timeout ]] \
  || fail "matching orphan detail was ${RANDOM_WORKER_DRAIN_DETAIL:-empty}"
matching_child_pid=$(cat "$matching_child_file")
stop_random_workers || fail 'token-matched orphan worker group was not stopped'
wait_until 'token-matched orphan child exit' worker_group_exited "$matching_group_pid" "$matching_child_pid"

unmatched_child_file=$test_root/unmatched-child.pid
unmatched_token=$(create_random_worker_token)
setsid env BNFS_RANDOM_WORKER_TOKEN="$unmatched_token" bash -c '
  env -u BNFS_RANDOM_WORKER_TOKEN sleep 30 &
  printf "%s\n" "$!" > "$1"
  sleep 0.2
' _ "$unmatched_child_file" &
unmatched_group_pid=$!
cleanup_group_pids+=("$unmatched_group_pid")
track_test_worker "$unmatched_group_pid" "$unmatched_token"
wait_until 'unmatched orphan child publication' test -s "$unmatched_child_file"
wait_until 'unmatched worker leader exit' process_exited "$unmatched_group_pid"
if drain_random_workers 1; then
  fail 'unmatched worker group leak was accepted as a clean drain'
fi
unmatched_child_pid=$(cat "$unmatched_child_file")
if stop_random_workers; then
  fail 'leaderless group without the worker token was signaled'
fi
[[ $RANDOM_WORKER_DRAIN_DETAIL == random_worker_identity_invalid ]] \
  || fail "leaderless unmatched detail was ${RANDOM_WORKER_DRAIN_DETAIL:-empty}"
kill -0 "$unmatched_child_pid" 2>/dev/null \
  || fail 'leaderless unmatched child was terminated despite failed identity validation'
kill -KILL -- "-$unmatched_group_pid" 2>/dev/null || true
wait_until 'manually cleaned unmatched worker group' worker_group_exited "$unmatched_group_pid" "$unmatched_child_pid"
clear_random_worker_tracking

healthy_record=$run_dir/transfer-records/healthy-boundary.tsv
healthy_term_marker=$test_root/healthy-term
export HEALTHY_RECORD=$healthy_record HEALTHY_TERM_MARKER=$healthy_term_marker EXPECTED_SHA=$expected_sha
export RUN_DIR_FOR_TEST=$run_dir
export -f write_failed_transfer write_transfer_record_atomic append_transfer_record
healthy_worker_token=$(create_random_worker_token)
setsid env BNFS_RANDOM_WORKER_TOKEN="$healthy_worker_token" bash -c '
  trap '\'' : > "$HEALTHY_TERM_MARKER"; exit 143 '\'' TERM
  write_failed_transfer natclient01 relay01 natserver01 healthy-boundary "$HEALTHY_RECORD" 125 100
  sleep 0.2
  write_transfer_record_atomic "$HEALTHY_RECORD" "$(date --iso-8601=seconds)" healthy-boundary \
    natclient01 relay01 natserver01 100 0 104857600 20.000000 5.000 yes \
    "$EXPECTED_SHA" "$EXPECTED_SHA"
  append_transfer_record "$RUN_DIR_FOR_TEST" "$HEALTHY_RECORD"
  rm -f "$HEALTHY_RECORD"
' &
healthy_worker_pid=$!
track_test_worker "$healthy_worker_pid" "$healthy_worker_token"
drain_random_workers 2 || fail "healthy worker did not drain: ${RANDOM_WORKER_DRAIN_DETAIL:-unknown}"
[[ ! -e $healthy_term_marker ]] || fail 'healthy boundary worker received TERM'
wait_until 'healthy transfer watcher cursor' watcher_caught_up_with_failures 0
[[ ! -e $run_dir/failure-watcher.alert ]] || fail 'healthy boundary transfer raised an alert'

timeout_command_file=$test_root/timeout-command
STUB_EXPECTED_SHA=$expected_sha
TIMEOUT_COMMAND_FILE=$timeout_command_file
export STUB_EXPECTED_SHA TIMEOUT_COMMAND_FILE
dc() {
  local service=${3-}
  if [[ $service == natserver01 ]]; then
    printf '%s\n' "$STUB_EXPECTED_SHA"
    return 0
  fi
  if [[ $service == natclient01 ]]; then
    printf '%s\n' "${6-}" > "$TIMEOUT_COMMAND_FILE"
    printf '0\t\t1.000000\n'
    return 28
  fi
  return 1
}
export -f dc is_positive_integer deadline_step_timeout_seconds write_transfer_record_atomic random_transfer_once

timeout_record=$run_dir/transfer-records/self-timeout.tsv
timeout_deadline=$(( $(date +%s) + 2 ))
if BNFS_RANDOM_TRANSFER_LIMIT_KIBPS=512 random_transfer_once \
  "$run_dir" random-workload natserver01 natclient01 relay01 18101 \
  self-timeout "$timeout_record" 100 "$timeout_deadline"; then
  fail 'deadline-limited transfer unexpectedly succeeded'
else
  timeout_rc=$?
fi
[[ $timeout_rc == 28 ]] || fail "deadline-limited transfer returned rc=$timeout_rc"
grep -Eq -- "--max-time '[12]'" "$timeout_command_file" \
  || fail 'curl did not receive the remaining attempt budget'
grep -q -- "--limit-rate '512k'" "$timeout_command_file" \
  || fail 'curl did not receive the KiB/s CPU safety rate'
awk -F '\t' 'NF == 13 && $2 == "self-timeout" && $7 == 28 && $10 == "0.000" && $11 == "no" { found=1 } END { exit !found }' \
  "$timeout_record" || fail 'self-timeout did not persist a real timeout record'
append_transfer_record "$run_dir" "$timeout_record" || fail 'self-timeout record append failed'
rm -f "$timeout_record"
wait_until 'self-timeout watcher alert' watcher_caught_up_with_failures 1

random_gate_line=$(awk '/elif \(\( random_workers_ok == 0 \)\)/ { print NR; exit }' \
  "$ROOT_DIR/test/runtimeScript/local-chaos-stability.sh")
watcher_gate_line=$(awk '/elif ! wait_failure_watcher_caught_up/ { print NR; exit }' \
  "$ROOT_DIR/test/runtimeScript/local-chaos-stability.sh")
[[ $random_gate_line =~ ^[0-9]+$ && $watcher_gate_line =~ ^[0-9]+$ \
  && random_gate_line -lt watcher_gate_line ]] \
  || fail 'reconciled placeholder evidence can still override the drain root cause'

blocked_marker=$test_root/blocked-curl.started
STUB_EXPECTED_SHA=$expected_sha
BLOCKED_MARKER=$blocked_marker
BLOCKED_DC_PID_FILE=$blocked_dc_pid_file
export STUB_EXPECTED_SHA BLOCKED_MARKER BLOCKED_DC_PID_FILE
dc() {
  local service=${3-} command=${4-}
  if [[ $service == natserver01 && $command == curl ]]; then
    printf '%s\n' "$STUB_EXPECTED_SHA"
    return 0
  fi
  if [[ $service == natclient01 && $command == sh ]]; then
    printf '%s\n' "$BASHPID" > "$BLOCKED_DC_PID_FILE"
    : > "$BLOCKED_MARKER"
    trap 'exit 143' TERM INT HUP
    while :; do
      sleep 0.1
    done
  fi
  return 1
}
export -f dc is_positive_integer deadline_step_timeout_seconds write_transfer_record_atomic random_transfer_once

blocked_record=$run_dir/transfer-records/interrupted-boundary.tsv
blocked_worker_token=$(create_random_worker_token)
setsid env BNFS_RANDOM_WORKER_TOKEN="$blocked_worker_token" bash -c 'random_transfer_once "$@"' _ \
  "$run_dir" random-workload natserver01 natclient01 relay01 18101 \
  interrupted-boundary "$blocked_record" 100 &
blocked_group_pid=$!
track_test_worker "$blocked_group_pid" "$blocked_worker_token"
wait_until 'blocked curl entry' test -e "$blocked_marker"
[[ -s $blocked_record ]] || fail 'attempt was not persisted before the blocking curl'
awk -F '\t' 'NF == 13 && $2 == "interrupted-boundary" && $7 == 125 && $11 == "not-run" { found=1 } END { exit !found }' \
  "$blocked_record" || fail 'pre-call attempt record is malformed'
if append_transfer_record "$run_dir" "$blocked_record"; then
  fail 'in-flight crash-recovery placeholder was published as a transfer result'
fi
if reconcile_pending_transfer_records "$run_dir"; then
  fail 'reconciliation accepted an unfinished crash-recovery placeholder'
fi
[[ -e $blocked_record ]] || fail 'rejected in-flight placeholder was discarded'

if drain_random_workers 1 0; then
  fail 'blocked transfer unexpectedly drained'
fi
[[ $RANDOM_WORKER_DRAIN_DETAIL == random_worker_drain_timeout ]] \
  || fail "unexpected drain detail: ${RANDOM_WORKER_DRAIN_DETAIL:-empty}"
blocked_child_pid=$(cat "$blocked_dc_pid_file")
stop_random_workers || fail "worker process group did not stop: ${RANDOM_WORKER_DRAIN_DETAIL:-unknown}"
wait_until 'blocked worker process group exit' worker_group_exited "$blocked_group_pid" "$blocked_child_pid"
blocked_group_pid=
finalize_random_worker_evidence "$run_dir" \
  || fail "interrupted attempt finalization failed: ${RANDOM_WORKER_EVIDENCE_DETAIL:-unknown}"
[[ ! -e $blocked_record ]] || fail 'reconciled record was not removed'
wait_until 'interrupted transfer watcher alert' watcher_caught_up_with_failures 2
[[ -s $run_dir/failure-watcher.alert ]] || fail 'watcher did not publish a failure sentinel'
[[ $(wc -l < "$run_dir/transfers.tsv") -eq 4 ]] || fail 'unexpected transfer row count'
awk -F '\t' 'NR > 1 && $2 == "interrupted-boundary" && $7 == 28 && $9 > 0 && $11 == "not-run" { found=1 } END { exit !found }' \
  "$run_dir/transfers.tsv" || fail 'interrupted attempt was not appended as real timeout evidence'
stable_digest=$(sha256sum "$run_dir/transfers.tsv" "$run_dir/large-probes.tsv")
stable_pending_count=$(find "$run_dir/transfer-records" -mindepth 1 -maxdepth 1 -type f | wc -l)
sleep 0.3
[[ $(sha256sum "$run_dir/transfers.tsv" "$run_dir/large-probes.tsv") == "$stable_digest" ]] \
  || fail 'transfer evidence changed after process-group stop and reconciliation'
[[ $(find "$run_dir/transfer-records" -mindepth 1 -maxdepth 1 -type f | wc -l) == "$stable_pending_count" ]] \
  || fail 'pending transfer records changed after reconciliation'

tail -n 1 "$run_dir/transfers.tsv" > "$blocked_record"
reconcile_pending_transfer_records "$run_dir" || fail 'idempotent reconciliation failed'
[[ $(wc -l < "$run_dir/transfers.tsv") -eq 4 ]] || fail 'reconciliation duplicated a transfer row'
[[ $(wc -l < "$run_dir/large-probes.tsv") -eq 4 ]] || fail 'reconciliation duplicated a probe row'

printf 'malformed\n' > "$run_dir/transfer-records/malformed.tsv"
if reconcile_pending_transfer_records "$run_dir"; then
  fail 'malformed pending evidence was accepted'
fi
[[ -e $run_dir/transfer-records/malformed.tsv ]] || fail 'malformed evidence was discarded'

printf 'random transfer deadline regression passed\n'
