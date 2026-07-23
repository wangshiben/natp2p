#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
source "$ROOT_DIR/scripts/local-chaos-stability.sh"
test_root=$(mktemp -d)
cleanup_groups=()
cleanup_pids=()

cleanup() {
  local identity group_id expected_start current_start pid
  for identity in "${cleanup_groups[@]}"; do
    IFS=: read -r group_id expected_start <<< "$identity"
    [[ $group_id =~ ^[1-9][0-9]*$ && $expected_start =~ ^[1-9][0-9]*$ ]] || continue
    current_start=$(awk '{print $22}' "/proc/$group_id/stat" 2>/dev/null || true)
    [[ $current_start == "$expected_start" ]] \
      && kill -KILL -- "-$group_id" 2>/dev/null || true
  done
  for identity in "${cleanup_pids[@]}"; do
    IFS=: read -r pid expected_start <<< "$identity"
    [[ $pid =~ ^[1-9][0-9]*$ && $expected_start =~ ^[1-9][0-9]*$ ]] || continue
    current_start=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null || true)
    [[ $current_start == "$expected_start" ]] && kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  rm -rf "$test_root"
}
trap cleanup EXIT

fail() {
  printf 'resource guard worker cleanup regression failed: %s\n' "$*" >&2
  exit 1
}

docker() {
  if [[ ${1:-} == info ]]; then
    printf '%s\n' "$TEST_DOCKER_ROOT"
  elif [[ ${1:-} == ps && ${TEST_DOCKER_LEAK:-0} == 1 ]]; then
    printf 'leaked-container\n'
  fi
  return 0
}
export -f docker
export TEST_DOCKER_ROOT=$test_root/docker-root
mkdir -p "$TEST_DOCKER_ROOT"

df() {
  printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
  printf 'stub 100 1 99 1%% /\n'
}
export -f df

wait_until() {
  local description=$1
  shift
  for _ in $(seq 1 100); do
    "$@" && return 0
    sleep 0.05
  done
  fail "timed out waiting for $description"
}

guard_running() {
  [[ -s $1/resource-guard.status ]] && grep -q '^RUNNING ' "$1/resource-guard.status"
}

process_stopped() {
  local state
  state=$(ps -o stat= -p "$1" 2>/dev/null | tr -d '[:space:]')
  [[ -z $state || $state == Z* ]]
}

start_group() {
  local token=${1:-}
  if [[ -n $token ]]; then
    setsid env BNFS_RANDOM_WORKER_TOKEN="$token" bash -c \
      'trap "exit 0" TERM INT HUP; while :; do sleep 0.1; done' \
      > /dev/null 2>&1 &
  else
    setsid bash -c 'while :; do sleep 0.1; done' > /dev/null 2>&1 &
  fi
  STARTED_PID=$!
  STARTED_START=$(awk '{print $22}' "/proc/$STARTED_PID/stat")
  cleanup_groups+=("$STARTED_PID:$STARTED_START")
}

run_inspector_case() {
  local run_dir=$test_root/inspector now_epoch stale_epoch guard_pid guard_start
  local expected_header
  mkdir -p "$run_dir"
  start_group
  guard_pid=$STARTED_PID
  guard_start=$STARTED_START
  now_epoch=$(date +%s)
  printf 'RUNNING started=%s duration_seconds=60 interval_seconds=1 cpu_limit_pct=100 memory_limit_pct=100 disk_limit_pct=100 logical_cpus=1\n' \
    "$(date --iso-8601=seconds)" > "$run_dir/resource-guard.status"
  expected_header=$'timestamp\tepoch\tcontainers\tproject_cpu_raw_pct\tproject_cpu_host_pct\thost_cpu_pct\tproject_memory_bytes\tproject_memory_host_pct\thost_memory_pct\tdocker_disk_pct\tartifact_disk_pct\tguard_disk_pct\tstate'
  printf '%s\n' "$expected_header" > "$run_dir/resources.tsv"
  printf '%s\t%s\t1\t0\t0\t0\t0\t0\t0\t1\t1\t1\tOK\n' \
    "$(date --iso-8601=seconds)" "$now_epoch" >> "$run_dir/resources.tsv"
  inspect_resource_guard "$run_dir" "$guard_pid" "$guard_start" 1 60 100 100 100 "$now_epoch" \
    || fail "healthy resource guard was rejected: $RESOURCE_GUARD_DETAIL"

  stale_epoch=$((now_epoch - 31))
  sed -i "2s/^[^	]*	[0-9]*/$(date --iso-8601=seconds)	$stale_epoch/" "$run_dir/resources.tsv"
  if inspect_resource_guard "$run_dir" "$guard_pid" "$guard_start" 1 60 100 100 100 "$now_epoch"; then
    fail 'stale resource guard sample was accepted'
  fi
  [[ $RESOURCE_GUARD_DETAIL == resource_guard_sample_stale ]] \
    || fail "stale resource guard detail was $RESOURCE_GUARD_DETAIL"

  sed -i "2s/^[^	]*	[0-9]*/$(date --iso-8601=seconds)	$now_epoch/" "$run_dir/resources.tsv"
  printf 'STOPPED_BY_SIGNAL timestamp=%s\n' "$(date --iso-8601=seconds)" \
    > "$run_dir/resource-guard.status"
  if inspect_resource_guard "$run_dir" "$guard_pid" "$guard_start" 1 60 100 100 100 "$now_epoch"; then
    fail 'terminal resource guard status was accepted as RUNNING'
  fi
  [[ $RESOURCE_GUARD_DETAIL == resource_guard_status_invalid ]] \
    || fail "terminal resource guard detail was $RESOURCE_GUARD_DETAIL"

  kill -KILL -- "-$guard_pid" 2>/dev/null || true
  wait "$guard_pid" 2>/dev/null || true
  if inspect_resource_guard "$run_dir" "$guard_pid" "$guard_start" 1 60 100 100 100 "$now_epoch"; then
    fail 'exited resource guard identity was accepted'
  fi
  [[ $RESOURCE_GUARD_DETAIL == resource_guard_exited ]] \
    || fail "exited resource guard detail was $RESOURCE_GUARD_DETAIL"
}

run_stop_case() {
  local run_dir=$test_root/stop guard_pid guard_start
  mkdir -p "$run_dir"
  setsid env STATUS_FILE="$run_dir/resource-guard.status" bash -c '
    trap '\''printf "STOPPED_BY_SIGNAL timestamp=%s\\n" "$(date --iso-8601=seconds)" > "$STATUS_FILE"; exit 0'\'' TERM
    while :; do sleep 0.1; done
  ' > /dev/null 2>&1 &
  guard_pid=$!
  guard_start=$(awk '{print $22}' "/proc/$guard_pid/stat")
  cleanup_pids+=("$guard_pid:$guard_start")
  stop_resource_guard "$run_dir" "$guard_pid" "$guard_start" \
    || fail "resource guard stop was rejected: $RESOURCE_GUARD_DETAIL"
  grep -q '^STOPPED_BY_SIGNAL timestamp=' "$run_dir/resource-guard.status" \
    || fail 'resource guard stop did not retain terminal status'
}

run_case() {
  local name=$1 mismatch=$2
  local run_dir=$test_root/$name
  local runner_pid runner_start worker_pid worker_start token guard_pid guard_start guard_rc
  mkdir -p "$run_dir"
  printf '{}\n' > "$run_dir/compose.json"

  start_group
  runner_pid=$STARTED_PID
  runner_start=$(awk '{print $22}' "/proc/$runner_pid/stat")
  token=0123456789abcdef0123456789abcdef
  start_group "$token"
  worker_pid=$STARTED_PID
  worker_start=$(awk '{print $22}' "/proc/$worker_pid/stat")
  (( mismatch == 0 )) || worker_start=$((worker_start + 1))
  printf 'client\tpid\tstarttime\tpgid\ttoken\n' > "$run_dir/worker-pids.tsv"
  printf 'natclient01\t%s\t%s\t%s\t%s\n' \
    "$worker_pid" "$worker_start" "$worker_pid" "$token" >> "$run_dir/worker-pids.tsv"
  if (( mismatch == 0 )); then
    mkdir -p "$run_dir/transfer-records"
    printf 'timestamp\ttransfer_id\tclient\tingress_relay\tserver\trequested_mib\trc\tbytes\tseconds\tmib_per_second\tsha256_ok\texpected_sha\tactual_sha\n' \
      > "$run_dir/transfers.tsv"
    printf 'timestamp\tlabel\trequested_mib\trc\tbytes\tseconds\tmib_per_second\tsha256_ok\tclient\texpected_sha\tactual_sha\n' \
      > "$run_dir/large-probes.tsv"
    printf '%s\tguard-interrupted\tnatclient01\trelay01\tnatserver01\t100\t125\t0\t0.000000\t0.000\tnot-run\t\t\n' \
      "$(date --iso-8601=seconds --date='2 seconds ago')" \
      > "$run_dir/transfer-records/guard-interrupted.tsv"
  fi

  setsid bash "$ROOT_DIR/test/local-chaos/resource-guard.sh" \
    --compose-file "$run_dir/compose.json" --project "guard-$name" --output-dir "$run_dir" \
    --watch-pid "$runner_pid" --watch-pgid "$runner_pid" --duration-seconds 60 \
    --interval-seconds 1 --cpu-limit 100 --memory-limit 100 --disk-limit 100 \
    > "$run_dir/guard.log" 2>&1 &
  guard_pid=$!
  guard_start=$(awk '{print $22}' "/proc/$guard_pid/stat")
  cleanup_pids+=("$guard_pid:$guard_start")
  wait_until "$name guard startup" guard_running "$run_dir"

  kill -KILL -- "-$runner_pid"
  wait "$runner_pid" 2>/dev/null || true
  set +e
  wait "$guard_pid"
  guard_rc=$?
  set -e
  [[ $guard_rc == 4 ]] || fail "$name guard exit code was $guard_rc"
  [[ -e $run_dir/worker-pids.closed ]] || fail "$name registry was not closed"
  grep -q '^FAILED$' "$run_dir/phase" || fail "$name did not publish FAILED phase"

  if (( mismatch == 0 )); then
    if ! grep -q 'worker_cleanup_verified=yes' "$run_dir/resource-guard.status"; then
      printf '%s\n' 'resource guard status:' >&2
      cat "$run_dir/resource-guard.status" >&2
      printf '%s\n' 'resource guard events:' >&2
      cat "$run_dir/resource-events.log" >&2
      fail "$name worker cleanup was not verified"
    fi
    wait_until "$name worker cleanup" process_stopped "$worker_pid"
    wait "$worker_pid" 2>/dev/null || true
    grep -q '^detail=runner_exited_unexpectedly$' "$run_dir/status.env" \
      || fail "$name did not retain unexpected-runner failure"
    awk -F '\t' 'NR > 1 && $2 == "guard-interrupted" && $7 == 28 \
      && $9 > 0 && $11 == "not-run" { found=1 } END { exit !found }' \
      "$run_dir/transfers.tsv" || fail "$name pending transfer was not finalized as rc=28"
    [[ ! -e $run_dir/transfer-records/guard-interrupted.tsv ]] \
      || fail "$name finalized transfer placeholder was retained"
  else
    kill -0 "$worker_pid" 2>/dev/null || fail "$name identity mismatch killed the worker"
    grep -q '^detail=worker_identity_invalid$' "$run_dir/status.env" \
      || fail "$name identity mismatch was not fail-closed"
    grep -q 'worker_cleanup_verified=no' "$run_dir/resource-guard.status" \
      || fail "$name unsafe cleanup was not recorded"
    kill -TERM -- "-$worker_pid" 2>/dev/null || true
    wait_until "$name manual worker cleanup" process_stopped "$worker_pid"
    wait "$worker_pid" 2>/dev/null || true
  fi
}

run_token_drop_case() {
  local run_dir=$test_root/token-drop
  local runner_pid worker_pid worker_start token guard_pid guard_start guard_rc
  local token_drop_marker=$run_dir/token-dropped
  mkdir -p "$run_dir"
  printf '{}\n' > "$run_dir/compose.json"

  start_group
  runner_pid=$STARTED_PID
  token=abcdef0123456789abcdef0123456789
  setsid env BNFS_RANDOM_WORKER_TOKEN="$token" TOKEN_DROP_MARKER="$token_drop_marker" \
    bash -c '
      trap '\''printf "dropped\n" > "$TOKEN_DROP_MARKER"; exec env -u BNFS_RANDOM_WORKER_TOKEN bash -c "trap \"\" TERM; while :; do sleep 0.1; done"'\'' TERM
      while :; do sleep 0.1; done
    ' > /dev/null 2>&1 &
  worker_pid=$!
  worker_start=$(awk '{print $22}' "/proc/$worker_pid/stat")
  cleanup_groups+=("$worker_pid:$worker_start")
  printf 'client\tpid\tstarttime\tpgid\ttoken\n' > "$run_dir/worker-pids.tsv"
  printf 'natclient01\t%s\t%s\t%s\t%s\n' \
    "$worker_pid" "$worker_start" "$worker_pid" "$token" >> "$run_dir/worker-pids.tsv"

  setsid bash "$ROOT_DIR/test/local-chaos/resource-guard.sh" \
    --compose-file "$run_dir/compose.json" --project guard-token-drop --output-dir "$run_dir" \
    --watch-pid "$runner_pid" --watch-pgid "$runner_pid" --duration-seconds 60 \
    --interval-seconds 1 --cpu-limit 100 --memory-limit 100 --disk-limit 100 \
    > "$run_dir/guard.log" 2>&1 &
  guard_pid=$!
  guard_start=$(awk '{print $22}' "/proc/$guard_pid/stat")
  cleanup_pids+=("$guard_pid:$guard_start")
  wait_until 'token-drop guard startup' guard_running "$run_dir"

  kill -KILL -- "-$runner_pid"
  wait "$runner_pid" 2>/dev/null || true
  set +e
  wait "$guard_pid"
  guard_rc=$?
  set -e
  [[ $guard_rc == 4 ]] || fail "token-drop guard exit code was $guard_rc"
  [[ -s $token_drop_marker ]] || fail 'token-drop worker did not receive TERM'
  ! process_stopped "$worker_pid" \
    || fail 'token-drop worker was killed without revalidating its KILL identity'
  grep -q '^detail=worker_identity_invalid$' "$run_dir/status.env" \
    || fail 'token-drop cleanup did not fail closed'
  kill -KILL -- "-$worker_pid" 2>/dev/null || true
  wait_until 'token-drop manual cleanup' process_stopped "$worker_pid"
  wait "$worker_pid" 2>/dev/null || true
}

run_watched_identity_loss_case() {
  local run_dir=$test_root/watched-identity-loss
  local child_file=$run_dir/child.pid runner_pid runner_start child_pid guard_pid guard_start guard_rc
  mkdir -p "$run_dir"
  printf '{}\n' > "$run_dir/compose.json"
  printf 'client\tpid\tstarttime\tpgid\ttoken\n' > "$run_dir/worker-pids.tsv"
  setsid bash -c '
    sleep 30 &
    printf "%s\n" "$!" > "$1"
    while :; do sleep 0.1; done
  ' _ "$child_file" > /dev/null 2>&1 &
  runner_pid=$!
  runner_start=$(awk '{print $22}' "/proc/$runner_pid/stat")
  cleanup_groups+=("$runner_pid:$runner_start")
  wait_until 'watched child publication' test -s "$child_file"
  child_pid=$(cat "$child_file")

  setsid bash "$ROOT_DIR/test/local-chaos/resource-guard.sh" \
    --compose-file "$run_dir/compose.json" --project guard-watched-identity-loss \
    --output-dir "$run_dir" --watch-pid "$runner_pid" --watch-pgid "$runner_pid" \
    --duration-seconds 60 --interval-seconds 1 --cpu-limit 100 --memory-limit 100 \
    --disk-limit 100 > "$run_dir/guard.log" 2>&1 &
  guard_pid=$!
  guard_start=$(awk '{print $22}' "/proc/$guard_pid/stat")
  cleanup_pids+=("$guard_pid:$guard_start")
  wait_until 'watched identity-loss guard startup' guard_running "$run_dir"

  kill -KILL "$runner_pid"
  wait "$runner_pid" 2>/dev/null || true
  set +e
  wait "$guard_pid"
  guard_rc=$?
  set -e
  [[ $guard_rc == 4 ]] || fail "watched identity-loss guard exit code was $guard_rc"
  ! process_stopped "$child_pid" \
    || fail 'leaderless watched group was signaled without a verifiable identity'
  grep -q '^detail=watched_group_identity_invalid$' "$run_dir/status.env" \
    || fail 'leaderless watched group did not fail closed'
  kill -KILL -- "-$runner_pid" 2>/dev/null || true
  wait_until 'watched identity-loss manual cleanup' process_stopped "$child_pid"
}

run_limit_case() {
  local run_dir=$test_root/resource-limit
  local runner_pid runner_start worker_pid worker_start token guard_pid guard_start guard_rc
  mkdir -p "$run_dir"
  printf '{}\n' > "$run_dir/compose.json"

  start_group
  runner_pid=$STARTED_PID
  runner_start=$STARTED_START
  token=fedcba9876543210fedcba9876543210
  start_group "$token"
  worker_pid=$STARTED_PID
  worker_start=$STARTED_START
  printf 'client\tpid\tstarttime\tpgid\ttoken\n' > "$run_dir/worker-pids.tsv"
  printf 'natclient01\t%s\t%s\t%s\t%s\n' \
    "$worker_pid" "$worker_start" "$worker_pid" "$token" >> "$run_dir/worker-pids.tsv"

  setsid bash "$ROOT_DIR/test/local-chaos/resource-guard.sh" \
    --compose-file "$run_dir/compose.json" --project guard-resource-limit --output-dir "$run_dir" \
    --watch-pid "$runner_pid" --watch-pgid "$runner_pid" --duration-seconds 60 \
    --interval-seconds 1 --cpu-limit 100 --memory-limit 100 --disk-limit 0 \
    > "$run_dir/guard.log" 2>&1 &
  guard_pid=$!
  guard_start=$(awk '{print $22}' "/proc/$guard_pid/stat")
  cleanup_pids+=("$guard_pid:$guard_start")
  set +e
  wait "$guard_pid"
  guard_rc=$?
  set -e
  [[ $guard_rc == 3 ]] || fail "resource-limit guard exit code was $guard_rc"
  wait_until 'resource-limit runner cleanup' process_stopped "$runner_pid"
  wait_until 'resource-limit worker cleanup' process_stopped "$worker_pid"
  wait "$runner_pid" 2>/dev/null || true
  wait "$worker_pid" 2>/dev/null || true
  grep -q '^RESOURCE_LIMIT$' "$run_dir/phase" || fail 'resource limit phase was not retained'
  grep -q '^detail=resource_threshold_exceeded$' "$run_dir/status.env" \
    || fail 'successful resource cleanup lost the threshold detail'
  grep -q '^TERMINATED .*worker_cleanup_verified=yes detail=resource_threshold_exceeded$' \
    "$run_dir/resource-guard.status" || fail 'resource limit cleanup was not verified'
}

run_deadline_cleanup_failure_case() {
  local run_dir=$test_root/deadline-cleanup-failure
  local runner_pid runner_start guard_pid guard_start guard_rc
  mkdir -p "$run_dir"
  printf '{}\n' > "$run_dir/compose.json"
  printf 'client\tpid\tstarttime\tpgid\ttoken\n' > "$run_dir/worker-pids.tsv"
  start_group
  runner_pid=$STARTED_PID
  runner_start=$STARTED_START

  TEST_DOCKER_LEAK=1 setsid bash "$ROOT_DIR/test/local-chaos/resource-guard.sh" \
    --compose-file "$run_dir/compose.json" --project guard-deadline-failure --output-dir "$run_dir" \
    --watch-pid "$runner_pid" --watch-pgid "$runner_pid" --duration-seconds 1 \
    --interval-seconds 1 --cpu-limit 100 --memory-limit 100 --disk-limit 100 \
    > "$run_dir/guard.log" 2>&1 &
  guard_pid=$!
  guard_start=$(awk '{print $22}' "/proc/$guard_pid/stat")
  cleanup_pids+=("$guard_pid:$guard_start")
  set +e
  wait "$guard_pid"
  guard_rc=$?
  set -e
  [[ $guard_rc == 4 ]] || fail "deadline cleanup failure exit code was $guard_rc"
  wait_until 'deadline runner cleanup' process_stopped "$runner_pid"
  wait "$runner_pid" 2>/dev/null || true
  grep -q '^FAILED$' "$run_dir/phase" || fail 'deadline cleanup failure did not fail the run'
  grep -q '^detail=resource_guard_cleanup_failed$' "$run_dir/status.env" \
    || fail 'non-worker cleanup failure was mislabeled as clean'
  grep -q 'worker_cleanup_verified=yes detail=resource_guard_cleanup_failed$' \
    "$run_dir/resource-guard.status" || fail 'deadline cleanup failure evidence is incomplete'
}

run_inspector_case
run_stop_case
run_case verified 0
run_case identity-mismatch 1
run_token_drop_case
run_watched_identity_loss_case
run_limit_case
run_deadline_cleanup_failure_case

printf 'resource guard worker cleanup regression passed\n'
