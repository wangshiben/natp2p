#!/usr/bin/env bash

set -uo pipefail
umask 077

BNFS_SECURITY_PROFILE=${BNFS_SECURITY_PROFILE:-development}
export BNFS_SECURITY_PROFILE

if [[ -n ${BNFS_STABILITY_ROOT_DIR:-} ]]; then
  ROOT_DIR=$BNFS_STABILITY_ROOT_DIR
else
  ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fi
STABILITY_SUPPORT_ROOT=${BNFS_STABILITY_SUPPORT_ROOT:-$ROOT_DIR}
STABILITY_WORKER_SCRIPT=${BNFS_STABILITY_WORKER_SCRIPT:-}
SOAK_HOME=${BNFS_SOAK_HOME:-$ROOT_DIR/test/local-chaos/.soak}
STATE_DIR=$SOAK_HOME/state
CURRENT_FILE=$STATE_DIR/current
DEFAULT_DURATION_SECONDS=43200
DEFAULT_CPU_LIMIT=55
DEFAULT_MEMORY_LIMIT=40
DEFAULT_DISK_LIMIT=40
DEFAULT_SAMPLE_SECONDS=5
DEFAULT_PROBE_SECONDS=60
DEFAULT_MAX_INFLIGHT=1
DEFAULT_DASHBOARD_HOST=0.0.0.0
DEFAULT_DASHBOARD_PORT=8911
DEFAULT_CA_PORT=19100
DEFAULT_CA_WEB_PORT=8088
DEFAULT_RECONNECT_GATE_PORT=18912
DEFAULT_SOAK_CREDIT_BYTES=2199023255552
DEFAULT_WORKLOAD_LIMIT_MIBPS=5
DEFAULT_FAILURE_WATCHER_HEARTBEAT_TIMEOUT_SECONDS=15
DEFAULT_FAILURE_WATCHER_DEGRADED_GRACE_SECONDS=15
DEFAULT_FAILURE_WATCHER_SOURCE_LAG_GRACE_SECONDS=15
DEFAULT_FAILURE_WATCHER_SETTLE_TIMEOUT_SECONDS=30
DEFAULT_BILLING_ADVERSARY_MODE=enforce
DEFAULT_DASHBOARD_STATUS_PROBE_SECONDS=5
DEFAULT_DASHBOARD_STATUS_FAILURE_GRACE_SECONDS=20
DEFAULT_DASHBOARD_STATUS_MIN_FAILURES=3
DEFAULT_CORE_HEALTH_FAILURE_GRACE_SECONDS=15
DEFAULT_CORE_HEALTH_MIN_FAILURES=3
DEFAULT_CORE_HEALTH_PROBE_SECONDS=3
DEFAULT_VALIDATION_MODE=full
DEFAULT_IP_FAMILY_COVERAGE=off
DEFAULT_RANDOM_ATTEMPT_TIMEOUT_SECONDS=900
SMOKE_RANDOM_ATTEMPT_TIMEOUT_SECONDS=180
DEFAULT_PROFILE_RELAY_MIGRATION_TIMEOUT_SECONDS=360
DEFAULT_RANDOM_WORKER_STOP_TIMEOUT_SECONDS=5
DEFAULT_RESOURCE_GUARD_STOP_TIMEOUT_SECONDS=10
DEFAULT_WAIT_INTERVAL_SECONDS=30
POST_GATE_SERVER_RECOVERY_TIMEOUT_SECONDS=45
POST_GATE_SERVER_RECOVERY_STABLE_SAMPLES=3
PROFILE_SETUP_PRIVATE_SUBDIR=profile-setup
PROFILE_SETUP_NAT_KEY_DIR=/artifacts/.private/$PROFILE_SETUP_PRIVATE_SUBDIR
TOPOLOGY_RELAY_COUNT=7
TOPOLOGY_NAT_SERVER_COUNT=13
TOPOLOGY_NAT_CLIENT_COUNT=6
MALICIOUS_NAT_CLIENT=malicious-natclient
MALICIOUS_RANDOM_NAT_SERVER=malicious-random-natserver
RANDOM_CLIENT_POOL_COUNT=$((TOPOLOGY_NAT_CLIENT_COUNT + 1))
RANDOM_MULTI_CLIENT_PERCENT=60
RANDOM_MULTI_CLIENT_MIN=2
RANDOM_MULTI_CLIENT_MAX=4
RANDOM_STREAM_LIMIT_KIBPS=5120
RANDOM_BATCH_CLIENT_START_STAGGER_SECONDS=30
RANDOM_BATCH_MIXED_PATH_QUIET_SAMPLES=3
RANDOM_BATCH_MIXED_PATH_QUIET_TIMEOUT_SECONDS=45
RANDOM_WORKER_PIDS=()
RANDOM_WORKER_STARTTIMES=()
RANDOM_WORKER_PGIDS=()
RANDOM_WORKER_TOKENS=()
FAILURE_WATCHER_DETAIL=
FAILURE_WATCHER_DEGRADED_SINCE=0
FAILURE_WATCHER_LAG_SINCE=0
FAILURE_WATCHER_STATUS=
FAILURE_WATCHER_HEARTBEAT_EPOCH=
FAILURE_WATCHER_SOURCE_AVAILABLE=
FAILURE_WATCHER_SOURCE_SIZE=
FAILURE_WATCHER_SOURCE_OFFSET=
FAILURE_WATCHER_NEW_FAILURES=
RESOURCE_GUARD_DETAIL=
CORE_HEALTH_DETAIL=
CORE_HEALTH_UNHEALTHY_SERVICES=
CORE_HEALTH_SNAPSHOT=
CORE_IDENTITY_DETAIL=
PROFILE_SETUP_DETAIL=

source "$STABILITY_SUPPORT_ROOT/test/local-chaos/billing-adversary-gate.sh"
source "$STABILITY_SUPPORT_ROOT/test/local-chaos/billing-production-gate.sh"
source "$STABILITY_SUPPORT_ROOT/test/local-chaos/mixed-path-gate.sh"
source "$STABILITY_SUPPORT_ROOT/test/local-chaos/network-pools.sh"
REAL_BILLING_GATE_SERVER=natserver06

usage() {
  cat <<'EOF'
usage:
  local-chaos-stability.sh run [options]
  local-chaos-stability.sh start [options]
  local-chaos-stability.sh wait [--interval-seconds N]
  local-chaos-stability.sh status
  local-chaos-stability.sh stop

run/start options:
  --scenario random|1|2|3       fixed profile for the whole run (default: random)
  --duration-seconds N          running duration after the cluster is ready (default: 43200)
  --cpu-limit PCT               project CPU percentage of host capacity (default: 55)
  --memory-limit PCT            project memory percentage of host memory (default: 40)
  --disk-limit PCT              max Docker/artifact filesystem usage (default: 40)
  --sample-seconds N            resource sample interval (default: 5)
  --probe-seconds N             end-to-end file probe interval (default: 60)
  --max-inflight N              concurrent random batches; currently must be 1 (default: 1)
  --workload-limit-mibps N      per-stream transfer ceiling; 0 disables (default: 5)
  --dashboard-host HOST         dashboard bind host (default: 0.0.0.0)
  --dashboard-port PORT         dashboard port (default: 8911)
  --ca-port PORT                loopback CA port (default: 19100)
  --ca-web-port PORT            HTTPS CA Web port (default: 8088)
  --billing-adversary MODE      enforce|report|off (default: enforce)
  --validation-mode MODE        smoke|full validation (default: full)
  --ip-family-coverage MODE     off|random IPv4/IPv6/dual-stack coverage (default: off)

run-only options:
  --wait-interval-seconds N     progress output interval (default: 30)
EOF
}

scenario_name() {
  case "$1" in
    1) printf 'partition_bridge' ;;
    2) printf 'nat_path_failover' ;;
    3) printf 'kcp_tcp_fallback' ;;
  esac
}

numbered_service_names() {
  local prefix=$1 count=$2 number
  for ((number = 1; number <= count; number++)); do
    printf '%s%02d\n' "$prefix" "$number"
  done
}

core_service_names() {
	printf '%s\n' ca-postgres ca ca-web index
  numbered_service_names relay "$TOPOLOGY_RELAY_COUNT"
}

core_identity_service_names() {
	printf '%s\n' ca-postgres ca index
  numbered_service_names relay "$TOPOLOGY_RELAY_COUNT"
}

worker_runtime_snapshot_files() {
  printf '%s\n' \
    scripts/local-chaos-stability.sh \
    test/local-chaos/billing-adversary-gate.sh \
    test/local-chaos/billing-production-gate.sh \
    test/local-chaos/mixed-path-gate.sh \
    test/local-chaos/network-pools.sh \
    test/local-chaos/lib.sh
}

prepare_worker_runtime_snapshot() {
  local run_dir=$1 source_root=${2:-$ROOT_DIR}
  local snapshot_root="$run_dir/runtime/worker-root"
  local staging_root relative_file source_file destination temp manifest
  [[ -d $run_dir && ! -e $snapshot_root ]] || return 1
  mkdir -p "$run_dir/runtime" || return 1
  staging_root=$(mktemp -d "$run_dir/runtime/.worker-root.XXXXXX") || return 1
  while IFS= read -r relative_file; do
    source_file="$source_root/$relative_file"
    destination="$staging_root/$relative_file"
    if [[ ! -f $source_file ]]; then
      rm -rf "$staging_root"
      return 1
    fi
    mkdir -p "$(dirname "$destination")" || {
      rm -rf "$staging_root"
      return 1
    }
    temp=$(mktemp "$staging_root/.snapshot.XXXXXX") || {
      rm -rf "$staging_root"
      return 1
    }
    if ! cp -- "$source_file" "$temp" || ! bash -n "$temp"; then
      rm -f "$temp"
      rm -rf "$staging_root"
      return 1
    fi
    chmod 500 "$temp" || {
      rm -f "$temp"
      rm -rf "$staging_root"
      return 1
    }
    mv -- "$temp" "$destination" || {
      rm -f "$temp"
      rm -rf "$staging_root"
      return 1
    }
  done < <(worker_runtime_snapshot_files)
  manifest="$staging_root/worker-runtime.sha256"
  if ! (
    cd "$staging_root" || exit 1
    sha256sum $(worker_runtime_snapshot_files) > "$manifest"
  ); then
    rm -rf "$staging_root"
    return 1
  fi
  chmod 400 "$manifest" || {
    rm -rf "$staging_root"
    return 1
  }
  chmod 500 "$staging_root/scripts" "$staging_root/test" \
    "$staging_root/test/local-chaos" || {
    rm -rf "$staging_root"
    return 1
  }
  mv -- "$staging_root" "$snapshot_root" || {
    rm -rf "$staging_root"
    return 1
  }
  printf '%s\n' "$snapshot_root/scripts/local-chaos-stability.sh"
}

is_positive_integer() {
  [[ $1 =~ ^[1-9][0-9]*$ ]]
}

validation_mode_attempt_timeout_seconds() {
  case ${1:-$DEFAULT_VALIDATION_MODE} in
    smoke) printf '%s\n' "$SMOKE_RANDOM_ATTEMPT_TIMEOUT_SECONDS" ;;
    full) printf '%s\n' "$DEFAULT_RANDOM_ATTEMPT_TIMEOUT_SECONDS" ;;
    *) return 1 ;;
  esac
}

random_worker_drain_timeout_seconds() {
  local attempt_timeout_seconds=$1 stop_grace_seconds=${2:-$DEFAULT_RANDOM_WORKER_STOP_TIMEOUT_SECONDS}
  is_positive_integer "$attempt_timeout_seconds" || return 1
  is_nonnegative_integer "$stop_grace_seconds" || return 1
  printf '%s\n' "$((attempt_timeout_seconds + stop_grace_seconds))"
}

deadline_step_timeout_seconds() {
  local deadline_epoch=$1 maximum_seconds=$2 now_epoch remaining_seconds
  [[ $deadline_epoch =~ ^[1-9][0-9]*$ ]] || return 1
  is_positive_integer "$maximum_seconds" || return 1
  now_epoch=$(date +%s)
  remaining_seconds=$((deadline_epoch - now_epoch))
  (( remaining_seconds > 0 )) || return 1
  if (( remaining_seconds < maximum_seconds )); then
    printf '%s\n' "$remaining_seconds"
  else
    printf '%s\n' "$maximum_seconds"
  fi
}

is_nonnegative_integer() {
  [[ $1 =~ ^[0-9]+$ ]]
}

is_percentage() {
  awk -v value="$1" 'BEGIN { exit !(value ~ /^[0-9]+([.][0-9]+)?$/ && value >= 0 && value <= 100) }'
}

is_port() {
  [[ $1 =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 ))
}

pid_matches() {
  local pid=$1 expected_start=$2 expected_token=$3 current_start cmdline
  [[ $pid =~ ^[1-9][0-9]*$ && -r /proc/$pid/stat ]] || return 1
  current_start=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null || true)
  [[ $current_start == "$expected_start" ]] || return 1
  cmdline=$({ tr '\0' ' ' < "/proc/$pid/cmdline"; } 2>/dev/null || true)
  [[ $cmdline == *"$expected_token"* ]]
}

process_starttime() {
  local pid=$1
  [[ $pid =~ ^[1-9][0-9]*$ && -r /proc/$pid/stat ]] || return 1
  awk '{print $22}' "/proc/$pid/stat" 2>/dev/null
}

process_group_id() {
  local pid=$1 group_id
  [[ $pid =~ ^[1-9][0-9]*$ ]] || return 1
  group_id=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d '[:space:]')
  [[ $group_id =~ ^[1-9][0-9]*$ ]] || return 1
  printf '%s\n' "$group_id"
}

process_identity_alive() {
  local pid=$1 expected_start=$2 expected_group=$3 current_start current_group state
  [[ $pid =~ ^[1-9][0-9]*$ && $expected_start =~ ^[1-9][0-9]*$ \
    && $expected_group =~ ^[1-9][0-9]*$ ]] || return 1
  current_start=$(process_starttime "$pid" 2>/dev/null || true)
  [[ $current_start == "$expected_start" ]] || return 1
  current_group=$(process_group_id "$pid" 2>/dev/null || true)
  [[ $current_group == "$expected_group" ]] || return 1
  state=$(ps -o stat= -p "$pid" 2>/dev/null | tr -d '[:space:]')
  [[ -n $state && $state != Z* ]]
}

process_is_alive() {
  local pid=$1 state
  [[ $pid =~ ^[1-9][0-9]*$ ]] || return 1
  state=$(ps -o stat= -p "$pid" 2>/dev/null | tr -d '[:space:]')
  [[ -n $state && $state != Z* ]]
}

random_worker_tracking_valid() {
  (( ${#RANDOM_WORKER_PIDS[@]} == ${#RANDOM_WORKER_STARTTIMES[@]} \
    && ${#RANDOM_WORKER_PIDS[@]} == ${#RANDOM_WORKER_PGIDS[@]} \
    && ${#RANDOM_WORKER_PIDS[@]} == ${#RANDOM_WORKER_TOKENS[@]} ))
}

clear_random_worker_tracking() {
  RANDOM_WORKER_PIDS=()
  RANDOM_WORKER_STARTTIMES=()
  RANDOM_WORKER_PGIDS=()
  RANDOM_WORKER_TOKENS=()
}

create_random_worker_token() {
  local token
  token=$(od -An -N16 -tx1 /dev/urandom 2>/dev/null | tr -d '[:space:]') || return 1
  [[ $token =~ ^[[:xdigit:]]{32}$ ]] || return 1
  printf '%s\n' "${token,,}"
}

process_has_random_worker_token() {
  local pid=$1 token=$2 entry
  [[ $pid =~ ^[1-9][0-9]*$ && $token =~ ^[[:xdigit:]]{32}$ && -r /proc/$pid/environ ]] || return 1
  while IFS= read -r -d '' entry; do
    [[ $entry == "BNFS_RANDOM_WORKER_TOKEN=$token" ]] && return 0
  done < "/proc/$pid/environ"
  return 1
}

random_worker_token_mismatch_is_live() {
  local pid=$1 expected_group=$2 state current_group
  [[ $pid =~ ^[1-9][0-9]*$ && $expected_group =~ ^[1-9][0-9]*$ ]] || return 1
  state=$(ps -o stat= -p "$pid" 2>/dev/null | tr -d '[:space:]')
  [[ -n $state && $state != Z* ]] || return 1
  current_group=$(process_group_id "$pid" 2>/dev/null || true)
  [[ $current_group == "$expected_group" ]]
}

track_random_worker() {
  local pid=$1 token=$2 start= group_id= attempt
  [[ $token =~ ^[[:xdigit:]]{32}$ ]] || return 1
  for attempt in $(seq 1 50); do
    start=$(process_starttime "$pid" 2>/dev/null || true)
    group_id=$(process_group_id "$pid" 2>/dev/null || true)
    if [[ $start =~ ^[1-9][0-9]*$ && $group_id == "$pid" ]] \
      && process_has_random_worker_token "$pid" "$token"; then
      break
    fi
    kill -0 "$pid" 2>/dev/null || return 1
    sleep 0.02
  done
  [[ $start =~ ^[1-9][0-9]*$ && $group_id == "$pid" ]] \
    && process_has_random_worker_token "$pid" "$token" || return 1
  RANDOM_WORKER_PIDS+=("$pid")
  RANDOM_WORKER_STARTTIMES+=("$start")
  RANDOM_WORKER_PGIDS+=("$group_id")
  RANDOM_WORKER_TOKENS+=("$token")
}

random_worker_registered() {
  local registry=$1 client=$2 pid=$3 start=$4 group_id=$5 token=$6
  [[ -f $registry ]] || return 1
  awk -F '\t' -v client="$client" -v pid="$pid" -v start="$start" \
    -v group_id="$group_id" -v token="$token" '
      $1 == client && $2 == pid && $3 == start && $4 == group_id && $5 == token {
        found = 1
      }
      END { exit !found }
    ' "$registry"
}

wait_random_worker_registered() {
  local registry=$1 client=$2 pid=$3 start=$4 group_id=$5 token=$6 attempt
  for attempt in $(seq 1 50); do
    random_worker_registered "$registry" "$client" "$pid" "$start" "$group_id" "$token" \
      && return 0
    kill -0 "$pid" 2>/dev/null || return 1
    sleep 0.02
  done
  return 1
}

registered_random_worker() {
  local run_dir=$1 client=$2 expected_runner_pid=$3 expected_runner_start=$4
  shift 4
  local registry=$run_dir/worker-pids.tsv
  local registry_lock=$run_dir/worker-pids.lock
  local registry_closed=$run_dir/worker-pids.closed
  local token=${BNFS_RANDOM_WORKER_TOKEN:-}
  local worker_pid=$$ worker_start worker_group
  worker_start=$(process_starttime "$worker_pid" 2>/dev/null || true)
  worker_group=$(process_group_id "$worker_pid" 2>/dev/null || true)
  [[ $client == batch-scheduler || $client =~ ^natclient0[1-6]$ || $client == "$MALICIOUS_NAT_CLIENT" ]] || return 1
  [[ $token =~ ^[[:xdigit:]]{32}$ \
    && $worker_start =~ ^[1-9][0-9]*$ && $worker_group == "$worker_pid" ]] || return 1

  exec 8> "$registry_lock"
  flock -x 8 || return 1
  [[ ! -e $registry_closed \
    && $(head -n 1 "$registry" 2>/dev/null || true) == $'client\tpid\tstarttime\tpgid\ttoken' \
    && $expected_runner_pid =~ ^[1-9][0-9]*$ \
    && $expected_runner_start =~ ^[1-9][0-9]*$ \
    && $(process_starttime "$expected_runner_pid" 2>/dev/null || true) == "$expected_runner_start" \
    && $(process_group_id "$expected_runner_pid" 2>/dev/null || true) == "$expected_runner_pid" ]] \
    || return 1
  if awk -F '\t' -v client="$client" -v pid="$worker_pid" -v group_id="$worker_group" \
    -v token="$token" 'NR > 1 && ($1 == client || $2 == pid || $4 == group_id || $5 == token) { found=1 } END { exit !found }' \
    "$registry"; then
    return 1
  fi
  printf '%s\t%s\t%s\t%s\t%s\n' \
    "$client" "$worker_pid" "$worker_start" "$worker_group" "$token" >> "$registry"
  flock -u 8
  exec 8>&-
  if [[ $client == batch-scheduler ]]; then
    exec bash "${STABILITY_WORKER_SCRIPT:-$ROOT_DIR/scripts/local-chaos-stability.sh}" \
      _batch_worker "$run_dir" "$@"
  fi
  exec bash "${STABILITY_WORKER_SCRIPT:-$ROOT_DIR/scripts/local-chaos-stability.sh}" \
    _worker "$run_dir" "$client" "$@"
}

random_worker_identity_alive() {
  local index=$1
  random_worker_tracking_valid || return 1
  [[ $index =~ ^[0-9]+$ && $index -lt ${#RANDOM_WORKER_PIDS[@]} ]] || return 1
  process_identity_alive "${RANDOM_WORKER_PIDS[$index]}" \
    "${RANDOM_WORKER_STARTTIMES[$index]}" "${RANDOM_WORKER_PGIDS[$index]}" \
    && process_has_random_worker_token "${RANDOM_WORKER_PIDS[$index]}" \
      "${RANDOM_WORKER_TOKENS[$index]}"
}

random_worker_group_identity_valid() {
  local index=$1 pid expected_start expected_group token current_start current_group members member state
  random_worker_tracking_valid || return 1
  [[ $index =~ ^[0-9]+$ && $index -lt ${#RANDOM_WORKER_PIDS[@]} ]] || return 1
  pid=${RANDOM_WORKER_PIDS[$index]}
  expected_start=${RANDOM_WORKER_STARTTIMES[$index]}
  expected_group=${RANDOM_WORKER_PGIDS[$index]}
  token=${RANDOM_WORKER_TOKENS[$index]}
  [[ $pid == "$expected_group" && $expected_start =~ ^[1-9][0-9]*$ \
    && $token =~ ^[[:xdigit:]]{32}$ ]] || return 1
  members=$(random_worker_group_members "$expected_group") || return 1
  [[ -n $members ]] || return 1
  if [[ -r /proc/$pid/stat ]]; then
    current_start=$(process_starttime "$pid" 2>/dev/null || true)
    current_group=$(process_group_id "$pid" 2>/dev/null || true)
    state=$(ps -o stat= -p "$pid" 2>/dev/null | tr -d '[:space:]')
    [[ $current_start == "$expected_start" && $current_group == "$expected_group" \
      && -n $state ]] || return 1
  fi
  while IFS= read -r member; do
    [[ -r /proc/$member/stat ]] || continue
    current_group=$(process_group_id "$member" 2>/dev/null || true)
    [[ -n $current_group ]] || continue
    [[ $current_group == "$expected_group" ]] || return 1
    if ! process_has_random_worker_token "$member" "$token"; then
      # A process can exit after the group snapshot but before /proc/environ is
      # read. Recheck its non-zombie identity before treating it as tokenless.
      random_worker_token_mismatch_is_live "$member" "$expected_group" || continue
      return 1
    fi
  done <<< "$members"
}

random_worker_group_members() {
  local group_id=$1
  [[ $group_id =~ ^[1-9][0-9]*$ ]] || return 1
  ps -eo pid=,pgid=,stat= | awk -v group_id="$group_id" '
    $2 == group_id && $3 !~ /^Z/ { print $1 }
  '
}

random_worker_group_alive() {
  local group_id=$1 members
  members=$(random_worker_group_members "$group_id") || return 1
  [[ -n $members ]]
}

random_worker_groups_valid_for_signal() {
  local index pid group_id
  random_worker_tracking_valid || return 1
  for index in "${!RANDOM_WORKER_PIDS[@]}"; do
    pid=${RANDOM_WORKER_PIDS[$index]}
    group_id=${RANDOM_WORKER_PGIDS[$index]}
    if random_worker_group_alive "$group_id"; then
      random_worker_group_identity_valid "$index" || return 1
    elif process_is_alive "$pid"; then
      return 1
    fi
  done
}

signal_random_worker_groups() {
  local signal=$1 index group_id
  [[ $signal == TERM || $signal == KILL ]] || return 1
  random_worker_groups_valid_for_signal || return 1
  for index in "${!RANDOM_WORKER_PIDS[@]}"; do
    group_id=${RANDOM_WORKER_PGIDS[$index]}
    random_worker_group_alive "$group_id" || continue
    random_worker_group_identity_valid "$index" || return 1
    if ! kill -"$signal" -- "-$group_id" 2>/dev/null; then
      random_worker_group_alive "$group_id" && return 1
    fi
  done
}

stop_dashboard_process() {
  local run_dir=$1 pid start attempt
  [[ -f $run_dir/dashboard.pid && -f $run_dir/dashboard.starttime ]] || return 0
  pid=$(cat "$run_dir/dashboard.pid" 2>/dev/null || true)
  start=$(cat "$run_dir/dashboard.starttime" 2>/dev/null || true)
  pid_matches "$pid" "$start" 'monitor/server.mjs' \
    && process_identity_alive "$pid" "$start" "$pid" || return 0

  kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
  for attempt in $(seq 1 20); do
    pid_matches "$pid" "$start" 'monitor/server.mjs' \
      && process_identity_alive "$pid" "$start" "$pid" || return 0
    sleep 0.1
  done
  if pid_matches "$pid" "$start" 'monitor/server.mjs' \
    && process_identity_alive "$pid" "$start" "$pid"; then
    kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
  fi
  for attempt in $(seq 1 20); do
    pid_matches "$pid" "$start" 'monitor/server.mjs' || return 0
    sleep 0.1
  done
  return 1
}

stop_reconnect_gate_process() {
  local run_dir=$1 pid start attempt
  [[ -f $run_dir/reconnect-gate.pid && -f $run_dir/reconnect-gate.starttime ]] || return 0
  pid=$(cat "$run_dir/reconnect-gate.pid" 2>/dev/null || true)
  start=$(cat "$run_dir/reconnect-gate.starttime" 2>/dev/null || true)
  pid_matches "$pid" "$start" 'reconnect-gate.mjs' \
    && process_identity_alive "$pid" "$start" "$pid" || return 0

  kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
  for attempt in $(seq 1 30); do
    pid_matches "$pid" "$start" 'reconnect-gate.mjs' \
      && process_identity_alive "$pid" "$start" "$pid" || return 0
    sleep 0.1
  done
  if pid_matches "$pid" "$start" 'reconnect-gate.mjs' \
    && process_identity_alive "$pid" "$start" "$pid"; then
    kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
  fi
  for attempt in $(seq 1 20); do
    pid_matches "$pid" "$start" 'reconnect-gate.mjs' || return 0
    sleep 0.1
  done
  return 1
}

dashboard_run_for_pid() {
  local target_pid=$1 pid_file run_dir tracked_pid tracked_start
  for pid_file in "$SOAK_HOME"/runs/*/dashboard.pid; do
    [[ -f $pid_file ]] || continue
    run_dir=${pid_file%/dashboard.pid}
    [[ -f $run_dir/dashboard.starttime ]] || continue
    tracked_pid=$(cat "$pid_file" 2>/dev/null || true)
    [[ $tracked_pid == "$target_pid" ]] || continue
    tracked_start=$(cat "$run_dir/dashboard.starttime" 2>/dev/null || true)
    if pid_matches "$tracked_pid" "$tracked_start" 'monitor/server.mjs'; then
      printf '%s\n' "$run_dir"
      return 0
    fi
  done
  return 1
}

read_current_run() {
  [[ -f $CURRENT_FILE ]] || return 1
  cat "$CURRENT_FILE"
}

current_runner_alive() {
  local run_dir=$1 pid start
  [[ -f $run_dir/runner.pid && -f $run_dir/runner.starttime ]] || return 1
  pid=$(cat "$run_dir/runner.pid")
  start=$(cat "$run_dir/runner.starttime")
  pid_matches "$pid" "$start" 'local-chaos-stability.sh _run' \
    && process_identity_alive "$pid" "$start" "$pid"
}

write_metadata() {
  local run_dir=$1
  shift
  printf '%s\n' "$@" > "$run_dir/metadata.env"
}

set_phase() {
  local run_dir=$1 phase=$2
  printf '%s\n' "$phase" > "$run_dir/phase"
}

completed_terminal_evidence_valid() {
  local status_file=$1
  [[ $(run_field "$status_file" outcome 2>/dev/null || true) == COMPLETED \
    && $(run_field "$status_file" detail 2>/dev/null || true) == duration_complete \
    && $(run_field "$status_file" remaining_containers 2>/dev/null || true) == 0 \
    && $(run_field "$status_file" remaining_networks 2>/dev/null || true) == 0 ]]
}

publish_terminal_result() {
  local run_dir=$1 outcome=$2 detail=$3 remaining_containers=$4 remaining_networks=$5
  local finished_epoch status_temporary phase_temporary
  case $outcome in
    COMPLETED|FAILED|RESOURCE_LIMIT|STOPPED) ;;
    *) return 1 ;;
  esac
  [[ $detail =~ ^[a-z0-9_]+$ ]] || return 1
  [[ $remaining_containers == unknown || $remaining_containers =~ ^[0-9]+$ ]] || return 1
  [[ $remaining_networks == unknown || $remaining_networks =~ ^[0-9]+$ ]] || return 1
  if [[ $outcome == COMPLETED ]]; then
    [[ $detail == duration_complete && $remaining_containers == 0 \
      && $remaining_networks == 0 ]] || return 1
  fi
  finished_epoch=$(date +%s) || return 1
  status_temporary=$run_dir/status.env.tmp.$BASHPID
  phase_temporary=$run_dir/phase.tmp.$BASHPID
  if ! printf 'outcome=%s\ndetail=%s\nfinished_epoch=%s\nremaining_containers=%s\nremaining_networks=%s\n' \
    "$outcome" "$detail" "$finished_epoch" "$remaining_containers" "$remaining_networks" \
    > "$status_temporary" \
    || ! printf '%s\n' "$outcome" > "$phase_temporary"; then
    rm -f "$status_temporary" "$phase_temporary"
    return 1
  fi
  if ! mv "$status_temporary" "$run_dir/status.env"; then
    rm -f "$status_temporary" "$phase_temporary"
    return 1
  fi
  if ! mv "$phase_temporary" "$run_dir/phase"; then
    rm -f "$phase_temporary"
    return 1
  fi
}

random_scenario() {
  local value
  value=$(od -An -N4 -tu4 /dev/urandom | tr -d '[:space:]')
  [[ $value =~ ^[0-9]+$ ]] || return 1
  printf '%s\t%s\n' "$((value % 3 + 1))" "$value"
}

is_ip_family_coverage_mode() {
  [[ ${1:-} == off || ${1:-} == random ]]
}

create_ip_family_plan() {
  local run_dir=$1 mode=$2 selected=${3:-} plan_file family relay natserver natclient excluded_client= scenario_reserved_server=
  local -a relays=() natservers=() natclients=()
  is_ip_family_coverage_mode "$mode" || return 1
  plan_file=$run_dir/ip-family-plan.tsv
  if [[ $mode == off ]]; then
    rm -f "$plan_file"
    return 0
  fi
  mapfile -t relays < <(numbered_service_names relay "$TOPOLOGY_RELAY_COUNT" | awk '/^relay0[3-7]$/' | shuf -n 3)
  # natserver06 is reserved by the production waitSubmit recovery gate.
  [[ $selected != 2 ]] || scenario_reserved_server=natserver02
  mapfile -t natservers < <(numbered_service_names natserver "$TOPOLOGY_NAT_SERVER_COUNT" \
    | awk -v reserved="$scenario_reserved_server" '$0 != "natserver06" && $0 != reserved' | shuf -n 3)
  [[ $selected != 2 ]] || excluded_client=natclient04
  mapfile -t natclients < <(numbered_service_names natclient "$TOPOLOGY_NAT_CLIENT_COUNT" \
    | awk -v excluded="$excluded_client" '$0 != excluded' | shuf -n 3)
  (( ${#relays[@]} == 3 && ${#natservers[@]} == 3 && ${#natclients[@]} == 3 )) || return 1
  {
    printf 'family\trelay\tnatserver\tnatclient\n'
    for family in ipv4 ipv6 dual; do
      case $family in
        ipv4) printf '%s\t%s\t%s\t%s\n' "$family" "${relays[0]}" "${natservers[0]}" "${natclients[0]}" ;;
        ipv6) printf '%s\t%s\t%s\t%s\n' "$family" "${relays[1]}" "${natservers[1]}" "${natclients[1]}" ;;
        dual) printf '%s\t%s\t%s\t%s\n' "$family" "${relays[2]}" "${natservers[2]}" "${natclients[2]}" ;;
      esac
    done
  } > "$plan_file"
  chmod 600 "$plan_file"
  validate_ip_family_plan "$plan_file"
}

validate_ip_family_plan() {
  local plan_file=${1:-}
  [[ -s $plan_file && ! -L $plan_file ]] || return 1
  [[ $(wc -l < "$plan_file") -eq 4 ]] || return 1
  awk -F '\t' '
    NR == 1 { valid=($0 == "family\trelay\tnatserver\tnatclient"); next }
    NF != 4 || !($1 == "ipv4" || $1 == "ipv6" || $1 == "dual") \
      || $2 !~ /^relay0[3-7]$/ || $3 !~ /^natserver(0[1-9]|1[0-3])$/ \
      || $4 !~ /^natclient0[1-6]$/ { valid=0; next }
    family[$1]++; relay[$2]++; server[$3]++; client[$4]++
    END {
      valid = valid && family["ipv4"] == 1 && family["ipv6"] == 1 && family["dual"] == 1
      for (name in relay) if (relay[name] != 1) valid=0
      for (name in server) if (server[name] != 1) valid=0
      for (name in client) if (client[name] != 1) valid=0
      exit !valid
    }
  ' "$plan_file"
}

ip_family_plan_file() {
  local run_dir=$1 plan_file=$run_dir/ip-family-plan.tsv
  if [[ -s $plan_file ]] && validate_ip_family_plan "$plan_file"; then
    printf '%s\n' "$plan_file"
  fi
}

service_ip_family() {
  local run_dir=$1 service=$2 plan_file family
  plan_file=$(ip_family_plan_file "$run_dir" 2>/dev/null || true)
  if [[ -n $plan_file ]]; then
    family=$(awk -F '\t' -v service="$service" 'NR > 1 && ($2 == service || $3 == service || $4 == service) { print $1; exit }' "$plan_file")
    if [[ $family == ipv4 || $family == ipv6 || $family == dual ]]; then
      printf '%s\n' "$family"
      return 0
    fi
  fi
  printf 'default\n'
}

service_ip_family_relay() {
  local run_dir=$1 service=$2 fallback_relay=$3 plan_file relay
  [[ $fallback_relay =~ ^relay0[1-7]$ ]] || return 1
  plan_file=$(ip_family_plan_file "$run_dir" 2>/dev/null || true)
  if [[ -n $plan_file ]]; then
    relay=$(awk -F '\t' -v service="$service" 'NR > 1 && ($2 == service || $3 == service || $4 == service) { print $2; exit }' "$plan_file")
    if [[ $relay =~ ^relay0[3-7]$ ]]; then
      printf '%s\n' "$relay"
      return 0
    fi
  fi
  printf '%s\n' "$fallback_relay"
}

ip_family_relay_endpoint() {
  local family=$1 role=$2 fallback_relay=$3
  [[ $fallback_relay =~ ^relay0[1-7]$ ]] || return 1
  case "$family:$role" in
    ipv4:*) printf '10.253.41.250:9000\n' ;;
    ipv6:*) printf '[fd92:7b5e:4c31:42::250]:9000\n' ;;
    dual:natserver) printf '[fd92:7b5e:4c31:43::250]:9000\n' ;;
    dual:*) printf '10.253.43.250:9000\n' ;;
    default:*) printf '%s:9000\n' "$fallback_relay" ;;
    *) return 1 ;;
  esac
}

service_relay_endpoint() {
  local run_dir=$1 service=$2 role=$3 relay=$4 family
  family=$(service_ip_family "$run_dir" "$service") || return 1
  ip_family_relay_endpoint "$family" "$role" "$relay"
}

service_ca_endpoint() {
  local run_dir=$1 service=$2 role=$3 family
  family=$(service_ip_family "$run_dir" "$service") || return 1
  case "$family:$role" in
    ipv4:*) printf 'http://10.253.41.251:9100\n' ;;
    ipv6:*) printf 'http://[fd92:7b5e:4c31:42::251]:9100\n' ;;
    dual:natserver) printf 'http://[fd92:7b5e:4c31:43::251]:9100\n' ;;
    dual:*) printf 'http://10.253.43.251:9100\n' ;;
    default:*) printf 'http://ca:9100\n' ;;
    *) return 1 ;;
  esac
}

launch_tunnel_server_for_ip_family() {
  local run_dir=$1 service=$2 relay=$3 scenario=$4 ca_endpoint relay_endpoint
  ca_endpoint=$(service_ca_endpoint "$run_dir" "$service" natserver) || return 1
  relay_endpoint=$(service_relay_endpoint "$run_dir" "$service" natserver "$relay") || return 1
  BNFS_CHAOS_NAT_CA_URL="$ca_endpoint" launch_tunnel_server "$service" "$relay_endpoint" "$scenario"
}

start_tunnel_server_for_ip_family() {
  local run_dir=$1 service=$2 relay=$3 scenario=$4 size_mb=$5 max_size_mb=$6 send_rate_mibps=$7
  local ca_endpoint relay_endpoint
  ca_endpoint=$(service_ca_endpoint "$run_dir" "$service" natserver) || return 1
  relay_endpoint=$(service_relay_endpoint "$run_dir" "$service" natserver "$relay") || return 1
  BNFS_CHAOS_NAT_CA_URL="$ca_endpoint" start_tunnel_server "$service" "$relay_endpoint" \
    "$scenario" "$size_mb" "$max_size_mb" "$send_rate_mibps"
}

restart_tunnel_server_for_ip_family() {
  local run_dir=$1 service=$2 relay=$3 scenario=$4 ca_endpoint relay_endpoint
  ca_endpoint=$(service_ca_endpoint "$run_dir" "$service" natserver) || return 1
  relay_endpoint=$(service_relay_endpoint "$run_dir" "$service" natserver "$relay") || return 1
  BNFS_CHAOS_NAT_CA_URL="$ca_endpoint" restart_tunnel_server "$service" "$relay_endpoint" "$scenario"
}

launch_tunnel_client_for_ip_family() {
  local run_dir=$1 service=$2 relay=$3 target_id=$4 listen_port=$5 scenario=$6
  local ca_endpoint relay_endpoint
  ca_endpoint=$(service_ca_endpoint "$run_dir" "$service" natclient) || return 1
  relay_endpoint=$(service_relay_endpoint "$run_dir" "$service" natclient "$relay") || return 1
  BNFS_CHAOS_NAT_CA_URL="$ca_endpoint" launch_tunnel_client "$service" "$relay_endpoint" \
    "$target_id" "$listen_port" "$scenario"
}

create_unique_run_directory() {
  local scenario=$1 attempt nonce run_id run_dir
  mkdir -p "$SOAK_HOME/runs"
  for attempt in $(seq 1 20); do
    nonce=$(od -An -N8 -tx1 /dev/urandom 2>/dev/null | tr -d '[:space:]') || return 1
    [[ $nonce =~ ^[[:xdigit:]]{16}$ ]] || return 1
    run_id=$(date -u +%Y%m%dT%H%M%S.%NZ)-${nonce,,}-s${scenario}
    run_dir=$SOAK_HOME/runs/$run_id
    if mkdir "$run_dir" 2>/dev/null; then
      chmod 700 "$run_dir"
      printf '%s\t%s\n' "$run_id" "$run_dir"
      return 0
    fi
  done
  return 1
}

start_run() {
  local scenario= random_value= duration=$DEFAULT_DURATION_SECONDS
  local cpu_limit=$DEFAULT_CPU_LIMIT memory_limit=$DEFAULT_MEMORY_LIMIT disk_limit=$DEFAULT_DISK_LIMIT
  local sample_seconds=$DEFAULT_SAMPLE_SECONDS probe_seconds=$DEFAULT_PROBE_SECONDS
  local max_inflight=$DEFAULT_MAX_INFLIGHT
  local workload_limit_mibps=$DEFAULT_WORKLOAD_LIMIT_MIBPS
  local billing_adversary_mode=$DEFAULT_BILLING_ADVERSARY_MODE
  local validation_mode=$DEFAULT_VALIDATION_MODE random_attempt_timeout_seconds random_drain_timeout_seconds
  local ip_family_coverage=$DEFAULT_IP_FAMILY_COVERAGE
  local dashboard_host=$DEFAULT_DASHBOARD_HOST dashboard_port=$DEFAULT_DASHBOARD_PORT
  local ca_port=$DEFAULT_CA_PORT ca_web_port=$DEFAULT_CA_WEB_PORT

  scenario=random
  while (($#)); do
    case "$1" in
      --scenario) scenario=${2:?}; shift 2 ;;
      --duration-seconds) duration=${2:?}; shift 2 ;;
      --cpu-limit) cpu_limit=${2:?}; shift 2 ;;
      --memory-limit) memory_limit=${2:?}; shift 2 ;;
      --disk-limit) disk_limit=${2:?}; shift 2 ;;
      --sample-seconds) sample_seconds=${2:?}; shift 2 ;;
      --probe-seconds) probe_seconds=${2:?}; shift 2 ;;
      --max-inflight) max_inflight=${2:?}; shift 2 ;;
      --workload-limit-mibps) workload_limit_mibps=${2:?}; shift 2 ;;
      --dashboard-host) dashboard_host=${2:?}; shift 2 ;;
      --dashboard-port) dashboard_port=${2:?}; shift 2 ;;
      --ca-port) ca_port=${2:?}; shift 2 ;;
      --ca-web-port) ca_web_port=${2:?}; shift 2 ;;
      --billing-adversary) billing_adversary_mode=${2:?}; shift 2 ;;
      --validation-mode) validation_mode=${2:?}; shift 2 ;;
      --ip-family-coverage) ip_family_coverage=${2:?}; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
  done

  [[ $scenario == random || $scenario == 1 || $scenario == 2 || $scenario == 3 ]] || {
    printf 'invalid scenario: %s\n' "$scenario" >&2
    exit 2
  }
  for value in "$duration" "$sample_seconds" "$probe_seconds" "$max_inflight"; do
    is_positive_integer "$value" || { printf 'expected positive integer: %s\n' "$value" >&2; exit 2; }
  done
  (( max_inflight == 1 )) || {
    printf 'max-inflight must be 1 for the coordinated random batch scheduler\n' >&2
    exit 2
  }
  is_nonnegative_integer "$workload_limit_mibps" || {
    printf 'expected non-negative integer: %s\n' "$workload_limit_mibps" >&2
    exit 2
  }
  local per_transfer_limit_mibps=0
  if (( workload_limit_mibps > 0 )); then
    per_transfer_limit_mibps=$workload_limit_mibps
  fi
  for value in "$dashboard_port" "$ca_port" "$ca_web_port"; do
    is_port "$value" || { printf 'invalid TCP port: %s\n' "$value" >&2; exit 2; }
  done
  [[ $dashboard_host =~ ^[A-Za-z0-9.-]+$ ]] || {
    printf 'invalid dashboard host: %s\n' "$dashboard_host" >&2
    exit 2
  }
  [[ $billing_adversary_mode == enforce || $billing_adversary_mode == report || $billing_adversary_mode == off ]] || {
    printf 'invalid billing adversary mode: %s\n' "$billing_adversary_mode" >&2
    exit 2
  }
  is_ip_family_coverage_mode "$ip_family_coverage" || {
    printf 'invalid IP family coverage mode: %s\n' "$ip_family_coverage" >&2
    exit 2
  }
  random_attempt_timeout_seconds=$(validation_mode_attempt_timeout_seconds "$validation_mode") || {
    printf 'invalid validation mode: %s\n' "$validation_mode" >&2
    exit 2
  }
  random_drain_timeout_seconds=$(random_worker_drain_timeout_seconds \
    "$random_attempt_timeout_seconds") || exit 2
  for value in "$cpu_limit" "$memory_limit" "$disk_limit"; do
    is_percentage "$value" || { printf 'invalid percentage: %s\n' "$value" >&2; exit 2; }
  done

  mkdir -p "$STATE_DIR" "$SOAK_HOME/runs"
  exec 9> "$STATE_DIR/start.lock"
  flock -n 9 || { printf 'another stability start/stop operation is active\n' >&2; exit 2; }

  local previous
  previous=$(read_current_run 2>/dev/null || true)
  if [[ -n $previous ]] && current_runner_alive "$previous"; then
    printf 'a stability run is already active: %s\n' "$previous" >&2
    exit 2
  fi
  if [[ -n $previous ]] && ! stop_dashboard_process "$previous"; then
    printf 'unable to stop the previous stability dashboard: %s\n' "$previous" >&2
    exit 2
  fi
  if [[ -n $previous ]] && ! stop_reconnect_gate_process "$previous"; then
    printf 'unable to stop the previous reconnect gate: %s\n' "$previous" >&2
    exit 2
  fi

  select_topology_network_octets || exit 1

  if [[ $scenario == random ]]; then
    read -r scenario random_value < <(random_scenario)
  else
    random_value=explicit
  fi

  local run_id run_dir project project_suffix
  if ! IFS=$'\t' read -r run_id run_dir < <(create_unique_run_directory "$scenario"); then
    printf 'unable to allocate a unique stability run directory\n' >&2
    exit 1
  fi
  project_suffix=${run_id//[^a-zA-Z0-9]/}
  project=bnfs-soak-${project_suffix,,}
  if ! create_ip_family_plan "$run_dir" "$ip_family_coverage" "$scenario"; then
    printf 'unable to create IP family coverage plan\n' >&2
    rm -f "$run_dir/ip-family-plan.tsv"
    rmdir "$run_dir" 2>/dev/null || true
    exit 1
  fi
  printf '%s\n' "$run_dir" > "$CURRENT_FILE"
  write_metadata "$run_dir" \
    "run_id=$run_id" \
    "scenario=$scenario" \
    "scenario_name=$(scenario_name "$scenario")" \
    "random_value=$random_value" \
    "duration_seconds=$duration" \
    "cpu_limit_pct=$cpu_limit" \
    "memory_limit_pct=$memory_limit" \
    "disk_limit_pct=$disk_limit" \
    "sample_seconds=$sample_seconds" \
    "probe_seconds=$probe_seconds" \
    "max_inflight=$max_inflight" \
    "workload_limit_mibps=$workload_limit_mibps" \
    "per_transfer_limit_mibps=$per_transfer_limit_mibps" \
    "dashboard_host=$dashboard_host" \
    "dashboard_port=$dashboard_port" \
    "ca_port=$ca_port" \
    "ca_web_port=$ca_web_port" \
    "billing_adversary_mode=$billing_adversary_mode" \
    "validation_mode=$validation_mode" \
    "ip_family_coverage=$ip_family_coverage" \
    "ip_family_plan_file=$run_dir/ip-family-plan.tsv" \
    "control_network_second_octet=$BNFS_CHAOS_CONTROL_NETWORK_SECOND_OCTET" \
    "access_network_second_octet=$BNFS_CHAOS_ACCESS_NETWORK_SECOND_OCTET" \
    "random_attempt_timeout_seconds=$random_attempt_timeout_seconds" \
    "random_worker_drain_timeout_seconds=$random_drain_timeout_seconds" \
    "compose_project=$project"
  set_phase "$run_dir" LAUNCHING

  nohup setsid bash "$0" _run "$run_dir" > "$run_dir/supervisor.log" 2>&1 < /dev/null &
  local launcher_pid=$!
  printf '%s\n' "$launcher_pid" > "$run_dir/runner.pid"
  # The start/stop lock protects state publication, not the whole potentially
  # multi-minute startup. Release it once the detached runner has published
  # its PID identity so `stop` remains available during BUILDING/STARTING.
  for _ in $(seq 1 50); do
    [[ -s $run_dir/runner.starttime ]] && break
    kill -0 "$launcher_pid" 2>/dev/null || break
    sleep 0.1
  done
  flock -u 9
  exec 9>&-
  for _ in $(seq 1 150); do
    local phase
    phase=$(cat "$run_dir/phase" 2>/dev/null || true)
    case "$phase" in
      RUNNING|FAILED|RESOURCE_LIMIT|COMPLETED|STOPPED) break ;;
    esac
    kill -0 "$launcher_pid" 2>/dev/null || break
    sleep 2
  done

  local phase
  phase=$(cat "$run_dir/phase" 2>/dev/null || printf 'UNKNOWN')
  printf 'run_id=%s\nscenario=%s\nscenario_name=%s\nphase=%s\nrun_dir=%s\ndashboard=http://%s:%s/\nca_web=https://%s:%s/\n' \
    "$run_id" "$scenario" "$(scenario_name "$scenario")" "$phase" "$run_dir" \
    "$dashboard_host" "$dashboard_port" "$dashboard_host" "$ca_web_port"
  if [[ $phase == COMPLETED ]]; then
    completed_terminal_evidence_valid "$run_dir/status.env"
    return
  fi
  [[ $phase == RUNNING || $phase == BUILDING || $phase == STARTING_CLUSTER \
    || $phase == CONFIGURING_PROFILE || $phase == VERIFYING_BILLING ]]
}

run_foreground() {
  local wait_interval=$DEFAULT_WAIT_INTERVAL_SECONDS
  local -a start_args=()
  while (($#)); do
    case "$1" in
      --wait-interval-seconds)
        wait_interval=${2:?}
        shift 2
        ;;
      *)
        start_args+=("$1")
        shift
        ;;
    esac
  done
  is_positive_integer "$wait_interval" || {
    printf 'expected positive integer: %s\n' "$wait_interval" >&2
    return 2
  }
  start_run "${start_args[@]}" || return $?
  local run_dir
  run_dir=$(read_current_run 2>/dev/null || true)
  [[ -n $run_dir && -d $run_dir ]] || {
    printf 'started stability run is unavailable\n' >&2
    return 1
  }
  wait_for_run_completion "$run_dir" "$wait_interval"
}

credit_node() {
  local ca_port=$1 node_id=$2 add_bytes=$3 response balance payload token
  payload="{\"node_id\":\"$node_id\",\"add_bytes\":$add_bytes}"
  token=$(<"$PRIVATE_RUNTIME_DIR/ca/admin.token") || return 1
  response=$(curl -fsS --connect-timeout 5 --max-time 10 \
    -H "Authorization: Bearer $token" -H "Content-Type: application/json" \
    --data-binary "$payload" "http://127.0.0.1:$ca_port/credit") || return 1
  balance=$(sed -n 's/.*"balance":[[:space:]]*\([-0-9][0-9]*\).*/\1/p' <<< "$response")
  [[ $balance =~ ^[1-9][0-9]*$ ]]
}

provision_container_adversaries() {
  local run_dir=$1 ca_port=$2
  PRIVATE_RUNTIME_DIR="$PRIVATE_RUNTIME_DIR" \
    CA_BASE_URL="http://127.0.0.1:$ca_port" \
    node "$ROOT_DIR/test/local-chaos/provision-adversaries.mjs" \
      > "$run_dir/container-adversary-provision.log" 2>&1
}

generate_key() {
  local path=$1
  openssl rand -hex 32 > "$path"
  chmod 600 "$path"
}

prepare_profile_setup_identity() {
  local service=$1 directory
  [[ $service =~ ^nat(server|client)[0-9]{2}$ ]] || return 1
  directory=$PRIVATE_RUNTIME_DIR/$service/$PROFILE_SETUP_PRIVATE_SUBDIR
  mkdir -p "$directory"
  chmod 700 "$directory"
  generate_key "$directory/$service.key"
}

nat_key_host_file() {
  local service=$1 directory key_directory=${BNFS_CHAOS_NAT_KEY_DIR:-/artifacts/.private}
  [[ $service =~ ^nat(server|client)[0-9]{2}$ ]] || return 1
  case $key_directory in
    /artifacts/.private)
      directory=$PRIVATE_RUNTIME_DIR/$service
      ;;
    "$PROFILE_SETUP_NAT_KEY_DIR")
      directory=$PRIVATE_RUNTIME_DIR/$service/$PROFILE_SETUP_PRIVATE_SUBDIR
      ;;
    *)
      return 1
      ;;
  esac
  printf '%s/%s.key\n' "$directory" "$service"
}

ensure_key() {
  local path=$1
  [[ -s $path ]] || generate_key "$path"
}

node_id_from_private_key() {
  node "$ROOT_DIR/test/local-chaos/node-id-from-key.mjs" "$1"
}

wait_service_health() {
  local service=$1 timeout_seconds=$2 deadline id health
  deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    id=$(dc ps -q "$service" 2>/dev/null || true)
    health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$id" 2>/dev/null || true)
    [[ $health == healthy ]] && return 0
    sleep 1
  done
  return 1
}

wait_dashboard_health() {
  local dashboard_host=$1 dashboard_port=$2 deadline probe_host
  probe_host=$dashboard_host
  [[ $probe_host != 0.0.0.0 ]] || probe_host=127.0.0.1
  deadline=$((SECONDS + 15))
  while (( SECONDS < deadline )); do
    if curl -fsS --connect-timeout 1 --max-time 2 "http://$probe_host:$dashboard_port/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

DASHBOARD_STATUS_PROBE_DETAIL=
probe_dashboard_status() {
  local dashboard_host=$1 dashboard_port=$2 response_file=$3 expected_phase=${4:-}
  local probe_host http_status validation_rc=0
  probe_host=$dashboard_host
  [[ $probe_host != 0.0.0.0 ]] || probe_host=127.0.0.1
  DASHBOARD_STATUS_PROBE_DETAIL=dashboard_status_api_transport_failed
  http_status=$(curl -sS --connect-timeout 1 --max-time 4 \
    --output "$response_file" --write-out '%{http_code}' \
    "http://$probe_host:$dashboard_port/api/status?fresh=1" 2>/dev/null) || {
    rm -f "$response_file"
    return 1
  }
  if [[ $http_status != 200 ]]; then
    DASHBOARD_STATUS_PROBE_DETAIL=dashboard_status_api_http_invalid
    rm -f "$response_file"
    return 1
  fi
  node -e '
    const fs = require("node:fs");
    const value = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const expectedPhase = process.argv[2] || "";
    if (!value || Array.isArray(value) || typeof value !== "object"
      || typeof value.generatedAt !== "string" || !Number.isFinite(Date.parse(value.generatedAt))
      || typeof value.phase !== "string" || !value.status || Array.isArray(value.status)
      || typeof value.status !== "object") process.exit(1);
    if (expectedPhase && value.phase !== expectedPhase) process.exit(3);
    if (!["RUNNING", "COMPLETED"].includes(value.phase)
      || value.metadata?.billing_adversary_mode === "off") process.exit(0);
    const expected = [
      { service: "malicious-natserver", actor: "natserver", required: 4 },
      { service: "malicious-relay", actor: "relay", required: 5 },
    ];
    const valid = Array.isArray(value.maliciousNodes)
      && value.maliciousNodes.length === expected.length
      && expected.every((item, index) => {
        const node = value.maliciousNodes[index];
        const probe = node?.probe;
        return node && typeof node === "object" && !Array.isArray(node)
          && node.service === item.service && node.actor === item.actor
          && node.running === true && node.health === "healthy"
          && Number.isSafeInteger(node.restartCount) && node.restartCount === 0
          && probe && typeof probe === "object" && !Array.isArray(probe)
          && probe.status === "RUNNING"
          && Number.isSafeInteger(probe.executed) && probe.executed >= item.required
          && Number.isSafeInteger(probe.failed) && probe.failed === 0
          && Number.isSafeInteger(probe.covered) && probe.covered === item.required
          && Number.isSafeInteger(probe.required) && probe.required === item.required;
      });
    if (!valid) process.exit(2);
    const mixed = value.mixedPath;
    const partitionForRelay = relay => ["relay03", "relay04", "relay05"].includes(relay)
      ? "control_partition_a"
      : ["relay06", "relay07"].includes(relay)
        ? "control_partition_b"
        : "";
    const terminalReady = mixed?.status === "STOPPED" && mixed?.probe?.status === "PASS"
      && mixed?.probe?.sha256Verified === true && mixed?.generation >= 9;
    const natAttachment = mixed?.attachments?.maliciousNatserver;
    const relayAttachment = mixed?.attachments?.maliciousRelay;
    const attachmentValid = natAttachment?.attachmentType === "registered_to_normal_relay"
      && natAttachment?.basis === "live_relay_registration"
      && partitionForRelay(natAttachment?.currentRelay) === natAttachment?.normalPartition
      && relayAttachment?.attachmentType === "control_peer_with_normal_relay"
      && relayAttachment?.basis === "live_control_hello"
      && relayAttachment?.peerDirection === "normal_relay_to_malicious_relay"
      && partitionForRelay(relayAttachment?.currentRelay) === relayAttachment?.normalPartition;
    const latestMigrations = Array.isArray(mixed?.migrations) ? mixed.migrations.slice(0, 2) : [];
    const terminalContainmentValid = !terminalReady || (latestMigrations.length === 2
      && latestMigrations.every(migration => migration?.trigger?.contained === true
        && migration?.triggerContained === true && migration?.isolationVerified === true
        && migration?.containmentVerified === true && migration?.probePassed === true
        && partitionForRelay(migration?.currentRelay) === migration?.normalPartition));
    const terminalNetworkCoverageValid = !terminalReady || (mixed?.networkSummary?.required === 9
      && mixed?.networkSummary?.covered === 9 && mixed?.networkSummary?.violations === 0
      && mixed?.networkSummary?.executed === mixed?.generation
      && mixed?.networkSummary?.contained === mixed?.generation);
    const mixedValid = mixed && typeof mixed === "object" && !Array.isArray(mixed)
      && mixed.available === true && (mixed.healthy === true || terminalReady)
      && Array.isArray(mixed.path?.nodes) && mixed.path.nodes.includes("mixed-path-probe")
      && mixed.path.nodes.includes("malicious-natserver")
      && mixed.path?.kind === "normal_partition_mixed_adversary"
      && mixed.path?.containsNormalPartition === true && mixed.path?.containsMaliciousNode === true
      && mixed.probe?.status === "PASS" && mixed.probe?.sha256Verified === true
      && attachmentValid && terminalContainmentValid && terminalNetworkCoverageValid
      && mixed.attachments?.maliciousNatserver?.currentRelay?.match(/^relay0[3-7]$/)
      && ["malicious-relay", ...Array.from({length: 7}, (_, index) => `relay0${index + 1}`)]
        .includes(mixed.attachments?.normalProbe?.currentRelay);
    if (!mixedValid) process.exit(4);
  ' "$response_file" "$expected_phase" >/dev/null 2>&1 || validation_rc=$?
  if (( validation_rc != 0 )); then
    if (( validation_rc == 2 )); then
      DASHBOARD_STATUS_PROBE_DETAIL=dashboard_status_api_malicious_nodes_invalid
    elif (( validation_rc == 4 )); then
      DASHBOARD_STATUS_PROBE_DETAIL=dashboard_status_api_mixed_path_invalid
    elif (( validation_rc == 3 )); then
      DASHBOARD_STATUS_PROBE_DETAIL=dashboard_status_api_phase_invalid
    else
      DASHBOARD_STATUS_PROBE_DETAIL=dashboard_status_api_json_invalid
    fi
    rm -f "$response_file"
    return 1
  fi
  rm -f "$response_file"
  DASHBOARD_STATUS_PROBE_DETAIL=
  return 0
}

dashboard_status_failure_is_fatal() {
  local now_epoch=$1 failed_since=$2 consecutive_failures=$3
  (( failed_since > 0 \
    && consecutive_failures >= DEFAULT_DASHBOARD_STATUS_MIN_FAILURES \
    && now_epoch - failed_since >= DEFAULT_DASHBOARD_STATUS_FAILURE_GRACE_SECONDS ))
}

DASHBOARD_FINALIZATION_DETAIL=
verify_dashboard_finalization() {
  local dashboard_pid=$1 dashboard_start=$2 dashboard_host=$3 dashboard_port=$4 response_file=$5
  local expected_phase=${6:-COMPLETED}
  DASHBOARD_FINALIZATION_DETAIL=
  if ! pid_matches "$dashboard_pid" "$dashboard_start" 'monitor/server.mjs'; then
    DASHBOARD_FINALIZATION_DETAIL=dashboard_exited
    return 1
  fi
  if ! probe_dashboard_status "$dashboard_host" "$dashboard_port" "$response_file" "$expected_phase"; then
    DASHBOARD_FINALIZATION_DETAIL=${DASHBOARD_STATUS_PROBE_DETAIL:-dashboard_status_api_invalid}
    return 1
  fi
}

wait_dashboard_status() {
  local dashboard_host=$1 dashboard_port=$2 response_file=$3 deadline
  deadline=$((SECONDS + 20))
  while (( SECONDS < deadline )); do
    if probe_dashboard_status "$dashboard_host" "$dashboard_port" "$response_file"; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

resource_guard_max_sample_age() {
  local interval_seconds=$1 maximum_age=$((interval_seconds * 3))
  (( maximum_age >= 30 )) || maximum_age=30
  printf '%s\n' "$maximum_age"
}

inspect_resource_guard() {
  local run_dir=$1 guard_pid=$2 guard_start=$3 interval_seconds=$4
  local expected_duration=$5 cpu_limit=$6 memory_limit=$7 disk_limit=$8 now_epoch=$9
  local status_line expected_header latest_line timestamp epoch containers state maximum_age
  local project_cpu_raw project_cpu_host host_cpu project_memory project_memory_host
  local host_memory docker_disk artifact_disk guard_disk
  RESOURCE_GUARD_DETAIL=
  if [[ ! -r /proc/$guard_pid/stat ]]; then
    RESOURCE_GUARD_DETAIL=resource_guard_exited
    return 1
  fi
  if ! process_identity_alive "$guard_pid" "$guard_start" "$guard_pid"; then
    RESOURCE_GUARD_DETAIL=resource_guard_identity_invalid
    return 1
  fi
  if [[ ! -s $run_dir/resource-guard.status ]] \
    || (( $(wc -l < "$run_dir/resource-guard.status") != 1 )); then
    RESOURCE_GUARD_DETAIL=resource_guard_status_invalid
    return 1
  fi
  status_line=$(<"$run_dir/resource-guard.status")
  local -a status_fields=()
  read -r -a status_fields <<< "$status_line"
  if (( ${#status_fields[@]} != 8 )) \
    || [[ ${status_fields[0]} != RUNNING \
      || ! ${status_fields[1]} =~ ^started=[0-9T:+-]+$ \
      || ${status_fields[2]} != "duration_seconds=$expected_duration" \
      || ${status_fields[3]} != "interval_seconds=$interval_seconds" \
      || ${status_fields[4]} != "cpu_limit_pct=$cpu_limit" \
      || ${status_fields[5]} != "memory_limit_pct=$memory_limit" \
      || ${status_fields[6]} != "disk_limit_pct=$disk_limit" \
      || ! ${status_fields[7]} =~ ^logical_cpus=[1-9][0-9]*$ ]]; then
    RESOURCE_GUARD_DETAIL=resource_guard_status_invalid
    return 1
  fi
  expected_header=$'timestamp\tepoch\tcontainers\tproject_cpu_raw_pct\tproject_cpu_host_pct\thost_cpu_pct\tproject_memory_bytes\tproject_memory_host_pct\thost_memory_pct\tdocker_disk_pct\tartifact_disk_pct\tguard_disk_pct\tstate'
  if [[ ! -s $run_dir/resources.tsv \
    || $(head -n 1 "$run_dir/resources.tsv" 2>/dev/null || true) != "$expected_header" \
    || $(wc -l < "$run_dir/resources.tsv") -lt 2 ]]; then
    RESOURCE_GUARD_DETAIL=resource_guard_sample_missing
    return 1
  fi
  latest_line=$(tail -n 1 "$run_dir/resources.tsv" 2>/dev/null || true)
  IFS=$'\t' read -r timestamp epoch containers project_cpu_raw project_cpu_host host_cpu \
    project_memory project_memory_host host_memory docker_disk artifact_disk guard_disk state \
    <<< "$latest_line"
  if [[ ! $timestamp =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2} \
    || ! $epoch =~ ^[0-9]+$ || ! $containers =~ ^[1-9][0-9]*$ \
    || ! $project_memory =~ ^[0-9]+$ || $state != OK ]]; then
    RESOURCE_GUARD_DETAIL=resource_guard_sample_invalid
    return 1
  fi
  local numeric_value
  for numeric_value in "$project_cpu_raw" "$project_cpu_host" "$host_cpu" \
    "$project_memory_host" "$host_memory" "$docker_disk" "$artifact_disk" "$guard_disk"; do
    if [[ ! $numeric_value =~ ^[0-9]+([.][0-9]+)?$ ]]; then
      RESOURCE_GUARD_DETAIL=resource_guard_sample_invalid
      return 1
    fi
  done
  if (( epoch > now_epoch + 5 )); then
    RESOURCE_GUARD_DETAIL=resource_guard_sample_invalid
    return 1
  fi
  maximum_age=$(resource_guard_max_sample_age "$interval_seconds")
  if (( now_epoch - epoch > maximum_age )); then
    RESOURCE_GUARD_DETAIL=resource_guard_sample_stale
    return 1
  fi
}

wait_resource_guard_ready() {
  local run_dir=$1 guard_pid=$2 guard_start=$3 interval_seconds=$4
  local expected_duration=$5 cpu_limit=$6 memory_limit=$7 disk_limit=$8 deadline
  deadline=$((SECONDS + $(resource_guard_max_sample_age "$interval_seconds")))
  while (( SECONDS < deadline )); do
    if inspect_resource_guard "$run_dir" "$guard_pid" "$guard_start" "$interval_seconds" \
      "$expected_duration" "$cpu_limit" "$memory_limit" "$disk_limit" "$(date +%s)"; then
      return 0
    fi
    [[ $RESOURCE_GUARD_DETAIL != resource_guard_exited \
      && $RESOURCE_GUARD_DETAIL != resource_guard_identity_invalid ]] || return 1
    sleep 0.25
  done
  return 1
}

stop_resource_guard() {
  local run_dir=$1 guard_pid=$2 guard_start=$3 attempt guard_rc=0 status_line
  RESOURCE_GUARD_DETAIL=
  if [[ ! -r /proc/$guard_pid/stat ]]; then
    RESOURCE_GUARD_DETAIL=resource_guard_exited
    return 1
  fi
  if ! process_identity_alive "$guard_pid" "$guard_start" "$guard_pid"; then
    RESOURCE_GUARD_DETAIL=resource_guard_identity_invalid
    return 1
  fi
  kill -TERM "$guard_pid" 2>/dev/null || {
    RESOURCE_GUARD_DETAIL=resource_guard_stop_failed
    return 1
  }
  for attempt in $(seq 1 $((DEFAULT_RESOURCE_GUARD_STOP_TIMEOUT_SECONDS * 10))); do
    process_identity_alive "$guard_pid" "$guard_start" "$guard_pid" || break
    sleep 0.1
  done
  if process_identity_alive "$guard_pid" "$guard_start" "$guard_pid"; then
    kill -KILL "$guard_pid" 2>/dev/null || true
    wait "$guard_pid" 2>/dev/null || true
    RESOURCE_GUARD_DETAIL=resource_guard_stop_timeout
    return 1
  fi
  wait "$guard_pid" || guard_rc=$?
  if (( guard_rc != 0 )) || [[ ! -s $run_dir/resource-guard.status ]] \
    || (( $(wc -l < "$run_dir/resource-guard.status") != 1 )); then
    RESOURCE_GUARD_DETAIL=resource_guard_stop_failed
    return 1
  fi
  status_line=$(<"$run_dir/resource-guard.status")
  if [[ ! $status_line =~ ^STOPPED_BY_SIGNAL[[:space:]]timestamp=[0-9T:+-]+$ ]]; then
    RESOURCE_GUARD_DETAIL=resource_guard_stop_failed
    return 1
  fi
}

wait_failure_watcher_ready() {
  local run_dir=$1 watcher_pid=$2 deadline
  deadline=$((SECONDS + 10))
  while (( SECONDS < deadline )); do
    kill -0 "$watcher_pid" 2>/dev/null || return 1
    if [[ -s $run_dir/failure-watcher.json ]] \
      && grep -Eq '"status"[[:space:]]*:[[:space:]]*"RUNNING"' "$run_dir/failure-watcher.json" \
      && inspect_failure_watcher "$run_dir" "$watcher_pid" "$(date +%s)" 0; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

stop_failure_watcher() {
  local watcher_pid=${1:-} attempt
  [[ $watcher_pid =~ ^[1-9][0-9]*$ ]] || return 0
  kill -TERM "$watcher_pid" 2>/dev/null || true
  for attempt in $(seq 1 20); do
    kill -0 "$watcher_pid" 2>/dev/null || break
    sleep 0.1
  done
  kill -KILL "$watcher_pid" 2>/dev/null || true
  wait "$watcher_pid" 2>/dev/null || true
}

read_failure_watcher_status() {
  local status_file=$1 values

  FAILURE_WATCHER_STATUS=
  FAILURE_WATCHER_HEARTBEAT_EPOCH=
  FAILURE_WATCHER_SOURCE_AVAILABLE=
  FAILURE_WATCHER_SOURCE_SIZE=
  FAILURE_WATCHER_SOURCE_OFFSET=
  FAILURE_WATCHER_NEW_FAILURES=

  values=$(awk -F= '
    function capture(key) {
      seen[key]++
      value[key]=substr($0, length(key) + 2)
    }
    $1 == "schema_version" || $1 == "status" || $1 == "heartbeat_epoch" \
      || $1 == "source_available" || $1 == "source_size_bytes" \
      || $1 == "source_offset_bytes" || $1 == "new_failure_records" {
      capture($1)
    }
    END {
      if (seen["schema_version"] != 1 || value["schema_version"] != "1" \
        || seen["status"] != 1 || seen["heartbeat_epoch"] != 1 \
        || seen["source_available"] != 1 || seen["source_size_bytes"] != 1 \
        || seen["source_offset_bytes"] != 1 || seen["new_failure_records"] != 1) {
        exit 1
      }
      printf "%s|%s|%s|%s|%s|%s", value["status"], value["heartbeat_epoch"], \
        value["source_available"], value["source_size_bytes"], \
        value["source_offset_bytes"], value["new_failure_records"]
    }
  ' "$status_file") || return 1

  IFS='|' read -r FAILURE_WATCHER_STATUS FAILURE_WATCHER_HEARTBEAT_EPOCH \
    FAILURE_WATCHER_SOURCE_AVAILABLE FAILURE_WATCHER_SOURCE_SIZE \
    FAILURE_WATCHER_SOURCE_OFFSET FAILURE_WATCHER_NEW_FAILURES <<< "$values"
}

inspect_failure_watcher() {
  local run_dir=$1 watcher_pid=$2 now_epoch=$3 degraded_since=${4:-0} allow_source_lag=${5:-0}
  local lag_since=${6:-0} heartbeat_timeout=${7:-$DEFAULT_FAILURE_WATCHER_HEARTBEAT_TIMEOUT_SECONDS}
  local degraded_grace=${8:-$DEFAULT_FAILURE_WATCHER_DEGRADED_GRACE_SECONDS}
  local source_lag_grace=${9:-$DEFAULT_FAILURE_WATCHER_SOURCE_LAG_GRACE_SECONDS}
  local status_file=$run_dir/failure-watcher.status status heartbeat_epoch source_available
  local source_size source_offset new_failures

  FAILURE_WATCHER_DETAIL=
  FAILURE_WATCHER_DEGRADED_SINCE=$degraded_since
  FAILURE_WATCHER_LAG_SINCE=$lag_since

  if [[ -s $run_dir/failure-watcher.alert ]]; then
    FAILURE_WATCHER_DETAIL=transfer_failure_detected
    return 1
  fi
  if [[ ! -s $status_file ]]; then
    FAILURE_WATCHER_DETAIL=failure_watcher_status_missing
    return 1
  fi

  if ! read_failure_watcher_status "$status_file" 2>/dev/null; then
    FAILURE_WATCHER_DETAIL=failure_watcher_status_invalid
    return 1
  fi
  status=$FAILURE_WATCHER_STATUS
  heartbeat_epoch=$FAILURE_WATCHER_HEARTBEAT_EPOCH
  source_available=$FAILURE_WATCHER_SOURCE_AVAILABLE
  source_size=$FAILURE_WATCHER_SOURCE_SIZE
  source_offset=$FAILURE_WATCHER_SOURCE_OFFSET
  new_failures=$FAILURE_WATCHER_NEW_FAILURES

  if [[ ! $heartbeat_epoch =~ ^[0-9]+$ || ! $source_available =~ ^[01]$ \
    || ! $source_size =~ ^[0-9]+$ || ! $source_offset =~ ^[0-9]+$ \
    || ! $new_failures =~ ^[0-9]+$ ]]; then
    FAILURE_WATCHER_DETAIL=failure_watcher_status_invalid
    return 1
  fi
  heartbeat_epoch=$((10#$heartbeat_epoch))
  source_size=$((10#$source_size))
  source_offset=$((10#$source_offset))
  new_failures=$((10#$new_failures))

  if (( new_failures > 0 )); then
    FAILURE_WATCHER_DETAIL=transfer_failure_detected
    return 1
  fi
  if [[ $status == FAILED ]]; then
    FAILURE_WATCHER_DETAIL=failure_watcher_failed
    return 1
  fi
  if ! kill -0 "$watcher_pid" 2>/dev/null; then
    FAILURE_WATCHER_DETAIL=failure_watcher_exited
    return 1
  fi
  if (( heartbeat_epoch == 0 || heartbeat_epoch > now_epoch + 5 \
    || now_epoch - heartbeat_epoch > heartbeat_timeout )); then
    FAILURE_WATCHER_DETAIL=failure_watcher_heartbeat_stale
    return 1
  fi

  case $status in
    RUNNING)
      FAILURE_WATCHER_DEGRADED_SINCE=0
      ;;
    DEGRADED)
      if (( FAILURE_WATCHER_DEGRADED_SINCE == 0 )); then
        FAILURE_WATCHER_DEGRADED_SINCE=$now_epoch
      elif (( now_epoch - FAILURE_WATCHER_DEGRADED_SINCE >= degraded_grace )); then
        FAILURE_WATCHER_DETAIL=failure_watcher_degraded
        return 1
      fi
      ;;
    *)
      FAILURE_WATCHER_DETAIL=failure_watcher_unhealthy_status
      return 1
      ;;
  esac

  if (( source_available != 1 )); then
    FAILURE_WATCHER_DETAIL=failure_watcher_source_unavailable
    return 1
  fi
  if (( source_offset > source_size )); then
    FAILURE_WATCHER_DETAIL=failure_watcher_status_invalid
    return 1
  fi
  if (( source_offset == source_size )); then
    FAILURE_WATCHER_LAG_SINCE=0
  elif (( FAILURE_WATCHER_LAG_SINCE == 0 )); then
    FAILURE_WATCHER_LAG_SINCE=$now_epoch
  elif (( allow_source_lag != 1 && now_epoch - FAILURE_WATCHER_LAG_SINCE >= source_lag_grace )); then
    FAILURE_WATCHER_DETAIL=failure_watcher_source_lag
    return 1
  fi
  return 0
}

wait_failure_watcher_caught_up() {
  local run_dir=$1 watcher_pid=$2 timeout_seconds=${3:-$DEFAULT_FAILURE_WATCHER_SETTLE_TIMEOUT_SECONDS}
  local degraded_since=${4:-0} poll_seconds=${5:-0.1}
  local lag_since=0 deadline now_epoch watcher_status source_size source_offset actual_size
  deadline=$(( $(date +%s) + timeout_seconds ))

  while (( $(date +%s) <= deadline )); do
    now_epoch=$(date +%s)
    if ! inspect_failure_watcher "$run_dir" "$watcher_pid" "$now_epoch" "$degraded_since" 1 "$lag_since"; then
      return 1
    fi
    degraded_since=$FAILURE_WATCHER_DEGRADED_SINCE
    lag_since=$FAILURE_WATCHER_LAG_SINCE
    watcher_status=$FAILURE_WATCHER_STATUS
    source_size=$FAILURE_WATCHER_SOURCE_SIZE
    source_offset=$FAILURE_WATCHER_SOURCE_OFFSET
    actual_size=$(stat -c %s "$run_dir/transfers.tsv" 2>/dev/null) || actual_size=
    if [[ $watcher_status == RUNNING && $source_size =~ ^[0-9]+$ \
      && $source_offset =~ ^[0-9]+$ && $actual_size =~ ^[0-9]+$ ]] \
      && (( 10#$source_size == 10#$source_offset && 10#$source_offset == 10#$actual_size )); then
      FAILURE_WATCHER_DEGRADED_SINCE=$degraded_since
      return 0
    fi
    sleep "$poll_seconds"
  done

  FAILURE_WATCHER_DETAIL=failure_watcher_source_lag_timeout
  FAILURE_WATCHER_DEGRADED_SINCE=$degraded_since
  FAILURE_WATCHER_LAG_SINCE=$lag_since
  return 1
}

free_dashboard_port() {
  local port=$1 pids pid run_dir attempt
  pids=$(ss -lntpH "sport = :$port" 2>/dev/null \
    | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | sort -u)
  for pid in $pids; do
    [[ $pid =~ ^[1-9][0-9]*$ && $pid != $$ ]] || return 1
    run_dir=$(dashboard_run_for_pid "$pid" 2>/dev/null || true)
    [[ -n $run_dir ]] || return 1
    printf 'stopping previous stability dashboard: port=%s run=%s\n' "$port" "$(basename "$run_dir")"
    stop_dashboard_process "$run_dir" || return 1
  done
  for attempt in $(seq 1 20); do
    ss -lntH "sport = :$port" 2>/dev/null | grep -q . || return 0
    sleep 0.1
  done
  return 1
}

free_reconnect_gate_port() {
  local port=$1 pids pid run_dir attempt
  pids=$(ss -lntpH "sport = :$port" 2>/dev/null \
    | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | sort -u)
  for pid in $pids; do
    [[ $pid =~ ^[1-9][0-9]*$ && $pid != $$ ]] || return 1
    run_dir=$(reconnect_gate_run_for_pid "$pid" 2>/dev/null || true)
    [[ -n $run_dir ]] || return 1
    printf 'stopping previous reconnect gate: port=%s run=%s\n' "$port" "$(basename "$run_dir")"
    stop_reconnect_gate_process "$run_dir" || return 1
  done
  for attempt in $(seq 1 20); do
    ss -lntH "sport = :$port" 2>/dev/null | grep -q . || return 0
    sleep 0.1
  done
  return 1
}

wait_reconnect_gate_health() {
  local port=$1 token=$2 deadline
  deadline=$((SECONDS + 10))
  while (( SECONDS < deadline )); do
    if curl -fsS --connect-timeout 1 --max-time 2 \
      -H "Authorization: Bearer $token" \
      "http://127.0.0.1:$port/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

capture_reconnect_gate_snapshot() {
  local run_dir=$1 port=$2 token=$3
  local output=$run_dir/reconnect-gate-final.json temporary=$run_dir/reconnect-gate-final.json.tmp.$$
  if ! curl -fsS --connect-timeout 1 --max-time 3 \
    -H "Authorization: Bearer $token" \
    "http://127.0.0.1:$port/metrics" > "$temporary"; then
    rm -f "$temporary"
    return 1
  fi
  chmod 600 "$temporary"
  mv -f -- "$temporary" "$output"
}

start_client_and_credit() {
  local service=$1 relay=$2 target_id=$3 listen_port=$4 scenario=$5 ca_port=$6
  local log_file=$RUNTIME_DIR/$scenario/$service.log
  local key_file node_id logged_node_id

  key_file=$(nat_key_host_file "$service") || return 1
  [[ -s $key_file ]] || return 1
  node_id=$(node_id_from_private_key "$key_file") || return 1
  [[ $node_id =~ ^[[:xdigit:]]{64}$ ]] || return 1
  credit_node "$ca_port" "$node_id" "$DEFAULT_SOAK_CREDIT_BYTES" || return 1

  launch_tunnel_client "$service" "$relay" "$target_id" "$listen_port" "$scenario" || return 1
  wait_file_pattern "$log_file" '本节点 ID:' 20 || return 1
  logged_node_id=$(awk '/本节点 ID:/{print $NF; exit}' "$log_file")
  [[ $logged_node_id == "$node_id" ]] || return 1
  wait_client_ready "$service" "$scenario" 70
}

probe_once() {
  local run_dir=$1 client=$2 listen_port=$3 expected_size=$4 expected_sha=$5 label=$6
  local tmp_file=$run_dir/probe.bin started_ns ended_ns rc=0 size=0 sha= elapsed sha_ok=no timestamp
  started_ns=$(date +%s%N)
  if dc exec -T "$client" curl -fsS --max-time 180 "http://127.0.0.1:$listen_port/file" > "$tmp_file"; then
    size=$(stat -c %s "$tmp_file" 2>/dev/null || printf '0')
    sha=$(sha256sum "$tmp_file" | awk '{print $1}')
    if [[ $size == "$expected_size" && $sha == "$expected_sha" ]]; then
      sha_ok=yes
    else
      rc=1
    fi
  else
    rc=$?
  fi
  ended_ns=$(date +%s%N)
  elapsed=$(awk -v start="$started_ns" -v end="$ended_ns" 'BEGIN {printf "%.6f", (end-start)/1000000000}')
  timestamp=$(date --iso-8601=seconds)
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$timestamp" "$label" "$rc" "$size" "$elapsed" "$sha_ok" "$client" >> "$run_dir/probes.tsv"
  rm -f "$tmp_file"
  [[ $rc -eq 0 && $sha_ok == yes ]]
}

core_services_healthy() {
  local snapshot_file=${1:-} ids rows= service row row_count state health
  local timestamp epoch temporary result=0
  CORE_HEALTH_DETAIL=
  CORE_HEALTH_UNHEALTHY_SERVICES=
  CORE_HEALTH_SNAPSHOT=
  timestamp=$(date --iso-8601=seconds)
  epoch=$(date +%s)

  if ! ids=$(docker ps -aq --filter "label=com.docker.compose.project=$COMPOSE_PROJECT" 2>/dev/null); then
    CORE_HEALTH_DETAIL=docker_ps_failed
    result=1
  elif [[ -z $ids ]]; then
    CORE_HEALTH_DETAIL=project_containers_missing
    result=1
  elif ! rows=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.service"}}	{{.Id}}	{{.State.Status}}	{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}	{{.State.StartedAt}}	{{.RestartCount}}' $ids 2>/dev/null); then
    CORE_HEALTH_DETAIL=docker_inspect_failed
    result=1
  fi
  CORE_HEALTH_SNAPSHOT=$rows

  if [[ -n $rows ]]; then
    while IFS= read -r service; do
      row_count=$(awk -F '\t' -v service="$service" '$1 == service { count++ } END { print count + 0 }' <<< "$rows")
      if [[ $row_count != 1 ]]; then
        CORE_HEALTH_UNHEALTHY_SERVICES+="${CORE_HEALTH_UNHEALTHY_SERVICES:+,}$service:instances=$row_count"
        result=1
        continue
      fi
      row=$(awk -F '\t' -v service="$service" '$1 == service { print; exit }' <<< "$rows")
      IFS=$'\t' read -r _ _ state health _ _ <<< "$row"
      if [[ $state != running || $health != healthy ]]; then
        CORE_HEALTH_UNHEALTHY_SERVICES+="${CORE_HEALTH_UNHEALTHY_SERVICES:+,}$service:$state/$health"
        result=1
      fi
    done < <(core_service_names)
  elif [[ $result == 0 ]]; then
    CORE_HEALTH_DETAIL=inspect_rows_empty
    result=1
  fi

  if [[ $CORE_HEALTH_DETAIL == docker_inspect_failed && -n $rows \
    && -z $CORE_HEALTH_UNHEALTHY_SERVICES ]]; then
    CORE_HEALTH_DETAIL=partial_inspect_ignored
    result=0
  fi

  if [[ -n $snapshot_file ]]; then
    temporary=$snapshot_file.tmp.$BASHPID
    {
      printf 'timestamp\tepoch\tservice\tcontainer_id\tstate\thealth\tstarted_at\trestart_count\n'
      if [[ -n $rows ]]; then
        while IFS= read -r service; do
          awk -F '\t' -v service="$service" -v timestamp="$timestamp" -v epoch="$epoch" \
            '$1 == service { print timestamp "\t" epoch "\t" $0 }' <<< "$rows"
        done < <(core_service_names)
      fi
    } > "$temporary"
    mv "$temporary" "$snapshot_file"
  fi

  if (( result == 0 )); then
    [[ -n $CORE_HEALTH_DETAIL ]] || CORE_HEALTH_DETAIL=healthy
    return 0
  fi
  [[ -n $CORE_HEALTH_DETAIL ]] || CORE_HEALTH_DETAIL=service_unhealthy
  return 1
}

core_services_snapshot_unchanged() {
  local snapshot=$1 identity_file=$2 service row row_count
  local current_id current_started current_restarts expected_id expected_started expected_restarts
  CORE_IDENTITY_DETAIL=
  [[ -n $snapshot && -s $identity_file ]] || {
    CORE_IDENTITY_DETAIL=core_snapshot_unavailable
    return 1
  }
  while IFS=$'\t' read -r service expected_id expected_started expected_restarts; do
    [[ $service != service ]] || continue
    row_count=$(awk -F '\t' -v service="$service" '$1 == service { count++ } END { print count + 0 }' <<< "$snapshot")
    if [[ $row_count != 1 ]]; then
      CORE_IDENTITY_DETAIL="$service:instances=$row_count"
      return 1
    fi
    row=$(awk -F '\t' -v service="$service" '$1 == service { print; exit }' <<< "$snapshot")
    IFS=$'\t' read -r _ current_id _ _ current_started current_restarts <<< "$row"
    if [[ $current_id != "$expected_id" ]]; then
      CORE_IDENTITY_DETAIL="$service:container_id_changed"
      return 1
    fi
    if [[ $current_started != "$expected_started" ]]; then
      CORE_IDENTITY_DETAIL="$service:started_at_changed"
      return 1
    fi
    if [[ $current_restarts != "$expected_restarts" ]]; then
      CORE_IDENTITY_DETAIL="$service:restart_count_changed"
      return 1
    fi
  done < "$identity_file"
  return 0
}

wait_core_services_healthy() {
  local run_dir=$1 identity_file=$2 timeout_seconds=${3:-$DEFAULT_CORE_HEALTH_FAILURE_GRACE_SECONDS}
  local deadline now
  is_positive_integer "$timeout_seconds" || return 1
  deadline=$(( $(date +%s) + timeout_seconds ))
  while :; do
    if core_services_healthy "$run_dir/core-health-latest.tsv"; then
      core_services_snapshot_unchanged "$CORE_HEALTH_SNAPSHOT" "$identity_file" || return 1
      return 0
    fi
    if [[ -n $CORE_HEALTH_SNAPSHOT ]] \
      && ! core_services_snapshot_unchanged "$CORE_HEALTH_SNAPSHOT" "$identity_file"; then
      return 1
    fi
    now=$(date +%s)
    (( now >= deadline )) && return 1
    sleep 1
  done
}

core_health_failure_is_fatal() {
  local now_epoch=$1 failed_since=$2 consecutive_failures=$3
  [[ $now_epoch =~ ^[1-9][0-9]*$ && $failed_since =~ ^[1-9][0-9]*$ \
    && $consecutive_failures =~ ^[1-9][0-9]*$ ]] || return 1
  (( consecutive_failures >= DEFAULT_CORE_HEALTH_MIN_FAILURES \
    && now_epoch - failed_since >= DEFAULT_CORE_HEALTH_FAILURE_GRACE_SECONDS ))
}

record_core_health_event() {
  local run_dir=$1 event=$2 consecutive_failures=$3 failed_since=$4
  local now_epoch duration_seconds=0
  now_epoch=$(date +%s)
  if [[ $failed_since =~ ^[1-9][0-9]*$ && $now_epoch -ge $failed_since ]]; then
    duration_seconds=$((now_epoch - failed_since))
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(date --iso-8601=seconds)" "$event" "$consecutive_failures" \
    "$duration_seconds" "${CORE_HEALTH_DETAIL:-unknown}" \
    "${CORE_HEALTH_UNHEALTHY_SERVICES:-unknown}" "$now_epoch" \
    >> "$run_dir/core-health-events.tsv"
}

write_core_identity() {
  local output=$1 service id started restart_count
  printf 'service\tcontainer_id\tstarted_at\trestart_count\n' > "$output"
  while IFS= read -r service; do
    id=$(dc ps -q "$service" 2>/dev/null || true)
    [[ -n $id ]] || return 1
    started=$(docker inspect --format '{{.State.StartedAt}}' "$id" 2>/dev/null || true)
    restart_count=$(docker inspect --format '{{.RestartCount}}' "$id" 2>/dev/null || true)
    printf '%s\t%s\t%s\t%s\n' "$service" "$id" "$started" "$restart_count" >> "$output"
  done < <(core_identity_service_names)
}

core_services_unchanged() {
  local identity_file=$1
  [[ -s $identity_file ]] || return 1
  core_services_healthy || return 1
  core_services_snapshot_unchanged "$CORE_HEALTH_SNAPSHOT" "$identity_file"
}

capture_project_evidence() {
  local run_dir=$1 suffix=$2 ids
  docker compose --project-name "$COMPOSE_PROJECT" --file "$COMPOSE_FILE" \
    logs --no-color > "$run_dir/compose-$suffix.log" 2>&1 || true
  printf 'service\tcontainer_id\tstatus\thealth\tstarted_at\trestart_count\n' > "$run_dir/containers-$suffix.tsv"
  ids=$(docker ps -aq --filter "label=com.docker.compose.project=$COMPOSE_PROJECT")
  [[ -n $ids ]] || return 0
  docker inspect --format '{{index .Config.Labels "com.docker.compose.service"}}|{{.Id}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.State.StartedAt}}|{{.RestartCount}}' \
    $ids 2>/dev/null | awk -F '|' 'BEGIN { OFS="\t" } { print $1, $2, $3, $4, $5, $6 }' \
    | sort >> "$run_dir/containers-$suffix.tsv" || true
}

prepare_stability_profile() {
  local run_dir=$1 scenario=$2 ca_port=$3 max_inflight=$4
  local per_transfer_limit_mibps=$5 workload_limit_mibps=$6
  PROFILE_SETUP_DETAIL=

  if ! configure_profile "$run_dir" "$scenario" "$ca_port" "$per_transfer_limit_mibps"; then
    PROFILE_SETUP_DETAIL=profile_configuration_failed
  elif ! initialize_random_workload "$run_dir" "$ca_port" "$scenario" "$max_inflight" \
    "$per_transfer_limit_mibps" "$workload_limit_mibps"; then
    PROFILE_SETUP_DETAIL=random_workload_initialization_failed
  elif ! verify_profile3_tcp_cold_start "$run_dir" "$scenario"; then
    PROFILE_SETUP_DETAIL=profile_transport_gate_failed
  elif ! wait_core_services_healthy "$run_dir" "$run_dir/core-identity.pre-gate.tsv"; then
    if [[ -n $CORE_IDENTITY_DETAIL ]]; then
      PROFILE_SETUP_DETAIL=profile_core_identity_changed
    else
      PROFILE_SETUP_DETAIL=profile_core_health_timeout
    fi
  else
    PROFILE_SETUP_DETAIL=ready
    return 0
  fi

  record_profile_setup_failure "$run_dir" "$PROFILE_SETUP_DETAIL"
  return 1
}

configure_profile() {
  local run_dir=$1 selected=$2 ca_port=$3 per_transfer_limit_mibps=$4
  local scenario=stability server client server_relay client_relay listen_port server_id source_sha source_size
  mkdir -p "$RUNTIME_DIR/$scenario"
  export BNFS_CHAOS_NAT_CA_URL=http://ca:9100
  export BNFS_CHAOS_NAT_KEY_DIR=$PROFILE_SETUP_NAT_KEY_DIR

  case "$selected" in
    1)
      server=natserver04; client=natclient02
      server_relay=relay03:9000; client_relay=relay01:9000; listen_port=18082
      assert_unreachable index relay03 9000 || return 1
      assert_reachable relay01 relay03 9000 || return 1
      ;;
    2)
      server=natserver02; client=natclient04
      server_relay=; client_relay=; listen_port=18084
      block_relay "$server" relay02 || return 1
      block_relay "$client" relay02 || return 1
      ;;
    3)
      server=natserver03; client=natclient05
      server_relay=relay03:9000; client_relay=relay01:9000; listen_port=18085
      ;;
  esac

  prepare_profile_setup_identity "$server" || return 1
  prepare_profile_setup_identity "$client" || return 1
  server_id=$(start_tunnel_server "$server" "$server_relay" "$scenario" 5 200 "$per_transfer_limit_mibps") || return 1
  credit_node "$ca_port" "$server_id" "$DEFAULT_SOAK_CREDIT_BYTES" || return 1
  start_client_and_credit "$client" "$client_relay" "$server_id" "$listen_port" "$scenario" "$ca_port" || return 1

  if [[ $selected == 2 ]]; then
    local relay02_server_ip relay02_client_ip deadline server_migrated=0 client_migrated=0
    relay02_server_ip=$(dc exec -T "$server" getent ahostsv4 relay02 | awk 'NR==1{print $1}')
    relay02_client_ip=$(dc exec -T "$client" getent ahostsv4 relay02 | awk 'NR==1{print $1}')
    disconnect_relay_path "$server" relay01 || return 1
    disconnect_relay_path "$client" relay01 || return 1
    unblock_relay "$server" relay02
    unblock_relay "$client" relay02
    deadline=$((SECONDS + DEFAULT_PROFILE_RELAY_MIGRATION_TIMEOUT_SECONDS))
    while (( SECONDS < deadline )); do
      grep -q "注册到 relay: $relay02_server_ip:9000" "$RUNTIME_DIR/$scenario/$server.log" && server_migrated=1
      grep -q "注册到 relay: $relay02_client_ip:9000" "$RUNTIME_DIR/$scenario/$client.log" && client_migrated=1
      (( server_migrated == 1 && client_migrated == 1 )) && break
      sleep 1
    done
    if (( server_migrated != 1 || client_migrated != 1 )); then
      record_profile_setup_failure "$run_dir" \
        "relay02_migration_timeout_server_${server_migrated}_client_${client_migrated}"
      return 1
    fi
  fi

  source_sha=$(dc exec -T "$server" curl -fsS http://127.0.0.1:8080/checksum | tr -d '[:space:]')
  [[ $source_sha =~ ^[[:xdigit:]]{64}$ ]] || return 1
  source_size=5242880

  if [[ $selected == 3 ]]; then
    local packets started_ns ended_ns elapsed timestamp rc=1 actual_size=0 actual_sha= sha_ok=no
    netns_exec "$server" iptables -I OUTPUT 1 -p udp --dport 9000 -m comment --comment BNFS_SOAK_KCP -j ACCEPT
    started_ns=$(date +%s%N)
    start_limited_download "$client" "$listen_port" "$scenario" 256k 180
    wait_file_size "$RUNTIME_DIR/$scenario/download.bin" 262144 20 || return 1
    packets=$(netns_exec "$server" iptables -L OUTPUT -v -n -x | awk '/BNFS_SOAK_KCP/{print $1; exit}')
    packets=${packets:-0}
    (( packets > 20 )) || return 1
    printf '[stability] profile3 active KCP packets before blackhole=%s\n' "$packets" >&2
    netns_exec "$server" iptables -D OUTPUT -p udp --dport 9000 -m comment --comment BNFS_SOAK_KCP -j ACCEPT >/dev/null 2>&1 || true
    netns_exec "$server" iptables -I OUTPUT 1 -p udp --dport 9000 -j DROP
    netns_exec "$client" iptables -I OUTPUT 1 -p udp --dport 9000 -j DROP
    if wait_file_exists "$RUNTIME_DIR/$scenario/curl.rc" 150 \
      && [[ $(tr -d '[:space:]' < "$RUNTIME_DIR/$scenario/curl.rc") == 0 ]]; then
      actual_size=$(stat -c %s "$RUNTIME_DIR/$scenario/download.bin" 2>/dev/null || printf '0')
      actual_sha=$(sha256sum "$RUNTIME_DIR/$scenario/download.bin" 2>/dev/null | awk '{print $1}')
      if [[ $actual_size == "$source_size" && $actual_sha == "$source_sha" ]]; then
        rc=0
        sha_ok=yes
      fi
    fi
    ended_ns=$(date +%s%N)
    elapsed=$(awk -v start="$started_ns" -v end="$ended_ns" 'BEGIN {printf "%.6f", (end-start)/1000000000}')
    timestamp=$(date --iso-8601=seconds)
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$timestamp" profile3_kcp_to_tcp_inflight "$rc" "$actual_size" "$elapsed" "$sha_ok" "$client" \
      >> "$run_dir/probes.tsv"
    [[ $rc -eq 0 && $sha_ok == yes ]] || return 1
    netns_exec "$server" ss -tn | grep -q ':9000' || return 1
  fi

  printf 'server=%s\nclient=%s\nlisten_port=%s\nsource_size=%s\nsource_sha=%s\n' \
    "$server" "$client" "$listen_port" "$source_size" "$source_sha" > "$run_dir/workload.env"
}

server_entry_relay() {
  local service=$1 selected=${2:-} number relay_number
  if [[ $service == "$MALICIOUS_RANDOM_NAT_SERVER" ]]; then
    printf 'relay03\n'
    return 0
  fi
  number=${service#natserver}
  case "$number" in
    01|03|04|05) relay_number=3 ;;
    02)
      relay_number=1
      [[ $selected != 2 ]] || relay_number=2
      ;;
    06) relay_number=4 ;;
    *) relay_number=$(( (10#$number - 1) % (TOPOLOGY_RELAY_COUNT - 2) + 3 )) ;;
  esac
  printf 'relay%02d\n' "$relay_number"
}

client_entry_relay() {
  local service=${1:-} selected=${2:-} number
  if [[ $service == "$MALICIOUS_NAT_CLIENT" ]]; then
    printf 'relay01\n'
    return 0
  fi
  [[ $service =~ ^natclient([0-9]{2})$ ]] || return 1
  number=$((10#${BASH_REMATCH[1]}))
  (( number >= 1 && number <= TOPOLOGY_NAT_CLIENT_COUNT )) || return 1
  case "$selected:$service" in
    2:natclient04) printf 'relay02\n' ;;
    1:*|2:*|3:*) printf 'relay01\n' ;;
    *) return 1 ;;
  esac
}

relay_can_reach_server_relay() {
  local entry_relay=${1:-} server_relay=${2:-}
  [[ $entry_relay =~ ^relay0[1-7]$ && $server_relay =~ ^relay0[1-7]$ ]] || return 1
  [[ $entry_relay == "$server_relay" ]] && return 0
  [[ $entry_relay == relay01 && $server_relay =~ ^relay0[3-7]$ ]] && return 0
  [[ $server_relay == relay01 && $entry_relay =~ ^relay0[3-7]$ ]]
}

random_reachable_server_line() {
  local run_dir=$1 entry_relay=$2 entry_family=${3:-default}
  [[ -s $run_dir/server-pool.tsv && $entry_relay =~ ^relay0[1-7]$ \
    && $entry_family =~ ^(default|ipv4|ipv6|dual)$ ]] || return 1
  awk -F '\t' -v entry_relay="$entry_relay" -v entry_family="$entry_family" '
    function reachable(entry, host) {
      return entry == host \
        || (entry == "relay01" && host ~ /^relay0[3-7]$/) \
        || (host == "relay01" && entry ~ /^relay0[3-7]$/)
    }
    NR > 1 && ((NF == 5 && $4 == entry_family) || (NF == 3 && entry_family == "default")) \
      && reachable(entry_relay, $2) { print }
  ' "$run_dir/server-pool.tsv" | shuf -n 1
}

validate_client_entry_table() {
  local table=${1:-} selected=${2:-} service_column=${3:-} relay_column=${4:-} role_column=${5:-0} run_dir=${6:-}
  local number service expected_relay actual_relay record_count
  [[ -s $table && $service_column =~ ^[1-9][0-9]*$ && $relay_column =~ ^[1-9][0-9]*$ \
    && $role_column =~ ^[0-9]+$ ]] || return 1
  record_count=$(awk -F '\t' -v role_column="$role_column" '
    NR > 1 && (role_column == 0 || $role_column == "natclient") { count++ }
    END { print count + 0 }
  ' "$table") || return 1
  if (( role_column == 0 )); then
    (( record_count == TOPOLOGY_NAT_CLIENT_COUNT || record_count == RANDOM_CLIENT_POOL_COUNT )) || return 1
  else
    (( record_count == TOPOLOGY_NAT_CLIENT_COUNT )) || return 1
  fi
  for ((number = 1; number <= TOPOLOGY_NAT_CLIENT_COUNT; number++)); do
    printf -v service 'natclient%02d' "$number"
    expected_relay=$(client_entry_relay "$service" "$selected") || return 1
    if [[ -n $run_dir ]]; then
      expected_relay=$(service_ip_family_relay "$run_dir" "$service" "$expected_relay") || return 1
    fi
    actual_relay=$(awk -F '\t' -v service="$service" -v service_column="$service_column" \
      -v relay_column="$relay_column" -v role_column="$role_column" '
      NR == 1 { next }
      $service_column == service {
        if (role_column != 0 && $role_column != "natclient") next
        matches++
        relay=$relay_column
      }
      END {
        if (matches != 1 || relay == "") exit 1
        print relay
      }
    ' "$table") || return 1
    [[ $actual_relay == "$expected_relay" ]] || return 1
  done
}

reconnect_gate_run_for_pid() {
  local target_pid=$1 pid_file run_dir tracked_pid tracked_start
  for pid_file in "$SOAK_HOME"/runs/*/reconnect-gate.pid; do
    [[ -f $pid_file ]] || continue
    run_dir=${pid_file%/reconnect-gate.pid}
    [[ -f $run_dir/reconnect-gate.starttime ]] || continue
    tracked_pid=$(cat "$pid_file" 2>/dev/null || true)
    tracked_start=$(cat "$run_dir/reconnect-gate.starttime" 2>/dev/null || true)
    if [[ $tracked_pid == "$target_pid" ]] \
      && pid_matches "$tracked_pid" "$tracked_start" 'reconnect-gate.mjs'; then
      printf '%s\n' "$run_dir"
      return 0
    fi
  done
  return 1
}

stop_random_nat_processes() {
  local service
  while IFS= read -r service; do
    stop_nat_process "$service" tunclient || return 1
  done < <(numbered_service_names natclient "$TOPOLOGY_NAT_CLIENT_COUNT")
  stop_nat_process "$MALICIOUS_NAT_CLIENT" tunclient || return 1
  while IFS= read -r service; do
    stop_nat_process "$service" tunserver || return 1
    stop_nat_process "$service" httpfileserver || return 1
  done < <(numbered_service_names natserver "$TOPOLOGY_NAT_SERVER_COUNT")
  stop_nat_process "$MALICIOUS_RANDOM_NAT_SERVER" tunserver || return 1
  stop_nat_process "$MALICIOUS_RANDOM_NAT_SERVER" httpfileserver || return 1
}

initialize_random_workload() {
  local run_dir=$1 ca_port=$2 selected=$3 max_inflight=$4 per_transfer_limit_mibps=$5 workload_limit_mibps=$6 scenario=random-workload
  local number service relay relay_endpoint family node_id expected_node_id listen_port role count registration_count client_ingress_override
  mkdir -p "$RUNTIME_DIR/$scenario" "$run_dir/server-locks" \
    "$run_dir/inflight-slots" \
    "$run_dir/server-fresh" "$run_dir/transfer-records" "$run_dir/transfer-errors" \
    "$run_dir/transfer-logs" "$run_dir/workers"
  export BNFS_CHAOS_NAT_CA_URL=http://ca:9100
  export BNFS_CHAOS_NAT_KEY_DIR=/artifacts/.private

  client_entry_relay natclient01 "$selected" >/dev/null || return 1
  stop_random_nat_processes || return 1
  printf 'service\trole\tnode_id\tingress_relay\tcredited\n' > "$run_dir/nat-identities.tsv"
  for role in natserver natclient; do
    count=$TOPOLOGY_NAT_SERVER_COUNT
    [[ $role == natserver ]] || count=$TOPOLOGY_NAT_CLIENT_COUNT
    for ((number = 1; number <= count; number++)); do
      printf -v service '%s%02d' "$role" "$number"
      if [[ $role == natserver ]]; then
        relay=$(service_ip_family_relay "$run_dir" "$service" \
          "$(server_entry_relay "$service" "$selected")") || return 1
      else
        relay=$(service_ip_family_relay "$run_dir" "$service" \
          "$(client_entry_relay "$service" "$selected")") || return 1
      fi
      mkdir -p "$PRIVATE_RUNTIME_DIR/$service"
      chmod 700 "$PRIVATE_RUNTIME_DIR/$service"
      ensure_key "$PRIVATE_RUNTIME_DIR/$service/$service.key"
      node_id=$(node_id_from_private_key "$PRIVATE_RUNTIME_DIR/$service/$service.key") || return 1
      [[ $node_id =~ ^[[:xdigit:]]{64}$ ]] || return 1
      credit_node "$ca_port" "$node_id" "$DEFAULT_SOAK_CREDIT_BYTES" || return 1
      printf '%s\t%s\t%s\t%s\tyes\n' "$service" "$role" "$node_id" "$relay" >> "$run_dir/nat-identities.tsv"
    done
  done
  service=$MALICIOUS_RANDOM_NAT_SERVER
  relay=$(server_entry_relay "$service" "$selected") || return 1
  mkdir -p "$PRIVATE_RUNTIME_DIR/$service"
  chmod 700 "$PRIVATE_RUNTIME_DIR/$service"
  ensure_key "$PRIVATE_RUNTIME_DIR/$service/$service.key"
  node_id=$(node_id_from_private_key "$PRIVATE_RUNTIME_DIR/$service/$service.key") || return 1
  [[ $node_id =~ ^[[:xdigit:]]{64}$ ]] || return 1
  credit_node "$ca_port" "$node_id" "$DEFAULT_SOAK_CREDIT_BYTES" || return 1
  printf '%s\tmalicious-natserver\t%s\t%s\tyes\n' \
    "$service" "$node_id" "$relay" >> "$run_dir/nat-identities.tsv"
  service=$MALICIOUS_NAT_CLIENT
  relay=$(client_entry_relay "$service" "$selected") || return 1
  mkdir -p "$PRIVATE_RUNTIME_DIR/$service"
  chmod 700 "$PRIVATE_RUNTIME_DIR/$service"
  ensure_key "$PRIVATE_RUNTIME_DIR/$service/$service.key"
  node_id=$(node_id_from_private_key "$PRIVATE_RUNTIME_DIR/$service/$service.key") || return 1
  [[ $node_id =~ ^[[:xdigit:]]{64}$ ]] || return 1
  credit_node "$ca_port" "$node_id" "$DEFAULT_SOAK_CREDIT_BYTES" || return 1
  printf '%s\t%s\t%s\t%s\tyes\n' \
    "$service" malicious-natclient "$node_id" "$relay" >> "$run_dir/nat-identities.tsv"
  [[ $(tail -n +2 "$run_dir/nat-identities.tsv" | cut -f3 | sort -u | wc -l) -eq $((TOPOLOGY_NAT_SERVER_COUNT + RANDOM_CLIENT_POOL_COUNT + 1)) ]] || return 1
  validate_client_entry_table "$run_dir/nat-identities.tsv" "$selected" 1 4 2 "$run_dir" || return 1

  printf 'server\tingress_relay\trelay_endpoint\tip_family\tnode_id\n' > "$run_dir/server-pool.tsv"
  for ((number = 1; number <= TOPOLOGY_NAT_SERVER_COUNT; number++)); do
    printf -v service 'natserver%02d' "$number"
    relay=$(service_ip_family_relay "$run_dir" "$service" "$(server_entry_relay "$service" "$selected")") || return 1
    family=$(service_ip_family "$run_dir" "$service") || return 1
    relay_endpoint=$(service_relay_endpoint "$run_dir" "$service" natserver "$relay") || return 1
    expected_node_id=$(awk -F '\t' -v service="$service" '$1==service {print $3}' "$run_dir/nat-identities.tsv")
    registration_count=$(relay_registration_count "$relay" "$expected_node_id") || return 1
    node_id=$(start_tunnel_server_for_ip_family "$run_dir" "$service" "$relay" "$scenario" \
      5 200 "$per_transfer_limit_mibps") || return 1
    [[ $node_id == "$expected_node_id" ]] || return 1
    wait_relay_registration "$relay" "$node_id" "$registration_count" 20 || return 1
    wait_random_server_billing_ready "$service" "$POST_GATE_SERVER_RECOVERY_TIMEOUT_SECONDS" || return 1
    printf '%s\t%s\t%s\t%s\t%s\n' \
      "$service" "$relay" "$relay_endpoint" "$family" "$node_id" >> "$run_dir/server-pool.tsv"
    touch "$run_dir/server-fresh/$service"
  done
  service=$MALICIOUS_RANDOM_NAT_SERVER
  relay=$(server_entry_relay "$service" "$selected") || return 1
  family=$(service_ip_family "$run_dir" "$service") || return 1
  relay_endpoint=$(service_relay_endpoint "$run_dir" "$service" natserver "$relay") || return 1
  expected_node_id=$(awk -F '\t' -v service="$service" '$1==service {print $3}' "$run_dir/nat-identities.tsv")
  registration_count=$(relay_registration_count "$relay" "$expected_node_id") || return 1
  node_id=$(start_tunnel_server_for_ip_family "$run_dir" "$service" "$relay" "$scenario" \
    5 200 "$per_transfer_limit_mibps") || return 1
  [[ $node_id == "$expected_node_id" ]] || return 1
  wait_relay_registration "$relay" "$node_id" "$registration_count" 20 || return 1
  wait_random_server_billing_ready "$service" "$POST_GATE_SERVER_RECOVERY_TIMEOUT_SECONDS" || return 1
  printf '%s\t%s\t%s\t%s\t%s\n' \
    "$service" "$relay" "$relay_endpoint" "$family" "$node_id" >> "$run_dir/server-pool.tsv"
  touch "$run_dir/server-fresh/$service"

  printf 'client\tingress_relay\trelay_endpoint\tip_family\tlisten_port\tnode_id\n' > "$run_dir/client-pool.tsv"
  for ((number = 1; number <= TOPOLOGY_NAT_CLIENT_COUNT; number++)); do
    printf -v service 'natclient%02d' "$number"
    relay=$(service_ip_family_relay "$run_dir" "$service" "$(client_entry_relay "$service" "$selected")") || return 1
    family=$(service_ip_family "$run_dir" "$service") || return 1
    relay_endpoint=$(service_relay_endpoint "$run_dir" "$service" natclient "$relay") || return 1
    listen_port=$((18100 + number))
    node_id=$(awk -F '\t' -v service="$service" '$1==service {print $3}' "$run_dir/nat-identities.tsv")
    [[ $node_id =~ ^[[:xdigit:]]{64}$ ]] || return 1
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$service" "$relay" "$relay_endpoint" "$family" "$listen_port" "$node_id" >> "$run_dir/client-pool.tsv"
  done
  service=$MALICIOUS_NAT_CLIENT
  relay=$(client_entry_relay "$service" "$selected") || return 1
  family=$(service_ip_family "$run_dir" "$service") || return 1
  relay_endpoint=$(service_relay_endpoint "$run_dir" "$service" natclient "$relay") || return 1
  listen_port=18107
  node_id=$(awk -F '\t' -v service="$service" '$1==service {print $3}' "$run_dir/nat-identities.tsv")
  [[ $node_id =~ ^[[:xdigit:]]{64}$ ]] || return 1
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$service" "$relay" "$relay_endpoint" "$family" "$listen_port" "$node_id" >> "$run_dir/client-pool.tsv"
  validate_client_entry_table "$run_dir/client-pool.tsv" "$selected" 1 2 0 "$run_dir" || return 1
  awk -F '\t' -v service="$MALICIOUS_NAT_CLIENT" '
    $1 == service && $2 == "relay01" && $4 == "default" && $5 == 18107 \
      && length($6) == 64 && $6 ~ /^[[:xdigit:]]+$/ { found=1 }
    END { exit !found }
  ' "$run_dir/client-pool.tsv" || return 1
  client_ingress_override=$(awk -F '\t' '
    NR > 1 && $2 != "relay01" {
      if (overrides != "") overrides=overrides ","
      overrides=overrides $1 ":" $2
    }
    END { print overrides == "" ? "none" : overrides }
  ' "$run_dir/client-pool.tsv") || return 1
  [[ -n $client_ingress_override ]] || return 1

  printf 'mode=random_batch\nclient_count=%s\nnormal_client_count=%s\nmalicious_client_count=1\nserver_count=%s\nnormal_server_count=%s\nmalicious_server_count=1\nmax_inflight_batches=%s\nworkload_limit_mibps=%s\nper_transfer_limit_mibps=%s\nbatch_limit_1_client_kibps=%s\nbatch_limit_2_clients_kibps=%s\nbatch_limit_3_clients_kibps=%s\nbatch_limit_4_clients_kibps=%s\nbatch_client_start_stagger_seconds=%s\nbatch_mixed_path_quiet_samples=%s\nbatch_mixed_path_quiet_timeout_seconds=%s\nmulti_client_probability_pct=%s\nmulti_client_min=%s\nmulti_client_max=%s\nselection_order=server_then_mode_then_clients\nrandom_ingress_default=relay01\nrandom_ingress_override=%s\n' \
    "$RANDOM_CLIENT_POOL_COUNT" "$TOPOLOGY_NAT_CLIENT_COUNT" "$((TOPOLOGY_NAT_SERVER_COUNT + 1))" "$TOPOLOGY_NAT_SERVER_COUNT" "$max_inflight" \
    "$workload_limit_mibps" "$per_transfer_limit_mibps" \
    "$(random_batch_transfer_limit_kibps 1 "$workload_limit_mibps")" \
    "$(random_batch_transfer_limit_kibps 2 "$workload_limit_mibps")" \
    "$(random_batch_transfer_limit_kibps 3 "$workload_limit_mibps")" \
    "$(random_batch_transfer_limit_kibps 4 "$workload_limit_mibps")" \
    "$RANDOM_BATCH_CLIENT_START_STAGGER_SECONDS" \
    "$RANDOM_BATCH_MIXED_PATH_QUIET_SAMPLES" \
    "$RANDOM_BATCH_MIXED_PATH_QUIET_TIMEOUT_SECONDS" \
    "$RANDOM_MULTI_CLIENT_PERCENT" \
    "$RANDOM_MULTI_CLIENT_MIN" "$RANDOM_MULTI_CLIENT_MAX" "$client_ingress_override" >> "$run_dir/workload.env"
}

ip_family_address_gate() {
  local service=$1 family=$2 expected_host=${3:-} ipv4_pattern= ipv6_pattern=
  local container_id addresses
  case $family in
    ipv4) ipv4_pattern='10.253.41.' ;;
    ipv6) ipv6_pattern='fd92:7b5e:4c31:42:' ;;
    dual) ipv4_pattern='10.253.43.'; ipv6_pattern='fd92:7b5e:4c31:43:' ;;
    *) return 1 ;;
  esac
  container_id=$(dc ps -q "$service" 2>/dev/null) || return 1
  [[ $container_id =~ ^[[:xdigit:]]{12,64}$ ]] || return 1
  addresses=$(docker inspect --format \
    '{{range .NetworkSettings.Networks}}{{printf "%s\t%s\n" .IPAddress .GlobalIPv6Address}}{{end}}' \
    "$container_id" 2>/dev/null) || return 1
  if [[ -n $ipv4_pattern ]] && ! awk -F '\t' -v prefix="$ipv4_pattern" '
    { for (field = 1; field <= NF; field++) if (index($field, prefix) == 1) found=1 }
    END { exit !found }
  ' <<< "$addresses"; then
    return 1
  fi
  if [[ -n $ipv6_pattern ]] && ! awk -F '\t' -v prefix="$ipv6_pattern" '
    { for (field = 1; field <= NF; field++) if (index($field, prefix) == 1) found=1 }
    END { exit !found }
  ' <<< "$addresses"; then
    return 1
  fi
  [[ -z $expected_host ]] && return 0
  awk -F '\t' -v expected="$expected_host" '
    { for (field = 1; field <= NF; field++) if ($field == expected) found=1 }
    END { exit !found }
  ' <<< "$addresses"
}

ip_family_relay_socket_gate() {
  local service=$1 endpoint=$2 host deadline
  host=${endpoint%:9000}
  host=${host#[}
  host=${host%]}
  [[ -n $host ]] || return 1
  deadline=$((SECONDS + 15))
  while (( SECONDS < deadline )); do
    if netns_exec "$service" ss -Htn state established 2>/dev/null | grep -Fq "$host"; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

verify_ip_family_coverage() {
  local run_dir=$1 plan_file family relay server client server_endpoint client_endpoint target_id listen_port
  local transfer_id record_file actual_relay client_socket=fail server_socket=fail address_check=fail transfer_result=fail
  plan_file=$(ip_family_plan_file "$run_dir" 2>/dev/null || true)
  [[ -n $plan_file ]] || return 0
  printf 'timestamp\tfamily\trelay\tnatserver\tnatclient\tclient_endpoint\tserver_endpoint\taddress_check\tclient_socket\tserver_socket\tsha256\tstatus\n' \
    > "$run_dir/ip-family-coverage.tsv"
  while IFS=$'\t' read -r -u 7 family relay server client; do
    [[ $family != family ]] || continue
    address_check=fail
    client_socket=fail
    server_socket=fail
    transfer_result=fail
    server_endpoint=$(service_relay_endpoint "$run_dir" "$server" natserver "$relay") || return 1
    client_endpoint=$(service_relay_endpoint "$run_dir" "$client" natclient "$relay") || return 1
    target_id=$(awk -F '\t' -v server="$server" '$1 == server { print $5; exit }' "$run_dir/server-pool.tsv")
    listen_port=$(awk -F '\t' -v client="$client" '$1 == client { print $5; exit }' "$run_dir/client-pool.tsv")
    [[ $target_id =~ ^[[:xdigit:]]{64}$ && $listen_port =~ ^[0-9]+$ ]] || return 1
    if ip_family_address_gate "$relay" "$family" \
      "$(case "$family" in ipv4) printf '10.253.41.250';; ipv6) printf 'fd92:7b5e:4c31:42::250';; dual) printf '10.253.43.250';; esac)" \
      && ip_family_address_gate "$server" "$family" \
      && ip_family_address_gate "$client" "$family" \
      && ip_family_address_gate ca "$family" \
        "$(case "$family" in ipv4) printf '10.253.41.251';; ipv6) printf 'fd92:7b5e:4c31:42::251';; dual) printf '10.253.43.251';; esac)"; then
      address_check=pass
    fi
    if [[ $address_check == pass ]]; then
      stop_nat_process "$client" tunclient || true
      launch_tunnel_client_for_ip_family "$run_dir" "$client" "$relay" "$target_id" "$listen_port" random-workload || true
      if wait_client_ready "$client" random-workload 70; then
        ip_family_relay_socket_gate "$client" "$client_endpoint" && client_socket=pass
        ip_family_relay_socket_gate "$server" "$server_endpoint" && server_socket=pass
        actual_relay=$(wait_client_entry_relay "$client" 5 "$relay" 2>/dev/null || true)
        transfer_id="ip-family-$family-$(date +%s%N)"
        record_file=$run_dir/transfer-records/$transfer_id.tsv
        if [[ $actual_relay == "$relay" ]] \
          && random_transfer_once "$run_dir" random-workload "$server" "$client" "$actual_relay" \
            "$listen_port" "$transfer_id" "$record_file" 1 "$(( $(date +%s) + 180 ))" \
          && append_transfer_record "$run_dir" "$record_file"; then
          transfer_result=pass
        fi
        rm -f "$record_file"
      fi
      stop_nat_process "$client" tunclient || true
    fi
    local status=fail
    [[ $address_check == pass && $client_socket == pass && $server_socket == pass && $transfer_result == pass ]] && status=pass
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$(date --iso-8601=seconds)" "$family" "$relay" "$server" "$client" \
      "$client_endpoint" "$server_endpoint" "$address_check" "$client_socket" "$server_socket" \
      "$transfer_result" "$status" >> "$run_dir/ip-family-coverage.tsv"
    [[ $status == pass ]] || return 1
  done 7< "$plan_file"
}

validate_ip_family_coverage() {
  local run_dir=$1 plan_file
  plan_file=$(ip_family_plan_file "$run_dir" 2>/dev/null || true)
  [[ -n $plan_file ]] || return 0
  awk -F '\t' '
    NR == FNR { if (FNR > 1) expected[$1]=$2 "\\t" $3 "\\t" $4; next }
    FNR == 1 { valid=($0 == "timestamp\tfamily\trelay\tnatserver\tnatclient\tclient_endpoint\tserver_endpoint\taddress_check\tclient_socket\tserver_socket\tsha256\tstatus"); next }
    NF == 12 && expected[$2] == $3 "\\t" $4 "\\t" $5 && $8 == "pass" && $9 == "pass" \
      && $10 == "pass" && $11 == "pass" && $12 == "pass" { passed[$2]=1 }
    END { exit !(valid && passed["ipv4"] && passed["ipv6"] && passed["dual"]) }
  ' "$plan_file" "$run_dir/ip-family-coverage.tsv"
}

record_profile_setup_failure() {
  local run_dir=$1 reason=$2
  printf '%s\treason=%s\n' "$(date --iso-8601=seconds)" "$reason" >> "$run_dir/profile-setup.log"
  printf '[stability] profile setup check failed: %s\n' "$reason" >&2
}

verify_profile3_tcp_cold_start() {
  local run_dir=$1 selected=$2
  [[ $selected == 3 ]] || return 0

  local server=natserver03 client=natclient05 relay=relay01 listen_port=18105
  local target_id transfer_id record_file actual_relay rc=0
  : > "$run_dir/profile-setup.log"
  if ! netns_exec "$server" iptables -C OUTPUT -p udp --dport 9000 -j DROP >/dev/null 2>&1; then
    record_profile_setup_failure "$run_dir" server_udp_drop_missing
    return 1
  fi
  if ! netns_exec "$client" iptables -C OUTPUT -p udp --dport 9000 -j DROP >/dev/null 2>&1; then
    record_profile_setup_failure "$run_dir" client_udp_drop_missing
    return 1
  fi
  target_id=$(awk -F '\t' -v server="$server" '$1 == server { print $5; exit }' "$run_dir/server-pool.tsv")
  if [[ ! $target_id =~ ^[[:xdigit:]]{64}$ ]]; then
    record_profile_setup_failure "$run_dir" server_pool_identity_missing_or_invalid
    return 1
  fi
  if grep -q 'Listen 退出:' "$RUNTIME_DIR/random-workload/$server.log"; then
    record_profile_setup_failure "$run_dir" tunnel_server_listener_exited
    return 1
  fi
  local server_processes server_tcp_legs
  server_processes=$(dc exec -T "$server" pgrep -x tunserver 2>/dev/null | wc -l)
  if [[ $server_processes -ne 1 ]]; then
    record_profile_setup_failure "$run_dir" "tunserver_process_count_$server_processes"
    return 1
  fi
  server_tcp_legs=$(netns_exec "$server" ss -Hnt state established 2>/dev/null \
    | awk '$NF ~ /:9000$/ { count++ } END { print count + 0 }')
  if (( server_tcp_legs < 2 )); then
    record_profile_setup_failure "$run_dir" "established_tcp_relay_leg_count_$server_tcp_legs"
    return 1
  fi

  stop_nat_process "$client" tunclient || true
  launch_tunnel_client "$client" "$relay:9000" "$target_id" "$listen_port" random-workload
  if ! wait_client_ready "$client" random-workload 70; then
    stop_nat_process "$client" tunclient || true
    record_profile_setup_failure "$run_dir" tunnel_client_not_ready
    return 1
  fi
  actual_relay=$(wait_client_entry_relay "$client" 5 2>/dev/null || true)
  if [[ -z $actual_relay ]]; then
    stop_nat_process "$client" tunclient || true
    record_profile_setup_failure "$run_dir" tunnel_client_entry_relay_not_detected
    return 1
  fi
  transfer_id="profile3-tcp-cold-$(date +%s%N)"
  record_file=$run_dir/transfer-records/$transfer_id.tsv
  random_transfer_once "$run_dir" random-workload "$server" "$client" "$actual_relay" \
    "$listen_port" "$transfer_id" "$record_file" 100 || rc=$?
  snapshot_transfer_logs "$run_dir" "$transfer_id" "$client" "$server"
  if append_transfer_record "$run_dir" "$record_file"; then
    rm -f "$record_file" || rc=1
  else
    rc=1
  fi
  stop_nat_process "$client" tunclient || true
  if (( rc != 0 )); then
    record_profile_setup_failure "$run_dir" tcp_cold_start_transfer_failed
  elif ! rm -f "$run_dir/server-fresh/$server"; then
    record_profile_setup_failure "$run_dir" tcp_cold_start_server_state_update_failed
    rc=1
  fi
  (( rc == 0 ))
}

write_failed_transfer() {
  local client=$1 relay=$2 server=$3 transfer_id=$4 record_file=$5 rc=${6:-1} requested_mib=${7:-0}
  write_transfer_record_atomic "$record_file" "$(date --iso-8601=seconds)" "$transfer_id" \
    "$client" "$relay" "$server" "$requested_mib" "$rc" 0 0.000000 0.000 not-run '' ''
}

write_timed_out_transfer() {
  local client=$1 relay=$2 server=$3 transfer_id=$4 record_file=$5 requested_mib=$6 started_ns=$7
  local ended_ns elapsed
  ended_ns=$(date +%s%N)
  elapsed=$(awk -v start="$started_ns" -v end="$ended_ns" \
    'BEGIN {printf "%.6f", (end-start)/1000000000}')
  write_transfer_record_atomic "$record_file" "$(date --iso-8601=seconds)" "$transfer_id" \
    "$client" "$relay" "$server" "$requested_mib" 28 0 "$elapsed" 0.000 not-run '' ''
}

relay_registration_count() {
  local relay=$1 node_id=$2 prefix=${2:0:16}
  dc logs --no-color "$relay" 2>&1 | awk -v prefix="$prefix" '
    index($0, prefix) && ($0 ~ /新建 StreamGroup/ || $0 ~ /附加 relay leg/) { count++ }
    END { print count + 0 }
  '
}

wait_relay_registration() {
  local relay=$1 node_id=$2 previous_count=$3 timeout_seconds=${4:-20}
  local deadline current_count
  deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    current_count=$(relay_registration_count "$relay" "$node_id") || return 1
    if (( current_count > previous_count )); then
      return 0
    fi
    sleep 0.25
  done
  log_step "$node_id 未在 $relay 完成新一代注册"
  return 1
}

wait_relay_registration_generation() {
  local relay=$1 node_id=$2 previous_count=$3 timeout_seconds=${4:-45}
  local deadline current_count
  deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    current_count=$(relay_registration_count "$relay" "$node_id") || return 1
    if (( current_count >= previous_count + 2 )); then
      return 0
    fi
    sleep 0.25
  done
  log_step "$node_id 未在 $relay 完成新代次双腿注册"
  return 1
}

wait_random_server_listener_idle() {
  local server=$1 timeout_seconds=${2:-$POST_GATE_SERVER_RECOVERY_TIMEOUT_SECONDS}
  local status_file=$PRIVATE_RUNTIME_DIR/$server/service-listener.json
  local deadline observation previous_observation= stable_samples=0
  [[ $server =~ ^natserver(0[1-9]|1[0-3])$ || $server == "$MALICIOUS_RANDOM_NAT_SERVER" ]] || return 1
  deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    observation=$(node -e '
      const fs = require("node:fs");
      const file = process.argv[1];
      const expectedService = process.argv[2];
      let value;
      try {
        value = JSON.parse(fs.readFileSync(file, "utf8"));
      } catch {
        process.exit(1);
      }
      const observed = Date.parse(value?.observedAt ?? "");
      const now = Date.now();
      if (value?.schemaVersion !== 1 || value?.service !== expectedService
        || value?.carrierConnected !== true || value?.activeSessions !== 0
        || value?.acceptQueueDepth !== 0 || !Array.isArray(value?.sessions)
        || value.sessions.length !== 0 || !Number.isFinite(observed)
        || observed > now + 5000 || now - observed > 5000) process.exit(1);
      process.stdout.write(new Date(observed).toISOString());
    ' "$status_file" "$server" 2>/dev/null) || observation=
    if [[ -n $observation ]]; then
      if [[ $observation != "$previous_observation" ]]; then
        stable_samples=$((stable_samples + 1))
        previous_observation=$observation
      fi
      if (( stable_samples >= POST_GATE_SERVER_RECOVERY_STABLE_SAMPLES )); then
        return 0
      fi
    else
      stable_samples=0
      previous_observation=
    fi
    sleep 0.25
  done
  log_step "$server 的持久 ServiceListener 未完成会话回收"
  return 1
}

random_server_tunnel_process_count() {
  local server=$1 count
  count=$(dc exec -T "$server" pgrep -x tunserver 2>/dev/null | wc -l) || return 1
  [[ $count =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$count"
}

random_server_relay_tcp_connection_count() {
  local server=$1 count
  count=$(netns_exec "$server" ss -Hnt state established 2>/dev/null \
    | awk '$NF ~ /:9000$/ { count++ } END { print count + 0 }') || return 1
  [[ $count =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$count"
}

wait_random_server_billing_ready() {
  local server=$1 timeout_seconds=${2:-$POST_GATE_SERVER_RECOVERY_TIMEOUT_SECONDS}
  local deadline stable_samples=0 process_count tcp_connections observation
  local version billing_enabled active_sessions observed cosigned fully_confirmed generated_milliseconds
  deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    process_count=$(random_server_tunnel_process_count "$server" 2>/dev/null || printf '0')
    tcp_connections=$(random_server_relay_tcp_connection_count "$server" 2>/dev/null || printf '0')
    observation=$(billing_production_gate_read_nat_observation "$server" 2>/dev/null || true)
    IFS=$'\t' read -r version billing_enabled active_sessions observed cosigned \
      fully_confirmed generated_milliseconds <<< "$observation"
    if [[ $process_count == 1 && $tcp_connections =~ ^[0-9]+$ && tcp_connections -ge 2 \
      && $version == 1 && $billing_enabled == true && $active_sessions == 1 \
      && $observed =~ ^[0-9]+$ && $cosigned =~ ^[0-9]+$ && $fully_confirmed == true ]] \
      && (( observed >= cosigned )) \
      && billing_production_gate_observation_is_fresh "$generated_milliseconds"; then
      stable_samples=$((stable_samples + 1))
      if (( stable_samples >= POST_GATE_SERVER_RECOVERY_STABLE_SAMPLES )); then
        return 0
      fi
    else
      stable_samples=0
    fi
    sleep 0.25
  done
  log_step "$server 的双腿数据路径或双签计费控制未稳定"
  return 1
}

recover_random_server_pool_after_relay_restart() {
  local run_dir=$1 affected_relay=$2
  local server server_relay server_endpoint server_family expected_node_id previous_count actual_node_id gate_server_line
  local recovered=0
  [[ $REAL_BILLING_GATE_SERVER =~ ^natserver[0-9]{2}$ ]] || return 1
  [[ -s $run_dir/server-pool.tsv ]] || return 1
  gate_server_line=$(awk -F '\t' -v server="$REAL_BILLING_GATE_SERVER" \
    '$1 == server { print; exit }' "$run_dir/server-pool.tsv") || return 1
  IFS=$'\t' read -r server server_relay server_endpoint server_family expected_node_id <<< "$gate_server_line"
  if [[ -z $expected_node_id && $server_endpoint =~ ^[[:xdigit:]]{64}$ ]]; then
    expected_node_id=$server_endpoint
    server_endpoint=$affected_relay:9000
    server_family=default
  fi
  [[ $server == "$REAL_BILLING_GATE_SERVER" && $server_relay == "$affected_relay" \
    && $server_endpoint == "$affected_relay:9000" && $server_family == default \
    && $expected_node_id =~ ^[[:xdigit:]]{64}$ ]] || return 1
  rm -f "$run_dir/server-fresh/$server" || return 1
  wait_random_server_billing_ready "$server" "$POST_GATE_SERVER_RECOVERY_TIMEOUT_SECONDS" || return 1
  recovered=1

  while IFS=$'\t' read -r server server_relay server_endpoint server_family expected_node_id; do
    [[ $server != server ]] || continue
    if [[ -z $expected_node_id && $server_endpoint =~ ^[[:xdigit:]]{64}$ ]]; then
      expected_node_id=$server_endpoint
      server_endpoint=$server_relay:9000
      server_family=default
    fi
    [[ $server_relay == "$affected_relay" ]] || continue
    [[ ($server =~ ^natserver[0-9]{2}$ || $server == "$MALICIOUS_RANDOM_NAT_SERVER") \
      && $server_endpoint && $server_family =~ ^(default|ipv4|ipv6|dual)$ \
      && $expected_node_id =~ ^[[:xdigit:]]{64}$ ]] || return 1
    [[ $server != "$REAL_BILLING_GATE_SERVER" ]] || continue
    rm -f "$run_dir/server-fresh/$server" || return 1
    previous_count=$(relay_registration_count "$affected_relay" "$expected_node_id") || return 1
    actual_node_id=$(restart_tunnel_server_for_ip_family "$run_dir" "$server" "$affected_relay" random-workload \
      2>/dev/null </dev/null) || return 1
    [[ $actual_node_id == "$expected_node_id" ]] || return 1
    wait_relay_registration_generation "$affected_relay" "$expected_node_id" "$previous_count" \
      "$POST_GATE_SERVER_RECOVERY_TIMEOUT_SECONDS" || return 1
    wait_random_server_billing_ready "$server" "$POST_GATE_SERVER_RECOVERY_TIMEOUT_SECONDS" || return 1
    touch "$run_dir/server-fresh/$server" || return 1
    recovered=$((recovered + 1))
  done < "$run_dir/server-pool.tsv"
  (( recovered > 0 ))
}

snapshot_transfer_logs() {
  local run_dir=$1 transfer_id=$2 client=$3 server=$4
  local source_dir=$RUNTIME_DIR/random-workload destination=$run_dir/transfer-logs
  mkdir -p "$destination"
  [[ ! -f $source_dir/$client.log ]] || cp "$source_dir/$client.log" "$destination/$transfer_id-client.log"
  [[ ! -f $source_dir/$server.log ]] || cp "$source_dir/$server.log" "$destination/$transfer_id-server.log"
}

validate_scenario_client_ingress_coverage() {
  local run_dir=$1 selected=$2 number client expected_relay
  [[ $selected == 2 ]] || return 0
  for ((number = 1; number <= TOPOLOGY_NAT_CLIENT_COUNT; number++)); do
    printf -v client 'natclient%02d' "$number"
    expected_relay=$(client_entry_relay "$client" "$selected") || return 1
    expected_relay=$(service_ip_family_relay "$run_dir" "$client" "$expected_relay") || return 1
    if ! awk -F '\t' -v client="$client" -v expected_relay="$expected_relay" '
      NR > 1 && $3 == client && $7 == 0 && $8 > 0 && $11 == "yes" {
        successes++
        if ($4 == expected_relay) expected++
        else unexpected++
      }
      END { exit !(successes > 0 && expected == successes && unexpected == 0) }
    ' "$run_dir/transfers.tsv"; then
      log_step "$client 没有始终经预期入口 $expected_relay 完成成功传输"
      return 1
    fi
  done
}

validate_random_workload_coverage() {
  local run_dir=$1 selected=${2:-} validation_mode=${3:-$DEFAULT_VALIDATION_MODE}
  local client expected_relay
  [[ $validation_mode == smoke || $validation_mode == full ]] || return 1
  while IFS= read -r client; do
    if ! awk -F '\t' -v client="$client" 'NR > 1 && $3 == client && $4 ~ /^relay0[1-7]$/ && $7 == 0 && $8 > 0 && $11 == "yes" { found=1 } END { exit !found }' \
      "$run_dir/transfers.tsv"; then
      log_step "$client 没有完成任何一条 SHA-256 正确的随机传输"
      return 1
    fi
    expected_relay=$(client_entry_relay "$client" "$selected") || return 1
    expected_relay=$(service_ip_family_relay "$run_dir" "$client" "$expected_relay") || return 1
    if ! awk -F '\t' -v client="$client" -v expected_relay="$expected_relay" \
      -v validation_mode="$validation_mode" '
      function reachable(entry, host) {
        return entry == host \
          || (entry == "relay01" && host ~ /^relay0[3-7]$/) \
          || (host == "relay01" && entry ~ /^relay0[3-7]$/)
      }
      NR == FNR {
        if (FNR > 1) {
          host[$1]=$2
          if ($2 ~ /^relay0[2-5]$/) partition[$1]="A"
          if ($2 ~ /^relay0[6-7]$/) partition[$1]="B"
          if (reachable(expected_relay, $2) && partition[$1] == "A") expectedA=1
          if (reachable(expected_relay, $2) && partition[$1] == "B") expectedB=1
        }
        next
      }
      FNR > 1 && $3 == client && $4 ~ /^relay0[1-7]$/ && $7 == 0 && $8 > 0 && $11 == "yes" {
        if (!reachable($4, host[$5])) invalid=1
        if (partition[$5] == "A") seenA=1
        if (partition[$5] == "B") seenB=1
      }
      END {
        exit invalid || (validation_mode == "full" \
          && ((expectedA && !seenA) || (expectedB && !seenB)))
      }
    ' "$run_dir/server-pool.tsv" "$run_dir/transfers.tsv"; then
      log_step "$client 未覆盖所有一跳可达控制分区，或记录了不可达的成功路径"
      return 1
    fi
  done < <(numbered_service_names natclient "$TOPOLOGY_NAT_CLIENT_COUNT")
  if [[ $validation_mode == full ]]; then
    if ! awk -F '\t' -v client="$MALICIOUS_NAT_CLIENT" '
      NR > 1 && $3 == client && $4 ~ /^relay0[1-7]$/ && $7 == 0 && $8 > 0 && $11 == "yes" { found=1 }
      END { exit !found }
    ' "$run_dir/transfers.tsv"; then
      log_step "$MALICIOUS_NAT_CLIENT 未完成任何一条 SHA-256 正确的随机传输"
      return 1
    fi
  fi
  if [[ $validation_mode == full ]]; then
    if ! awk -F '\t' '
      NR == FNR { if (FNR > 1) expected[$1]=1; next }
      FNR > 1 && $4 ~ /^relay0[1-7]$/ && $7 == 0 && $8 > 0 && $11 == "yes" { reached[$5]=1 }
      END {
        missing=0
        for (server in expected) if (!reached[server]) missing++
        exit missing != 0
      }
    ' "$run_dir/server-pool.tsv" "$run_dir/transfers.tsv"; then
      log_step "随机负载尚未成功覆盖完整 $((TOPOLOGY_NAT_SERVER_COUNT + 1)) NatServer 池"
      return 1
    fi
  elif ! awk -F '\t' '
    NR == FNR {
      if (FNR > 1 && $2 ~ /^relay0[2-5]$/) expectedA=1
      if (FNR > 1 && $2 ~ /^relay0[6-7]$/) expectedB=1
      host[$1]=$2
      next
    }
    FNR > 1 && $7 == 0 && $8 > 0 && $11 == "yes" {
      if (host[$5] ~ /^relay0[2-5]$/) seenA=1
      if (host[$5] ~ /^relay0[6-7]$/) seenB=1
    }
    END { exit (expectedA && !seenA) || (expectedB && !seenB) }
  ' "$run_dir/server-pool.tsv" "$run_dir/transfers.tsv"; then
    log_step "smoke 随机负载未覆盖所有存在的控制分区"
    return 1
  fi
  validate_scenario_client_ingress_coverage "$run_dir" "$selected" || return 1
  validate_random_batch_evidence "$run_dir" "$validation_mode" || return 1
  return 0
}

validate_random_batch_evidence() {
  local run_dir=$1 validation_mode=${2:-$DEFAULT_VALIDATION_MODE}
  [[ $validation_mode == smoke || $validation_mode == full ]] || return 1
  [[ -s $run_dir/random-batches.tsv ]] || return 1
  awk -F '\t' -v validation_mode="$validation_mode" -v malicious_client="$MALICIOUS_NAT_CLIENT" \
    -v malicious_server="$MALICIOUS_RANDOM_NAT_SERVER" '
    NR == 1 {
      valid=($0 == "timestamp\tbatch_id\tselected_server\tserver_pool_includes_malicious\tserver_malicious\tmode\trequested_clients\tselected_clients\tclient_pool_includes_malicious\tmalicious_client_selected\tstatus\ttarget_pairs\tsucceeded\tfailed")
      next
    }
    {
      count=split($8, clients, ",")
      target_count=split($12, targets, ",")
      row_valid=($2 ~ /^batch-[0-9]+-[0-9]+$/ \
        && ($3 ~ /^natserver(0[1-9]|1[0-3])$/ || $3 == malicious_server) \
        && $4 == "true" && (($5 == "true") == ($3 == malicious_server)) \
        && ($6 == "single" || $6 == "multi") && $7 ~ /^[1-4]$/ \
        && count == $7 && target_count == $7 && $9 == "true" \
        && ($10 == "true" || $10 == "false") \
        && ($11 == "RUNNING" || $11 == "PASS" || $11 == "FAIL") \
        && $13 ~ /^[0-9]+$/ && $14 ~ /^[0-9]+$/)
      if ($6 == "single" && $7 != 1) row_valid=0
      if ($6 == "multi" && ($7 < 2 || $7 > 4)) row_valid=0
      malicious_found=0
      delete unique
      for (idx=1; idx<=count; idx++) {
        if (!(clients[idx] ~ /^natclient0[1-6]$/ || clients[idx] == malicious_client) || unique[clients[idx]]++) row_valid=0
        if (clients[idx] == malicious_client) malicious_found=1
        target_parts=split(targets[idx], target, "→")
        if (target_parts != 2 || target[1] != clients[idx] || target[2] != $3) row_valid=0
      }
      if (($10 == "true") != malicious_found) row_valid=0
      if (!row_valid) invalid=1
      if ($11 == "PASS") {
        passed++
        if ($6 == "multi") multi_passed++
        if ($6 == "single") single_passed++
        if (malicious_found) malicious_passed++
        if ($3 == malicious_server) malicious_server_passed++
      }
    }
    END {
      if (!valid || invalid || passed == 0) exit 1
      if (validation_mode == "full" && (!multi_passed || !single_passed \
        || !malicious_passed || !malicious_server_passed)) exit 1
    }
  ' "$run_dir/random-batches.tsv"
}

append_transfer_record() {
  local run_dir=$1 record_file=$2
  local timestamp transfer_id client relay server requested_mib rc bytes seconds throughput sha_ok expected_sha actual_sha
  local record_line probe_line existing_record existing_probe lock_fd append_rc=0
  [[ -f $record_file ]] || return 1
  [[ $(wc -l < "$record_file") -eq 1 ]] || return 1
  awk -F '\t' 'NR == 1 { valid=(NF == 13) } END { exit !(NR == 1 && valid) }' "$record_file" || return 1
  IFS=$'\t' read -r timestamp transfer_id client relay server requested_mib rc bytes seconds throughput sha_ok expected_sha actual_sha < "$record_file"
  [[ $timestamp =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T \
    && -n $transfer_id && -n $client && -n $relay && -n $server \
    && $requested_mib =~ ^[0-9]+$ && $rc =~ ^[0-9]+$ && $bytes =~ ^[0-9]+$ \
    && $seconds =~ ^[0-9]+([.][0-9]+)?$ && $throughput =~ ^[0-9]+([.][0-9]+)?$ \
    && $sha_ok =~ ^(yes|no|not-run)$ ]] || return 1
  [[ $rc != 125 || $sha_ok != not-run ]] || return 1
  record_line=$(<"$record_file")
  probe_line=$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' \
    "$timestamp" "$transfer_id" "$requested_mib" "$rc" "$bytes" "$seconds" "$throughput" \
    "$sha_ok" "$client" "$expected_sha" "$actual_sha")

  exec {lock_fd}>> "$run_dir/transfers.lock" || return 1
  if ! flock "$lock_fd"; then
    exec {lock_fd}>&-
    return 1
  fi
  if ! existing_record=$(awk -F '\t' -v transfer_id="$transfer_id" '
    NR > 1 && $2 == transfer_id { count++; if (count == 1) record=$0 }
    END { if (count > 1) exit 2; if (count == 1) print record }
  ' "$run_dir/transfers.tsv"); then
    append_rc=1
  elif [[ -n $existing_record ]]; then
    [[ $existing_record == "$record_line" ]] || append_rc=1
  elif ! printf '%s\n' "$record_line" >> "$run_dir/transfers.tsv"; then
    append_rc=1
  fi

  if (( append_rc == 0 )); then
    if ! existing_probe=$(awk -F '\t' -v transfer_id="$transfer_id" '
      NR > 1 && $2 == transfer_id { count++; if (count == 1) record=$0 }
      END { if (count > 1) exit 2; if (count == 1) print record }
    ' "$run_dir/large-probes.tsv"); then
      append_rc=1
    elif [[ -n $existing_probe ]]; then
      [[ $existing_probe == "$probe_line" ]] || append_rc=1
    elif ! printf '%s\n' "$probe_line" >> "$run_dir/large-probes.tsv"; then
      append_rc=1
    fi
  fi
  flock -u "$lock_fd" 2>/dev/null || append_rc=1
  exec {lock_fd}>&-
  (( append_rc == 0 ))
}

reconcile_pending_transfer_records() {
  local run_dir=$1 record_file unexpected_file reconcile_rc=0
  [[ -d $run_dir/transfer-records ]] || return 1
  while IFS= read -r -d '' record_file; do
    if append_transfer_record "$run_dir" "$record_file"; then
      rm -f "$record_file" || reconcile_rc=1
    else
      reconcile_rc=1
    fi
  done < <(find "$run_dir/transfer-records" -mindepth 1 -maxdepth 1 -type f -name '*.tsv' -print0)
  unexpected_file=$(find "$run_dir/transfer-records" -mindepth 1 -maxdepth 1 -type f ! -name '*.tsv' -print -quit)
  [[ -z $unexpected_file ]] || reconcile_rc=1
  (( reconcile_rc == 0 ))
}

mark_pending_transfer_timeouts() {
  local run_dir=$1 record_file timestamp transfer_id client relay server requested_mib
  local rc bytes seconds throughput sha_ok expected_sha actual_sha started_epoch now_epoch elapsed
  local update_rc=0
  [[ -d $run_dir/transfer-records ]] || return 1
  now_epoch=$(date +%s)
  while IFS= read -r -d '' record_file; do
    [[ $(wc -l < "$record_file") -eq 1 ]] || { update_rc=1; continue; }
    awk -F '\t' 'NR == 1 { valid=(NF == 13) } END { exit !(NR == 1 && valid) }' \
      "$record_file" || { update_rc=1; continue; }
    IFS=$'\t' read -r timestamp transfer_id client relay server requested_mib rc bytes seconds \
      throughput sha_ok expected_sha actual_sha < "$record_file"
    [[ $rc == 125 && $sha_ok == not-run ]] || continue
    if [[ ! $timestamp =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T || -z $transfer_id \
      || -z $client || -z $relay || -z $server || ! $requested_mib =~ ^[0-9]+$ \
      || $bytes != 0 || ! $seconds =~ ^[0-9]+([.][0-9]+)?$ \
      || ! $throughput =~ ^[0-9]+([.][0-9]+)?$ ]]; then
      update_rc=1
      continue
    fi
    started_epoch=$(date --date="$timestamp" +%s 2>/dev/null || true)
    if [[ ! $started_epoch =~ ^[0-9]+$ || $started_epoch -gt $now_epoch ]]; then
      update_rc=1
      continue
    fi
    printf -v elapsed '%d.000000' "$((now_epoch - started_epoch))"
    write_transfer_record_atomic "$record_file" "$(date --iso-8601=seconds)" "$transfer_id" \
      "$client" "$relay" "$server" "$requested_mib" 28 0 "$elapsed" 0.000 not-run \
      "$expected_sha" "$actual_sha" || update_rc=1
  done < <(find "$run_dir/transfer-records" -mindepth 1 -maxdepth 1 -type f -name '*.tsv' -print0)
  (( update_rc == 0 ))
}

RANDOM_WORKER_EVIDENCE_DETAIL=
finalize_random_worker_evidence() {
  local run_dir=$1
  RANDOM_WORKER_EVIDENCE_DETAIL=
  if ! mark_pending_transfer_timeouts "$run_dir"; then
    RANDOM_WORKER_EVIDENCE_DETAIL=random_transfer_timeout_record_failed
    return 1
  fi
  if ! reconcile_pending_transfer_records "$run_dir"; then
    RANDOM_WORKER_EVIDENCE_DETAIL=random_transfer_reconciliation_failed
    return 1
  fi
  if awk -F '\t' 'NR > 1 && $7 == 125 && $11 == "not-run" { found=1 } END { exit !found }' \
    "$run_dir/transfers.tsv"; then
    RANDOM_WORKER_EVIDENCE_DETAIL=random_transfer_placeholder_published
    return 1
  fi
}

random_below() {
  local upper=$1 value
  (( upper > 0 )) || { printf '0\n'; return 0; }
  value=$(od -An -N4 -tu4 /dev/urandom | tr -d '[:space:]')
  [[ $value =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$((value % upper))"
}

random_batch_client_count() {
  local probability_roll=${1:-} size_roll=${2:-}
  if [[ -z $probability_roll ]]; then
    probability_roll=$(random_below 100) || return 1
  fi
  [[ $probability_roll =~ ^[0-9]+$ ]] && (( probability_roll < 100 )) || return 1
  if (( probability_roll >= RANDOM_MULTI_CLIENT_PERCENT )); then
    printf '1\n'
    return 0
  fi
  if [[ -z $size_roll ]]; then
    size_roll=$(random_below "$((RANDOM_MULTI_CLIENT_MAX - RANDOM_MULTI_CLIENT_MIN + 1))") || return 1
  fi
  [[ $size_roll =~ ^[0-9]+$ ]] \
    && (( size_roll <= RANDOM_MULTI_CLIENT_MAX - RANDOM_MULTI_CLIENT_MIN )) || return 1
  printf '%s\n' "$((RANDOM_MULTI_CLIENT_MIN + size_roll))"
}

random_batch_transfer_limit_kibps() {
  local client_count=$1 workload_limit_mibps=$2 requested_limit
  [[ $client_count =~ ^[1-4]$ ]] || return 1
  is_nonnegative_integer "$workload_limit_mibps" || return 1
  (( workload_limit_mibps > 0 )) || { printf '0\n'; return 0; }
  requested_limit=$((workload_limit_mibps * 1024))
  (( requested_limit <= RANDOM_STREAM_LIMIT_KIBPS )) || requested_limit=$RANDOM_STREAM_LIMIT_KIBPS
  printf '%s\n' "$requested_limit"
}

random_batch_client_start_stagger_seconds() {
  local client_count=$1
  [[ $client_count =~ ^[1-4]$ ]] || return 1
  if (( client_count == 1 )); then
    printf '0\n'
  else
    printf '%s\n' "$RANDOM_BATCH_CLIENT_START_STAGGER_SECONDS"
  fi
}

wait_random_batch_mixed_path_quiet() {
  local run_dir=$1 deadline_epoch=$2
  local required_samples=${3:-$RANDOM_BATCH_MIXED_PATH_QUIET_SAMPLES}
  local timeout_seconds=${4:-$RANDOM_BATCH_MIXED_PATH_QUIET_TIMEOUT_SECONDS}
  local status_file=$run_dir/mixed-adversary-path.status
  local now_epoch wait_deadline status quiet_samples=0
  [[ -d $run_dir && $deadline_epoch =~ ^[1-9][0-9]*$ ]] || return 1
  is_positive_integer "$required_samples" || return 1
  is_positive_integer "$timeout_seconds" || return 1
  [[ -e $status_file ]] || return 0
  now_epoch=$(date +%s)
  (( now_epoch < deadline_epoch )) || return 1
  wait_deadline=$((now_epoch + timeout_seconds))
  (( wait_deadline <= deadline_epoch )) || wait_deadline=$deadline_epoch
  while (( now_epoch < wait_deadline )); do
    status=$(mixed_path_field "$status_file" status 2>/dev/null || true)
    case $status in
      RUNNING)
        quiet_samples=$((quiet_samples + 1))
        (( quiet_samples >= required_samples )) && return 0
        ;;
      STARTING|MIGRATING|'')
        quiet_samples=0
        ;;
      FAILED|DEGRADED|STOPPED)
        return 1
        ;;
      *)
        return 1
        ;;
    esac
    sleep 1
    now_epoch=$(date +%s)
  done
  return 1
}

validate_random_client_pool() {
  local pool_file=$1
  [[ -s $pool_file ]] || return 1
  awk -F '\t' -v malicious="$MALICIOUS_NAT_CLIENT" -v expected="$RANDOM_CLIENT_POOL_COUNT" '
    NR == 1 {
      valid=($0 == "client\tingress_relay\trelay_endpoint\tip_family\tlisten_port\tnode_id")
      next
    }
    NF != 6 || !($1 ~ /^natclient0[1-6]$/ || $1 == malicious) \
      || $2 !~ /^relay0[1-7]$/ || $3 == "" || $4 !~ /^(default|ipv4|ipv6|dual)$/ \
      || $5 !~ /^[0-9]+$/ || length($6) != 64 || $6 !~ /^[[:xdigit:]]+$/ || seen[$1]++ { valid=0; next }
    $1 == malicious { malicious_count++ }
    END { exit !(valid && length(seen) == expected && malicious_count == 1) }
  ' "$pool_file"
}

validate_random_server_pool() {
  local pool_file=$1 expected=$((TOPOLOGY_NAT_SERVER_COUNT + 1))
  [[ -s $pool_file ]] || return 1
  awk -F '\t' -v malicious="$MALICIOUS_RANDOM_NAT_SERVER" -v expected="$expected" '
    NR == 1 {
      valid=($0 == "server\tingress_relay\trelay_endpoint\tip_family\tnode_id")
      next
    }
    NF != 5 || !(($1 ~ /^natserver(0[1-9]|1[0-3])$/) || $1 == malicious) \
      || $2 !~ /^relay0[1-7]$/ || $3 == "" || $4 !~ /^(default|ipv4|ipv6|dual)$/ \
      || length($5) != 64 || $5 !~ /^[[:xdigit:]]+$/ || seen[$1]++ { valid=0; next }
    $1 == malicious { malicious_count++ }
    END { exit !(valid && length(seen) == expected && malicious_count == 1) }
  ' "$pool_file"
}

random_batch_server_line() {
  local run_dir=$1 selection_roll=${2:-} count uncovered_line=
  validate_random_server_pool "$run_dir/server-pool.tsv" || return 1
  count=$(awk 'END { print NR - 1 }' "$run_dir/server-pool.tsv") || return 1
  (( count > 0 )) || return 1
  if [[ -z $selection_roll ]]; then
    if [[ -s $run_dir/random-batches.tsv ]]; then
      uncovered_line=$(awk -F '\t' '
        NR == FNR { if (FNR > 1 && $11 == "PASS") covered[$3]=1; next }
        FNR > 1 && !covered[$1] { print }
      ' "$run_dir/random-batches.tsv" "$run_dir/server-pool.tsv" | shuf -n 1) || return 1
      if [[ -n $uncovered_line ]]; then
        printf '%s\n' "$uncovered_line"
        return 0
      fi
    fi
    selection_roll=$(random_below "$count") || return 1
  fi
  [[ $selection_roll =~ ^[0-9]+$ ]] && (( selection_roll < count )) || return 1
  awk -v selected="$((selection_roll + 2))" 'NR == selected { print; exit }' \
    "$run_dir/server-pool.tsv"
}

random_client_partition_covered() {
  local run_dir=$1 client=$2 partition=$3
  [[ $client =~ ^natclient0[1-6]$ && $partition =~ ^[AB]$ ]] || return 1
  [[ -s $run_dir/transfers.tsv ]] || return 1
  awk -F '\t' -v client="$client" -v partition="$partition" '
    NR == FNR {
      if (FNR > 1 && $2 ~ /^relay0[2-5]$/) server_partition[$1]="A"
      if (FNR > 1 && $2 ~ /^relay0[6-7]$/) server_partition[$1]="B"
      next
    }
    FNR > 1 && $3 == client && $7 == 0 && $8 > 0 && $11 == "yes" \
      && server_partition[$5] == partition { found=1 }
    END { exit !found }
  ' "$run_dir/server-pool.tsv" "$run_dir/transfers.tsv"
}

random_malicious_client_covered() {
  local run_dir=$1
  awk -F '\t' '$11 == "PASS" && $10 == "true" { found=1 } END { exit !found }' \
    "$run_dir/random-batches.tsv"
}

select_random_batch_clients() {
  local run_dir=$1 server_line=$2 eligible_file=$3 selected_file=$4 client_count=$5
  local server server_relay server_endpoint server_family target_id partition= client line
  local priority_file=${selected_file}.priority candidate_file=${selected_file}.candidates
  IFS=$'\t' read -r server server_relay server_endpoint server_family target_id <<< "$server_line"
  [[ $server_relay =~ ^relay0[1-7]$ && $client_count =~ ^[1-4]$ ]] || return 1
  case $server_relay in
    relay0[2-5]) partition=A ;;
    relay0[6-7]) partition=B ;;
  esac
  : > "$priority_file"
  while IFS= read -r line; do
    client=${line%%$'\t'*}
    if [[ -n $partition && $client =~ ^natclient0[1-6]$ ]] \
      && ! random_client_partition_covered "$run_dir" "$client" "$partition"; then
      printf '%s\n' "$line" >> "$priority_file"
    fi
  done < "$eligible_file"
  shuf "$priority_file" > "$candidate_file" || return 1
  if ! random_malicious_client_covered "$run_dir"; then
    awk -F '\t' -v malicious="$MALICIOUS_NAT_CLIENT" '$1 == malicious { print; exit }' \
      "$eligible_file" >> "$candidate_file"
  fi
  shuf "$eligible_file" >> "$candidate_file" || return 1
  awk -F '\t' -v limit="$client_count" '!seen[$1]++ { print; selected++; if (selected == limit) exit }' \
    "$candidate_file" > "$selected_file"
  rm -f "$priority_file" "$candidate_file"
  [[ $(wc -l < "$selected_file") -eq $client_count ]]
}

random_clients_reaching_server() {
  local run_dir=$1 server_line=$2
  local server server_relay server_endpoint server_family target_id
  IFS=$'\t' read -r server server_relay server_endpoint server_family target_id <<< "$server_line"
  [[ -s $run_dir/client-pool.tsv && -n $server && $server_relay =~ ^relay0[1-7]$ \
    && $server_endpoint && $server_family =~ ^(default|ipv4|ipv6|dual)$ \
    && $target_id =~ ^[[:xdigit:]]{64}$ ]] || return 1
  awk -F '\t' -v server_relay="$server_relay" '
    function reachable(entry, host) {
      return entry == host \
        || (entry == "relay01" && host ~ /^relay0[3-7]$/) \
        || (host == "relay01" && entry ~ /^relay0[3-7]$/)
    }
    NR > 1 && NF == 6 && reachable($2, server_relay) { print }
  ' "$run_dir/client-pool.tsv"
}

append_random_batch_event() {
  local run_dir=$1 timestamp=$2 batch_id=$3 selected_server=$4 server_malicious=$5 mode=$6
  local requested_clients=$7 selected_clients=$8 malicious_client_selected=$9 status=${10}
  local target_pairs=${11} succeeded=${12} failed=${13}
  local lock_fd
  exec {lock_fd}>> "$run_dir/random-batches.lock" || return 1
  flock -x "$lock_fd" || { exec {lock_fd}>&-; return 1; }
  printf '%s\t%s\t%s\ttrue\t%s\t%s\t%s\t%s\ttrue\t%s\t%s\t%s\t%s\t%s\n' \
    "$timestamp" "$batch_id" "$selected_server" "$server_malicious" "$mode" \
    "$requested_clients" "$selected_clients" "$malicious_client_selected" "$status" \
    "$target_pairs" "$succeeded" "$failed" \
    >> "$run_dir/random-batches.tsv"
  flock -u "$lock_fd"
  exec {lock_fd}>&-
}

random_batch_worker() {
  local run_dir=$1 deadline_epoch=$2 pause_seconds=$3 max_inflight_batches=$4
  local attempt_timeout_seconds=$5 workload_limit_mibps=$6
  local client_count batch_id mode eligible_file selected_file assignment_file selected_clients malicious_selected
  local server_line target_pairs per_client_limit_kibps start_stagger_seconds launched_clients
  local child_pid child_failed eligible_count server_malicious
  local selected_server selected_server_malicious
  local client_line client relay relay_endpoint family listen_port node_id
  local server server_relay server_endpoint server_family target_id
  local succeeded failed cooldown now_epoch remaining_seconds
  local -a selected_lines=() child_pids=()
  is_positive_integer "$deadline_epoch" || return 1
  is_positive_integer "$pause_seconds" || return 1
  is_positive_integer "$max_inflight_batches" || return 1
  is_positive_integer "$attempt_timeout_seconds" || return 1
  is_nonnegative_integer "$workload_limit_mibps" || return 1
  validate_random_client_pool "$run_dir/client-pool.tsv" || return 1
  validate_random_server_pool "$run_dir/server-pool.tsv" || return 1
  mkdir -p "$run_dir/random-batches" "$run_dir/workers"

  while (( $(date +%s) < deadline_epoch )); do
    batch_id="batch-$(date +%s%N)-$(random_below 1000000)"
    server_line=$(random_batch_server_line "$run_dir") || return 1
    IFS=$'\t' read -r server server_relay server_endpoint server_family target_id <<< "$server_line"
    [[ -n $server && $target_id =~ ^[[:xdigit:]]{64}$ ]] || return 1
    server_malicious=false
    [[ $server == "$MALICIOUS_RANDOM_NAT_SERVER" ]] && server_malicious=true
    selected_server=$server
    selected_server_malicious=$server_malicious
    eligible_file=$run_dir/random-batches/$batch_id.eligible-clients.tsv
    selected_file=$run_dir/random-batches/$batch_id.clients.tsv
    assignment_file=$run_dir/random-batches/$batch_id.assignments.tsv
    random_clients_reaching_server "$run_dir" "$server_line" > "$eligible_file" || return 1
    eligible_count=$(wc -l < "$eligible_file")
    client_count=$(random_batch_client_count) || return 1
    if (( eligible_count < client_count )); then
      rm -f "$eligible_file"
      sleep 1
      continue
    fi
    select_random_batch_clients "$run_dir" "$server_line" "$eligible_file" "$selected_file" \
      "$client_count" || return 1
    mapfile -t selected_lines < "$selected_file"
    (( ${#selected_lines[@]} == client_count )) || return 1
    selected_clients=$(cut -f1 "$selected_file" | paste -sd, -)
    [[ $selected_clients ]] || return 1
    malicious_selected=false
    grep -q "^$MALICIOUS_NAT_CLIENT"$'\t' "$selected_file" && malicious_selected=true
    mode=single
    (( client_count == 1 )) || mode=multi
    : > "$assignment_file"
    while IFS= read -r client_line; do
      IFS=$'\t' read -r client relay relay_endpoint family listen_port node_id <<< "$client_line"
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$client" "$relay" "$relay_endpoint" "$family" "$listen_port" "$node_id" \
        "$server" "$server_relay" "$server_endpoint" "$server_family" "$target_id" \
        >> "$assignment_file"
    done < "$selected_file"
    target_pairs=$(awk -F '\t' '{ if (pairs != "") pairs=pairs ","; pairs=pairs $1 "→" $7 } END { print pairs }' "$assignment_file")
    [[ $target_pairs ]] || return 1
    if ! wait_random_batch_mixed_path_quiet "$run_dir" "$deadline_epoch"; then
      rm -f "$eligible_file" "$selected_file" "$assignment_file"
      now_epoch=$(date +%s)
      (( now_epoch < deadline_epoch )) || return 0
      sleep 1
      continue
    fi
    append_random_batch_event "$run_dir" "$(date --iso-8601=seconds)" "$batch_id" \
      "$selected_server" "$selected_server_malicious" "$mode" "$client_count" "$selected_clients" \
      "$malicious_selected" RUNNING "$target_pairs" 0 0 || return 1

    per_client_limit_kibps=$(random_batch_transfer_limit_kibps \
      "$client_count" "$workload_limit_mibps") || return 1
    start_stagger_seconds=$(random_batch_client_start_stagger_seconds "$client_count") || return 1
    launched_clients=0
    child_failed=0
    child_pids=()
    while IFS=$'\t' read -r client relay relay_endpoint family listen_port node_id \
      server server_relay server_endpoint server_family target_id; do
      server_line=$(printf '%s\t%s\t%s\t%s\t%s' \
        "$server" "$server_relay" "$server_endpoint" "$server_family" "$target_id")
      BNFS_RANDOM_BATCH_ID="$batch_id" BNFS_RANDOM_BATCH_MEMBER=1 \
        BNFS_RANDOM_SERVER_LINE="$server_line" \
        BNFS_RANDOM_TRANSFER_LIMIT_KIBPS="$per_client_limit_kibps" \
        bash "${STABILITY_WORKER_SCRIPT:-$ROOT_DIR/scripts/local-chaos-stability.sh}" \
          _worker "$run_dir" "$client" \
          "$relay" "$relay_endpoint" "$family" "$listen_port" "$deadline_epoch" 1 \
          "$client_count" "$attempt_timeout_seconds" 1 \
          > "$run_dir/workers/$batch_id-$client.log" 2>&1 < /dev/null &
      child_pids+=("$!")
      launched_clients=$((launched_clients + 1))
      if (( launched_clients < client_count && start_stagger_seconds > 0 )); then
        sleep "$start_stagger_seconds"
      fi
    done < "$assignment_file"
    for child_pid in "${child_pids[@]}"; do
      wait "$child_pid" || child_failed=1
    done
    if ! wait_random_server_listener_idle "$selected_server" \
      "$POST_GATE_SERVER_RECOVERY_TIMEOUT_SECONDS"; then
      child_failed=1
    elif ! wait_random_server_billing_ready "$selected_server" \
      "$POST_GATE_SERVER_RECOVERY_TIMEOUT_SECONDS"; then
      child_failed=1
    fi
    read -r succeeded failed < <(awk -F '\t' -v prefix="$batch_id-" '
      NR > 1 && index($2, prefix) == 1 {
        if ($7 == 0 && $8 > 0 && $11 == "yes") succeeded++
        else failed++
      }
      END { print succeeded + 0, failed + 0 }
    ' "$run_dir/transfers.tsv")
    if (( child_failed == 0 && succeeded == client_count && failed == 0 )); then
      append_random_batch_event "$run_dir" "$(date --iso-8601=seconds)" "$batch_id" \
        "$selected_server" "$selected_server_malicious" "$mode" "$client_count" "$selected_clients" \
        "$malicious_selected" PASS "$target_pairs" \
        "$succeeded" "$failed" || return 1
    else
      append_random_batch_event "$run_dir" "$(date --iso-8601=seconds)" "$batch_id" \
        "$selected_server" "$selected_server_malicious" "$mode" "$client_count" "$selected_clients" \
        "$malicious_selected" FAIL "$target_pairs" \
        "$succeeded" "$failed" || true
      return 1
    fi
    rm -f "$eligible_file" "$selected_file" "$assignment_file"
    now_epoch=$(date +%s)
    (( now_epoch < deadline_epoch )) || return 0
    cooldown=$(( $(random_below "$pause_seconds") + 1 )) || return 1
    remaining_seconds=$((deadline_epoch - now_epoch))
    (( cooldown <= remaining_seconds )) || cooldown=$remaining_seconds
    (( cooldown == 0 )) || sleep "$cooldown"
  done
}

acquire_transfer_slot() {
  local run_dir=$1 max_inflight=$2 deadline_epoch=$3 slot slot_fd
  while (( $(date +%s) < deadline_epoch )); do
    for ((slot = 1; slot <= max_inflight; slot++)); do
      exec {slot_fd}> "$run_dir/inflight-slots/slot-$slot.lock" || return 2
      if flock -n "$slot_fd"; then
        if (( $(date +%s) >= deadline_epoch )); then
          exec {slot_fd}>&-
          return 1
        fi
        TRANSFER_SLOT_FD=$slot_fd
        return 0
      fi
      exec {slot_fd}>&-
      unset slot_fd
    done
    sleep 0.25
  done
  return 1
}

release_transfer_slot() {
  [[ -n ${TRANSFER_SLOT_FD:-} ]] || return 0
  flock -u "$TRANSFER_SLOT_FD" 2>/dev/null || true
  exec {TRANSFER_SLOT_FD}>&-
  TRANSFER_SLOT_FD=
}

random_client_worker() {
  local run_dir=$1 client=$2 relay=$3 relay_endpoint=$4 client_family=$5 listen_port=$6 deadline_epoch=$7 pause_seconds=$8 max_inflight=${9:-}
  local attempt_timeout_seconds=${10:-$DEFAULT_RANDOM_ATTEMPT_TIMEOUT_SECONDS}
  local max_attempts=${11:-0} attempt_count=0
  local failures=0 initial_delay server_line server server_relay server_endpoint server_family target_id client_ca_endpoint
  local server_lock_fd transfer_id record_file transfer_ok cooldown actual_relay server_lock_name
  local requested_mib slot_rc append_ok client_ready rearm_ok now_epoch remaining_seconds TRANSFER_SLOT_FD=
  local attempt_started_ns attempt_deadline_epoch step_timeout transfer_rc attempt_timed_out
  if [[ $relay_endpoint =~ ^[0-9]+$ ]]; then
    attempt_timeout_seconds=$pause_seconds
    max_inflight=$deadline_epoch
    pause_seconds=$listen_port
    deadline_epoch=$client_family
    listen_port=$relay_endpoint
    relay_endpoint=$relay:9000
    client_family=default
  fi
  is_positive_integer "$attempt_timeout_seconds" || return 1
  is_nonnegative_integer "$max_attempts" || return 1
  [[ $relay =~ ^relay0[1-7]$ && $relay_endpoint && $client_family =~ ^(default|ipv4|ipv6|dual)$ ]] || return 1
  [[ $(service_ip_family "$run_dir" "$client") == "$client_family" ]] || return 1
  [[ $(service_relay_endpoint "$run_dir" "$client" natclient "$relay") == "$relay_endpoint" ]] || return 1
  client_ca_endpoint=$(service_ca_endpoint "$run_dir" "$client" natclient) || return 1
  initial_delay=0
  [[ ${BNFS_RANDOM_BATCH_MEMBER:-0} == 1 ]] || initial_delay=$(random_below "$((pause_seconds + 1))") || return 1
  (( initial_delay == 0 )) || sleep "$initial_delay"

  while (( $(date +%s) < deadline_epoch )); do
    server_line=${BNFS_RANDOM_SERVER_LINE:-}
    [[ -n $server_line ]] || server_line=$(random_reachable_server_line "$run_dir" "$relay" "$client_family") || return 1
    IFS=$'\t' read -r server server_relay server_endpoint server_family target_id <<< "$server_line"
    [[ -n $server && -n $server_relay && -n $server_endpoint \
      && $server_family =~ ^(default|ipv4|ipv6|dual)$ \
      && -n $target_id ]] || return 1
    requested_mib=$(random_probe_size_mib) || return 1
    server_lock_name=$server
    [[ -z ${BNFS_RANDOM_BATCH_ID:-} ]] || server_lock_name=$server-$client
    exec {server_lock_fd}> "$run_dir/server-locks/$server_lock_name.lock"
    while ! flock -n "$server_lock_fd"; do
      if (( $(date +%s) >= deadline_epoch )); then
        exec {server_lock_fd}>&-
        return 0
      fi
      sleep 0.25
    done

    acquire_transfer_slot "$run_dir" "$max_inflight" "$deadline_epoch"
    slot_rc=$?
    if (( slot_rc != 0 )); then
      flock -u "$server_lock_fd"
      exec {server_lock_fd}>&-
      (( slot_rc == 1 )) && return 0
      return 1
    fi

    transfer_id="$(date +%s%N)-$client"
    if [[ ${BNFS_RANDOM_BATCH_ID:-} =~ ^batch-[0-9]+-[0-9]+$ ]]; then
      transfer_id=${BNFS_RANDOM_BATCH_ID}-$(date +%s%N)-$client
    fi
    record_file=$run_dir/transfer-records/$transfer_id.tsv
    attempt_started_ns=$(date +%s%N)
    attempt_deadline_epoch=$(( $(date +%s) + attempt_timeout_seconds ))
    if ! write_failed_transfer "$client" "$relay" "$server" "$transfer_id" "$record_file" 125 "$requested_mib"; then
      release_transfer_slot
      flock -u "$server_lock_fd" 2>/dev/null || true
      exec {server_lock_fd}>&-
      return 1
    fi
    transfer_ok=0
    client_ready=0
    rearm_ok=1
    attempt_timed_out=0
    stop_nat_process "$client" tunclient || true
    rm -f "$run_dir/server-fresh/$server"
    if ! step_timeout=$(deadline_step_timeout_seconds "$attempt_deadline_epoch" 70); then
      write_timed_out_transfer "$client" "$relay" "$server" "$transfer_id" \
        "$record_file" "$requested_mib" "$attempt_started_ns"
      attempt_timed_out=1
    else
      BNFS_CHAOS_NAT_CA_URL="$client_ca_endpoint" launch_tunnel_client \
        "$client" "$relay_endpoint" "$target_id" "$listen_port" random-workload
      if ! step_timeout=$(deadline_step_timeout_seconds "$attempt_deadline_epoch" 70); then
        write_timed_out_transfer "$client" "$relay" "$server" "$transfer_id" \
          "$record_file" "$requested_mib" "$attempt_started_ns"
        attempt_timed_out=1
      fi
    fi
    if (( attempt_timed_out == 0 )) \
      && wait_client_ready "$client" random-workload "$step_timeout"; then
      client_ready=1
      if step_timeout=$(deadline_step_timeout_seconds "$attempt_deadline_epoch" 5); then
        actual_relay=$(wait_client_entry_relay "$client" "$step_timeout" "$relay" 2>/dev/null || true)
      else
        actual_relay=
      fi
      if [[ -n $actual_relay ]]; then
        if random_transfer_once "$run_dir" random-workload "$server" "$client" "$actual_relay" \
          "$listen_port" "$transfer_id" "$record_file" "$requested_mib" \
          "$attempt_deadline_epoch"; then
          transfer_ok=1
        else
          transfer_rc=$?
          (( transfer_rc == 28 )) && attempt_timed_out=1
        fi
      elif (( $(date +%s) >= attempt_deadline_epoch )); then
        write_timed_out_transfer "$client" "$relay" "$server" "$transfer_id" \
          "$record_file" "$requested_mib" "$attempt_started_ns"
        attempt_timed_out=1
      else
        write_failed_transfer "$client" unknown "$server" "$transfer_id" "$record_file" 4 "$requested_mib"
      fi
    elif (( attempt_timed_out == 0 && $(date +%s) >= attempt_deadline_epoch )); then
      actual_relay=$(wait_client_entry_relay "$client" 1 "$relay" 2>/dev/null || true)
      [[ -n $actual_relay ]] || actual_relay=$relay
      write_timed_out_transfer "$client" "$actual_relay" "$server" "$transfer_id" \
        "$record_file" "$requested_mib" "$attempt_started_ns"
      attempt_timed_out=1
    elif (( attempt_timed_out == 0 )); then
      actual_relay=$(wait_client_entry_relay "$client" 2 "$relay" 2>/dev/null || true)
      [[ -n $actual_relay ]] || actual_relay=unknown
      write_failed_transfer "$client" "$actual_relay" "$server" "$transfer_id" "$record_file" 2 "$requested_mib"
    fi
    if ! stop_nat_process "$client" tunclient; then
      rearm_ok=0
    fi
    if [[ ${BNFS_RANDOM_BATCH_MEMBER:-0} != 1 ]] \
      && (( rearm_ok == 1 && attempt_timed_out == 0 )); then
      if step_timeout=$(deadline_step_timeout_seconds "$attempt_deadline_epoch" \
        "$POST_GATE_SERVER_RECOVERY_TIMEOUT_SECONDS"); then
        if ! wait_random_server_listener_idle "$server" "$step_timeout"; then
          rearm_ok=0
          (( $(date +%s) < attempt_deadline_epoch )) || attempt_timed_out=1
        fi
      else
        rearm_ok=0
        attempt_timed_out=1
      fi
    fi
    if [[ ${BNFS_RANDOM_BATCH_MEMBER:-0} != 1 ]] \
      && (( rearm_ok == 1 && attempt_timed_out == 0 )); then
      if step_timeout=$(deadline_step_timeout_seconds "$attempt_deadline_epoch" \
        "$POST_GATE_SERVER_RECOVERY_TIMEOUT_SECONDS"); then
        if ! wait_random_server_billing_ready "$server" "$step_timeout"; then
          rearm_ok=0
          (( $(date +%s) < attempt_deadline_epoch )) || attempt_timed_out=1
        fi
      else
        rearm_ok=0
        attempt_timed_out=1
      fi
    fi
    snapshot_transfer_logs "$run_dir" "$transfer_id" "$client" "$server"
    append_ok=1
    if append_transfer_record "$run_dir" "$record_file"; then
      rm -f "$record_file" || append_ok=0
    else
      append_ok=0
    fi
    release_transfer_slot
    flock -u "$server_lock_fd"
    exec {server_lock_fd}>&-
    (( append_ok == 1 )) || return 1
    (( attempt_timed_out == 0 )) || return 28
    (( rearm_ok == 1 )) || return 1

    if (( transfer_ok == 1 )); then
      failures=0
    else
      failures=$((failures + 1))
      (( failures < 3 )) || return 1
    fi
    attempt_count=$((attempt_count + 1))
    if (( max_attempts > 0 && attempt_count >= max_attempts )); then
      (( transfer_ok == 1 )) && return 0
      return 1
    fi
    now_epoch=$(date +%s)
    (( now_epoch < deadline_epoch )) || return 0
    cooldown=$(( $(random_below "$pause_seconds") + 1 )) || return 1
    remaining_seconds=$((deadline_epoch - now_epoch))
    (( cooldown <= remaining_seconds )) || cooldown=$remaining_seconds
    (( cooldown == 0 )) || sleep "$cooldown"
  done
}

RANDOM_WORKER_DRAIN_DETAIL=
drain_random_workers() {
  local attempt_timeout_seconds=${1:-$DEFAULT_RANDOM_ATTEMPT_TIMEOUT_SECONDS}
  local stop_grace_seconds=${2:-$DEFAULT_RANDOM_WORKER_STOP_TIMEOUT_SECONDS}
  local timeout_seconds
  local deadline_epoch index pid group_id alive=0 wait_failed=0 group_leaked=0
  RANDOM_WORKER_DRAIN_DETAIL=
  timeout_seconds=$(random_worker_drain_timeout_seconds \
    "$attempt_timeout_seconds" "$stop_grace_seconds") || {
    RANDOM_WORKER_DRAIN_DETAIL=random_worker_identity_invalid
    return 1
  }
  (( ${#RANDOM_WORKER_PIDS[@]} > 0 )) || return 0
  if ! random_worker_tracking_valid; then
    RANDOM_WORKER_DRAIN_DETAIL=random_worker_identity_invalid
    return 1
  fi
  deadline_epoch=$(( $(date +%s) + timeout_seconds ))
  while :; do
    alive=0
    for index in "${!RANDOM_WORKER_PIDS[@]}"; do
      pid=${RANDOM_WORKER_PIDS[$index]}
      group_id=${RANDOM_WORKER_PGIDS[$index]}
      if random_worker_group_alive "$group_id"; then
        if ! random_worker_group_identity_valid "$index"; then
          if ! random_worker_group_alive "$group_id" && ! process_is_alive "$pid"; then
            continue
          fi
          sleep 0.01
          if ! random_worker_group_identity_valid "$index"; then
            if ! random_worker_group_alive "$group_id" && ! process_is_alive "$pid"; then
              continue
            fi
            RANDOM_WORKER_DRAIN_DETAIL=random_worker_identity_invalid
            return 1
          fi
        fi
        alive=1
      elif process_is_alive "$pid"; then
        RANDOM_WORKER_DRAIN_DETAIL=random_worker_identity_invalid
        return 1
      fi
    done
    (( alive == 1 )) || break
    if (( $(date +%s) >= deadline_epoch )); then
      RANDOM_WORKER_DRAIN_DETAIL=random_worker_drain_timeout
      return 1
    fi
    sleep 0.25
  done
  for pid in "${RANDOM_WORKER_PIDS[@]}"; do
    wait "$pid" 2>/dev/null || wait_failed=1
  done
  for group_id in "${RANDOM_WORKER_PGIDS[@]}"; do
    random_worker_group_alive "$group_id" && group_leaked=1
  done
  if (( group_leaked == 1 )); then
    RANDOM_WORKER_DRAIN_DETAIL=random_worker_group_leaked
    return 1
  fi
  clear_random_worker_tracking
  if (( wait_failed == 1 )); then
    RANDOM_WORKER_DRAIN_DETAIL=random_client_worker_failed
    return 1
  fi
}

stop_random_workers() {
  local pid group_id deadline_epoch alive=0 stop_failed=0
  (( ${#RANDOM_WORKER_PIDS[@]} > 0 )) || return 0
  if ! random_worker_tracking_valid; then
    RANDOM_WORKER_DRAIN_DETAIL=random_worker_identity_invalid
    return 1
  fi
  if ! signal_random_worker_groups TERM; then
    RANDOM_WORKER_DRAIN_DETAIL=random_worker_identity_invalid
    return 1
  fi
  deadline_epoch=$(( $(date +%s) + DEFAULT_RANDOM_WORKER_STOP_TIMEOUT_SECONDS ))
  while :; do
    alive=0
    for group_id in "${RANDOM_WORKER_PGIDS[@]}"; do
      if random_worker_group_alive "$group_id"; then
        alive=1
        break
      fi
    done
    (( alive == 1 && $(date +%s) < deadline_epoch )) || break
    sleep 0.1
  done
  if (( alive == 1 )); then
    if ! signal_random_worker_groups KILL; then
      RANDOM_WORKER_DRAIN_DETAIL=random_worker_identity_invalid
      return 1
    fi
  fi
  for pid in "${RANDOM_WORKER_PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  for _ in $(seq 1 40); do
    alive=0
    for group_id in "${RANDOM_WORKER_PGIDS[@]}"; do
      if random_worker_group_alive "$group_id"; then
        alive=1
        break
      fi
    done
    (( alive == 0 )) && break
    sleep 0.05
  done
  (( alive == 0 )) || stop_failed=1
  if (( stop_failed == 1 )); then
    RANDOM_WORKER_DRAIN_DETAIL=random_worker_group_stop_failed
    return 1
  fi
  clear_random_worker_tracking
}

cleanup_project() {
  local compose_file=$1 project=$2
  if [[ -f $compose_file ]]; then
    docker compose --project-name "$project" --file "$compose_file" down --remove-orphans --timeout 3 >/dev/null 2>&1 || true
  fi
  local ids networks
  ids=$(docker ps -aq --filter "label=com.docker.compose.project=$project")
  [[ -z $ids ]] || docker rm -f $ids >/dev/null 2>&1 || true
  networks=$(docker network ls -q --filter "label=com.docker.compose.project=$project")
  [[ -z $networks ]] || docker network rm $networks >/dev/null 2>&1 || true
}

PROJECT_REMAINING_CONTAINERS=unknown
PROJECT_REMAINING_NETWORKS=unknown
inspect_compose_project_residuals() {
  local project=$1 container_ids= network_ids= result=0
  PROJECT_REMAINING_CONTAINERS=unknown
  PROJECT_REMAINING_NETWORKS=unknown
  [[ $project =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] || return 1
  if container_ids=$(docker ps -aq --filter "label=com.docker.compose.project=$project"); then
    PROJECT_REMAINING_CONTAINERS=$(awk 'NF { count++ } END { print count + 0 }' <<< "$container_ids")
  else
    result=1
  fi
  if network_ids=$(docker network ls -q --filter "label=com.docker.compose.project=$project"); then
    PROJECT_REMAINING_NETWORKS=$(awk 'NF { count++ } END { print count + 0 }' <<< "$network_ids")
  else
    result=1
  fi
  return "$result"
}

terminal_result_after_cleanup() {
  local outcome=$1 detail=$2 inspection_status=$3
  local remaining_containers=$4 remaining_networks=$5
  if [[ $outcome == COMPLETED ]]; then
    if [[ $inspection_status != ok || ! $remaining_containers =~ ^[0-9]+$ \
      || ! $remaining_networks =~ ^[0-9]+$ ]]; then
      outcome=FAILED
      detail=project_cleanup_inspection_failed
    elif (( remaining_containers != 0 || remaining_networks != 0 )); then
      outcome=FAILED
      detail=project_cleanup_incomplete
    fi
  fi
  printf '%s\t%s\n' "$outcome" "$detail"
}

finalize_run_terminal_result() {
  local run_dir=$1 compose_file=$2 project=$3 dashboard_pid=$4 dashboard_start=$5
  local dashboard_host=$6 dashboard_port=$7 dashboard_probe_file=$8
  local outcome=$9 detail=${10} inspection_status=ok
  if [[ $outcome == COMPLETED ]] \
    && ! verify_dashboard_finalization "$dashboard_pid" "$dashboard_start" \
      "$dashboard_host" "$dashboard_port" "$dashboard_probe_file" RUNNING; then
    outcome=FAILED
    detail=${DASHBOARD_FINALIZATION_DETAIL:-dashboard_status_api_invalid}
  fi
  cleanup_project "$compose_file" "$project" || true
  if ! inspect_compose_project_residuals "$project"; then
    inspection_status=failed
  fi
  IFS=$'\t' read -r outcome detail < <(terminal_result_after_cleanup "$outcome" "$detail" \
    "$inspection_status" "$PROJECT_REMAINING_CONTAINERS" "$PROJECT_REMAINING_NETWORKS")
  publish_terminal_result "$run_dir" "$outcome" "$detail" \
    "$PROJECT_REMAINING_CONTAINERS" "$PROJECT_REMAINING_NETWORKS" || return 1
  [[ $outcome == COMPLETED ]]
}

run_internal() {
  local run_dir=$1
  local scenario duration cpu_limit memory_limit disk_limit sample_seconds probe_seconds max_inflight workload_limit_mibps per_transfer_limit_mibps dashboard_host dashboard_port ca_port ca_web_port billing_adversary_mode validation_mode ip_family_coverage ip_family_plan_path random_attempt_timeout random_worker_drain_timeout enable_container_adversaries project
  local reconnect_gate_port=$DEFAULT_RECONNECT_GATE_PORT reconnect_gate_token reconnect_gate_pid= reconnect_gate_start=
  source "$run_dir/metadata.env"
  scenario=${scenario:?}
  duration=${duration_seconds:?}
  cpu_limit=${cpu_limit_pct:?}
  memory_limit=${memory_limit_pct:?}
  disk_limit=${disk_limit_pct:?}
  sample_seconds=${sample_seconds:?}
  probe_seconds=${probe_seconds:?}
  max_inflight=${max_inflight:?}
  workload_limit_mibps=${workload_limit_mibps:?}
  per_transfer_limit_mibps=${per_transfer_limit_mibps:?}
  dashboard_host=${dashboard_host:?}
  dashboard_port=${dashboard_port:?}
  ca_port=${ca_port:?}
  ca_web_port=${ca_web_port:?}
  billing_adversary_mode=${billing_adversary_mode:-$DEFAULT_BILLING_ADVERSARY_MODE}
  validation_mode=${validation_mode:-$DEFAULT_VALIDATION_MODE}
  ip_family_coverage=${ip_family_coverage:-$DEFAULT_IP_FAMILY_COVERAGE}
  ip_family_plan_path=${ip_family_plan_file:-$run_dir/ip-family-plan.tsv}
  random_attempt_timeout=${random_attempt_timeout_seconds:-}
  random_worker_drain_timeout=${random_worker_drain_timeout_seconds:-}
  [[ $(validation_mode_attempt_timeout_seconds "$validation_mode" 2>/dev/null || true) \
      == "$random_attempt_timeout" \
    && $(random_worker_drain_timeout_seconds "$random_attempt_timeout" 2>/dev/null || true) \
      == "$random_worker_drain_timeout" ]] || return 1
  is_ip_family_coverage_mode "$ip_family_coverage" || return 1
  if [[ $ip_family_coverage == random ]]; then
    [[ $ip_family_plan_path == "$run_dir/ip-family-plan.tsv" ]] \
      && validate_ip_family_plan "$ip_family_plan_path" || return 1
  else
    [[ ! -e $ip_family_plan_path ]] || return 1
  fi
  enable_container_adversaries=1
  [[ $billing_adversary_mode != off ]] || enable_container_adversaries=0
  project=${compose_project:?}

  local runner_pid=$$ runner_start compose_file=$run_dir/runtime/compose.json
  local worker_script worker_support_root
  runner_start=$(awk '{print $22}' "/proc/$runner_pid/stat")
  printf '%s\n' "$runner_pid" > "$run_dir/runner.pid"
  printf '%s\n' "$runner_start" > "$run_dir/runner.starttime"
  printf 'timestamp\tlabel\trc\tbytes\tseconds\tsha256_ok\tclient\n' > "$run_dir/probes.tsv"
  printf 'timestamp\tlabel\trequested_mib\trc\tbytes\tseconds\tmib_per_second\tsha256_ok\tclient\texpected_sha\tactual_sha\n' \
    > "$run_dir/large-probes.tsv"
  printf 'timestamp\ttransfer_id\tclient\tingress_relay\tserver\trequested_mib\trc\tbytes\tseconds\tmib_per_second\tsha256_ok\texpected_sha\tactual_sha\n' \
    > "$run_dir/transfers.tsv"
  printf 'timestamp\tbatch_id\tselected_server\tserver_pool_includes_malicious\tserver_malicious\tmode\trequested_clients\tselected_clients\tclient_pool_includes_malicious\tmalicious_client_selected\tstatus\ttarget_pairs\tsucceeded\tfailed\n' \
    > "$run_dir/random-batches.tsv"
  printf 'timestamp\tevent\tconsecutive_failures\tduration_seconds\tdetail\tservices\tepoch\n' \
    > "$run_dir/core-health-events.tsv"
  local stop_requested=0 guard_pid= guard_start= dashboard_pid= dashboard_start= failure_watcher_pid= billing_adversary_pid= mixed_path_pid= outcome=FAILED detail=initializing
  local failure_watcher_degraded_since=0 failure_watcher_lag_since=0
  local core_health_failed_since=0 core_health_consecutive_failures=0 core_health_next_probe=0 core_health_now=0
  local dashboard_status_failed_since=0 dashboard_status_consecutive_failures=0
  local dashboard_status_next_probe=0 dashboard_status_probe_file=$run_dir/dashboard-status-probe.tmp

  trap 'stop_requested=1' INT TERM HUP
  set_phase "$run_dir" BUILDING
  if ! BNFS_CHAOS_RUNTIME_DIR="$run_dir/build-runtime" BNFS_CHAOS_COMPOSE_PROJECT="$project-build" \
    BNFS_CHAOS_ENABLE_CA=1 BNFS_CHAOS_CA_HOST_PORT="$ca_port" \
    bash "$ROOT_DIR/scripts/local-deploy-test.sh" --build-only > "$run_dir/build.log" 2>&1; then
    printf 'outcome=FAILED\ndetail=build_failed\n' > "$run_dir/status.env"
    set_phase "$run_dir" FAILED
    return 1
  fi

  mkdir -p "$run_dir/runtime"
  worker_script=$(prepare_worker_runtime_snapshot "$run_dir") || {
    printf 'outcome=FAILED\ndetail=worker_runtime_snapshot_failed\n' > "$run_dir/status.env"
    set_phase "$run_dir" FAILED
    return 1
  }
  worker_support_root=$(dirname "$(dirname "$worker_script")")
  STABILITY_WORKER_SCRIPT=$worker_script
  export BNFS_STABILITY_ROOT_DIR="$ROOT_DIR"
  export BNFS_STABILITY_SUPPORT_ROOT="$worker_support_root"
  export BNFS_STABILITY_WORKER_SCRIPT="$worker_script"
  export ROOT_DIR
  export RUNTIME_DIR=$run_dir/runtime
  export PRIVATE_RUNTIME_DIR=$RUNTIME_DIR/.private
  export COMPOSE_FILE=$compose_file
  export COMPOSE_PROJECT=$project
  export BNFS_CHAOS_IMAGE=${BNFS_CHAOS_IMAGE:-bnfs-local-chaos:latest}
  if [[ -z ${BNFS_CHAOS_CA_ADMIN_TOKEN_FILE:-} && -f $SOAK_HOME/secrets/ca-admin.token ]]; then
    export BNFS_CHAOS_CA_ADMIN_TOKEN_FILE=$SOAK_HOME/secrets/ca-admin.token
  fi
  reconnect_gate_token=$(od -An -N32 -tx1 /dev/urandom 2>/dev/null | tr -d '[:space:]') || return 1
  [[ $reconnect_gate_token =~ ^[[:xdigit:]]{64}$ ]] || return 1
  printf '%s\n' "$reconnect_gate_token" > "$run_dir/reconnect-gate.token"
  chmod 600 "$run_dir/reconnect-gate.token"
  BNFS_CHAOS_ENABLE_CA=1 BNFS_CHAOS_ENABLE_ADVERSARIES="$enable_container_adversaries" BNFS_CHAOS_CA_HOST_PORT="$ca_port" \
    BNFS_CHAOS_CA_WEB_HOST_PORT="$ca_web_port" \
    BNFS_CHAOS_IP_FAMILY_PLAN_FILE="$ip_family_plan_path" \
    BNFS_CHAOS_RECONNECT_GATE_URL="http://host.docker.internal:$reconnect_gate_port" \
    BNFS_CHAOS_RECONNECT_GATE_TOKEN="$reconnect_gate_token" \
    node "$ROOT_DIR/test/local-chaos/generate-compose.mjs" "$RUNTIME_DIR" > "$COMPOSE_FILE"
  source "$ROOT_DIR/test/local-chaos/lib.sh"

	if ! free_dashboard_port "$dashboard_port"; then
		printf 'outcome=FAILED\ndetail=dashboard_port_busy\n' > "$run_dir/status.env"
    set_phase "$run_dir" FAILED
    return 1
  fi
  if ! free_reconnect_gate_port "$reconnect_gate_port"; then
    printf 'outcome=FAILED\ndetail=reconnect_gate_port_busy\n' > "$run_dir/status.env"
    set_phase "$run_dir" FAILED
    return 1
  fi
  if ss -lntH "sport = :$ca_port" | grep -q .; then
    printf 'outcome=FAILED\ndetail=ca_port_busy\n' > "$run_dir/status.env"
    set_phase "$run_dir" FAILED
    return 1
  fi
  if ss -lntH "sport = :$ca_web_port" | grep -q .; then
    printf 'outcome=FAILED\ndetail=ca_web_port_busy\n' > "$run_dir/status.env"
    set_phase "$run_dir" FAILED
    return 1
  fi

  export BNFS_CHAOS_CA_HOST_PORT=$ca_port

  env RUN_DIR="$run_dir" WATCH_PID="$runner_pid" \
    node "$ROOT_DIR/test/local-chaos/monitor/failure-watcher.mjs" \
    > "$run_dir/failure-watcher.log" 2>&1 < /dev/null &
  failure_watcher_pid=$!
  printf '%s\n' "$failure_watcher_pid" > "$run_dir/failure-watcher.pid"
  printf '%s\n' "$(awk '{print $22}' "/proc/$failure_watcher_pid/stat")" > "$run_dir/failure-watcher.starttime"
  if ! wait_failure_watcher_ready "$run_dir" "$failure_watcher_pid"; then
    stop_failure_watcher "$failure_watcher_pid"
    printf 'outcome=FAILED\ndetail=failure_watcher_start_failed\n' > "$run_dir/status.env"
    set_phase "$run_dir" FAILED
    return 1
  fi

  setsid env BNFS_RECONNECT_GATE_TOKEN="$reconnect_gate_token" \
    node "$ROOT_DIR/test/local-chaos/reconnect-gate.mjs" \
      --listen "0.0.0.0:$reconnect_gate_port" \
      > "$run_dir/reconnect-gate.log" 2>&1 < /dev/null &
  reconnect_gate_pid=$!
  reconnect_gate_start=$(process_starttime "$reconnect_gate_pid" 2>/dev/null || true)
  printf '%s\n' "$reconnect_gate_pid" > "$run_dir/reconnect-gate.pid"
  printf '%s\n' "$reconnect_gate_start" > "$run_dir/reconnect-gate.starttime"
  if ! wait_file_pattern "$run_dir/reconnect-gate.log" 'RECONNECT_GATE_LISTEN' 10 \
    || ! pid_matches "$reconnect_gate_pid" "$reconnect_gate_start" 'reconnect-gate.mjs' \
    || ! wait_reconnect_gate_health "$reconnect_gate_port" "$reconnect_gate_token"; then
    stop_reconnect_gate_process "$run_dir" || true
    stop_failure_watcher "$failure_watcher_pid"
    printf 'outcome=FAILED\ndetail=reconnect_gate_start_failed\n' > "$run_dir/status.env"
    set_phase "$run_dir" FAILED
    return 1
  fi

  # The Dashboard owns an independent session so terminal evidence remains
  # available after the runner and Compose project have stopped. Explicit stop
  # and the next start reclaim it through the recorded PID identity.
  setsid env HOST="$dashboard_host" PORT="$dashboard_port" RUN_DIR="$run_dir" \
    COMPOSE_PROJECT="$project" COMPOSE_FILE="$compose_file" CA_PORT="$ca_port" CA_WEB_PORT="$ca_web_port" \
    BNFS_RECONNECT_GATE_MONITOR_URL="http://127.0.0.1:$reconnect_gate_port" \
    BNFS_RECONNECT_GATE_TOKEN="$reconnect_gate_token" \
    node "$ROOT_DIR/test/local-chaos/monitor/server.mjs" > "$run_dir/dashboard.log" 2>&1 < /dev/null &
  dashboard_pid=$!
  dashboard_start=$(process_starttime "$dashboard_pid" 2>/dev/null || true)
  printf '%s\n' "$dashboard_pid" > "$run_dir/dashboard.pid"
  printf '%s\n' "$dashboard_start" > "$run_dir/dashboard.starttime"
  if ! wait_file_pattern "$run_dir/dashboard.log" 'BNFS stability dashboard listening' 10 \
    || ! pid_matches "$dashboard_pid" "$dashboard_start" 'monitor/server.mjs' \
    || ! wait_dashboard_health "$dashboard_host" "$dashboard_port" \
    || ! wait_dashboard_status "$dashboard_host" "$dashboard_port" "$dashboard_status_probe_file"; then
    stop_dashboard_process "$run_dir" || true
    wait "$dashboard_pid" 2>/dev/null || true
    stop_reconnect_gate_process "$run_dir" || true
    stop_failure_watcher "$failure_watcher_pid"
    printf 'outcome=FAILED\ndetail=dashboard_start_failed\n' > "$run_dir/status.env"
    set_phase "$run_dir" FAILED
    return 1
  fi

  set_phase "$run_dir" STARTING_CLUSTER
  if ! topology_reset || ! wait_service_health ca 45; then
    detail=cluster_start_failed
  else
    local billing_adversary_ready=1 billing_adversary_allow_violations=0
    [[ $billing_adversary_mode == report ]] && billing_adversary_allow_violations=1
    setsid "$ROOT_DIR/test/local-chaos/resource-guard.sh" \
      --compose-file "$compose_file" --project "$project" --output-dir "$run_dir" \
      --watch-pid "$runner_pid" --watch-pgid "$runner_pid" --duration-seconds "$((duration + 900))" \
      --interval-seconds "$sample_seconds" --cpu-limit "$cpu_limit" \
      --memory-limit "$memory_limit" --disk-limit "$disk_limit" \
      > "$run_dir/resource-guard.log" 2>&1 &
    guard_pid=$!
    guard_start=$(process_starttime "$guard_pid" 2>/dev/null || true)
    printf '%s\n' "$guard_pid" > "$run_dir/resource-guard.pid"
    printf '%s\n' "$guard_start" > "$run_dir/resource-guard.starttime"

    if ! wait_resource_guard_ready "$run_dir" "$guard_pid" "$guard_start" "$sample_seconds" \
      "$((duration + 900))" "$cpu_limit" "$memory_limit" "$disk_limit"; then
      detail=${RESOURCE_GUARD_DETAIL:-resource_guard_start_failed}
    else
      set_phase "$run_dir" CONFIGURING_PROFILE
      if ! write_core_identity "$run_dir/core-identity.pre-gate.tsv"; then
        detail=core_identity_capture_failed
      else
        capture_project_evidence "$run_dir" initial
        if prepare_stability_profile "$run_dir" "$scenario" "$ca_port" "$max_inflight" \
          "$per_transfer_limit_mibps" "$workload_limit_mibps"; then
          if [[ -s $run_dir/resource-termination.tsv ]] \
            && (( $(wc -l < "$run_dir/resource-termination.tsv") > 1 )); then
            outcome=RESOURCE_LIMIT
            detail=resource_threshold_exceeded
          elif ! inspect_resource_guard "$run_dir" "$guard_pid" "$guard_start" "$sample_seconds" \
            "$((duration + 900))" "$cpu_limit" "$memory_limit" "$disk_limit" "$(date +%s)"; then
            outcome=FAILED
            detail=$RESOURCE_GUARD_DETAIL
          elif (( stop_requested == 1 )); then
            outcome=STOPPED
            detail=signal_requested_during_profile
          else
            set_phase "$run_dir" VERIFYING_BILLING
            if ! run_billing_production_gate "$run_dir"; then
              detail=$(read_billing_production_gate_detail \
                "$run_dir/billing-production-gate.status" 2>/dev/null || true)
              [[ -n $detail ]] || detail=billing_production_gate_failed
            elif ! inspect_resource_guard "$run_dir" "$guard_pid" "$guard_start" "$sample_seconds" \
              "$((duration + 900))" "$cpu_limit" "$memory_limit" "$disk_limit" "$(date +%s)"; then
              detail=$RESOURCE_GUARD_DETAIL
            elif ! recover_random_server_pool_after_relay_restart \
              "$run_dir" "$REAL_BILLING_GATE_RELAY"; then
              detail=post_gate_server_pool_recovery_failed
            elif ! verify_ip_family_coverage "$run_dir"; then
              detail=ip_family_coverage_gate_failed
            elif ! inspect_resource_guard "$run_dir" "$guard_pid" "$guard_start" "$sample_seconds" \
              "$((duration + 900))" "$cpu_limit" "$memory_limit" "$disk_limit" "$(date +%s)"; then
              detail=$RESOURCE_GUARD_DETAIL
            elif ! core_services_healthy; then
              detail=billing_production_gate_core_unhealthy
            elif ! write_core_identity "$run_dir/core-identity.tsv"; then
              detail=core_identity_recapture_failed
            else
              if [[ $billing_adversary_mode != off ]]; then
                if ! provision_container_adversaries "$run_dir" "$ca_port"; then
                  billing_adversary_ready=0
                  detail=container_adversary_provision_failed
                else
                  billing_adversary_pid=$(start_billing_adversary \
                    "$run_dir" "$ca_port" "$runner_pid" "$billing_adversary_mode" 2>/dev/null || true)
                  if [[ ! $billing_adversary_pid =~ ^[1-9][0-9]*$ ]]; then
                    billing_adversary_ready=0
                    detail=billing_adversary_start_failed
                  elif ! inspect_billing_adversary "$run_dir" "$billing_adversary_pid" \
                    "$(date +%s)" "$billing_adversary_allow_violations"; then
                    billing_adversary_ready=0
                    detail=$BILLING_ADVERSARY_DETAIL
                  else
                    mixed_path_pid=$(start_mixed_adversary_path \
                      "$run_dir" "$ca_port" "$runner_pid" 2>/dev/null || true)
                    if [[ ! $mixed_path_pid =~ ^[1-9][0-9]*$ ]]; then
                      billing_adversary_ready=0
                      detail=mixed_path_start_failed
                    elif ! inspect_mixed_adversary_path \
                      "$run_dir" "$mixed_path_pid" "$(date +%s)" 0; then
                      billing_adversary_ready=0
                      detail=$MIXED_PATH_DETAIL
                    fi
                  fi
                fi
              fi
              if (( billing_adversary_ready == 1 )) \
                && ! inspect_resource_guard "$run_dir" "$guard_pid" "$guard_start" "$sample_seconds" \
                  "$((duration + 900))" "$cpu_limit" "$memory_limit" "$disk_limit" "$(date +%s)"; then
                billing_adversary_ready=0
                detail=$RESOURCE_GUARD_DETAIL
              fi
              if (( billing_adversary_ready == 1 )); then
                local started_epoch deadline_epoch worker_failed=0 pid
                local worker_start worker_group worker_index worker_token
                local random_workers_ok=1 random_workers_quiesced=0
                local random_worker_terminalization_failed=0 random_worker_failure_detail=
                started_epoch=$(date +%s)
                deadline_epoch=$((started_epoch + duration))
                printf 'started_epoch=%s\ndeadline_epoch=%s\n' \
                  "$started_epoch" "$deadline_epoch" >> "$run_dir/metadata.env"
                set_phase "$run_dir" RUNNING
                outcome=COMPLETED
                detail=duration_complete
                clear_random_worker_tracking
                rm -f "$run_dir/worker-pids.closed"
                printf 'client\tpid\tstarttime\tpgid\ttoken\n' > "$run_dir/worker-pids.tsv"
                local worker_client=batch-scheduler
                worker_token=$(create_random_worker_token 2>/dev/null || true)
                if [[ ! $worker_token =~ ^[[:xdigit:]]{32}$ ]]; then
                  worker_failed=1
                else
                  env BNFS_RANDOM_WORKER_TOKEN="$worker_token" \
                    BNFS_STABILITY_ROOT_DIR="$ROOT_DIR" \
                    BNFS_STABILITY_SUPPORT_ROOT="$worker_support_root" \
                    BNFS_STABILITY_WORKER_SCRIPT="$worker_script" \
                    setsid bash "$worker_script" _registered_worker \
                    "$run_dir" "$worker_client" "$runner_pid" "$runner_start" \
                    "$deadline_epoch" "$probe_seconds" "$max_inflight" \
                    "$random_attempt_timeout" "$workload_limit_mibps" \
                    > "$run_dir/workers/$worker_client.log" 2>&1 &
                  pid=$!
                  if track_random_worker "$pid" "$worker_token"; then
                    worker_index=$(( ${#RANDOM_WORKER_PIDS[@]} - 1 ))
                    worker_start=${RANDOM_WORKER_STARTTIMES[$worker_index]}
                    worker_group=${RANDOM_WORKER_PGIDS[$worker_index]}
                    if ! wait_random_worker_registered "$run_dir/worker-pids.tsv" \
                      "$worker_client" "$pid" "$worker_start" "$worker_group" "$worker_token"; then
                      worker_failed=1
                    fi
                  else
                    kill -TERM "$pid" 2>/dev/null || true
                    wait "$pid" 2>/dev/null || true
                    worker_failed=1
                  fi
                fi
                if (( ${#RANDOM_WORKER_PIDS[@]} != 1 || worker_failed == 1 )); then
                  outcome=FAILED
                  detail=random_worker_start_failed
                else
                  while (( $(date +%s) < deadline_epoch )); do
                    if [[ -s $run_dir/resource-termination.tsv ]] \
                      && (( $(wc -l < "$run_dir/resource-termination.tsv") > 1 )); then
                      outcome=RESOURCE_LIMIT
                      detail=resource_threshold_exceeded
                      break
                    fi
                    if ! inspect_resource_guard "$run_dir" "$guard_pid" "$guard_start" "$sample_seconds" \
                      "$((duration + 900))" "$cpu_limit" "$memory_limit" "$disk_limit" "$(date +%s)"; then
                      outcome=FAILED
                      detail=$RESOURCE_GUARD_DETAIL
                      break
                    fi
                    if (( stop_requested == 1 )); then
                      outcome=STOPPED
                      detail=signal_requested
                      break
                    fi
                    if ! inspect_failure_watcher "$run_dir" "$failure_watcher_pid" "$(date +%s)" \
                      "$failure_watcher_degraded_since" 0 "$failure_watcher_lag_since"; then
                      outcome=FAILED
                      detail=$FAILURE_WATCHER_DETAIL
                      break
                    fi
                    failure_watcher_degraded_since=$FAILURE_WATCHER_DEGRADED_SINCE
                    failure_watcher_lag_since=$FAILURE_WATCHER_LAG_SINCE
                    if [[ $billing_adversary_mode != off ]] \
                      && ! inspect_billing_adversary "$run_dir" "$billing_adversary_pid" \
                        "$(date +%s)" "$billing_adversary_allow_violations"; then
                      outcome=FAILED
                      detail=$BILLING_ADVERSARY_DETAIL
                      break
                    fi
                    if [[ $billing_adversary_mode != off ]] \
                      && ! inspect_mixed_adversary_path \
                        "$run_dir" "$mixed_path_pid" "$(date +%s)" 0; then
                      outcome=FAILED
                      detail=$MIXED_PATH_DETAIL
                      break
                    fi
                    if ! pid_matches "$dashboard_pid" "$dashboard_start" 'monitor/server.mjs'; then
                      wait "$dashboard_pid" 2>/dev/null || true
                      outcome=FAILED
                      detail=dashboard_exited
                      break
                    fi
                    local dashboard_status_now
                    dashboard_status_now=$(date +%s)
                    if (( dashboard_status_now >= dashboard_status_next_probe )); then
                      dashboard_status_next_probe=$((dashboard_status_now \
                        + DEFAULT_DASHBOARD_STATUS_PROBE_SECONDS))
                      if probe_dashboard_status \
                        "$dashboard_host" "$dashboard_port" "$dashboard_status_probe_file"; then
                        dashboard_status_failed_since=0
                        dashboard_status_consecutive_failures=0
                      else
                        dashboard_status_consecutive_failures=$((dashboard_status_consecutive_failures + 1))
                        if (( dashboard_status_failed_since == 0 )); then
                          dashboard_status_failed_since=$dashboard_status_now
                        fi
                        if dashboard_status_failure_is_fatal "$dashboard_status_now" \
                          "$dashboard_status_failed_since" "$dashboard_status_consecutive_failures"; then
                          outcome=FAILED
                          detail=${DASHBOARD_STATUS_PROBE_DETAIL:-dashboard_status_api_invalid}
                          break
                        fi
                      fi
                    fi
                    core_health_now=$(date +%s)
                    if (( core_health_now >= core_health_next_probe )); then
                      core_health_next_probe=$((core_health_now + DEFAULT_CORE_HEALTH_PROBE_SECONDS))
                      if core_services_healthy "$run_dir/core-health-latest.tsv"; then
                        if ! core_services_snapshot_unchanged "$CORE_HEALTH_SNAPSHOT" \
                          "$run_dir/core-identity.tsv"; then
                          outcome=FAILED
                          detail=core_service_recreated_or_restarted
                          CORE_HEALTH_DETAIL=$CORE_IDENTITY_DETAIL
                          record_core_health_event "$run_dir" identity_changed \
                            "$core_health_consecutive_failures" "$core_health_failed_since"
                          break
                        fi
                        if (( core_health_failed_since > 0 )); then
                          record_core_health_event "$run_dir" recovered \
                            "$core_health_consecutive_failures" "$core_health_failed_since"
                          core_health_failed_since=0
                          core_health_consecutive_failures=0
                        fi
                      else
                        if [[ -n $CORE_HEALTH_SNAPSHOT ]] \
                          && ! core_services_snapshot_unchanged "$CORE_HEALTH_SNAPSHOT" \
                            "$run_dir/core-identity.tsv"; then
                          outcome=FAILED
                          detail=core_service_recreated_or_restarted
                          CORE_HEALTH_DETAIL=$CORE_IDENTITY_DETAIL
                          record_core_health_event "$run_dir" identity_changed \
                            "$core_health_consecutive_failures" "$core_health_failed_since"
                          break
                        fi
                        (( core_health_consecutive_failures += 1 ))
                        if (( core_health_failed_since == 0 )); then
                          core_health_failed_since=$core_health_now
                        fi
                        record_core_health_event "$run_dir" degraded \
                          "$core_health_consecutive_failures" "$core_health_failed_since"
                        if core_health_failure_is_fatal "$core_health_now" \
                          "$core_health_failed_since" "$core_health_consecutive_failures"; then
                          outcome=FAILED
                          detail=core_service_unhealthy
                          record_core_health_event "$run_dir" terminal \
                            "$core_health_consecutive_failures" "$core_health_failed_since"
                          break
                        fi
                      fi
                    fi
                    worker_failed=0
                    for worker_index in "${!RANDOM_WORKER_PIDS[@]}"; do
                      pid=${RANDOM_WORKER_PIDS[$worker_index]}
                      if ! random_worker_identity_alive "$worker_index"; then
                        if (( $(date +%s) < deadline_epoch )); then
                          if process_is_alive "$pid"; then
                            detail=random_worker_identity_invalid
                          else
                            wait "$pid" 2>/dev/null || true
                            detail=random_client_worker_failed
                          fi
                          worker_failed=1
                        fi
                        break
                      fi
                    done
                    if (( worker_failed == 1 )); then
                      if (( $(date +%s) < deadline_epoch )); then
                        outcome=FAILED
                      fi
                      break
                    fi
                    sleep 1
                  done
                fi
                if [[ $outcome == COMPLETED ]]; then
                  if drain_random_workers "$random_attempt_timeout"; then
                    random_workers_quiesced=1
                  else
                    random_workers_ok=0
                    random_worker_failure_detail=$RANDOM_WORKER_DRAIN_DETAIL
                    if stop_random_workers; then
                      random_workers_quiesced=1
                    elif [[ -n $RANDOM_WORKER_DRAIN_DETAIL ]]; then
                      random_worker_failure_detail=$RANDOM_WORKER_DRAIN_DETAIL
                      random_worker_terminalization_failed=1
                    fi
                  fi
                else
                  if stop_random_workers; then
                    random_workers_quiesced=1
                  else
                    random_workers_ok=0
                    random_worker_failure_detail=${RANDOM_WORKER_DRAIN_DETAIL:-random_worker_group_stop_failed}
                    random_worker_terminalization_failed=1
                  fi
                fi
                if (( random_workers_quiesced == 1 )); then
                  if ! finalize_random_worker_evidence "$run_dir"; then
                    random_worker_failure_detail=${RANDOM_WORKER_EVIDENCE_DETAIL:-random_transfer_reconciliation_failed}
                    random_worker_terminalization_failed=1
                  fi
                else
                  random_worker_terminalization_failed=1
                fi
                if (( random_worker_terminalization_failed == 1 )); then
                  outcome=FAILED
                  detail=${random_worker_failure_detail:-random_worker_terminalization_failed}
                fi
                if [[ $outcome == COMPLETED ]]; then
                  if [[ -s $run_dir/resource-termination.tsv ]] \
                    && (( $(wc -l < "$run_dir/resource-termination.tsv") > 1 )); then
                    outcome=RESOURCE_LIMIT
                    detail=resource_threshold_exceeded
                  elif ! inspect_resource_guard "$run_dir" "$guard_pid" "$guard_start" "$sample_seconds" \
                    "$((duration + 900))" "$cpu_limit" "$memory_limit" "$disk_limit" "$(date +%s)"; then
                    outcome=FAILED
                    detail=$RESOURCE_GUARD_DETAIL
                  elif (( random_workers_ok == 0 )); then
                    outcome=FAILED
                    detail=${random_worker_failure_detail:-random_client_worker_failed}
                  elif ! wait_failure_watcher_caught_up "$run_dir" "$failure_watcher_pid" \
                    "$DEFAULT_FAILURE_WATCHER_SETTLE_TIMEOUT_SECONDS" \
                    "$failure_watcher_degraded_since"; then
                    outcome=FAILED
                    detail=$FAILURE_WATCHER_DETAIL
                  elif ! wait_core_services_healthy "$run_dir" "$run_dir/core-identity.tsv"; then
                    outcome=FAILED
                    detail=core_service_unhealthy
                    [[ -n $CORE_IDENTITY_DETAIL ]] && detail=core_service_recreated_or_restarted
                  elif ! validate_random_workload_coverage "$run_dir" "$scenario" "$validation_mode"; then
                    outcome=FAILED
                    detail=random_workload_coverage_failed
                  elif ! validate_ip_family_coverage "$run_dir"; then
                    outcome=FAILED
                    detail=ip_family_coverage_gate_failed
                  elif [[ $billing_adversary_mode != off ]] \
                    && ! drain_mixed_adversary_path "$run_dir" "$mixed_path_pid" 90; then
                    outcome=FAILED
                    detail=$MIXED_PATH_DETAIL
                  fi
                fi
              fi
            fi
          fi
        else
          detail=${PROFILE_SETUP_DETAIL:-profile_setup_failed}
        fi
      fi
    fi
  fi

  if ! stop_mixed_adversary_path "$mixed_path_pid"; then
    outcome=FAILED
    detail=mixed_path_stop_timeout
  fi
  if ! stop_billing_adversary "$billing_adversary_pid"; then
    outcome=FAILED
    detail=billing_adversary_stop_timeout
  fi
  if [[ $outcome == COMPLETED && $billing_adversary_mode != off ]] \
    && ! inspect_billing_adversary_final "$run_dir" "$(date +%s)" \
      "$billing_adversary_allow_violations"; then
    outcome=FAILED
    detail=$BILLING_ADVERSARY_DETAIL
  fi
  capture_reconnect_gate_snapshot "$run_dir" "$reconnect_gate_port" "$reconnect_gate_token" || true
  if ! stop_reconnect_gate_process "$run_dir"; then
    outcome=FAILED
    detail=reconnect_gate_stop_failed
  fi
  stop_failure_watcher "$failure_watcher_pid"
  capture_project_evidence "$run_dir" final
  if [[ -n $guard_pid ]]; then
    if [[ $outcome == COMPLETED ]] \
      && ! inspect_resource_guard "$run_dir" "$guard_pid" "$guard_start" "$sample_seconds" \
        "$((duration + 900))" "$cpu_limit" "$memory_limit" "$disk_limit" "$(date +%s)"; then
      outcome=FAILED
      detail=$RESOURCE_GUARD_DETAIL
    fi
    if ! stop_resource_guard "$run_dir" "$guard_pid" "$guard_start"; then
      outcome=FAILED
      detail=${RESOURCE_GUARD_DETAIL:-resource_guard_stop_failed}
    fi
  fi
  finalize_run_terminal_result "$run_dir" "$compose_file" "$project" \
    "$dashboard_pid" "$dashboard_start" "$dashboard_host" "$dashboard_port" \
    "$dashboard_status_probe_file" "$outcome" "$detail"
}

run_field() {
  local file=$1 key=$2
  [[ -f $file ]] || return 1
  awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$file"
}

print_wait_snapshot() {
  local run_dir=$1 phase=$2 alive=$3 now_epoch deadline remaining=pending
  local transfer_rows=0 transfer_failures=0 detail dashboard_host dashboard_port
  now_epoch=$(date +%s)
  deadline=$(run_field "$run_dir/metadata.env" deadline_epoch 2>/dev/null || true)
  if [[ $deadline =~ ^[0-9]+$ ]]; then
    remaining=$((deadline > now_epoch ? deadline - now_epoch : 0))
  fi
  if [[ -f $run_dir/transfers.tsv ]]; then
    read -r transfer_rows transfer_failures < <(awk -F '\t' '
      NR > 1 {
        rows++
        if ($7 != 0 || tolower($11) != "yes") failures++
      }
      END { print rows + 0, failures + 0 }
    ' "$run_dir/transfers.tsv")
  fi
  detail=$(run_field "$run_dir/status.env" detail 2>/dev/null || true)
  dashboard_host=$(run_field "$run_dir/metadata.env" dashboard_host 2>/dev/null || true)
  dashboard_port=$(run_field "$run_dir/metadata.env" dashboard_port 2>/dev/null || true)
  printf 'timestamp=%s phase=%s runner_alive=%s remaining_seconds=%s transfers=%s failures=%s detail=%s dashboard=http://%s:%s/\n' \
    "$(date --iso-8601=seconds)" "$phase" "$alive" "$remaining" \
    "$transfer_rows" "$transfer_failures" "${detail:-pending}" \
    "${dashboard_host:-unknown}" "${dashboard_port:-unknown}"
}

wait_for_run_completion() {
  local run_dir=$1 interval_seconds=$2 phase alive outcome detail
  is_positive_integer "$interval_seconds" || {
    printf 'expected positive integer: %s\n' "$interval_seconds" >&2
    return 2
  }
  [[ -d $run_dir ]] || {
    printf 'stability run directory does not exist: %s\n' "$run_dir" >&2
    return 1
  }
  printf 'waiting_for_run=%s\n' "$run_dir"
  while :; do
    phase=$(cat "$run_dir/phase" 2>/dev/null || printf 'UNKNOWN')
    alive=no
    current_runner_alive "$run_dir" && alive=yes
    print_wait_snapshot "$run_dir" "$phase" "$alive"
    case "$phase" in
      COMPLETED)
        outcome=$(run_field "$run_dir/status.env" outcome 2>/dev/null || true)
        detail=$(run_field "$run_dir/status.env" detail 2>/dev/null || true)
        completed_terminal_evidence_valid "$run_dir/status.env" || {
          printf 'stability terminal evidence is inconsistent: outcome=%s detail=%s\n' \
            "${outcome:-missing}" "${detail:-missing}" >&2
          return 1
        }
        return 0
        ;;
      FAILED|RESOURCE_LIMIT|STOPPED)
        return 1
        ;;
    esac
    if [[ $alive != yes ]]; then
      printf 'stability runner exited before publishing a terminal result\n' >&2
      return 1
    fi
    sleep "$interval_seconds"
  done
}

wait_run() {
  local interval_seconds=$DEFAULT_WAIT_INTERVAL_SECONDS
  while (($#)); do
    case "$1" in
      --interval-seconds)
        interval_seconds=${2:?}
        shift 2
        ;;
      -h|--help)
        usage
        return 0
        ;;
      *)
        printf 'unknown wait option: %s\n' "$1" >&2
        return 2
        ;;
    esac
  done
  local run_dir
  run_dir=$(read_current_run 2>/dev/null || true)
  [[ -n $run_dir && -d $run_dir ]] || {
    printf 'no stability run found\n' >&2
    return 1
  }
  wait_for_run_completion "$run_dir" "$interval_seconds"
}

status_run() {
  local run_dir
  run_dir=$(read_current_run 2>/dev/null || true)
  [[ -n $run_dir && -d $run_dir ]] || { printf 'no stability run found\n'; exit 1; }
  local phase alive=no
  phase=$(cat "$run_dir/phase" 2>/dev/null || printf 'UNKNOWN')
  current_runner_alive "$run_dir" && alive=yes
  printf 'run_dir=%s\nphase=%s\nrunner_alive=%s\n' "$run_dir" "$phase" "$alive"
  cat "$run_dir/metadata.env" 2>/dev/null || true
  cat "$run_dir/status.env" 2>/dev/null || true
  cat "$run_dir/billing-production-gate.status" 2>/dev/null || true
  cat "$run_dir/billing-adversary.status" 2>/dev/null || true
  if [[ -f $run_dir/resources.tsv ]]; then
    printf 'latest_resource_sample='; tail -n 1 "$run_dir/resources.tsv"
  fi
  if [[ -f $run_dir/probes.tsv ]]; then
    printf 'probe_rows=%s\n' "$(( $(wc -l < "$run_dir/probes.tsv") - 1 ))"
    printf 'latest_probe='; tail -n 1 "$run_dir/probes.tsv"
  fi
  if [[ -f $run_dir/large-probes.tsv ]]; then
    printf 'large_probe_rows=%s\n' "$(( $(wc -l < "$run_dir/large-probes.tsv") - 1 ))"
    printf 'latest_large_probe='; tail -n 1 "$run_dir/large-probes.tsv"
  fi
  if [[ -f $run_dir/transfers.tsv ]]; then
    printf 'transfer_rows=%s\n' "$(( $(wc -l < "$run_dir/transfers.tsv") - 1 ))"
    printf 'latest_transfer='; tail -n 1 "$run_dir/transfers.tsv"
  fi
}

stop_run() {
  mkdir -p "$STATE_DIR"
  exec 9> "$STATE_DIR/start.lock"
  flock -n 9 || { printf 'another stability start/stop operation is active\n' >&2; exit 2; }
  local run_dir pid start project compose_file public_pid public_start watcher_pid watcher_start
  run_dir=$(read_current_run 2>/dev/null || true)
  [[ -n $run_dir && -d $run_dir ]] || { printf 'no stability run found\n'; exit 0; }
  if current_runner_alive "$run_dir"; then
    pid=$(cat "$run_dir/runner.pid")
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 1 60); do
      current_runner_alive "$run_dir" || break
      sleep 1
    done
    if current_runner_alive "$run_dir"; then
      kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
    fi
  fi
  project=$(awk -F= '$1=="compose_project"{print $2}' "$run_dir/metadata.env")
  compose_file=$run_dir/runtime/compose.json
  cleanup_project "$compose_file" "$project"
  stop_mixed_adversary_path_run "$run_dir"
  stop_billing_adversary_run "$run_dir"
  stop_reconnect_gate_process "$run_dir" || true
  stop_dashboard_process "$run_dir" || true
  if [[ -f $run_dir/dashboard-public.pid && -f $run_dir/dashboard-public.starttime ]]; then
    public_pid=$(cat "$run_dir/dashboard-public.pid")
    public_start=$(cat "$run_dir/dashboard-public.starttime")
    if pid_matches "$public_pid" "$public_start" 'monitor/supervised-server.sh'; then
      kill -TERM -- "-$public_pid" 2>/dev/null || kill -TERM "$public_pid" 2>/dev/null || true
    fi
  fi
  if [[ -f $run_dir/failure-watcher.pid && -f $run_dir/failure-watcher.starttime ]]; then
    watcher_pid=$(cat "$run_dir/failure-watcher.pid")
    watcher_start=$(cat "$run_dir/failure-watcher.starttime")
    if pid_matches "$watcher_pid" "$watcher_start" 'monitor/failure-watcher.mjs'; then
      kill -TERM "$watcher_pid" 2>/dev/null || true
    fi
  fi
  set_phase "$run_dir" STOPPED
  printf 'stopped_run=%s\n' "$run_dir"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  case ${1:-status} in
    run) shift; run_foreground "$@" ;;
    start) shift; start_run "$@" ;;
    wait) shift || true; wait_run "$@" ;;
    status) shift || true; status_run "$@" ;;
    stop) shift || true; stop_run "$@" ;;
    _run) shift; run_internal "${1:?run directory required}" ;;
    _worker)
      shift
      source "$STABILITY_SUPPORT_ROOT/test/local-chaos/lib.sh"
      run_dir=${1:?run directory required}
      random_client_worker "$run_dir" "${2:?client required}" \
        "${3:?relay required}" "${4:?relay endpoint required}" "${5:?IP family required}" \
        "${6:?listen port required}" "${7:?deadline required}" \
        "${8:?pause required}" "${9:?max inflight required}" \
        "${10:?attempt timeout required}" "${11:-0}"
      ;;
    _batch_worker)
      shift
      source "$STABILITY_SUPPORT_ROOT/test/local-chaos/lib.sh"
      random_batch_worker "${1:?run directory required}" "${2:?deadline required}" \
        "${3:?pause required}" "${4:?max inflight batches required}" \
        "${5:?attempt timeout required}" "${6:?workload limit required}"
      ;;
    _registered_worker) shift; registered_random_worker \
      "${1:?run directory required}" "${2:?client required}" \
      "${3:?runner PID required}" "${4:?runner start time required}" \
      "${@:5}" ;;
    -h|--help|help) usage ;;
    *) usage >&2; exit 2 ;;
  esac
fi
