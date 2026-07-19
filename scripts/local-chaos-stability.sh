#!/usr/bin/env bash

set -uo pipefail
umask 077

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SOAK_HOME=${BNFS_SOAK_HOME:-$ROOT_DIR/test/local-chaos/.soak}
STATE_DIR=$SOAK_HOME/state
CURRENT_FILE=$STATE_DIR/current
DEFAULT_DURATION_SECONDS=43200
DEFAULT_CPU_LIMIT=55
DEFAULT_MEMORY_LIMIT=40
DEFAULT_DISK_LIMIT=40
DEFAULT_SAMPLE_SECONDS=5
DEFAULT_PROBE_SECONDS=60
DEFAULT_MAX_INFLIGHT=2
DEFAULT_DASHBOARD_HOST=0.0.0.0
DEFAULT_DASHBOARD_PORT=8911
DEFAULT_CA_PORT=19100
DEFAULT_SOAK_CREDIT_BYTES=2199023255552
DEFAULT_WORKLOAD_LIMIT_MIBPS=10
DEFAULT_FAILURE_WATCHER_HEARTBEAT_TIMEOUT_SECONDS=15
DEFAULT_FAILURE_WATCHER_DEGRADED_GRACE_SECONDS=15
DEFAULT_FAILURE_WATCHER_SOURCE_LAG_GRACE_SECONDS=15
DEFAULT_FAILURE_WATCHER_SETTLE_TIMEOUT_SECONDS=30
TOPOLOGY_RELAY_COUNT=7
TOPOLOGY_NAT_SERVER_COUNT=13
TOPOLOGY_NAT_CLIENT_COUNT=6
RANDOM_WORKER_PIDS=()
FAILURE_WATCHER_DETAIL=
FAILURE_WATCHER_DEGRADED_SINCE=0
FAILURE_WATCHER_LAG_SINCE=0
FAILURE_WATCHER_STATUS=
FAILURE_WATCHER_HEARTBEAT_EPOCH=
FAILURE_WATCHER_SOURCE_AVAILABLE=
FAILURE_WATCHER_SOURCE_SIZE=
FAILURE_WATCHER_SOURCE_OFFSET=
FAILURE_WATCHER_NEW_FAILURES=

usage() {
  cat <<'EOF'
usage:
  local-chaos-stability.sh start [options]
  local-chaos-stability.sh status
  local-chaos-stability.sh stop

start options:
  --scenario random|1|2|3       fixed profile for the whole run (default: random)
  --duration-seconds N          running duration after the cluster is ready (default: 43200)
  --cpu-limit PCT               project CPU percentage of host capacity (default: 55)
  --memory-limit PCT            project memory percentage of host memory (default: 40)
  --disk-limit PCT              max Docker/artifact filesystem usage (default: 40)
  --sample-seconds N            resource sample interval (default: 5)
  --probe-seconds N             end-to-end file probe interval (default: 60)
  --max-inflight N              max concurrent transfer setups/downloads (default: 2)
  --workload-limit-mibps N      aggregate transfer budget; 0 disables (default: 10)
  --dashboard-host HOST         dashboard bind host (default: 0.0.0.0)
  --dashboard-port PORT         dashboard port (default: 8911)
  --ca-port PORT                loopback CA port (default: 19100)
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
  printf '%s\n' ca index
  numbered_service_names relay "$TOPOLOGY_RELAY_COUNT"
}

is_positive_integer() {
  [[ $1 =~ ^[1-9][0-9]*$ ]]
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

stop_dashboard_process() {
  local run_dir=$1 pid start attempt
  [[ -f $run_dir/dashboard.pid && -f $run_dir/dashboard.starttime ]] || return 0
  pid=$(cat "$run_dir/dashboard.pid" 2>/dev/null || true)
  start=$(cat "$run_dir/dashboard.starttime" 2>/dev/null || true)
  pid_matches "$pid" "$start" 'monitor/server.mjs' || return 0

  kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
  for attempt in $(seq 1 20); do
    pid_matches "$pid" "$start" 'monitor/server.mjs' || return 0
    sleep 0.1
  done
  if pid_matches "$pid" "$start" 'monitor/server.mjs'; then
    kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
  fi
  for attempt in $(seq 1 20); do
    pid_matches "$pid" "$start" 'monitor/server.mjs' || return 0
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
  pid_matches "$pid" "$start" 'local-chaos-stability.sh _run'
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

random_scenario() {
  local value
  value=$(od -An -N4 -tu4 /dev/urandom | tr -d '[:space:]')
  [[ $value =~ ^[0-9]+$ ]] || return 1
  printf '%s\t%s\n' "$((value % 3 + 1))" "$value"
}

start_run() {
  local scenario= random_value= duration=$DEFAULT_DURATION_SECONDS
  local cpu_limit=$DEFAULT_CPU_LIMIT memory_limit=$DEFAULT_MEMORY_LIMIT disk_limit=$DEFAULT_DISK_LIMIT
  local sample_seconds=$DEFAULT_SAMPLE_SECONDS probe_seconds=$DEFAULT_PROBE_SECONDS
  local max_inflight=$DEFAULT_MAX_INFLIGHT
  local workload_limit_mibps=$DEFAULT_WORKLOAD_LIMIT_MIBPS
  local dashboard_host=$DEFAULT_DASHBOARD_HOST dashboard_port=$DEFAULT_DASHBOARD_PORT ca_port=$DEFAULT_CA_PORT

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
  is_nonnegative_integer "$workload_limit_mibps" || {
    printf 'expected non-negative integer: %s\n' "$workload_limit_mibps" >&2
    exit 2
  }
  if (( workload_limit_mibps > 0 && max_inflight > workload_limit_mibps )); then
    printf 'max-inflight must not exceed workload-limit-mibps when limiting is enabled\n' >&2
    exit 2
  fi
  local per_transfer_limit_mibps=0
  if (( workload_limit_mibps > 0 )); then
    per_transfer_limit_mibps=$((workload_limit_mibps / max_inflight))
  fi
  for value in "$dashboard_port" "$ca_port"; do
    is_port "$value" || { printf 'invalid TCP port: %s\n' "$value" >&2; exit 2; }
  done
  [[ $dashboard_host =~ ^[A-Za-z0-9.-]+$ ]] || {
    printf 'invalid dashboard host: %s\n' "$dashboard_host" >&2
    exit 2
  }
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

  if [[ $scenario == random ]]; then
    read -r scenario random_value < <(random_scenario)
  else
    random_value=explicit
  fi

  local run_id run_dir project project_suffix
  run_id=$(date -u +%Y%m%dT%H%M%SZ)-s${scenario}
  run_dir=$SOAK_HOME/runs/$run_id
  project_suffix=${run_id//[^a-zA-Z0-9]/}
  project=bnfs-soak-${project_suffix,,}
  mkdir -p "$run_dir"
  chmod 700 "$run_dir"
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
  printf 'run_id=%s\nscenario=%s\nscenario_name=%s\nphase=%s\nrun_dir=%s\ndashboard=http://%s:%s/\n' \
    "$run_id" "$scenario" "$(scenario_name "$scenario")" "$phase" "$run_dir" "$dashboard_host" "$dashboard_port"
  [[ $phase == RUNNING || $phase == BUILDING || $phase == STARTING_CLUSTER || $phase == CONFIGURING_PROFILE ]]
}

credit_node() {
  local ca_port=$1 node_id=$2 add_bytes=$3 response balance
  # Perform ledger mutation inside the CA container. This remains reliable
  # even when Docker host-port forwarding is unavailable during startup; the
  # loopback host port is reserved for the read-only monitoring/dashboard path.
  response=$(dc exec -T ca curl -fsS --connect-timeout 5 -H 'Content-Type: application/json' \
    --data-binary "{\"node_id\":\"$node_id\",\"add_bytes\":$add_bytes}" \
    "http://127.0.0.1:9100/credit") || return 1
  balance=$(sed -n 's/.*"balance":[[:space:]]*\([-0-9][0-9]*\).*/\1/p' <<< "$response")
  [[ $balance =~ ^[1-9][0-9]*$ ]]
}

generate_key() {
  local path=$1
  openssl rand -hex 32 > "$path"
  chmod 600 "$path"
}

ensure_key() {
  local path=$1
  [[ -s $path ]] || generate_key "$path"
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

wait_resource_guard_ready() {
  local run_dir=$1 guard_pid=$2 deadline
  deadline=$((SECONDS + 10))
  while (( SECONDS < deadline )); do
    kill -0 "$guard_pid" 2>/dev/null || return 1
    if [[ -s $run_dir/resource-guard.status ]] \
      && grep -q '^RUNNING ' "$run_dir/resource-guard.status"; then
      return 0
    fi
    sleep 0.1
  done
  return 1
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

start_client_and_credit() {
  local service=$1 relay=$2 target_id=$3 listen_port=$4 scenario=$5 ca_port=$6
  local log_file=$RUNTIME_DIR/$scenario/$service.log node_id relaunched_node_id

  # The client starts connecting immediately after printing its NodeID. The CA
  # deposit check can therefore beat a post-launch /credit request. Use the
  # stable private key for an identity warm-up, credit that identity, stop the
  # warm-up process, then start the real client with the same NodeID.
  launch_tunnel_client "$service" "$relay" "$target_id" "$listen_port" "$scenario"
  wait_file_pattern "$log_file" '本节点 ID:' 20 || return 1
  node_id=$(awk '/本节点 ID:/{print $NF; exit}' "$log_file")
  [[ $node_id =~ ^[[:xdigit:]]{64}$ ]] || return 1
  credit_node "$ca_port" "$node_id" "$DEFAULT_SOAK_CREDIT_BYTES" || return 1

  dc exec -T "$service" sh -lc 'pkill -TERM -x tunclient >/dev/null 2>&1 || true; sleep 0.5; pkill -KILL -x tunclient >/dev/null 2>&1 || true'
  launch_tunnel_client "$service" "$relay" "$target_id" "$listen_port" "$scenario"
  wait_file_pattern "$log_file" '本节点 ID:' 20 || return 1
  relaunched_node_id=$(awk '/本节点 ID:/{print $NF; exit}' "$log_file")
  [[ $relaunched_node_id == "$node_id" ]] || return 1
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
  local service
  while IFS= read -r service; do
    local id health
    id=$(dc ps -q "$service" 2>/dev/null || true)
    health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$id" 2>/dev/null || true)
    [[ $health == healthy ]] || return 1
  done < <(core_service_names)
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
  done < <(core_service_names)
}

core_services_unchanged() {
  local identity_file=$1 service expected_id expected_started expected_restarts
  [[ -s $identity_file ]] || return 1
  while IFS=$'\t' read -r service expected_id expected_started expected_restarts; do
    [[ $service != service ]] || continue
    local id started restart_count
    id=$(dc ps -q "$service" 2>/dev/null || true)
    [[ -n $id && $id == "$expected_id" ]] || return 1
    started=$(docker inspect --format '{{.State.StartedAt}}' "$id" 2>/dev/null || true)
    restart_count=$(docker inspect --format '{{.RestartCount}}' "$id" 2>/dev/null || true)
    [[ $started == "$expected_started" && $restart_count == "$expected_restarts" ]] || return 1
  done < "$identity_file"
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

configure_profile() {
  local run_dir=$1 selected=$2 ca_port=$3 per_transfer_limit_mibps=$4
  local scenario=stability server client server_relay client_relay listen_port server_id source_sha source_size
  mkdir -p "$RUNTIME_DIR/$scenario" "$RUNTIME_DIR/keys"
  export BNFS_CHAOS_NAT_CA_URL=http://ca:9100
  export BNFS_CHAOS_NAT_KEY_DIR=/artifacts/keys

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

  generate_key "$RUNTIME_DIR/keys/$server.key"
  generate_key "$RUNTIME_DIR/keys/$client.key"
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
    deadline=$((SECONDS + 70))
    while (( SECONDS < deadline )); do
      grep -q "注册到 relay: $relay02_server_ip:9000" "$RUNTIME_DIR/$scenario/$server.log" && server_migrated=1
      grep -q "注册到 relay: $relay02_client_ip:9000" "$RUNTIME_DIR/$scenario/$client.log" && client_migrated=1
      (( server_migrated == 1 && client_migrated == 1 )) && break
      sleep 1
    done
    (( server_migrated == 1 && client_migrated == 1 )) || return 1
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

stop_random_nat_processes() {
  local service
  while IFS= read -r service; do
    stop_nat_process "$service" tunclient || return 1
  done < <(numbered_service_names natclient "$TOPOLOGY_NAT_CLIENT_COUNT")
  while IFS= read -r service; do
    stop_nat_process "$service" tunserver || return 1
    stop_nat_process "$service" httpfileserver || return 1
  done < <(numbered_service_names natserver "$TOPOLOGY_NAT_SERVER_COUNT")
}

initialize_random_workload() {
  local run_dir=$1 ca_port=$2 selected=$3 max_inflight=$4 per_transfer_limit_mibps=$5 workload_limit_mibps=$6 scenario=random-workload
  local number service relay node_id expected_node_id listen_port role count registration_count
  mkdir -p "$RUNTIME_DIR/$scenario" "$RUNTIME_DIR/keys" "$run_dir/server-locks" \
    "$run_dir/inflight-slots" \
    "$run_dir/server-fresh" "$run_dir/transfer-records" "$run_dir/transfer-errors" \
    "$run_dir/transfer-logs" "$run_dir/workers"
  export BNFS_CHAOS_NAT_CA_URL=http://ca:9100
  export BNFS_CHAOS_NAT_KEY_DIR=/artifacts/keys

  stop_random_nat_processes || return 1
  printf 'service\trole\tnode_id\tingress_relay\tcredited\n' > "$run_dir/nat-identities.tsv"
  for role in natserver natclient; do
    count=$TOPOLOGY_NAT_SERVER_COUNT
    [[ $role == natserver ]] || count=$TOPOLOGY_NAT_CLIENT_COUNT
    for ((number = 1; number <= count; number++)); do
      printf -v service '%s%02d' "$role" "$number"
      if [[ $role == natserver ]]; then
        relay=$(server_entry_relay "$service" "$selected") || return 1
      else
        relay=relay01
      fi
      ensure_key "$RUNTIME_DIR/keys/$service.key"
      node_id=$(node "$ROOT_DIR/test/local-chaos/node-id-from-key.mjs" "$RUNTIME_DIR/keys/$service.key") || return 1
      [[ $node_id =~ ^[[:xdigit:]]{64}$ ]] || return 1
      credit_node "$ca_port" "$node_id" "$DEFAULT_SOAK_CREDIT_BYTES" || return 1
      printf '%s\t%s\t%s\t%s\tyes\n' "$service" "$role" "$node_id" "$relay" >> "$run_dir/nat-identities.tsv"
    done
  done
  [[ $(tail -n +2 "$run_dir/nat-identities.tsv" | cut -f3 | sort -u | wc -l) -eq $((TOPOLOGY_NAT_SERVER_COUNT + TOPOLOGY_NAT_CLIENT_COUNT)) ]] || return 1
  awk -F '\t' '$2 == "natclient" && $4 != "relay01" { exit 1 }' "$run_dir/nat-identities.tsv" || return 1

  printf 'server\tingress_relay\tnode_id\n' > "$run_dir/server-pool.tsv"
  for ((number = 1; number <= TOPOLOGY_NAT_SERVER_COUNT; number++)); do
    printf -v service 'natserver%02d' "$number"
    relay=$(server_entry_relay "$service" "$selected") || return 1
    expected_node_id=$(awk -F '\t' -v service="$service" '$1==service {print $3}' "$run_dir/nat-identities.tsv")
    registration_count=$(relay_registration_count "$relay" "$expected_node_id") || return 1
    node_id=$(start_tunnel_server "$service" "$relay:9000" "$scenario" 5 200 "$per_transfer_limit_mibps") || return 1
    [[ $node_id == "$expected_node_id" ]] || return 1
    wait_relay_registration "$relay" "$node_id" "$registration_count" 20 || return 1
    printf '%s\t%s\t%s\n' "$service" "$relay" "$node_id" >> "$run_dir/server-pool.tsv"
    touch "$run_dir/server-fresh/$service"
  done

  printf 'client\tingress_relay\tlisten_port\tnode_id\n' > "$run_dir/client-pool.tsv"
  for ((number = 1; number <= TOPOLOGY_NAT_CLIENT_COUNT; number++)); do
    printf -v service 'natclient%02d' "$number"
    relay=relay01
    listen_port=$((18100 + number))
    node_id=$(awk -F '\t' -v service="$service" '$1==service {print $3}' "$run_dir/nat-identities.tsv")
    [[ $node_id =~ ^[[:xdigit:]]{64}$ ]] || return 1
    printf '%s\t%s\t%s\t%s\n' "$service" "$relay" "$listen_port" "$node_id" >> "$run_dir/client-pool.tsv"
  done
  awk -F '\t' 'NR > 1 && $2 != "relay01" { exit 1 }' "$run_dir/client-pool.tsv" || return 1

  printf 'mode=random_concurrent\nclient_count=%s\nserver_count=%s\nmax_inflight=%s\nworkload_limit_mibps=%s\nper_transfer_limit_mibps=%s\nrandom_ingress_default=relay01\n' \
    "$TOPOLOGY_NAT_CLIENT_COUNT" "$TOPOLOGY_NAT_SERVER_COUNT" "$max_inflight" \
    "$workload_limit_mibps" "$per_transfer_limit_mibps" >> "$run_dir/workload.env"
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
  target_id=$(awk -F '\t' -v server="$server" '$1 == server { print $3; exit }' "$run_dir/server-pool.tsv")
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
  append_transfer_record "$run_dir" "$record_file" || rc=1
  rm -f "$record_file"
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
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t0\t0.000000\t0.000\tnot-run\t\t\n' \
    "$(date --iso-8601=seconds)" "$transfer_id" "$client" "$relay" "$server" "$requested_mib" "$rc" > "$record_file"
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

snapshot_transfer_logs() {
  local run_dir=$1 transfer_id=$2 client=$3 server=$4
  local source_dir=$RUNTIME_DIR/random-workload destination=$run_dir/transfer-logs
  mkdir -p "$destination"
  [[ ! -f $source_dir/$client.log ]] || cp "$source_dir/$client.log" "$destination/$transfer_id-client.log"
  [[ ! -f $source_dir/$server.log ]] || cp "$source_dir/$server.log" "$destination/$transfer_id-server.log"
}

validate_random_workload_coverage() {
  local run_dir=$1 client
  while IFS= read -r client; do
    if ! awk -F '\t' -v client="$client" 'NR > 1 && $3 == client && $4 ~ /^relay0[1-7]$/ && $7 == 0 && $8 > 0 && $11 == "yes" { found=1 } END { exit !found }' \
      "$run_dir/transfers.tsv"; then
      log_step "$client 没有完成任何一条 SHA-256 正确的随机传输"
      return 1
    fi
    if ! awk -F '\t' -v client="$client" '
      NR == FNR {
        if (FNR > 1) {
          if ($2 ~ /^relay0[2-5]$/) partition[$1]="A"
          if ($2 ~ /^relay0[6-7]$/) partition[$1]="B"
        }
        next
      }
      FNR > 1 && $3 == client && $4 ~ /^relay0[1-7]$/ && $7 == 0 && $8 > 0 && $11 == "yes" {
        if (partition[$5] == "A") seenA=1
        if (partition[$5] == "B") seenB=1
      }
      END { exit !(seenA && seenB) }
    ' "$run_dir/server-pool.tsv" "$run_dir/transfers.tsv"; then
      log_step "$client 未同时完成分区 A 与分区 B 的 SHA-256 正确传输"
      return 1
    fi
  done < <(numbered_service_names natclient "$TOPOLOGY_NAT_CLIENT_COUNT")
  if ! awk -F '\t' '
    NR == FNR { if (FNR > 1) expected[$1]=1; next }
    FNR > 1 && $4 ~ /^relay0[1-7]$/ && $7 == 0 && $8 > 0 && $11 == "yes" { reached[$5]=1 }
    END {
      missing=0
      for (server in expected) if (!reached[server]) missing++
      exit missing != 0
    }
  ' "$run_dir/server-pool.tsv" "$run_dir/transfers.tsv"; then
    log_step "随机负载尚未成功覆盖完整 $TOPOLOGY_NAT_SERVER_COUNT NatServer 池"
    return 1
  fi
  return 0
}

append_transfer_record() {
  local run_dir=$1 record_file=$2
  local timestamp transfer_id client relay server requested_mib rc bytes seconds throughput sha_ok expected_sha actual_sha
  IFS=$'\t' read -r timestamp transfer_id client relay server requested_mib rc bytes seconds throughput sha_ok expected_sha actual_sha < "$record_file"
  [[ -n $timestamp && -n $transfer_id && -n $client && -n $relay && -n $server ]] || return 1
  {
    flock 9
    cat "$record_file" >> "$run_dir/transfers.tsv"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$timestamp" "$transfer_id" "$requested_mib" "$rc" "$bytes" "$seconds" "$throughput" \
      "$sha_ok" "$client" "$expected_sha" "$actual_sha" >> "$run_dir/large-probes.tsv"
  } 9>> "$run_dir/transfers.lock"
}

random_below() {
  local upper=$1 value
  (( upper > 0 )) || { printf '0\n'; return 0; }
  value=$(od -An -N4 -tu4 /dev/urandom | tr -d '[:space:]')
  [[ $value =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$((value % upper))"
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
  local run_dir=$1 client=$2 relay=$3 listen_port=$4 deadline_epoch=$5 pause_seconds=$6 max_inflight=$7
  local failures=0 initial_delay server_line server server_relay target_id
  local server_lock_fd transfer_id record_file server_node_id transfer_ok cooldown actual_relay
  local requested_mib registration_count slot_rc append_ok TRANSFER_SLOT_FD=
  initial_delay=$(random_below "$((pause_seconds + 1))") || return 1
  (( initial_delay == 0 )) || sleep "$initial_delay"

  while (( $(date +%s) < deadline_epoch )); do
    server_line=$(tail -n +2 "$run_dir/server-pool.tsv" | shuf -n 1) || return 1
    IFS=$'\t' read -r server server_relay target_id <<< "$server_line"
    [[ -n $server && -n $server_relay && -n $target_id ]] || return 1
    requested_mib=$(random_probe_size_mib) || return 1
    exec {server_lock_fd}> "$run_dir/server-locks/$server.lock"
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
    record_file=$run_dir/transfer-records/$transfer_id.tsv
    transfer_ok=0
    stop_nat_process "$client" tunclient || true
    if [[ -f $run_dir/server-fresh/$server ]]; then
      rm -f "$run_dir/server-fresh/$server"
      server_node_id=$target_id
    else
      registration_count=$(relay_registration_count "$server_relay" "$target_id") || registration_count=0
      server_node_id=$(restart_tunnel_server "$server" "$server_relay:9000" random-workload 2>/dev/null || true)
      if [[ $server_node_id == "$target_id" ]]; then
        wait_relay_registration "$server_relay" "$server_node_id" "$registration_count" 20 || server_node_id=
      fi
    fi
    if [[ $server_node_id == "$target_id" ]]; then
      launch_tunnel_client "$client" "$relay:9000" "$target_id" "$listen_port" random-workload
      if wait_client_ready "$client" random-workload 70; then
        actual_relay=$(wait_client_entry_relay "$client" 5 2>/dev/null || true)
        if [[ -n $actual_relay ]]; then
          if random_transfer_once "$run_dir" random-workload "$server" "$client" "$actual_relay" "$listen_port" "$transfer_id" "$record_file" "$requested_mib"; then
            transfer_ok=1
          fi
        else
          write_failed_transfer "$client" unknown "$server" "$transfer_id" "$record_file" 4 "$requested_mib"
        fi
      else
        actual_relay=$(wait_client_entry_relay "$client" 2 2>/dev/null || true)
        [[ -n $actual_relay ]] || actual_relay=unknown
        write_failed_transfer "$client" "$actual_relay" "$server" "$transfer_id" "$record_file" 2 "$requested_mib"
      fi
    else
      write_failed_transfer "$client" unknown "$server" "$transfer_id" "$record_file" 3 "$requested_mib"
    fi
    snapshot_transfer_logs "$run_dir" "$transfer_id" "$client" "$server"
    stop_nat_process "$client" tunclient || true
    append_ok=1
    append_transfer_record "$run_dir" "$record_file" || append_ok=0
    rm -f "$record_file"
    release_transfer_slot
    flock -u "$server_lock_fd"
    exec {server_lock_fd}>&-
    (( append_ok == 1 )) || return 1

    if (( transfer_ok == 1 )); then
      failures=0
    else
      failures=$((failures + 1))
      (( failures < 3 )) || return 1
    fi
    cooldown=$(( $(random_below "$pause_seconds") + 1 )) || return 1
    sleep "$cooldown"
  done
}

stop_random_workers() {
  local pid
  (( ${#RANDOM_WORKER_PIDS[@]} > 0 )) || return 0
  for pid in "${RANDOM_WORKER_PIDS[@]}"; do
    kill -TERM "$pid" 2>/dev/null || true
  done
  for pid in "${RANDOM_WORKER_PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  RANDOM_WORKER_PIDS=()
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

run_internal() {
  local run_dir=$1
  local scenario duration cpu_limit memory_limit disk_limit sample_seconds probe_seconds max_inflight workload_limit_mibps per_transfer_limit_mibps dashboard_host dashboard_port ca_port project
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
  project=${compose_project:?}

  local runner_pid=$$ runner_start compose_file=$run_dir/runtime/compose.json
  runner_start=$(awk '{print $22}' "/proc/$runner_pid/stat")
  printf '%s\n' "$runner_pid" > "$run_dir/runner.pid"
  printf '%s\n' "$runner_start" > "$run_dir/runner.starttime"
  printf 'timestamp\tlabel\trc\tbytes\tseconds\tsha256_ok\tclient\n' > "$run_dir/probes.tsv"
  printf 'timestamp\tlabel\trequested_mib\trc\tbytes\tseconds\tmib_per_second\tsha256_ok\tclient\texpected_sha\tactual_sha\n' \
    > "$run_dir/large-probes.tsv"
  printf 'timestamp\ttransfer_id\tclient\tingress_relay\tserver\trequested_mib\trc\tbytes\tseconds\tmib_per_second\tsha256_ok\texpected_sha\tactual_sha\n' \
    > "$run_dir/transfers.tsv"
  local stop_requested=0 guard_pid= dashboard_pid= dashboard_start= failure_watcher_pid= outcome=FAILED detail=initializing
  local failure_watcher_degraded_since=0 failure_watcher_lag_since=0

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
  export ROOT_DIR
  export RUNTIME_DIR=$run_dir/runtime
  export COMPOSE_FILE=$compose_file
  export COMPOSE_PROJECT=$project
  export BNFS_CHAOS_IMAGE=${BNFS_CHAOS_IMAGE:-bnfs-local-chaos:latest}
  BNFS_CHAOS_ENABLE_CA=1 BNFS_CHAOS_CA_HOST_PORT="$ca_port" \
    node "$ROOT_DIR/test/local-chaos/generate-compose.mjs" "$RUNTIME_DIR" > "$COMPOSE_FILE"
  source "$ROOT_DIR/test/local-chaos/lib.sh"

	if ! free_dashboard_port "$dashboard_port"; then
		printf 'outcome=FAILED\ndetail=dashboard_port_busy\n' > "$run_dir/status.env"
    set_phase "$run_dir" FAILED
    return 1
  fi
  if ss -lntH "sport = :$ca_port" | grep -q .; then
    printf 'outcome=FAILED\ndetail=ca_port_busy\n' > "$run_dir/status.env"
    set_phase "$run_dir" FAILED
    return 1
  fi

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

  # The Dashboard owns an independent session so terminal evidence remains
  # available after the runner and Compose project have stopped. Explicit stop
  # and the next start reclaim it through the recorded PID identity.
  setsid env HOST="$dashboard_host" PORT="$dashboard_port" RUN_DIR="$run_dir" \
    COMPOSE_PROJECT="$project" COMPOSE_FILE="$compose_file" CA_PORT="$ca_port" \
    node "$ROOT_DIR/test/local-chaos/monitor/server.mjs" > "$run_dir/dashboard.log" 2>&1 < /dev/null &
  dashboard_pid=$!
  dashboard_start=$(process_starttime "$dashboard_pid" 2>/dev/null || true)
  printf '%s\n' "$dashboard_pid" > "$run_dir/dashboard.pid"
  printf '%s\n' "$dashboard_start" > "$run_dir/dashboard.starttime"
  if ! wait_file_pattern "$run_dir/dashboard.log" 'BNFS stability dashboard listening' 10 \
    || ! pid_matches "$dashboard_pid" "$dashboard_start" 'monitor/server.mjs' \
    || ! wait_dashboard_health "$dashboard_host" "$dashboard_port"; then
    stop_dashboard_process "$run_dir" || true
    wait "$dashboard_pid" 2>/dev/null || true
    stop_failure_watcher "$failure_watcher_pid"
    printf 'outcome=FAILED\ndetail=dashboard_start_failed\n' > "$run_dir/status.env"
    set_phase "$run_dir" FAILED
    return 1
  fi

  set_phase "$run_dir" STARTING_CLUSTER
  if ! topology_reset || ! wait_service_health ca 45; then
    detail=cluster_start_failed
  else
    setsid "$ROOT_DIR/test/local-chaos/resource-guard.sh" \
      --compose-file "$compose_file" --project "$project" --output-dir "$run_dir" \
      --watch-pid "$runner_pid" --watch-pgid "$runner_pid" --duration-seconds "$((duration + 900))" \
      --interval-seconds "$sample_seconds" --cpu-limit "$cpu_limit" \
      --memory-limit "$memory_limit" --disk-limit "$disk_limit" \
      > "$run_dir/resource-guard.log" 2>&1 &
    guard_pid=$!
    printf '%s\n' "$guard_pid" > "$run_dir/resource-guard.pid"

    if ! wait_resource_guard_ready "$run_dir" "$guard_pid"; then
      detail=resource_guard_start_failed
    else
      set_phase "$run_dir" CONFIGURING_PROFILE
      if ! write_core_identity "$run_dir/core-identity.tsv"; then
        detail=core_identity_capture_failed
      else
        capture_project_evidence "$run_dir" initial
        if configure_profile "$run_dir" "$scenario" "$ca_port" "$per_transfer_limit_mibps" \
          && initialize_random_workload "$run_dir" "$ca_port" "$scenario" "$max_inflight" "$per_transfer_limit_mibps" "$workload_limit_mibps" \
          && verify_profile3_tcp_cold_start "$run_dir" "$scenario" \
          && core_services_healthy \
          && core_services_unchanged "$run_dir/core-identity.tsv"; then
          if [[ -s $run_dir/resource-termination.tsv ]] && (( $(wc -l < "$run_dir/resource-termination.tsv") > 1 )); then
            outcome=RESOURCE_LIMIT
            detail=resource_threshold_exceeded
          elif (( stop_requested == 1 )); then
            outcome=STOPPED
            detail=signal_requested_during_profile
          else
            local started_epoch deadline_epoch client_line worker_failed=0 pid worker_start
            started_epoch=$(date +%s)
            deadline_epoch=$((started_epoch + duration))
            printf 'started_epoch=%s\ndeadline_epoch=%s\n' "$started_epoch" "$deadline_epoch" >> "$run_dir/metadata.env"
            set_phase "$run_dir" RUNNING
            outcome=COMPLETED
            detail=duration_complete
            RANDOM_WORKER_PIDS=()
            printf 'client\tpid\tstarttime\n' > "$run_dir/worker-pids.tsv"
            while IFS= read -r client_line; do
              local worker_client worker_relay worker_port worker_node_id
              IFS=$'\t' read -r worker_client worker_relay worker_port worker_node_id <<< "$client_line"
              (
                random_client_worker "$run_dir" "$worker_client" "$worker_relay" "$worker_port" "$deadline_epoch" "$probe_seconds" "$max_inflight"
              ) > "$run_dir/workers/$worker_client.log" 2>&1 &
              pid=$!
              worker_start=$(process_starttime "$pid" 2>/dev/null || true)
              RANDOM_WORKER_PIDS+=("$pid")
              printf '%s\t%s\t%s\n' "$worker_client" "$pid" "$worker_start" >> "$run_dir/worker-pids.tsv"
              [[ $worker_start =~ ^[1-9][0-9]*$ ]] || worker_failed=1
            done < <(tail -n +2 "$run_dir/client-pool.tsv")
            if (( ${#RANDOM_WORKER_PIDS[@]} != TOPOLOGY_NAT_CLIENT_COUNT || worker_failed == 1 )); then
              outcome=FAILED
              detail=random_worker_start_failed
            else
              while (( $(date +%s) < deadline_epoch )); do
                if [[ -s $run_dir/resource-termination.tsv ]] && (( $(wc -l < "$run_dir/resource-termination.tsv") > 1 )); then
                  outcome=RESOURCE_LIMIT
                  detail=resource_threshold_exceeded
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
                if ! pid_matches "$dashboard_pid" "$dashboard_start" 'monitor/server.mjs'; then
                  wait "$dashboard_pid" 2>/dev/null || true
                  outcome=FAILED
                  detail=dashboard_exited
                  break
                fi
                if ! core_services_healthy; then
                  outcome=FAILED
                  detail=core_service_unhealthy
                  break
                fi
                if ! core_services_unchanged "$run_dir/core-identity.tsv"; then
                  outcome=FAILED
                  detail=core_service_recreated_or_restarted
                  break
                fi
                worker_failed=0
                for pid in "${RANDOM_WORKER_PIDS[@]}"; do
                  if ! kill -0 "$pid" 2>/dev/null; then
                    wait "$pid" 2>/dev/null || true
                    worker_failed=1
                    break
                  fi
                done
                if (( worker_failed == 1 )); then
                  outcome=FAILED
                  detail=random_client_worker_failed
                  break
                fi
                sleep 1
              done
            fi
            stop_random_workers
            if [[ $outcome == COMPLETED ]]; then
              if ! wait_failure_watcher_caught_up "$run_dir" "$failure_watcher_pid" \
                "$DEFAULT_FAILURE_WATCHER_SETTLE_TIMEOUT_SECONDS" "$failure_watcher_degraded_since"; then
                outcome=FAILED
                detail=$FAILURE_WATCHER_DETAIL
              elif ! validate_random_workload_coverage "$run_dir"; then
                outcome=FAILED
                detail=random_workload_coverage_failed
              fi
            fi
          fi
        else
          detail=profile_setup_failed
        fi
      fi
    fi
  fi

  stop_failure_watcher "$failure_watcher_pid"
  capture_project_evidence "$run_dir" final
  if [[ -n $guard_pid ]]; then
    kill -TERM "$guard_pid" 2>/dev/null || true
    wait "$guard_pid" 2>/dev/null || true
  fi
  cleanup_project "$compose_file" "$project"
  local remaining_containers remaining_networks
  remaining_containers=$(docker ps -aq --filter "label=com.docker.compose.project=$project" | wc -l)
  remaining_networks=$(docker network ls -q --filter "label=com.docker.compose.project=$project" | wc -l)
  printf 'outcome=%s\ndetail=%s\nfinished_epoch=%s\nremaining_containers=%s\nremaining_networks=%s\n' \
    "$outcome" "$detail" "$(date +%s)" "$remaining_containers" "$remaining_networks" > "$run_dir/status.env"
  set_phase "$run_dir" "$outcome"
  [[ $outcome == COMPLETED ]]
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
    start) shift; start_run "$@" ;;
    status) shift || true; status_run "$@" ;;
    stop) shift || true; stop_run "$@" ;;
    _run) shift; run_internal "${1:?run directory required}" ;;
    -h|--help|help) usage ;;
    *) usage >&2; exit 2 ;;
  esac
fi
