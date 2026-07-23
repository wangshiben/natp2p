#!/usr/bin/env bash

BILLING_ADVERSARY_DETAIL=
BILLING_ADVERSARY_STATUS=
BILLING_ADVERSARY_HEARTBEAT_EPOCH=
BILLING_ADVERSARY_EXECUTED_CHECKS=
BILLING_ADVERSARY_FAILED_CHECKS=
BILLING_ADVERSARY_COVERED_SCENARIOS=
BILLING_ADVERSARY_REQUIRED_SCENARIOS=
BILLING_CONTAINER_PROBE_STATUS=
BILLING_CONTAINER_PROBE_EXECUTED_CHECKS=
BILLING_CONTAINER_PROBE_FAILED_CHECKS=
BILLING_CONTAINER_PROBE_COVERED_SCENARIOS=
BILLING_CONTAINER_PROBE_REQUIRED_SCENARIOS=
BILLING_CONTAINER_PROBE_ERROR_CODE=
BILLING_ADVERSARY_EXPECTED_SCENARIOS=9
BILLING_CONTAINER_PROBE_EXPECTED_SCENARIOS=9
BILLING_ADVERSARY_STOP_ATTEMPTS=60

start_billing_adversary() {
  local run_dir=$1 ca_port=$2 watch_pid=$3 container_probe_mode=${4:-enforce} attempt pid start
  local component_probe_bin=${COMPONENT_PROBE_BIN:-$run_dir/build-runtime/build/billing-adversary-probe}
  local component_probe_state_dir=${COMPONENT_PROBE_STATE_DIR:-$run_dir/billing-component-probe}
  local credential_root=${PRIVATE_RUNTIME_DIR:-$run_dir/runtime/.private}/ca
  local credential_environment=()
  if [[ -f $credential_root/enroll-server.token && -f $credential_root/enroll-relay.token \
    && -f $credential_root/admin.token ]]; then
    credential_environment=(
      "CA_SERVER_ENROLLMENT_TOKEN_FILE=$credential_root/enroll-server.token"
      "CA_RELAY_ENROLLMENT_TOKEN_FILE=$credential_root/enroll-relay.token"
      "CA_ADMIN_TOKEN_FILE=$credential_root/admin.token"
    )
  fi
  env RUN_DIR="$run_dir" CA_BASE_URL="http://127.0.0.1:$ca_port" WATCH_PID="$watch_pid" \
    COMPONENT_PROBE_BIN="$component_probe_bin" COMPONENT_PROBE_STATE_DIR="$component_probe_state_dir" \
    CONTAINER_ADVERSARY_STATE_ROOT="${PRIVATE_RUNTIME_DIR:-$run_dir/runtime/.private}" \
    CONTAINER_PROBE_MODE="$container_probe_mode" \
    "${credential_environment[@]}" \
    node "$ROOT_DIR/test/local-chaos/monitor/billing-adversary.mjs" \
    > "$run_dir/billing-adversary.log" 2>&1 < /dev/null &
  pid=$!
  start=$(process_starttime "$pid" 2>/dev/null || true)
  printf '%s\n' "$pid" > "$run_dir/billing-adversary.pid"
  printf '%s\n' "$start" > "$run_dir/billing-adversary.starttime"
  [[ $start =~ ^[1-9][0-9]*$ ]] || return 1

  for attempt in $(seq 1 900); do
    pid_matches "$pid" "$start" 'monitor/billing-adversary.mjs' || return 1
    if [[ -s $run_dir/billing-adversary.status ]] \
      && read_billing_adversary_status "$run_dir/billing-adversary.status"; then
      printf '%s\n' "$pid"
      return 0
    fi
    sleep 0.1
  done
  stop_billing_adversary "$pid"
  return 1
}

stop_billing_adversary() {
  local pid=${1:-} attempts=${2:-$BILLING_ADVERSARY_STOP_ATTEMPTS} attempt state
  [[ $pid =~ ^[1-9][0-9]*$ ]] || return 0
  [[ $attempts =~ ^[1-9][0-9]*$ ]] || return 1
  kill -TERM "$pid" 2>/dev/null || true
  for attempt in $(seq 1 "$attempts"); do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid" 2>/dev/null || true
      return 0
    fi
    state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || true)
    if [[ -z $state || $state == Z ]]; then
      wait "$pid" 2>/dev/null || true
      return 0
    fi
    sleep 0.1
  done
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  return 1
}

stop_billing_adversary_run() {
  local run_dir=$1 pid start
  [[ -f $run_dir/billing-adversary.pid && -f $run_dir/billing-adversary.starttime ]] || return 0
  pid=$(cat "$run_dir/billing-adversary.pid" 2>/dev/null || true)
  start=$(cat "$run_dir/billing-adversary.starttime" 2>/dev/null || true)
  pid_matches "$pid" "$start" 'monitor/billing-adversary.mjs' || return 0
  stop_billing_adversary "$pid"
}

read_billing_adversary_status() {
  local status_file=$1 values
  BILLING_ADVERSARY_STATUS=
  BILLING_ADVERSARY_HEARTBEAT_EPOCH=
  BILLING_ADVERSARY_EXECUTED_CHECKS=
  BILLING_ADVERSARY_FAILED_CHECKS=
  BILLING_ADVERSARY_COVERED_SCENARIOS=
  BILLING_ADVERSARY_REQUIRED_SCENARIOS=
  BILLING_CONTAINER_PROBE_STATUS=
  BILLING_CONTAINER_PROBE_EXECUTED_CHECKS=
  BILLING_CONTAINER_PROBE_FAILED_CHECKS=
  BILLING_CONTAINER_PROBE_COVERED_SCENARIOS=
  BILLING_CONTAINER_PROBE_REQUIRED_SCENARIOS=
  BILLING_CONTAINER_PROBE_ERROR_CODE=

  values=$(awk -F= '
    function capture(key) {
      seen[key]++
      value[key]=substr($0, length(key) + 2)
    }
    $1 == "schema_version" || $1 == "status" || $1 == "heartbeat_epoch" \
      || $1 == "executed_checks" || $1 == "failed_checks" \
      || $1 == "covered_scenarios" || $1 == "required_scenarios" \
      || $1 == "container_status" || $1 == "container_executed_checks" \
      || $1 == "container_failed_checks" || $1 == "container_covered_scenarios" \
      || $1 == "container_required_scenarios" || $1 == "container_error_code" {
      capture($1)
    }
    END {
      if (seen["schema_version"] != 1 || value["schema_version"] != "1" \
        || seen["status"] != 1 || seen["heartbeat_epoch"] != 1 \
        || seen["executed_checks"] != 1 || seen["failed_checks"] != 1 \
        || seen["covered_scenarios"] != 1 || seen["required_scenarios"] != 1 \
        || seen["container_status"] != 1 || seen["container_executed_checks"] != 1 \
        || seen["container_failed_checks"] != 1 || seen["container_covered_scenarios"] != 1 \
        || seen["container_required_scenarios"] != 1 || seen["container_error_code"] != 1) {
        exit 1
      }
      printf "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s", value["status"], value["heartbeat_epoch"], \
        value["executed_checks"], value["failed_checks"], \
        value["covered_scenarios"], value["required_scenarios"], \
        value["container_status"], value["container_executed_checks"], \
        value["container_failed_checks"], value["container_covered_scenarios"], \
        value["container_required_scenarios"], value["container_error_code"]
    }
  ' "$status_file") || return 1

  IFS='|' read -r BILLING_ADVERSARY_STATUS BILLING_ADVERSARY_HEARTBEAT_EPOCH \
    BILLING_ADVERSARY_EXECUTED_CHECKS BILLING_ADVERSARY_FAILED_CHECKS \
    BILLING_ADVERSARY_COVERED_SCENARIOS BILLING_ADVERSARY_REQUIRED_SCENARIOS \
    BILLING_CONTAINER_PROBE_STATUS BILLING_CONTAINER_PROBE_EXECUTED_CHECKS \
    BILLING_CONTAINER_PROBE_FAILED_CHECKS BILLING_CONTAINER_PROBE_COVERED_SCENARIOS \
    BILLING_CONTAINER_PROBE_REQUIRED_SCENARIOS BILLING_CONTAINER_PROBE_ERROR_CODE <<< "$values"
}

billing_container_probe_failure_detail() {
  case $BILLING_CONTAINER_PROBE_ERROR_CODE in
    container_probe_start_timeout) printf 'billing_container_probe_start_timeout' ;;
    container_probe_heartbeat_stale) printf 'billing_container_probe_heartbeat_stale' ;;
    container_probe_actor_stopped) printf 'billing_container_probe_actor_stopped' ;;
    container_probe_runtime_failed) printf 'billing_container_probe_runtime_failed' ;;
    container_probe_snapshot_invalid|container_probe_coverage_invalid|container_probe_counter_invalid|container_probe_summary_invalid|container_probe_running_state_invalid|container_probe_failed_state_invalid)
      printf 'billing_container_probe_status_invalid'
      ;;
    *) printf 'billing_container_probe_security_violation' ;;
  esac
}

inspect_billing_adversary() {
  local run_dir=$1 pid=$2 now_epoch=$3 allow_violations=${4:-0} heartbeat_timeout=${5:-20}
  local status_file=$run_dir/billing-adversary.status
  BILLING_ADVERSARY_DETAIL=

  if [[ ! -s $status_file ]] || ! read_billing_adversary_status "$status_file"; then
    BILLING_ADVERSARY_DETAIL=billing_adversary_status_invalid
    return 1
  fi
  if [[ ! $BILLING_ADVERSARY_HEARTBEAT_EPOCH =~ ^[0-9]+$ \
    || ! $BILLING_ADVERSARY_EXECUTED_CHECKS =~ ^[0-9]+$ \
    || ! $BILLING_ADVERSARY_FAILED_CHECKS =~ ^[0-9]+$ \
    || ! $BILLING_ADVERSARY_COVERED_SCENARIOS =~ ^[0-9]+$ \
    || ! $BILLING_ADVERSARY_REQUIRED_SCENARIOS =~ ^[1-9][0-9]*$ \
    || ! $BILLING_CONTAINER_PROBE_EXECUTED_CHECKS =~ ^[0-9]+$ \
    || ! $BILLING_CONTAINER_PROBE_FAILED_CHECKS =~ ^[0-9]+$ \
    || ! $BILLING_CONTAINER_PROBE_COVERED_SCENARIOS =~ ^[0-9]+$ \
    || ! $BILLING_CONTAINER_PROBE_REQUIRED_SCENARIOS =~ ^[1-9][0-9]*$ \
    || ! $BILLING_CONTAINER_PROBE_ERROR_CODE =~ ^[a-z0-9_-]+$ ]]; then
    BILLING_ADVERSARY_DETAIL=billing_adversary_status_invalid
    return 1
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    BILLING_ADVERSARY_DETAIL=billing_adversary_exited
    return 1
  fi

  local heartbeat=$((10#$BILLING_ADVERSARY_HEARTBEAT_EPOCH))
  local executed=$((10#$BILLING_ADVERSARY_EXECUTED_CHECKS))
  local failed=$((10#$BILLING_ADVERSARY_FAILED_CHECKS))
  local covered=$((10#$BILLING_ADVERSARY_COVERED_SCENARIOS))
  local required=$((10#$BILLING_ADVERSARY_REQUIRED_SCENARIOS))
  local container_executed=$((10#$BILLING_CONTAINER_PROBE_EXECUTED_CHECKS))
  local container_failed=$((10#$BILLING_CONTAINER_PROBE_FAILED_CHECKS))
  local container_covered=$((10#$BILLING_CONTAINER_PROBE_COVERED_SCENARIOS))
  local container_required=$((10#$BILLING_CONTAINER_PROBE_REQUIRED_SCENARIOS))
  if (( heartbeat == 0 || heartbeat > now_epoch + 5 || now_epoch - heartbeat > heartbeat_timeout )); then
    BILLING_ADVERSARY_DETAIL=billing_adversary_heartbeat_stale
    return 1
  fi
  if (( required != BILLING_ADVERSARY_EXPECTED_SCENARIOS \
    || executed < BILLING_ADVERSARY_EXPECTED_SCENARIOS \
    || covered != BILLING_ADVERSARY_EXPECTED_SCENARIOS )); then
    BILLING_ADVERSARY_DETAIL=billing_adversary_coverage_incomplete
    return 1
  fi
  if (( container_failed > 0 )); then
    if (( allow_violations == 1 )) && [[ $BILLING_CONTAINER_PROBE_ERROR_CODE != container_probe_* ]] \
      && [[ $BILLING_ADVERSARY_STATUS == FAILED && $BILLING_CONTAINER_PROBE_STATUS == FAILED ]]; then
      return 0
    fi
    BILLING_ADVERSARY_DETAIL=$(billing_container_probe_failure_detail)
    return 1
  fi
  if (( container_required != BILLING_CONTAINER_PROBE_EXPECTED_SCENARIOS \
    || container_executed < BILLING_CONTAINER_PROBE_EXPECTED_SCENARIOS \
    || container_covered != BILLING_CONTAINER_PROBE_EXPECTED_SCENARIOS )); then
    BILLING_ADVERSARY_DETAIL=billing_container_probe_coverage_incomplete
    return 1
  fi
  if (( failed > 0 )) || [[ -s $run_dir/billing-adversary.alert ]]; then
    if (( allow_violations == 1 )); then
      return 0
    fi
    BILLING_ADVERSARY_DETAIL=billing_adversary_security_violation
    return 1
  fi
  if [[ $BILLING_ADVERSARY_STATUS != RUNNING ]]; then
    BILLING_ADVERSARY_DETAIL=billing_adversary_unhealthy_status
    return 1
  fi
  if [[ $BILLING_CONTAINER_PROBE_STATUS != RUNNING || $BILLING_CONTAINER_PROBE_ERROR_CODE != none ]]; then
    BILLING_ADVERSARY_DETAIL=billing_container_probe_unhealthy_status
    return 1
  fi
  return 0
}

inspect_billing_adversary_final() {
  local run_dir=$1 now_epoch=$2 allow_violations=${3:-0} heartbeat_timeout=${4:-20}
  local status_file=$run_dir/billing-adversary.status
  BILLING_ADVERSARY_DETAIL=

  if [[ ! -s $status_file ]] || ! read_billing_adversary_status "$status_file"; then
    BILLING_ADVERSARY_DETAIL=billing_adversary_status_invalid
    return 1
  fi
  if [[ ! $BILLING_ADVERSARY_HEARTBEAT_EPOCH =~ ^[0-9]+$ \
    || ! $BILLING_ADVERSARY_EXECUTED_CHECKS =~ ^[0-9]+$ \
    || ! $BILLING_ADVERSARY_FAILED_CHECKS =~ ^[0-9]+$ \
    || ! $BILLING_ADVERSARY_COVERED_SCENARIOS =~ ^[0-9]+$ \
    || ! $BILLING_ADVERSARY_REQUIRED_SCENARIOS =~ ^[1-9][0-9]*$ \
    || ! $BILLING_CONTAINER_PROBE_EXECUTED_CHECKS =~ ^[0-9]+$ \
    || ! $BILLING_CONTAINER_PROBE_FAILED_CHECKS =~ ^[0-9]+$ \
    || ! $BILLING_CONTAINER_PROBE_COVERED_SCENARIOS =~ ^[0-9]+$ \
    || ! $BILLING_CONTAINER_PROBE_REQUIRED_SCENARIOS =~ ^[1-9][0-9]*$ \
    || ! $BILLING_CONTAINER_PROBE_ERROR_CODE =~ ^[a-z0-9_-]+$ ]]; then
    BILLING_ADVERSARY_DETAIL=billing_adversary_status_invalid
    return 1
  fi

  local heartbeat=$((10#$BILLING_ADVERSARY_HEARTBEAT_EPOCH))
  local executed=$((10#$BILLING_ADVERSARY_EXECUTED_CHECKS))
  local failed=$((10#$BILLING_ADVERSARY_FAILED_CHECKS))
  local covered=$((10#$BILLING_ADVERSARY_COVERED_SCENARIOS))
  local required=$((10#$BILLING_ADVERSARY_REQUIRED_SCENARIOS))
  local container_executed=$((10#$BILLING_CONTAINER_PROBE_EXECUTED_CHECKS))
  local container_failed=$((10#$BILLING_CONTAINER_PROBE_FAILED_CHECKS))
  local container_covered=$((10#$BILLING_CONTAINER_PROBE_COVERED_SCENARIOS))
  local container_required=$((10#$BILLING_CONTAINER_PROBE_REQUIRED_SCENARIOS))
  if (( heartbeat == 0 || heartbeat > now_epoch + 5 || now_epoch - heartbeat > heartbeat_timeout )); then
    BILLING_ADVERSARY_DETAIL=billing_adversary_heartbeat_stale
    return 1
  fi
  if (( required != BILLING_ADVERSARY_EXPECTED_SCENARIOS \
    || executed < BILLING_ADVERSARY_EXPECTED_SCENARIOS \
    || covered != BILLING_ADVERSARY_EXPECTED_SCENARIOS )); then
    BILLING_ADVERSARY_DETAIL=billing_adversary_coverage_incomplete
    return 1
  fi
  if (( container_failed > 0 )); then
    if (( allow_violations == 1 )) && [[ $BILLING_CONTAINER_PROBE_ERROR_CODE != container_probe_* ]] \
      && [[ $BILLING_ADVERSARY_STATUS == FAILED && $BILLING_CONTAINER_PROBE_STATUS == FAILED ]]; then
      return 0
    fi
    BILLING_ADVERSARY_DETAIL=$(billing_container_probe_failure_detail)
    return 1
  fi
  if (( container_required != BILLING_CONTAINER_PROBE_EXPECTED_SCENARIOS \
    || container_executed < BILLING_CONTAINER_PROBE_EXPECTED_SCENARIOS \
    || container_covered != BILLING_CONTAINER_PROBE_EXPECTED_SCENARIOS )); then
    BILLING_ADVERSARY_DETAIL=billing_container_probe_coverage_incomplete
    return 1
  fi
  if (( failed > 0 )) || [[ -s $run_dir/billing-adversary.alert ]]; then
    if (( allow_violations == 1 )) && [[ $BILLING_ADVERSARY_STATUS == FAILED ]]; then
      return 0
    fi
    BILLING_ADVERSARY_DETAIL=billing_adversary_security_violation
    return 1
  fi
  if [[ $BILLING_ADVERSARY_STATUS != STOPPED ]]; then
    BILLING_ADVERSARY_DETAIL=billing_adversary_final_status_invalid
    return 1
  fi
  if [[ $BILLING_CONTAINER_PROBE_STATUS != RUNNING || $BILLING_CONTAINER_PROBE_ERROR_CODE != none ]]; then
    BILLING_ADVERSARY_DETAIL=billing_container_probe_unhealthy_status
    return 1
  fi
  return 0
}
