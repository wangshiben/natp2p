#!/usr/bin/env bash

MIXED_PATH_DETAIL=

start_mixed_adversary_path() {
  local run_dir=$1 ca_port=$2 watch_pid=$3 pid start deadline
  setsid env RUN_DIR="$run_dir" PRIVATE_RUNTIME_DIR="$PRIVATE_RUNTIME_DIR" \
    COMPOSE_FILE="$COMPOSE_FILE" COMPOSE_PROJECT="$COMPOSE_PROJECT" \
    CA_BASE_URL="http://127.0.0.1:$ca_port" WATCH_PID="$watch_pid" \
    node "$ROOT_DIR/test/local-chaos/mixed-path-controller.mjs" \
    > "$run_dir/mixed-adversary-path.log" 2>&1 < /dev/null &
  pid=$!
  start=$(process_starttime "$pid" 2>/dev/null || true)
  [[ $pid =~ ^[1-9][0-9]*$ && $start =~ ^[1-9][0-9]*$ ]] || return 1
  printf '%s\n' "$pid" > "$run_dir/mixed-adversary-path.pid"
  printf '%s\n' "$start" > "$run_dir/mixed-adversary-path.starttime"
  deadline=$((SECONDS + 180))
  while (( SECONDS < deadline )); do
    if ! pid_matches "$pid" "$start" 'mixed-path-controller.mjs'; then
      wait "$pid" 2>/dev/null || true
      return 1
    fi
    if inspect_mixed_adversary_path "$run_dir" "$pid" "$(date +%s)" 0; then
      case $(mixed_path_field "$run_dir/mixed-adversary-path.status" status) in
        RUNNING|MIGRATING)
          printf '%s\n' "$pid"
          return 0
          ;;
      esac
    fi
    sleep 1
  done
  stop_mixed_adversary_path "$pid" || true
  return 1
}

inspect_mixed_adversary_path() {
  local run_dir=$1 pid=$2 now_epoch=$3 require_migrations=${4:-0}
  local status_file=$run_dir/mixed-adversary-path.status status_snapshot status heartbeat generation
  local probe_status consecutive migration_count verified_migration_count latest_two_verified
  local observed_triggers network_event_count network_violation_count network_scenario_coverage required_network_scenarios
  local malicious_natserver_relay malicious_natserver_partition malicious_relay_peer malicious_relay_partition
  local attachment_verified path_has_normal_partition path_has_malicious_node error_code initial_path_verified
  MIXED_PATH_DETAIL=
  [[ -s $status_file ]] || { MIXED_PATH_DETAIL=mixed_path_status_invalid; return 1; }
  status_snapshot=$(<"$status_file") \
    || { MIXED_PATH_DETAIL=mixed_path_status_invalid; return 1; }
  status=$(mixed_path_snapshot_field "$status_snapshot" status)
  heartbeat=$(mixed_path_snapshot_field "$status_snapshot" heartbeat_epoch)
  initial_path_verified=$(mixed_path_snapshot_field "$status_snapshot" initial_path_verified)
  generation=$(mixed_path_snapshot_field "$status_snapshot" generation)
  observed_triggers=$(mixed_path_snapshot_field "$status_snapshot" observed_triggers)
  probe_status=$(mixed_path_snapshot_field "$status_snapshot" probe_status)
  consecutive=$(mixed_path_snapshot_field "$status_snapshot" probe_consecutive_failures)
  migration_count=$(mixed_path_snapshot_field "$status_snapshot" migration_count)
  verified_migration_count=$(mixed_path_snapshot_field "$status_snapshot" verified_migration_count)
  latest_two_verified=$(mixed_path_snapshot_field "$status_snapshot" latest_two_migrations_verified)
  network_event_count=$(mixed_path_snapshot_field "$status_snapshot" network_event_count)
  network_violation_count=$(mixed_path_snapshot_field "$status_snapshot" network_violation_count)
  network_scenario_coverage=$(mixed_path_snapshot_field "$status_snapshot" network_scenario_coverage)
  required_network_scenarios=$(mixed_path_snapshot_field "$status_snapshot" required_network_scenarios)
  malicious_natserver_relay=$(mixed_path_snapshot_field "$status_snapshot" malicious_natserver_relay)
  malicious_natserver_partition=$(mixed_path_snapshot_field "$status_snapshot" malicious_natserver_partition)
  malicious_relay_peer=$(mixed_path_snapshot_field "$status_snapshot" malicious_relay_peer)
  malicious_relay_partition=$(mixed_path_snapshot_field "$status_snapshot" malicious_relay_partition)
  attachment_verified=$(mixed_path_snapshot_field "$status_snapshot" normal_partition_attachment_verified)
  path_has_normal_partition=$(mixed_path_snapshot_field "$status_snapshot" path_contains_normal_partition)
  path_has_malicious_node=$(mixed_path_snapshot_field "$status_snapshot" path_contains_malicious_node)
  error_code=$(mixed_path_snapshot_field "$status_snapshot" error_code)
  if [[ ! $heartbeat =~ ^[0-9]+$ || ! $initial_path_verified =~ ^[01]$ \
    || ! $generation =~ ^[0-9]+$ || ! $observed_triggers =~ ^[0-9]+$ \
    || ! $consecutive =~ ^[0-9]+$ || ! $migration_count =~ ^[0-9]+$ \
    || ! $verified_migration_count =~ ^[0-9]+$ || ! $latest_two_verified =~ ^[01]$ \
    || ! $network_event_count =~ ^[0-9]+$ || ! $network_violation_count =~ ^[0-9]+$ \
    || ! $network_scenario_coverage =~ ^[0-9]+$ || ! $required_network_scenarios =~ ^[0-9]+$ \
    || ! $attachment_verified =~ ^[01]$ || ! $path_has_normal_partition =~ ^[01]$ \
    || ! $path_has_malicious_node =~ ^[01]$ ]]; then
    MIXED_PATH_DETAIL=mixed_path_status_invalid
    return 1
  fi
  if (( initial_path_verified != 1 )); then
    MIXED_PATH_DETAIL=mixed_path_initial_path_unverified
    return 1
  fi
  if ! mixed_path_normal_relay_partition_matches "$malicious_natserver_relay" "$malicious_natserver_partition" \
    || ! mixed_path_normal_relay_partition_matches "$malicious_relay_peer" "$malicious_relay_partition" \
    || (( path_has_normal_partition != 1 || path_has_malicious_node != 1 )); then
    MIXED_PATH_DETAIL=mixed_path_normal_partition_attachment_invalid
    return 1
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    MIXED_PATH_DETAIL=mixed_path_controller_exited
    return 1
  fi
  if (( heartbeat == 0 || heartbeat > now_epoch + 5 || now_epoch - heartbeat > 15 )); then
    MIXED_PATH_DETAIL=mixed_path_heartbeat_stale
    return 1
  fi
  case $status in
    RUNNING)
      [[ $probe_status == PASS && $consecutive == 0 ]] || {
        MIXED_PATH_DETAIL=mixed_path_probe_failed
        return 1
      }
      (( attachment_verified == 1 )) || {
        MIXED_PATH_DETAIL=mixed_path_normal_partition_attachment_invalid
        return 1
      }
      if (( network_violation_count != 0 )); then
        MIXED_PATH_DETAIL=mixed_path_network_containment_violation
        return 1
      fi
      if (( required_network_scenarios != 9 || network_scenario_coverage > required_network_scenarios \
        || network_event_count != generation || verified_migration_count != generation \
        || observed_triggers < network_event_count )); then
        MIXED_PATH_DETAIL=mixed_path_network_evidence_invalid
        return 1
      fi
      ;;
    STARTING|MIGRATING)
      (( require_migrations == 0 )) || {
        MIXED_PATH_DETAIL=mixed_path_migration_incomplete
        return 1
      }
      ;;
    FAILED|DEGRADED)
      if [[ $error_code =~ ^mixed_path_[a-z0-9_]{1,52}$ ]]; then
        MIXED_PATH_DETAIL=$error_code
      else
        MIXED_PATH_DETAIL=mixed_path_probe_failed
      fi
      return 1
      ;;
    *)
      MIXED_PATH_DETAIL=mixed_path_status_invalid
      return 1
      ;;
  esac
  if (( require_migrations == 1 )); then
    if (( verified_migration_count != generation || latest_two_verified != 1 )); then
      MIXED_PATH_DETAIL=mixed_path_containment_unverified
      return 1
    fi
    if (( generation < 9 || migration_count < 9 )); then
      MIXED_PATH_DETAIL=mixed_path_migration_incomplete
      return 1
    fi
    if (( network_scenario_coverage != required_network_scenarios )); then
      MIXED_PATH_DETAIL=mixed_path_network_coverage_incomplete
      return 1
    fi
  fi
  return 0
}

drain_mixed_adversary_path() {
  local run_dir=$1 pid=$2 timeout_seconds=${3:-90} deadline status drain_complete
  [[ $pid =~ ^[1-9][0-9]*$ && $timeout_seconds =~ ^[1-9][0-9]*$ ]] || {
    MIXED_PATH_DETAIL=mixed_path_drain_configuration_invalid
    return 1
  }
  printf 'requested_at=%s\n' "$(date +%s)" > "$run_dir/mixed-adversary-path.drain.tmp"
  mv -f -- "$run_dir/mixed-adversary-path.drain.tmp" "$run_dir/mixed-adversary-path.drain"
  deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    status=$(mixed_path_field "$run_dir/mixed-adversary-path.status" status)
    drain_complete=$(mixed_path_field "$run_dir/mixed-adversary-path.status" drain_complete)
    if [[ $status == RUNNING && $drain_complete == 1 ]] \
      && inspect_mixed_adversary_path "$run_dir" "$pid" "$(date +%s)" 1; then
      return 0
    fi
    if [[ $status != STARTING && $status != MIGRATING && $status != RUNNING ]]; then
      [[ -n $MIXED_PATH_DETAIL ]] || MIXED_PATH_DETAIL=mixed_path_drain_failed
      return 1
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      MIXED_PATH_DETAIL=mixed_path_controller_exited
      return 1
    fi
    sleep 0.25
  done
  MIXED_PATH_DETAIL=mixed_path_drain_timeout
  return 1
}

mixed_path_normal_relay_partition_matches() {
  local relay=$1 partition=$2
  case $relay in
    relay03|relay04|relay05) [[ $partition == control_partition_a ]] ;;
    relay06|relay07) [[ $partition == control_partition_b ]] ;;
    *) return 1 ;;
  esac
}

stop_mixed_adversary_path() {
  local pid=${1:-} attempts state
  [[ $pid =~ ^[1-9][0-9]*$ ]] || return 0
  kill -TERM "$pid" 2>/dev/null || return 0
  for attempts in $(seq 1 50); do
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

stop_mixed_adversary_path_run() {
  local run_dir=$1 pid start
  [[ -f $run_dir/mixed-adversary-path.pid && -f $run_dir/mixed-adversary-path.starttime ]] || return 0
  pid=$(<"$run_dir/mixed-adversary-path.pid")
  start=$(<"$run_dir/mixed-adversary-path.starttime")
  pid_matches "$pid" "$start" 'mixed-path-controller.mjs' || return 0
  stop_mixed_adversary_path "$pid"
}

mixed_path_field() {
  local file=$1 key=$2
  awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$file"
}

mixed_path_snapshot_field() {
  local snapshot=$1 key=$2
  awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' <<< "$snapshot"
}
