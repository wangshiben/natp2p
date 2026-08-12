#!/usr/bin/env bash
set -u

run_dir=${1:-}
interval_seconds=${2:-180}
required_samples=${3:-21}

if [[ ! -d $run_dir || ! $interval_seconds =~ ^[1-9][0-9]*$ \
  || ! $required_samples =~ ^[1-9][0-9]*$ ]]; then
  printf 'usage: first-hour-audit.sh RUN_DIR [INTERVAL_SECONDS] [SAMPLES]\n' >&2
  exit 2
fi

audit_file=$run_dir/first-hour-audit.tsv
status_file=$run_dir/first-hour-audit.status
printf '%s\n' "$$" > "$run_dir/first-hour-audit.pid"
awk '{print $22}' "/proc/$$/stat" > "$run_dir/first-hour-audit.starttime"

read_field() {
  local file=$1 key=$2
  awk -F= -v wanted="$key" '$1 == wanted { print substr($0, index($0, "=") + 1); exit }' "$file" 2>/dev/null
}

process_identity_alive() {
  local pid=$1 expected_start=$2 actual_start=
  [[ $pid =~ ^[1-9][0-9]*$ && $expected_start =~ ^[1-9][0-9]*$ && -r /proc/$pid/stat ]] || return 1
  actual_start=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null) || return 1
  [[ $actual_start == "$expected_start" ]]
}

publish_status() {
  local status=$1 completed=$2 checked_at=$3 detail=$4 temporary=$status_file.tmp.$$
  printf 'schema_version=1\nstatus=%s\ncompleted_samples=%s\nrequired_samples=%s\ninterval_seconds=%s\nchecked_at=%s\ndetail=%s\n' \
    "$status" "$completed" "$required_samples" "$interval_seconds" "$checked_at" "$detail" > "$temporary"
  mv -f -- "$temporary" "$status_file"
}

printf 'timestamp\tsample\tphase\trunner\tbilling_adversary\tmixed_path\tfailure_watcher\tresource_state\tproject_cpu_host_pct\thost_cpu_pct\tproject_memory_host_pct\thost_memory_pct\tguard_disk_pct\ttransfer_rows\tresult\tdetail\n' \
  > "$audit_file"
publish_status RUNNING 0 "$(date --iso-8601=seconds)" waiting_first_sample

overall=PASSED
overall_detail=verified
for sample in $(seq 1 "$required_samples"); do
  if (( sample > 1 )); then
    sleep "$interval_seconds"
  fi

  checked_at=$(date --iso-8601=seconds)
  phase=$(sed -n '1p' "$run_dir/phase" 2>/dev/null || true)
  runner_pid=$(sed -n '1p' "$run_dir/runner.pid" 2>/dev/null || true)
  runner_start=$(sed -n '1p' "$run_dir/runner.starttime" 2>/dev/null || true)
  runner_state=stopped
  process_identity_alive "$runner_pid" "$runner_start" && runner_state=alive
  billing_state=$(read_field "$run_dir/billing-adversary.status" status)
  billing_failed=$(read_field "$run_dir/billing-adversary.status" failed_checks)
  billing_container_failed=$(read_field "$run_dir/billing-adversary.status" container_failed_checks)
  mixed_state=$(read_field "$run_dir/mixed-adversary-path.status" status)
  mixed_violations=$(read_field "$run_dir/mixed-adversary-path.status" network_violation_count)
  mixed_probe_failures=$(read_field "$run_dir/mixed-adversary-path.status" probe_failures)
  failure_state=$(read_field "$run_dir/failure-watcher.status" status)
  new_failures=$(read_field "$run_dir/failure-watcher.status" new_failure_records)
  resource_line=$(tail -n 1 "$run_dir/resources.tsv" 2>/dev/null || true)
  project_cpu_host=unknown
  host_cpu=unknown
  project_memory_host=unknown
  host_memory=unknown
  guard_disk=unknown
  resource_state=missing
  if [[ -n $resource_line ]]; then
    IFS=$'\t' read -r _ _ _ _ project_cpu_host host_cpu _ project_memory_host host_memory _ _ guard_disk resource_state \
      <<< "$resource_line"
  fi
  transfer_rows=$(awk 'END { print (NR > 0 ? NR - 1 : 0) }' "$run_dir/transfers.tsv" 2>/dev/null || printf '0\n')
  transfer_rows=${transfer_rows:-0}

  result=PASS
  detail=verified
  if [[ $phase != RUNNING ]]; then
    result=FAIL
    detail=phase_not_running
  elif [[ $runner_state != alive ]]; then
    result=FAIL
    detail=runner_identity_not_alive
  elif [[ $billing_state != RUNNING || $billing_failed != 0 || $billing_container_failed != 0 ]]; then
    result=FAIL
    detail=billing_adversary_unhealthy
  elif [[ $mixed_state != RUNNING && $mixed_state != STARTING && $mixed_state != MIGRATING ]]; then
    result=FAIL
    detail=mixed_path_unhealthy
  elif [[ $mixed_violations != 0 || $mixed_probe_failures != 0 ]]; then
    result=FAIL
    detail=mixed_path_unhealthy
  elif [[ $failure_state != RUNNING || $new_failures != 0 ]]; then
    result=FAIL
    detail=failure_watcher_alert
  elif [[ $resource_state != OK ]]; then
    result=FAIL
    detail=resource_guard_unhealthy
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$checked_at" "$sample" "$phase" "$runner_state" "$billing_state" "$mixed_state" \
    "$failure_state" "$resource_state" "$project_cpu_host" "$host_cpu" "$project_memory_host" \
    "$host_memory" "$guard_disk" "$transfer_rows" "$result" "$detail" >> "$audit_file"

  if [[ $result != PASS ]]; then
    overall=FAILED
    overall_detail=$detail
  fi
  publish_status RUNNING "$sample" "$checked_at" "$detail"
done

publish_status "$overall" "$required_samples" "$(date --iso-8601=seconds)" "$overall_detail"
[[ $overall == PASSED ]]
