#!/usr/bin/env bash

set -uo pipefail

usage() {
  cat <<'EOF'
usage: resource-guard.sh --compose-file FILE --project NAME --output-dir DIR
                         --watch-pid PID --watch-pgid PGID [options]

Options:
  --duration-seconds N   Stop monitoring after N seconds (default: 43200)
  --interval-seconds N   Resource sampling interval (default: 5)
  --cpu-limit PCT        Project CPU as a percentage of host capacity (default: 55)
  --memory-limit PCT     Project memory as a percentage of host memory (default: 40)
  --disk-limit PCT       Filesystem usage percentage (default: 40)

The watched PID must be the leader of an independent process group. Start the
test worker with setsid, and start this guard in a different process group.

Exit status:
  0  duration completed (the watched process group is stopped) or watched runner exited normally
  3  a resource limit was exceeded and the test was forcibly terminated
  2  invalid arguments or unavailable prerequisites
EOF
}

compose_file=
project=
output_dir=
watch_pid=
watch_pgid=
duration_seconds=${SOAK_DURATION_SECONDS:-43200}
interval_seconds=${RESOURCE_SAMPLE_INTERVAL_SECONDS:-5}
cpu_limit=${RESOURCE_CPU_LIMIT_PCT:-55}
memory_limit=${RESOURCE_MEMORY_LIMIT_PCT:-40}
disk_limit=${RESOURCE_DISK_LIMIT_PCT:-40}

while (($#)); do
  case "$1" in
    --compose-file)
      compose_file=${2:?--compose-file requires a path}
      shift 2
      ;;
    --project)
      project=${2:?--project requires a name}
      shift 2
      ;;
    --output-dir)
      output_dir=${2:?--output-dir requires a path}
      shift 2
      ;;
    --watch-pid)
      watch_pid=${2:?--watch-pid requires a PID}
      shift 2
      ;;
    --watch-pgid)
      watch_pgid=${2:?--watch-pgid requires a process group ID}
      shift 2
      ;;
    --duration-seconds)
      duration_seconds=${2:?--duration-seconds requires a value}
      shift 2
      ;;
    --interval-seconds)
      interval_seconds=${2:?--interval-seconds requires a value}
      shift 2
      ;;
    --cpu-limit)
      cpu_limit=${2:?--cpu-limit requires a value}
      shift 2
      ;;
    --memory-limit)
      memory_limit=${2:?--memory-limit requires a value}
      shift 2
      ;;
    --disk-limit)
      disk_limit=${2:?--disk-limit requires a value}
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'resource-guard: unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

is_positive_integer() {
  [[ $1 =~ ^[1-9][0-9]*$ ]]
}

is_percentage() {
  awk -v value="$1" 'BEGIN { exit !(value ~ /^[0-9]+([.][0-9]+)?$/ && value >= 0 && value <= 100) }'
}

if [[ -z $compose_file || -z $project || -z $output_dir || -z $watch_pid || -z $watch_pgid ]]; then
  printf 'resource-guard: --compose-file, --project, --output-dir, --watch-pid and --watch-pgid are required\n' >&2
  usage >&2
  exit 2
fi
if [[ ! -f $compose_file ]]; then
  printf 'resource-guard: compose file does not exist: %s\n' "$compose_file" >&2
  exit 2
fi
if ! is_positive_integer "$watch_pid" || (( watch_pid <= 1 || watch_pid == $$ )); then
  printf 'resource-guard: unsafe watch PID: %s\n' "$watch_pid" >&2
  exit 2
fi
if ! is_positive_integer "$watch_pgid" || (( watch_pgid <= 1 )); then
  printf 'resource-guard: unsafe watch process group: %s\n' "$watch_pgid" >&2
  exit 2
fi
if ! kill -0 "$watch_pid" 2>/dev/null; then
  printf 'resource-guard: watched PID is not running: %s\n' "$watch_pid" >&2
  exit 2
fi
actual_watch_pgid=$(ps -o pgid= -p "$watch_pid" 2>/dev/null | tr -d '[:space:]')
own_pgid=$(ps -o pgid= -p $$ 2>/dev/null | tr -d '[:space:]')
if [[ $actual_watch_pgid != "$watch_pgid" || $watch_pid != "$watch_pgid" ]]; then
  printf 'resource-guard: watched PID must be its process-group leader: pid=%s expected_pgid=%s actual_pgid=%s\n' \
    "$watch_pid" "$watch_pgid" "${actual_watch_pgid:-unknown}" >&2
  exit 2
fi
if [[ $own_pgid == "$watch_pgid" ]]; then
  printf 'resource-guard: guard and watched runner share process group %s; start the guard with setsid\n' "$watch_pgid" >&2
  exit 2
fi
watch_starttime=$(awk '{print $22}' "/proc/$watch_pid/stat" 2>/dev/null || true)
if ! is_positive_integer "$watch_starttime"; then
  printf 'resource-guard: cannot read watched PID start time: %s\n' "$watch_pid" >&2
  exit 2
fi
if ! is_positive_integer "$duration_seconds" || ! is_positive_integer "$interval_seconds"; then
  printf 'resource-guard: duration and interval must be positive integers\n' >&2
  exit 2
fi
for value in "$cpu_limit" "$memory_limit" "$disk_limit"; do
  if ! is_percentage "$value"; then
    printf 'resource-guard: resource limits must be percentages in [0, 100]: %s\n' "$value" >&2
    exit 2
  fi
done
for command in awk date df docker nproc ps tr; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'resource-guard: missing prerequisite: %s\n' "$command" >&2
    exit 2
  fi
done
if ! docker compose version >/dev/null 2>&1; then
  printf 'resource-guard: docker compose is unavailable\n' >&2
  exit 2
fi

mkdir -p "$output_dir"
samples_file=$output_dir/resources.tsv
events_file=$output_dir/resource-events.log
termination_file=$output_dir/resource-termination.tsv
status_file=$output_dir/resource-guard.status
docker_root=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)
[[ -d $docker_root ]] || docker_root=/
logical_cpus=$(nproc)
host_memory_bytes=$(awk '/^MemTotal:/ { print $2 * 1024; exit }' /proc/meminfo)
started_epoch=$(date +%s)
deadline_epoch=$((started_epoch + duration_seconds))
stop_requested=0
cleanup_verified=not_run

printf 'timestamp\tepoch\tcontainers\tproject_cpu_raw_pct\tproject_cpu_host_pct\thost_cpu_pct\tproject_memory_bytes\tproject_memory_host_pct\thost_memory_pct\tdocker_disk_pct\tartifact_disk_pct\tguard_disk_pct\tstate\n' > "$samples_file"
printf 'metric\tlimit_pct\tobserved_pct\ttimestamp\tepoch\n' > "$termination_file"
printf 'RUNNING started=%s duration_seconds=%s interval_seconds=%s cpu_limit_pct=%s memory_limit_pct=%s disk_limit_pct=%s logical_cpus=%s\n' \
  "$(date --iso-8601=seconds)" "$duration_seconds" "$interval_seconds" "$cpu_limit" "$memory_limit" "$disk_limit" "$logical_cpus" > "$status_file"

log_event() {
  printf '%s %s\n' "$(date --iso-8601=seconds)" "$*" | tee -a "$events_file" >&2
}

on_signal() {
  stop_requested=1
}
trap on_signal INT TERM HUP

read_cpu_ticks() {
  awk '/^cpu / {
    idle = $5 + $6
    total = 0
    for (i = 2; i <= NF; i++) total += $i
    print total, idle
    exit
  }' /proc/stat
}

filesystem_usage_pct() {
  local path=$1
  df -P "$path" 2>/dev/null | awk 'NR == 2 { gsub(/%/, "", $5); print $5; exit }'
}

collect_project_stats() {
  local ids stats
  ids=$(docker compose --project-name "$project" --file "$compose_file" ps -q 2>/dev/null || true)
  if [[ -z $ids ]]; then
    printf '0\t0\t0\n'
    return
  fi

  # Docker reports 100% per fully occupied logical CPU. Summing all project
  # containers and dividing by nproc converts it to whole-host capacity.
  stats=$(docker stats --no-stream --format '{{.CPUPerc}}\t{{.MemUsage}}' $ids 2>/dev/null || true)
  awk -F '\t' '
    function bytes(value, number, unit) {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      number = value + 0
      unit = value
      sub(/^[0-9.]+[[:space:]]*/, "", unit)
      if (unit == "KiB" || unit == "kB" || unit == "KB") return number * 1024
      if (unit == "MiB" || unit == "MB") return number * 1024 * 1024
      if (unit == "GiB" || unit == "GB") return number * 1024 * 1024 * 1024
      if (unit == "TiB" || unit == "TB") return number * 1024 * 1024 * 1024 * 1024
      return number
    }
    NF >= 2 {
      cpu = $1
      gsub(/%/, "", cpu)
      split($2, memory, " / ")
      cpu_sum += cpu + 0
      memory_sum += bytes(memory[1])
      count++
    }
    END { printf "%d\t%.6f\t%.0f\n", count, cpu_sum, memory_sum }
  ' <<< "$stats"
}

watch_is_alive() {
  local current_start current_pgid
  [[ -r /proc/$watch_pid/stat ]] || return 1
  current_start=$(awk '{print $22}' "/proc/$watch_pid/stat" 2>/dev/null || true)
  current_pgid=$(ps -o pgid= -p "$watch_pid" 2>/dev/null | tr -d '[:space:]')
  [[ $current_start == "$watch_starttime" && $current_pgid == "$watch_pgid" ]]
}

watched_group_is_alive() {
  # A dead group leader may remain as a zombie until its launcher reaps it;
  # zombies must not delay cleanup or be mistaken for live workload helpers.
  ps -eo pgid=,stat= | awk -v expected="$watch_pgid" '
    $1 == expected && $2 !~ /^Z/ { alive = 1 }
    END { exit !alive }
  '
}

terminate_watched_tree() {
  local signal=$1
  watched_group_is_alive || return 0
  # Worker and guard are different setsid process groups. Group signalling
  # therefore reaches late-forked children without risking the guard itself.
  kill -"$signal" -- "-$watch_pgid" 2>/dev/null || true
}

wait_for_watched_tree() {
  local attempts=$1 attempt
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    watched_group_is_alive || return 0
    sleep 0.5
  done
  return 1
}

cleanup_compose_project() {
  local ids networks remaining_containers remaining_networks
  docker compose --project-name "$project" --file "$compose_file" \
    down --remove-orphans --timeout 3 >> "$events_file" 2>&1 || true

  # A killed Compose client can leave resources behind. Fall back to labels,
  # while remaining strictly scoped to this test project.
  ids=$(docker ps -aq --filter "label=com.docker.compose.project=$project")
  if [[ -n $ids ]]; then
    docker rm -f $ids >> "$events_file" 2>&1 || true
  fi
  networks=$(docker network ls -q --filter "label=com.docker.compose.project=$project")
  if [[ -n $networks ]]; then
    docker network rm $networks >> "$events_file" 2>&1 || true
  fi

  remaining_containers=$(docker ps -aq --filter "label=com.docker.compose.project=$project" | wc -l)
  remaining_networks=$(docker network ls -q --filter "label=com.docker.compose.project=$project" | wc -l)
  remaining_containers=${remaining_containers//[[:space:]]/}
  remaining_networks=${remaining_networks//[[:space:]]/}
  if [[ ${remaining_containers:-0} != 0 || ${remaining_networks:-0} != 0 ]]; then
    cleanup_verified=no
    log_event "cleanup verification failed: project=$project remaining_containers=$remaining_containers remaining_networks=$remaining_networks"
    return 1
  fi
  cleanup_verified=yes
  log_event "cleanup verified: project=$project remaining_containers=0 remaining_networks=0"
}

capture_project_evidence() {
  local suffix=$1 ids
  docker compose --project-name "$project" --file "$compose_file" \
    logs --no-color > "$output_dir/compose-$suffix.log" 2>&1 || true
  printf 'service\tcontainer_id\tstatus\thealth\tstarted_at\trestart_count\n' \
    > "$output_dir/containers-$suffix.tsv"
  ids=$(docker ps -aq --filter "label=com.docker.compose.project=$project")
  [[ -n $ids ]] || return 0
  docker inspect --format '{{index .Config.Labels "com.docker.compose.service"}}|{{.Id}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.State.StartedAt}}|{{.RestartCount}}' \
    $ids 2>/dev/null | awk -F '|' 'BEGIN { OFS="\t" } { print $1, $2, $3, $4, $5, $6 }' \
    | sort >> "$output_dir/containers-$suffix.tsv" || true
}

stop_test_and_cleanup() {
  terminate_watched_tree TERM
  if ! wait_for_watched_tree 10; then
    log_event "watched process group ignored TERM; sending KILL pgid=$watch_pgid"
    terminate_watched_tree KILL
    wait_for_watched_tree 10 || true
  fi
  cleanup_compose_project || true
}

force_terminate() {
  local metric=$1 observed=$2 now_epoch=$3 now_iso=$4
  log_event "LIMIT_EXCEEDED metric=$metric observed_pct=$observed; stopping compose project=$project watched_pid=$watch_pid"
  printf '%s\t%s\t%s\t%s\t%s\n' "$metric" "${metric_limits[$metric]}" "$observed" "$now_iso" "$now_epoch" >> "$termination_file"
  printf 'RESOURCE_LIMIT\n' > "$output_dir/phase"
  printf 'outcome=RESOURCE_LIMIT\ndetail=resource_threshold_exceeded\nfinished_epoch=%s\n' \
    "$now_epoch" > "$output_dir/status.env"

  # Stop the runner and all of its current descendants before tearing down the
  # Compose project. This prevents an in-flight scenario from racing `down`
  # with a new `up`. Cleanup remains scoped to this one project.
  capture_project_evidence resource-limit
  stop_test_and_cleanup

  printf 'RESOURCE_LIMIT\n' > "$output_dir/phase"
  printf 'outcome=RESOURCE_LIMIT\ndetail=resource_threshold_exceeded\nfinished_epoch=%s\n' \
    "$now_epoch" > "$output_dir/status.env"
  printf 'TERMINATED metric=%s observed_pct=%s limit_pct=%s timestamp=%s cleanup_verified=%s\n' \
    "$metric" "$observed" "${metric_limits[$metric]}" "$now_iso" "$cleanup_verified" > "$status_file"
  exit 3
}

complete_duration() {
  local now_iso
  now_iso=$(date --iso-8601=seconds)
  log_event "requested monitoring duration completed; stopping watched test process group"
  printf 'FAILED\n' > "$output_dir/phase"
  printf 'outcome=FAILED\ndetail=resource_guard_deadline_exceeded\nfinished_epoch=%s\n' \
    "$(date +%s)" > "$output_dir/status.env"
  capture_project_evidence guard-timeout
  stop_test_and_cleanup
  printf 'COMPLETED timestamp=%s duration_seconds=%s watched_group_stopped=yes cleanup_verified=%s\n' \
    "$now_iso" "$duration_seconds" "$cleanup_verified" > "$status_file"
  exit 0
}

declare -A metric_limits=(
  [cpu]="$cpu_limit"
  [memory]="$memory_limit"
  [disk]="$disk_limit"
)

read -r previous_total previous_idle < <(read_cpu_ticks)
log_event "monitor started project=$project watch_pid=$watch_pid duration_seconds=$duration_seconds"

while true; do
  if (( stop_requested == 1 )); then
    printf 'STOPPED_BY_SIGNAL timestamp=%s\n' "$(date --iso-8601=seconds)" > "$status_file"
    exit 0
  fi
  if ! watch_is_alive; then
    log_event "watched runner exited; stopping any remaining group members and cleaning project"
    capture_project_evidence runner-exited
    stop_test_and_cleanup
    printf 'RUNNER_EXITED timestamp=%s cleanup_verified=%s\n' \
      "$(date --iso-8601=seconds)" "$cleanup_verified" > "$status_file"
    exit 0
  fi

  now_epoch=$(date +%s)
  if (( now_epoch >= deadline_epoch )); then
    complete_duration
  fi

  read -r container_count project_cpu_raw project_memory_bytes < <(collect_project_stats)
  read -r current_total current_idle < <(read_cpu_ticks)
  cpu_delta=$((current_total - previous_total))
  idle_delta=$((current_idle - previous_idle))
  if (( cpu_delta > 0 )); then
    host_cpu_pct=$(awk -v total="$cpu_delta" -v idle="$idle_delta" 'BEGIN { printf "%.6f", 100 * (total - idle) / total }')
  else
    host_cpu_pct=0
  fi
  previous_total=$current_total
  previous_idle=$current_idle

  project_cpu_host_pct=$(awk -v raw="$project_cpu_raw" -v cpus="$logical_cpus" 'BEGIN { printf "%.6f", raw / cpus }')
  project_memory_host_pct=$(awk -v used="$project_memory_bytes" -v total="$host_memory_bytes" 'BEGIN { printf "%.6f", (total > 0 ? 100 * used / total : 0) }')
  host_memory_available_bytes=$(awk '/^MemAvailable:/ { print $2 * 1024; exit }' /proc/meminfo)
  host_memory_pct=$(awk -v available="$host_memory_available_bytes" -v total="$host_memory_bytes" 'BEGIN { printf "%.6f", (total > 0 ? 100 * (total - available) / total : 0) }')
  docker_disk_pct=$(filesystem_usage_pct "$docker_root")
  artifact_disk_pct=$(filesystem_usage_pct "$output_dir")
  docker_disk_pct=${docker_disk_pct:-100}
  artifact_disk_pct=${artifact_disk_pct:-100}
  guard_disk_pct=$(awk -v docker_used="$docker_disk_pct" -v artifact_used="$artifact_disk_pct" 'BEGIN { print (docker_used > artifact_used ? docker_used : artifact_used) }')

  state=OK
  breach_metric=
  breach_observed=
  if awk -v observed="$project_cpu_host_pct" -v limit="$cpu_limit" 'BEGIN { exit !(observed > limit) }'; then
    state=LIMIT_EXCEEDED
    breach_metric=cpu
    breach_observed=$project_cpu_host_pct
  elif awk -v observed="$project_memory_host_pct" -v limit="$memory_limit" 'BEGIN { exit !(observed > limit) }'; then
    state=LIMIT_EXCEEDED
    breach_metric=memory
    breach_observed=$project_memory_host_pct
  elif awk -v observed="$guard_disk_pct" -v limit="$disk_limit" 'BEGIN { exit !(observed > limit) }'; then
    state=LIMIT_EXCEEDED
    breach_metric=disk
    breach_observed=$guard_disk_pct
  fi

  now_iso=$(date --iso-8601=seconds)
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$now_iso" "$now_epoch" "$container_count" "$project_cpu_raw" "$project_cpu_host_pct" "$host_cpu_pct" \
    "$project_memory_bytes" "$project_memory_host_pct" "$host_memory_pct" "$docker_disk_pct" \
    "$artifact_disk_pct" "$guard_disk_pct" "$state" >> "$samples_file"

  if [[ $state == LIMIT_EXCEEDED ]]; then
    force_terminate "$breach_metric" "$breach_observed" "$now_epoch" "$now_iso"
  fi
  sleep "$interval_seconds"
done
