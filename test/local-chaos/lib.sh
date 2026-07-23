#!/usr/bin/env bash

set -o pipefail

ROOT_DIR=${ROOT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}
RUNTIME_DIR=${RUNTIME_DIR:-$ROOT_DIR/test/local-chaos/.runtime}
COMPOSE_FILE=${COMPOSE_FILE:-$RUNTIME_DIR/compose.json}
COMPOSE_PROJECT=${COMPOSE_PROJECT:-bnfs-local-chaos}

dc() {
  docker compose --project-name "$COMPOSE_PROJECT" --file "$COMPOSE_FILE" "$@"
}

netns_exec() {
  local service=$1
  shift
  local container_id container_pid
  container_id=$(dc ps -q "$service")
  container_pid=$(docker inspect --format '{{.State.Pid}}' "$container_id")
  nsenter --target "$container_pid" --net -- "$@"
}

log_step() {
  printf '[local-chaos] %s\n' "$*" >&2
}

topology_reset() {
  log_step "重建 1 Index + 7 Relay + 19 NAT 容器拓扑"
  dc down --remove-orphans --timeout 3 >/dev/null 2>&1 || true
  if ! dc up -d --remove-orphans > "$RUNTIME_DIR/topology-up.log" 2>&1; then
    log_step "Compose 拓扑启动失败，原始输出: $RUNTIME_DIR/topology-up.log"
    tail -n 160 "$RUNTIME_DIR/topology-up.log" >&2 || true
    return 1
  fi

  local service container_id health deadline
  deadline=$((SECONDS + 45))
  for service in index relay01 relay02 relay03 relay04 relay05 relay06 relay07; do
    while true; do
      container_id=$(dc ps -q "$service")
      health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id" 2>/dev/null || true)
      if [[ $health == healthy ]]; then
        break
      fi
      if (( SECONDS >= deadline )); then
        log_step "$service 未在期限内健康，当前状态=$health"
        dc logs --no-color "$service" >&2 || true
        return 1
      fi
      sleep 1
    done
  done

  for service in relay01 relay02 relay03 relay04 relay05 relay06 relay07; do
    if ! wait_compose_log "$service" '已注册到 index:' 35; then
      log_step "$service 控制链路未就绪"
      dc logs --no-color "$service" >&2 || true
      return 1
    fi
  done
}

wait_compose_log() {
  local service=$1 pattern=$2 timeout_seconds=$3 deadline output
  deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    output=$(dc logs --no-color "$service" 2>&1 || true)
    if grep -q -- "$pattern" <<< "$output"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_file_pattern() {
  local file=$1 pattern=$2 timeout_seconds=$3 deadline
  deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    if [[ -f $file ]] && grep -q -- "$pattern" "$file"; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

wait_file_size() {
  local file=$1 minimum_size=$2 timeout_seconds=$3 deadline size
  deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    size=$(stat -c %s "$file" 2>/dev/null || printf '0')
    if (( size >= minimum_size )); then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

wait_file_exists() {
  local file=$1 timeout_seconds=$2 deadline
  deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    [[ -f $file ]] && return 0
    sleep 0.25
  done
  return 1
}

assert_reachable() {
  local source=$1 target=$2 port=${3:-9000}
  if ! dc exec -T "$source" timeout 2 bash -lc "exec 3<>/dev/tcp/$target/$port" >/dev/null 2>&1; then
    log_step "预期可达但失败: $source -> $target:$port"
    return 1
  fi
}

assert_unreachable() {
  local source=$1 target=$2 port=${3:-9000}
  if dc exec -T "$source" timeout 2 bash -lc "exec 3<>/dev/tcp/$target/$port" >/dev/null 2>&1; then
    log_step "预期隔离但实际可达: $source -> $target:$port"
    return 1
  fi
}

start_http_file_server() {
  local service=$1 relay=$2 scenario=$3 size_mb=${4:-1}
  local max_size_mb=${5:-$size_mb}
  local send_rate_mibps=${6:-0}
  local host_dir=$RUNTIME_DIR/$scenario inside_dir=/artifacts/$scenario
  local http_log=$host_dir/${service}-http.log
  mkdir -p "$host_dir"
  rm -f "$http_log"

  dc exec -T "$service" sh -lc \
    'pkill -TERM -x httpfileserver >/dev/null 2>&1 || true; sleep 0.1; pkill -KILL -x httpfileserver >/dev/null 2>&1 || true'

  dc exec -T -d "$service" sh -lc \
    "exec /opt/bnfs/httpfileserver -port 8080 -size $size_mb -max-size $max_size_mb -send-rate-mibps $send_rate_mibps > '$inside_dir/${service}-http.log' 2>&1"
  if ! wait_file_pattern "$http_log" 'HTTP 文件服务器监听:' 15; then
    log_step "$service HTTP 源未启动"
    return 1
  fi
}

launch_tunnel_server() {
  local service=$1 relay=$2 scenario=$3
  local host_dir=$RUNTIME_DIR/$scenario inside_dir=/artifacts/$scenario
  local server_log=$host_dir/${service}.log
  mkdir -p "$host_dir"
  rm -f "$server_log"

  local command="exec env BNFS_RELAY_INCLUDE_INDEX=0 /opt/bnfs/tunserver -index index:9000 -target 127.0.0.1:8080"
  if [[ -n $relay ]]; then
    command+=" -relay $relay"
  fi
  if [[ -n ${BNFS_CHAOS_NAT_CA_URL:-} ]]; then
    command+=" -ca $BNFS_CHAOS_NAT_CA_URL"
  fi
  if [[ -n ${BNFS_CHAOS_NAT_KEY_DIR:-} ]]; then
    command+=" -key $BNFS_CHAOS_NAT_KEY_DIR/$service.key"
    command+=" -billing-private-snapshot $BNFS_CHAOS_NAT_KEY_DIR/billing-meter.json"
  fi
  command+=" > '$inside_dir/${service}.log' 2>&1"
  dc exec -T -d "$service" sh -lc "$command"

  if ! wait_file_pattern "$server_log" '服务端已就绪' 25; then
    log_step "$service Tunnel Server 未就绪"
    [[ -f $server_log ]] && tail -n 80 "$server_log" >&2
    return 1
  fi
  awk '/本节点 ID:/{print $NF; exit}' "$server_log"
}

stop_nat_process() {
  local service=$1 process_name=$2
  dc exec -T "$service" sh -lc "
    pkill -TERM -x '$process_name' >/dev/null 2>&1 || true
    attempt=0
    while pgrep -x '$process_name' >/dev/null 2>&1 && [ \"\$attempt\" -lt 30 ]; do
      sleep 0.1
      attempt=\$((attempt + 1))
    done
    pkill -KILL -x '$process_name' >/dev/null 2>&1 || true
    attempt=0
    while pgrep -x '$process_name' >/dev/null 2>&1 && [ \"\$attempt\" -lt 20 ]; do
      sleep 0.1
      attempt=\$((attempt + 1))
    done
    if pgrep -x '$process_name' >/dev/null 2>&1; then
      ps -eo pid,stat,comm,args | awk -v name='$process_name' '\$3 == name { print }' >&2
      exit 1
    fi
  " </dev/null
}

restart_tunnel_server() {
  local service=$1 relay=$2 scenario=$3
  stop_nat_process "$service" tunserver || return 1
  launch_tunnel_server "$service" "$relay" "$scenario"
}

start_tunnel_server() {
  local service=$1 relay=$2 scenario=$3 size_mb=${4:-1}
  local max_size_mb=${5:-$size_mb}
  local send_rate_mibps=${6:-0}
  start_http_file_server "$service" "$relay" "$scenario" "$size_mb" "$max_size_mb" "$send_rate_mibps" || return 1
  launch_tunnel_server "$service" "$relay" "$scenario"
}

random_probe_size_mib() {
  local random_value
  random_value=$(od -An -N4 -tu4 /dev/urandom | tr -d '[:space:]')
  [[ $random_value =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$((random_value % 101 + 100))"
}

large_probe_once() {
  local run_dir=$1 server=$2 client=$3 listen_port=$4 label=$5
  local requested_mib expected_size expected_sha result actual_size=0 actual_sha= rc=0 sha_ok=no
  local started_ns ended_ns elapsed throughput timestamp inside_file=/artifacts/large-probe.bin
  local limit_rate=${LARGE_PROBE_LIMIT_RATE:-0}
  local rate_option=

  [[ $limit_rate == 0 || $limit_rate =~ ^[1-9][0-9]*[kKmMgG]$ ]] || {
    log_step "无效的大文件探测速率上限: $limit_rate"
    return 1
  }
  [[ $limit_rate == 0 ]] || rate_option="--limit-rate '$limit_rate'"

  requested_mib=$(random_probe_size_mib) || return 1
  expected_size=$((requested_mib * 1024 * 1024))
  expected_sha=$(dc exec -T "$server" curl -fsS --max-time 120 \
    "http://127.0.0.1:8080/checksum?size_mb=$requested_mib" | tr -d '[:space:]') || rc=$?
  [[ $expected_sha =~ ^[[:xdigit:]]{64}$ ]] || rc=1

  started_ns=$(date +%s%N)
  if (( rc == 0 )); then
    result=$(dc exec -T "$client" sh -lc \
      "set -e; rm -f '$inside_file'; curl -fsS $rate_option --max-time 900 -o '$inside_file' 'http://127.0.0.1:$listen_port/file?size_mb=$requested_mib'; size=\$(stat -c %s '$inside_file'); sha=\$(sha256sum '$inside_file' | awk '{print \$1}'); printf '%s\\t%s\\n' \"\$size\" \"\$sha\"" \
      2> "$run_dir/large-probe-curl.err") || rc=$?
    if (( rc == 0 )); then
      IFS=$'\t' read -r actual_size actual_sha <<< "$result"
      if [[ $actual_size == "$expected_size" && $actual_sha == "$expected_sha" ]]; then
        sha_ok=yes
      else
        rc=1
      fi
    fi
  fi
  ended_ns=$(date +%s%N)
  elapsed=$(awk -v start="$started_ns" -v end="$ended_ns" 'BEGIN {printf "%.6f", (end-start)/1000000000}')
  throughput=$(LC_ALL=C awk -v b="${actual_size:-0}" -v s="$elapsed" \
    'BEGIN {rate = 0; if (s > 0) rate = b / 1048576 / s; printf "%.3f\n", rate}')
  [[ -n $throughput ]] || throughput=0.000
  timestamp=$(date --iso-8601=seconds)
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$timestamp" "$label" "$requested_mib" "$rc" "${actual_size:-0}" "$elapsed" "$throughput" \
    "$sha_ok" "$client" "$expected_sha" "$actual_sha" >> "$run_dir/large-probes.tsv"
  rm -f "$run_dir/runtime/large-probe.bin"
  [[ $rc -eq 0 && $sha_ok == yes ]]
}

write_transfer_record_atomic() {
  local record_file=$1 timestamp=$2 transfer_id=$3 client=$4 ingress_relay=$5 server=$6
  local requested_mib=$7 rc=$8 bytes=$9 seconds=${10} throughput=${11} sha_ok=${12}
  local expected_sha=${13-} actual_sha=${14-} temporary=$1.tmp.$BASHPID

  if ! printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$timestamp" "$transfer_id" "$client" "$ingress_relay" "$server" "$requested_mib" "$rc" \
    "$bytes" "$seconds" "$throughput" "$sha_ok" "$expected_sha" "$actual_sha" > "$temporary"; then
    rm -f "$temporary"
    return 1
  fi
  if ! mv -f -- "$temporary" "$record_file"; then
    rm -f "$temporary"
    return 1
  fi
}

random_transfer_once() {
	local run_dir=$1 scenario=$2 server=$3 client=$4 ingress_relay=$5 listen_port=$6 transfer_id=$7 record_file=$8
	local requested_mib_override=${9:-}
	local attempt_deadline_epoch=${10:-}
	local requested_mib expected_size expected_sha result actual_size=0 actual_sha= rc=0 sha_ok=no
  local curl_seconds= step_timeout
  local started_ns ended_ns elapsed throughput timestamp
  local inside_file=/tmp/bnfs-${client}-${transfer_id}.bin
  local error_file=$run_dir/transfer-errors/${client}-${transfer_id}.log

  mkdir -p "$run_dir/transfer-errors" "$(dirname "$record_file")"
	if [[ $requested_mib_override =~ ^(100|1[0-9][0-9]|200)$ ]]; then
		requested_mib=$requested_mib_override
	else
		requested_mib=$(random_probe_size_mib) || return 1
	fi
	if [[ -z $attempt_deadline_epoch ]]; then
		attempt_deadline_epoch=$(( $(date +%s) + 900 ))
	fi
	[[ $attempt_deadline_epoch =~ ^[1-9][0-9]*$ ]] || return 1
  started_ns=$(date +%s%N)
	timestamp=$(date --iso-8601=seconds)
	write_transfer_record_atomic "$record_file" "$timestamp" "$transfer_id" "$client" \
		"$ingress_relay" "$server" "$requested_mib" 125 0 0.000000 0.000 not-run '' '' || return 1
  expected_size=$((requested_mib * 1024 * 1024))
  if step_timeout=$(deadline_step_timeout_seconds "$attempt_deadline_epoch" 120); then
    expected_sha=$(dc exec -T "$server" curl -fsS --max-time "$step_timeout" \
      "http://127.0.0.1:8080/checksum?size_mb=$requested_mib" | tr -d '[:space:]') || rc=$?
    if (( rc == 0 )) && [[ ! $expected_sha =~ ^[[:xdigit:]]{64}$ ]]; then
      rc=1
    fi
  else
    rc=28
  fi

  if (( rc == 0 )); then
    if step_timeout=$(deadline_step_timeout_seconds "$attempt_deadline_epoch" 900); then
      printf 'attempt_deadline_epoch=%s\ntransfer_timeout_seconds=%s\n' \
        "$attempt_deadline_epoch" "$step_timeout" > "$error_file"
      result=$(dc exec -T "$client" sh -lc \
        "rm -f '$inside_file'; transfer_rc=0; transfer_seconds=\$(curl -fsS --max-time '$step_timeout' -w '%{time_total}' -o '$inside_file' 'http://127.0.0.1:$listen_port/file?size_mb=$requested_mib') || transfer_rc=\$?; size=\$(stat -c %s '$inside_file' 2>/dev/null || printf 0); sha=\$(sha256sum '$inside_file' 2>/dev/null | awk '{print \$1}'); rm -f '$inside_file'; printf '%s\\t%s\\t%s\\n' \"\$size\" \"\$sha\" \"\$transfer_seconds\"; exit \"\$transfer_rc\"" \
        2>> "$error_file") || rc=$?
      IFS=$'\t' read -r actual_size actual_sha curl_seconds <<< "$result"
      [[ $actual_size =~ ^[0-9]+$ ]] || actual_size=0
      if (( rc == 0 )) && [[ $actual_size == "$expected_size" && $actual_sha == "$expected_sha" ]]; then
        sha_ok=yes
      elif (( rc == 0 )); then
        rc=1
      fi
    else
      rc=28
    fi
  fi
  ended_ns=$(date +%s%N)
  elapsed=$(awk -v start="$started_ns" -v end="$ended_ns" 'BEGIN {printf "%.6f", (end-start)/1000000000}')
  if [[ $curl_seconds =~ ^[0-9]+([.][0-9]+)?$ ]] \
    && awk -v seconds="$curl_seconds" 'BEGIN { exit !(seconds > 0) }'; then
    elapsed=$curl_seconds
  fi
  throughput=$(LC_ALL=C awk -v b="${actual_size:-0}" -v s="$elapsed" \
    'BEGIN {rate = 0; if (s > 0) rate = b / 1048576 / s; printf "%.3f\n", rate}')
  timestamp=$(date --iso-8601=seconds)
  write_transfer_record_atomic "$record_file" "$timestamp" "$transfer_id" "$client" \
    "$ingress_relay" "$server" "$requested_mib" "$rc" "${actual_size:-0}" "$elapsed" \
    "$throughput" "$sha_ok" "$expected_sha" "$actual_sha" || return 1
  if (( rc == 0 )) && [[ $sha_ok == yes ]]; then
    return 0
  fi
  (( rc >= 1 && rc <= 255 )) || rc=1
  return "$rc"
}

launch_tunnel_client() {
  local service=$1 relay=$2 target_id=$3 listen_port=$4 scenario=$5
  local host_dir=$RUNTIME_DIR/$scenario inside_dir=/artifacts/$scenario
  local client_log=$host_dir/${service}.log
  mkdir -p "$host_dir"
  rm -f "$client_log"
  local command="exec env BNFS_RELAY_INCLUDE_INDEX=0 /opt/bnfs/tunclient -index index:9000 -target $target_id -listen 127.0.0.1:$listen_port"
  if [[ -n $relay ]]; then
    command+=" -relay $relay"
  fi
  if [[ -n ${BNFS_CHAOS_NAT_CA_URL:-} ]]; then
    command+=" -ca $BNFS_CHAOS_NAT_CA_URL"
  fi
  if [[ -n ${BNFS_CHAOS_NAT_KEY_DIR:-} ]]; then
    command+=" -key $BNFS_CHAOS_NAT_KEY_DIR/$service.key"
  fi
  command+=" > '$inside_dir/${service}.log' 2>&1"
  dc exec -T -d "$service" sh -lc "$command"
}

wait_client_ready() {
  local service=$1 scenario=$2 timeout_seconds=${3:-45}
  local client_log=$RUNTIME_DIR/$scenario/${service}.log deadline remaining
  deadline=$((SECONDS + timeout_seconds))
  if ! wait_file_pattern "$client_log" '已建立隧道连接' "$timeout_seconds"; then
    return 1
  fi
  remaining=$((deadline - SECONDS))
  (( remaining > 0 )) || return 1
  wait_file_pattern "$client_log" '本地监听:' "$remaining"
}

detect_client_entry_relay() {
  local service=$1 peer relay relay_ip
  peer=$(netns_exec "$service" ss -Hnt state established 2>/dev/null \
    | awk '$NF ~ /:9000$/ {print $NF; exit}')
  peer=${peer%:9000}
  peer=${peer#\[}
  peer=${peer%\]}
  [[ -n $peer ]] || return 1
  for relay in relay01 relay02 relay03 relay04 relay05 relay06 relay07; do
    relay_ip=$(dc exec -T "$service" getent ahostsv4 "$relay" 2>/dev/null | awk 'NR==1 {print $1}')
    if [[ -n $relay_ip && $peer == "$relay_ip" ]]; then
      printf '%s\n' "$relay"
      return 0
    fi
  done
  return 1
}

wait_client_entry_relay() {
  local service=$1 timeout_seconds=${2:-5} deadline relay
  deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    relay=$(detect_client_entry_relay "$service" 2>/dev/null || true)
    if [[ $relay =~ ^relay0[1-7]$ ]]; then
      printf '%s\n' "$relay"
      return 0
    fi
    sleep 0.25
  done
  return 1
}

block_relay() {
  local service=$1 relay=$2 ip
  ip=$(dc exec -T "$service" getent ahostsv4 "$relay" | awk 'NR==1{print $1}')
  [[ -n $ip ]] || return 1
  netns_exec "$service" iptables -I OUTPUT 1 -d "$ip" -p tcp --dport 9000 -j REJECT
  netns_exec "$service" iptables -I OUTPUT 1 -d "$ip" -p udp --dport 9000 -j REJECT
}

disconnect_relay_path() {
  local service=$1 relay=$2 ip
  ip=$(dc exec -T "$service" getent ahostsv4 "$relay" | awk 'NR==1{print $1}')
  [[ -n $ip ]] || return 1
  block_relay "$service" "$relay" || return 1

  # Packet rejection alone does not invalidate an established TCP socket: a
  # write can still enter the local send buffer and delay failover detection.
  # Destroy only this NAT namespace's sockets to the old Relay so the existing
  # registration/business legs observe a real disconnect while the Relay
  # container itself keeps running for the entire soak test.
  if ! netns_exec "$service" ss -K dst "$ip" dport = :9000 >/dev/null 2>&1; then
    log_step "无法销毁现存 Relay socket: $service -> $relay($ip):9000"
    return 1
  fi
}

unblock_relay() {
  local service=$1 relay=$2 ip
  ip=$(dc exec -T "$service" getent ahostsv4 "$relay" | awk 'NR==1{print $1}')
  [[ -n $ip ]] || return 0
  netns_exec "$service" iptables -D OUTPUT -d "$ip" -p tcp --dport 9000 -j REJECT >/dev/null 2>&1 || true
  netns_exec "$service" iptables -D OUTPUT -d "$ip" -p udp --dport 9000 -j REJECT >/dev/null 2>&1 || true
}

start_limited_download() {
  local service=$1 listen_port=$2 scenario=$3 rate=${4:-256k} max_time=${5:-90}
  local inside_dir=/artifacts/$scenario
  rm -f "$RUNTIME_DIR/$scenario/download.bin" "$RUNTIME_DIR/$scenario/curl.rc"
  dc exec -T -d "$service" sh -lc \
    "rc=0; curl -fsS --limit-rate '$rate' --max-time '$max_time' -o '$inside_dir/download.bin' 'http://127.0.0.1:$listen_port/file' || rc=\$?; printf '%s\\n' \"\$rc\" > '$inside_dir/curl.rc'"
}

capture_topology_logs() {
  local scenario=$1
  dc logs --no-color > "$RUNTIME_DIR/$scenario/compose.log" 2>&1 || true
  local container_ids
  container_ids=$(dc ps -q | tr '\n' ' ')
  if [[ -n $container_ids ]]; then
    docker stats --no-stream --format \
      'name={{.Name}} cpu={{.CPUPerc}} memory={{.MemUsage}} pids={{.PIDs}}' \
      $container_ids > "$RUNTIME_DIR/$scenario/container-stats.txt" 2>&1 || true
  fi
  {
    uptime
    free -h
    printf 'running_containers='
    dc ps -q | wc -l
  } > "$RUNTIME_DIR/$scenario/host-stats.txt" 2>&1 || true
}
