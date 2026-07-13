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
  log_step "重建 1 Index + 9 Relay + 27 NAT 容器拓扑"
  dc down --remove-orphans --timeout 3 >/dev/null 2>&1 || true
  dc up -d --remove-orphans >/dev/null 2>&1

  local service container_id health deadline
  deadline=$((SECONDS + 45))
  for service in index relay01 relay02 relay03 relay04 relay05 relay06 relay07 relay08 relay09; do
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

  for service in relay01 relay02 relay03 relay04 relay05 relay06 relay07 relay08 relay09; do
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

start_tunnel_server() {
  local service=$1 relay=$2 scenario=$3 size_mb=${4:-1}
  local host_dir=$RUNTIME_DIR/$scenario inside_dir=/artifacts/$scenario
  local http_log=$host_dir/${service}-http.log server_log=$host_dir/${service}.log
  mkdir -p "$host_dir"
  rm -f "$http_log" "$server_log"

  dc exec -T -d "$service" sh -lc \
    "exec /opt/bnfs/httpfileserver -port 8080 -size $size_mb > '$inside_dir/${service}-http.log' 2>&1"
  if ! wait_file_pattern "$http_log" 'HTTP 文件服务器监听:' 15; then
    log_step "$service HTTP 源未启动"
    return 1
  fi

  local command="exec env BNFS_RELAY_INCLUDE_INDEX=0 /opt/bnfs/tunserver -index index:9000 -target 127.0.0.1:8080"
  if [[ -n $relay ]]; then
    command+=" -relay $relay"
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
  command+=" > '$inside_dir/${service}.log' 2>&1"
  dc exec -T -d "$service" sh -lc "$command"
}

wait_client_ready() {
  local service=$1 scenario=$2 timeout_seconds=${3:-45}
  local client_log=$RUNTIME_DIR/$scenario/${service}.log
  if ! wait_file_pattern "$client_log" '已建立隧道连接' "$timeout_seconds"; then
    return 1
  fi
  wait_file_pattern "$client_log" '本地监听:' 10
}

block_relay() {
  local service=$1 relay=$2 ip
  ip=$(dc exec -T "$service" getent ahostsv4 "$relay" | awk 'NR==1{print $1}')
  [[ -n $ip ]] || return 1
  netns_exec "$service" iptables -I OUTPUT 1 -d "$ip" -p tcp --dport 9000 -j REJECT
  netns_exec "$service" iptables -I OUTPUT 1 -d "$ip" -p udp --dport 9000 -j REJECT
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
