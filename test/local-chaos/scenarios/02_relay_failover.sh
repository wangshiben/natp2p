#!/usr/bin/env bash

set -uo pipefail
source "${ROOT_DIR:?}/test/local-chaos/lib.sh"

scenario=02_relay_failover
scenario_dir=$RUNTIME_DIR/$scenario
mkdir -p "$scenario_dir"
failures=0

fail() {
  printf '[scenario-2] FAIL: %s\n' "$*" >&2
  failures=$((failures + 1))
}

pass() {
  printf '[scenario-2] PASS: %s\n' "$*"
}

if ! topology_reset; then
  exit 1
fi

block_relay natserver02 relay02 || fail '无法在 NatServer 上预先屏蔽 relay02'
block_relay natclient04 relay02 || fail '无法在 NatClient 上预先屏蔽 relay02'
relay01_server_ip=$(dc exec -T natserver02 getent ahostsv4 relay01 | awk 'NR==1{print $1}')
relay01_client_ip=$(dc exec -T natclient04 getent ahostsv4 relay01 | awk 'NR==1{print $1}')
relay02_server_ip=$(dc exec -T natserver02 getent ahostsv4 relay02 | awk 'NR==1{print $1}')
relay02_client_ip=$(dc exec -T natclient04 getent ahostsv4 relay02 | awk 'NR==1{print $1}')

server_id=$(start_tunnel_server natserver02 '' "$scenario" 50) || {
  fail '自动选择 Tunnel Server 启动失败'
  capture_topology_logs "$scenario"
  exit 1
}
if grep -q "注册到 relay: $relay01_server_ip:9000" "$scenario_dir/natserver02.log"; then
  pass 'NatServer 初始入口固定为 relay01'
else
  fail 'NatServer 初始入口不是 relay01'
fi

launch_tunnel_client natclient04 '' "$server_id" 18084 "$scenario"
if ! wait_client_ready natclient04 "$scenario" 40; then
  fail '故障注入前隧道未建立'
  capture_topology_logs "$scenario"
  exit 1
fi
if grep -q "注册到 relay: $relay01_client_ip:9000" "$scenario_dir/natclient04.log"; then
  pass 'NatClient 初始入口固定为 relay01'
else
  fail 'NatClient 初始入口不是 relay01'
fi

start_limited_download natclient04 18084 "$scenario" 1m 120
if ! wait_file_size "$scenario_dir/download.bin" 65536 20; then
  fail 'Relay 下线前没有产生有效业务流量'
  capture_topology_logs "$scenario"
  exit 1
fi

pass '传输进行中，停止当前入口 relay01'
dc stop --timeout 1 relay01 >/dev/null
unblock_relay natserver02 relay02
unblock_relay natclient04 relay02

deadline=$((SECONDS + 45))
server_migrated=0
client_migrated=0
while (( SECONDS < deadline )); do
  grep -q "注册到 relay: $relay02_server_ip:9000" "$scenario_dir/natserver02.log" && server_migrated=1
  grep -q "注册到 relay: $relay02_client_ip:9000" "$scenario_dir/natclient04.log" && client_migrated=1
  if (( server_migrated == 1 && client_migrated == 1 )); then
    break
  fi
  sleep 1
done

if (( server_migrated == 1 )); then
  pass 'NatServer 自动迁移到 relay02'
else
  fail 'NatServer 在 45 秒内没有重新 Bootstrap 到 relay02'
fi
if (( client_migrated == 1 )); then
  pass 'NatClient 自动迁移到 relay02'
else
  fail 'NatClient 在 45 秒内没有重新 Bootstrap 到 relay02'
fi

if (( server_migrated == 1 && client_migrated == 1 )); then
  if wait_file_exists "$scenario_dir/curl.rc" 70 \
    && [[ $(tr -d '[:space:]' < "$scenario_dir/curl.rc") == 0 ]] \
    && [[ $(stat -c %s "$scenario_dir/download.bin" 2>/dev/null || printf '0') == 52428800 ]]; then
    pass 'Relay 切换后原传输恢复并完成'
  else
    fail 'Relay 已迁移，但原业务传输没有恢复'
  fi
else
  dc exec -T natclient04 pkill -f 'curl .*18084/file' >/dev/null 2>&1 || true
  fail '入口未迁移，业务传输不具备恢复条件'
fi

capture_topology_logs "$scenario"
exit "$failures"
