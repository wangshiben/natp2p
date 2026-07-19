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

relay02_has_registration() {
  local prefix=${1:0:16}
  dc logs --no-color relay02 2>&1 | awk -v prefix="$prefix" '
    index($0, prefix) && ($0 ~ /新建 StreamGroup/ || $0 ~ /附加 relay leg/) { found=1 }
    END { exit !found }
  '
}

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

source_checksum=$(dc exec -T natserver02 curl -fsS http://127.0.0.1:8080/checksum | tr -d '[:space:]')
if [[ ! $source_checksum =~ ^[[:xdigit:]]{64}$ ]]; then
  fail '无法取得源文件 SHA256，不能验证 Relay 迁移后的数据完整性'
  capture_topology_logs "$scenario"
  exit 1
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
client_id=$(awk '/本节点 ID:/{print $NF; exit}' "$scenario_dir/natclient04.log")
if [[ ! $client_id =~ ^[[:xdigit:]]{64}$ ]]; then
  fail '无法取得 NatClient NodeID，不能验证 Relay 侧真实注册'
  capture_topology_logs "$scenario"
  exit 1
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
assert_reachable natserver02 relay02 9000 || fail '解除屏蔽后 NatServer 仍无法直连 relay02'
assert_reachable natclient04 relay02 9000 || fail '解除屏蔽后 NatClient 仍无法直连 relay02'

deadline=$((SECONDS + 45))
server_migrated=0
client_migrated=0
while (( SECONDS < deadline )); do
  relay02_has_registration "$server_id" && server_migrated=1
  relay02_has_registration "$client_id" && client_migrated=1
  if (( server_migrated == 1 && client_migrated == 1 )); then
    break
  fi
  sleep 1
done

if (( server_migrated == 1 )); then
  pass "NatServer 已在 relay02 建立空 ConnectionId 注册（地址 $relay02_server_ip:9000）"
else
  fail 'NatServer 在 45 秒内没有在 relay02 建立真实注册 group'
fi
if (( client_migrated == 1 )); then
  pass "NatClient 已在 relay02 建立空 ConnectionId 注册（地址 $relay02_client_ip:9000）"
else
  fail 'NatClient 在 45 秒内没有在 relay02 建立真实注册 group'
fi

if (( server_migrated == 1 && client_migrated == 1 )); then
  if wait_file_exists "$scenario_dir/curl.rc" 70 \
    && [[ $(tr -d '[:space:]' < "$scenario_dir/curl.rc") == 0 ]]; then
    received_size=$(stat -c %s "$scenario_dir/download.bin" 2>/dev/null || printf '0')
    received_checksum=$(sha256sum "$scenario_dir/download.bin" 2>/dev/null | awk '{print $1}')
    if [[ $received_size == 52428800 && $received_checksum == "$source_checksum" ]]; then
      pass 'Relay 切换后原传输恢复，50MiB 文件大小与 SHA256 均一致'
    else
      fail "Relay 切换后的文件不完整: size=$received_size sha=$received_checksum"
    fi
  else
    fail 'Relay 已迁移，但原业务传输没有恢复'
  fi
else
  dc exec -T natclient04 pkill -f 'curl .*18084/file' >/dev/null 2>&1 || true
  fail '入口未迁移，业务传输不具备恢复条件'
fi

capture_topology_logs "$scenario"
exit "$failures"
