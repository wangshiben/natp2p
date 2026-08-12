#!/usr/bin/env bash

set -uo pipefail
source "${ROOT_DIR:?}/test/runtimeScript/local-chaos/lib.sh"

scenario=05_multi_relay_service
scenario_dir=$RUNTIME_DIR/$scenario
failures=0
mkdir -p "$scenario_dir"

fail() {
  printf '[scenario-5] FAIL: %s\n' "$*" >&2
  failures=$((failures + 1))
}

pass() {
  printf '[scenario-5] PASS: %s\n' "$*"
}

if ! topology_reset; then
  exit 1
fi

export BNFS_CHAOS_NAT_KEY_DIR=/artifacts/.private
server_id=$(start_tunnel_server natserver02 'relay01:9000,relay02:9000' "$scenario" 4) || {
  fail '多 Relay Tunnel Server 启动失败'
  capture_topology_logs "$scenario"
  exit 1
}
server_prefix=${server_id:0:16}

for relay in relay01 relay02; do
  if wait_compose_log "$relay" "$server_prefix" 15; then
    pass "同一 NatServer NodeID 已注册到 $relay"
  else
    fail "$relay 未观察到 NatServer carrier"
  fi
done

launch_tunnel_client natclient01 relay01:9000 "$server_id" 18101 "$scenario"
launch_tunnel_client natclient04 relay02:9000 "$server_id" 18102 "$scenario"
launch_tunnel_client natserver01 relay03:9000 "$server_id" 18103 "$scenario"

for client in natclient01 natclient04 natserver01; do
  if wait_client_ready "$client" "$scenario" 45; then
    pass "$client 已经由独立入口建立服务会话"
  else
    fail "$client 多 Relay 服务会话未就绪"
  fi
done

source_checksum=$(dc exec -T natserver02 curl -fsS 'http://127.0.0.1:8080/checksum?size_mb=4' | tr -d '[:space:]')
pids=()
for pair in 'natclient01 18101' 'natclient04 18102' 'natserver01 18103'; do
  read -r client port <<< "$pair"
  dc exec -T "$client" curl -fsS --max-time 50 "http://127.0.0.1:$port/file?size_mb=4" > "$scenario_dir/$client.bin" &
  pids+=("$!")
done
for index in 0 1 2; do
  client=(natclient01 natclient04 natserver01)
  rc=0
  wait "${pids[$index]}" || rc=$?
  file=$scenario_dir/${client[$index]}.bin
  size=$(stat -c %s "$file" 2>/dev/null || printf '0')
  checksum=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
  if (( rc == 0 )) && [[ $size == 4194304 && $checksum == "$source_checksum" ]]; then
    pass "${client[$index]} 并发 4MiB 传输大小与 SHA256 一致"
  else
    fail "${client[$index]} 传输失败: rc=$rc size=$size sha=$checksum"
  fi
done

status_file=$RUNTIME_DIR/.private/natserver02/service-listener.json
if wait_file_pattern "$status_file" '"activeSessions":3' 10 \
  && node --input-type=module - "$status_file" <<'NODE'
import fs from 'node:fs';
const status = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const carriers = status.carriers ?? [];
const relays = new Set(carriers.filter((carrier) => carrier.connected).map((carrier) => carrier.relayAddress));
if (carriers.length !== 2 || !relays.has('relay01:9000') || !relays.has('relay02:9000')) process.exit(1);
if (status.activeSessions !== 3 || (status.sessions ?? []).length !== 3) process.exit(1);
NODE
then
  pass '状态快照展示两个健康 carrier 与三个独立会话'
else
  fail '多 Relay 状态快照不正确'
fi

dc stop --timeout 1 relay01 >/dev/null
if dc exec -T natclient04 curl -fsS --max-time 15 http://127.0.0.1:18102/health | grep -q 'ok'; then
  pass 'relay01 下线未影响 relay02 上的既有会话'
else
  fail 'relay01 下线错误中断了 relay02 会话'
fi

stop_nat_process natclient04 tunclient || fail '无法停止 relay02 客户端'
launch_tunnel_client natclient04 relay02:9000 "$server_id" 18102 "$scenario"
if wait_client_ready natclient04 "$scenario" 35 \
  && dc exec -T natclient04 curl -fsS --max-time 15 http://127.0.0.1:18102/health | grep -q 'ok'; then
  pass '目标 Relay 下线后，新会话仍可经健康 carrier 建立'
else
  fail '目标 Relay 下线后，新会话未能经健康 carrier 建立'
fi

capture_topology_logs "$scenario"
exit "$failures"
