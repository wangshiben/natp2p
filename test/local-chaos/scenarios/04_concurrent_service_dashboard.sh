#!/usr/bin/env bash

set -uo pipefail
source "${ROOT_DIR:?}/test/local-chaos/lib.sh"

scenario=04_concurrent_service_dashboard
scenario_dir=$RUNTIME_DIR/$scenario
dashboard_port=18912
dashboard_pid=
failures=0
mkdir -p "$scenario_dir"

fail() {
  printf '[scenario-4] FAIL: %s\n' "$*" >&2
  failures=$((failures + 1))
}

pass() {
  printf '[scenario-4] PASS: %s\n' "$*"
}

cleanup_dashboard() {
  if [[ $dashboard_pid =~ ^[1-9][0-9]*$ ]]; then
    kill -TERM "$dashboard_pid" >/dev/null 2>&1 || true
    wait "$dashboard_pid" 2>/dev/null || true
  fi
}
trap cleanup_dashboard EXIT

if ! topology_reset; then
  exit 1
fi

export BNFS_CHAOS_NAT_KEY_DIR=/artifacts/.private
server_id=$(start_tunnel_server natserver02 relay01:9000 "$scenario" 2) || {
  fail 'Tunnel Server 启动失败'
  capture_topology_logs "$scenario"
  exit 1
}
launch_tunnel_client natclient01 relay01:9000 "$server_id" 18091 "$scenario"
launch_tunnel_client natclient02 relay01:9000 "$server_id" 18092 "$scenario"

for client in natclient01 natclient02; do
  if wait_client_ready "$client" "$scenario" 40; then
    pass "$client 已建立独立服务会话"
  else
    fail "$client 未建立服务会话"
  fi
done

source_checksum=$(dc exec -T natserver02 curl -fsS http://127.0.0.1:8080/checksum | tr -d '[:space:]')
dc exec -T natclient01 curl -fsS --max-time 40 http://127.0.0.1:18091/file > "$scenario_dir/natclient01.bin" &
client_one_pid=$!
dc exec -T natclient02 curl -fsS --max-time 40 http://127.0.0.1:18092/file > "$scenario_dir/natclient02.bin" &
client_two_pid=$!
client_one_rc=0
client_two_rc=0
wait "$client_one_pid" || client_one_rc=$?
wait "$client_two_pid" || client_two_rc=$?
for client in natclient01 natclient02; do
  file=$scenario_dir/$client.bin
  checksum=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
  size=$(stat -c %s "$file" 2>/dev/null || printf '0')
  rc=$client_one_rc
  [[ $client == natclient02 ]] && rc=$client_two_rc
  if (( rc == 0 )) && [[ $size == 2097152 && $checksum == "$source_checksum" ]]; then
    pass "$client 并发 2MiB 传输大小与 SHA256 一致"
  else
    fail "$client 并发传输失败: rc=$rc size=$size sha=$checksum"
  fi
done

status_file=$RUNTIME_DIR/.private/natserver02/service-listener.json
if wait_file_pattern "$status_file" '"activeSessions":2' 10; then
  pass 'NatServer carrier 保持注册且同时承载 2 条活跃会话'
else
  fail 'ServiceListener 状态未观察到 2 条活跃会话'
fi

client_one_id=$(awk '/本节点 ID:/{print $NF; exit}' "$scenario_dir/natclient01.log")
client_two_id=$(awk '/本节点 ID:/{print $NF; exit}' "$scenario_dir/natclient02.log")
cat > "$scenario_dir/nat-identities.tsv" <<EOF
service	role	node_id	ingress_relay	credited
natclient01	natclient	$client_one_id	relay01	yes
natclient02	natclient	$client_two_id	relay01	yes
natserver02	natserver	$server_id	relay01	yes
EOF

if ss -ltnH "sport = :$dashboard_port" | grep -q .; then
  fail "Dashboard 测试端口 $dashboard_port 已被占用"
else
  HOST=127.0.0.1 PORT=$dashboard_port RUN_DIR="$scenario_dir" \
    PRIVATE_RUNTIME_DIR="$RUNTIME_DIR/.private" COMPOSE_PROJECT="$COMPOSE_PROJECT" \
    COMPOSE_FILE="$COMPOSE_FILE" \
    node "$ROOT_DIR/test/local-chaos/monitor/server.mjs" > "$scenario_dir/dashboard.log" 2>&1 &
  dashboard_pid=$!
  if wait_file_pattern "$scenario_dir/dashboard.log" 'BNFS stability dashboard listening' 10 \
    && curl -fsS --max-time 5 "http://127.0.0.1:$dashboard_port/api/status?fresh=1" \
      > "$scenario_dir/dashboard-status.json"; then
    if node --input-type=module - "$scenario_dir/dashboard-status.json" <<'NODE'
import fs from 'node:fs';
const status = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const sessions = status.serviceSessions?.sessions ?? [];
const expected = new Set(['natclient01', 'natclient02']);
if (status.serviceSessions?.summary?.activeSessions !== 2 || sessions.length !== 2) process.exit(1);
for (const session of sessions) {
  if (!expected.delete(session.client) || session.server !== 'natserver02' || session.relay !== 'relay01') process.exit(1);
  if (!/^[0-9a-f]{8}$/.test(session.connectionID)) process.exit(1);
}
if (expected.size !== 0 || sessions[0].connectionID === sessions[1].connectionID) process.exit(1);
NODE
    then
      pass 'Dashboard API 展示 2 条唯一 NatClient→relay01→natserver02 会话路径'
    else
      fail 'Dashboard API 并发服务会话内容不正确'
    fi
    if curl -fsS --max-time 5 "http://127.0.0.1:$dashboard_port/" > "$scenario_dir/dashboard.html" \
      && grep -q 'NatServer 持久注册与并发服务会话' "$scenario_dir/dashboard.html"; then
      pass 'Dashboard 页面包含并发服务会话监控区域'
    else
      fail 'Dashboard 页面缺少并发服务会话监控区域'
    fi
  else
    fail 'Dashboard 测试实例未正常启动或 API 不可用'
  fi
fi

capture_topology_logs "$scenario"
exit "$failures"
