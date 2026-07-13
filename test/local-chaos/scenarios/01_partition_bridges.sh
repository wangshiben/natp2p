#!/usr/bin/env bash

set -uo pipefail
source "${ROOT_DIR:?}/test/local-chaos/lib.sh"

scenario=01_partition_bridges
scenario_dir=$RUNTIME_DIR/$scenario
mkdir -p "$scenario_dir"
failures=0

fail() {
  printf '[scenario-1] FAIL: %s\n' "$*" >&2
  failures=$((failures + 1))
}

pass() {
  printf '[scenario-1] PASS: %s\n' "$*"
}

if ! topology_reset; then
  exit 1
fi

assert_unreachable index relay03 9000 && pass 'Index 无法直连分区内 relay03' || fail 'Index 意外可达 relay03'
assert_reachable relay01 relay03 9000 && pass '桥接 relay01 可以直连 relay03' || fail '桥接 relay01 无法到达 relay03'
assert_unreachable natclient03 relay03 9000 && pass '分区 B 的 NAT 无法直连 relay03' || fail '分区隔离未生效'
assert_reachable natclient03 relay04 9000 && pass '分区 B 的 NAT 可以直连本区 relay04' || fail 'NAT 无法连接本区 relay04'

direct_id=$(start_tunnel_server natserver01 relay03:9000 "$scenario" 1) || {
  fail '直接路径 Tunnel Server 启动失败'
  capture_topology_logs "$scenario"
  exit 1
}
launch_tunnel_client natclient01 relay03:9000 "$direct_id" 18081 "$scenario"
if wait_client_ready natclient01 "$scenario" 35 \
  && dc exec -T natclient01 curl -fsS --max-time 10 http://127.0.0.1:18081/health | grep -q 'ok'; then
  pass '同一分区、同一 Relay 的 NAT 节点可以通信'
else
  fail '同一分区直连业务失败'
fi

bridge_id=$(start_tunnel_server natserver04 relay03:9000 "$scenario" 1) || {
  fail '桥接路径 Tunnel Server 启动失败'
  capture_topology_logs "$scenario"
  exit 1
}
launch_tunnel_client natclient02 relay01:9000 "$bridge_id" 18082 "$scenario"
if wait_client_ready natclient02 "$scenario" 40 \
  && dc exec -T natclient02 curl -fsS --max-time 10 http://127.0.0.1:18082/health | grep -q 'ok'; then
  pass '唯一桥接 Relay relay01 可以连接入口分区与 relay03 托管节点'
else
  fail '桥接 Relay 未能完成跨 Relay 连接'
fi

isolated_id=$(start_tunnel_server natserver05 relay03:9000 "$scenario" 1) || {
  fail '隔离目标 Tunnel Server 启动失败'
  capture_topology_logs "$scenario"
  exit 1
}
launch_tunnel_client natclient03 relay04:9000 "$isolated_id" 18083 "$scenario"
if wait_client_ready natclient03 "$scenario" 18; then
  fail '非桥接 leaf relay04 意外穿透分区连接到 relay03 的 NAT 节点'
else
  pass '普通 leaf Relay 无法替代桥接 Relay 穿透分区'
fi

capture_topology_logs "$scenario"
exit "$failures"
