#!/usr/bin/env bash

set -uo pipefail
source "${ROOT_DIR:?}/test/local-chaos/lib.sh"

scenario=03_kcp_tcp_fallback
scenario_dir=$RUNTIME_DIR/$scenario
mkdir -p "$scenario_dir"
failures=0

fail() {
  printf '[scenario-3] FAIL: %s\n' "$*" >&2
  failures=$((failures + 1))
}

pass() {
  printf '[scenario-3] PASS: %s\n' "$*"
}

if ! topology_reset; then
  exit 1
fi

server_id=$(start_tunnel_server natserver03 relay02:9000 "$scenario" 5) || {
  fail 'Tunnel Server 启动失败'
  capture_topology_logs "$scenario"
  exit 1
}
launch_tunnel_client natclient05 relay02:9000 "$server_id" 18085 "$scenario"
if ! wait_client_ready natclient05 "$scenario" 40; then
  fail '故障注入前隧道未建立'
  capture_topology_logs "$scenario"
  exit 1
fi

source_checksum=$(dc exec -T natserver03 curl -fsS http://127.0.0.1:8080/checksum | tr -d '[:space:]')
netns_exec natserver03 iptables -I OUTPUT 1 -p udp --dport 9000 \
  -m comment --comment BNFS_KCP_OBSERVE -j ACCEPT

start_limited_download natclient05 18085 "$scenario" 256k 90
if ! wait_file_size "$scenario_dir/download.bin" 262144 20; then
  fail 'UDP 黑洞注入前没有产生有效业务流量'
  capture_topology_logs "$scenario"
  exit 1
fi

kcp_packets=$(netns_exec natserver03 iptables -L OUTPUT -v -n -x | awk '/BNFS_KCP_OBSERVE/{print $1; exit}')
kcp_packets=${kcp_packets:-0}
if (( kcp_packets > 20 )); then
  pass "注入前 KCP 正在承载数据，观察到 UDP 包 $kcp_packets"
else
  fail "注入前仅观察到 $kcp_packets 个 UDP 包，不能证明 KCP 是活动数据腿"
fi

netns_exec natserver03 iptables -D OUTPUT -p udp --dport 9000 \
  -m comment --comment BNFS_KCP_OBSERVE -j ACCEPT >/dev/null 2>&1 || true
netns_exec natserver03 iptables -I OUTPUT 1 -p udp --dport 9000 -j DROP
netns_exec natclient05 iptables -I OUTPUT 1 -p udp --dport 9000 -j DROP
pass '传输中同时阻断 NatServer/NatClient 到 Relay 的 UDP，TCP 保持可达'

if wait_file_exists "$scenario_dir/curl.rc" 70 \
  && [[ $(tr -d '[:space:]' < "$scenario_dir/curl.rc") == 0 ]]; then
  received_checksum=$(sha256sum "$scenario_dir/download.bin" | awk '{print $1}')
  received_size=$(stat -c %s "$scenario_dir/download.bin")
  if [[ $received_size == 5242880 && $received_checksum == "$source_checksum" ]]; then
    pass 'KCP 失效后 TCP 接管，5MiB 文件完整传输'
  else
    fail "TCP 接管后的文件不完整: size=$received_size sha=$received_checksum"
  fi
else
  fail 'KCP 失效后 TCP 未能在 70 秒内接管并完成传输'
fi

if netns_exec natserver03 ss -tn | grep -q ':9000'; then
  pass 'UDP 黑洞期间 TCP Relay 连接仍存活'
else
  fail 'UDP 黑洞期间没有可用 TCP Relay 连接'
fi

capture_topology_logs "$scenario"
exit "$failures"
