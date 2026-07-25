#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
test_root=$(mktemp -d)
trap 'rm -rf "$test_root"' EXIT

source "$ROOT_DIR/scripts/local-chaos-stability.sh"

run_dir=$test_root/run
mkdir -p "$run_dir/transfer-records"
cat > "$run_dir/ip-family-plan.tsv" <<'EOF'
family	relay	natserver	natclient
ipv4	relay03	natserver01	natclient01
ipv6	relay04	natserver02	natclient02
dual	relay05	natserver03	natclient03
EOF
node_id=$(printf 'a%.0s' {1..64})
{
  printf 'server\tingress_relay\trelay_endpoint\tip_family\tnode_id\n'
  printf 'natserver01\trelay03\t10.253.41.250:9000\tipv4\t%s\n' "$node_id"
  printf 'natserver02\trelay04\t[fd92:7b5e:4c31:42::250]:9000\tipv6\t%s\n' "$node_id"
  printf 'natserver03\trelay05\t[fd92:7b5e:4c31:43::250]:9000\tdual\t%s\n' "$node_id"
} > "$run_dir/server-pool.tsv"
{
  printf 'client\tingress_relay\trelay_endpoint\tip_family\tlisten_port\tnode_id\n'
  printf 'natclient01\trelay03\t10.253.41.250:9000\tipv4\t18101\t%s\n' "$node_id"
  printf 'natclient02\trelay04\t[fd92:7b5e:4c31:42::250]:9000\tipv6\t18102\t%s\n' "$node_id"
  printf 'natclient03\trelay05\t10.253.43.250:9000\tdual\t18103\t%s\n' "$node_id"
} > "$run_dir/client-pool.tsv"

ip_family_address_gate() { return 0; }
ip_family_relay_socket_gate() { return 0; }
stop_nat_process() { return 0; }
launch_tunnel_client() { while IFS= read -r _; do :; done; }
wait_client_ready() { return 0; }
wait_client_entry_relay() { printf '%s\n' "$3"; }
random_transfer_once() { : > "$8"; }
append_transfer_record() { return 0; }

verify_ip_family_coverage "$run_dir"
validate_ip_family_coverage "$run_dir"
[[ $(wc -l < "$run_dir/ip-family-coverage.tsv") -eq 4 ]]
[[ $(tail -n +2 "$run_dir/ip-family-coverage.tsv" | cut -f2 | paste -sd, -) == ipv4,ipv6,dual ]]

printf 'IP family coverage regression passed\n'
