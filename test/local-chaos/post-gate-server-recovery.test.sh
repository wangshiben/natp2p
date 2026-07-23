#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
test_root=$(mktemp -d)
cleanup() {
  rm -rf "$test_root"
}
trap cleanup EXIT

source "$ROOT_DIR/scripts/local-chaos-stability.sh"

POST_GATE_SERVER_RECOVERY_TIMEOUT_SECONDS=2
POST_GATE_SERVER_RECOVERY_STABLE_SAMPLES=3
REAL_BILLING_GATE_SERVER=natserver06
MOCK_EVENTS=$test_root/events
MOCK_MISMATCH_SERVER=
MOCK_SINGLE_LEG_SERVER=
MOCK_BILLING_NOT_READY_SERVER=

fail() {
  printf 'post-gate server recovery regression failed: %s\n' "$1" >&2
  exit 1
}

log_step() {
  printf 'log:%s\n' "$1" >> "$MOCK_EVENTS"
}

server_for_node() {
  case "$1" in
    "$(printf '6%.0s' {1..64})") printf 'natserver06\n' ;;
    "$(printf '7%.0s' {1..64})") printf 'natserver07\n' ;;
    "$(printf '8%.0s' {1..64})") printf 'natserver08\n' ;;
    "$(printf 'c%.0s' {1..64})") printf 'natserver12\n' ;;
    *) return 1 ;;
  esac
}

relay_registration_count() {
  local relay=$1 node_id=$2 server calls
  server=$(server_for_node "$node_id") || return 1
  calls=$(grep -Fxc "count:$server" "$MOCK_EVENTS" 2>/dev/null || true)
  printf 'count:%s\n' "$server" >> "$MOCK_EVENTS"
  if (( calls == 0 )); then
    printf '10\n'
  elif [[ $server == "$MOCK_SINGLE_LEG_SERVER" ]]; then
    printf '11\n'
  else
    printf '12\n'
  fi
}

restart_tunnel_server() {
  local server=$1 relay=$2 scenario=$3 expected
  [[ ! -e $MOCK_RUN_DIR/server-fresh/$server ]] \
    || fail "$server was restarted before its fresh marker was cleared"
  printf 'restart:%s:%s:%s\n' "$server" "$relay" "$scenario" >> "$MOCK_EVENTS"
  expected=$(awk -F '\t' -v service="$server" '$1 == service { print $3; exit }' \
    "$MOCK_RUN_DIR/server-pool.tsv")
  if [[ $server == "$MOCK_MISMATCH_SERVER" ]]; then
    printf '%064d\n' 9
  else
    printf '%s\n' "$expected"
  fi
}

random_server_tunnel_process_count() {
  printf '1\n'
}

random_server_relay_tcp_connection_count() {
  printf '2\n'
}

billing_production_gate_read_nat_observation() {
  local server=$1 active=1
  [[ ! -e $MOCK_RUN_DIR/server-fresh/$server ]] \
    || fail "$server billing readiness was checked after restoring its fresh marker"
  printf 'billing:%s\n' "$server" >> "$MOCK_EVENTS"
  [[ $server != "$MOCK_BILLING_NOT_READY_SERVER" ]] || active=0
  printf '1\ttrue\t%s\t100\t100\ttrue\t1\n' "$active"
}

billing_production_gate_observation_is_fresh() {
  return 0
}

make_run_dir() {
  local name=$1 run_dir=$test_root/$name server
  mkdir -p "$run_dir/server-fresh"
  {
    printf 'server\tingress_relay\tnode_id\n'
    printf 'natserver06\trelay04\t%s\n' "$(printf '6%.0s' {1..64})"
    printf 'natserver07\trelay04\t%s\n' "$(printf '7%.0s' {1..64})"
    printf 'natserver08\trelay05\t%s\n' "$(printf '8%.0s' {1..64})"
    printf 'natserver12\trelay04\t%s\n' "$(printf 'c%.0s' {1..64})"
  } > "$run_dir/server-pool.tsv"
  for server in natserver06 natserver07 natserver08 natserver12; do
    : > "$run_dir/server-fresh/$server"
  done
  printf '%s\n' "$run_dir"
}

reset_case() {
  local name=$1
  : > "$MOCK_EVENTS"
  MOCK_MISMATCH_SERVER=
  MOCK_SINGLE_LEG_SERVER=
  MOCK_BILLING_NOT_READY_SERVER=
  MOCK_RUN_DIR=$(make_run_dir "$name")
  rm -f "$MOCK_RUN_DIR/server-fresh/$REAL_BILLING_GATE_SERVER"
}

assert_restarted() {
  local server=$1 expected_count=${2:-1}
  [[ $(grep -c "^restart:$server:" "$MOCK_EVENTS" 2>/dev/null || true) -eq $expected_count ]] \
    || fail "$server restart count was not $expected_count"
}

reset_case success
recover_random_server_pool_after_relay_restart "$MOCK_RUN_DIR" relay04 \
  || fail 'healthy Relay server pool did not recover'
assert_restarted natserver06 0
[[ ! -e $MOCK_RUN_DIR/server-fresh/natserver06 ]] \
  || fail 'production-gate server was incorrectly marked as a fresh channel'
[[ $(grep -c '^billing:natserver06$' "$MOCK_EVENTS") -eq 3 ]] \
  || fail 'production-gate server did not produce three stable re-arm samples'
for server in natserver07 natserver12; do
  assert_restarted "$server"
  [[ -e $MOCK_RUN_DIR/server-fresh/$server ]] || fail "$server fresh marker was not restored"
  [[ $(grep -c "^billing:$server$" "$MOCK_EVENTS") -eq 3 ]] \
    || fail "$server did not produce three stable billing samples"
done
assert_restarted natserver08 0
[[ -e $MOCK_RUN_DIR/server-fresh/natserver08 ]] || fail 'unaffected server fresh marker changed'

reset_case identity-mismatch
MOCK_MISMATCH_SERVER=natserver07
if recover_random_server_pool_after_relay_restart "$MOCK_RUN_DIR" relay04; then
  fail 'mismatched server identity unexpectedly passed'
fi
[[ ! -e $MOCK_RUN_DIR/server-fresh/natserver07 ]] || fail 'identity failure restored fresh marker'
assert_restarted natserver12 0

reset_case single-leg
MOCK_SINGLE_LEG_SERVER=natserver07
if recover_random_server_pool_after_relay_restart "$MOCK_RUN_DIR" relay04; then
  fail 'single-leg Relay registration unexpectedly passed'
fi
[[ ! -e $MOCK_RUN_DIR/server-fresh/natserver07 ]] || fail 'single-leg failure restored fresh marker'
[[ $(grep -c '^billing:natserver07$' "$MOCK_EVENTS" 2>/dev/null || true) -eq 0 ]] \
  || fail 'billing readiness ran before both registration legs existed'
assert_restarted natserver12 0

reset_case billing-not-ready
MOCK_BILLING_NOT_READY_SERVER=natserver07
if recover_random_server_pool_after_relay_restart "$MOCK_RUN_DIR" relay04; then
  fail 'unstable billing control unexpectedly passed'
fi
[[ ! -e $MOCK_RUN_DIR/server-fresh/natserver07 ]] || fail 'billing failure restored fresh marker'
assert_restarted natserver12 0

reset_case gate-server-billing-not-ready
MOCK_BILLING_NOT_READY_SERVER=natserver06
if recover_random_server_pool_after_relay_restart "$MOCK_RUN_DIR" relay04; then
  fail 'production-gate server without a stable re-arm unexpectedly passed'
fi
assert_restarted natserver06 0
assert_restarted natserver07 0
assert_restarted natserver12 0
[[ ! -e $MOCK_RUN_DIR/server-fresh/natserver06 ]] \
  || fail 'failed production-gate re-arm restored a fresh marker'

stability_script=$ROOT_DIR/scripts/local-chaos-stability.sh
production_gate_line=$(awk '/^[[:space:]]*if ! run_billing_production_gate / { print NR; exit }' "$stability_script")
recovery_line=$(awk '/^[[:space:]]*elif ! recover_random_server_pool_after_relay_restart / { print NR; exit }' "$stability_script")
core_health_line=$(awk '/^[[:space:]]*elif ! core_services_healthy/ { print NR; exit }' "$stability_script")
worker_line=$(awk '/random_client_worker "\$run_dir"/ { print NR; exit }' "$stability_script")
[[ $production_gate_line =~ ^[1-9][0-9]*$ && $recovery_line =~ ^[1-9][0-9]*$ \
  && $core_health_line =~ ^[1-9][0-9]*$ && $worker_line =~ ^[1-9][0-9]*$ \
  && production_gate_line -lt recovery_line && recovery_line -lt core_health_line \
  && core_health_line -lt worker_line ]] \
  || fail 'post-gate recovery barrier ordering is unsafe'

worker_body=$(awk '/^random_client_worker\(\)/,/^}/' "$stability_script")
if grep -q 'restart_tunnel_server' <<< "$worker_body"; then
  fail 'random worker still cold-restarts a normally reused Tunnel Server'
fi
worker_registration_line=$(awk '/registration_count=\$\(relay_registration_count/ { print NR; exit }' <<< "$worker_body")
worker_stop_line=$(awk '/^[[:space:]]*if ! stop_nat_process "\$client" tunclient/ { print NR; exit }' <<< "$worker_body")
worker_generation_line=$(awk '/wait_relay_registration_generation/ { print NR; exit }' <<< "$worker_body")
worker_billing_line=$(awk '/wait_random_server_billing_ready/ { print NR; exit }' <<< "$worker_body")
worker_unlock_line=$(awk '/flock -u "\$server_lock_fd"/ { line=NR } END { print line }' <<< "$worker_body")
[[ $worker_registration_line =~ ^[1-9][0-9]*$ && $worker_stop_line =~ ^[1-9][0-9]*$ \
  && $worker_generation_line =~ ^[1-9][0-9]*$ && $worker_billing_line =~ ^[1-9][0-9]*$ \
  && $worker_unlock_line =~ ^[1-9][0-9]*$ \
  && worker_registration_line -lt worker_stop_line \
  && worker_stop_line -lt worker_generation_line \
  && worker_generation_line -lt worker_billing_line \
  && worker_billing_line -lt worker_unlock_line ]] \
  || fail 'random worker does not hold the Server lock through dual-leg billing re-arm'

printf 'post-gate server recovery regression passed\n'
