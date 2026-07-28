#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
test_root=$(mktemp -d)
export BNFS_SOAK_HOME=$test_root/soak
source "$ROOT_DIR/scripts/local-chaos-stability.sh"

trap 'rm -rf "$test_root"' EXIT

TOPOLOGY_NAT_SERVER_COUNT=1
readiness_checks=0

fail() {
  printf 'client entry relay regression failed: %s\n' "$1" >&2
  exit 1
}

log_step() {
  return 0
}

mock_node_id_for_service() {
  local service=$1 character= index node_id=
  case "$service" in
    natserver01) character=a ;;
    malicious-random-natserver) character=e ;;
    natclient0[1-6]) character=${service#natclient0} ;;
    malicious-natclient) character=7 ;;
    *) return 1 ;;
  esac
  for ((index = 0; index < 64; index++)); do
    node_id+=$character
  done
  printf '%s\n' "$node_id"
}

stop_random_nat_processes() {
  return 0
}

ensure_key() {
  printf 'mock-key\n' > "$1"
}

node_id_from_private_key() {
  local service_dir=${1%/*} service
  service=${service_dir##*/}
  mock_node_id_for_service "$service"
}

credit_node() {
  return 0
}

relay_registration_count() {
  printf '0\n'
}

start_tunnel_server() {
  mock_node_id_for_service "$1"
}

wait_relay_registration() {
  return 0
}

wait_random_server_billing_ready() {
  readiness_checks=$((readiness_checks + 1))
  return 0
}

table_relay_for_client() {
  local table=$1 service=$2 relay_column=$3 role_column=${4:-0}
  awk -F '\t' -v service="$service" -v relay_column="$relay_column" \
    -v role_column="$role_column" '
    NR > 1 && $1 == service && (role_column == 0 || $role_column == "natclient") {
      print $relay_column
    }
  ' "$table"
}

run_case() {
  local selected=$1 expected_override=$2 run_dir
  local number service expected_relay identity_relay pool_relay actual_override
  run_dir=$test_root/scenario-$selected
  RUNTIME_DIR=$run_dir/runtime
  PRIVATE_RUNTIME_DIR=$RUNTIME_DIR/.private
  mkdir -p "$RUNTIME_DIR" "$PRIVATE_RUNTIME_DIR"
  readiness_checks=0

  initialize_random_workload "$run_dir" 19100 "$selected" 2 5 10 \
    || fail "scenario $selected initialization failed"
  [[ $readiness_checks -eq $((TOPOLOGY_NAT_SERVER_COUNT + 1)) ]] \
    || fail "scenario $selected skipped initial Server readiness checks"

  for ((number = 1; number <= TOPOLOGY_NAT_CLIENT_COUNT; number++)); do
    printf -v service 'natclient%02d' "$number"
    expected_relay=$(client_entry_relay "$service" "$selected") \
      || fail "scenario $selected rejected $service"
    identity_relay=$(table_relay_for_client "$run_dir/nat-identities.tsv" "$service" 4 2)
    pool_relay=$(table_relay_for_client "$run_dir/client-pool.tsv" "$service" 2)
    [[ $identity_relay == "$expected_relay" ]] \
      || fail "scenario $selected identity relay mismatch for $service"
    [[ $pool_relay == "$expected_relay" ]] \
      || fail "scenario $selected pool relay mismatch for $service"
  done
  [[ $(table_relay_for_client "$run_dir/client-pool.tsv" malicious-natclient 2) == relay01 ]] \
    || fail "scenario $selected malicious NatClient relay mismatch"
  validate_random_client_pool "$run_dir/client-pool.tsv" \
    || fail "scenario $selected random Client pool omitted the malicious node"

  actual_override=$(awk -F= '$1 == "random_ingress_override" { print $2 }' "$run_dir/workload.env")
  [[ $actual_override == "$expected_override" ]] \
    || fail "scenario $selected workload override was $actual_override"
}

run_case 1 none
run_case 2 natclient04:relay02
run_case 3 none

[[ $(client_entry_relay natclient04 2) == relay02 ]] \
  || fail 'scenario 2 did not retain natclient04 on relay02'
[[ $(client_entry_relay natclient03 2) == relay01 ]] \
  || fail 'scenario 2 changed an unrelated Client ingress'
if client_entry_relay natclient07 2 >/dev/null; then
  fail 'out-of-pool Client was accepted'
fi
if client_entry_relay natclient04 4 >/dev/null; then
  fail 'unknown scenario was accepted'
fi

relay_can_reach_server_relay relay02 relay02 \
  || fail 'same-Relay target was rejected'
relay_can_reach_server_relay relay01 relay03 \
  || fail 'bridge Relay could not reach its direct leaf'
relay_can_reach_server_relay relay03 relay01 \
  || fail 'leaf Relay could not reach its direct bridge'
if relay_can_reach_server_relay relay02 relay03; then
  fail 'relay02 was allowed to reach a non-neighbor leaf'
fi
if relay_can_reach_server_relay relay01 relay02; then
  fail 'relay01 was allowed to reach an Index sibling'
fi
if relay_can_reach_server_relay relay04 relay03; then
  fail 'leaf Relay was allowed to traverse the bridge to a sibling'
fi

[[ $DEFAULT_VALIDATION_MODE == full ]] \
  || fail 'default validation mode was downgraded from full'
[[ $(validation_mode_attempt_timeout_seconds) == "$DEFAULT_RANDOM_ATTEMPT_TIMEOUT_SECONDS" ]] \
  || fail 'default validation mode did not retain the full attempt SLA'
[[ $(validation_mode_attempt_timeout_seconds smoke) == "$SMOKE_RANDOM_ATTEMPT_TIMEOUT_SECONDS" ]] \
  || fail 'smoke validation mode did not use its explicit attempt SLA'
[[ $(random_worker_drain_timeout_seconds "$DEFAULT_RANDOM_ATTEMPT_TIMEOUT_SECONDS") \
    == $((DEFAULT_RANDOM_ATTEMPT_TIMEOUT_SECONDS + DEFAULT_RANDOM_WORKER_STOP_TIMEOUT_SECONDS)) ]] \
  || fail 'full worker drain was not derived from attempt SLA plus stop grace'
if validation_mode_attempt_timeout_seconds invalid >/dev/null 2>&1; then
  fail 'invalid validation mode was accepted'
fi

reachability_pool=$test_root/reachability-pool
mkdir -p "$reachability_pool"
printf 'server\tingress_relay\tnode_id\nnatserver01\trelay02\t%s\nnatserver02\trelay03\t%s\n' \
  "$(printf 'a%.0s' {1..64})" "$(printf 'b%.0s' {1..64})" \
  > "$reachability_pool/server-pool.tsv"
[[ $(random_reachable_server_line "$reachability_pool" relay02 | cut -f1) == natserver01 ]] \
  || fail 'relay02 selected a server outside its one-hop reachability'
[[ $(random_reachable_server_line "$reachability_pool" relay01 | cut -f1) == natserver02 ]] \
  || fail 'bridge Relay did not select its reachable leaf server'

printf 'natclient04\trelay01\t18104\t%s\n' "$(mock_node_id_for_service natclient04)" \
  >> "$test_root/scenario-2/client-pool.tsv"
if validate_client_entry_table "$test_root/scenario-2/client-pool.tsv" 2 1 2; then
  fail 'duplicate conflicting Client pool record was accepted'
fi

coverage_dir=$test_root/runtime-coverage
mkdir -p "$coverage_dir"
printf 'timestamp\ttransfer_id\tclient\tingress_relay\tserver\trequested_mib\trc\tbytes\tseconds\tmib_per_second\tsha256_ok\texpected_sha\tactual_sha\n' \
  > "$coverage_dir/transfers.tsv"
for number in $(seq 1 "$TOPOLOGY_NAT_CLIENT_COUNT"); do
  printf -v service 'natclient%02d' "$number"
  expected_relay=$(client_entry_relay "$service" 2)
  printf '2026-07-20T00:00:00+08:00\ttransfer-%s\t%s\t%s\tnatserver01\t100\t0\t104857600\t20.000000\t5.000\tyes\texpected\tactual\n' \
    "$number" "$service" "$expected_relay" >> "$coverage_dir/transfers.tsv"
done
validate_scenario_client_ingress_coverage "$coverage_dir" 2 \
  || fail 'valid scenario 2 runtime ingress coverage was rejected'

awk -F '\t' 'BEGIN { OFS="\t" } $3 == "natclient04" { $4="relay01" } { print }' \
  "$coverage_dir/transfers.tsv" > "$coverage_dir/transfers.tmp"
mv "$coverage_dir/transfers.tmp" "$coverage_dir/transfers.tsv"
if validate_scenario_client_ingress_coverage "$coverage_dir" 2; then
  fail 'natclient04 runtime success through relay01 was accepted'
fi

awk -F '\t' 'BEGIN { OFS="\t" } $3 == "natclient04" { $4="relay02" } $3 == "natclient03" { $4="relay02" } { print }' \
  "$coverage_dir/transfers.tsv" > "$coverage_dir/transfers.tmp"
mv "$coverage_dir/transfers.tmp" "$coverage_dir/transfers.tsv"
if validate_scenario_client_ingress_coverage "$coverage_dir" 2; then
  fail 'unrelated Client runtime success through relay02 was accepted'
fi

reachable_coverage_dir=$test_root/reachable-coverage
mkdir -p "$reachable_coverage_dir"
printf 'server\tingress_relay\tnode_id\n' > "$reachable_coverage_dir/server-pool.tsv"
printf 'natserver01\trelay02\t%s\n' "$(printf 'a%.0s' {1..64})" >> "$reachable_coverage_dir/server-pool.tsv"
printf 'natserver02\trelay03\t%s\n' "$(printf 'b%.0s' {1..64})" >> "$reachable_coverage_dir/server-pool.tsv"
printf 'natserver03\trelay06\t%s\n' "$(printf 'c%.0s' {1..64})" >> "$reachable_coverage_dir/server-pool.tsv"
printf 'malicious-random-natserver\trelay03\t%s\n' "$(printf 'e%.0s' {1..64})" \
  >> "$reachable_coverage_dir/server-pool.tsv"
printf 'timestamp\ttransfer_id\tclient\tingress_relay\tserver\trequested_mib\trc\tbytes\tseconds\tmib_per_second\tsha256_ok\texpected_sha\tactual_sha\n' \
  > "$reachable_coverage_dir/transfers.tsv"
for number in $(seq 1 "$TOPOLOGY_NAT_CLIENT_COUNT"); do
  printf -v service 'natclient%02d' "$number"
  if [[ $service == natclient04 ]]; then
    printf '2026-07-20T00:00:00+08:00\tlocal-%s\t%s\trelay02\tnatserver01\t100\t0\t104857600\t20.0\t5.0\tyes\texpected\tactual\n' \
      "$service" "$service" >> "$reachable_coverage_dir/transfers.tsv"
  else
    printf '2026-07-20T00:00:00+08:00\tpartition-a-%s\t%s\trelay01\tnatserver02\t100\t0\t104857600\t20.0\t5.0\tyes\texpected\tactual\n' \
      "$service" "$service" >> "$reachable_coverage_dir/transfers.tsv"
    printf '2026-07-20T00:00:00+08:00\tpartition-b-%s\t%s\trelay01\tnatserver03\t100\t0\t104857600\t20.0\t5.0\tyes\texpected\tactual\n' \
      "$service" "$service" >> "$reachable_coverage_dir/transfers.tsv"
  fi
done
printf '2026-07-20T00:00:00+08:00\tmalicious-transfer\tmalicious-natclient\trelay01\tnatserver02\t100\t0\t104857600\t20.0\t5.0\tyes\texpected\tactual\n' \
  >> "$reachable_coverage_dir/transfers.tsv"
printf '2026-07-20T00:00:30+08:00\tmalicious-server-transfer\tnatclient01\trelay01\tmalicious-random-natserver\t100\t0\t104857600\t20.0\t5.0\tyes\texpected\tactual\n' \
  >> "$reachable_coverage_dir/transfers.tsv"
{
  printf 'timestamp\tbatch_id\tselected_server\tserver_pool_includes_malicious\tserver_malicious\tmode\trequested_clients\tselected_clients\tclient_pool_includes_malicious\tmalicious_client_selected\tstatus\ttarget_pairs\tsucceeded\tfailed\n'
  printf '2026-07-20T00:00:00+08:00\tbatch-1-1\tmalicious-random-natserver\ttrue\ttrue\tmulti\t2\tnatclient01,malicious-natclient\ttrue\ttrue\tPASS\tnatclient01→malicious-random-natserver,malicious-natclient→malicious-random-natserver\t2\t0\n'
  printf '2026-07-20T00:01:00+08:00\tbatch-2-2\tnatserver03\ttrue\tfalse\tsingle\t1\tnatclient02\ttrue\tfalse\tPASS\tnatclient02→natserver03\t1\t0\n'
} > "$reachable_coverage_dir/random-batches.tsv"
validate_random_workload_coverage "$reachable_coverage_dir" 2 \
  || fail 'valid one-hop reachable coverage was rejected'

printf 'natserver04\trelay03\t%s\n' "$(printf 'd%.0s' {1..64})" \
  >> "$reachable_coverage_dir/server-pool.tsv"
if validate_random_workload_coverage "$reachable_coverage_dir" 2 full; then
  fail 'full validation accepted incomplete Server coverage'
fi
if validate_random_workload_coverage "$reachable_coverage_dir" 2; then
  fail 'default validation silently downgraded incomplete full coverage'
fi
validate_random_workload_coverage "$reachable_coverage_dir" 2 smoke \
  || fail 'smoke validation rejected healthy lane and partition coverage'
if validate_random_workload_coverage "$reachable_coverage_dir" 2 invalid; then
  fail 'unknown workload validation mode was accepted'
fi

smoke_missing_lane_dir=$test_root/smoke-missing-lane
mkdir -p "$smoke_missing_lane_dir"
cp "$reachable_coverage_dir/server-pool.tsv" "$smoke_missing_lane_dir/server-pool.tsv"
awk -F '\t' '$3 != "natclient06"' "$reachable_coverage_dir/transfers.tsv" \
  > "$smoke_missing_lane_dir/transfers.tsv"
if validate_random_workload_coverage "$smoke_missing_lane_dir" 2 smoke; then
  fail 'smoke validation accepted a missing Client lane'
fi

awk -F '\t' 'BEGIN { OFS="\t" } $3 == "natclient04" { $5="natserver02" } { print }' \
  "$reachable_coverage_dir/transfers.tsv" > "$reachable_coverage_dir/transfers.tmp"
mv "$reachable_coverage_dir/transfers.tmp" "$reachable_coverage_dir/transfers.tsv"
if validate_random_workload_coverage "$reachable_coverage_dir" 2; then
  fail 'unreachable relay02 to relay03 success path was accepted'
fi

printf 'client entry relay regression passed\n'
