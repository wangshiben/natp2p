#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
test_root=$(mktemp -d)
trap 'rm -rf "$test_root"' EXIT

source "$ROOT_DIR/test/local-chaos/mixed-path-gate.sh"

fail() {
  printf 'mixed path gate regression failed: %s\n' "$1" >&2
  exit 1
}

write_status() {
  local nat_relay=$1 nat_partition=$2 relay_peer=$3 relay_partition=$4
  local generation=$5 migrations=$6 verified=$7 latest_two=$8 attachment_verified=$9
  local network_coverage=${10:-0} network_violations=${11:-0} drain_complete=${12:-0}
  cat > "$test_root/mixed-adversary-path.status" <<EOF
schema_version=1
status=RUNNING
error_code=
heartbeat_epoch=$(date +%s)
generation=$generation
observed_triggers=$migrations
drain_complete=$drain_complete
probe_status=PASS
probe_failures=0
probe_consecutive_failures=0
migration_count=$migrations
verified_migration_count=$verified
latest_two_migrations_verified=$latest_two
network_event_count=$generation
network_violation_count=$network_violations
network_scenario_coverage=$network_coverage
required_network_scenarios=9
malicious_natserver_relay=$nat_relay
malicious_natserver_partition=$nat_partition
malicious_relay_peer=$relay_peer
malicious_relay_partition=$relay_partition
normal_partition_attachment_verified=$attachment_verified
path_contains_normal_partition=1
path_contains_malicious_node=1
EOF
}

write_status relay04 control_partition_a relay03 control_partition_a 0 0 0 0 1
inspect_mixed_adversary_path "$test_root" "$$" "$(date +%s)" 0 \
  || fail "valid initial normal-partition attachment was rejected: $MIXED_PATH_DETAIL"

write_status relay01 control_partition_a relay03 control_partition_a 0 0 0 0 1
if inspect_mixed_adversary_path "$test_root" "$$" "$(date +%s)" 0; then
  fail 'malicious NAT Server attached outside relay03..relay07 passed'
fi
[[ $MIXED_PATH_DETAIL == mixed_path_normal_partition_attachment_invalid ]] \
  || fail "unexpected invalid NAT attachment detail: $MIXED_PATH_DETAIL"

write_status relay06 control_partition_a relay03 control_partition_a 0 0 0 0 1
if inspect_mixed_adversary_path "$test_root" "$$" "$(date +%s)" 0; then
  fail 'normal Relay with a mismatched partition passed'
fi

write_status relay06 control_partition_b relay03 control_partition_a 2 2 2 0 1 2
if inspect_mixed_adversary_path "$test_root" "$$" "$(date +%s)" 1; then
  fail 'two migrations without contained/isolation/probe evidence passed'
fi
[[ $MIXED_PATH_DETAIL == mixed_path_containment_unverified ]] \
  || fail "unexpected containment detail: $MIXED_PATH_DETAIL"

write_status relay06 control_partition_b relay03 control_partition_a 9 9 9 1 1 8
if inspect_mixed_adversary_path "$test_root" "$$" "$(date +%s)" 1; then
  fail 'normal-network migrations without 9/9 scenario coverage passed'
fi
[[ $MIXED_PATH_DETAIL == mixed_path_network_coverage_incomplete ]] \
  || fail "unexpected network coverage detail: $MIXED_PATH_DETAIL"

write_status relay06 control_partition_b relay03 control_partition_a 9 9 9 1 1 9 1
if inspect_mixed_adversary_path "$test_root" "$$" "$(date +%s)" 1; then
  fail 'normal-network containment violation passed'
fi
[[ $MIXED_PATH_DETAIL == mixed_path_network_containment_violation ]] \
  || fail "unexpected network violation detail: $MIXED_PATH_DETAIL"

write_status relay06 control_partition_b relay03 control_partition_a 9 9 9 1 1 9
inspect_mixed_adversary_path "$test_root" "$$" "$(date +%s)" 1 \
  || fail "verified mixed-partition migrations were rejected: $MIXED_PATH_DETAIL"

sed -e 's/^status=RUNNING$/status=FAILED/' \
  -e 's/^error_code=$/error_code=mixed_path_relay_control_timeout/' \
  "$test_root/mixed-adversary-path.status" > "$test_root/failed.status"
mv "$test_root/failed.status" "$test_root/mixed-adversary-path.status"
if inspect_mixed_adversary_path "$test_root" "$$" "$(date +%s)" 0; then
  fail 'typed mixed-path controller failure passed'
fi
[[ $MIXED_PATH_DETAIL == mixed_path_relay_control_timeout ]] \
  || fail "controller failure detail was lost: $MIXED_PATH_DETAIL"

write_status relay06 control_partition_b relay03 control_partition_a 9 9 9 1 1 9
cp "$test_root/mixed-adversary-path.status" "$test_root/valid-running.status"
write_status relay06 control_partition_b relay03 control_partition_a 9 9 9 1 0 9
sed 's/^status=RUNNING$/status=MIGRATING/' "$test_root/mixed-adversary-path.status" \
  > "$test_root/replacement-migrating.status"
cp "$test_root/valid-running.status" "$test_root/mixed-adversary-path.status"
MIXED_PATH_SWAP_ON_FIELD_READ=1
mixed_path_field() {
  local file=$1 key=$2 value
  if [[ ${MIXED_PATH_SWAP_ON_FIELD_READ:-0} == 1 && $key == status \
    && -s $test_root/replacement-migrating.status ]]; then
    value=$(awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$file")
    mv "$test_root/replacement-migrating.status" "$file"
    printf '%s\n' "$value"
    return
  fi
  awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$file"
}
inspect_mixed_adversary_path "$test_root" "$$" "$(date +%s)" 1 \
  || fail "one inspection mixed fields from different atomic snapshots: $MIXED_PATH_DETAIL"
[[ -s $test_root/replacement-migrating.status ]] \
  || fail 'inspection reopened the status file after capturing its snapshot'
MIXED_PATH_SWAP_ON_FIELD_READ=0

write_status relay06 control_partition_b relay03 control_partition_a 9 9 9 1 1 9 0 1
drain_mixed_adversary_path "$test_root" "$$" 1 \
  || fail "verified idle controller did not drain: $MIXED_PATH_DETAIL"
[[ -s $test_root/mixed-adversary-path.drain ]] || fail 'drain request marker was not published'

printf 'mixed path gate regression passed\n'
