#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
test_dir=$(mktemp -d)
export BNFS_SOAK_HOME=$test_dir/soak
source "$ROOT_DIR/scripts/local-chaos-stability.sh"

trap 'rm -rf "$test_dir"' EXIT

RUNTIME_DIR=$test_dir/runtime
PRIVATE_RUNTIME_DIR=$RUNTIME_DIR/.private
service=natclient04
scenario=stability
expected_node_id=$(printf 'a%.0s' {1..64})
events_file=$test_dir/events
mkdir -p "$RUNTIME_DIR/$scenario" "$PRIVATE_RUNTIME_DIR/$service"
printf '%064d\n' 1 > "$PRIVATE_RUNTIME_DIR/$service/$service.key"

fail() {
  printf 'client credit order regression failed: %s\n' "$1" >&2
  exit 1
}

node_id_from_private_key() {
  printf 'derive:%s\n' "$1" >> "$events_file"
  printf '%s\n' "$expected_node_id"
}

credit_node() {
  printf 'credit:%s:%s:%s\n' "$1" "$2" "$3" >> "$events_file"
  [[ $2 == "$expected_node_id" ]]
}

launch_tunnel_client() {
  printf 'launch:%s:%s:%s:%s:%s\n' "$1" "$2" "$3" "$4" "$5" >> "$events_file"
  printf '本节点 ID: %s\n' "$expected_node_id" > "$RUNTIME_DIR/$5/$1.log"
}

wait_file_pattern() {
  printf 'wait-id:%s\n' "$1" >> "$events_file"
  grep -q "$2" "$1"
}

wait_client_ready() {
  printf 'ready:%s:%s:%s\n' "$1" "$2" "$3" >> "$events_file"
}

start_client_and_credit "$service" relay01:9000 target-node 18084 "$scenario" 19100 \
  || fail 'credited client did not start'

expected_events=$test_dir/expected-events
printf 'derive:%s\ncredit:19100:%s:%s\nlaunch:%s:relay01:9000:target-node:18084:%s\nwait-id:%s\nready:%s:%s:70\n' \
  "$PRIVATE_RUNTIME_DIR/$service/$service.key" "$expected_node_id" "$DEFAULT_SOAK_CREDIT_BYTES" \
  "$service" "$scenario" "$RUNTIME_DIR/$scenario/$service.log" "$service" "$scenario" \
  > "$expected_events"
cmp -s "$events_file" "$expected_events" || {
  diff -u "$expected_events" "$events_file" >&2 || true
  fail 'identity, credit, and launch order changed'
}
[[ $(grep -c '^launch:' "$events_file") -eq 1 ]] || fail 'client launched more than once'

profile_key=$PRIVATE_RUNTIME_DIR/$service/profile-setup/$service.key
mkdir -p "${profile_key%/*}"
printf '%064d\n' 2 > "$profile_key"
BNFS_CHAOS_NAT_KEY_DIR=$PROFILE_SETUP_NAT_KEY_DIR
: > "$events_file"
start_client_and_credit "$service" relay01:9000 target-node 18084 "$scenario" 19100 \
  || fail 'profile setup client did not start'
grep -Fx "derive:$profile_key" "$events_file" >/dev/null \
  || fail 'profile setup client did not derive its isolated key'
grep -q '^credit:' "$events_file" || fail 'profile setup client was not credited'
grep -q '^launch:' "$events_file" || fail 'profile setup client was not launched'
BNFS_CHAOS_NAT_KEY_DIR=/artifacts/.private

: > "$events_file"
credit_node() {
  printf 'credit:%s:%s:%s\n' "$1" "$2" "$3" >> "$events_file"
  return 1
}
if start_client_and_credit "$service" relay01:9000 target-node 18084 "$scenario" 19100; then
  fail 'client started after credit failure'
fi
grep -q '^derive:' "$events_file" || fail 'identity was not derived before failed credit'
grep -q '^credit:' "$events_file" || fail 'credit was not attempted'
! grep -q '^launch:' "$events_file" || fail 'client launched despite failed credit'

: > "$events_file"
credit_node() {
  printf 'credit:%s:%s:%s\n' "$1" "$2" "$3" >> "$events_file"
}
launch_tunnel_client() {
  printf 'launch:%s\n' "$1" >> "$events_file"
  printf '本节点 ID: %s\n' "$(printf 'b%.0s' {1..64})" > "$RUNTIME_DIR/$5/$1.log"
}
if start_client_and_credit "$service" relay01:9000 target-node 18084 "$scenario" 19100; then
  fail 'mismatched runtime identity was accepted'
fi
! grep -q '^ready:' "$events_file" || fail 'readiness wait ran after identity mismatch'

printf 'client credit order regression passed\n'
