#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
test_root=$(mktemp -d)
export BNFS_SOAK_HOME=$test_root/soak
source "$ROOT_DIR/test/runtimeScript/local-chaos-stability.sh"

trap 'rm -rf "$test_root"' EXIT

fail() {
  printf 'profile setup identity regression failed: %s\n' "$1" >&2
  exit 1
}

generate_key() {
  local path=$1
  printf 'test-key-for=%s\n' "$path" > "$path"
  chmod 600 "$path"
}

PRIVATE_RUNTIME_DIR=$test_root/private
mkdir -p "$PRIVATE_RUNTIME_DIR/natserver03"
chmod 700 "$PRIVATE_RUNTIME_DIR/natserver03"

prepare_profile_setup_identity natserver03 \
  || fail 'valid NatServer identity was rejected'

profile_key=$PRIVATE_RUNTIME_DIR/natserver03/profile-setup/natserver03.key
random_key=$PRIVATE_RUNTIME_DIR/natserver03/natserver03.key
[[ $PROFILE_SETUP_NAT_KEY_DIR == /artifacts/.private/profile-setup ]] \
  || fail 'container profile key directory changed'
BNFS_CHAOS_NAT_KEY_DIR=$PROFILE_SETUP_NAT_KEY_DIR
[[ $(nat_key_host_file natserver03) == "$profile_key" ]] \
  || fail 'profile container key path did not map to its host key'
[[ -s $profile_key ]] || fail 'profile identity key was not created'
[[ ! -e $random_key ]] || fail 'profile identity overwrote the random-workload identity'
[[ $(stat -c %a "${profile_key%/*}") == 700 ]] \
  || fail 'profile identity directory is not private'
[[ $(stat -c %a "$profile_key") == 600 ]] \
  || fail 'profile identity key is not private'

BNFS_CHAOS_NAT_KEY_DIR=/artifacts/.private
[[ $(nat_key_host_file natserver03) == "$random_key" ]] \
  || fail 'random-workload container key path did not map to its host key'
ensure_key "$random_key"
[[ -s $random_key ]] || fail 'random-workload identity key was not created'
cmp -s "$profile_key" "$random_key" \
  && fail 'profile and random-workload identities were not isolated'

BNFS_CHAOS_NAT_KEY_DIR=/artifacts/.private/../escaped
if nat_key_host_file natserver03 >/dev/null; then
  fail 'unsupported container key directory escaped the private mount'
fi

if prepare_profile_setup_identity relay03; then
  fail 'non-NAT service was accepted for a profile identity'
fi

printf 'profile setup identity regression: PASS\n'
