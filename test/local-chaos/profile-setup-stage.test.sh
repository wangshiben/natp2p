#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
test_root=$(mktemp -d)
cleanup() {
  rm -rf "$test_root"
}
trap cleanup EXIT

source "$ROOT_DIR/scripts/local-chaos-stability.sh"

trace=$test_root/trace
: > "$trace"

fail() {
  printf 'profile setup stage regression failed: %s\n' "$*" >&2
  exit 1
}

MOCK_FAILURE=
configure_profile() {
  printf 'configure\n' >> "$trace"
  [[ $MOCK_FAILURE != configure ]]
}
initialize_random_workload() {
  printf 'initialize\n' >> "$trace"
  [[ $MOCK_FAILURE != initialize ]]
}
verify_profile3_tcp_cold_start() {
  printf 'transport\n' >> "$trace"
  [[ $MOCK_FAILURE != transport ]]
}
wait_core_services_healthy() {
  printf 'health\n' >> "$trace"
  CORE_IDENTITY_DETAIL=
  if [[ $MOCK_FAILURE == identity ]]; then
    CORE_IDENTITY_DETAIL=relay03:container_id_changed
    return 1
  fi
  [[ $MOCK_FAILURE != health ]]
}

run_dir=$test_root/run
mkdir -p "$run_dir"
prepare_stability_profile "$run_dir" 1 19100 1 5 5 \
  || fail "healthy stages were rejected: $PROFILE_SETUP_DETAIL"
[[ $PROFILE_SETUP_DETAIL == ready ]] || fail "unexpected success detail $PROFILE_SETUP_DETAIL"
[[ $(paste -sd, "$trace") == configure,initialize,transport,health ]] \
  || fail 'healthy stages ran out of order'

declare -A expected=(
  [configure]=profile_configuration_failed
  [initialize]=random_workload_initialization_failed
  [transport]=profile_transport_gate_failed
  [health]=profile_core_health_timeout
  [identity]=profile_core_identity_changed
)
for MOCK_FAILURE in configure initialize transport health identity; do
  : > "$trace"
  : > "$run_dir/profile-setup.log"
  if prepare_stability_profile "$run_dir" 1 19100 1 5 5; then
    fail "$MOCK_FAILURE failure was accepted"
  fi
  [[ $PROFILE_SETUP_DETAIL == "${expected[$MOCK_FAILURE]}" ]] \
    || fail "$MOCK_FAILURE produced $PROFILE_SETUP_DETAIL"
  grep -q "reason=${expected[$MOCK_FAILURE]}$" "$run_dir/profile-setup.log" \
    || fail "$MOCK_FAILURE diagnostic was not retained"
done

printf 'profile setup stage regression passed\n'
