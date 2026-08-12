#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
test_root=$(mktemp -d)
cleanup() {
  rm -rf "$test_root"
}
trap cleanup EXIT

RUNTIME_DIR=$test_root/runtime
COMPOSE_FILE=$RUNTIME_DIR/compose.json
COMPOSE_PROJECT=topology-bootstrap-order
mkdir -p "$RUNTIME_DIR/.private/ca"
source "$ROOT_DIR/test/runtimeScript/local-chaos/lib.sh"

trace=$test_root/trace
: > "$trace"

fail() {
  printf 'topology bootstrap order regression failed: %s\n' "$*" >&2
  exit 1
}

dc() {
  printf 'dc %s\n' "$*" >> "$trace"
  if [[ ${1:-} == config && ${2:-} == --services ]]; then
    printf '%s\n' ca-postgres ca ca-web index relay01 relay02 relay03 relay04 relay05 relay06 relay07
  fi
}

node() {
  [[ ${1:-} == "$ROOT_DIR/test/runtimeScript/local-chaos/bootstrap-billing-keys.mjs" ]] \
    || fail "unexpected Node entrypoint ${1:-missing}"
  [[ ${PRIVATE_RUNTIME_DIR:-} == "$RUNTIME_DIR/.private" ]] \
    || fail 'private runtime was not passed to bootstrap'
  [[ ${CA_BASE_URL:-} == http://127.0.0.1:19100 ]] \
    || fail 'loopback CA URL was not passed to bootstrap'
  printf 'node bootstrap\n' >> "$trace"
  printf 'billing key bootstrap complete users=3 services=1\n'
}

wait_services_healthy() {
  printf 'healthy %s\n' "$*" >> "$trace"
}

wait_compose_log() {
  printf 'log-ready %s\n' "$1" >> "$trace"
}

topology_reset || fail 'CA-enabled topology reset failed'

bootstrap_line=$(grep -n '^node bootstrap$' "$trace" | cut -d: -f1)
ca_up_line=$(grep -n '^dc up -d --remove-orphans ca-postgres ca ca-web$' "$trace" | cut -d: -f1)
full_up_line=$(grep -n '^dc up -d --remove-orphans$' "$trace" | cut -d: -f1)
[[ -n $bootstrap_line && -n $ca_up_line && -n $full_up_line ]] \
  || fail 'expected staged startup calls are missing'
(( ca_up_line < bootstrap_line && bootstrap_line < full_up_line )) \
  || fail 'billing bootstrap did not run between CA and topology startup'
grep -q '^billing key bootstrap complete' "$RUNTIME_DIR/billing-key-bootstrap.log" \
  || fail 'bootstrap output was not retained'

: > "$trace"
dc() {
  printf 'dc %s\n' "$*" >> "$trace"
  if [[ ${1:-} == config ]]; then
    printf 'invalid compose fixture\n' >&2
    return 41
  fi
}
if topology_reset; then
  fail 'Compose service discovery failure was accepted'
fi
grep -q '^invalid compose fixture$' "$RUNTIME_DIR/compose-config.log" \
  || fail 'Compose discovery diagnostics were not retained'
if grep -q '^dc up ' "$trace"; then
  fail 'topology startup continued after service discovery failed'
fi

printf 'topology bootstrap order regression passed\n'
