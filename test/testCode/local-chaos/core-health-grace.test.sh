#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
test_root=$(mktemp -d)
cleanup() {
  rm -rf "$test_root"
}
trap cleanup EXIT

source "$ROOT_DIR/test/runtimeScript/local-chaos-stability.sh"

fail() {
  printf 'core health grace regression failed: %s\n' "$*" >&2
  exit 1
}

COMPOSE_PROJECT=core-health-test
MOCK_BAD_SERVICE=
MOCK_PS_FAILURE=0
MOCK_INSPECT_FAILURE=0
MOCK_TRACE=$test_root/docker.trace
: > "$MOCK_TRACE"

docker() {
  printf '%s\n' "$*" >> "$MOCK_TRACE"
  if [[ ${1:-} == ps ]]; then
    (( MOCK_PS_FAILURE == 0 )) || return 41
    while IFS= read -r service; do
      printf 'id-%s\n' "$service"
    done < <(core_service_names)
    return 0
  fi
  if [[ ${1:-} == inspect ]]; then
    shift 3
    local id service health
    for id in "$@"; do
      service=${id#id-}
      health=healthy
      [[ $service != "$MOCK_BAD_SERVICE" ]] || health=unhealthy
      printf '%s\t%s\trunning\t%s\t2026-08-04T00:00:00Z\t0\n' \
        "$service" "$id" "$health"
    done
    (( MOCK_INSPECT_FAILURE == 0 )) || return 42
    return 0
  fi
  return 42
}

snapshot=$test_root/core-health.tsv
core_services_healthy "$snapshot" || fail "healthy snapshot was rejected: $CORE_HEALTH_DETAIL"
[[ $(wc -l < "$snapshot") == 12 ]] || fail 'healthy snapshot did not contain all core services'
[[ $(wc -l < "$MOCK_TRACE") == 2 ]] || fail 'one health pass did not use exactly two Docker calls'

identity_services=$(core_identity_service_names)
grep -qx 'ca-web' <<< "$identity_services" \
  && fail 'replaceable CA Web frontend remained identity-pinned'
for service in ca-postgres ca index relay01 relay02 relay03 relay04 relay05 relay06 relay07; do
  grep -qx "$service" <<< "$identity_services" \
    || fail "identity-pinned service was omitted: $service"
done
[[ $(wc -l <<< "$identity_services") == 10 ]] \
  || fail 'identity service set contained an unexpected service'

MOCK_INSPECT_FAILURE=1
core_services_healthy "$snapshot" || fail 'partial non-core inspect failure poisoned core health'
[[ $CORE_HEALTH_DETAIL == partial_inspect_ignored ]] \
  || fail "unexpected partial inspect detail $CORE_HEALTH_DETAIL"
MOCK_INSPECT_FAILURE=0

MOCK_BAD_SERVICE=relay03
if core_services_healthy "$snapshot"; then
  fail 'unhealthy Relay was accepted'
fi
[[ $CORE_HEALTH_DETAIL == service_unhealthy ]] || fail "unexpected detail $CORE_HEALTH_DETAIL"
[[ $CORE_HEALTH_UNHEALTHY_SERVICES == relay03:running/unhealthy ]] \
  || fail "unexpected unhealthy services $CORE_HEALTH_UNHEALTHY_SERVICES"
grep -q $'relay03\tid-relay03\trunning\tunhealthy' "$snapshot" \
  || fail 'unhealthy Relay was absent from the diagnostic snapshot'

MOCK_BAD_SERVICE=
MOCK_PS_FAILURE=1
if core_services_healthy "$snapshot"; then
  fail 'Docker query failure was accepted'
fi
[[ $CORE_HEALTH_DETAIL == docker_ps_failed ]] || fail "unexpected query detail $CORE_HEALTH_DETAIL"

if core_health_failure_is_fatal 114 100 3; then
  fail 'failure became fatal before the grace elapsed'
fi
if core_health_failure_is_fatal 115 100 2; then
  fail 'failure became fatal before the minimum sample count'
fi
core_health_failure_is_fatal 115 100 3 || fail 'sustained failure did not become fatal'

printf 'core health grace regression passed\n'
