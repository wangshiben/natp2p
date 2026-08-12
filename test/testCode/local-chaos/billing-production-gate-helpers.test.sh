#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
test_root=$(mktemp -d)
cleanup() {
  rm -rf "$test_root"
}
trap cleanup EXIT

source "$ROOT_DIR/test/runtimeScript/local-chaos/billing-production-gate.sh"

fail() {
  printf 'billing production gate helper regression failed: %s\n' "$1" >&2
  exit 1
}

events=$test_root/events
: > "$events"

stop_nat_process() {
  printf 'stop\n' >> "$events"
}
launch_tunnel_client() {
  printf 'launch\n' >> "$events"
  return "${MOCK_LAUNCH_RC:-0}"
}
wait_client_ready() {
  printf 'wait\n' >> "$events"
}
billing_production_gate_assert_client_alive() {
  printf 'alive\n' >> "$events"
}

MOCK_LAUNCH_RC=7
if billing_production_gate_start_client natclient01 "$(printf 'a%.0s' {1..64})" 18101; then
  fail 'client launch failure was ignored'
fi
grep -q '^launch$' "$events" || fail 'client launch was not attempted'
if grep -qE '^(wait|alive)$' "$events"; then
  fail 'readiness checks ran after client launch failure'
fi

: > "$events"
MOCK_LAUNCH_RC=0
billing_production_gate_start_client natclient01 "$(printf 'a%.0s' {1..64})" 18101 \
  || fail 'healthy client launch did not pass readiness'
printf 'stop\nlaunch\nwait\nalive\n' > "$test_root/expected-start-events"
cmp -s "$events" "$test_root/expected-start-events" \
  || fail 'client launch/readiness order changed'

(
  : > "$events"
  REAL_BILLING_GATE_CLIENT_HEARTBEAT_SAMPLES=3
  REAL_BILLING_GATE_CLIENT_HEARTBEAT_INTERVAL_SECONDS=1
  sleep() {
    printf 'sleep:%s\n' "$1" >> "$events"
  }
  billing_production_gate_assert_client_alive() {
    printf 'heartbeat\n' >> "$events"
  }
  billing_production_gate_wait_client_heartbeat natclient01 18101 \
    || fail 'healthy three-second heartbeat barrier failed'
  [[ $(grep -c '^sleep:1$' "$events") -eq 3 ]] \
    || fail 'heartbeat barrier did not preserve three one-second intervals'
  [[ $(grep -c '^heartbeat$' "$events") -eq 4 ]] \
    || fail 'heartbeat barrier did not check before and after every interval'
)

restart_events=$test_root/restart-events
: > "$restart_events"
expected_server_id=$(printf 'c%.0s' {1..64})
relay_registration_count() {
  printf 'count:%s:%s\n' "$1" "$2" >> "$restart_events"
  printf '10\n'
}
restart_tunnel_server() {
  printf 'restart:%s:%s:%s\n' "$1" "$2" "$3" >> "$restart_events"
  printf '%s\n' "$expected_server_id"
}
wait_relay_registration_generation() {
  printf 'generation:%s:%s:%s:%s\n' "$1" "$2" "$3" "$4" >> "$restart_events"
  [[ $1 == relay04 && $2 == "$expected_server_id" && $3 == 10 && $4 == 45 ]]
}
billing_production_gate_restart_server natserver06 relay04 "$expected_server_id" \
  || fail 'healthy recovery server registration generation failed'
printf 'count:relay04:%s\nrestart:natserver06:relay04:9000:random-workload\ngeneration:relay04:%s:10:45\n' \
  "$expected_server_id" "$expected_server_id" > "$test_root/expected-restart-events"
cmp -s "$restart_events" "$test_root/expected-restart-events" \
  || fail 'server restart did not wait for a new two-leg registration generation'

PRIVATE_RUNTIME_DIR=$test_root/private
mkdir -p "$PRIVATE_RUNTIME_DIR/relay04" "$PRIVATE_RUNTIME_DIR/natclient01" \
  "$PRIVATE_RUNTIME_DIR/natserver06"
chmod 700 "$PRIVATE_RUNTIME_DIR/relay04" "$PRIVATE_RUNTIME_DIR/natclient01" \
  "$PRIVATE_RUNTIME_DIR/natserver06"

MOCK_CA_PROBE=unavailable
dc() {
  if [[ ${3:-} == relay04 ]]; then
    case "$MOCK_CA_PROBE" in
      unavailable)
        printf 'curl: (28) operation timed out\n' >&2
        printf '28\n'
        ;;
      reachable)
        printf '0\n'
        ;;
      exec-failed)
        printf 'compose exec failed\n' >&2
        return 125
        ;;
    esac
    return
  fi
  return 1
}

billing_production_gate_assert_ca_unavailable relay04 \
  || fail 'unavailable CA was not accepted'
grep -q '^stage=ca_unavailable$' \
  "$PRIVATE_RUNTIME_DIR/relay04/billing-production-gate-ca-probe.status" \
  || fail 'CA-unavailable stage was not preserved'
grep -q '^curl_rc=28$' \
  "$PRIVATE_RUNTIME_DIR/relay04/billing-production-gate-ca-probe.status" \
  || fail 'CA curl exit code was not preserved'
grep -q 'operation timed out' \
  "$PRIVATE_RUNTIME_DIR/relay04/billing-production-gate-ca-probe.stderr" \
  || fail 'CA probe stderr was not preserved privately'

MOCK_CA_PROBE=reachable
ca_probe_rc=0
billing_production_gate_assert_ca_unavailable relay04 || ca_probe_rc=$?
[[ $ca_probe_rc -eq 1 ]] || fail 'reachable CA did not return the distinct reachable result'
grep -q '^stage=ca_reachable$' \
  "$PRIVATE_RUNTIME_DIR/relay04/billing-production-gate-ca-probe.status" \
  || fail 'CA-reachable stage was not preserved'

MOCK_CA_PROBE=exec-failed
ca_probe_rc=0
billing_production_gate_assert_ca_unavailable relay04 || ca_probe_rc=$?
[[ $ca_probe_rc -eq 2 ]] || fail 'Compose exec failure was confused with CA unavailability'
grep -q '^stage=exec_failed$' \
  "$PRIVATE_RUNTIME_DIR/relay04/billing-production-gate-ca-probe.status" \
  || fail 'CA probe exec failure stage was not preserved'
grep -q '^exec_rc=125$' \
  "$PRIVATE_RUNTIME_DIR/relay04/billing-production-gate-ca-probe.status" \
  || fail 'CA probe exec failure code was not preserved'
grep -q '^curl_rc=not_observed$' \
  "$PRIVATE_RUNTIME_DIR/relay04/billing-production-gate-ca-probe.status" \
  || fail 'CA probe incorrectly invented a curl result after exec failure'

printf '{"version":1,"billing_enabled":true,"active_session_count":1}\n' \
  > "$PRIVATE_RUNTIME_DIR/natserver06/billing-meter.json"
download_calls=$test_root/download-calls
: > "$download_calls"
MOCK_DOWNLOAD=curl-failed
MOCK_EXPECTED_SHA=$(printf 'b%.0s' {1..64})
dc() {
  local service=${3:-}
  if [[ $service == natserver06 ]]; then
    printf '%s\n' "$MOCK_EXPECTED_SHA"
    return 0
  fi
  if [[ $service == natclient01 ]]; then
    printf 'client\n' >> "$download_calls"
    if [[ $MOCK_DOWNLOAD == curl-failed ]]; then
      printf 'curl: (18) transfer closed with outstanding data\n' >&2
      printf '18\t1234\t\n'
    else
      printf '0\t1048576\t%s\n' "$MOCK_EXPECTED_SHA"
    fi
    return 0
  fi
  return 1
}

if billing_production_gate_download primary natserver06 natclient01 18101 4; then
  fail 'failed single curl unexpectedly passed'
fi
primary_status=$PRIVATE_RUNTIME_DIR/natclient01/billing-production-gate-primary-download.status
grep -q '^stage=curl_failed$' "$primary_status" \
  || fail 'curl failure stage was not preserved'
grep -q '^exec_rc=0$' "$primary_status" \
  || fail 'successful Compose exec was not distinguished from curl failure'
grep -q '^curl_rc=18$' "$primary_status" \
  || fail 'curl exit code was not preserved'
grep -q '^actual_bytes=1234$' "$primary_status" \
  || fail 'partial transfer byte count was not preserved'
grep -q '^expected_bytes=4194304$' "$primary_status" \
  || fail 'expected transfer byte count was not preserved'
grep -q 'transfer closed with outstanding data' \
  "$PRIVATE_RUNTIME_DIR/natclient01/billing-production-gate-primary-curl.stderr" \
  || fail 'curl stderr was not preserved privately'
grep -q '"active_session_count":1' \
  "$PRIVATE_RUNTIME_DIR/natserver06/billing-production-gate-primary-nat-snapshot.json" \
  || fail 'failure-time NAT billing snapshot was not frozen'
[[ $(wc -l < "$download_calls") -eq 1 ]] \
  || fail 'failed transfer was retried'

: > "$download_calls"
MOCK_DOWNLOAD=success
download_bytes=$(billing_production_gate_download recovery natserver06 natclient01 18101 1) \
  || fail 'healthy single curl failed'
[[ $download_bytes == 1048576 ]] || fail 'healthy transfer returned the wrong size'
recovery_status=$PRIVATE_RUNTIME_DIR/natclient01/billing-production-gate-recovery-download.status
grep -q '^stage=verified$' "$recovery_status" \
  || fail 'verified transfer stage was not preserved'
grep -q '^curl_rc=0$' "$recovery_status" \
  || fail 'successful curl result was not preserved'
grep -q '^actual_bytes=1048576$' "$recovery_status" \
  || fail 'successful transfer byte count was not preserved'
[[ $(wc -l < "$download_calls") -eq 1 ]] \
  || fail 'healthy transfer ran more than once'

[[ $(stat -c '%a' "$primary_status") == 600 ]] \
  || fail 'private download evidence permissions were not 0600'
[[ $(stat -c '%a' "$PRIVATE_RUNTIME_DIR/relay04/billing-production-gate-ca-probe.stderr") == 600 ]] \
  || fail 'private CA stderr permissions were not 0600'

public_run=$test_root/public-run
mkdir -p "$public_run"
write_billing_production_gate_snapshot "$public_run" FAILED \
  billing_production_gate_transfer_failed 0 0 0 0 0 0 0 false false 0 0 0
write_billing_production_gate_status "$public_run" FAILED \
  billing_production_gate_transfer_failed
if grep -Eq 'curl_rc|actual_bytes|operation timed out|transfer closed|active_session_count' \
  "$public_run/billing-production-gate.json" "$public_run/billing-production-gate.status"; then
  fail 'private transfer or NAT evidence leaked into public gate artifacts'
fi

printf 'billing production gate helper regression passed\n'
