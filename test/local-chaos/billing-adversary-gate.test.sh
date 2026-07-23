#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
test_dir=$(mktemp -d)
graceful_pid=
stuck_pid=
cleanup() {
  [[ ! $graceful_pid =~ ^[1-9][0-9]*$ ]] || kill -KILL "$graceful_pid" 2>/dev/null || true
  [[ ! $stuck_pid =~ ^[1-9][0-9]*$ ]] || kill -KILL "$stuck_pid" 2>/dev/null || true
  rm -rf "$test_dir"
}
trap cleanup EXIT
source "$ROOT_DIR/test/local-chaos/billing-adversary-gate.sh"

fail() {
  printf 'billing-adversary gate regression failed: %s\n' "$1" >&2
  exit 1
}

write_status() {
  local status=$1 heartbeat=$2 executed=$3 failed=$4 covered=$5 required=$6
  local container_status=${7:-RUNNING} container_executed=${8:-9} container_failed=${9:-0}
  local container_covered=${10:-9} container_required=${11:-9} container_error=${12:-none}
  local temporary=$test_dir/billing-adversary.status.tmp
  printf 'schema_version=1\nstatus=%s\nheartbeat_epoch=%s\nexecuted_checks=%s\nfailed_checks=%s\ncovered_scenarios=%s\nrequired_scenarios=%s\ncontainer_status=%s\ncontainer_executed_checks=%s\ncontainer_failed_checks=%s\ncontainer_covered_scenarios=%s\ncontainer_required_scenarios=%s\ncontainer_error_code=%s\n' \
    "$status" "$heartbeat" "$executed" "$failed" "$covered" "$required" \
    "$container_status" "$container_executed" "$container_failed" "$container_covered" "$container_required" "$container_error" > "$temporary"
  mv "$temporary" "$test_dir/billing-adversary.status"
}

expect_failure() {
  local expected=$1
  shift
  if "$@"; then
    fail "expected $expected but check passed"
  fi
  [[ $BILLING_ADVERSARY_DETAIL == "$expected" ]] \
    || fail "expected $expected, got ${BILLING_ADVERSARY_DETAIL:-empty}"
}

now_epoch=$(date +%s)
write_status RUNNING "$now_epoch" 9 0 9 9
inspect_billing_adversary "$test_dir" "$$" "$now_epoch" 0 \
  || fail "healthy sidecar was rejected: $BILLING_ADVERSARY_DETAIL"

race_failure=
(
  for _ in $(seq 1 1000); do
    write_status RUNNING "$now_epoch" 9 0 9 9
  done
) &
writer_pid=$!
for _ in $(seq 1 1000); do
  if ! inspect_billing_adversary "$test_dir" "$$" "$now_epoch" 0; then
    race_failure=$BILLING_ADVERSARY_DETAIL
    break
  fi
done
wait "$writer_pid"
[[ -z $race_failure ]] \
  || fail "atomic status replacement produced a mixed snapshot: $race_failure"

printf 'schema_version=1\nstatus=RUNNING\nheartbeat_epoch=%s\n' "$now_epoch" > "$test_dir/billing-adversary.status"
expect_failure billing_adversary_status_invalid \
  inspect_billing_adversary "$test_dir" "$$" "$now_epoch" 0

write_status RUNNING "$now_epoch" 9 1 9 9
expect_failure billing_adversary_security_violation \
  inspect_billing_adversary "$test_dir" "$$" "$now_epoch" 0
inspect_billing_adversary "$test_dir" "$$" "$now_epoch" 1 \
  || fail "report mode rejected a recorded violation: $BILLING_ADVERSARY_DETAIL"

write_status RUNNING "$now_epoch" 8 0 8 9
expect_failure billing_adversary_coverage_incomplete \
  inspect_billing_adversary "$test_dir" "$$" "$now_epoch" 0

write_status STARTING "$now_epoch" 9 0 9 9 STARTING 8 0 8 9 none
expect_failure billing_container_probe_coverage_incomplete \
  inspect_billing_adversary "$test_dir" "$$" "$now_epoch" 0

write_status FAILED "$now_epoch" 9 0 9 9 FAILED 9 1 9 9 forged_identity_accepted
expect_failure billing_container_probe_security_violation \
  inspect_billing_adversary "$test_dir" "$$" "$now_epoch" 0
inspect_billing_adversary "$test_dir" "$$" "$now_epoch" 1 \
  || fail "report mode rejected a container-fixture violation: $BILLING_ADVERSARY_DETAIL"

write_status FAILED "$now_epoch" 9 0 9 9 FAILED 0 1 0 9 container_probe_heartbeat_stale
expect_failure billing_container_probe_heartbeat_stale \
  inspect_billing_adversary "$test_dir" "$$" "$now_epoch" 1

write_status RUNNING "$now_epoch" 1 0 1 1
expect_failure billing_adversary_coverage_incomplete \
  inspect_billing_adversary "$test_dir" "$$" "$now_epoch" 0

write_status RUNNING "$((now_epoch - 21))" 9 0 9 9
expect_failure billing_adversary_heartbeat_stale \
  inspect_billing_adversary "$test_dir" "$$" "$now_epoch" 0

write_status DEGRADED "$now_epoch" 9 0 9 9
expect_failure billing_adversary_unhealthy_status \
  inspect_billing_adversary "$test_dir" "$$" "$now_epoch" 0

write_status RUNNING "$now_epoch" 9 0 9 9
printf '{"status":"SECURITY_INVARIANT_FAILED"}\n' > "$test_dir/billing-adversary.alert"
expect_failure billing_adversary_security_violation \
  inspect_billing_adversary "$test_dir" "$$" "$now_epoch" 0
rm -f "$test_dir/billing-adversary.alert"

write_status RUNNING "$now_epoch" 9 0 9 9
expect_failure billing_adversary_final_status_invalid \
  inspect_billing_adversary_final "$test_dir" "$now_epoch" 0
write_status STOPPED "$now_epoch" 9 0 9 9
inspect_billing_adversary_final "$test_dir" "$now_epoch" 0 \
  || fail "healthy final snapshot was rejected: $BILLING_ADVERSARY_DETAIL"
write_status FAILED "$now_epoch" 9 1 9 9
expect_failure billing_adversary_security_violation \
  inspect_billing_adversary_final "$test_dir" "$now_epoch" 0
inspect_billing_adversary_final "$test_dir" "$now_epoch" 1 \
  || fail "report mode rejected its final violation snapshot: $BILLING_ADVERSARY_DETAIL"

write_status RUNNING "$now_epoch" 9 0 9 9
expect_failure billing_adversary_exited \
  inspect_billing_adversary "$test_dir" 999999999 "$now_epoch" 0

bash -c 'trap "sleep 3; exit 0" TERM; while :; do sleep 0.1; done' &
graceful_pid=$!
sleep 0.1
stop_billing_adversary "$graceful_pid" \
  || fail "sidecar did not receive enough time for a three-second in-flight request"

bash -c 'trap "" TERM; while :; do sleep 0.1; done' &
stuck_pid=$!
sleep 0.1
if stop_billing_adversary "$stuck_pid" 2; then
	fail "unresponsive sidecar stop unexpectedly succeeded"
fi

stability_script=$ROOT_DIR/scripts/local-chaos-stability.sh
production_gate_line=$(awk '/^[[:space:]]*if ! run_billing_production_gate / { print NR; exit }' "$stability_script")
container_provision_line=$(awk '/^[[:space:]]*if ! provision_container_adversaries / { print NR; exit }' "$stability_script")
adversary_start_line=$(awk '/billing_adversary_pid=[$][(]start_billing_adversary/ { print NR; exit }' "$stability_script")
[[ $production_gate_line =~ ^[1-9][0-9]*$ && $container_provision_line =~ ^[1-9][0-9]*$ \
	&& $adversary_start_line =~ ^[1-9][0-9]*$ \
	&& production_gate_line -lt container_provision_line \
	&& container_provision_line -lt adversary_start_line ]] \
	|| fail "container adversaries were not provisioned strictly after the production CA outage gate"

printf 'billing-adversary gate regression passed\n'
