#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
test_root=$(mktemp -d)
cleanup() {
  rm -rf "$test_root"
}
trap cleanup EXIT

source "$ROOT_DIR/test/local-chaos/billing-production-gate.sh"

REAL_BILLING_GATE_QUEUE_TIMEOUT_SECONDS=3
REAL_BILLING_GATE_RECOVERY_TIMEOUT_SECONDS=3
REAL_BILLING_GATE_STABLE_SAMPLES=2
PRIVATE_RUNTIME_DIR=$test_root/private
MOCK_EVENTS=$test_root/events
mkdir -p "$PRIVATE_RUNTIME_DIR"
: > "$MOCK_EVENTS"

fail() {
  printf 'billing production gate regression failed: %s\n' "$1" >&2
  exit 1
}

mock_event() {
  printf '%s\n' "$1" >> "$MOCK_EVENTS"
}

mock_event_count() {
  local event=$1
  grep -Fxc "$event" "$MOCK_EVENTS" 2>/dev/null || true
}

reset_mocks() {
  : > "$MOCK_EVENTS"
  MOCK_DIGEST_CHANGE=0
  MOCK_AUTHORIZED_BYTES=4811576
  MOCK_OBSERVED_BYTES=4900000
  MOCK_COSIGNED_BYTES=4811576
  MOCK_PAYER_DEBIT=4811576
  MOCK_RELAY_CREDIT=4570997
  MOCK_RELAY_INCOME_CREDIT=4570997
  MOCK_CHANNEL_COUNT=1
  MOCK_CHANNEL_GROSS=4811576
  MOCK_CHANNEL_RELAY=4570997
  MOCK_CHANNEL_CA=240579
  MOCK_GLOBAL_CA_NOISE=39322
	MOCK_RECOVERY_DOWNLOAD_FAIL=0
}

billing_production_gate_resolve_payer() { printf '%064d\n' 1; }
billing_production_gate_resolve_relay() { printf '%064d\n' 2; }
billing_production_gate_container_identity() { printf '%064d\n' 3; }
billing_production_gate_relay_registration_count() { printf '1\n'; }
billing_production_gate_inspect_live() {
  local calls
  calls=$(mock_event_count inspect_live)
  mock_event inspect_live
  if (( calls == 0 )); then
    printf 'billingqueue-wal/v3\t0\t0\tfalse\t0\t0\t0\n'
  else
    printf 'billingqueue-wal/v3\t5\t5000\tfalse\t5\t%s\t1\n' "$MOCK_AUTHORIZED_BYTES"
  fi
}
billing_production_gate_inspect_host() {
  local calls
  calls=$(mock_event_count inspect_host)
  mock_event inspect_host
  if (( calls == 0 )); then
    printf 'billingqueue-wal/v3\t5\t5000\tfalse\t5\t%s\t1\n' "$MOCK_AUTHORIZED_BYTES"
  else
    printf 'billingqueue-wal/v3\t0\t0\tfalse\t0\t0\t0\n'
  fi
}
billing_production_gate_read_nat_observation() {
  local calls generated_milliseconds
  calls=$(mock_event_count nat_observation)
  mock_event nat_observation
  generated_milliseconds=$(date +%s%3N)
  if (( calls == 0 )); then
    printf '1\ttrue\t1\t0\t0\ttrue\t%s\n' "$generated_milliseconds"
  else
    printf '1\ttrue\t1\t%s\t%s\ttrue\t%s\n' \
      "$MOCK_OBSERVED_BYTES" "$MOCK_COSIGNED_BYTES" "$generated_milliseconds"
  fi
}
billing_production_gate_queue_digest() {
  local calls
  calls=$(mock_event_count queue_digest)
  mock_event queue_digest
  if (( MOCK_DIGEST_CHANGE == 1 && calls > 0 )); then
    printf '%064d\n' 5
  else
    printf '%064d\n' 4
  fi
}
billing_production_gate_read_balance() {
  local node_id=$1 calls
  calls=$(mock_event_count "balance:$node_id")
  mock_event "balance:$node_id"
  if [[ $node_id == "$(printf '%064d' 1)" ]]; then
    if (( calls == 0 )); then printf '10000000\n'; else printf '%s\n' "$((10000000 - MOCK_PAYER_DEBIT))"; fi
  else
    if (( calls == 0 )); then printf '0\n'; else printf '%s\n' "$MOCK_RELAY_CREDIT"; fi
  fi
}
billing_production_gate_read_accounting() {
  local calls
  calls=$(mock_event_count accounting)
  mock_event accounting
  if (( calls == 0 )); then
    printf '100\t200\t7\t0\t0\t0\t0\n'
  else
    printf '%s\t%s\t10\t%s\t%s\t%s\t%s\n' \
      "$((100 + MOCK_CHANNEL_CA + MOCK_GLOBAL_CA_NOISE))" \
      "$((200 + MOCK_RELAY_INCOME_CREDIT))" \
      "$MOCK_CHANNEL_COUNT" "$MOCK_CHANNEL_GROSS" "$MOCK_CHANNEL_RELAY" "$MOCK_CHANNEL_CA"
  fi
}
billing_production_gate_start_client() {
  if (( $(mock_event_count start_client) == 0 )); then
    mock_event start_client
  else
    mock_event recovery_start_client
  fi
}
billing_production_gate_stop_client() {
  if (( $(mock_event_count stop_client) == 0 )); then
    mock_event stop_client
  else
    mock_event recovery_stop_client
  fi
}
billing_production_gate_restart_server() { mock_event restart_server; }
billing_production_gate_cleanup_download() { mock_event cleanup_download; }
billing_production_gate_pause_ca() { mock_event pause_ca; }
billing_production_gate_resume_ca() { mock_event resume_ca; }
billing_production_gate_assert_ca_unavailable() { mock_event ca_unavailable; }
billing_production_gate_wait_client_heartbeat() {
  if (( $(mock_event_count client_heartbeat) == 0 )); then
    mock_event client_heartbeat
  else
    mock_event recovery_client_heartbeat
  fi
}
billing_production_gate_download() {
  local size_mib=$5
  if (( $(mock_event_count download) == 0 )); then
    mock_event download
  else
    mock_event recovery_download
    (( MOCK_RECOVERY_DOWNLOAD_FAIL == 0 )) || return 1
  fi
  printf '%s\n' "$((size_mib * REAL_BILLING_GATE_WINDOW_BYTES))"
}
billing_production_gate_crash_relay() { mock_event crash_relay; }
billing_production_gate_start_relay() { mock_event start_relay; }

make_run_dir() {
  local name=$1 run_dir
  run_dir=$test_root/$name
  mkdir -p "$run_dir/server-fresh" "$PRIVATE_RUNTIME_DIR/natserver06"
  : > "$run_dir/server-fresh/natserver06"
  : > "$PRIVATE_RUNTIME_DIR/natserver06/billing-meter.json"
  printf 'server\tingress_relay\tnode_id\n' > "$run_dir/server-pool.tsv"
  printf '%s\n' "$run_dir"
}

assert_event_before() {
  local first=$1 second=$2 first_line second_line
  first_line=$(grep -n -m1 -Fx "$first" "$MOCK_EVENTS" | cut -d: -f1)
  second_line=$(grep -n -m1 -Fx "$second" "$MOCK_EVENTS" | cut -d: -f1)
  [[ $first_line =~ ^[0-9]+$ && $second_line =~ ^[0-9]+$ && first_line -lt second_line ]] \
    || fail "event order $first -> $second was not preserved"
}

assert_failure_detail() {
  local run_dir=$1 expected=$2 description=$3
  grep -q '^status=FAILED$' "$run_dir/billing-production-gate.status" \
    || fail "$description did not persist FAILED status"
  grep -q "^detail=$expected$" "$run_dir/billing-production-gate.status" \
    || fail "$description did not produce $expected"
}

reset_mocks
pass_run=$(make_run_dir pass)
run_billing_production_gate "$pass_run" || fail "healthy mocked production gate failed"
grep -q '^status=PASSED$' "$pass_run/billing-production-gate.status" \
  || fail "successful gate status was not persisted"
node -e '
  const fs = require("fs");
  const value = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  const expected = ["amountVerified", "authorizedBillableBytes", "caCredit", "detail", "observedAt", "observedBillableBytes", "payerDebit", "queueDepthAfterRecovery", "queueDepthAfterRestart", "queueDepthBefore", "relayCredit", "schemaVersion", "splitVerified", "status", "transferBytes", "unsettledTailBytes"];
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(expected)) process.exit(1);
  if (value.schemaVersion !== 2 || value.status !== "PASSED" || value.queueDepthBefore !== 5 || value.queueDepthAfterRestart !== 5
    || value.queueDepthAfterRecovery !== 0 || value.transferBytes !== 4194304 || value.observedBillableBytes !== 4900000
    || value.authorizedBillableBytes !== 4811576 || value.payerDebit !== 4811576 || value.unsettledTailBytes !== 88424
    || value.relayCredit !== 4570997 || value.caCredit !== 240579 || value.detail !== "verified"
    || value.amountVerified !== true || value.splitVerified !== true || typeof value.observedAt !== "string") process.exit(1);
' "$pass_run/billing-production-gate.json" || fail "schema-v2 public gate snapshot was invalid or not strictly redacted"
assert_event_before start_client pause_ca
assert_event_before pause_ca client_heartbeat
assert_event_before client_heartbeat download
assert_event_before download stop_client
assert_event_before stop_client crash_relay
assert_event_before crash_relay resume_ca
assert_event_before resume_ca start_relay
assert_event_before start_relay restart_server
assert_event_before restart_server recovery_start_client
assert_event_before start_relay recovery_start_client
assert_event_before recovery_start_client recovery_client_heartbeat
assert_event_before recovery_client_heartbeat recovery_download
assert_event_before recovery_download recovery_stop_client
[[ $(mock_event_count stop_client) == 1 ]] || fail "probe client was not stopped exactly once"
[[ $(mock_event_count recovery_stop_client) == 1 ]] || fail "recovery client was not stopped exactly once"

reset_mocks
MOCK_DIGEST_CHANGE=1
persistence_run=$(make_run_dir persistence-failure)
if run_billing_production_gate "$persistence_run"; then
  fail "changed crash-persistent WAL unexpectedly passed"
fi
assert_failure_detail "$persistence_run" billing_production_gate_queue_persistence_changed "WAL mutation"
[[ $(mock_event_count resume_ca) == 1 ]] || fail "CA was not restored by the failure trap"
[[ $(mock_event_count stop_client) == 1 ]] || fail "probe client was not stopped by the failure trap"
[[ $(mock_event_count start_relay) == 1 ]] \
  || fail "Relay was not restored exactly once by the failure trap"
assert_event_before resume_ca start_relay

reset_mocks
MOCK_PAYER_DEBIT=$((MOCK_AUTHORIZED_BYTES + 1))
overcharge_run=$(make_run_dir payer-overcharge)
if run_billing_production_gate "$overcharge_run"; then
  fail "payer debit above the dual-signed authorization unexpectedly passed"
fi
assert_failure_detail "$overcharge_run" billing_production_gate_payer_overcharged "authorized+1 overcharge"

reset_mocks
MOCK_OBSERVED_BYTES=$((MOCK_AUTHORIZED_BYTES + REAL_BILLING_GATE_WINDOW_BYTES))
tail_run=$(make_run_dir tail-boundary)
if run_billing_production_gate "$tail_run"; then
  fail "an unsettled billable tail equal to W unexpectedly passed"
fi
assert_failure_detail "$tail_run" billing_production_gate_unbilled_tail_invalid "billable tail boundary"

reset_mocks
MOCK_CHANNEL_GROSS=$((MOCK_AUTHORIZED_BYTES - 1))
channel_gross_run=$(make_run_dir channel-gross-undercount)
if run_billing_production_gate "$channel_gross_run"; then
  fail "an undercounted target channel gross unexpectedly passed"
fi
assert_failure_detail "$channel_gross_run" billing_production_gate_channel_accounting_mismatch "target channel gross undercount"

reset_mocks
MOCK_CHANNEL_CA=$((MOCK_CHANNEL_CA - 1000))
MOCK_GLOBAL_CA_NOISE=1000
masked_ca_run=$(make_run_dir globally-masked-ca-undercount)
if run_billing_production_gate "$masked_ca_run"; then
  fail "global CA noise masked an undercounted target-channel CA share"
fi
assert_failure_detail "$masked_ca_run" billing_production_gate_ca_split_mismatch "target CA share undercount"

redaction_run=$(make_run_dir detail-redaction)
secret_detail=$'private/path\nsecret_node=abcdef'
write_billing_production_gate_snapshot "$redaction_run" FAILED "$secret_detail" 1 1 0 \
  4194304 4811576 4570997 240579 false false 4900000 4811576 88424
write_billing_production_gate_status "$redaction_run" FAILED "$secret_detail"
grep -q '^detail=billing_production_gate_failed$' "$redaction_run/billing-production-gate.status" \
  || fail "unknown private detail was not mapped to the generic error code"
if grep -R -Fq 'private/path' "$redaction_run/billing-production-gate."* \
  || grep -R -Fq 'secret_node' "$redaction_run/billing-production-gate."*; then
  fail "private detail leaked into the production gate artifacts"
fi

reset_mocks
MOCK_RECOVERY_DOWNLOAD_FAIL=1
recovery_failure_run=$(make_run_dir recovery-transfer-failure)
if run_billing_production_gate "$recovery_failure_run"; then
  fail "failed post-restart transfer unexpectedly passed"
fi
assert_failure_detail "$recovery_failure_run" billing_production_gate_recovery_transfer_failed "post-restart transfer failure"

printf 'billing production gate regression passed\n'
