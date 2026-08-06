#!/usr/bin/env bash

REAL_BILLING_GATE_WINDOW_BYTES=1048576
REAL_BILLING_GATE_MIN_DEPTH=3
REAL_BILLING_GATE_TRANSFER_MIB=4
REAL_BILLING_GATE_RECOVERY_TRANSFER_MIB=1
REAL_BILLING_GATE_QUEUE_TIMEOUT_SECONDS=30
REAL_BILLING_GATE_RECOVERY_TIMEOUT_SECONDS=90
REAL_BILLING_GATE_STABLE_SAMPLES=10
REAL_BILLING_GATE_RELAY=relay04
REAL_BILLING_GATE_CLIENT_HEARTBEAT_SAMPLES=3
REAL_BILLING_GATE_CLIENT_HEARTBEAT_INTERVAL_SECONDS=1
REAL_BILLING_GATE_SERVER_REGISTRATION_TIMEOUT_SECONDS=45

write_billing_production_gate_snapshot() {
  local run_dir=$1 status=$2 detail=$3 depth_before=$4 depth_after_restart=$5 depth_after_recovery=$6
  local transfer_bytes=${7:-0} payer_debit=${8:-0} relay_credit=${9:-0} ca_credit=${10:-0}
  local amount_verified=${11:-false} split_verified=${12:-false}
  local observed_billable_bytes=${13:-0} authorized_billable_bytes=${14:-0} unsettled_tail_bytes=${15:-0}
  local observed_at temporary sanitized_detail
  [[ $status == STARTING || $status == PASSED || $status == FAILED ]] || status=FAILED
  sanitized_detail=$(billing_production_gate_detail_for_status "$status" "$detail")
  [[ $depth_before =~ ^[0-9]+$ ]] || depth_before=0
  [[ $depth_after_restart =~ ^[0-9]+$ ]] || depth_after_restart=0
  [[ $depth_after_recovery =~ ^[0-9]+$ ]] || depth_after_recovery=0
  [[ $transfer_bytes =~ ^[0-9]+$ ]] || transfer_bytes=0
  [[ $payer_debit =~ ^[0-9]+$ ]] || payer_debit=0
  [[ $relay_credit =~ ^[0-9]+$ ]] || relay_credit=0
  [[ $ca_credit =~ ^[0-9]+$ ]] || ca_credit=0
  [[ $observed_billable_bytes =~ ^[0-9]+$ ]] || observed_billable_bytes=0
  [[ $authorized_billable_bytes =~ ^[0-9]+$ ]] || authorized_billable_bytes=0
  [[ $unsettled_tail_bytes =~ ^[0-9]+$ ]] || unsettled_tail_bytes=0
  [[ $amount_verified == true || $amount_verified == false ]] || amount_verified=false
  [[ $split_verified == true || $split_verified == false ]] || split_verified=false
  observed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  temporary=$run_dir/billing-production-gate.json.tmp.$$
  printf '{"schemaVersion":2,"status":"%s","detail":"%s","queueDepthBefore":%s,"queueDepthAfterRestart":%s,"queueDepthAfterRecovery":%s,"transferBytes":%s,"observedBillableBytes":%s,"authorizedBillableBytes":%s,"payerDebit":%s,"unsettledTailBytes":%s,"relayCredit":%s,"caCredit":%s,"amountVerified":%s,"splitVerified":%s,"observedAt":"%s"}\n' \
    "$status" "$sanitized_detail" "$depth_before" "$depth_after_restart" "$depth_after_recovery" \
    "$transfer_bytes" "$observed_billable_bytes" "$authorized_billable_bytes" "$payer_debit" \
    "$unsettled_tail_bytes" "$relay_credit" "$ca_credit" "$amount_verified" "$split_verified" \
    "$observed_at" > "$temporary"
  mv "$temporary" "$run_dir/billing-production-gate.json"
}

write_billing_production_gate_status() {
  local run_dir=$1 status=$2 detail=$3 temporary sanitized_detail
  [[ $status == STARTING || $status == PASSED || $status == FAILED ]] || status=FAILED
  sanitized_detail=$(billing_production_gate_detail_for_status "$status" "$detail")
  temporary=$run_dir/billing-production-gate.status.tmp.$$
  printf 'schema_version=1\nstatus=%s\ndetail=%s\n' "$status" "$sanitized_detail" > "$temporary"
  mv "$temporary" "$run_dir/billing-production-gate.status"
}

billing_production_gate_fail() {
  local run_dir=$1 detail=$2 depth_before=${3:-0} depth_after_restart=${4:-0}
  local depth_after_recovery=${5:-0} payer_debit=${6:-0} relay_credit=${7:-0}
  local transfer_bytes=${8:-0} ca_credit=${9:-0} amount_verified=${10:-false}
  local observed_billable_bytes=${11:-0} authorized_billable_bytes=${12:-0} unsettled_tail_bytes=${13:-0}
  write_billing_production_gate_snapshot "$run_dir" FAILED "$detail" "$depth_before" "$depth_after_restart" \
    "$depth_after_recovery" "$transfer_bytes" "$payer_debit" "$relay_credit" "$ca_credit" \
    "$amount_verified" false "$observed_billable_bytes" "$authorized_billable_bytes" "$unsettled_tail_bytes"
  write_billing_production_gate_status "$run_dir" FAILED "$detail"
}

billing_production_gate_public_detail() {
  case ${1:-} in
    initializing|verified|billing_production_gate_failed \
      |billing_production_gate_cleanup_failed \
      |billing_production_gate_actor_missing \
      |billing_production_gate_channel_not_fresh \
      |billing_production_gate_relay_identity_missing \
      |billing_production_gate_relay_registration_missing \
      |billing_production_gate_inspector_unavailable \
      |billing_production_gate_inspection_invalid \
      |billing_production_gate_queue_not_empty \
      |billing_production_gate_client_start_failed \
      |billing_production_gate_balance_read_failed \
      |billing_production_gate_accounting_read_failed \
      |billing_production_gate_ca_pause_failed \
      |billing_production_gate_ca_disconnect_not_observed \
      |billing_production_gate_transfer_failed \
      |billing_production_gate_producer_freeze_failed \
      |billing_production_gate_queue_depth_not_reached \
      |billing_production_gate_queue_digest_failed \
      |billing_production_gate_relay_crash_failed \
      |billing_production_gate_crash_inspection_failed \
      |billing_production_gate_queue_persistence_changed \
      |billing_production_gate_client_stop_failed \
      |billing_production_gate_ca_resume_failed \
      |billing_production_gate_relay_start_failed \
      |billing_production_gate_queue_recovery_timeout \
      |billing_production_gate_recovery_server_restart_failed \
      |billing_production_gate_recovery_client_start_failed \
      |billing_production_gate_recovery_transfer_failed \
      |billing_production_gate_recovery_client_stop_failed \
      |billing_production_gate_recovery_queue_timeout \
      |billing_production_gate_balance_delta_invalid \
      |billing_production_gate_nat_snapshot_unavailable \
      |billing_production_gate_nat_snapshot_invalid \
      |billing_production_gate_nat_snapshot_unstable \
      |billing_production_gate_authorization_invalid \
      |billing_production_gate_authorized_amount_mismatch \
      |billing_production_gate_payer_overcharged \
      |billing_production_gate_payer_debit_mismatch \
      |billing_production_gate_unbilled_tail_invalid \
      |billing_production_gate_channel_accounting_mismatch \
      |billing_production_gate_relay_income_mismatch \
      |billing_production_gate_split_mismatch \
      |billing_production_gate_ca_split_mismatch)
      printf '%s\n' "$1"
      ;;
    *) return 1 ;;
  esac
}

billing_production_gate_detail_for_status() {
  local status=$1 detail=$2
  if [[ $status == STARTING ]]; then
    printf 'initializing\n'
    return
  fi
  if [[ $status == PASSED ]]; then
    printf 'verified\n'
    return
  fi
  detail=$(billing_production_gate_public_detail "$detail" 2>/dev/null) \
    || detail=billing_production_gate_failed
  if [[ $detail == initializing || $detail == verified ]]; then
    detail=billing_production_gate_failed
  fi
  printf '%s\n' "$detail"
}

read_billing_production_gate_detail() {
  local status_file=$1 status detail
  status=$(awk -F= '$1 == "status" { print $2; exit }' "$status_file") || return 1
  [[ $status == FAILED ]] || return 1
  detail=$(awk -F= '$1 == "detail" { print $2; exit }' "$status_file") || return 1
  billing_production_gate_detail_for_status "$status" "$detail"
}

parse_billing_queue_inspection() {
  local encoded=$1 schema depth payload_bytes incomplete_tail channel_depth authorized_bytes session_count
  schema=$(sed -n 's/.*"schema":"\([^"]*\)".*/\1/p' <<< "$encoded")
  depth=$(sed -n 's/.*"depth":\([0-9][0-9]*\).*/\1/p' <<< "$encoded")
  payload_bytes=$(sed -n 's/.*"payload_bytes":\([0-9][0-9]*\).*/\1/p' <<< "$encoded")
  incomplete_tail=$(sed -n 's/.*"incomplete_tail":\(true\|false\).*/\1/p' <<< "$encoded")
  channel_depth=$(sed -n 's/.*"channel_depth":\([0-9][0-9]*\).*/\1/p' <<< "$encoded")
  authorized_bytes=$(sed -n 's/.*"authorized_bytes":\([0-9][0-9]*\).*/\1/p' <<< "$encoded")
  session_count=$(sed -n 's/.*"session_count":\([0-9][0-9]*\).*/\1/p' <<< "$encoded")
  [[ $schema == billingqueue-wal/v3 && $depth =~ ^[0-9]+$ \
    && $payload_bytes =~ ^[0-9]+$ && $incomplete_tail =~ ^(true|false)$ \
    && $channel_depth =~ ^[0-9]+$ && $authorized_bytes =~ ^[0-9]+$ \
    && $session_count =~ ^[0-9]+$ ]] || return 1
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$schema" "$depth" "$payload_bytes" \
    "$incomplete_tail" "$channel_depth" "$authorized_bytes" "$session_count"
}

billing_production_gate_inspect_live() {
  local run_dir=$1 payer=$2 relay=$3 payer_id=${4:-} relay_id=${5:-} inspector encoded
  inspector=$run_dir/build-runtime/build/billingqueue-inspect
  [[ -x $inspector ]] || return 1
  encoded=$("$inspector" -path "$PRIVATE_RUNTIME_DIR/$relay/wait-submit.queue" \
    -payer-id "$payer_id" -relay-id "$relay_id" \
    -relay-key "$PRIVATE_RUNTIME_DIR/$relay/identity.key" \
    -payer-billing-key "$PRIVATE_RUNTIME_DIR/$payer/billing-private.key" \
    -relay-billing-key "$PRIVATE_RUNTIME_DIR/$relay/billing-private.key" 2>/dev/null) || return 1
  parse_billing_queue_inspection "$encoded"
}

billing_production_gate_inspect_host() {
  local run_dir=$1 payer=$2 relay=$3 payer_id=${4:-} relay_id=${5:-} inspector encoded
  inspector=$run_dir/build-runtime/build/billingqueue-inspect
  [[ -x $inspector ]] || return 1
  encoded=$("$inspector" -path "$PRIVATE_RUNTIME_DIR/$relay/wait-submit.queue" \
    -payer-id "$payer_id" -relay-id "$relay_id" \
    -relay-key "$PRIVATE_RUNTIME_DIR/$relay/identity.key" \
    -payer-billing-key "$PRIVATE_RUNTIME_DIR/$payer/billing-private.key" \
    -relay-billing-key "$PRIVATE_RUNTIME_DIR/$relay/billing-private.key" 2>/dev/null) || return 1
  parse_billing_queue_inspection "$encoded"
}

billing_production_gate_queue_digest() {
  local run_dir=$1 relay=$2 queue_path=$PRIVATE_RUNTIME_DIR/$relay/wait-submit.queue digest
  [[ -f $queue_path ]] || return 1
  digest=$(sha256sum "$queue_path" 2>/dev/null | awk '{print $1}') || return 1
  [[ $digest =~ ^[[:xdigit:]]{64}$ ]] || return 1
  printf '%s\n' "$digest"
}

billing_production_gate_resolve_payer() {
  local run_dir=$1 server=$2 node_id
  node_id=$(awk -F '\t' -v service="$server" '
    $1 == service { if (NF >= 5) print $5; else print $3; exit }
  ' "$run_dir/server-pool.tsv")
  [[ $node_id =~ ^[[:xdigit:]]{64}$ ]] || return 1
  printf '%s\n' "$node_id"
}

billing_production_gate_resolve_relay() {
  local run_dir=$1 relay=$2 node_id
  node_id=$(node "$ROOT_DIR/test/local-chaos/node-id-from-key.mjs" \
    "$PRIVATE_RUNTIME_DIR/$relay/identity.key" 2>/dev/null) || return 1
  [[ $node_id =~ ^[[:xdigit:]]{64}$ ]] || return 1
  printf '%s\n' "$node_id"
}

billing_production_gate_read_balance() {
  local node_id=$1 response balance ca_port=${BNFS_CHAOS_CA_HOST_PORT:-19100}
  [[ $node_id =~ ^[[:xdigit:]]{64}$ ]] || return 1
  response=$(curl -fsS --connect-timeout 2 --max-time 5 \
    "http://127.0.0.1:$ca_port/balance?node=$node_id" 2>/dev/null) || return 1
  balance=$(sed -n 's/.*"balance":[[:space:]]*\([-0-9][0-9]*\).*/\1/p' <<< "$response")
  [[ $balance =~ ^-?[0-9]+$ ]] || return 1
  printf '%s\n' "$balance"
}

billing_production_gate_read_accounting() {
  local relay_id=$1 payer_id=$2 relay=$3 payer=$4 ca_port=${BNFS_CHAOS_CA_HOST_PORT:-19100}
  [[ $relay_id =~ ^[[:xdigit:]]{64}$ && $payer_id =~ ^[[:xdigit:]]{64}$ ]] || return 1
  CA_BASE_URL="http://127.0.0.1:$ca_port" \
    CA_ADMIN_TOKEN_FILE="$PRIVATE_RUNTIME_DIR/ca/admin.token" \
    CA_BILLING_BOOTSTRAP_FILE="$PRIVATE_RUNTIME_DIR/ca/billing-key-bootstrap.json" \
    node "$ROOT_DIR/test/local-chaos/ca-web-accounting.mjs" \
      "$relay_id" "$payer_id" "$relay" "$payer" 2>/dev/null
}

billing_production_gate_read_nat_observation() {
  local server=$1
  node "$ROOT_DIR/test/local-chaos/nat-billing-private-inspect.mjs" \
    "$PRIVATE_RUNTIME_DIR/$server/billing-meter.json" 2>/dev/null
}

billing_production_gate_observation_is_fresh() {
  local generated_milliseconds=$1 now_milliseconds
  [[ $generated_milliseconds =~ ^[1-9][0-9]*$ ]] || return 1
  now_milliseconds=$(date +%s%3N) || return 1
  [[ $now_milliseconds =~ ^[1-9][0-9]*$ ]] || return 1
  (( generated_milliseconds <= now_milliseconds + 2000 \
    && now_milliseconds - generated_milliseconds <= 2000 ))
}

billing_production_gate_private_phase() {
  case ${1:-} in
    primary|recovery) printf '%s\n' "$1" ;;
    *) return 1 ;;
  esac
}

billing_production_gate_private_stage() {
  case ${1:-} in
    initializing|source_checksum_failed|source_checksum_invalid \
      |client_not_ready|client_heartbeat_failed|client_exec_failed \
      |client_result_invalid|curl_failed|size_mismatch|checksum_mismatch|verified)
      printf '%s\n' "$1"
      ;;
    *) return 1 ;;
  esac
}

write_billing_production_gate_private_download_evidence() {
  local client=$1 phase=$2 stage=$3 exec_rc=$4 curl_rc=$5 actual_bytes=$6 expected_bytes=$7
  local directory temporary destination
  phase=$(billing_production_gate_private_phase "$phase") || return 1
  stage=$(billing_production_gate_private_stage "$stage") || return 1
  [[ $client =~ ^natclient[0-9]{2}$ ]] || return 1
  [[ $exec_rc == not_observed || $exec_rc =~ ^[0-9]+$ ]] || return 1
  [[ $curl_rc == not_observed || $curl_rc =~ ^[0-9]+$ ]] || return 1
  [[ $actual_bytes =~ ^[0-9]+$ && $expected_bytes =~ ^[0-9]+$ ]] || return 1
  directory=$PRIVATE_RUNTIME_DIR/$client
  [[ -d $directory && ! -L $directory ]] || return 1
  destination=$directory/billing-production-gate-$phase-download.status
  temporary=$destination.tmp.$$
  if ! printf 'schema_version=1\nphase=%s\nstage=%s\nexec_rc=%s\ncurl_rc=%s\nactual_bytes=%s\nexpected_bytes=%s\n' \
    "$phase" "$stage" "$exec_rc" "$curl_rc" "$actual_bytes" "$expected_bytes" > "$temporary"; then
    rm -f "$temporary"
    return 1
  fi
  chmod 600 "$temporary" || {
    rm -f "$temporary"
    return 1
  }
  mv "$temporary" "$destination"
}

billing_production_gate_capture_nat_snapshot() {
  local server=$1 phase=$2 source destination temporary
  phase=$(billing_production_gate_private_phase "$phase") || return 1
  [[ $server =~ ^natserver[0-9]{2}$ ]] || return 1
  source=$PRIVATE_RUNTIME_DIR/$server/billing-meter.json
  destination=$PRIVATE_RUNTIME_DIR/$server/billing-production-gate-$phase-nat-snapshot.json
  temporary=$destination.tmp.$$
  [[ -f $source && ! -L $source ]] || return 1
  if ! cp -- "$source" "$temporary"; then
    rm -f "$temporary"
    return 1
  fi
  chmod 600 "$temporary" || {
    rm -f "$temporary"
    return 1
  }
  mv "$temporary" "$destination"
}

billing_production_gate_record_private_download_evidence() {
  local server=$1 client=$2 phase=$3 stage=$4 exec_rc=$5 curl_rc=$6
  local actual_bytes=$7 expected_bytes=$8 result=0
  write_billing_production_gate_private_download_evidence "$client" "$phase" "$stage" \
    "$exec_rc" "$curl_rc" "$actual_bytes" "$expected_bytes" || result=1
  if [[ $stage != verified && $stage != initializing ]]; then
    billing_production_gate_capture_nat_snapshot "$server" "$phase" || result=1
  fi
  return "$result"
}

billing_production_gate_assert_client_alive() {
  local client=$1 listen_port=$2
  [[ $client =~ ^natclient[0-9]{2}$ && $listen_port =~ ^[1-9][0-9]*$ ]] || return 1
  dc exec -T "$client" sh -lc "
    process_count=\$(pgrep -x tunclient 2>/dev/null | wc -l | tr -d '[:space:]')
    [ \"\$process_count\" = 1 ] || exit 21
    netstat -lnt 2>/dev/null | awk -v endpoint='127.0.0.1:$listen_port' '
      \$4 == endpoint { found=1 }
      END { exit !found }
    '
  " </dev/null >/dev/null 2>&1
}

billing_production_gate_wait_client_heartbeat() {
  local client=$1 listen_port=$2
  local samples=$REAL_BILLING_GATE_CLIENT_HEARTBEAT_SAMPLES
  local interval=$REAL_BILLING_GATE_CLIENT_HEARTBEAT_INTERVAL_SECONDS sample
  [[ $samples =~ ^[0-9]+$ ]] && (( samples >= 3 )) || return 1
  [[ $interval =~ ^[0-9]+([.][0-9]+)?$ ]] || return 1
  billing_production_gate_assert_client_alive "$client" "$listen_port" || return 1
  for ((sample = 1; sample <= samples; sample++)); do
    sleep "$interval" || return 1
    billing_production_gate_assert_client_alive "$client" "$listen_port" || return 1
  done
}

billing_production_gate_start_client() {
  local client=$1 target_id=$2 listen_port=$3
  stop_nat_process "$client" tunclient >/dev/null 2>&1 || return 1
  launch_tunnel_client "$client" relay01:9000 "$target_id" "$listen_port" random-workload \
    || return 1
  wait_client_ready "$client" random-workload 70 || return 1
  billing_production_gate_assert_client_alive "$client" "$listen_port"
}

billing_production_gate_stop_client() {
  local client=$1
  stop_nat_process "$client" tunclient >/dev/null 2>&1
}

billing_production_gate_restart_server() {
  local server=$1 relay=$2 expected_node_id=$3 actual_node_id previous_count
  previous_count=$(relay_registration_count "$relay" "$expected_node_id") || return 1
  actual_node_id=$(restart_tunnel_server "$server" "$relay:9000" random-workload 2>/dev/null) || return 1
  [[ $actual_node_id == "$expected_node_id" ]] || return 1
  wait_relay_registration_generation "$relay" "$expected_node_id" "$previous_count" \
    "$REAL_BILLING_GATE_SERVER_REGISTRATION_TIMEOUT_SECONDS"
}

billing_production_gate_cleanup_download() {
  local client=$1
  dc exec -T "$client" rm -f /tmp/bnfs-billing-production-gate.bin >/dev/null 2>&1 || true
}

billing_production_gate_pause_ca() {
  dc pause ca >/dev/null
}

billing_production_gate_resume_ca() {
  local deadline ca_port=${BNFS_CHAOS_CA_HOST_PORT:-19100}
  dc unpause ca >/dev/null 2>&1 || true
  wait_service_health ca 45 || return 1
  deadline=$((SECONDS + 15))
  while (( SECONDS < deadline )); do
    if curl -fsS --connect-timeout 1 --max-time 2 \
      "http://127.0.0.1:$ca_port/pubkey" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

billing_production_gate_assert_ca_unavailable() {
  local relay=$1 result exec_rc=0 curl_rc stage
  local directory stderr_file status_file temporary
  [[ $relay =~ ^relay[0-9]{2}$ ]] || return 2
  directory=$PRIVATE_RUNTIME_DIR/$relay
  [[ -d $directory && ! -L $directory ]] || return 2
  stderr_file=$directory/billing-production-gate-ca-probe.stderr
  status_file=$directory/billing-production-gate-ca-probe.status
  : > "$stderr_file" || return 2
  chmod 600 "$stderr_file" || return 2
  if result=$(dc exec -T "$relay" sh -lc '
    curl_rc=0
    curl -fsS --connect-timeout 1 --max-time 2 http://ca:9100/pubkey >/dev/null || curl_rc=$?
    printf "%s\n" "$curl_rc"
    exit 0
  ' 2> "$stderr_file"); then
    exec_rc=0
  else
    exec_rc=$?
  fi
  result=${result//$'\r'/}
  result=${result//$'\n'/}
  if (( exec_rc != 0 )); then
    stage=exec_failed
    curl_rc=not_observed
  elif [[ ! $result =~ ^[0-9]+$ ]]; then
    stage=result_invalid
    curl_rc=not_observed
  else
    curl_rc=$result
    if (( curl_rc == 0 )); then
      stage=ca_reachable
    else
      stage=ca_unavailable
    fi
  fi
  temporary=$status_file.tmp.$$
  if ! printf 'schema_version=1\nstage=%s\nexec_rc=%s\ncurl_rc=%s\n' \
    "$stage" "$exec_rc" "$curl_rc" > "$temporary"; then
    rm -f "$temporary"
    return 2
  fi
  chmod 600 "$temporary" || {
    rm -f "$temporary"
    return 2
  }
  mv "$temporary" "$status_file" || return 2
  [[ $stage == ca_unavailable ]] && return 0
  [[ $stage == ca_reachable ]] && return 1
  return 2
}

billing_production_gate_download() {
  local phase=$1 server=$2 client=$3 listen_port=$4 size_mib=$5
  local expected_sha result actual_size=0 actual_sha curl_rc=not_observed
  local expected_bytes checksum_rc=0 exec_rc=0 checksum_stderr curl_stderr
  phase=$(billing_production_gate_private_phase "$phase") || return 1
  expected_bytes=$((size_mib * REAL_BILLING_GATE_WINDOW_BYTES))
  checksum_stderr=$PRIVATE_RUNTIME_DIR/$server/billing-production-gate-$phase-checksum.stderr
  curl_stderr=$PRIVATE_RUNTIME_DIR/$client/billing-production-gate-$phase-curl.stderr
  : > "$checksum_stderr" || return 1
  : > "$curl_stderr" || return 1
  chmod 600 "$checksum_stderr" "$curl_stderr" || return 1
  billing_production_gate_record_private_download_evidence "$server" "$client" "$phase" \
    initializing not_observed not_observed 0 "$expected_bytes" || return 1
  if expected_sha=$(dc exec -T "$server" curl -fsS --connect-timeout 2 --max-time 15 \
    "http://127.0.0.1:8080/checksum?size_mb=$size_mib" 2> "$checksum_stderr" \
    | tr -d '[:space:]'); then
    checksum_rc=0
  else
    checksum_rc=$?
  fi
  if (( checksum_rc != 0 )); then
    billing_production_gate_record_private_download_evidence "$server" "$client" "$phase" \
      source_checksum_failed "$checksum_rc" not_observed 0 "$expected_bytes" || true
    return 1
  fi
  if [[ ! $expected_sha =~ ^[[:xdigit:]]{64}$ ]]; then
    billing_production_gate_record_private_download_evidence "$server" "$client" "$phase" \
      source_checksum_invalid 0 not_observed 0 "$expected_bytes" || true
    return 1
  fi
  if result=$(dc exec -T "$client" sh -lc \
    "output=/tmp/bnfs-billing-production-gate.bin; rm -f \"\$output\"; curl_rc=0; curl -fsS --max-time 180 -o \"\$output\" 'http://127.0.0.1:$listen_port/file?size_mb=$size_mib' || curl_rc=\$?; size=\$(stat -c %s \"\$output\" 2>/dev/null || printf 0); sha=\$(sha256sum \"\$output\" 2>/dev/null | awk '{print \$1}'); printf '%s\\t%s\\t%s\\n' \"\$curl_rc\" \"\$size\" \"\$sha\"; exit 0" \
    2> "$curl_stderr"); then
    exec_rc=0
  else
    exec_rc=$?
  fi
  if (( exec_rc != 0 )); then
    billing_production_gate_record_private_download_evidence "$server" "$client" "$phase" \
      client_exec_failed "$exec_rc" not_observed 0 "$expected_bytes" || true
    return 1
  fi
  IFS=$'\t' read -r curl_rc actual_size actual_sha <<< "$result"
  if [[ ! $curl_rc =~ ^[0-9]+$ || ! $actual_size =~ ^[0-9]+$ ]]; then
    billing_production_gate_record_private_download_evidence "$server" "$client" "$phase" \
      client_result_invalid 0 not_observed 0 "$expected_bytes" || true
    return 1
  fi
  if (( curl_rc != 0 )); then
    billing_production_gate_record_private_download_evidence "$server" "$client" "$phase" \
      curl_failed 0 "$curl_rc" "$actual_size" "$expected_bytes" || true
    return 1
  fi
  if [[ $actual_size != "$expected_bytes" ]]; then
    billing_production_gate_record_private_download_evidence "$server" "$client" "$phase" \
      size_mismatch 0 "$curl_rc" "$actual_size" "$expected_bytes" || true
    return 1
  fi
  if [[ $actual_sha != "$expected_sha" ]]; then
    billing_production_gate_record_private_download_evidence "$server" "$client" "$phase" \
      checksum_mismatch 0 "$curl_rc" "$actual_size" "$expected_bytes" || true
    return 1
  fi
  billing_production_gate_record_private_download_evidence "$server" "$client" "$phase" \
    verified 0 "$curl_rc" "$actual_size" "$expected_bytes" || return 1
  printf '%s\n' "$actual_size"
}

billing_production_gate_container_identity() {
  local relay=$1 container_id
  container_id=$(dc ps -q --all "$relay" 2>/dev/null) || return 1
  [[ $container_id =~ ^[[:xdigit:]]{12,64}$ ]] || return 1
  printf '%s\n' "$container_id"
}

billing_production_gate_relay_registration_count() {
  local relay=$1 count
  count=$(dc logs --no-color "$relay" 2>/dev/null | awk '/已注册到 index:/ { count++ } END { print count + 0 }') || return 1
  [[ $count =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$count"
}

billing_production_gate_crash_relay() {
  local relay=$1 container_id state deadline
  container_id=$(billing_production_gate_container_identity "$relay") || return 1
  dc kill -s KILL "$relay" >/dev/null || return 1
  deadline=$((SECONDS + 15))
  while (( SECONDS < deadline )); do
    state=$(docker inspect --format '{{.State.Running}}' "$container_id" 2>/dev/null || true)
    [[ $state == false ]] && return 0
    sleep 0.1
  done
  return 1
}

billing_production_gate_start_relay() {
  local relay=$1 expected_container_id=$2 previous_registration_count=$3
  local actual_container_id registration_count deadline
  dc start "$relay" >/dev/null || return 1
  wait_service_health "$relay" 45 || return 1
  actual_container_id=$(billing_production_gate_container_identity "$relay") || return 1
  [[ $actual_container_id == "$expected_container_id" ]] || return 1
  deadline=$((SECONDS + 45))
  while (( SECONDS < deadline )); do
    registration_count=$(billing_production_gate_relay_registration_count "$relay" 2>/dev/null || true)
    if [[ $registration_count =~ ^[0-9]+$ ]] && (( registration_count > previous_registration_count )); then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

run_billing_production_gate() (
	local run_dir=$1 server=natserver06 client=natclient01 relay=$REAL_BILLING_GATE_RELAY listen_port=18101
  local payer_id relay_id payer_debit=0 relay_credit=0
  local ca_before relay_income_before ca_after relay_income_after ca_credit=0 relay_income_credit=0 global_ca_credit=0
  local channel_count_before=0 channel_gross_before=0 channel_relay_before=0 channel_ca_before=0
  local channel_count_after=0 channel_gross_after=0 channel_relay_after=0 channel_ca_after=0
  local channel_gross_credit=0 channel_relay_credit=0
  local payer_consumed_before=0 payer_consumed_after=0 payer_account_before=0 payer_account_after=0
  local relay_account_before=0 relay_account_after=0 same_user_before=false same_user_after=false
  local payer_account_delta=0 relay_account_delta=0 expected_account_delta=0
  local expected_relay_credit expected_ca_credit accounting ca_sequence transfer_bytes=0 amount_verified=false
	local schema depth payload incomplete channel_depth authorized session_count inspection deadline
  local before_depth=0 before_payload=0 before_channel_depth=0 authorized_billable_bytes=0 authorized_sessions=0
	local stable_samples=0 previous_depth=-1 previous_payload=-1 previous_channel_depth=-1 previous_authorized=-1
  local nat_observation nat_version billing_enabled active_sessions observed_total cosigned_total fully_confirmed generated_milliseconds
  local observed_before=0 cosigned_before=0 observed_after=0 cosigned_after=0 observed_billable_bytes=0
  local unsettled_tail_bytes=0 previous_observed=-1 previous_cosigned=-1
  local observation_seen=0 observation_invalid=0 observation_ready=0
  local after_restart_depth=0 after_restart_payload=0 after_restart_channel_depth=0
  local after_restart_authorized=0 after_restart_sessions=0 after_recovery_depth=0
  local recovery_transfer_bytes=0
  local digest_before digest_after relay_container_id
  local relay_registration_count_before
	local ca_paused=0 client_started=0 relay_stopped=0 cleanup_failed=0 original_status

  cleanup_billing_production_gate() {
    original_status=$?
    trap - EXIT INT TERM HUP
    billing_production_gate_cleanup_download "$client" || true
    if (( client_started == 1 )); then
      billing_production_gate_stop_client "$client" >/dev/null 2>&1 || cleanup_failed=1
      client_started=0
    fi
		if (( ca_paused == 1 )); then
			billing_production_gate_resume_ca >/dev/null 2>&1 || cleanup_failed=1
			ca_paused=0
		fi
    if (( relay_stopped == 1 )); then
      billing_production_gate_start_relay "$relay" "$relay_container_id" \
        "$relay_registration_count_before" >/dev/null 2>&1 || cleanup_failed=1
      relay_stopped=0
    fi
    if (( cleanup_failed == 1 )); then
      billing_production_gate_fail "$run_dir" billing_production_gate_cleanup_failed \
        "$before_depth" "$after_restart_depth" "$after_recovery_depth" "$payer_debit" "$relay_credit" \
        "$transfer_bytes" "$ca_credit" "$amount_verified" "$observed_billable_bytes" \
        "$authorized_billable_bytes" "$unsettled_tail_bytes"
      original_status=1
    fi
    exit "$original_status"
  }
  fail_with_current_billing_evidence() {
    local failure_detail=$1 failure_after_restart=${2:-$after_restart_depth}
    local failure_after_recovery=${3:-$after_recovery_depth}
    billing_production_gate_fail "$run_dir" "$failure_detail" "$before_depth" \
      "$failure_after_restart" "$failure_after_recovery" "$payer_debit" "$relay_credit" \
      "$transfer_bytes" "$ca_credit" "$amount_verified" "$observed_billable_bytes" \
      "$authorized_billable_bytes" "$unsettled_tail_bytes"
  }
  trap cleanup_billing_production_gate EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM HUP

  write_billing_production_gate_snapshot "$run_dir" STARTING initializing 0 0 0 0 0 0 0 false false 0 0 0
  write_billing_production_gate_status "$run_dir" STARTING initializing

  payer_id=$(billing_production_gate_resolve_payer "$run_dir" "$server" 2>/dev/null) || {
    billing_production_gate_fail "$run_dir" billing_production_gate_actor_missing
    return 1
  }
  relay_id=$(billing_production_gate_resolve_relay "$run_dir" "$relay" 2>/dev/null) || {
    billing_production_gate_fail "$run_dir" billing_production_gate_actor_missing
    return 1
  }
  if [[ ! -f $run_dir/server-fresh/$server ]]; then
    billing_production_gate_fail "$run_dir" billing_production_gate_channel_not_fresh
    return 1
  fi
  relay_container_id=$(billing_production_gate_container_identity "$relay" 2>/dev/null) || {
    billing_production_gate_fail "$run_dir" billing_production_gate_relay_identity_missing
    return 1
  }
  relay_registration_count_before=$(billing_production_gate_relay_registration_count "$relay" 2>/dev/null) || {
    billing_production_gate_fail "$run_dir" billing_production_gate_relay_registration_missing
    return 1
  }
  if (( relay_registration_count_before < 1 )); then
    billing_production_gate_fail "$run_dir" billing_production_gate_relay_registration_missing
    return 1
  fi

  inspection=$(billing_production_gate_inspect_live \
    "$run_dir" "$server" "$relay" "$payer_id" "$relay_id" 2>/dev/null) || {
    billing_production_gate_fail "$run_dir" billing_production_gate_inspector_unavailable
    return 1
  }
  IFS=$'\t' read -r schema before_depth before_payload incomplete before_channel_depth \
    authorized_billable_bytes authorized_sessions <<< "$inspection"
  if [[ $schema != billingqueue-wal/v3 || ! $before_depth =~ ^[0-9]+$ \
    || ! $before_payload =~ ^[0-9]+$ || $incomplete != false \
    || ! $before_channel_depth =~ ^[0-9]+$ || ! $authorized_billable_bytes =~ ^[0-9]+$ \
    || ! $authorized_sessions =~ ^[0-9]+$ ]]; then
    billing_production_gate_fail "$run_dir" billing_production_gate_inspection_invalid
    return 1
  fi
  if (( before_depth != 0 || before_payload != 0 || before_channel_depth != 0 \
    || authorized_billable_bytes != 0 || authorized_sessions != 0 )); then
    billing_production_gate_fail "$run_dir" billing_production_gate_queue_not_empty "$before_depth"
    return 1
  fi

  client_started=1
  if ! billing_production_gate_start_client "$client" "$payer_id" "$listen_port"; then
    billing_production_gate_fail "$run_dir" billing_production_gate_client_start_failed
    return 1
  fi
  deadline=$((SECONDS + 5))
  while (( SECONDS < deadline )); do
    if [[ -f $PRIVATE_RUNTIME_DIR/$server/billing-meter.json ]]; then
      nat_observation=$(billing_production_gate_read_nat_observation "$server" 2>/dev/null) || {
        observation_invalid=1
        break
      }
      observation_seen=1
      IFS=$'\t' read -r nat_version billing_enabled active_sessions observed_total cosigned_total \
        fully_confirmed generated_milliseconds <<< "$nat_observation"
      if [[ $nat_version == 1 && $billing_enabled == true && $active_sessions == 1 \
        && $observed_total =~ ^[0-9]+$ && $cosigned_total =~ ^[0-9]+$ \
        && $fully_confirmed =~ ^(true|false)$ ]] \
        && billing_production_gate_observation_is_fresh "$generated_milliseconds"; then
        observed_before=$observed_total
        cosigned_before=$cosigned_total
        observation_ready=1
        break
      fi
    fi
    sleep 0.1
  done
  if (( observation_invalid == 1 )); then
    billing_production_gate_fail "$run_dir" billing_production_gate_nat_snapshot_invalid
    return 1
  fi
  if (( observation_seen == 0 )); then
    billing_production_gate_fail "$run_dir" billing_production_gate_nat_snapshot_unavailable
    return 1
  fi
  if (( observation_ready == 0 )) || [[ $active_sessions != 1 || ! $observed_before =~ ^[0-9]+$ \
    || ! $cosigned_before =~ ^[0-9]+$ ]]; then
    billing_production_gate_fail "$run_dir" billing_production_gate_nat_snapshot_unstable
    return 1
  fi
  if (( observed_before != 0 || cosigned_before != 0 )); then
    billing_production_gate_fail "$run_dir" billing_production_gate_channel_not_fresh
    return 1
  fi
  accounting=$(billing_production_gate_read_accounting \
    "$relay_id" "$payer_id" "$relay" "$server" 2>/dev/null) || {
    billing_production_gate_fail "$run_dir" billing_production_gate_accounting_read_failed
    return 1
  }
  IFS=$'\t' read -r ca_before relay_income_before ca_sequence channel_count_before \
    channel_gross_before channel_relay_before channel_ca_before payer_consumed_before \
    payer_account_before relay_account_before same_user_before <<< "$accounting"
  if [[ ! $ca_before =~ ^[0-9]+$ || ! $relay_income_before =~ ^[0-9]+$ \
    || ! $ca_sequence =~ ^[0-9]+$ || ! $channel_count_before =~ ^[0-9]+$ \
    || ! $channel_gross_before =~ ^[0-9]+$ || ! $channel_relay_before =~ ^[0-9]+$ \
    || ! $channel_ca_before =~ ^[0-9]+$ || ! $payer_consumed_before =~ ^[0-9]+$ \
    || ! $payer_account_before =~ ^[0-9]+$ || ! $relay_account_before =~ ^[0-9]+$ \
    || ! $same_user_before =~ ^(true|false)$ ]]; then
    billing_production_gate_fail "$run_dir" billing_production_gate_accounting_read_failed
    return 1
  fi
  if (( channel_count_before != 0 || channel_gross_before != 0 \
    || channel_relay_before != 0 || channel_ca_before != 0 )); then
    billing_production_gate_fail "$run_dir" billing_production_gate_channel_not_fresh
    return 1
  fi

	ca_paused=1
  if ! billing_production_gate_pause_ca; then
    billing_production_gate_fail "$run_dir" billing_production_gate_ca_pause_failed
    return 1
  fi
  if ! billing_production_gate_assert_ca_unavailable "$relay"; then
    billing_production_gate_fail "$run_dir" billing_production_gate_ca_disconnect_not_observed
    return 1
  fi
  if ! billing_production_gate_wait_client_heartbeat "$client" "$listen_port"; then
    billing_production_gate_record_private_download_evidence "$server" "$client" primary \
      client_heartbeat_failed not_observed not_observed 0 \
      "$((REAL_BILLING_GATE_TRANSFER_MIB * REAL_BILLING_GATE_WINDOW_BYTES))" || true
    billing_production_gate_fail "$run_dir" billing_production_gate_transfer_failed
    return 1
  fi
  transfer_bytes=$(billing_production_gate_download primary \
    "$server" "$client" "$listen_port" "$REAL_BILLING_GATE_TRANSFER_MIB") || {
    billing_production_gate_fail "$run_dir" billing_production_gate_transfer_failed
    return 1
  }
  if [[ ! $transfer_bytes =~ ^[0-9]+$ ]]; then
    billing_production_gate_fail "$run_dir" billing_production_gate_transfer_failed
    return 1
  fi

  # Freeze the only application-level producer before observing the durable
  # WAL. Stopping the tunnel also flushes any final Record-boundary voucher;
  # the stability samples below therefore describe a quiescent queue rather
  # than a digest that can race a still-running transfer.
  if ! billing_production_gate_stop_client "$client"; then
    billing_production_gate_fail "$run_dir" billing_production_gate_producer_freeze_failed
    return 1
  fi
  client_started=0

  deadline=$((SECONDS + REAL_BILLING_GATE_QUEUE_TIMEOUT_SECONDS))
  inspection=
  observation_invalid=0
  while (( SECONDS < deadline )); do
    inspection=$(billing_production_gate_inspect_live \
      "$run_dir" "$server" "$relay" "$payer_id" "$relay_id" 2>/dev/null || true)
    IFS=$'\t' read -r schema depth payload incomplete channel_depth authorized session_count <<< "$inspection"
    nat_observation=$(billing_production_gate_read_nat_observation "$server" 2>/dev/null) || {
      observation_invalid=1
      break
    }
    IFS=$'\t' read -r nat_version billing_enabled active_sessions observed_total cosigned_total \
      fully_confirmed generated_milliseconds <<< "$nat_observation"
    if [[ $schema == billingqueue-wal/v3 && $depth =~ ^[0-9]+$ && $payload =~ ^[0-9]+$ \
      && $incomplete == false && $channel_depth =~ ^[0-9]+$ && $authorized =~ ^[1-9][0-9]*$ \
      && $session_count == 1 && $nat_version == 1 && $billing_enabled == true \
      && $active_sessions == 1 && $observed_total =~ ^[0-9]+$ \
      && $cosigned_total =~ ^[0-9]+$ && $fully_confirmed == true ]] \
      && (( channel_depth >= REAL_BILLING_GATE_MIN_DEPTH \
        && observed_total >= observed_before && cosigned_total >= cosigned_before \
        && observed_total >= authorized && cosigned_total - cosigned_before == authorized )) \
      && billing_production_gate_observation_is_fresh "$generated_milliseconds"; then
      before_depth=$depth
      before_payload=$payload
      before_channel_depth=$channel_depth
      authorized_billable_bytes=$authorized
      authorized_sessions=$session_count
      observed_after=$observed_total
      cosigned_after=$cosigned_total
      if (( depth == previous_depth && payload == previous_payload \
        && channel_depth == previous_channel_depth && authorized == previous_authorized \
        && observed_total == previous_observed && cosigned_total == previous_cosigned )); then
        stable_samples=$((stable_samples + 1))
      else
        stable_samples=1
        previous_depth=$depth
        previous_payload=$payload
        previous_channel_depth=$channel_depth
        previous_authorized=$authorized
        previous_observed=$observed_total
        previous_cosigned=$cosigned_total
      fi
      if (( stable_samples >= REAL_BILLING_GATE_STABLE_SAMPLES )); then
        break
      fi
    else
      stable_samples=0
      previous_depth=-1
      previous_payload=-1
      previous_channel_depth=-1
      previous_authorized=-1
      previous_observed=-1
      previous_cosigned=-1
    fi
    sleep 0.1
  done
  if (( observation_invalid == 1 )); then
    billing_production_gate_fail "$run_dir" billing_production_gate_nat_snapshot_invalid \
      "$before_depth" 0 0 0 0 "$transfer_bytes"
    return 1
  fi
  if (( before_channel_depth < REAL_BILLING_GATE_MIN_DEPTH )); then
    billing_production_gate_fail "$run_dir" billing_production_gate_queue_depth_not_reached "$before_depth"
    return 1
  fi
  if (( stable_samples < REAL_BILLING_GATE_STABLE_SAMPLES )); then
    billing_production_gate_fail "$run_dir" billing_production_gate_nat_snapshot_unstable \
      "$before_depth" 0 0 0 0 "$transfer_bytes"
    return 1
  fi
  if (( observed_after < observed_before )); then
    billing_production_gate_fail "$run_dir" billing_production_gate_authorization_invalid \
      "$before_depth" 0 0 0 0 "$transfer_bytes" 0 false 0 "$authorized_billable_bytes" 0
    return 1
  fi
  observed_billable_bytes=$((observed_after - observed_before))
  if (( cosigned_after < cosigned_before \
    || cosigned_after - cosigned_before != authorized_billable_bytes )); then
    billing_production_gate_fail "$run_dir" billing_production_gate_authorized_amount_mismatch \
      "$before_depth" 0 0 0 0 "$transfer_bytes" 0 false \
      "$observed_billable_bytes" "$authorized_billable_bytes" 0
    return 1
  fi
  if (( observed_billable_bytes < authorized_billable_bytes )); then
    billing_production_gate_fail "$run_dir" billing_production_gate_authorization_invalid \
      "$before_depth" 0 0 0 0 "$transfer_bytes" 0 false \
      "$observed_billable_bytes" "$authorized_billable_bytes" 0
    return 1
  fi
  unsettled_tail_bytes=$((observed_billable_bytes - authorized_billable_bytes))
  if (( unsettled_tail_bytes >= REAL_BILLING_GATE_WINDOW_BYTES )); then
    billing_production_gate_fail "$run_dir" billing_production_gate_unbilled_tail_invalid \
      "$before_depth" 0 0 0 0 "$transfer_bytes" 0 false \
      "$observed_billable_bytes" "$authorized_billable_bytes" "$unsettled_tail_bytes"
    return 1
  fi
  digest_before=$(billing_production_gate_queue_digest "$run_dir" "$relay" 2>/dev/null) || {
    fail_with_current_billing_evidence billing_production_gate_queue_digest_failed
    return 1
  }

  if ! billing_production_gate_crash_relay "$relay"; then
    fail_with_current_billing_evidence billing_production_gate_relay_crash_failed
    return 1
  fi
  relay_stopped=1
  inspection=$(billing_production_gate_inspect_host \
    "$run_dir" "$server" "$relay" "$payer_id" "$relay_id" 2>/dev/null) || {
    fail_with_current_billing_evidence billing_production_gate_crash_inspection_failed
    return 1
  }
  IFS=$'\t' read -r schema after_restart_depth after_restart_payload incomplete \
    after_restart_channel_depth after_restart_authorized after_restart_sessions <<< "$inspection"
  digest_after=$(billing_production_gate_queue_digest "$run_dir" "$relay" 2>/dev/null) || {
    fail_with_current_billing_evidence billing_production_gate_queue_digest_failed "$after_restart_depth"
    return 1
  }
  if [[ $schema != billingqueue-wal/v3 || $incomplete != false || $after_restart_depth != "$before_depth" \
    || $after_restart_payload != "$before_payload" || $after_restart_channel_depth != "$before_channel_depth" \
    || $after_restart_authorized != "$authorized_billable_bytes" \
    || $after_restart_sessions != "$authorized_sessions" || $digest_after != "$digest_before" ]]; then
    fail_with_current_billing_evidence billing_production_gate_queue_persistence_changed "$after_restart_depth"
    return 1
  fi

  if ! billing_production_gate_resume_ca; then
    fail_with_current_billing_evidence billing_production_gate_ca_resume_failed "$after_restart_depth"
    return 1
  fi
  ca_paused=0
  if ! billing_production_gate_start_relay "$relay" "$relay_container_id" \
    "$relay_registration_count_before"; then
    fail_with_current_billing_evidence billing_production_gate_relay_start_failed "$after_restart_depth"
    return 1
  fi
  relay_stopped=0

  deadline=$((SECONDS + REAL_BILLING_GATE_RECOVERY_TIMEOUT_SECONDS))
  while (( SECONDS < deadline )); do
    inspection=$(billing_production_gate_inspect_host \
      "$run_dir" "$server" "$relay" "$payer_id" "$relay_id" 2>/dev/null || true)
    IFS=$'\t' read -r schema depth payload incomplete channel_depth authorized session_count <<< "$inspection"
    if [[ $schema == billingqueue-wal/v3 && $depth == 0 && $payload == 0 && $incomplete == false \
      && $channel_depth == 0 && $authorized == 0 && $session_count == 0 ]]; then
      after_recovery_depth=0
      break
    fi
    after_recovery_depth=${depth:-$after_restart_depth}
    sleep 0.25
  done
  if [[ $schema != billingqueue-wal/v3 || $depth != 0 || $payload != 0 || $incomplete != false \
    || $channel_depth != 0 || $authorized != 0 || $session_count != 0 ]]; then
    fail_with_current_billing_evidence billing_production_gate_queue_recovery_timeout \
      "$after_restart_depth" "$after_recovery_depth"
    return 1
  fi

  accounting=$(billing_production_gate_read_accounting \
    "$relay_id" "$payer_id" "$relay" "$server" 2>/dev/null) || {
    fail_with_current_billing_evidence billing_production_gate_accounting_read_failed "$after_restart_depth" 0
    return 1
  }
  IFS=$'\t' read -r ca_after relay_income_after ca_sequence channel_count_after \
    channel_gross_after channel_relay_after channel_ca_after payer_consumed_after \
    payer_account_after relay_account_after same_user_after <<< "$accounting"
  if [[ ! $ca_after =~ ^[0-9]+$ || ! $relay_income_after =~ ^[0-9]+$ \
    || ! $ca_sequence =~ ^[0-9]+$ || ! $channel_count_after =~ ^[0-9]+$ \
    || ! $channel_gross_after =~ ^[0-9]+$ || ! $channel_relay_after =~ ^[0-9]+$ \
    || ! $channel_ca_after =~ ^[0-9]+$ || ! $payer_consumed_after =~ ^[0-9]+$ \
    || ! $payer_account_after =~ ^[0-9]+$ || ! $relay_account_after =~ ^[0-9]+$ \
    || ! $same_user_after =~ ^(true|false)$ || $same_user_after != "$same_user_before" ]]; then
    fail_with_current_billing_evidence billing_production_gate_accounting_read_failed "$after_restart_depth" 0
    return 1
  fi
  payer_debit=$((payer_consumed_after - payer_consumed_before))
  relay_credit=$((relay_income_after - relay_income_before))
  global_ca_credit=$((ca_after - ca_before))
  relay_income_credit=$((relay_income_after - relay_income_before))
  channel_gross_credit=$((channel_gross_after - channel_gross_before))
  channel_relay_credit=$((channel_relay_after - channel_relay_before))
  ca_credit=$((channel_ca_after - channel_ca_before))
  payer_account_delta=$((payer_account_after - payer_account_before))
  relay_account_delta=$((relay_account_after - relay_account_before))
  if (( payer_debit < 0 || relay_credit < 0 || global_ca_credit < 0 || relay_income_credit < 0 \
    || channel_gross_credit < 0 || channel_relay_credit < 0 || ca_credit < 0 )); then
    billing_production_gate_fail "$run_dir" billing_production_gate_balance_delta_invalid \
      "$before_depth" "$after_restart_depth" 0 "$payer_debit" "$relay_credit" "$transfer_bytes" "$ca_credit" false \
      "$observed_billable_bytes" "$authorized_billable_bytes" "$unsettled_tail_bytes"
    return 1
  fi
  if [[ $same_user_after == true ]]; then
    expected_account_delta=$((relay_credit - payer_debit))
    if (( payer_account_before != relay_account_before || payer_account_after != relay_account_after \
      || payer_account_delta != expected_account_delta )); then
      fail_with_current_billing_evidence billing_production_gate_balance_delta_invalid "$after_restart_depth" 0
      return 1
    fi
  elif (( payer_account_delta != -payer_debit || relay_account_delta != relay_credit )); then
    fail_with_current_billing_evidence billing_production_gate_balance_delta_invalid "$after_restart_depth" 0
    return 1
  fi
  if (( channel_count_after != 1 || authorized_sessions != 1 \
    || channel_gross_credit != authorized_billable_bytes \
    || global_ca_credit < ca_credit )); then
    billing_production_gate_fail "$run_dir" billing_production_gate_channel_accounting_mismatch \
      "$before_depth" "$after_restart_depth" 0 "$payer_debit" "$relay_credit" "$transfer_bytes" "$ca_credit" false \
      "$observed_billable_bytes" "$authorized_billable_bytes" "$unsettled_tail_bytes"
    return 1
  fi
  if (( payer_debit > authorized_billable_bytes )); then
    billing_production_gate_fail "$run_dir" billing_production_gate_payer_overcharged \
      "$before_depth" "$after_restart_depth" 0 "$payer_debit" "$relay_credit" "$transfer_bytes" "$ca_credit" false \
      "$observed_billable_bytes" "$authorized_billable_bytes" "$unsettled_tail_bytes"
    return 1
  fi
  if (( payer_debit != authorized_billable_bytes )); then
    billing_production_gate_fail "$run_dir" billing_production_gate_payer_debit_mismatch \
      "$before_depth" "$after_restart_depth" 0 "$payer_debit" "$relay_credit" "$transfer_bytes" "$ca_credit" false \
      "$observed_billable_bytes" "$authorized_billable_bytes" "$unsettled_tail_bytes"
    return 1
  fi
  amount_verified=true
  if (( relay_income_credit != relay_credit || channel_relay_credit != relay_credit )); then
    billing_production_gate_fail "$run_dir" billing_production_gate_relay_income_mismatch \
      "$before_depth" "$after_restart_depth" 0 "$payer_debit" "$relay_credit" "$transfer_bytes" "$ca_credit" true \
      "$observed_billable_bytes" "$authorized_billable_bytes" "$unsettled_tail_bytes"
    return 1
  fi
  expected_relay_credit=$((payer_debit / 100 * 95 + payer_debit % 100 * 95 / 100))
  expected_ca_credit=$((payer_debit - expected_relay_credit))
  if (( relay_credit != expected_relay_credit )); then
    billing_production_gate_fail "$run_dir" billing_production_gate_split_mismatch \
      "$before_depth" "$after_restart_depth" 0 "$payer_debit" "$relay_credit" "$transfer_bytes" "$ca_credit" true \
      "$observed_billable_bytes" "$authorized_billable_bytes" "$unsettled_tail_bytes"
    return 1
  fi
  if (( ca_credit != expected_ca_credit )); then
    billing_production_gate_fail "$run_dir" billing_production_gate_ca_split_mismatch \
      "$before_depth" "$after_restart_depth" 0 "$payer_debit" "$relay_credit" "$transfer_bytes" "$ca_credit" true \
      "$observed_billable_bytes" "$authorized_billable_bytes" "$unsettled_tail_bytes"
    return 1
  fi

  if ! billing_production_gate_restart_server "$server" "$relay" "$payer_id"; then
    fail_with_current_billing_evidence billing_production_gate_recovery_server_restart_failed \
      "$after_restart_depth" 0
    return 1
  fi
  client_started=1
  if ! billing_production_gate_start_client "$client" "$payer_id" "$listen_port"; then
    fail_with_current_billing_evidence billing_production_gate_recovery_client_start_failed "$after_restart_depth" 0
    return 1
  fi
  if ! billing_production_gate_wait_client_heartbeat "$client" "$listen_port"; then
    billing_production_gate_record_private_download_evidence "$server" "$client" recovery \
      client_heartbeat_failed not_observed not_observed 0 \
      "$((REAL_BILLING_GATE_RECOVERY_TRANSFER_MIB * REAL_BILLING_GATE_WINDOW_BYTES))" || true
    fail_with_current_billing_evidence billing_production_gate_recovery_transfer_failed \
      "$after_restart_depth" 0
    return 1
  fi
  recovery_transfer_bytes=$(billing_production_gate_download recovery \
    "$server" "$client" "$listen_port" "$REAL_BILLING_GATE_RECOVERY_TRANSFER_MIB") || {
    fail_with_current_billing_evidence billing_production_gate_recovery_transfer_failed "$after_restart_depth" 0
    return 1
  }
  if [[ $recovery_transfer_bytes != "$((REAL_BILLING_GATE_RECOVERY_TRANSFER_MIB * REAL_BILLING_GATE_WINDOW_BYTES))" ]]; then
    fail_with_current_billing_evidence billing_production_gate_recovery_transfer_failed "$after_restart_depth" 0
    return 1
  fi
  if ! billing_production_gate_stop_client "$client"; then
    fail_with_current_billing_evidence billing_production_gate_recovery_client_stop_failed "$after_restart_depth" 0
    return 1
  fi
  client_started=0

  deadline=$((SECONDS + REAL_BILLING_GATE_RECOVERY_TIMEOUT_SECONDS))
  while (( SECONDS < deadline )); do
    inspection=$(billing_production_gate_inspect_host \
      "$run_dir" "$server" "$relay" "$payer_id" "$relay_id" 2>/dev/null || true)
    IFS=$'\t' read -r schema depth payload incomplete channel_depth authorized session_count <<< "$inspection"
    if [[ $schema == billingqueue-wal/v3 && $depth == 0 && $payload == 0 && $incomplete == false \
      && $channel_depth == 0 && $authorized == 0 && $session_count == 0 ]]; then
      after_recovery_depth=0
      break
    fi
    after_recovery_depth=${depth:-0}
    sleep 0.25
  done
  if [[ $schema != billingqueue-wal/v3 || $depth != 0 || $payload != 0 || $incomplete != false \
    || $channel_depth != 0 || $authorized != 0 || $session_count != 0 ]]; then
    fail_with_current_billing_evidence billing_production_gate_recovery_queue_timeout \
      "$after_restart_depth" "$after_recovery_depth"
    return 1
  fi
	if ! rm -f "$run_dir/server-fresh/$server"; then
    fail_with_current_billing_evidence billing_production_gate_cleanup_failed \
      "$after_restart_depth" "$after_recovery_depth"
		return 1
	fi
	write_billing_production_gate_snapshot "$run_dir" PASSED verified "$before_depth" "$after_restart_depth" 0 \
    "$transfer_bytes" "$payer_debit" "$relay_credit" "$ca_credit" true true \
    "$observed_billable_bytes" "$authorized_billable_bytes" "$unsettled_tail_bytes"
  write_billing_production_gate_status "$run_dir" PASSED verified
  return 0
)
