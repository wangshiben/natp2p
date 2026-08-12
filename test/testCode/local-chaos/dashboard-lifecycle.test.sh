#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
test_dir=$(mktemp -d)
export BNFS_SOAK_HOME=$test_dir/soak
source "$ROOT_DIR/test/runtimeScript/local-chaos-stability.sh"

cleanup_pids=()
cleanup() {
  local pid
  for pid in "${cleanup_pids[@]}"; do
    [[ $pid =~ ^[1-9][0-9]*$ ]] || continue
    kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
  done
  rm -rf "$test_dir"
}
trap cleanup EXIT

fail() {
  printf 'dashboard lifecycle regression failed: %s\n' "$1" >&2
  exit 1
}

IFS=$'\t' read -r first_run_id first_run_dir < <(create_unique_run_directory 1) \
  || fail 'first unique run directory allocation failed'
IFS=$'\t' read -r second_run_id second_run_dir < <(create_unique_run_directory 1) \
  || fail 'second unique run directory allocation failed'
[[ $first_run_id != "$second_run_id" && $first_run_dir != "$second_run_dir" ]] \
  || fail 'back-to-back run IDs collided'
[[ $first_run_id =~ ^[0-9]{8}T[0-9]{6}[.][0-9]{9}Z-[0-9a-f]{16}-s1$ ]] \
  || fail "run ID does not contain nanosecond and random uniqueness: $first_run_id"

if dashboard_status_failure_is_fatal 120 100 2; then
  fail 'dashboard API grace ignored minimum consecutive failures'
fi
if dashboard_status_failure_is_fatal 119 100 "$DEFAULT_DASHBOARD_STATUS_MIN_FAILURES"; then
  fail 'dashboard API grace expired too early'
fi
dashboard_status_failure_is_fatal 120 100 "$DEFAULT_DASHBOARD_STATUS_MIN_FAILURES" \
  || fail 'dashboard API grace did not become fatal at its boundary'

free_port() {
  node -e 'const net=require("node:net");const server=net.createServer();server.listen(0,"127.0.0.1",()=>{console.log(server.address().port);server.close()})'
}

prepare_run() {
  local run_dir=$1 phase=${2:-FAILED}
  mkdir -p "$run_dir/runtime"
  printf '%s\n' "$phase" > "$run_dir/phase"
  printf '{}\n' > "$run_dir/runtime/compose.json"
  printf 'timestamp\ttransfer_id\tclient\tingress_relay\tserver\trequested_mib\trc\tbytes\tseconds\tmib_per_second\tsha256_ok\texpected_sha\tactual_sha\n' \
    > "$run_dir/transfers.tsv"
}

dashboard_pid=
dashboard_start=
start_dashboard() {
  local run_dir=$1 port=$2 attempt
  setsid env HOST=127.0.0.1 PORT="$port" RUN_DIR="$run_dir" COMPOSE_PROJECT= \
    COMPOSE_FILE="$run_dir/runtime/compose.json" CA_PORT=1 \
    node "$ROOT_DIR/test/runtimeScript/local-chaos/monitor/server.mjs" > "$run_dir/dashboard.log" 2>&1 < /dev/null &
  dashboard_pid=$!
  cleanup_pids+=("$dashboard_pid")
  dashboard_start=
  for attempt in $(seq 1 50); do
    dashboard_start=$(process_starttime "$dashboard_pid" 2>/dev/null || true)
    [[ $dashboard_start =~ ^[1-9][0-9]*$ ]] && break
    sleep 0.02
  done
  [[ $dashboard_start =~ ^[1-9][0-9]*$ ]] || fail 'dashboard start time unavailable'
  printf '%s\n' "$dashboard_pid" > "$run_dir/dashboard.pid"
  printf '%s\n' "$dashboard_start" > "$run_dir/dashboard.starttime"
  wait_dashboard_health 127.0.0.1 "$port" || fail 'dashboard health endpoint unavailable'
  probe_dashboard_status 127.0.0.1 "$port" "$run_dir/dashboard-probe.json" \
    || fail "dashboard status API probe failed: $DASHBOARD_STATUS_PROBE_DETAIL"
}

run_dir=$SOAK_HOME/runs/terminal-evidence
prepare_run "$run_dir" FAILED
port=$(free_port)
start_dashboard "$run_dir" "$port"
sleep 0.2
dashboard_pgid=$(ps -o pgid= -p "$dashboard_pid" | tr -d '[:space:]')
[[ $dashboard_pgid == "$dashboard_pid" ]] || fail "dashboard PGID $dashboard_pgid is not its independent PID $dashboard_pid"
pid_matches "$dashboard_pid" "$dashboard_start" 'monitor/server.mjs' \
  || fail 'terminal dashboard exited with the runner phase'
verify_dashboard_finalization "$dashboard_pid" "$dashboard_start" 127.0.0.1 "$port" \
  "$run_dir/finalization-probe.json" FAILED || fail "healthy finalization probe failed: $DASHBOARD_FINALIZATION_DETAIL"
wrong_port=$(free_port)
if verify_dashboard_finalization "$dashboard_pid" "$dashboard_start" 127.0.0.1 "$wrong_port" \
  "$run_dir/finalization-wrong-port.json" FAILED; then
  fail 'finalization accepted an unreachable Dashboard API'
fi
[[ $DASHBOARD_FINALIZATION_DETAIL == dashboard_status_api_transport_failed ]] \
  || fail "unreachable finalization detail was $DASHBOARD_FINALIZATION_DETAIL"
api_phase=$(curl -fsS "http://127.0.0.1:$port/api/status" | node -e 'let value="";process.stdin.on("data",chunk=>value+=chunk);process.stdin.on("end",()=>console.log(JSON.parse(value).phase))')
[[ $api_phase == FAILED ]] || fail "terminal Dashboard API phase was $api_phase"
stop_dashboard_process "$run_dir" || fail 'identity-matched dashboard did not stop'
pid_matches "$dashboard_pid" "$dashboard_start" 'monitor/server.mjs' \
  && fail 'identity-matched dashboard remained alive'
if verify_dashboard_finalization "$dashboard_pid" "$dashboard_start" 127.0.0.1 "$port" \
  "$run_dir/finalization-dead.json" FAILED; then
  fail 'finalization accepted an exited Dashboard process'
fi
[[ $DASHBOARD_FINALIZATION_DETAIL == dashboard_exited ]] \
  || fail "exited finalization detail was $DASHBOARD_FINALIZATION_DETAIL"

run_dir=$SOAK_HOME/runs/starttime-safety
prepare_run "$run_dir" FAILED
port=$(free_port)
start_dashboard "$run_dir" "$port"
printf '%s\n' "$((dashboard_start + 1))" > "$run_dir/dashboard.starttime"
stop_dashboard_process "$run_dir" || fail 'mismatched identity check returned an error'
kill -0 "$dashboard_pid" 2>/dev/null || fail 'mismatched start time killed the dashboard'
printf '%s\n' "$dashboard_start" > "$run_dir/dashboard.starttime"
stop_dashboard_process "$run_dir" || fail 'restored dashboard identity did not stop'

run_dir=$SOAK_HOME/runs/cmdline-safety
mkdir -p "$run_dir"
sleep 30 &
unrelated_pid=$!
cleanup_pids+=("$unrelated_pid")
unrelated_start=$(process_starttime "$unrelated_pid")
printf '%s\n' "$unrelated_pid" > "$run_dir/dashboard.pid"
printf '%s\n' "$unrelated_start" > "$run_dir/dashboard.starttime"
stop_dashboard_process "$run_dir" || fail 'command-line mismatch check returned an error'
kill -0 "$unrelated_pid" 2>/dev/null || fail 'command-line mismatch killed an unrelated process'
kill -TERM "$unrelated_pid" 2>/dev/null || true
wait "$unrelated_pid" 2>/dev/null || true

run_dir=$SOAK_HOME/runs/next-start-reclaim
prepare_run "$run_dir" FAILED
port=$(free_port)
start_dashboard "$run_dir" "$port"
free_dashboard_port "$port" || fail 'next-start port cleanup did not reclaim the tracked dashboard'
pid_matches "$dashboard_pid" "$dashboard_start" 'monitor/server.mjs' \
  && fail 'tracked dashboard remained after port cleanup'
ss -lntH "sport = :$port" 2>/dev/null | grep -q . \
  && fail 'dashboard port remained occupied after cleanup'

invalid_port=$(free_port)
setsid node -e '
  const http = require("node:http");
  const port = Number(process.argv[1]);
  http.createServer((_request, response) => {
    response.writeHead(200, {"Content-Type":"application/json"});
    response.end("not-json");
  }).listen(port, "127.0.0.1");
' "$invalid_port" >/dev/null 2>&1 &
invalid_pid=$!
cleanup_pids+=("$invalid_pid")
for _ in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:$invalid_port/api/status" >/dev/null 2>&1 && break
  sleep 0.02
done
if probe_dashboard_status 127.0.0.1 "$invalid_port" "$test_dir/invalid-probe.json"; then
  fail 'malformed dashboard JSON unexpectedly passed'
fi
[[ $DASHBOARD_STATUS_PROBE_DETAIL == dashboard_status_api_json_invalid ]] \
  || fail "malformed dashboard detail was $DASHBOARD_STATUS_PROBE_DETAIL"
kill -TERM "$invalid_pid" 2>/dev/null || true
wait "$invalid_pid" 2>/dev/null || true

status_port=$(free_port)
status_fixture=$test_dir/status-fixture.json
write_status_fixture() {
  local mutation=$1
  node -e '
    const fs = require("node:fs");
    const filename = process.argv[1];
    const mutation = process.argv[2];
    const value = {
      generatedAt: new Date().toISOString(),
      phase: "RUNNING",
      status: { outcome: "", detail: "" },
      maliciousNodes: [{
        service: "malicious-natserver",
        actor: "natserver",
        running: true,
        health: "healthy",
        restartCount: 0,
        probe: { status: "RUNNING", executed: 8, failed: 0, covered: 4, required: 4 },
      }, {
        service: "malicious-relay",
        actor: "relay",
        running: true,
        health: "healthy",
        restartCount: 0,
        probe: { status: "RUNNING", executed: 10, failed: 0, covered: 5, required: 5 },
      }],
      mixedPath: {
        available: true,
        status: "RUNNING",
        healthy: true,
        generation: 2,
        path: {
          nodes: ["mixed-path-probe", "relay05", "malicious-natserver"],
          kind: "normal_partition_mixed_adversary",
          containsNormalPartition: true,
          containsMaliciousNode: true,
        },
        probe: { status: "PASS", sha256Verified: true },
        attachments: {
          maliciousNatserver: {
            currentRelay: "relay05",
            normalPartition: "control_partition_a",
            attachmentType: "registered_to_normal_relay",
            basis: "live_relay_registration",
          },
          normalProbe: { currentRelay: "relay05" },
          maliciousRelay: {
            currentRelay: "relay03",
            normalPartition: "control_partition_a",
            attachmentType: "control_peer_with_normal_relay",
            basis: "live_control_hello",
            peerDirection: "normal_relay_to_malicious_relay",
          },
        },
        migrations: ["relay05", "relay04"].map((currentRelay, index) => ({
          generation: 2 - index,
          currentRelay,
          normalPartition: "control_partition_a",
          trigger: { contained: true },
          triggerContained: true,
          isolationVerified: true,
          containmentVerified: true,
          probePassed: true,
        })),
      },
    };
    switch (mutation) {
      case "terminal_without_nodes": value.phase = "COMPLETED"; delete value.maliciousNodes; break;
      case "terminal_valid":
        value.phase = "COMPLETED";
        value.mixedPath.status = "STOPPED";
        value.mixedPath.healthy = false;
        value.mixedPath.generation = 9;
        value.mixedPath.migrations[0].generation = 9;
        value.mixedPath.migrations[1].generation = 8;
        value.mixedPath.networkSummary = {
          required: 9, covered: 9, violations: 0, executed: 9, contained: 9,
        };
        break;
      case "off_without_nodes": value.metadata = { billing_adversary_mode: "off" }; delete value.maliciousNodes; break;
      case "default_without_nodes": delete value.maliciousNodes; break;
      case "enforce_without_nodes": value.metadata = { billing_adversary_mode: "enforce" }; delete value.maliciousNodes; break;
      case "report_without_nodes": value.metadata = { billing_adversary_mode: "report" }; delete value.maliciousNodes; break;
      case "missing_node": value.maliciousNodes.pop(); break;
      case "extra_node": value.maliciousNodes.push({ ...value.maliciousNodes[1] }); break;
      case "wrong_service": value.maliciousNodes[0].service = "malicious-other"; break;
      case "wrong_actor": value.maliciousNodes[1].actor = "natserver"; break;
      case "not_running": value.maliciousNodes[0].running = false; break;
      case "unhealthy": value.maliciousNodes[1].health = "unhealthy"; break;
      case "running_health_only": value.maliciousNodes[1].health = "running"; break;
      case "restarted": value.maliciousNodes[0].restartCount = 1; break;
      case "probe_status": value.maliciousNodes[1].probe.status = "FAILED"; break;
      case "probe_failed": value.maliciousNodes[0].probe.failed = 1; break;
      case "probe_coverage": value.maliciousNodes[1].probe.covered = 4; break;
      case "probe_required": value.maliciousNodes[0].probe.required = 3; break;
      case "probe_executed": value.maliciousNodes[1].probe.executed = 4; break;
      case "valid": break;
      default: process.exit(2);
    }
    fs.writeFileSync(filename, `${JSON.stringify(value)}\n`);
  ' "$status_fixture" "$mutation" || fail "could not write status fixture $mutation"
}

write_status_fixture terminal_without_nodes
setsid env DASHBOARD_STATUS_FIXTURE="$status_fixture" node -e '
  const fs = require("node:fs");
  const http = require("node:http");
  const port = Number(process.argv[1]);
  http.createServer((_request, response) => {
    response.writeHead(200, {"Content-Type":"application/json"});
    response.end(fs.readFileSync(process.env.DASHBOARD_STATUS_FIXTURE));
  }).listen(port, "127.0.0.1");
' "$status_port" >/dev/null 2>&1 &
status_pid=$!
cleanup_pids+=("$status_pid")
for _ in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:$status_port/api/status" >/dev/null 2>&1 && break
  sleep 0.02
done
if probe_dashboard_status 127.0.0.1 "$status_port" "$test_dir/terminal-status-probe.json" COMPLETED; then
  fail 'COMPLETED status without malicious nodes unexpectedly passed'
fi
[[ $DASHBOARD_STATUS_PROBE_DETAIL == dashboard_status_api_malicious_nodes_invalid ]] \
  || fail "terminal missing-node detail was $DASHBOARD_STATUS_PROBE_DETAIL"
write_status_fixture terminal_valid
probe_dashboard_status 127.0.0.1 "$status_port" "$test_dir/terminal-valid-probe.json" COMPLETED \
  || fail "valid COMPLETED malicious nodes failed: $DASHBOARD_STATUS_PROBE_DETAIL"
write_status_fixture valid
if probe_dashboard_status 127.0.0.1 "$status_port" "$test_dir/stale-phase-probe.json" COMPLETED; then
  fail 'RUNNING response satisfied a COMPLETED finalization probe'
fi
[[ $DASHBOARD_STATUS_PROBE_DETAIL == dashboard_status_api_phase_invalid ]] \
  || fail "stale phase detail was $DASHBOARD_STATUS_PROBE_DETAIL"
write_status_fixture off_without_nodes
probe_dashboard_status 127.0.0.1 "$status_port" "$test_dir/off-running-probe.json" \
  || fail "RUNNING off mode unexpectedly required malicious nodes: $DASHBOARD_STATUS_PROBE_DETAIL"
write_status_fixture valid
probe_dashboard_status 127.0.0.1 "$status_port" "$test_dir/valid-running-probe.json" \
  || fail "valid RUNNING malicious nodes failed: $DASHBOARD_STATUS_PROBE_DETAIL"
for mutation in default_without_nodes enforce_without_nodes report_without_nodes \
  missing_node extra_node wrong_service wrong_actor not_running unhealthy running_health_only restarted \
  probe_status probe_failed probe_coverage probe_required probe_executed; do
  write_status_fixture "$mutation"
  if probe_dashboard_status 127.0.0.1 "$status_port" "$test_dir/$mutation-probe.json"; then
    fail "invalid RUNNING malicious nodes passed: $mutation"
  fi
  [[ $DASHBOARD_STATUS_PROBE_DETAIL == dashboard_status_api_malicious_nodes_invalid ]] \
    || fail "$mutation detail was $DASHBOARD_STATUS_PROBE_DETAIL"
done
kill -TERM "$status_pid" 2>/dev/null || true
wait "$status_pid" 2>/dev/null || true

unreachable_port=$(free_port)
if probe_dashboard_status 127.0.0.1 "$unreachable_port" "$test_dir/unreachable-probe.json"; then
  fail 'unreachable dashboard API unexpectedly passed'
fi
[[ $DASHBOARD_STATUS_PROBE_DETAIL == dashboard_status_api_transport_failed ]] \
  || fail "unreachable dashboard detail was $DASHBOARD_STATUS_PROBE_DETAIL"

printf 'dashboard lifecycle regression passed\n'
