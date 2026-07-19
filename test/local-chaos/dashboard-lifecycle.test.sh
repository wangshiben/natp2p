#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
test_dir=$(mktemp -d)
export BNFS_SOAK_HOME=$test_dir/soak
source "$ROOT_DIR/scripts/local-chaos-stability.sh"

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
    node "$ROOT_DIR/test/local-chaos/monitor/server.mjs" > "$run_dir/dashboard.log" 2>&1 < /dev/null &
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
api_phase=$(curl -fsS "http://127.0.0.1:$port/api/status" | node -e 'let value="";process.stdin.on("data",chunk=>value+=chunk);process.stdin.on("end",()=>console.log(JSON.parse(value).phase))')
[[ $api_phase == FAILED ]] || fail "terminal Dashboard API phase was $api_phase"
stop_dashboard_process "$run_dir" || fail 'identity-matched dashboard did not stop'
pid_matches "$dashboard_pid" "$dashboard_start" 'monitor/server.mjs' \
  && fail 'identity-matched dashboard remained alive'

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
prepare_run "$run_dir" COMPLETED
port=$(free_port)
start_dashboard "$run_dir" "$port"
free_dashboard_port "$port" || fail 'next-start port cleanup did not reclaim the tracked dashboard'
pid_matches "$dashboard_pid" "$dashboard_start" 'monitor/server.mjs' \
  && fail 'tracked dashboard remained after port cleanup'
ss -lntH "sport = :$port" 2>/dev/null | grep -q . \
  && fail 'dashboard port remained occupied after cleanup'

printf 'dashboard lifecycle regression passed\n'
