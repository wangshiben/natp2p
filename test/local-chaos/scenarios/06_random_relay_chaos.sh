#!/usr/bin/env bash

set -uo pipefail
source "${ROOT_DIR:?}/test/local-chaos/lib.sh"

scenario=06_random_relay_chaos
scenario_dir=$RUNTIME_DIR/$scenario
duration_seconds=${BNFS_RANDOM_RELAY_CHAOS_SECONDS:-600}
transfer_rate=${BNFS_RANDOM_RELAY_CHAOS_RATE:-2m}
status_file=$RUNTIME_DIR/.private/natserver02/service-listener.json
events_file=$scenario_dir/chaos-events.tsv
failures=0
active_client=0
cycle=0
pair_first=
mkdir -p "$scenario_dir"

fail() {
  printf '[scenario-6] FAIL: %s\n' "$*" >&2
  failures=$((failures + 1))
}

pass() {
  printf '[scenario-6] PASS: %s\n' "$*"
}

stop_active_client() {
  if (( active_client == 1 )); then
    stop_nat_process natclient04 tunclient >/dev/null 2>&1 || true
    active_client=0
  fi
}

cleanup_scenario() {
  stop_active_client
  dc start relay01 relay02 >/dev/null 2>&1 || true
}
trap cleanup_scenario EXIT

if [[ ! $duration_seconds =~ ^[1-9][0-9]*$ ]] || (( duration_seconds < 60 || duration_seconds > 3600 )); then
  printf '[scenario-6] BNFS_RANDOM_RELAY_CHAOS_SECONDS 必须在 60..3600 秒之间\n' >&2
  exit 2
fi
if [[ ! $transfer_rate =~ ^[1-9][0-9]*[kKmMgG]$ ]]; then
  printf '[scenario-6] BNFS_RANDOM_RELAY_CHAOS_RATE 必须是正整数加 k/m/g 后缀\n' >&2
  exit 2
fi

carrier_state_matches() {
  local relay=$1 expected=$2
  [[ -s $status_file ]] || return 1
  node --input-type=module - "$status_file" "$relay:9000" "$expected" <<'NODE'
import fs from 'node:fs';
const [file, relay, expected] = process.argv.slice(2);
const status = JSON.parse(fs.readFileSync(file, 'utf8'));
const carrier = (status.carriers ?? []).find((entry) => entry.relayAddress === relay);
if (!carrier || String(carrier.connected) !== expected) process.exit(1);
NODE
}

wait_carrier_state() {
  local relay=$1 expected=$2 timeout_seconds=$3 deadline
  deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    if carrier_state_matches "$relay" "$expected"; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

wait_relay_healthy() {
  local relay=$1 timeout_seconds=$2 deadline container_id health
  deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    container_id=$(dc ps -q "$relay")
    health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id" 2>/dev/null || true)
    [[ $health == healthy ]] && return 0
    sleep 0.5
  done
  return 1
}

relay_is_stopped() {
  local relay=$1 container_id
  container_id=$(dc ps -aq "$relay")
  [[ -n $container_id ]] || return 1
  [[ $(docker inspect --format '{{.State.Running}}' "$container_id" 2>/dev/null) == false ]]
}

relay_registration_count() {
  local relay=$1 prefix=$2
  dc logs --no-color "$relay" 2>&1 | awk -v prefix="$prefix" '
    index($0, prefix) && ($0 ~ /新建 StreamGroup/ || $0 ~ /附加 relay leg/) { count++ }
    END { print count + 0 }
  '
}

wait_relay_registration_increment() {
  local relay=$1 prefix=$2 previous=$3 timeout_seconds=$4 deadline count
  deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    count=$(relay_registration_count "$relay" "$prefix")
    if [[ $count =~ ^[0-9]+$ ]] && (( count > previous )); then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

launch_and_verify_client() {
  local relay=$1 label=$2
  stop_active_client
  launch_tunnel_client natclient04 "$relay:9000" "$server_id" 18121 "$scenario"
  active_client=1
  if ! wait_client_ready natclient04 "$scenario" 35; then
    fail "$label: natclient04 未经 $relay 建立会话"
    return 1
  fi
  if ! dc exec -T natclient04 curl -fsS --max-time 15 http://127.0.0.1:18121/health | grep -q 'ok'; then
    fail "$label: $relay 上的服务健康检查失败"
    return 1
  fi
}

random_relay_pair() {
  local random_value
  if (( cycle % 2 == 1 )); then
    random_value=$(od -An -N4 -tu4 /dev/urandom | tr -d '[:space:]')
    [[ $random_value =~ ^[0-9]+$ ]] || return 1
    if (( random_value % 2 == 0 )); then
      pair_first=relay01
    else
      pair_first=relay02
    fi
    selection_token=$random_value
    victim=$pair_first
  elif [[ $pair_first == relay01 ]]; then
    selection_token=paired
    victim=relay02
  else
    selection_token=paired
    victim=relay01
  fi
  if [[ $victim == relay01 ]]; then
    survivor=relay02
  else
    survivor=relay01
  fi
}

if ! topology_reset; then
  exit 1
fi

export BNFS_CHAOS_NAT_KEY_DIR=/artifacts/.private
server_id=$(start_tunnel_server natserver02 'relay01:9000,relay02:9000' "$scenario" 100 200) || {
  fail '多 Relay Tunnel Server 启动失败'
  capture_topology_logs "$scenario"
  exit 1
}
server_prefix=${server_id:0:16}
for relay in relay01 relay02; do
  if ! wait_carrier_state "$relay" true 30; then
    fail "初始 carrier 未连接到 $relay"
  fi
done
if (( failures > 0 )); then
  capture_topology_logs "$scenario"
  exit "$failures"
fi

printf 'cycle\tselected_at\tselection_token\tvictim\tsurvivor\trequested_mib\texpected_bytes\tfault_started\trecovered_at\toutage_ms\ttransfer_seconds\tmib_per_second\tbytes\tsha256_ok\texisting_session_ok\tnew_session_ok\trecovered_session_ok\n' > "$events_file"
chaos_started_epoch=$(date +%s)
chaos_deadline=$((SECONDS + duration_seconds))
pass "开始 ${duration_seconds} 秒随机 Relay 下线测试"

while (( SECONDS < chaos_deadline )); do
  cycle=$((cycle + 1))
  victim=
  survivor=
  selection_token=
  if ! random_relay_pair; then
    fail "第 $cycle 轮无法取得随机数"
    break
  fi
  selected_at=$(date --iso-8601=seconds)
  requested_mib=$(random_probe_size_mib)
  if [[ ! $requested_mib =~ ^(100|1[0-9][0-9]|200)$ ]]; then
    fail "第 $cycle 轮无法选择 100..200 MiB 文件"
    break
  fi
  expected_bytes=$((requested_mib * 1024 * 1024))
  source_checksum=$(dc exec -T natserver02 curl -fsS --max-time 30 \
    "http://127.0.0.1:8080/checksum?size_mb=$requested_mib" | tr -d '[:space:]')
  if [[ ! $source_checksum =~ ^[[:xdigit:]]{64}$ ]]; then
    fail "第 $cycle 轮无法取得 ${requested_mib} MiB 源文件 SHA256"
    break
  fi
  printf '[scenario-6] cycle=%d random=%s victim=%s survivor=%s size=%sMiB\n' \
    "$cycle" "$selection_token" "$victim" "$survivor" "$requested_mib"
  registration_count_before=$(relay_registration_count "$victim" "$server_prefix")
  if [[ ! $registration_count_before =~ ^[1-9][0-9]*$ ]]; then
    fail "第 $cycle 轮故障前 $victim 没有 NatServer carrier 注册证据"
    break
  fi

  if ! launch_and_verify_client "$survivor" "第 $cycle 轮故障前"; then
    break
  fi
  cp "$scenario_dir/natclient04.log" "$scenario_dir/cycle-${cycle}-existing.log"
  rm -f "$scenario_dir/download.bin" "$scenario_dir/curl.rc"
  transfer_started_ns=$(date +%s%N)
  dc exec -T -d natclient04 sh -lc \
    "rc=0; curl -fsS --limit-rate '$transfer_rate' --max-time 240 -o '/artifacts/$scenario/download.bin' 'http://127.0.0.1:18121/file?size_mb=$requested_mib' || rc=\$?; printf '%s\\n' \"\$rc\" > '/artifacts/$scenario/curl.rc'"
  if ! wait_file_size "$scenario_dir/download.bin" 1048576 20; then
    fail "第 $cycle 轮故障前没有产生有效业务流量"
    break
  fi

  fault_started=$(date --iso-8601=seconds)
  fault_started_ns=$(date +%s%N)
  if ! dc stop --timeout 1 "$victim" >/dev/null; then
    fail "第 $cycle 轮无法停止 $victim"
    break
  fi
  if ! relay_is_stopped "$victim" || ! carrier_state_matches "$survivor" true; then
    fail "第 $cycle 轮故障未生效或幸存 carrier 异常: victim=$victim survivor=$survivor"
    break
  fi
  cp "$status_file" "$scenario_dir/cycle-${cycle}-fault.json"

  if ! wait_file_exists "$scenario_dir/curl.rc" 260; then
    fail "第 $cycle 轮跨故障传输没有结束"
    break
  fi
  transfer_ended_ns=$(date +%s%N)
  transfer_seconds=$(awk -v start="$transfer_started_ns" -v end="$transfer_ended_ns" \
    'BEGIN { printf "%.6f", (end-start)/1000000000 }')
  transfer_rc=$(tr -d '[:space:]' < "$scenario_dir/curl.rc")
  transfer_size=$(stat -c %s "$scenario_dir/download.bin" 2>/dev/null || printf '0')
  transfer_sha=$(sha256sum "$scenario_dir/download.bin" 2>/dev/null | awk '{print $1}')
  transfer_mibps=$(awk -v bytes="$transfer_size" -v seconds="$transfer_seconds" \
    'BEGIN { rate=0; if (seconds > 0) rate=bytes/1048576/seconds; printf "%.3f", rate }')
  if [[ $transfer_rc != 0 || $transfer_size != "$expected_bytes" || $transfer_sha != "$source_checksum" ]]; then
    fail "第 $cycle 轮跨故障传输失败: rc=$transfer_rc size=$transfer_size sha=$transfer_sha"
    break
  fi
  if ! dc exec -T natclient04 curl -fsS --max-time 15 http://127.0.0.1:18121/health | grep -q 'ok'; then
    fail "第 $cycle 轮 $survivor 上的既有会话失效"
    break
  fi
  existing_session_ok=yes

  if ! launch_and_verify_client "$survivor" "第 $cycle 轮故障期间新会话"; then
    break
  fi
  cp "$scenario_dir/natclient04.log" "$scenario_dir/cycle-${cycle}-new.log"
  new_session_ok=yes

  if ! dc start "$victim" >/dev/null || ! wait_relay_healthy "$victim" 30; then
    fail "第 $cycle 轮 $victim 未恢复健康"
    break
  fi
  if ! wait_relay_registration_increment "$victim" "$server_prefix" "$registration_count_before" 45 \
    || ! wait_carrier_state "$victim" true 15 || ! carrier_state_matches "$survivor" true; then
    fail "第 $cycle 轮 $victim 恢复后 carrier 未重新注册"
    break
  fi
  recovered_at=$(date --iso-8601=seconds)
  recovered_ns=$(date +%s%N)
  outage_ms=$(((recovered_ns - fault_started_ns) / 1000000))
  cp "$status_file" "$scenario_dir/cycle-${cycle}-recovered.json"

  if ! launch_and_verify_client "$victim" "第 $cycle 轮恢复 Relay 新会话"; then
    break
  fi
  cp "$scenario_dir/natclient04.log" "$scenario_dir/cycle-${cycle}-recovered.log"
  recovered_session_ok=yes
  stop_active_client

  printf '%d\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\t%d\t%s\t%s\t%d\tyes\t%s\t%s\t%s\n' \
    "$cycle" "$selected_at" "$selection_token" "$victim" "$survivor" "$requested_mib" \
    "$expected_bytes" "$fault_started" "$recovered_at" "$outage_ms" "$transfer_seconds" \
    "$transfer_mibps" "$transfer_size" "$existing_session_ok" \
    "$new_session_ok" "$recovered_session_ok" >> "$events_file"
  pass "第 $cycle 轮完成: ${requested_mib}MiB ${transfer_mibps}MiB/s，$victim 下线 ${outage_ms}ms"
done

chaos_ended_epoch=$(date +%s)
elapsed_seconds=$((chaos_ended_epoch - chaos_started_epoch))
relay01_cycles=$(awk -F '\t' 'NR > 1 && $4 == "relay01" { count++ } END { print count + 0 }' "$events_file")
relay02_cycles=$(awk -F '\t' 'NR > 1 && $4 == "relay02" { count++ } END { print count + 0 }' "$events_file")
completed_cycles=$(awk 'END { if (NR > 0) print NR - 1; else print 0 }' "$events_file")
read -r total_bytes minimum_mib maximum_mib average_mibps bad_rows < <(awk -F '\t' '
  NR > 1 {
    count++
    total += $13
    throughput += $12
    if (minimum == 0 || $6 < minimum) minimum = $6
    if ($6 > maximum) maximum = $6
    if ($6 < 100 || $6 > 200 || $7 != $6 * 1048576 || $13 != $7 ||
        $14 != "yes" || $15 != "yes" || $16 != "yes" || $17 != "yes") bad++
  }
  END {
    average = count > 0 ? throughput / count : 0
    printf "%.0f %d %d %.3f %d\n", total, minimum, maximum, average, bad
  }
' "$events_file")

if (( failures == 0 && elapsed_seconds < duration_seconds )); then
  fail "Chaos 阶段只运行了 ${elapsed_seconds}s，要求至少 ${duration_seconds}s"
fi
if (( completed_cycles < 2 || relay01_cycles == 0 || relay02_cycles == 0 )); then
  fail "随机故障覆盖不足: cycles=$completed_cycles relay01=$relay01_cycles relay02=$relay02_cycles"
fi
if (( bad_rows > 0 )); then
  fail "大文件 Chaos 证据不一致: bad_rows=$bad_rows"
fi

printf 'duration_seconds=%d\nelapsed_seconds=%d\ncompleted_cycles=%d\nrelay01_cycles=%d\nrelay02_cycles=%d\ntotal_bytes=%s\nminimum_mib=%d\nmaximum_mib=%d\naverage_mib_per_second=%s\nfailures=%d\n' \
  "$duration_seconds" "$elapsed_seconds" "$completed_cycles" "$relay01_cycles" "$relay02_cycles" \
  "$total_bytes" "$minimum_mib" "$maximum_mib" "$average_mibps" "$failures" \
  > "$scenario_dir/summary.env"
capture_topology_logs "$scenario"
if (( failures == 0 )); then
  pass "随机 Relay 容错测试完成: elapsed=${elapsed_seconds}s cycles=$completed_cycles relay01=$relay01_cycles relay02=$relay02_cycles"
fi
exit "$failures"
