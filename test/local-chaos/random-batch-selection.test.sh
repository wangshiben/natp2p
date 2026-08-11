#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
test_root=$(mktemp -d)
cleanup() {
  rm -rf "$test_root"
}
trap cleanup EXIT

source "$ROOT_DIR/scripts/local-chaos-stability.sh"

fail() {
  printf 'random batch selection regression failed: %s\n' "$1" >&2
  exit 1
}

[[ $(random_batch_client_count 0 0) == 2 ]] || fail 'roll 0 did not select two Clients'
[[ $(random_batch_client_count 59 2) == 4 ]] || fail 'roll 59 did not remain multi-Client'
[[ $(random_batch_client_count 60 0) == 1 ]] || fail 'roll 60 did not switch to single-Client'
[[ $(random_batch_client_count 99 2) == 1 ]] || fail 'roll 99 did not remain single-Client'
if random_batch_client_count 100 0 >/dev/null 2>&1; then
  fail 'out-of-range probability roll was accepted'
fi
[[ $(random_batch_transfer_limit_kibps 1 5) == 5120 ]] \
  || fail 'single-Client rate is not 5120 KiB/s'
[[ $(random_batch_transfer_limit_kibps 2 5) == 5120 ]] \
  || fail 'two-Client batch reduced the 5120 KiB/s per-stream limit'
[[ $(random_batch_transfer_limit_kibps 3 5) == 5120 ]] \
  || fail 'three-Client batch reduced the 5120 KiB/s per-stream limit'
[[ $(random_batch_transfer_limit_kibps 4 5) == 5120 ]] \
  || fail 'four-Client batch reduced the 5120 KiB/s per-stream limit'
[[ $(random_batch_transfer_limit_kibps 4 1) == 1024 ]] \
  || fail 'lower per-stream limit was divided by the Client count'
[[ $(random_batch_transfer_limit_kibps 4 0) == 0 ]] \
  || fail 'disabled workload limit unexpectedly throttled a stream'
[[ $(random_batch_client_start_stagger_seconds 1) == 0 ]] \
  || fail 'single-Client batch unexpectedly delays its only Client'
[[ $(random_batch_client_start_stagger_seconds 2) == 30 \
  && $(random_batch_client_start_stagger_seconds 4) == 30 ]] \
  || fail 'multi-Client handshakes are not staggered by 30 seconds'
quiet_run_dir=$test_root/quiet-run
mkdir -p "$quiet_run_dir"
quiet_deadline=$(( $(date +%s) + 5 ))
wait_random_batch_mixed_path_quiet "$quiet_run_dir" "$quiet_deadline" \
  || fail 'missing mixed-path controller did not bypass the quiet window'
printf 'status=RUNNING\n' > "$quiet_run_dir/mixed-adversary-path.status"
wait_random_batch_mixed_path_quiet "$quiet_run_dir" "$quiet_deadline" 1 1 \
  || fail 'stable mixed path did not satisfy the one-sample quiet window'

pool_file=$test_root/client-pool.tsv
printf 'client\tingress_relay\trelay_endpoint\tip_family\tlisten_port\tnode_id\n' > "$pool_file"
for number in $(seq 1 6); do
  printf 'natclient%02d\trelay01\trelay01:9000\tdefault\t181%02d\t%s\n' \
    "$number" "$number" "$(printf '%064d' "$number")" >> "$pool_file"
done
if validate_random_client_pool "$pool_file"; then
  fail 'pool without a malicious NatClient was accepted'
fi
printf 'malicious-natclient\trelay01\trelay01:9000\tdefault\t18107\t%s\n' \
  "$(printf '7%.0s' {1..64})" >> "$pool_file"
validate_random_client_pool "$pool_file" || fail 'valid pool with malicious NatClient was rejected'

run_dir=$test_root/run
mkdir -p "$run_dir"
cp "$pool_file" "$run_dir/client-pool.tsv"
{
  printf 'server\tingress_relay\trelay_endpoint\tip_family\tnode_id\n'
  for number in $(seq 1 13); do
    printf 'natserver%02d\trelay03\trelay03:9000\tdefault\t%064x\n' "$number" "$number"
  done
  printf 'malicious-random-natserver\trelay03\trelay03:9000\tdefault\t%s\n' \
    "$(printf 'e%.0s' {1..64})"
} > "$run_dir/server-pool.tsv"
validate_random_server_pool "$run_dir/server-pool.tsv" \
  || fail 'valid Server pool with malicious NatServer was rejected'
[[ $(random_batch_server_line "$run_dir" 0 | cut -f1) == natserver01 ]] \
  || fail 'step 0 did not select the requested normal NatServer'
[[ $(random_batch_server_line "$run_dir" 13 | cut -f1) == malicious-random-natserver ]] \
  || fail 'step 0 could not select the malicious NatServer'

printf 'timestamp\tbatch_id\tselected_server\tserver_pool_includes_malicious\tserver_malicious\tmode\trequested_clients\tselected_clients\tclient_pool_includes_malicious\tmalicious_client_selected\tstatus\ttarget_pairs\tsucceeded\tfailed\n' \
  > "$run_dir/random-batches.tsv"
for number in $(seq 1 13); do
  printf '2026-07-26T00:00:00+08:00\tbatch-%s-1\tnatserver%02d\ttrue\tfalse\tsingle\t1\tnatclient01\ttrue\tfalse\tPASS\tnatclient01→natserver%02d\t1\t0\n' \
    "$number" "$number" "$number" >> "$run_dir/random-batches.tsv"
done
[[ $(random_batch_server_line "$run_dir" | cut -f1) == malicious-random-natserver ]] \
  || fail 'coverage-aware Server selection repeated a covered NatServer'

printf 'timestamp\ttransfer_id\tclient\tingress_relay\tserver\trequested_mib\trc\tbytes\tseconds\tmib_per_second\tsha256_ok\texpected_sha\tactual_sha\n' \
  > "$run_dir/transfers.tsv"
for number in $(seq 1 6); do
  printf '2026-07-26T00:00:00+08:00\ttransfer-%s\tnatclient%02d\trelay01\tnatserver01\t100\t0\t104857600\t20\t5\tyes\texpected\tactual\n' \
    "$number" "$number" >> "$run_dir/transfers.tsv"
done
selected_clients_file=$test_root/selected-clients.tsv
select_random_batch_clients "$run_dir" "$(random_batch_server_line "$run_dir" 0)" \
  "$pool_file" "$selected_clients_file" 4 \
  || fail 'coverage-aware Client selection failed'
[[ $(wc -l < "$selected_clients_file") -eq 4 ]] \
  || fail 'coverage-aware Client selection returned the wrong count'
grep -q '^malicious-natclient'$'\t' "$selected_clients_file" \
  || fail 'coverage-aware Client selection omitted the untested malicious Client'

server_without_malicious=$test_root/server-without-malicious.tsv
head -n -1 "$run_dir/server-pool.tsv" > "$server_without_malicious"
if validate_random_server_pool "$server_without_malicious"; then
  fail 'Server pool without malicious NatServer was accepted'
fi

selected_server=$(random_batch_server_line "$run_dir" 13)
eligible=$test_root/eligible.tsv
random_clients_reaching_server "$run_dir" "$selected_server" > "$eligible"
[[ $(wc -l < "$eligible") -eq 7 ]] \
  || fail 'Server-first reachability did not retain all eligible Clients'
grep -q '^malicious-natclient'$'\t' "$eligible" \
  || fail 'Server-first Client candidate pool omitted the malicious NatClient'

evidence_dir=$test_root/evidence
mkdir -p "$evidence_dir"
{
  printf 'timestamp\tbatch_id\tselected_server\tserver_pool_includes_malicious\tserver_malicious\tmode\trequested_clients\tselected_clients\tclient_pool_includes_malicious\tmalicious_client_selected\tstatus\ttarget_pairs\tsucceeded\tfailed\n'
  printf '2026-07-26T00:00:00+08:00\tbatch-1-1\tmalicious-random-natserver\ttrue\ttrue\tmulti\t2\tnatclient01,malicious-natclient\ttrue\ttrue\tPASS\tnatclient01→malicious-random-natserver,malicious-natclient→malicious-random-natserver\t2\t0\n'
} > "$evidence_dir/random-batches.tsv"
validate_random_batch_evidence "$evidence_dir" smoke \
  || fail 'shared malicious Server evidence was rejected'
sed 's/malicious-natclient→malicious-random-natserver/malicious-natclient→natserver01/' \
  "$evidence_dir/random-batches.tsv" > "$evidence_dir/random-batches-invalid.tsv"
mv "$evidence_dir/random-batches-invalid.tsv" "$evidence_dir/random-batches.tsv"
if validate_random_batch_evidence "$evidence_dir" smoke; then
  fail 'one batch targeting two different NatServers was accepted'
fi

stability_source=$(<"$ROOT_DIR/scripts/local-chaos-stability.sh")
grep -q 'local worker_client=batch-scheduler' <<< "$stability_source" \
  || fail 'runner does not launch the batch scheduler'
grep -q 'RANDOM_MULTI_CLIENT_PERCENT=60' <<< "$stability_source" \
  || fail '60 percent multi-Client policy is missing'
grep -q 'server_line=$(random_batch_server_line "$run_dir")' <<< "$stability_source" \
  || fail 'batch scheduler does not perform Server selection step 0'
grep -q 'selected_server=$server' <<< "$stability_source" \
  || fail 'batch scheduler does not preserve the step-0 Server across Client loops'
grep -q 'wait_random_server_listener_idle "$selected_server"' <<< "$stability_source" \
  || fail 'batch scheduler does not own the shared Server recovery barrier'
grep -q 'BNFS_RANDOM_TRANSFER_LIMIT_KIBPS="$per_client_limit_kibps"' <<< "$stability_source" \
  || fail 'batch scheduler does not apply the KiB/s safety rate'
grep -q 'sleep "$start_stagger_seconds"' <<< "$stability_source" \
  || fail 'batch scheduler still launches all Client handshakes simultaneously'
grep -q 'wait_random_batch_mixed_path_quiet "$run_dir" "$deadline_epoch"' <<< "$stability_source" \
  || fail 'batch scheduler launches a Client without a mixed-path quiet window'
grep -q '> "$run_dir/workers/$batch_id-$client.log" 2>&1 < /dev/null &' <<< "$stability_source" \
  || fail 'staggered workers can consume the scheduler assignment stream'
grep -q 'BNFS_RANDOM_BATCH_MEMBER:-0} != 1' <<< "$stability_source" \
  || fail 'batch members still wait independently for global Server idleness'

defer_run_dir=$test_root/defer-run
mkdir -p "$defer_run_dir"
cp "$pool_file" "$defer_run_dir/client-pool.tsv"
cp "$run_dir/server-pool.tsv" "$defer_run_dir/server-pool.tsv"
printf 'timestamp\tbatch_id\tselected_server\tserver_pool_includes_malicious\tserver_malicious\tmode\trequested_clients\tselected_clients\tclient_pool_includes_malicious\tmalicious_client_selected\tstatus\ttarget_pairs\tsucceeded\tfailed\n' \
  > "$defer_run_dir/random-batches.tsv"
(
  wait_random_batch_mixed_path_quiet() {
    if (( $(wc -l < "$1/random-batches.tsv") != 1 )); then
      : > "$1/published-before-quiet"
    fi
    return 1
  }
  random_batch_client_count() {
    printf '1\n'
  }
  random_batch_worker "$defer_run_dir" "$(( $(date +%s) + 2 ))" 1 1 5 5
) || fail 'a busy mixed path still terminates the random batch scheduler'
[[ ! -e $defer_run_dir/published-before-quiet ]] \
  || fail 'a random batch was published before the mixed path became quiet'
[[ $(wc -l < "$defer_run_dir/random-batches.tsv") -eq 1 ]] \
  || fail 'a deferred batch was exposed as a false RUNNING or FAIL event'
[[ -z $(find "$defer_run_dir/random-batches" -type f -print -quit) ]] \
  || fail 'a deferred batch left stale assignment files'

printf 'random batch selection regression passed\n'
