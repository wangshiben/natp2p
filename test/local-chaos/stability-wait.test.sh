#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
source "$ROOT_DIR/scripts/local-chaos-stability.sh"

test_root=$(mktemp -d)
test_runner_pid=
test_runner_start=

cleanup() {
  local current_start
  if [[ ${test_runner_pid:-} =~ ^[1-9][0-9]*$ && ${test_runner_start:-} =~ ^[1-9][0-9]*$ ]]; then
    current_start=$(awk '{print $22}' "/proc/$test_runner_pid/stat" 2>/dev/null || true)
    [[ $current_start == "$test_runner_start" ]] \
      && kill -KILL -- "-$test_runner_pid" 2>/dev/null || true
    wait "$test_runner_pid" 2>/dev/null || true
  fi
  rm -rf "$test_root"
}
trap cleanup EXIT

fail() {
  printf 'stability wait regression failed: %s\n' "$*" >&2
  exit 1
}

prepare_run() {
  local run_dir=$1 phase=$2 outcome=$3 detail=$4
  local remaining_containers=${5:-0} remaining_networks=${6:-0}
  mkdir -p "$run_dir"
  printf 'duration_seconds=43200\ndashboard_host=127.0.0.1\ndashboard_port=8911\n' \
    > "$run_dir/metadata.env"
  printf '%s\n' "$phase" > "$run_dir/phase"
  printf 'outcome=%s\ndetail=%s\nremaining_containers=%s\nremaining_networks=%s\n' \
    "$outcome" "$detail" "$remaining_containers" "$remaining_networks" \
    > "$run_dir/status.env"
  printf 'timestamp\ttransfer_id\tclient\tingress_relay\tserver\trequested_mib\trc\tbytes\tseconds\tmib_per_second\tsha256_ok\texpected_sha\tactual_sha\n' \
    > "$run_dir/transfers.tsv"
}

[[ $DEFAULT_DURATION_SECONDS == 43200 ]] || fail 'default duration is not 12 hours'
usage_output=$(usage)
grep -q '^  local-chaos-stability.sh run \[options\]$' <<< "$usage_output" \
  || fail 'foreground run entry is missing from usage'
grep -q 'default: 43200' <<< "$usage_output" || fail '12-hour default is missing from usage'

completed_dir=$test_root/completed
prepare_run "$completed_dir" COMPLETED COMPLETED duration_complete
completed_output=$(wait_for_run_completion "$completed_dir" 1) \
  || fail 'valid completed evidence returned non-zero'
grep -q 'phase=COMPLETED' <<< "$completed_output" || fail 'completed snapshot was not observable'
grep -q 'remaining_seconds=pending' <<< "$completed_output" \
  || fail 'startup countdown fallback was not reported'

inconsistent_dir=$test_root/inconsistent
prepare_run "$inconsistent_dir" COMPLETED FAILED duration_complete
if wait_for_run_completion "$inconsistent_dir" 1 >/dev/null 2>&1; then
  fail 'inconsistent completed evidence returned zero'
fi

residual_completed_dir=$test_root/residual-completed
prepare_run "$residual_completed_dir" COMPLETED COMPLETED duration_complete 1 0
if wait_for_run_completion "$residual_completed_dir" 1 >/dev/null 2>&1; then
  fail 'completed evidence with a residual container returned zero'
fi

failed_dir=$test_root/failed
prepare_run "$failed_dir" FAILED FAILED transfer_failed
if wait_for_run_completion "$failed_dir" 1 >/dev/null 2>&1; then
  fail 'failed stability result returned zero'
fi

orphaned_dir=$test_root/orphaned
prepare_run "$orphaned_dir" RUNNING '' ''
if wait_for_run_completion "$orphaned_dir" 1 >/dev/null 2>&1; then
  fail 'dead non-terminal runner returned zero'
fi

if wait_for_run_completion "$completed_dir" 0 >/dev/null 2>&1; then
  fail 'zero wait interval was accepted'
fi

FAKE_DOCKER_CONTAINER_IDS=
FAKE_DOCKER_NETWORK_IDS=
FAKE_DOCKER_PS_FAIL=0
FAKE_DOCKER_NETWORK_FAIL=0
docker() {
  case ${1:-} in
    ps)
      (( FAKE_DOCKER_PS_FAIL == 0 )) || return 41
      printf '%s' "$FAKE_DOCKER_CONTAINER_IDS"
      ;;
    network)
      [[ ${2:-} == ls ]] || return 43
      (( FAKE_DOCKER_NETWORK_FAIL == 0 )) || return 42
      printf '%s' "$FAKE_DOCKER_NETWORK_IDS"
      ;;
    *) return 43 ;;
  esac
}

inspect_compose_project_residuals test-clean-project \
  || fail 'clean project residual inspection failed'
[[ $PROJECT_REMAINING_CONTAINERS == 0 && $PROJECT_REMAINING_NETWORKS == 0 ]] \
  || fail 'clean project residual counts were not 0/0'

FAKE_DOCKER_CONTAINER_IDS=$'container-one\ncontainer-two\n'
FAKE_DOCKER_NETWORK_IDS=$'network-one\n'
inspect_compose_project_residuals test-residual-project \
  || fail 'non-empty project residual inspection failed'
[[ $PROJECT_REMAINING_CONTAINERS == 2 && $PROJECT_REMAINING_NETWORKS == 1 ]] \
  || fail 'non-empty project residual counts were incorrect'

FAKE_DOCKER_CONTAINER_IDS=
FAKE_DOCKER_NETWORK_IDS=
FAKE_DOCKER_PS_FAIL=1
if inspect_compose_project_residuals test-container-query-failure; then
  fail 'failed container query was accepted as a clean inspection'
fi
[[ $PROJECT_REMAINING_CONTAINERS == unknown && $PROJECT_REMAINING_NETWORKS == 0 ]] \
  || fail 'failed container query was misreported as zero'

FAKE_DOCKER_PS_FAIL=0
FAKE_DOCKER_NETWORK_FAIL=1
if inspect_compose_project_residuals test-network-query-failure; then
  fail 'failed network query was accepted as a clean inspection'
fi
[[ $PROJECT_REMAINING_CONTAINERS == 0 && $PROJECT_REMAINING_NETWORKS == unknown ]] \
  || fail 'failed network query was misreported as zero'
unset -f docker

clean_result=$(terminal_result_after_cleanup COMPLETED duration_complete ok 0 0)
[[ $clean_result == $'COMPLETED\tduration_complete' ]] \
  || fail "clean terminal result was $clean_result"
residual_result=$(terminal_result_after_cleanup COMPLETED duration_complete ok 1 0)
[[ $residual_result == $'FAILED\tproject_cleanup_incomplete' ]] \
  || fail "residual terminal result was $residual_result"
inspection_failure_result=$(terminal_result_after_cleanup \
  COMPLETED duration_complete failed unknown 0)
[[ $inspection_failure_result == $'FAILED\tproject_cleanup_inspection_failed' ]] \
  || fail "inspection failure terminal result was $inspection_failure_result"

publish_dir=$test_root/publish
mkdir -p "$publish_dir"
printf 'RUNNING\n' > "$publish_dir/phase"
printf 'outcome=\ndetail=\n' > "$publish_dir/status.env"
terminal_mv_trace=$test_root/terminal-mv.trace
: > "$terminal_mv_trace"
mv() {
  printf '%s\n' "${@: -1}" >> "$terminal_mv_trace"
  command mv "$@"
}
publish_terminal_result "$publish_dir" COMPLETED duration_complete 0 0 \
  || fail 'valid terminal result was not published'
[[ $(sed -n '1p' "$terminal_mv_trace") == "$publish_dir/status.env" \
  && $(sed -n '2p' "$terminal_mv_trace") == "$publish_dir/phase" \
  && $(sed -n '3p' "$terminal_mv_trace") == '' ]] \
  || fail 'terminal phase was not the final atomic replacement'
grep -q '^COMPLETED$' "$publish_dir/phase" || fail 'published phase was not COMPLETED'
completed_terminal_evidence_valid "$publish_dir/status.env" \
  || fail 'published COMPLETED status evidence was invalid'

rejected_publish_dir=$test_root/rejected-publish
mkdir -p "$rejected_publish_dir"
printf 'RUNNING\n' > "$rejected_publish_dir/phase"
printf 'outcome=\ndetail=\n' > "$rejected_publish_dir/status.env"
if publish_terminal_result "$rejected_publish_dir" COMPLETED duration_complete 1 0; then
  fail 'COMPLETED terminal result with residual resources was published'
fi
[[ $(cat "$rejected_publish_dir/phase") == RUNNING ]] \
  || fail 'rejected terminal publication changed the phase'
[[ $(run_field "$rejected_publish_dir/status.env" outcome) == '' ]] \
  || fail 'rejected terminal publication changed status evidence'
unset -f mv

finalizer_clean_trace=$test_root/finalizer-clean.trace
(
  verify_dashboard_finalization() {
    printf 'dashboard:%s\n' "$6" >> "$finalizer_clean_trace"
  }
  cleanup_project() {
    printf 'cleanup\n' >> "$finalizer_clean_trace"
  }
  inspect_compose_project_residuals() {
    printf 'inspect\n' >> "$finalizer_clean_trace"
    PROJECT_REMAINING_CONTAINERS=0
    PROJECT_REMAINING_NETWORKS=0
  }
  publish_terminal_result() {
    printf 'publish:%s:%s:%s:%s\n' "$2" "$3" "$4" "$5" \
      >> "$finalizer_clean_trace"
  }
  finalize_run_terminal_result "$test_root/finalizer-clean" missing-compose.json \
    test-finalizer-project 1 2 127.0.0.1 8911 missing-probe.json \
    COMPLETED duration_complete
) || fail 'clean finalizer path returned non-zero'
[[ $(cat "$finalizer_clean_trace") == $'dashboard:RUNNING\ncleanup\ninspect\npublish:COMPLETED:duration_complete:0:0' ]] \
  || fail 'finalizer did not run Dashboard, cleanup, inspection, and publication in order'

finalizer_residual_trace=$test_root/finalizer-residual.trace
(
  verify_dashboard_finalization() {
    printf 'dashboard:%s\n' "$6" >> "$finalizer_residual_trace"
  }
  cleanup_project() {
    printf 'cleanup\n' >> "$finalizer_residual_trace"
  }
  inspect_compose_project_residuals() {
    printf 'inspect\n' >> "$finalizer_residual_trace"
    PROJECT_REMAINING_CONTAINERS=1
    PROJECT_REMAINING_NETWORKS=0
  }
  publish_terminal_result() {
    printf 'publish:%s:%s:%s:%s\n' "$2" "$3" "$4" "$5" \
      >> "$finalizer_residual_trace"
  }
  set +e
  finalize_run_terminal_result "$test_root/finalizer-residual" missing-compose.json \
    test-finalizer-project 1 2 127.0.0.1 8911 missing-probe.json \
    COMPLETED duration_complete
  finalizer_rc=$?
  set -e
  printf 'return:%s\n' "$finalizer_rc" >> "$finalizer_residual_trace"
)
[[ $(cat "$finalizer_residual_trace") == $'dashboard:RUNNING\ncleanup\ninspect\npublish:FAILED:project_cleanup_incomplete:1:0\nreturn:1' ]] \
  || fail 'residual finalizer path did not publish a FAILED terminal result'

registry_dir=$test_root/registry
fake_root=$test_root/fake-root
mkdir -p "$registry_dir" "$fake_root/scripts"
printf '#!/usr/bin/env bash\nexit 0\n' > "$fake_root/scripts/local-chaos-stability.sh"
printf 'client\tpid\tstarttime\tpgid\ttoken\n' > "$registry_dir/worker-pids.tsv"
setsid bash -c 'while :; do sleep 0.1; done' &
test_runner_pid=$!
test_runner_start=$(awk '{print $22}' "/proc/$test_runner_pid/stat")
registry_token=abcdef0123456789abcdef0123456789
REAL_ROOT=$ROOT_DIR FAKE_ROOT=$fake_root RUN_DIR_FOR_TEST=$registry_dir \
  RUNNER_PID_FOR_TEST=$test_runner_pid RUNNER_START_FOR_TEST=$test_runner_start \
  setsid env BNFS_RANDOM_WORKER_TOKEN="$registry_token" bash -c '
    source "$REAL_ROOT/scripts/local-chaos-stability.sh"
    ROOT_DIR=$FAKE_ROOT
    registered_random_worker "$RUN_DIR_FOR_TEST" natclient01 \
      "$RUNNER_PID_FOR_TEST" "$RUNNER_START_FOR_TEST"
  ' &
registered_pid=$!
wait "$registered_pid" || fail 'registered worker wrapper failed'
awk -F '\t' -v pid="$registered_pid" -v token="$registry_token" '
  $1 == "natclient01" && $2 == pid && $4 == pid && $5 == token { found=1 }
  END { exit !found }
' "$registry_dir/worker-pids.tsv" || fail 'private worker identity record is incomplete'

: > "$registry_dir/worker-pids.closed"
if REAL_ROOT=$ROOT_DIR FAKE_ROOT=$fake_root RUN_DIR_FOR_TEST=$registry_dir \
  RUNNER_PID_FOR_TEST=$test_runner_pid RUNNER_START_FOR_TEST=$test_runner_start \
  setsid env BNFS_RANDOM_WORKER_TOKEN=0123456789abcdef0123456789abcdef bash -c '
    source "$REAL_ROOT/scripts/local-chaos-stability.sh"
    ROOT_DIR=$FAKE_ROOT
    registered_random_worker "$RUN_DIR_FOR_TEST" natclient02 \
      "$RUNNER_PID_FOR_TEST" "$RUNNER_START_FOR_TEST"
  '; then
  fail 'closed worker registry accepted a late worker'
fi
! awk -F '\t' '$1 == "natclient02" { found=1 } END { exit !found }' \
  "$registry_dir/worker-pids.tsv" || fail 'late worker was written after registry closure'

printf 'stability wait regression passed\n'
