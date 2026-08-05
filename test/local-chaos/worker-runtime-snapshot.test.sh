#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
source "$ROOT_DIR/scripts/local-chaos-stability.sh"

test_root=$(mktemp -d)
cleanup() {
  rm -rf "$test_root"
}
trap cleanup EXIT

fail() {
  printf 'worker runtime snapshot regression failed: %s\n' "$*" >&2
  exit 1
}

source_root=$test_root/source
run_dir=$test_root/run
mkdir -p "$source_root/scripts" "$source_root/test/local-chaos" "$run_dir"

while IFS= read -r relative_file; do
  destination="$source_root/$relative_file"
  mkdir -p "$(dirname "$destination")"
  if [[ $relative_file == scripts/local-chaos-stability.sh ]]; then
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'printf "snapshot-worker-ok\\n"' > "$destination"
  else
    printf '%s\n' '#!/usr/bin/env bash' ':' > "$destination"
  fi
done < <(worker_runtime_snapshot_files)

snapshot_script=$(prepare_worker_runtime_snapshot "$run_dir" "$source_root") \
  || fail 'valid worker runtime was not snapshotted'
snapshot_root=$run_dir/runtime/worker-root
[[ $snapshot_script == "$snapshot_root/scripts/local-chaos-stability.sh" ]] \
  || fail "unexpected snapshot script path: $snapshot_script"

while IFS= read -r relative_file; do
  [[ -f $snapshot_root/$relative_file ]] \
    || fail "snapshot file is missing: $relative_file"
done < <(worker_runtime_snapshot_files)

(cd "$snapshot_root" && sha256sum -c worker-runtime.sha256 >/dev/null) \
  || fail 'snapshot manifest did not validate'
bash -n "$snapshot_script" \
  || fail 'snapshot worker failed syntax validation'
[[ $(bash "$snapshot_script") == snapshot-worker-ok ]] \
  || fail 'snapshot worker did not execute the captured runtime'

printf '%s\n' '#!/usr/bin/env bash' 'printf "' > "$source_root/scripts/local-chaos-stability.sh"
printf '%s\n' '#!/usr/bin/env bash' 'if [[ "' > "$source_root/test/local-chaos/lib.sh"
if bash -n "$source_root/scripts/local-chaos-stability.sh" >/dev/null 2>&1; then
  fail 'mutated source worker unexpectedly remained syntactically valid'
fi
if bash -n "$source_root/test/local-chaos/lib.sh" >/dev/null 2>&1; then
  fail 'mutated source dependency unexpectedly remained syntactically valid'
fi
bash -n "$snapshot_script" || fail 'snapshot became invalid after source mutation'
(cd "$snapshot_root" && sha256sum -c worker-runtime.sha256 >/dev/null) \
  || fail 'snapshot manifest changed after source mutation'
[[ $(bash "$snapshot_script") == snapshot-worker-ok ]] \
  || fail 'snapshot execution changed after source mutation'

printf 'worker runtime snapshot regression passed\n'
