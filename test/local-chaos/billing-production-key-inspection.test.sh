#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
test_root=$(mktemp -d)
cleanup() {
  rm -rf "$test_root"
}
trap cleanup EXIT

source "$ROOT_DIR/test/local-chaos/billing-production-gate.sh"

run_dir=$test_root/run
PRIVATE_RUNTIME_DIR=$test_root/private
inspector=$run_dir/build-runtime/build/billingqueue-inspect
arguments_file=$test_root/arguments
mkdir -p "$(dirname "$inspector")" "$PRIVATE_RUNTIME_DIR/natserver06" "$PRIVATE_RUNTIME_DIR/relay04"
printf '%064d\n' 1 > "$PRIVATE_RUNTIME_DIR/natserver06/billing-private.key"
printf '%064d\n' 2 > "$PRIVATE_RUNTIME_DIR/relay04/billing-private.key"
printf '%064d\n' 3 > "$PRIVATE_RUNTIME_DIR/relay04/identity.key"
: > "$PRIVATE_RUNTIME_DIR/relay04/wait-submit.queue"
chmod 600 "$PRIVATE_RUNTIME_DIR"/*/*.key "$PRIVATE_RUNTIME_DIR/relay04/wait-submit.queue"

cat > "$inspector" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$BILLING_INSPECT_ARGUMENTS_FILE"
printf '%s\n' '{"schema":"billingqueue-wal/v3","depth":2,"payload_bytes":4,"incomplete_tail":false,"channel_depth":2,"authorized_bytes":8,"session_count":1}'
EOF
chmod 700 "$inspector"
export BILLING_INSPECT_ARGUMENTS_FILE=$arguments_file

expected='billingqueue-wal/v3	2	4	false	2	8	1'
for inspect_function in billing_production_gate_inspect_live billing_production_gate_inspect_host; do
  actual=$($inspect_function "$run_dir" natserver06 relay04 "$(printf '%064d' 4)" "$(printf '%064d' 5)")
  [[ $actual == "$expected" ]] || {
    printf 'billing key inspection regression failed: %s output=%q\n' "$inspect_function" "$actual" >&2
    exit 1
  }
  grep -Fx -- '-payer-billing-key' "$arguments_file" >/dev/null
  grep -Fx -- "$PRIVATE_RUNTIME_DIR/natserver06/billing-private.key" "$arguments_file" >/dev/null
  grep -Fx -- '-relay-billing-key' "$arguments_file" >/dev/null
  grep -Fx -- "$PRIVATE_RUNTIME_DIR/relay04/billing-private.key" "$arguments_file" >/dev/null
done

printf 'billing production independent key inspection regression passed\n'
