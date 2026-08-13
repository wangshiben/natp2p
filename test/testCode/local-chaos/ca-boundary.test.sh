#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)

[[ ! -e $ROOT_DIR/test/testCode/caserver ]]
[[ ! -e $ROOT_DIR/test/runtimeScript/local-chaos/ca-ledger-inspect.mjs ]]
[[ ! -e $ROOT_DIR/test/testCode/local-chaos/ca-ledger-inspect.test.mjs ]]

if rg -n 'caserver|test/testCode/caserver|ca-ledger-inspect' \
  "$ROOT_DIR/test/runtimeScript" "$ROOT_DIR/internal/terminationpolicy"; then
  printf '检测到内置 CA 服务或旧账本解析器引用\n' >&2
  exit 1
fi

rg -q 'BNFS_CA_WEB_ROOT' "$ROOT_DIR/test/runtimeScript/local-deploy-test.sh"
rg -q 'CA_ENABLE_MOCK_USERS: "true"' "$ROOT_DIR/test/runtimeScript/local-chaos/generate-compose.mjs"
rg -q '/api/v1/auth/admin-login' "$ROOT_DIR/test/runtimeScript/local-chaos/bootstrap-billing-keys.mjs"
rg -q '/api/v1/admin/test/billing-keys' "$ROOT_DIR/test/runtimeScript/local-chaos/bootstrap-billing-keys.mjs"
rg -q '/api/v1/admin/users/credit' "$ROOT_DIR/test/runtimeScript/local-chaos/bootstrap-billing-keys.mjs"
rg -q 'branch == dev' "$ROOT_DIR/test/runtimeScript/test-ca-web.sh"
rg -q 'WEB_PORT=.*18088' "$ROOT_DIR/test/runtimeScript/test-ca-web.sh"

if rg -q 'Authorization|Bearer|Demo@2026|Dev@2026|View@2026' \
  "$ROOT_DIR/test/runtimeScript/local-chaos/bootstrap-billing-keys.mjs"; then
  printf '测试账号自动化未完全使用管理员 Session\n' >&2
  exit 1
fi

printf 'CA 仓库边界与管理员 Session 自动化门禁通过\n'
