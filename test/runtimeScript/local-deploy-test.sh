#!/usr/bin/env bash

set -uo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
CHAOS_RUNTIME_ROOT=$ROOT_DIR/test/runtimeScript/local-chaos
CHAOS_TEST_CODE_ROOT=$ROOT_DIR/test/testCode/local-chaos
RUNTIME_DIR=${BNFS_CHAOS_RUNTIME_DIR:-$CHAOS_RUNTIME_ROOT/.runtime}
COMPOSE_FILE=$RUNTIME_DIR/compose.json
COMPOSE_PROJECT=${BNFS_CHAOS_COMPOSE_PROJECT:-bnfs-local-chaos}
BNFS_CHAOS_IMAGE=${BNFS_CHAOS_IMAGE:-bnfs-local-chaos:latest}
BNFS_NATP2P_SDK_ROOT=${BNFS_NATP2P_SDK_ROOT:-$ROOT_DIR/../natP2pSDK}
BNFS_CA_WEB_ROOT=${BNFS_CA_WEB_ROOT:-$ROOT_DIR/ca_web}
BNFS_CHAOS_CA_BACKEND_IMAGE=${BNFS_CHAOS_CA_BACKEND_IMAGE:-bnfs-ca-web-backend:latest}
BNFS_CHAOS_CA_FRONTEND_IMAGE=${BNFS_CHAOS_CA_FRONTEND_IMAGE:-bnfs-ca-web-frontend:latest}
BNFS_SECURITY_PROFILE=${BNFS_SECURITY_PROFILE:-development}
export ROOT_DIR RUNTIME_DIR COMPOSE_FILE COMPOSE_PROJECT BNFS_CHAOS_IMAGE
export BNFS_NATP2P_SDK_ROOT
export BNFS_CA_WEB_ROOT BNFS_CHAOS_CA_BACKEND_IMAGE BNFS_CHAOS_CA_FRONTEND_IMAGE BNFS_SECURITY_PROFILE
source "$CHAOS_RUNTIME_ROOT/network-pools.sh"

scenario=all
keep=0
build=1
allow_failures=0
build_only=0

while (($#)); do
  case "$1" in
    --scenario)
      scenario=${2:?--scenario requires all, 1, 2, 3, 4, 5, or 6}
      shift 2
      ;;
    --keep)
      keep=1
      shift
      ;;
    --no-build)
      build=0
      shift
      ;;
    --allow-failures)
      allow_failures=1
      shift
      ;;
    --build-only)
      build_only=1
      shift
      ;;
    -h|--help)
      printf 'usage: %s [--scenario all|1|2|3|4|5|6] [--no-build] [--keep] [--allow-failures] [--build-only]\n' "$0"
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

case "$scenario" in
  all|1|2|3|4|5|6) ;;
  *) printf 'invalid scenario: %s\n' "$scenario" >&2; exit 2 ;;
esac

if [[ ${BNFS_CHAOS_ENABLE_CA:-0} == 1 && -z ${BNFS_CHAOS_CA_CLIENT_ROLE_SERVICES:-} ]]; then
  export BNFS_CHAOS_CA_CLIENT_ROLE_SERVICES=natserver01,natserver04,natserver06
fi
if [[ ${BNFS_CHAOS_ENABLE_CA:-0} == 1 && -z ${BNFS_CHAOS_AUTO_CREDIT_BYTES:-} ]]; then
  export BNFS_CHAOS_AUTO_CREDIT_BYTES=2199023255552
fi

select_topology_network_octets || exit 1
mkdir -p "$RUNTIME_DIR"
if ! node "$CHAOS_RUNTIME_ROOT/generate-compose.mjs" "$RUNTIME_DIR" > "$COMPOSE_FILE"; then
  printf '[local-chaos] 生成 Compose 拓扑失败\n' >&2
  exit 1
fi
source "$CHAOS_RUNTIME_ROOT/lib.sh"

if [[ ${BNFS_CHAOS_ENABLE_CA:-0} == 1 && -z ${BNFS_CHAOS_NAT_CA_URL:-} ]]; then
  export BNFS_CHAOS_NAT_CA_URL=http://ca:9100
fi

cleanup() {
  if (( keep == 0 )); then
    dc down --remove-orphans --timeout 3 >/dev/null 2>&1 || true
  else
    printf '[local-chaos] 保留容器，清理命令: docker compose -p %s -f %s down\n' "$COMPOSE_PROJECT" "$COMPOSE_FILE"
  fi
}
trap cleanup EXIT

if (( build == 1 )); then
  build_dir=$RUNTIME_DIR/build
  mkdir -p "$build_dir"
  if [[ ! -f $BNFS_NATP2P_SDK_ROOT/go.mod \
      || ! -f $BNFS_NATP2P_SDK_ROOT/cmd/tunclient/main.go \
      || ! -f $BNFS_NATP2P_SDK_ROOT/cmd/tunserver/main.go ]]; then
    printf '[local-chaos] natP2pSDK 源码目录无效: %s\n' "$BNFS_NATP2P_SDK_ROOT" >&2
    exit 1
  fi
  printf '[local-chaos] 在宿主机构建静态测试二进制\n'
  if ! GOCACHE=${GOCACHE:-/tmp/bnfs-go-cache} CGO_ENABLED=0 go build -o "$build_dir/nodeserver" "$ROOT_DIR/test/testCode/tunnel/nodeserver" \
    || ! GOCACHE=${GOCACHE:-/tmp/bnfs-go-cache} CGO_ENABLED=0 go build -o "$build_dir/caserver" "$ROOT_DIR/test/testCode/caserver" \
    || ! GOCACHE=${GOCACHE:-/tmp/bnfs-go-cache} CGO_ENABLED=0 go build -o "$build_dir/billingqueue-inspect" "$ROOT_DIR/test/testCode/billingqueue-inspect" \
    || ! GOCACHE=${GOCACHE:-/tmp/bnfs-go-cache} CGO_ENABLED=0 go build -o "$build_dir/billing-adversary-probe" "$ROOT_DIR/test/testCode/billing-adversary-probe" \
    || ! GOCACHE=${GOCACHE:-/tmp/bnfs-go-cache} CGO_ENABLED=0 go build -o "$build_dir/billing-adversary-node" "$ROOT_DIR/test/testCode/billing-adversary-node" \
    || ! (cd "$BNFS_NATP2P_SDK_ROOT" && GOCACHE=${GOCACHE:-/tmp/bnfs-go-cache} CGO_ENABLED=0 go build -o "$build_dir/tunserver" ./cmd/tunserver) \
    || ! (cd "$BNFS_NATP2P_SDK_ROOT" && GOCACHE=${GOCACHE:-/tmp/bnfs-go-cache} CGO_ENABLED=0 go build -o "$build_dir/tunclient" ./cmd/tunclient) \
    || ! GOCACHE=${GOCACHE:-/tmp/bnfs-go-cache} CGO_ENABLED=0 go build -o "$build_dir/httpfileserver" "$ROOT_DIR/test/testCode/tunnel/httpfileserver"; then
    printf '[local-chaos] 测试二进制构建失败\n' >&2
    exit 1
  fi
  install -m 0755 /usr/bin/busybox "$build_dir/busybox"
  printf '[local-chaos] 使用本机已有 centos:centos7 离线构建镜像 %s\n' "$BNFS_CHAOS_IMAGE"
  if ! docker image inspect centos:centos7 >/dev/null 2>&1; then
    printf '[local-chaos] 缺少离线基础镜像 centos:centos7\n' >&2
    exit 1
  fi
  if ! docker build --pull=false --tag "$BNFS_CHAOS_IMAGE" \
    --file "$CHAOS_RUNTIME_ROOT/Dockerfile" "$build_dir"; then
    printf '[local-chaos] 镜像构建失败\n' >&2
    exit 1
  fi
  if [[ ${BNFS_CHAOS_ENABLE_CA:-0} == 1 ]]; then
    if [[ ! -f $BNFS_CA_WEB_ROOT/backend/Dockerfile || ! -f $BNFS_CA_WEB_ROOT/frontend/Dockerfile ]]; then
      printf '[local-chaos] CA Web 源码目录无效: %s\n' "$BNFS_CA_WEB_ROOT" >&2
      exit 1
    fi
    printf '[local-chaos] 构建 CA Web 后端镜像 %s\n' "$BNFS_CHAOS_CA_BACKEND_IMAGE"
    if ! docker build --pull=false --tag "$BNFS_CHAOS_CA_BACKEND_IMAGE" "$BNFS_CA_WEB_ROOT/backend"; then
      printf '[local-chaos] CA Web 后端镜像构建失败\n' >&2
      exit 1
    fi
    printf '[local-chaos] 构建 CA Web 前端镜像 %s\n' "$BNFS_CHAOS_CA_FRONTEND_IMAGE"
    if ! docker build --pull=false --tag "$BNFS_CHAOS_CA_FRONTEND_IMAGE" "$BNFS_CA_WEB_ROOT/frontend"; then
      printf '[local-chaos] CA Web 前端镜像构建失败\n' >&2
      exit 1
    fi
  fi
fi

if (( build_only == 1 )); then
  printf '[local-chaos] 构建完成，按 --build-only 不启动场景\n'
  exit 0
fi

scripts=()
if [[ $scenario == all ]]; then
  scripts=(
    "$CHAOS_RUNTIME_ROOT/scenarios/01_partition_bridges.sh"
    "$CHAOS_RUNTIME_ROOT/scenarios/02_relay_failover.sh"
    "$CHAOS_RUNTIME_ROOT/scenarios/03_kcp_tcp_fallback.sh"
	"$CHAOS_RUNTIME_ROOT/scenarios/04_concurrent_service_dashboard.sh"
	"$CHAOS_RUNTIME_ROOT/scenarios/05_multi_relay_service.sh"
  )
else
  scripts=("$CHAOS_RUNTIME_ROOT/scenarios/0${scenario}_"*.sh)
fi

summary=$RUNTIME_DIR/summary.tsv
printf 'scenario\tstatus\telapsed_seconds\n' > "$summary"
failures=0
for script in "${scripts[@]}"; do
  name=$(basename "$script" .sh)
  started=$SECONDS
  printf '\n[local-chaos] ===== %s =====\n' "$name"
  if bash "$script"; then
    status=PASS
  else
    status=FAIL
    failures=$((failures + 1))
  fi
  elapsed=$((SECONDS - started))
  printf '%s\t%s\t%d\n' "$name" "$status" "$elapsed" | tee -a "$summary"
done

printf '\n[local-chaos] 汇总：\n'
column -t -s $'\t' "$summary" 2>/dev/null || cat "$summary"
printf '[local-chaos] 原始证据：%s\n' "$RUNTIME_DIR"

if (( failures > 0 && allow_failures == 0 )); then
  exit 1
fi
