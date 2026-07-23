#!/usr/bin/env bash

set -uo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUNTIME_DIR=${BNFS_CHAOS_RUNTIME_DIR:-$ROOT_DIR/test/local-chaos/.runtime}
COMPOSE_FILE=$RUNTIME_DIR/compose.json
COMPOSE_PROJECT=${BNFS_CHAOS_COMPOSE_PROJECT:-bnfs-local-chaos}
BNFS_CHAOS_IMAGE=${BNFS_CHAOS_IMAGE:-bnfs-local-chaos:latest}
export ROOT_DIR RUNTIME_DIR COMPOSE_FILE COMPOSE_PROJECT BNFS_CHAOS_IMAGE

scenario=all
keep=0
build=1
allow_failures=0
build_only=0

while (($#)); do
  case "$1" in
    --scenario)
      scenario=${2:?--scenario requires all, 1, 2, or 3}
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
      printf 'usage: %s [--scenario all|1|2|3] [--no-build] [--keep] [--allow-failures] [--build-only]\n' "$0"
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

case "$scenario" in
  all|1|2|3) ;;
  *) printf 'invalid scenario: %s\n' "$scenario" >&2; exit 2 ;;
esac

mkdir -p "$RUNTIME_DIR"
if ! node "$ROOT_DIR/test/local-chaos/generate-compose.mjs" "$RUNTIME_DIR" > "$COMPOSE_FILE"; then
  printf '[local-chaos] 生成 Compose 拓扑失败\n' >&2
  exit 1
fi
source "$ROOT_DIR/test/local-chaos/lib.sh"

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
  printf '[local-chaos] 在宿主机构建静态测试二进制\n'
  if ! GOCACHE=${GOCACHE:-/tmp/bnfs-go-cache} CGO_ENABLED=0 go build -o "$build_dir/nodeserver" "$ROOT_DIR/cmd/tunnel/nodeserver" \
    || ! GOCACHE=${GOCACHE:-/tmp/bnfs-go-cache} CGO_ENABLED=0 go build -o "$build_dir/caserver" "$ROOT_DIR/cmd/caserver" \
    || ! GOCACHE=${GOCACHE:-/tmp/bnfs-go-cache} CGO_ENABLED=0 go build -o "$build_dir/billingqueue-inspect" "$ROOT_DIR/cmd/billingqueue-inspect" \
    || ! GOCACHE=${GOCACHE:-/tmp/bnfs-go-cache} CGO_ENABLED=0 go build -o "$build_dir/billing-adversary-probe" "$ROOT_DIR/cmd/billing-adversary-probe" \
    || ! GOCACHE=${GOCACHE:-/tmp/bnfs-go-cache} CGO_ENABLED=0 go build -o "$build_dir/billing-adversary-node" "$ROOT_DIR/cmd/billing-adversary-node" \
    || ! GOCACHE=${GOCACHE:-/tmp/bnfs-go-cache} CGO_ENABLED=0 go build -o "$build_dir/tunserver" "$ROOT_DIR/cmd/tunnel/server" \
    || ! GOCACHE=${GOCACHE:-/tmp/bnfs-go-cache} CGO_ENABLED=0 go build -o "$build_dir/tunclient" "$ROOT_DIR/cmd/tunnel/client" \
    || ! GOCACHE=${GOCACHE:-/tmp/bnfs-go-cache} CGO_ENABLED=0 go build -o "$build_dir/httpfileserver" "$ROOT_DIR/cmd/tunnel/httpfileserver"; then
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
    --file "$ROOT_DIR/test/local-chaos/Dockerfile" "$build_dir"; then
    printf '[local-chaos] 镜像构建失败\n' >&2
    exit 1
  fi
fi

if (( build_only == 1 )); then
  printf '[local-chaos] 构建完成，按 --build-only 不启动场景\n'
  exit 0
fi

scripts=()
if [[ $scenario == all ]]; then
  scripts=(
    "$ROOT_DIR/test/local-chaos/scenarios/01_partition_bridges.sh"
    "$ROOT_DIR/test/local-chaos/scenarios/02_relay_failover.sh"
    "$ROOT_DIR/test/local-chaos/scenarios/03_kcp_tcp_fallback.sh"
  )
else
  scripts=("$ROOT_DIR/test/local-chaos/scenarios/0${scenario}_"*.sh)
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
