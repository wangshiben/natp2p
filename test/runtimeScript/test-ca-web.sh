#!/usr/bin/env bash

set -euo pipefail
umask 077

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
CA_WEB_ROOT=${BNFS_CA_WEB_ROOT:-$ROOT_DIR/ca_web}
RUNTIME_DIR=${BNFS_TEST_CA_RUNTIME_DIR:-$ROOT_DIR/test/runtimeScript/local-chaos/.test-ca-web}
COMPOSE_FILE=$RUNTIME_DIR/compose.yaml
COMPOSE_PROJECT=${BNFS_TEST_CA_PROJECT:-bnfs-test-ca-web}
WEB_PORT=${BNFS_TEST_CA_WEB_PORT:-18088}
API_PORT=${BNFS_TEST_CA_API_PORT:-19100}
BACKEND_IMAGE=${BNFS_CHAOS_CA_BACKEND_IMAGE:-bnfs-ca-web-backend:latest}
FRONTEND_IMAGE=${BNFS_CHAOS_CA_FRONTEND_IMAGE:-bnfs-ca-web-frontend:latest}
BACKEND_USER=$(id -u):$(id -g)
DATABASE_PASSWORD_FILE=$RUNTIME_DIR/.private/postgres.password
DATABASE_PASSWORD=

usage() {
  printf 'usage: %s start|status|stop\n' "$0"
}

validate_port() {
  [[ $1 =~ ^[1-9][0-9]{0,4}$ ]] && ((10#$1 <= 65535))
}

validate_source() {
  local branch
  [[ -d $CA_WEB_ROOT/.git && -f $CA_WEB_ROOT/backend/Dockerfile && -f $CA_WEB_ROOT/frontend/Dockerfile ]] || {
    printf '[test-ca-web] 独立 CA Web 仓库无效: %s\n' "$CA_WEB_ROOT" >&2
    return 1
  }
  branch=$(git -C "$CA_WEB_ROOT" symbolic-ref --quiet --short HEAD 2>/dev/null) || return 1
  [[ $branch == dev ]] || {
    printf '[test-ca-web] 测试实例必须使用 ca_web/dev，当前为 %s\n' "$branch" >&2
    return 1
  }
}

load_database_password() {
  local generated
  mkdir -p "$RUNTIME_DIR/.private"
  chmod 700 "$RUNTIME_DIR/.private"
  if [[ ! -e $DATABASE_PASSWORD_FILE ]]; then
    generated=$(od -An -N32 -tx1 /dev/urandom | tr -d '[:space:]')
    [[ $generated =~ ^[0-9a-f]{64}$ ]]
    printf '%s\n' "$generated" > "$DATABASE_PASSWORD_FILE"
    chmod 600 "$DATABASE_PASSWORD_FILE"
  fi
  [[ -f $DATABASE_PASSWORD_FILE && ! -L $DATABASE_PASSWORD_FILE ]]
  DATABASE_PASSWORD=$(tr -d '[:space:]' < "$DATABASE_PASSWORD_FILE")
  [[ $DATABASE_PASSWORD =~ ^[0-9a-f]{64}$ ]]
}

generate_fixture() {
  BNFS_CHAOS_ENABLE_CA=1 \
    BNFS_CHAOS_CA_HOST_PORT="$API_PORT" \
    BNFS_CHAOS_CA_WEB_HOST_PORT="$WEB_PORT" \
    BNFS_CHAOS_CA_BACKEND_IMAGE="$BACKEND_IMAGE" \
    BNFS_CHAOS_CA_FRONTEND_IMAGE="$FRONTEND_IMAGE" \
    node "$ROOT_DIR/test/runtimeScript/local-chaos/generate-compose.mjs" "$RUNTIME_DIR" \
      > "$RUNTIME_DIR/full-compose.json"
}

write_compose() {
  cat > "$COMPOSE_FILE" <<EOF
services:
  postgres:
    image: postgres:17-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: ca_web
      POSTGRES_USER: ca_web
      POSTGRES_PASSWORD: $DATABASE_PASSWORD
    volumes:
      - $RUNTIME_DIR/postgres:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ca_web -d ca_web"]
      interval: 2s
      timeout: 3s
      retries: 30
  backend:
    image: $BACKEND_IMAGE
    user: "$BACKEND_USER"
    restart: unless-stopped
    command: ["--issuer", "bnfs-test-ca", "--database-connections", "16", "--database-idle-connections", "2", "--admin-token-file", "/data/admin.token"]
    environment:
      CA_DATABASE_DRIVER: postgres
      CA_DATABASE_URL: postgres://ca_web:$DATABASE_PASSWORD@postgres:5432/ca_web?sslmode=disable
      CA_ENABLE_MOCK_USERS: "true"
      CA_LOG_DIRECTORY: /data/logs
      CA_LOG_LEVEL: info
      CA_LOG_MAX_SIZE_MIB: "32"
      CA_LOG_ROTATE_INTERVAL: 24h
      CA_LOG_RETENTION: 720h
      CA_LOG_CONSOLE: "true"
    ports:
      - "127.0.0.1:$API_PORT:8090"
    volumes:
      - $RUNTIME_DIR/.private/ca:/data
    depends_on:
      postgres:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "/ca-web", "--healthcheck", "http://127.0.0.1:8090/readyz"]
      interval: 2s
      timeout: 3s
      retries: 30
    read_only: true
    tmpfs:
      - /tmp:size=16m,mode=1777
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
  frontend:
    image: $FRONTEND_IMAGE
    restart: unless-stopped
    environment:
      BACKEND_URL: http://backend:8090
      TLS_HOSTS: localhost,127.0.0.1,::1,192.168.1.12
    ports:
      - "$WEB_PORT:8088"
    volumes:
      - $RUNTIME_DIR/frontend-tls:/etc/nginx/tls
    depends_on:
      backend:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-kfsS", "https://127.0.0.1:8088/"]
      interval: 3s
      timeout: 3s
      retries: 20
    read_only: true
    tmpfs:
      - /var/cache/nginx:size=32m,mode=0755
      - /var/run:size=4m,mode=0755
      - /etc/nginx/conf.d:size=1m,mode=0755
      - /tmp:size=4m,mode=1777
    security_opt:
      - no-new-privileges:true
EOF
  chmod 600 "$COMPOSE_FILE"
}

wait_healthy() {
  local service deadline=$((SECONDS + 90)) container health
  for service in "$@"; do
    while ((SECONDS < deadline)); do
      container=$(docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" ps -q "$service")
      health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container" 2>/dev/null || true)
      [[ $health == healthy ]] && break
      sleep 1
    done
    [[ $health == healthy ]] || return 1
  done
}

rotate_database_password() {
  printf "ALTER ROLE ca_web PASSWORD '%s';\n" "$DATABASE_PASSWORD" \
    | docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" exec -T postgres \
      psql -v ON_ERROR_STOP=1 -U ca_web -d ca_web >/dev/null
}

start() {
  validate_source
  validate_port "$WEB_PORT" && validate_port "$API_PORT" && [[ $WEB_PORT != "$API_PORT" ]]
  mkdir -p "$RUNTIME_DIR" "$RUNTIME_DIR/postgres" "$RUNTIME_DIR/frontend-tls"
  load_database_password
  generate_fixture
  write_compose
  docker build --pull=false -t "$BACKEND_IMAGE" "$CA_WEB_ROOT/backend"
  docker build --pull=false -t "$FRONTEND_IMAGE" "$CA_WEB_ROOT/frontend"
  docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" up -d postgres
  wait_healthy postgres || {
    docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" logs --no-color >&2
    return 1
  }
  rotate_database_password
  docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" up -d --force-recreate backend frontend
  wait_healthy backend frontend || {
    docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" logs --no-color >&2
    return 1
  }
  PRIVATE_RUNTIME_DIR="$RUNTIME_DIR/.private" \
    CA_BASE_URL="http://127.0.0.1:$API_PORT" \
    CA_ADMIN_TOKEN_FILE="$RUNTIME_DIR/.private/ca/admin.token" \
    node "$ROOT_DIR/test/runtimeScript/local-chaos/bootstrap-billing-keys.mjs"
  {
    printf 'branch=%s\n' "$(git -C "$CA_WEB_ROOT" symbolic-ref --short HEAD)"
    printf 'commit=%s\n' "$(git -C "$CA_WEB_ROOT" rev-parse HEAD)"
    printf 'web_bind=0.0.0.0:%s\n' "$WEB_PORT"
    printf 'web_url=https://127.0.0.1:%s/\n' "$WEB_PORT"
    printf 'api_url=http://127.0.0.1:%s/\n' "$API_PORT"
    printf 'automation=admin_session\n'
  } > "$RUNTIME_DIR/deployment.env"
  chmod 600 "$RUNTIME_DIR/deployment.env"
  printf '[test-ca-web] 已启动: https://127.0.0.1:%s/（绑定 0.0.0.0，API 仅回环 %s）\n' "$WEB_PORT" "$API_PORT"
}

status() {
  [[ -f $COMPOSE_FILE ]] || {
    printf '[test-ca-web] 尚未部署\n'
    return 1
  }
  docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" ps
  [[ -f $RUNTIME_DIR/deployment.env ]] && sed -n '1,6p' "$RUNTIME_DIR/deployment.env"
}

stop() {
  [[ -f $COMPOSE_FILE ]] || return 0
  docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" down --remove-orphans
  printf '[test-ca-web] 已停止，PostgreSQL 数据保留在 %s\n' "$RUNTIME_DIR/postgres"
}

case ${1:-} in
  start) start ;;
  status) status ;;
  stop) stop ;;
  *) usage >&2; exit 2 ;;
esac
