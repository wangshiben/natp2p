#!/usr/bin/env bash

set -euo pipefail
umask 077

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SOAK_HOME=${BNFS_SOAK_HOME:-$ROOT_DIR/test/local-chaos/.soak}
run_dir=

if [[ ${1:-} == --run-dir ]]; then
  run_dir=${2:?run directory is required}
  shift 2
fi
if (($#)); then
  printf 'usage: seed-node-user-bindings.sh [--run-dir DIR]\n' >&2
  exit 2
fi
if [[ -z $run_dir ]]; then
  run_dir=$(<"$SOAK_HOME/state/current")
fi
[[ -d $run_dir && -f $run_dir/metadata.env && -f $run_dir/nat-identities.tsv ]] || {
  printf 'current soak run does not expose node identities: %s\n' "$run_dir" >&2
  exit 1
}

phase=$(<"$run_dir/phase")
[[ $phase == RUNNING ]] || {
  printf 'node bindings require a RUNNING soak, current phase=%s\n' "$phase" >&2
  exit 1
}

metadata_value() {
  local key=$1
  awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); print; exit}' "$run_dir/metadata.env"
}

project=$(metadata_value compose_project)
compose_file=$run_dir/runtime/compose.json
[[ $project =~ ^bnfs-soak-[a-z0-9]+$ && -f $compose_file ]] || {
  printf 'invalid soak compose metadata\n' >&2
  exit 1
}

dc() {
  docker compose --project-name "$project" --file "$compose_file" "$@"
}

plan_file=$run_dir/node-user-binding-plan.tsv
result_file=$run_dir/node-user-bindings.tsv
printf 'node_id\tusername\tlabel\tbinding_source\n' > "$plan_file"
awk -F '\t' 'BEGIN { OFS="\t" }
  NR == 1 { next }
  $1 ~ /^natserver0[1-2]$/ { username="demo_user" }
  $1 ~ /^natserver0[3-4]$/ { username="developer" }
  $1 ~ /^natserver0[5-6]$/ { username="observer" }
  $1 == "natclient01" { username="demo_user" }
  $1 == "natclient02" { username="developer" }
  $1 == "natclient03" { username="observer" }
  username != "" {
    print $3, username, $1 " / " $2, "soak_seed"
    username=""
  }
' "$run_dir/nat-identities.tsv" >> "$plan_file"

[[ $(wc -l < "$plan_file") -eq 10 ]] || {
  printf 'expected nine deterministic NAT compatibility bindings\n' >&2
  exit 1
}

{
  cat <<'SQL'
BEGIN;
CREATE TEMP TABLE requested_node_bindings (
    node_id char(64),
    username text,
    label text,
    binding_source text
) ON COMMIT DROP;
COPY requested_node_bindings (node_id, username, label, binding_source)
FROM STDIN WITH (FORMAT text, DELIMITER E'\t');
SQL
  tail -n +2 "$plan_file"
  printf '\\.\n'
  cat <<'SQL'
INSERT INTO node_user_bindings
    (node_id, user_id, label, binding_source, bound_by, bound_at, updated_at)
SELECT requested.node_id, app_user.id, requested.label, requested.binding_source,
       'system:local-chaos-soak', now(), now()
FROM requested_node_bindings AS requested
JOIN nodes AS node ON node.id = requested.node_id
JOIN app_users AS app_user ON app_user.username = requested.username AND app_user.status = 'active'
WHERE NOT EXISTS (
    SELECT 1 FROM user_node_authorizations AS node_authorization
    WHERE node_authorization.node_id = requested.node_id AND node_authorization.status = 'active'
)
ON CONFLICT (node_id) DO NOTHING;

WITH ranked_relays AS (
    SELECT node.id, row_number() OVER (ORDER BY node.first_seen_at, node.id) AS position
    FROM nodes AS node
    WHERE node.role = 'relay'
), selected_relays AS (
    SELECT relay.id, relay.position,
           CASE relay.position
               WHEN 1 THEN 'demo_user'
               WHEN 2 THEN 'developer'
               WHEN 3 THEN 'observer'
           END AS username
    FROM ranked_relays AS relay
    WHERE relay.position <= 3
)
INSERT INTO node_user_bindings
    (node_id, user_id, label, binding_source, bound_by, bound_at, updated_at)
SELECT relay.id, app_user.id,
       'Relay 测试节点 ' || lpad(relay.position::text, 2, '0'),
       'soak_seed', 'system:local-chaos-soak', now(), now()
FROM selected_relays AS relay
JOIN app_users AS app_user ON app_user.username = relay.username AND app_user.status = 'active'
WHERE NOT EXISTS (
    SELECT 1 FROM user_node_authorizations AS node_authorization
    WHERE node_authorization.node_id = relay.id AND node_authorization.status = 'active'
)
ON CONFLICT (node_id) DO NOTHING;
COMMIT;
SQL
} | dc exec -T ca-postgres psql -v ON_ERROR_STOP=1 -U ca_web -d ca_web >/dev/null

dc exec -T ca-postgres psql -v ON_ERROR_STOP=1 -U ca_web -d ca_web -c "
COPY (
    SELECT binding.node_id, node.role, binding.label, app_user.username,
           app_user.display_name, binding.binding_source, binding.bound_at
    FROM node_user_bindings AS binding
    JOIN nodes AS node ON node.id = binding.node_id
    JOIN app_users AS app_user ON app_user.id = binding.user_id
    ORDER BY node.role, binding.label, binding.node_id
) TO STDOUT WITH (FORMAT csv, HEADER true, DELIMITER E'\t')" > "$result_file"

binding_count=$(( $(wc -l < "$result_file") - 1 ))
(( binding_count >= 12 )) || {
  printf 'only %d compatibility bindings were persisted\n' "$binding_count" >&2
  exit 1
}
printf 'run_dir=%s\nbindings=%d\nevidence=%s\n' "$run_dir" "$binding_count" "$result_file"
