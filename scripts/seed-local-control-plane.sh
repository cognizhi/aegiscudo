#!/usr/bin/env sh
set -eu

compose_file="${AEGISCUDO_COMPOSE_FILE:-infra/docker-compose.yml}"
postgres_service="${MIGRATION_POSTGRES_SERVICE:-postgres}"
db_name="${MIGRATION_DB_NAME:-aegiscudo}"
db_user="${MIGRATION_DB_USER:-aegiscudo}"
db_password="${MIGRATION_DB_PASSWORD:-aegiscudo}"

docker compose -f "$compose_file" exec -T "$postgres_service" \
  env PGPASSWORD="$db_password" \
  psql -U "$db_user" -d "$db_name" -v ON_ERROR_STOP=1 \
  < infra/fixtures/control-plane-seed.sql >/dev/null

printf '%s\n' "local control-plane seed applied to ${db_name}"