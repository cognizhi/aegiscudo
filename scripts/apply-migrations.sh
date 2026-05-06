#!/usr/bin/env sh
set -eu

compose_file="${AEGISCUDO_COMPOSE_FILE:-infra/docker-compose.yml}"
postgres_service="${MIGRATION_POSTGRES_SERVICE:-postgres}"
db_name="${MIGRATION_DB_NAME:-aegiscudo}"
db_user="${MIGRATION_DB_USER:-aegiscudo}"
db_password="${MIGRATION_DB_PASSWORD:-aegiscudo}"

run_sql_file() {
  docker compose -f "$compose_file" exec -T "$postgres_service" \
    env PGPASSWORD="$db_password" \
    psql -U "$db_user" -d "$db_name" -v ON_ERROR_STOP=1
}

for migration in migrations/*.sql; do
  run_sql_file < "$migration" >/dev/null
done

printf '%s\n' "migrations applied successfully to ${db_name}"