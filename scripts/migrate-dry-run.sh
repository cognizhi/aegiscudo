#!/usr/bin/env sh
set -eu

test_db_name="${MIGRATION_CHECK_DB_NAME:-aegiscudo_migrate_check}"
compose_file="${AEGISCUDO_COMPOSE_FILE:-infra/docker-compose.yml}"
postgres_service="${MIGRATION_CHECK_POSTGRES_SERVICE:-postgres}"
db_user="${MIGRATION_CHECK_DB_USER:-aegiscudo}"
db_password="${MIGRATION_CHECK_DB_PASSWORD:-aegiscudo}"

case "$test_db_name" in
  *[!A-Za-z0-9_]*|"")
    printf '%s\n' "MIGRATION_CHECK_DB_NAME must contain only letters, numbers, and underscores" >&2
    exit 1
    ;;
esac

run_admin_sql() {
  docker compose -f "$compose_file" exec -T "$postgres_service" \
    env PGPASSWORD="$db_password" \
    psql -U "$db_user" -d postgres -v ON_ERROR_STOP=1 "$@"
}

run_test_sql_file() {
  docker compose -f "$compose_file" exec -T "$postgres_service" \
    env PGPASSWORD="$db_password" \
    psql -U "$db_user" -d "$test_db_name" -v ON_ERROR_STOP=1
}

cleanup() {
  run_admin_sql <<SQL >/dev/null
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE datname = '${test_db_name}'
  AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS "${test_db_name}";
SQL
}

trap cleanup EXIT INT TERM

cleanup

run_admin_sql -c "CREATE DATABASE \"${test_db_name}\";" >/dev/null

for migration in migrations/*.sql; do
  run_test_sql_file < "$migration" >/dev/null
done

printf '%s\n' "migration dry run succeeded: ${test_db_name}"