#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

compose_file="${AEGISCUDO_COMPOSE_FILE:-infra/docker-compose.yml}"
postgres_service="${MIGRATION_POSTGRES_SERVICE:-postgres}"
db_name="${MIGRATION_DB_NAME:-aegiscudo}"
db_user="${MIGRATION_DB_USER:-aegiscudo}"
database_url="${DATABASE_URL:-postgres://aegiscudo:aegiscudo@127.0.0.1:15432/aegiscudo}"
api_bind_addr="${AEGISCUDO_API_BIND_ADDR:-127.0.0.1:18002}"

cd "$repo_root"

export DATABASE_URL="$database_url"
export AEGISCUDO_API_BIND_ADDR="$api_bind_addr"

if ! command -v psql >/dev/null 2>&1 && command -v docker >/dev/null 2>&1; then
  docker compose -f "$compose_file" up -d "$postgres_service" >/dev/null
  until docker compose -f "$compose_file" exec -T "$postgres_service" \
    pg_isready -U "$db_user" -d "$db_name" >/dev/null 2>&1; do
    printf '%s\n' "waiting for Compose PostgreSQL service $postgres_service" >&2
    sleep 1
  done
elif command -v pg_isready >/dev/null 2>&1; then
  until pg_isready -d "$DATABASE_URL" >/dev/null 2>&1; do
    printf '%s\n' "waiting for PostgreSQL at $DATABASE_URL" >&2
    sleep 1
  done
fi

./scripts/apply-migrations.sh
./scripts/seed-local-control-plane.sh

exec cargo run -p aegiscudo-api