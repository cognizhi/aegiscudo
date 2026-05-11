#!/usr/bin/env sh
set -eu

compose_file="${AEGISCUDO_COMPOSE_FILE:-infra/docker-compose.yml}"
postgres_service="${MIGRATION_POSTGRES_SERVICE:-postgres}"
db_name="${MIGRATION_DB_NAME:-aegiscudo}"
db_user="${MIGRATION_DB_USER:-aegiscudo}"
db_password="${MIGRATION_DB_PASSWORD:-aegiscudo}"
database_url="${DATABASE_URL:-}"

run_psql() {
  if [ -n "$database_url" ] && command -v psql >/dev/null 2>&1; then
    env PGPASSWORD="${PGPASSWORD:-$db_password}" \
      psql "$database_url" -v ON_ERROR_STOP=1 "$@"
    return
  fi

  docker compose -f "$compose_file" exec -T "$postgres_service" \
    env PGPASSWORD="$db_password" \
    psql -U "$db_user" -d "$db_name" -v ON_ERROR_STOP=1 "$@"
}

ensure_schema_migrations_table() {
  run_psql -c "
    CREATE TABLE IF NOT EXISTS schema_migrations (
      filename text PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    )
  " >/dev/null
}

is_recorded_migration() {
  migration_filename="$1"
  result=$(run_psql -Atqc "SELECT 1 FROM schema_migrations WHERE filename = '${migration_filename}'")
  [ "$result" = "1" ]
}

migration_effectively_applied() {
  migration_filename="$1"
  case "$migration_filename" in
    0001_init.sql)
      sql="SELECT to_regclass('public.analysis_jobs') IS NOT NULL"
      ;;
    0002_control_plane_constraints.sql)
      sql="
        SELECT
          EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'integration_credentials_tenant_id_id_unique')
          OR EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'registry_configs_policy_profile_tenant_fk')
          OR EXISTS (SELECT 1 FROM pg_class WHERE relname = 'registry_configs_active_mount_path_global_unique')
      "
      ;;
    0003_analysis_jobs_request_context.sql)
      sql="
        SELECT EXISTS (
          SELECT 1
          FROM information_schema.columns
          WHERE table_schema = 'public'
            AND table_name = 'analysis_jobs'
            AND column_name IN ('ecosystem', 'namespace', 'package_name', 'package_version', 'artifact_sha256')
        )
      "
      ;;
    0004_control_plane_signal_observations.sql)
      sql="SELECT to_regclass('public.package_signal_observations') IS NOT NULL"
      ;;
    0005_analysis_job_fetch_context.sql)
      sql="
        SELECT EXISTS (
          SELECT 1
          FROM information_schema.columns
          WHERE table_schema = 'public'
            AND table_name = 'analysis_jobs'
            AND column_name IN ('registry_config_id', 'source_url')
        )
      "
      ;;
    0006_analysis_summaries.sql)
      sql="SELECT to_regclass('public.analysis_summaries') IS NOT NULL"
      ;;
    0007_static_analysis_report_policy_snapshot.sql)
      sql="
        SELECT EXISTS (
          SELECT 1
          FROM information_schema.columns
          WHERE table_schema = 'public'
            AND table_name = 'static_analysis_reports'
            AND column_name = 'policy_version_id'
        )
      "
      ;;
    0008_static_analysis_report_storage.sql)
      sql="
        SELECT EXISTS (
          SELECT 1
          FROM information_schema.columns
          WHERE table_schema = 'public'
            AND table_name = 'static_analysis_reports'
            AND column_name IN ('report_storage_uri', 'report_storage_sha256', 'report_storage_size_bytes')
        )
      "
      ;;
    *)
      return 1
      ;;
  esac

  result=$(run_psql -Atqc "$sql")
  [ "$result" = "t" ]
}

record_migration() {
  migration_filename="$1"
  run_psql -c "
    INSERT INTO schema_migrations (filename)
    VALUES ('${migration_filename}')
    ON CONFLICT (filename) DO NOTHING
  " >/dev/null
}

ensure_schema_migrations_table

for migration in migrations/*.sql; do
  migration_filename=$(basename "$migration")

  if is_recorded_migration "$migration_filename"; then
    continue
  fi

  if migration_effectively_applied "$migration_filename"; then
    record_migration "$migration_filename"
    continue
  fi

  run_psql < "$migration" >/dev/null
  record_migration "$migration_filename"
done

printf '%s\n' "migrations applied successfully to ${db_name}"