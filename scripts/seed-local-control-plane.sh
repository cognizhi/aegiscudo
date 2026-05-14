#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
compose_file="${AEGISCUDO_COMPOSE_FILE:-infra/docker-compose.yml}"
postgres_service="${MIGRATION_POSTGRES_SERVICE:-postgres}"
db_name="${MIGRATION_DB_NAME:-aegiscudo}"
db_user="${MIGRATION_DB_USER:-aegiscudo}"
db_password="${MIGRATION_DB_PASSWORD:-aegiscudo}"
database_url="${DATABASE_URL:-}"

run_seed() {
  if [ -n "$database_url" ] && command -v psql >/dev/null 2>&1; then
    env PGPASSWORD="${PGPASSWORD:-$db_password}" \
      psql "$database_url" -v ON_ERROR_STOP=1
    return
  fi

  docker compose -f "$compose_file" exec -T "$postgres_service" \
    env PGPASSWORD="$db_password" \
    psql -U "$db_user" -d "$db_name" -v ON_ERROR_STOP=1
}

seed_live_npm_fixture_artifact() {
  artifact_id=$1
  package_name=$2
  package_version=$3
  storage_uri=$4
  created_at=$5

  fixture_values=$(
    REPO_ROOT="$repo_root" \
      PACKAGE_NAME="$package_name" \
      PACKAGE_VERSION="$package_version" \
      python3 - <<'PY'
from pathlib import Path
import hashlib
import os
import sys

repo_root = Path(os.environ["REPO_ROOT"])
package_name = os.environ["PACKAGE_NAME"]
package_version = os.environ["PACKAGE_VERSION"]
sys.path.insert(0, str(repo_root / "scripts"))

from fixture_registry import build_npm_tarball

tarball = build_npm_tarball(
    repo_root / "testdata" / "npm",
    package_name,
    package_version,
)
print(hashlib.sha256(tarball).hexdigest())
print(len(tarball))
PY
  )
  artifact_sha256=$(printf '%s\n' "$fixture_values" | sed -n '1p')
  artifact_size_bytes=$(printf '%s\n' "$fixture_values" | sed -n '2p')
  seeded_artifact_sha256=$artifact_sha256

  run_seed <<SQL >/dev/null
INSERT INTO artifacts (
  id,
  tenant_id,
  ecosystem,
  namespace,
  package_name,
  package_version,
  sha256,
  size_bytes,
  storage_uri,
  created_at
)
VALUES (
  '$artifact_id',
  '018f4a6f-55d0-7000-8000-000000000001',
  'npm',
  NULL,
  '$package_name',
  '$package_version',
  '$artifact_sha256',
  $artifact_size_bytes,
  '$storage_uri',
  '$created_at'
)
ON CONFLICT (id) DO UPDATE
SET ecosystem = EXCLUDED.ecosystem,
    namespace = EXCLUDED.namespace,
    package_name = EXCLUDED.package_name,
    package_version = EXCLUDED.package_version,
    sha256 = EXCLUDED.sha256,
    size_bytes = EXCLUDED.size_bytes,
    storage_uri = EXCLUDED.storage_uri,
    created_at = EXCLUDED.created_at;
SQL
}

seed_live_pypi_fixture_artifact() {
  artifact_id=$1
  package_name=$2
  package_version=$3
  fixture_path=$4
  storage_uri=$5
  created_at=$6

  fixture_values=$(
    REPO_ROOT="$repo_root" \
      FIXTURE_PATH="$fixture_path" \
      python3 - <<'PY'
from pathlib import Path
import hashlib
import os

repo_root = Path(os.environ["REPO_ROOT"])
fixture_path = repo_root / os.environ["FIXTURE_PATH"]
payload = fixture_path.read_bytes()
print(hashlib.sha256(payload).hexdigest())
print(len(payload))
PY
  )
  artifact_sha256=$(printf '%s\n' "$fixture_values" | sed -n '1p')
  artifact_size_bytes=$(printf '%s\n' "$fixture_values" | sed -n '2p')

  run_seed <<SQL >/dev/null
INSERT INTO artifacts (
  id,
  tenant_id,
  ecosystem,
  namespace,
  package_name,
  package_version,
  sha256,
  size_bytes,
  storage_uri,
  created_at
)
VALUES (
  '$artifact_id',
  '018f4a6f-55d0-7000-8000-000000000001',
  'pypi',
  NULL,
  '$package_name',
  '$package_version',
  '$artifact_sha256',
  $artifact_size_bytes,
  '$storage_uri',
  '$created_at'
)
ON CONFLICT (id) DO UPDATE
SET ecosystem = EXCLUDED.ecosystem,
    namespace = EXCLUDED.namespace,
    package_name = EXCLUDED.package_name,
    package_version = EXCLUDED.package_version,
    sha256 = EXCLUDED.sha256,
    size_bytes = EXCLUDED.size_bytes,
    storage_uri = EXCLUDED.storage_uri,
    created_at = EXCLUDED.created_at;
SQL
}

seed_live_cargo_fixture_artifact() {
  artifact_id=$1
  package_name=$2
  package_version=$3
  storage_uri=$4
  created_at=$5

  fixture_values=$(
    REPO_ROOT="$repo_root" \
      PACKAGE_NAME="$package_name" \
      PACKAGE_VERSION="$package_version" \
      python3 - <<'PY'
from pathlib import Path
import hashlib
import os
import sys

repo_root = Path(os.environ["REPO_ROOT"])
package_name = os.environ["PACKAGE_NAME"]
package_version = os.environ["PACKAGE_VERSION"]
sys.path.insert(0, str(repo_root / "scripts"))

from fixture_registry import build_cargo_crate

crate_bytes = build_cargo_crate(
    repo_root / "testdata" / "cargo",
    package_name,
    package_version,
)
print(hashlib.sha256(crate_bytes).hexdigest())
print(len(crate_bytes))
PY
  )
  artifact_sha256=$(printf '%s\n' "$fixture_values" | sed -n '1p')
  artifact_size_bytes=$(printf '%s\n' "$fixture_values" | sed -n '2p')

  run_seed <<SQL >/dev/null
INSERT INTO artifacts (
  id,
  tenant_id,
  ecosystem,
  namespace,
  package_name,
  package_version,
  sha256,
  size_bytes,
  storage_uri,
  created_at
)
VALUES (
  '$artifact_id',
  '018f4a6f-55d0-7000-8000-000000000001',
  'cargo',
  NULL,
  '$package_name',
  '$package_version',
  '$artifact_sha256',
  $artifact_size_bytes,
  '$storage_uri',
  '$created_at'
)
ON CONFLICT (id) DO UPDATE
SET ecosystem = EXCLUDED.ecosystem,
    namespace = EXCLUDED.namespace,
    package_name = EXCLUDED.package_name,
    package_version = EXCLUDED.package_version,
    sha256 = EXCLUDED.sha256,
    size_bytes = EXCLUDED.size_bytes,
    storage_uri = EXCLUDED.storage_uri,
    created_at = EXCLUDED.created_at;
SQL
}

seed_live_maven_fixture_artifact() {
  artifact_id=$1
  namespace=$2
  package_name=$3
  package_version=$4
  fixture_path=$5
  storage_uri=$6
  created_at=$7

  fixture_values=$(
    REPO_ROOT="$repo_root" \
      FIXTURE_PATH="$fixture_path" \
      python3 - <<'PY'
from pathlib import Path
import hashlib
import os

repo_root = Path(os.environ["REPO_ROOT"])
fixture_path = repo_root / os.environ["FIXTURE_PATH"]
payload = fixture_path.read_bytes()
print(hashlib.sha256(payload).hexdigest())
print(len(payload))
PY
  )
  artifact_sha256=$(printf '%s\n' "$fixture_values" | sed -n '1p')
  artifact_size_bytes=$(printf '%s\n' "$fixture_values" | sed -n '2p')

  run_seed <<SQL >/dev/null
INSERT INTO artifacts (
  id,
  tenant_id,
  ecosystem,
  namespace,
  package_name,
  package_version,
  sha256,
  size_bytes,
  storage_uri,
  created_at
)
VALUES (
  '$artifact_id',
  '018f4a6f-55d0-7000-8000-000000000001',
  'maven',
  '$namespace',
  '$package_name',
  '$package_version',
  '$artifact_sha256',
  $artifact_size_bytes,
  '$storage_uri',
  '$created_at'
)
ON CONFLICT (id) DO UPDATE
SET ecosystem = EXCLUDED.ecosystem,
    namespace = EXCLUDED.namespace,
    package_name = EXCLUDED.package_name,
    package_version = EXCLUDED.package_version,
    sha256 = EXCLUDED.sha256,
    size_bytes = EXCLUDED.size_bytes,
    storage_uri = EXCLUDED.storage_uri,
    created_at = EXCLUDED.created_at;
SQL
}

seed_live_package_signal() {
  signal_id=$1
  package_name=$2
  package_version=$3
  artifact_sha256=$4
  signal_name=$5
  signal_severity=$6
  signal_details=$7
  observed_at=$8

  run_seed <<SQL >/dev/null
INSERT INTO package_signal_observations (
  id,
  tenant_id,
  ecosystem,
  namespace,
  package_name,
  package_version,
  artifact_sha256,
  signal,
  severity,
  details,
  observed_at,
  expires_at
)
VALUES (
  '$signal_id',
  '018f4a6f-55d0-7000-8000-000000000001',
  'npm',
  NULL,
  '$package_name',
  '$package_version',
  '$artifact_sha256',
  '$signal_name',
  '$signal_severity',
  '$signal_details'::jsonb,
  '$observed_at',
  NULL
)
ON CONFLICT (id) DO UPDATE
SET package_version = EXCLUDED.package_version,
    artifact_sha256 = EXCLUDED.artifact_sha256,
    signal = EXCLUDED.signal,
    severity = EXCLUDED.severity,
    details = EXCLUDED.details,
    observed_at = EXCLUDED.observed_at,
    expires_at = EXCLUDED.expires_at;
SQL
}

reset_live_validation_request_history() {
  run_seed <<'SQL' >/dev/null
DELETE FROM policy_decisions pd
USING package_requests pr
WHERE pd.package_request_id = pr.id
  AND pr.tenant_id = '018f4a6f-55d0-7000-8000-000000000001'
  AND (
    pr.package_name = 'aegiscudo-benign-npm-fixture'
    OR pr.package_name = 'aegiscudo-benign-cargo-fixture'
    OR pr.package_name = 'aegiscudo-benign-pypi-fixture'
    OR pr.package_name = 'aegiscudo-benign-maven-fixture'
    OR (
      pr.package_name = 'fresh-postinstall'
      AND NOT (
        pr.id = '018f4a6f-55d0-7000-8000-000000000501'
        AND pd.id = '018f4a6f-55d0-7000-8000-000000000701'
      )
    )
  );

DELETE FROM package_requests
WHERE tenant_id = '018f4a6f-55d0-7000-8000-000000000001'
  AND package_name IN ('aegiscudo-benign-npm-fixture', 'aegiscudo-benign-cargo-fixture', 'aegiscudo-benign-pypi-fixture', 'aegiscudo-benign-maven-fixture', 'fresh-postinstall')
  AND id <> '018f4a6f-55d0-7000-8000-000000000501';
SQL
}

run_seed < "$repo_root/infra/fixtures/control-plane-seed.sql" >/dev/null
reset_live_validation_request_history
seed_live_npm_fixture_artifact \
  '018f4a6f-55d0-7000-8000-000000000601' \
  'fresh-postinstall' \
  '0.1.0' \
  'http://127.0.0.1:18080/fresh-postinstall/-/fresh-postinstall-0.1.0.tgz' \
  '2026-05-05T10:00:00Z'
seed_live_package_signal \
  '018f4a6f-55d0-7000-8000-000000001401' \
  'fresh-postinstall' \
  '0.1.0' \
  "$seeded_artifact_sha256" \
  'minimum-release-age-violation' \
  'medium' \
  '{"source":"live-fixture-seed","reason":"published within tenant minimum age window"}' \
  '2026-05-05T10:00:20Z'
seed_live_package_signal \
  '018f4a6f-55d0-7000-8000-000000001402' \
  'fresh-postinstall' \
  '0.1.0' \
  "$seeded_artifact_sha256" \
  'install-script-detected' \
  'high' \
  '{"source":"live-fixture-seed","script":"postinstall"}' \
  '2026-05-05T10:00:21Z'
seed_live_npm_fixture_artifact \
  '018f4a6f-55d0-7000-8000-000000000603' \
  'aegiscudo-benign-npm-fixture' \
  '1.0.0' \
  'http://127.0.0.1:18080/aegiscudo-benign-npm-fixture/-/aegiscudo-benign-npm-fixture-1.0.0.tgz' \
  '2026-05-05T10:20:00Z'
seed_live_cargo_fixture_artifact \
  '018f4a6f-55d0-7000-8000-000000000605' \
  'aegiscudo-benign-cargo-fixture' \
  '1.0.0' \
  'http://127.0.0.1:18082/api/v1/crates/aegiscudo-benign-cargo-fixture/1.0.0/download' \
  '2026-05-05T10:22:00Z'
seed_live_pypi_fixture_artifact \
  '018f4a6f-55d0-7000-8000-000000000604' \
  'aegiscudo-benign-pypi-fixture' \
  '1.0.0' \
  'testdata/pypi/packages/aegiscudo_benign_pypi_fixture-1.0.0-py3-none-any.whl' \
  'http://127.0.0.1:18081/packages/aegiscudo_benign_pypi_fixture-1.0.0-py3-none-any.whl' \
  '2026-05-05T10:25:00Z'
seed_live_maven_fixture_artifact \
  '018f4a6f-55d0-7000-8000-000000000606' \
  'com.aegiscudo.fixtures' \
  'aegiscudo-benign-maven-fixture' \
  '1.0.0' \
  'testdata/maven/com/aegiscudo/fixtures/aegiscudo-benign-maven-fixture/1.0.0/aegiscudo-benign-maven-fixture-1.0.0.jar' \
  'http://127.0.0.1:18083/com/aegiscudo/fixtures/aegiscudo-benign-maven-fixture/1.0.0/aegiscudo-benign-maven-fixture-1.0.0.jar' \
  '2026-05-05T10:26:00Z'

printf '%s\n' "local control-plane seed applied to ${db_name}"