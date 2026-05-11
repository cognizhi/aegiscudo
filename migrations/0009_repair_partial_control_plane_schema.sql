DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'integration_credentials_tenant_id_id_unique'
  ) THEN
    ALTER TABLE integration_credentials
      ADD CONSTRAINT integration_credentials_tenant_id_id_unique UNIQUE (tenant_id, id);
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'policy_profiles_tenant_id_id_unique'
  ) THEN
    ALTER TABLE policy_profiles
      ADD CONSTRAINT policy_profiles_tenant_id_id_unique UNIQUE (tenant_id, id);
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'registry_configs_tenant_id_id_unique'
  ) THEN
    ALTER TABLE registry_configs
      ADD CONSTRAINT registry_configs_tenant_id_id_unique UNIQUE (tenant_id, id);
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'registry_configs_policy_profile_tenant_fk'
  ) THEN
    ALTER TABLE registry_configs
      ADD CONSTRAINT registry_configs_policy_profile_tenant_fk
      FOREIGN KEY (tenant_id, policy_profile_id) REFERENCES policy_profiles(tenant_id, id);
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'registry_configs_credential_tenant_fk'
  ) THEN
    ALTER TABLE registry_configs
      ADD CONSTRAINT registry_configs_credential_tenant_fk
      FOREIGN KEY (tenant_id, credential_ref) REFERENCES integration_credentials(tenant_id, id);
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'registry_configs_mount_path_canonical'
  ) THEN
    ALTER TABLE registry_configs
      ADD CONSTRAINT registry_configs_mount_path_canonical
      CHECK (mount_path ~ '^/proxy/[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*$');
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'registry_configs_upstream_url_no_userinfo'
  ) THEN
    ALTER TABLE registry_configs
      ADD CONSTRAINT registry_configs_upstream_url_no_userinfo
      CHECK (upstream_url !~ '^https?://[^/@]+@');
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS registry_configs_active_mount_path_global_unique
  ON registry_configs (mount_path)
  WHERE deleted_at IS NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'policy_versions_policy_profile_tenant_fk'
  ) THEN
    ALTER TABLE policy_versions
      ADD CONSTRAINT policy_versions_policy_profile_tenant_fk
      FOREIGN KEY (tenant_id, policy_profile_id) REFERENCES policy_profiles(tenant_id, id);
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'package_requests_registry_config_tenant_fk'
  ) THEN
    ALTER TABLE package_requests
      ADD CONSTRAINT package_requests_registry_config_tenant_fk
      FOREIGN KEY (tenant_id, registry_config_id) REFERENCES registry_configs(tenant_id, id);
  END IF;
END $$;

ALTER TABLE analysis_jobs
  ADD COLUMN IF NOT EXISTS ecosystem package_ecosystem,
  ADD COLUMN IF NOT EXISTS namespace text,
  ADD COLUMN IF NOT EXISTS package_name text,
  ADD COLUMN IF NOT EXISTS package_version text,
  ADD COLUMN IF NOT EXISTS artifact_sha256 text CHECK (artifact_sha256 ~ '^[a-f0-9]{64}$'),
  ADD COLUMN IF NOT EXISTS registry_config_id uuid REFERENCES registry_configs(id),
  ADD COLUMN IF NOT EXISTS source_url text;

UPDATE analysis_jobs AS jobs
SET ecosystem = artifacts.ecosystem,
    namespace = artifacts.namespace,
    package_name = artifacts.package_name,
    package_version = artifacts.package_version,
    artifact_sha256 = artifacts.sha256
FROM artifacts
WHERE jobs.artifact_id = artifacts.id
  AND (
    jobs.ecosystem IS NULL
    OR jobs.package_name IS NULL
    OR jobs.artifact_sha256 IS NULL
  );

UPDATE analysis_jobs AS jobs
SET registry_config_id = requests.registry_config_id
FROM package_requests AS requests
WHERE jobs.trace_id = requests.trace_id
  AND jobs.tenant_id = requests.tenant_id
  AND jobs.registry_config_id IS NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'analysis_jobs_ecosystem_required'
  ) AND NOT EXISTS (
    SELECT 1 FROM analysis_jobs WHERE ecosystem IS NULL OR package_name IS NULL OR artifact_sha256 IS NULL
  ) THEN
    ALTER TABLE analysis_jobs
      ALTER COLUMN ecosystem SET NOT NULL,
      ALTER COLUMN package_name SET NOT NULL,
      ALTER COLUMN artifact_sha256 SET NOT NULL;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_analysis_jobs_tenant_trace
  ON analysis_jobs (tenant_id, trace_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_analysis_jobs_tenant_digest
  ON analysis_jobs (tenant_id, artifact_sha256);

CREATE TABLE IF NOT EXISTS package_signal_observations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  ecosystem package_ecosystem NOT NULL,
  namespace text,
  package_name text NOT NULL,
  package_version text,
  artifact_sha256 text CHECK (artifact_sha256 ~ '^[a-f0-9]{64}$'),
  signal text NOT NULL CHECK (signal IN (
    'minimum-release-age-violation',
    'install-script-detected',
    'dependency-confusion-risk',
    'typosquat-risk',
    'artifact-digest-reputation-risk',
    'github-to-registry-publish-gap-risk',
    'trusted-publisher-identity-mismatch',
    'maintainer-account-age-risk',
    'recent-maintainer-change-risk',
    'new-maintainer-ratio-risk',
    'known-malicious'
  )),
  severity text NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  observed_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz
);

CREATE INDEX IF NOT EXISTS idx_package_signal_observations_tenant_package
  ON package_signal_observations (tenant_id, ecosystem, package_name, package_version, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_package_signal_observations_tenant_digest
  ON package_signal_observations (tenant_id, artifact_sha256, observed_at DESC)
  WHERE artifact_sha256 IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_analysis_jobs_registry_state
  ON analysis_jobs (registry_config_id, state, updated_at DESC);

CREATE TABLE IF NOT EXISTS analysis_summaries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_job_id uuid NOT NULL REFERENCES analysis_jobs(id) ON DELETE CASCADE,
  artifact_id uuid NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
  recommended_action policy_decision NOT NULL,
  confidence text NOT NULL,
  requires_hitl boolean NOT NULL DEFAULT false,
  summary jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (analysis_job_id)
);

CREATE INDEX IF NOT EXISTS idx_analysis_summaries_artifact_created
  ON analysis_summaries (artifact_id, created_at DESC);

ALTER TABLE static_analysis_reports
  ADD COLUMN IF NOT EXISTS policy_version_id uuid REFERENCES policy_versions(id),
  ADD COLUMN IF NOT EXISTS report_storage_uri text,
  ADD COLUMN IF NOT EXISTS report_storage_sha256 text CHECK (
    report_storage_sha256 IS NULL
    OR report_storage_sha256 ~ '^[a-f0-9]{64}$'
  ),
  ADD COLUMN IF NOT EXISTS report_storage_size_bytes bigint CHECK (
    report_storage_size_bytes IS NULL
    OR report_storage_size_bytes >= 0
  );

UPDATE static_analysis_reports AS reports
SET policy_version_id = jobs.policy_version_id
FROM analysis_jobs AS jobs
WHERE reports.analysis_job_id = jobs.id
  AND reports.policy_version_id IS NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'static_analysis_reports_external_storage_fields_check'
  ) THEN
    ALTER TABLE static_analysis_reports
      ADD CONSTRAINT static_analysis_reports_external_storage_fields_check CHECK (
        (
          report_storage_uri IS NULL
          AND report_storage_sha256 IS NULL
          AND report_storage_size_bytes IS NULL
        )
        OR (
          report_storage_uri IS NOT NULL
          AND report_storage_sha256 IS NOT NULL
          AND report_storage_size_bytes IS NOT NULL
        )
      );
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM analysis_jobs jobs
    JOIN static_analysis_reports reports ON reports.analysis_job_id = jobs.id
    WHERE reports.policy_version_id IS NULL
  ) THEN
    ALTER TABLE static_analysis_reports
      ALTER COLUMN policy_version_id SET NOT NULL;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_static_analysis_reports_policy_version_created
  ON static_analysis_reports (policy_version_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_static_analysis_reports_external_storage_digest
  ON static_analysis_reports (report_storage_sha256)
  WHERE report_storage_sha256 IS NOT NULL;