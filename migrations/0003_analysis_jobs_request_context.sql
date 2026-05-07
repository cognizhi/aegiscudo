ALTER TABLE analysis_jobs
  ADD COLUMN ecosystem package_ecosystem,
  ADD COLUMN namespace text,
  ADD COLUMN package_name text,
  ADD COLUMN package_version text,
  ADD COLUMN artifact_sha256 text CHECK (artifact_sha256 ~ '^[a-f0-9]{64}$'),
  ALTER COLUMN artifact_id DROP NOT NULL;

UPDATE analysis_jobs AS jobs
SET ecosystem = artifacts.ecosystem,
    namespace = artifacts.namespace,
    package_name = artifacts.package_name,
    package_version = artifacts.package_version,
    artifact_sha256 = artifacts.sha256
FROM artifacts
WHERE jobs.artifact_id = artifacts.id;

ALTER TABLE analysis_jobs
  ALTER COLUMN ecosystem SET NOT NULL,
  ALTER COLUMN package_name SET NOT NULL,
  ALTER COLUMN artifact_sha256 SET NOT NULL;

CREATE INDEX idx_analysis_jobs_tenant_trace ON analysis_jobs (tenant_id, trace_id, updated_at DESC);
CREATE INDEX idx_analysis_jobs_tenant_digest ON analysis_jobs (tenant_id, artifact_sha256);