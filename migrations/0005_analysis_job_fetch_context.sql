ALTER TABLE analysis_jobs
  ADD COLUMN registry_config_id uuid REFERENCES registry_configs(id),
  ADD COLUMN source_url text;

UPDATE analysis_jobs AS jobs
SET registry_config_id = requests.registry_config_id
FROM package_requests AS requests
WHERE jobs.trace_id = requests.trace_id
  AND jobs.tenant_id = requests.tenant_id
  AND jobs.registry_config_id IS NULL;

CREATE INDEX idx_analysis_jobs_registry_state ON analysis_jobs (registry_config_id, state, updated_at DESC);
