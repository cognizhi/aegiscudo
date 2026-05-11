ALTER TABLE static_analysis_reports
  ADD COLUMN policy_version_id uuid REFERENCES policy_versions(id);

UPDATE static_analysis_reports AS reports
SET policy_version_id = jobs.policy_version_id
FROM analysis_jobs AS jobs
WHERE reports.analysis_job_id = jobs.id
  AND reports.policy_version_id IS NULL;

ALTER TABLE static_analysis_reports
  ALTER COLUMN policy_version_id SET NOT NULL;

CREATE INDEX idx_static_analysis_reports_policy_version_created
  ON static_analysis_reports (policy_version_id, created_at DESC);