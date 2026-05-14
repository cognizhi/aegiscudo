CREATE TABLE analysis_sbom_fragments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_job_id uuid NOT NULL REFERENCES analysis_jobs(id) ON DELETE CASCADE,
  artifact_id uuid NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  source text NOT NULL,
  fragment jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (analysis_job_id, artifact_id)
);

CREATE INDEX idx_analysis_sbom_fragments_analysis_job
  ON analysis_sbom_fragments (analysis_job_id, created_at DESC);

CREATE INDEX idx_analysis_sbom_fragments_tenant_created
  ON analysis_sbom_fragments (tenant_id, created_at DESC);
