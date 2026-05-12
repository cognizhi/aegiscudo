CREATE TABLE sbom_documents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_job_id uuid REFERENCES analysis_jobs(id) ON DELETE SET NULL,
  tenant_id uuid REFERENCES tenants(id) ON DELETE SET NULL,
  source text NOT NULL,
  format text NOT NULL CHECK (format IN ('cyclonedx-1.7-json', 'cyclonedx-1.6-json', 'spdx-2.3-json')),
  storage_uri text NOT NULL,
  storage_sha256 text NOT NULL CHECK (storage_sha256 ~ '^[a-f0-9]{64}$'),
  storage_size_bytes bigint NOT NULL CHECK (storage_size_bytes >= 0),
  component_count integer NOT NULL CHECK (component_count >= 0),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_sbom_documents_tenant_created_at
  ON sbom_documents (tenant_id, created_at DESC)
  WHERE tenant_id IS NOT NULL;

CREATE INDEX idx_sbom_documents_analysis_job
  ON sbom_documents (analysis_job_id)
  WHERE analysis_job_id IS NOT NULL;
