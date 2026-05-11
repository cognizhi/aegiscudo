CREATE TABLE llm_usage_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    analysis_job_id UUID NOT NULL REFERENCES analysis_jobs(id) ON DELETE CASCADE,
    artifact_id UUID NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    ai_explanation_id UUID NOT NULL REFERENCES ai_explanations(id) ON DELETE CASCADE,
    provider_config_id UUID NOT NULL REFERENCES ai_provider_configs(id),
    trace_id TEXT NOT NULL,
    provider_display_name TEXT NOT NULL,
    provider_type TEXT NOT NULL,
    model_id TEXT NOT NULL,
    langfuse_trace_id TEXT,
    prompt_template_version TEXT NOT NULL,
    prompt_tokens BIGINT,
    completion_tokens BIGINT,
    total_tokens BIGINT,
    estimated_cost DOUBLE PRECISION,
    latency_ms DOUBLE PRECISION,
    schema_valid BOOLEAN NOT NULL,
    redaction_complete BOOLEAN NOT NULL,
    evidence_hash TEXT,
    output_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_llm_usage_events_tenant_created_at
    ON llm_usage_events (tenant_id, created_at DESC);

CREATE INDEX idx_llm_usage_events_tenant_analysis_job
    ON llm_usage_events (tenant_id, analysis_job_id, created_at DESC);