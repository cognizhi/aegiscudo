-- GitHub Actions workflow integrity scan results
-- Populated when a CLI consumer calls POST /v1/cli/github-actions/enrich
-- so the Command Center can display workflow integrity scan history.

CREATE TABLE github_actions_scan_results (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    policy_profile_id UUID        NOT NULL,
    owner             TEXT        NOT NULL,
    repo              TEXT        NOT NULL,
    ref               TEXT        NOT NULL,
    decision          TEXT        NOT NULL,
    rationale         TEXT[]      NOT NULL DEFAULT '{}',
    trace_id          TEXT        NOT NULL,
    fallback_ref      TEXT,
    scanned_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_github_actions_scan_results_tenant
    ON github_actions_scan_results (tenant_id, scanned_at DESC);
