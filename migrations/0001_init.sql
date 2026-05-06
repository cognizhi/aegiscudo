CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TYPE package_ecosystem AS ENUM ('npm', 'pypi', 'cargo', 'maven', 'docker-oci', 'generic-http');
CREATE TYPE registry_adapter AS ENUM ('npm', 'pypi', 'cargo', 'maven', 'docker-oci', 'generic-http');
CREATE TYPE enforcement_mode AS ENUM ('shadow', 'warn', 'enforce');
CREATE TYPE credential_auth_type AS ENUM ('none', 'basic', 'bearer', 'mtls');
CREATE TYPE feed_state AS ENUM ('fresh', 'stale', 'degraded', 'unavailable');
CREATE TYPE policy_decision AS ENUM ('ALLOW', 'ALLOW_WITH_WARNING', 'QUARANTINE_PENDING_ANALYSIS', 'BLOCK_KNOWN_MALICIOUS', 'BLOCK_POLICY_VIOLATION', 'REQUIRE_HITL_APPROVAL', 'FALLBACK_TO_APPROVED_CANDIDATE');
CREATE TYPE analysis_job_state AS ENUM ('queued', 'fetching', 'static-running', 'sandbox-pending', 'sandbox-running', 'ai-pending', 'finalizing', 'completed', 'failed', 'cancelled');

CREATE TABLE tenants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  email text NOT NULL,
  display_name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, email)
);

CREATE TABLE roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  name text NOT NULL,
  UNIQUE (tenant_id, name)
);

CREATE TABLE user_roles (
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, role_id)
);

CREATE TABLE policy_profiles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  name text NOT NULL,
  mode enforcement_mode NOT NULL DEFAULT 'enforce',
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, name)
);

CREATE TABLE policy_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  policy_profile_id uuid NOT NULL REFERENCES policy_profiles(id),
  version text NOT NULL,
  immutable_rule_hash text NOT NULL CHECK (immutable_rule_hash ~ '^[a-f0-9]{64}$'),
  document jsonb NOT NULL,
  effective_at timestamptz NOT NULL DEFAULT now(),
  created_by uuid REFERENCES users(id),
  UNIQUE (policy_profile_id, version)
);

CREATE TABLE integration_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  name text NOT NULL,
  credential_type text NOT NULL,
  source text NOT NULL CHECK (source IN ('environment', 'database-runtime-override')),
  encrypted_value_ciphertext bytea,
  encrypted_value_key_id text,
  configured boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, name)
);

CREATE TABLE registry_configs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  name text NOT NULL,
  description text NOT NULL DEFAULT '',
  adapter registry_adapter NOT NULL,
  upstream_url text NOT NULL CHECK (upstream_url ~ '^https?://'),
  mount_path text NOT NULL CHECK (mount_path ~ '^/[a-zA-Z0-9/_-]+$'),
  auth_type credential_auth_type NOT NULL DEFAULT 'none',
  credential_ref uuid REFERENCES integration_credentials(id),
  mode enforcement_mode NOT NULL DEFAULT 'enforce',
  policy_profile_id uuid NOT NULL REFERENCES policy_profiles(id),
  cache_ttl_seconds integer NOT NULL DEFAULT 300 CHECK (cache_ttl_seconds >= 0),
  verify_upstream_tls boolean NOT NULL DEFAULT true,
  enabled boolean NOT NULL DEFAULT true,
  deleted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, mount_path),
  CHECK ((auth_type = 'none' AND credential_ref IS NULL) OR (auth_type <> 'none' AND credential_ref IS NOT NULL))
);

CREATE TABLE package_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  registry_config_id uuid NOT NULL REFERENCES registry_configs(id),
  client_type text NOT NULL,
  ecosystem package_ecosystem NOT NULL,
  namespace text,
  package_name text NOT NULL,
  package_version text,
  trace_id text NOT NULL,
  requested_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE artifacts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  ecosystem package_ecosystem NOT NULL,
  namespace text,
  package_name text NOT NULL,
  package_version text,
  sha256 text NOT NULL CHECK (sha256 ~ '^[a-f0-9]{64}$'),
  size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
  storage_uri text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, sha256)
);

CREATE TABLE artifact_files (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  artifact_id uuid NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
  path text NOT NULL,
  sha256 text NOT NULL CHECK (sha256 ~ '^[a-f0-9]{64}$'),
  size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
  UNIQUE (artifact_id, path)
);

CREATE TABLE policy_decisions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  package_request_id uuid REFERENCES package_requests(id),
  artifact_id uuid REFERENCES artifacts(id),
  policy_version_id uuid NOT NULL REFERENCES policy_versions(id),
  decision policy_decision NOT NULL,
  feed_state feed_state NOT NULL,
  feed_snapshot_age_seconds integer NOT NULL DEFAULT 0 CHECK (feed_snapshot_age_seconds >= 0),
  rationale jsonb NOT NULL,
  trace_id text NOT NULL,
  decided_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE overrides (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  scope jsonb NOT NULL,
  reason text NOT NULL,
  requested_by uuid REFERENCES users(id),
  approved_by uuid REFERENCES users(id),
  status text NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'revoked')),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE analysis_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  artifact_id uuid NOT NULL REFERENCES artifacts(id),
  policy_version_id uuid NOT NULL REFERENCES policy_versions(id),
  state analysis_job_state NOT NULL DEFAULT 'queued',
  retry_count integer NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
  trace_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE static_analysis_reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_job_id uuid NOT NULL REFERENCES analysis_jobs(id) ON DELETE CASCADE,
  artifact_id uuid NOT NULL REFERENCES artifacts(id),
  report jsonb NOT NULL,
  embedding vector(1536),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sandbox_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_job_id uuid NOT NULL REFERENCES analysis_jobs(id) ON DELETE CASCADE,
  artifact_id uuid NOT NULL REFERENCES artifacts(id),
  profile text NOT NULL,
  state text NOT NULL,
  telemetry jsonb NOT NULL DEFAULT '{}'::jsonb,
  started_at timestamptz,
  completed_at timestamptz
);

CREATE TABLE artifact_attestations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  artifact_id uuid NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
  attestation_type text NOT NULL,
  predicate_type text NOT NULL,
  issuer text NOT NULL,
  subject_digest text NOT NULL CHECK (subject_digest ~ '^[a-f0-9]{64}$'),
  result text NOT NULL CHECK (result IN ('pass', 'fail', 'missing', 'unverifiable')),
  raw_document_digest text NOT NULL CHECK (raw_document_digest ~ '^[a-f0-9]{64}$'),
  verified_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE ai_provider_configs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  display_name text NOT NULL,
  provider_type text NOT NULL,
  base_url text,
  model_id text NOT NULL,
  credential_ref uuid REFERENCES integration_credentials(id),
  is_local boolean NOT NULL DEFAULT false,
  active boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE ai_explanations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_job_id uuid NOT NULL REFERENCES analysis_jobs(id) ON DELETE CASCADE,
  provider_config_id uuid REFERENCES ai_provider_configs(id),
  langfuse_trace_id text,
  prompt_template_version text NOT NULL,
  redaction_complete boolean NOT NULL,
  schema_valid boolean NOT NULL,
  explanation jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE vulnerability_matches (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  artifact_id uuid NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
  source text NOT NULL,
  advisory_id text NOT NULL,
  severity text,
  epss_probability numeric,
  cisa_kev boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE malware_matches (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  artifact_id uuid NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
  source text NOT NULL,
  indicator text NOT NULL,
  confidence text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE feed_snapshots (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid REFERENCES tenants(id),
  feed_name text NOT NULL,
  state feed_state NOT NULL,
  normalized_record_count bigint NOT NULL DEFAULT 0,
  snapshot_digest text NOT NULL CHECK (snapshot_digest ~ '^[a-f0-9]{64}$'),
  last_success_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE user_settings (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  theme text NOT NULL DEFAULT 'dark' CHECK (theme IN ('dark', 'light', 'dim')),
  density text NOT NULL DEFAULT 'default' CHECK (density IN ('compact', 'default', 'comfortable')),
  glow_intensity text NOT NULL DEFAULT 'normal' CHECK (glow_intensity IN ('off', 'subtle', 'normal', 'strong')),
  animation_speed text NOT NULL DEFAULT 'normal' CHECK (animation_speed IN ('reduced', 'normal', 'snappy')),
  sidebar_mode text NOT NULL DEFAULT 'expanded' CHECK (sidebar_mode IN ('expanded', 'collapsed', 'icon-only')),
  dashboard_layout jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  actor text NOT NULL,
  action text NOT NULL,
  resource text NOT NULL,
  trace_id text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_registry_configs_tenant_enabled ON registry_configs (tenant_id, enabled) WHERE deleted_at IS NULL;
CREATE INDEX idx_package_requests_tenant_time ON package_requests (tenant_id, requested_at DESC);
CREATE INDEX idx_policy_decisions_tenant_time ON policy_decisions (tenant_id, decided_at DESC);
CREATE INDEX idx_artifacts_tenant_package ON artifacts (tenant_id, ecosystem, package_name, package_version);
CREATE INDEX idx_analysis_jobs_state ON analysis_jobs (state, updated_at);
CREATE INDEX idx_audit_events_tenant_time ON audit_events (tenant_id, occurred_at DESC);
CREATE INDEX idx_feed_snapshots_feed_time ON feed_snapshots (feed_name, created_at DESC);