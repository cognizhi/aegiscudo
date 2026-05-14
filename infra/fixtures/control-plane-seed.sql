BEGIN;

INSERT INTO tenants (id, name)
VALUES ('018f4a6f-55d0-7000-8000-000000000001', 'local-fixture-tenant')
ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name;

INSERT INTO policy_profiles (id, tenant_id, name, mode)
VALUES (
  '018f4a6f-55d0-7000-8000-000000000101',
  '018f4a6f-55d0-7000-8000-000000000001',
  'local-enforce-default',
  'enforce'
)
ON CONFLICT (tenant_id, name) DO UPDATE SET mode = EXCLUDED.mode;

INSERT INTO users (id, tenant_id, email, display_name)
VALUES (
  '018f4a6f-55d0-7000-8000-000000000011',
  '018f4a6f-55d0-7000-8000-000000000001',
  'local-admin@aegiscudo.invalid',
  'Local Admin'
)
ON CONFLICT (tenant_id, email) DO UPDATE SET display_name = EXCLUDED.display_name;

-- Additional mock-auth personas for local dev (ADR 0005).
INSERT INTO users (id, tenant_id, email, display_name)
VALUES (
  '018f4a6f-55d0-7000-8000-000000000021',
  '018f4a6f-55d0-7000-8000-000000000001',
  'dev@aegiscudo.invalid',
  'Dev User'
)
ON CONFLICT (tenant_id, email) DO UPDATE SET display_name = EXCLUDED.display_name;

INSERT INTO users (id, tenant_id, email, display_name)
VALUES (
  '018f4a6f-55d0-7000-8000-000000000022',
  '018f4a6f-55d0-7000-8000-000000000001',
  'security@aegiscudo.invalid',
  'Security Specialist'
)
ON CONFLICT (tenant_id, email) DO UPDATE SET display_name = EXCLUDED.display_name;

INSERT INTO users (id, tenant_id, email, display_name)
VALUES (
  '018f4a6f-55d0-7000-8000-000000000023',
  '018f4a6f-55d0-7000-8000-000000000001',
  'ciso@aegiscudo.invalid',
  'CISO Auditor'
)
ON CONFLICT (tenant_id, email) DO UPDATE SET display_name = EXCLUDED.display_name;

INSERT INTO roles (id, tenant_id, name)
VALUES (
  '018f4a6f-55d0-7000-8000-000000000012',
  '018f4a6f-55d0-7000-8000-000000000001',
  'admin'
)
ON CONFLICT (tenant_id, name) DO UPDATE SET name = EXCLUDED.name;

INSERT INTO user_roles (user_id, role_id)
VALUES (
  '018f4a6f-55d0-7000-8000-000000000011',
  '018f4a6f-55d0-7000-8000-000000000012'
)
ON CONFLICT DO NOTHING;

INSERT INTO roles (id, tenant_id, name)
VALUES
(
  '018f4a6f-55d0-7000-8000-000000000013',
  '018f4a6f-55d0-7000-8000-000000000001',
  'developer'
),
(
  '018f4a6f-55d0-7000-8000-000000000014',
  '018f4a6f-55d0-7000-8000-000000000001',
  'security-specialist'
),
(
  '018f4a6f-55d0-7000-8000-000000000015',
  '018f4a6f-55d0-7000-8000-000000000001',
  'auditor'
)
ON CONFLICT (tenant_id, name) DO UPDATE SET name = EXCLUDED.name;

INSERT INTO user_roles (user_id, role_id)
VALUES
(
  '018f4a6f-55d0-7000-8000-000000000021',
  '018f4a6f-55d0-7000-8000-000000000013'
),
(
  '018f4a6f-55d0-7000-8000-000000000022',
  '018f4a6f-55d0-7000-8000-000000000014'
),
(
  '018f4a6f-55d0-7000-8000-000000000023',
  '018f4a6f-55d0-7000-8000-000000000015'
)
ON CONFLICT DO NOTHING;

INSERT INTO overrides (
  id,
  tenant_id,
  scope,
  reason,
  requested_by,
  approved_by,
  status,
  expires_at,
  created_at
)
VALUES
(
  '018f4a6f-55d0-7000-8000-000000000021',
  '018f4a6f-55d0-7000-8000-000000000001',
  '{
    "ecosystem": "npm",
    "name": "fresh-postinstall",
    "version": "0.1.0",
    "kind": "metadata",
    "effect": "allow"
  }'::jsonb,
  'Temporary analyst review bypass',
  '018f4a6f-55d0-7000-8000-000000000011',
  NULL,
  'pending',
  now() + interval '12 hours',
  '2026-05-05T10:20:00Z'
),
(
  '018f4a6f-55d0-7000-8000-000000000022',
  '018f4a6f-55d0-7000-8000-000000000001',
  '{
    "ecosystem": "pypi",
    "name": "requestz",
    "version": "99.0.0",
    "kind": "artifact",
    "effect": "emergency-bypass",
    "digest": "2222222222222222222222222222222222222222222222222222222222222222"
  }'::jsonb,
  'Emergency unblock for incident triage',
  '018f4a6f-55d0-7000-8000-000000000011',
  '018f4a6f-55d0-7000-8000-000000000011',
  'approved',
  '2026-12-11T10:00:00Z',
  '2026-05-05T10:18:00Z'
),
(
  '018f4a6f-55d0-7000-8000-000000000023',
  '018f4a6f-55d0-7000-8000-000000000001',
  '{
    "ecosystem": "npm",
    "name": "left-pad",
    "version": "1.3.0",
    "kind": "metadata",
    "effect": "allow"
  }'::jsonb,
  'Request lacked incident justification',
  '018f4a6f-55d0-7000-8000-000000000011',
  '018f4a6f-55d0-7000-8000-000000000011',
  'denied',
  '2026-12-12T10:00:00Z',
  '2026-05-05T10:16:00Z'
)
ON CONFLICT (id) DO UPDATE
SET scope = EXCLUDED.scope,
    reason = EXCLUDED.reason,
    requested_by = EXCLUDED.requested_by,
    approved_by = EXCLUDED.approved_by,
    status = EXCLUDED.status,
    expires_at = EXCLUDED.expires_at,
    created_at = EXCLUDED.created_at;

INSERT INTO policy_versions (
  id,
  tenant_id,
  policy_profile_id,
  version,
  immutable_rule_hash,
  document
)
VALUES (
  '018f4a6f-55d0-7000-8000-000000000201',
  '018f4a6f-55d0-7000-8000-000000000001',
  '018f4a6f-55d0-7000-8000-000000000101',
  'local-2026.05.07',
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  '{
    "known_vulnerability_threshold": {
      "severity_floor": "high",
      "kev_override": true,
      "epss_probability_floor": 0.7
    },
    "rules": [
      {
        "signal": "vulnerable_above_threshold",
        "action": "warn",
        "enabled": true
      }
    ]
  }'::jsonb
)
ON CONFLICT (policy_profile_id, version) DO UPDATE
SET immutable_rule_hash = EXCLUDED.immutable_rule_hash,
    document = EXCLUDED.document,
    effective_at = now();

INSERT INTO registry_configs (
  id,
  tenant_id,
  name,
  description,
  adapter,
  upstream_url,
  mount_path,
  auth_type,
  mode,
  policy_profile_id,
  cache_ttl_seconds,
  verify_upstream_tls,
  enabled
)
VALUES
(
  '018f4a6f-55d0-7000-8000-000000000301',
  '018f4a6f-55d0-7000-8000-000000000001',
  'local npm fixture registry',
  'Local deterministic npm fixture upstream for Phase 1A integration tests',
  'npm',
  'http://npm-fixture-registry:8080',
  '/proxy/npm-fixtures',
  'none',
  'enforce',
  '018f4a6f-55d0-7000-8000-000000000101',
  300,
  true,
  true
),
(
  '018f4a6f-55d0-7000-8000-000000000302',
  '018f4a6f-55d0-7000-8000-000000000001',
  'local pypi fixture registry',
  'Local deterministic PyPI fixture upstream for Phase 1A integration tests',
  'pypi',
  'http://pypi-fixture-registry:8080',
  '/proxy/pypi-fixtures',
  'none',
  'enforce',
  '018f4a6f-55d0-7000-8000-000000000101',
  300,
  true,
  true
),
(
  '018f4a6f-55d0-7000-8000-000000000303',
  '018f4a6f-55d0-7000-8000-000000000001',
  'local cargo fixture registry',
  'Local deterministic Cargo sparse registry upstream for Phase 2 integration tests',
  'cargo',
  'http://cargo-fixture-registry:8080',
  '/proxy/cargo-fixtures',
  'none',
  'enforce',
  '018f4a6f-55d0-7000-8000-000000000101',
  300,
  true,
  true
),
(
  '018f4a6f-55d0-7000-8000-000000000304',
  '018f4a6f-55d0-7000-8000-000000000001',
  'local maven fixture registry',
  'Local deterministic Maven repository upstream for Phase 2 integration tests',
  'maven',
  'http://maven-fixture-registry:8080',
  '/proxy/maven-fixtures',
  'none',
  'enforce',
  '018f4a6f-55d0-7000-8000-000000000101',
  300,
  true,
  true
)
ON CONFLICT (tenant_id, mount_path) DO UPDATE
SET name = EXCLUDED.name,
    description = EXCLUDED.description,
    adapter = EXCLUDED.adapter,
    upstream_url = EXCLUDED.upstream_url,
    auth_type = EXCLUDED.auth_type,
    mode = EXCLUDED.mode,
    policy_profile_id = EXCLUDED.policy_profile_id,
    cache_ttl_seconds = EXCLUDED.cache_ttl_seconds,
    verify_upstream_tls = EXCLUDED.verify_upstream_tls,
    enabled = EXCLUDED.enabled,
    deleted_at = NULL,
    updated_at = now();

INSERT INTO integration_credentials (
  id,
  tenant_id,
  name,
  credential_type,
  source,
  configured
)
VALUES (
  '018f4a6f-55d0-7000-8000-000000000401',
  '018f4a6f-55d0-7000-8000-000000000001',
  'OPENROUTER_API_KEY',
  'ai-provider-api-key',
  'environment',
  true
)
ON CONFLICT (tenant_id, name) DO UPDATE
SET credential_type = EXCLUDED.credential_type,
    source = EXCLUDED.source,
    configured = EXCLUDED.configured,
    updated_at = now();

INSERT INTO ai_provider_configs (
  id,
  tenant_id,
  display_name,
  provider_type,
  base_url,
  model_id,
  credential_ref,
  is_local,
  active
)
VALUES (
  '018f4a6f-55d0-7000-8000-000000000402',
  '018f4a6f-55d0-7000-8000-000000000001',
  'local-openrouter',
  'openrouter',
  'https://openrouter.ai/api/v1',
  'qwen/qwen3.6-plus',
  '018f4a6f-55d0-7000-8000-000000000401',
  false,
  true
)
ON CONFLICT (id) DO UPDATE
SET display_name = EXCLUDED.display_name,
    provider_type = EXCLUDED.provider_type,
    base_url = EXCLUDED.base_url,
    model_id = EXCLUDED.model_id,
    credential_ref = EXCLUDED.credential_ref,
    is_local = EXCLUDED.is_local,
    active = EXCLUDED.active,
    updated_at = now();

INSERT INTO feed_snapshots (tenant_id, feed_name, state, normalized_record_count, snapshot_digest, last_success_at)
VALUES
('018f4a6f-55d0-7000-8000-000000000001', 'osv', 'fresh', 0, 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', now()),
('018f4a6f-55d0-7000-8000-000000000001', 'ghsa', 'fresh', 0, 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', now()),
('018f4a6f-55d0-7000-8000-000000000001', 'openssf-malicious-packages', 'fresh', 0, 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', now()),
('018f4a6f-55d0-7000-8000-000000000001', 'cisa-kev', 'fresh', 0, 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', now()),
('018f4a6f-55d0-7000-8000-000000000001', 'first-epss', 'fresh', 0, 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', now())
ON CONFLICT DO NOTHING;

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
VALUES
(
  '018f4a6f-55d0-7000-8000-000000000601',
  '018f4a6f-55d0-7000-8000-000000000001',
  'npm',
  NULL,
  'fresh-postinstall',
  '0.1.0',
  '1111111111111111111111111111111111111111111111111111111111111111',
  16384,
  's3://aegiscudo-artifacts-local/fixtures/npm/fresh-postinstall-0.1.0.tgz',
  '2026-05-05T10:00:00Z'
),
(
  '018f4a6f-55d0-7000-8000-000000000602',
  '018f4a6f-55d0-7000-8000-000000000001',
  'pypi',
  NULL,
  'requestz',
  '99.0.0',
  '2222222222222222222222222222222222222222222222222222222222222222',
  24576,
  's3://aegiscudo-artifacts-local/fixtures/pypi/requestz-99.0.0.whl',
  '2026-05-05T10:10:00Z'
)
ON CONFLICT (id) DO UPDATE
SET sha256 = EXCLUDED.sha256,
    size_bytes = EXCLUDED.size_bytes,
    storage_uri = EXCLUDED.storage_uri,
    created_at = EXCLUDED.created_at;

INSERT INTO package_requests (
  id,
  tenant_id,
  registry_config_id,
  client_type,
  ecosystem,
  namespace,
  package_name,
  package_version,
  trace_id,
  requested_at
)
VALUES
(
  '018f4a6f-55d0-7000-8000-000000000501',
  '018f4a6f-55d0-7000-8000-000000000001',
  '018f4a6f-55d0-7000-8000-000000000301',
  'npm-cli',
  'npm',
  NULL,
  'fresh-postinstall',
  '0.1.0',
  'trace-quarantine-002',
  '2026-05-05T10:00:00Z'
),
(
  '018f4a6f-55d0-7000-8000-000000000502',
  '018f4a6f-55d0-7000-8000-000000000001',
  '018f4a6f-55d0-7000-8000-000000000302',
  'pip',
  'pypi',
  NULL,
  'requestz',
  '99.0.0',
  'trace-block-003',
  '2026-05-05T10:10:00Z'
)
ON CONFLICT (id) DO UPDATE
SET client_type = EXCLUDED.client_type,
    package_version = EXCLUDED.package_version,
    trace_id = EXCLUDED.trace_id,
    requested_at = EXCLUDED.requested_at;

INSERT INTO policy_decisions (
  id,
  tenant_id,
  package_request_id,
  artifact_id,
  policy_version_id,
  decision,
  feed_state,
  feed_snapshot_age_seconds,
  rationale,
  trace_id,
  decided_at
)
VALUES
(
  '018f4a6f-55d0-7000-8000-000000000701',
  '018f4a6f-55d0-7000-8000-000000000001',
  '018f4a6f-55d0-7000-8000-000000000501',
  '018f4a6f-55d0-7000-8000-000000000601',
  '018f4a6f-55d0-7000-8000-000000000201',
  'QUARANTINE_PENDING_ANALYSIS',
  'fresh',
  120,
  '["Lifecycle script detected", "Package is younger than tenant minimum age"]'::jsonb,
  'trace-quarantine-002',
  '2026-05-05T10:01:00Z'
),
(
  '018f4a6f-55d0-7000-8000-000000000702',
  '018f4a6f-55d0-7000-8000-000000000001',
  '018f4a6f-55d0-7000-8000-000000000502',
  '018f4a6f-55d0-7000-8000-000000000602',
  '018f4a6f-55d0-7000-8000-000000000201',
  'BLOCK_POLICY_VIOLATION',
  'fresh',
  95,
  '["Typosquatting similarity triggered", "Sandbox observed outbound network attempt"]'::jsonb,
  'trace-block-003',
  '2026-05-05T10:11:00Z'
)
ON CONFLICT (id) DO UPDATE
SET decision = EXCLUDED.decision,
    rationale = EXCLUDED.rationale,
    decided_at = EXCLUDED.decided_at;

INSERT INTO analysis_jobs (
  id,
  tenant_id,
  artifact_id,
  policy_version_id,
  state,
  retry_count,
  trace_id,
  created_at,
  updated_at,
  ecosystem,
  namespace,
  package_name,
  package_version,
  artifact_sha256
)
VALUES
(
  '018f4a6f-55d0-7000-8000-000000000801',
  '018f4a6f-55d0-7000-8000-000000000001',
  '018f4a6f-55d0-7000-8000-000000000601',
  '018f4a6f-55d0-7000-8000-000000000201',
  'completed',
  0,
  'trace-quarantine-002',
  '2026-05-05T10:00:30Z',
  '2026-05-05T10:03:00Z',
  'npm',
  NULL,
  'fresh-postinstall',
  '0.1.0',
  '1111111111111111111111111111111111111111111111111111111111111111'
),
(
  '018f4a6f-55d0-7000-8000-000000000802',
  '018f4a6f-55d0-7000-8000-000000000001',
  '018f4a6f-55d0-7000-8000-000000000602',
  '018f4a6f-55d0-7000-8000-000000000201',
  'completed',
  0,
  'trace-block-003',
  '2026-05-05T10:10:30Z',
  '2026-05-05T10:13:00Z',
  'pypi',
  NULL,
  'requestz',
  '99.0.0',
  '2222222222222222222222222222222222222222222222222222222222222222'
)
ON CONFLICT (id) DO UPDATE
SET state = EXCLUDED.state,
    updated_at = EXCLUDED.updated_at,
    package_version = EXCLUDED.package_version,
    artifact_sha256 = EXCLUDED.artifact_sha256;

INSERT INTO static_analysis_reports (
  id,
  analysis_job_id,
  artifact_id,
  report,
  policy_version_id,
  created_at
)
VALUES
(
  '018f4a6f-55d0-7000-8000-000000000901',
  '018f4a6f-55d0-7000-8000-000000000801',
  '018f4a6f-55d0-7000-8000-000000000601',
  '{
    "artifact_digest": "1111111111111111111111111111111111111111111111111111111111111111",
    "analyzer_version": "fixture-static-1.0.0",
    "rule_set_version": "fixture-rules-2026.05.05",
    "indicators": [
      {
        "indicator_type": "lifecycle-script",
        "severity": "high",
        "file_path": "package.json",
        "start_line": 12,
        "end_line": 18,
        "redacted": false,
        "summary": "postinstall script invokes remote bootstrap"
      },
      {
        "indicator_type": "young-release-age",
        "severity": "medium",
        "file_path": "package.json",
        "start_line": 1,
        "end_line": 20,
        "redacted": false,
        "summary": "published within tenant minimum age window"
      }
    ]
  }'::jsonb,
  '018f4a6f-55d0-7000-8000-000000000201',
  '2026-05-05T10:01:30Z'
),
(
  '018f4a6f-55d0-7000-8000-000000000902',
  '018f4a6f-55d0-7000-8000-000000000802',
  '018f4a6f-55d0-7000-8000-000000000602',
  '{
    "artifact_digest": "2222222222222222222222222222222222222222222222222222222222222222",
    "analyzer_version": "fixture-static-1.0.0",
    "rule_set_version": "fixture-rules-2026.05.05",
    "indicators": [
      {
        "indicator_type": "typosquat-distance",
        "severity": "high",
        "file_path": "METADATA",
        "start_line": 2,
        "end_line": 4,
        "redacted": false,
        "summary": "package name closely matches requests"
      }
    ]
  }'::jsonb,
  '018f4a6f-55d0-7000-8000-000000000201',
  '2026-05-05T10:11:30Z'
)
ON CONFLICT (id) DO UPDATE
SET report = EXCLUDED.report,
    policy_version_id = EXCLUDED.policy_version_id,
    created_at = EXCLUDED.created_at;

INSERT INTO sandbox_runs (
  id,
  analysis_job_id,
  artifact_id,
  profile,
  state,
  telemetry,
  started_at,
  completed_at
)
VALUES (
  '018f4a6f-55d0-7000-8000-000000001001',
  '018f4a6f-55d0-7000-8000-000000000802',
  '018f4a6f-55d0-7000-8000-000000000602',
  'default',
  'completed',
  '{
    "phases": [
      {
        "name": "install",
        "events": [
          {
            "type": "process-spawn",
            "severity": "medium",
            "summary": "installer spawned helper shell"
          }
        ]
      },
      {
        "name": "runtime",
        "events": [
          {
            "type": "outbound-network-attempt",
            "severity": "high",
            "summary": "connection attempt to suspicious host"
          },
          {
            "type": "canary-secret-access",
            "severity": "critical",
            "summary": "sandbox canary credential was touched"
          }
        ]
      }
    ]
  }'::jsonb,
  '2026-05-05T10:11:45Z',
  '2026-05-05T10:12:40Z'
)
ON CONFLICT (id) DO UPDATE
SET state = EXCLUDED.state,
    telemetry = EXCLUDED.telemetry,
    completed_at = EXCLUDED.completed_at;

INSERT INTO ai_explanations (
  id,
  analysis_job_id,
  provider_config_id,
  langfuse_trace_id,
  prompt_template_version,
  redaction_complete,
  schema_valid,
  explanation,
  created_at
)
VALUES
(
  '018f4a6f-55d0-7000-8000-000000001101',
  '018f4a6f-55d0-7000-8000-000000000801',
  '018f4a6f-55d0-7000-8000-000000000402',
  'langfuse-trace-quarantine-002',
  'analysis-preview-v1',
  true,
  true,
  '{
    "observed_behavior": [
      "Detected postinstall execution path during package inspection."
    ],
    "inference": [
      "The package should remain quarantined pending manual review."
    ],
    "limitations": [
      "Sandbox evidence is missing for this artifact."
    ],
    "langfuse_trace_id": "langfuse-trace-quarantine-002",
    "advisory_only": true
  }'::jsonb,
  '2026-05-05T10:02:10Z'
),
(
  '018f4a6f-55d0-7000-8000-000000001102',
  '018f4a6f-55d0-7000-8000-000000000802',
  '018f4a6f-55d0-7000-8000-000000000402',
  'langfuse-trace-block-003',
  'analysis-preview-v1',
  true,
  true,
  '{
    "observed_behavior": [
      "Outbound network activity was observed in the runtime sandbox.",
      "Canary credential access was attempted."
    ],
    "inference": [
      "The package exhibits policy-violating execution behavior and should be blocked."
    ],
    "limitations": [],
    "langfuse_trace_id": "langfuse-trace-block-003",
    "advisory_only": true
  }'::jsonb,
  '2026-05-05T10:12:20Z'
)
ON CONFLICT (id) DO UPDATE
SET langfuse_trace_id = EXCLUDED.langfuse_trace_id,
    prompt_template_version = EXCLUDED.prompt_template_version,
    explanation = EXCLUDED.explanation,
    schema_valid = EXCLUDED.schema_valid,
    created_at = EXCLUDED.created_at;

INSERT INTO llm_usage_events (
  id,
  tenant_id,
  analysis_job_id,
  artifact_id,
  ai_explanation_id,
  provider_config_id,
  trace_id,
  provider_display_name,
  provider_type,
  model_id,
  langfuse_trace_id,
  prompt_template_version,
  prompt_tokens,
  completion_tokens,
  total_tokens,
  estimated_cost,
  latency_ms,
  schema_valid,
  redaction_complete,
  evidence_hash,
  output_hash,
  created_at
)
VALUES
(
  '018f4a6f-55d0-7000-8000-000000001151',
  '018f4a6f-55d0-7000-8000-000000000001',
  '018f4a6f-55d0-7000-8000-000000000801',
  '018f4a6f-55d0-7000-8000-000000000601',
  '018f4a6f-55d0-7000-8000-000000001101',
  '018f4a6f-55d0-7000-8000-000000000402',
  'trace-quarantine-002',
  'local-openrouter',
  'openrouter',
  'qwen/qwen3.6-plus',
  'langfuse-trace-quarantine-002',
  'analysis-preview-v1',
  880,
  220,
  1100,
  0.0521,
  742,
  true,
  true,
  'seed-evidence-hash-quarantine-002',
  'seed-output-hash-quarantine-002',
  '2026-05-05T10:02:10Z'
),
(
  '018f4a6f-55d0-7000-8000-000000001152',
  '018f4a6f-55d0-7000-8000-000000000001',
  '018f4a6f-55d0-7000-8000-000000000802',
  '018f4a6f-55d0-7000-8000-000000000602',
  '018f4a6f-55d0-7000-8000-000000001102',
  '018f4a6f-55d0-7000-8000-000000000402',
  'trace-block-003',
  'local-openrouter',
  'openrouter',
  'qwen/qwen3.6-plus',
  'langfuse-trace-block-003',
  'analysis-preview-v1',
  1160,
  340,
  1500,
  0.0734,
  1284,
  true,
  true,
  'seed-evidence-hash-block-003',
  'seed-output-hash-block-003',
  '2026-05-05T10:12:20Z'
)
ON CONFLICT (id) DO UPDATE
SET trace_id = EXCLUDED.trace_id,
    provider_display_name = EXCLUDED.provider_display_name,
    provider_type = EXCLUDED.provider_type,
    model_id = EXCLUDED.model_id,
    langfuse_trace_id = EXCLUDED.langfuse_trace_id,
    prompt_template_version = EXCLUDED.prompt_template_version,
    prompt_tokens = EXCLUDED.prompt_tokens,
    completion_tokens = EXCLUDED.completion_tokens,
    total_tokens = EXCLUDED.total_tokens,
    estimated_cost = EXCLUDED.estimated_cost,
    latency_ms = EXCLUDED.latency_ms,
    schema_valid = EXCLUDED.schema_valid,
    redaction_complete = EXCLUDED.redaction_complete,
    evidence_hash = EXCLUDED.evidence_hash,
    output_hash = EXCLUDED.output_hash,
    created_at = EXCLUDED.created_at;

INSERT INTO analysis_summaries (
  id,
  analysis_job_id,
  artifact_id,
  recommended_action,
  confidence,
  requires_hitl,
  summary,
  created_at
)
VALUES
(
  '018f4a6f-55d0-7000-8000-000000001201',
  '018f4a6f-55d0-7000-8000-000000000801',
  '018f4a6f-55d0-7000-8000-000000000601',
  'QUARANTINE_PENDING_ANALYSIS',
  'medium',
  true,
  '{
    "recommended_action": "QUARANTINE_PENDING_ANALYSIS",
    "confidence": "medium",
    "requires_hitl": true,
    "evidence": {
      "static_indicator_count": 2,
      "sandbox_event_count": 0,
      "vulnerability_count": 0,
      "malware_match_count": 0
    },
    "limitations": [
      "Sandbox evidence is missing for this artifact."
    ],
    "ai_observed_behavior": [
      "Detected postinstall execution path during package inspection."
    ],
    "ai_inference": [
      "The package should remain quarantined pending manual review."
    ]
  }'::jsonb,
  '2026-05-05T10:02:30Z'
),
(
  '018f4a6f-55d0-7000-8000-000000001202',
  '018f4a6f-55d0-7000-8000-000000000802',
  '018f4a6f-55d0-7000-8000-000000000602',
  'BLOCK_POLICY_VIOLATION',
  'high',
  false,
  '{
    "recommended_action": "BLOCK_POLICY_VIOLATION",
    "confidence": "high",
    "requires_hitl": false,
    "evidence": {
      "static_indicator_count": 1,
      "sandbox_event_count": 3,
      "vulnerability_count": 0,
      "malware_match_count": 0
    },
    "limitations": [],
    "ai_observed_behavior": [
      "Outbound network activity was observed in the runtime sandbox.",
      "Canary credential access was attempted."
    ],
    "ai_inference": [
      "The package exhibits policy-violating execution behavior and should be blocked."
    ]
  }'::jsonb,
  '2026-05-05T10:12:30Z'
)
ON CONFLICT (id) DO UPDATE
SET recommended_action = EXCLUDED.recommended_action,
    confidence = EXCLUDED.confidence,
    requires_hitl = EXCLUDED.requires_hitl,
    summary = EXCLUDED.summary,
    created_at = EXCLUDED.created_at;

INSERT INTO audit_events (
  id,
  tenant_id,
  actor,
  action,
  resource,
  trace_id,
  metadata,
  occurred_at
)
VALUES
(
  '018f4a6f-55d0-7000-8000-000000001301',
  '018f4a6f-55d0-7000-8000-000000000001',
  'system/fixture-seed',
  'package-request.recorded',
  'package-request/018f4a6f-55d0-7000-8000-000000000501',
  'trace-quarantine-002',
  '{"ecosystem":"npm","package":"fresh-postinstall"}'::jsonb,
  '2026-05-05T10:00:00Z'
),
(
  '018f4a6f-55d0-7000-8000-000000001302',
  '018f4a6f-55d0-7000-8000-000000000001',
  'system/fixture-seed',
  'analysis.summary.completed',
  'analysis-job/018f4a6f-55d0-7000-8000-000000000801',
  'trace-quarantine-002',
  '{"recommended_action":"QUARANTINE_PENDING_ANALYSIS","requires_hitl":true}'::jsonb,
  '2026-05-05T10:02:30Z'
),
(
  '018f4a6f-55d0-7000-8000-000000001303',
  '018f4a6f-55d0-7000-8000-000000000001',
  'system/fixture-seed',
  'package-request.recorded',
  'package-request/018f4a6f-55d0-7000-8000-000000000502',
  'trace-block-003',
  '{"ecosystem":"pypi","package":"requestz"}'::jsonb,
  '2026-05-05T10:10:00Z'
),
(
  '018f4a6f-55d0-7000-8000-000000001304',
  '018f4a6f-55d0-7000-8000-000000000001',
  'system/fixture-seed',
  'analysis.summary.completed',
  'analysis-job/018f4a6f-55d0-7000-8000-000000000802',
  'trace-block-003',
  '{"recommended_action":"BLOCK_POLICY_VIOLATION","requires_hitl":false}'::jsonb,
  '2026-05-05T10:12:30Z'
)
ON CONFLICT (id) DO UPDATE
SET action = EXCLUDED.action,
    resource = EXCLUDED.resource,
    metadata = EXCLUDED.metadata,
    occurred_at = EXCLUDED.occurred_at;

COMMIT;