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

INSERT INTO feed_snapshots (tenant_id, feed_name, state, normalized_record_count, snapshot_digest, last_success_at)
VALUES
('018f4a6f-55d0-7000-8000-000000000001', 'osv', 'fresh', 0, 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', now()),
('018f4a6f-55d0-7000-8000-000000000001', 'ghsa', 'fresh', 0, 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', now()),
('018f4a6f-55d0-7000-8000-000000000001', 'openssf-malicious-packages', 'fresh', 0, 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', now()),
('018f4a6f-55d0-7000-8000-000000000001', 'cisa-kev', 'fresh', 0, 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', now()),
('018f4a6f-55d0-7000-8000-000000000001', 'first-epss', 'fresh', 0, 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', now())
ON CONFLICT DO NOTHING;

COMMIT;