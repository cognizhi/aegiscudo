CREATE TABLE package_signal_observations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  ecosystem package_ecosystem NOT NULL,
  namespace text,
  package_name text NOT NULL,
  package_version text,
  artifact_sha256 text CHECK (artifact_sha256 ~ '^[a-f0-9]{64}$'),
  signal text NOT NULL CHECK (signal IN (
    'minimum-release-age-violation',
    'install-script-detected',
    'dependency-confusion-risk',
    'typosquat-risk',
    'artifact-digest-reputation-risk',
    'github-to-registry-publish-gap-risk',
    'trusted-publisher-identity-mismatch',
    'maintainer-account-age-risk',
    'recent-maintainer-change-risk',
    'new-maintainer-ratio-risk',
    'known-malicious'
  )),
  severity text NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  observed_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz
);

CREATE INDEX idx_package_signal_observations_tenant_package
  ON package_signal_observations (tenant_id, ecosystem, package_name, package_version, observed_at DESC);

CREATE INDEX idx_package_signal_observations_tenant_digest
  ON package_signal_observations (tenant_id, artifact_sha256, observed_at DESC)
  WHERE artifact_sha256 IS NOT NULL;