CREATE TABLE cross_ecosystem_ioc_records (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  snapshot_id uuid NOT NULL REFERENCES feed_snapshots(id) ON DELETE CASCADE,
  ecosystem text NOT NULL,
  namespace text,
  package_name text NOT NULL,
  package_version text,
  indicator_type text NOT NULL CHECK (indicator_type IN (
    'maintainer-identity',
    'domain',
    'ip',
    'url',
    'package-name',
    'behavioral-fingerprint'
  )),
  indicator_value text NOT NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_cross_ecosystem_ioc_records_snapshot
  ON cross_ecosystem_ioc_records (snapshot_id, created_at DESC);

CREATE INDEX idx_cross_ecosystem_ioc_records_lookup
  ON cross_ecosystem_ioc_records (ecosystem, namespace, package_name, package_version);

CREATE INDEX idx_cross_ecosystem_ioc_records_indicator
  ON cross_ecosystem_ioc_records (indicator_type, indicator_value);