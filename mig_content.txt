CREATE TABLE deps_dev_packages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  snapshot_id uuid NOT NULL REFERENCES feed_snapshots(id) ON DELETE CASCADE,
  purl text NOT NULL,
  ecosystem text NOT NULL,
  namespace text,
  package_name text NOT NULL,
  package_version text,
  licenses jsonb NOT NULL DEFAULT '[]'::jsonb,
  dependency_count integer NOT NULL DEFAULT 0 CHECK (dependency_count >= 0),
  project_links jsonb NOT NULL DEFAULT '[]'::jsonb,
  raw_document jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (snapshot_id, purl)
);

CREATE INDEX idx_deps_dev_packages_snapshot
  ON deps_dev_packages (snapshot_id, created_at DESC);

CREATE INDEX idx_deps_dev_packages_lookup
  ON deps_dev_packages (ecosystem, package_name, package_version);

CREATE TABLE deps_dev_dependency_edges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  snapshot_id uuid NOT NULL REFERENCES feed_snapshots(id) ON DELETE CASCADE,
  package_purl text NOT NULL,
  dependency_purl text NOT NULL,
  relationship text NOT NULL DEFAULT 'depends-on',
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (snapshot_id, package_purl, dependency_purl, relationship)
);

CREATE INDEX idx_deps_dev_dependency_edges_snapshot
  ON deps_dev_dependency_edges (snapshot_id, created_at DESC);

CREATE INDEX idx_deps_dev_dependency_edges_package
  ON deps_dev_dependency_edges (package_purl, dependency_purl);

CREATE TABLE openssf_scorecard_results (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  snapshot_id uuid NOT NULL REFERENCES feed_snapshots(id) ON DELETE CASCADE,
  observed_on date,
  repo_name text NOT NULL,
  repo_commit text,
  scorecard_version text,
  scorecard_commit text,
  score double precision NOT NULL,
  raw_document jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (snapshot_id, repo_name)
);

CREATE INDEX idx_openssf_scorecard_results_snapshot
  ON openssf_scorecard_results (snapshot_id, created_at DESC);

CREATE INDEX idx_openssf_scorecard_results_repo
  ON openssf_scorecard_results (repo_name, observed_on DESC);

CREATE TABLE openssf_scorecard_checks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  result_id uuid NOT NULL REFERENCES openssf_scorecard_results(id) ON DELETE CASCADE,
  check_name text NOT NULL,
  score double precision NOT NULL,
  reason text,
  details jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (result_id, check_name)
);

CREATE INDEX idx_openssf_scorecard_checks_result
  ON openssf_scorecard_checks (result_id, created_at DESC);