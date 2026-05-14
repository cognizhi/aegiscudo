# Feed Harvester

Source PRD sections: 3.3, 3.4.1, 3.7.1, 4.6, 4.8.

Feed Harvester ingests external intelligence outside the request path.

Phase-gated feed scope is summarized centrally in the [Capability By Phase](../README.md#capability-by-phase) matrix.

## Responsibilities

- Ingest OSV, GHSA, GCVE, CISA KEV, FIRST EPSS, OpenSSF Malicious Packages, OpenSSF Package Analysis, deps.dev, and OpenSSF Scorecard data as phase scope allows.
- Normalize external records into internal threat-intel tables and snapshots.
- Persist the last successful snapshot for every feed.
- Expose feed state as `fresh`, `stale`, `degraded`, or `unavailable`.
- Use quota-aware pagination, conditional requests, exponential backoff with jitter, and per-feed circuit breakers.
- Alert when feed freshness exceeds policy thresholds.

## Boundaries

- Request-time policy must not call public feed APIs synchronously.
- Feed ingestion outages degrade freshness state but must not block deterministic cached decisions.

## Current Implementation State

The active implementation is a Rust service under `services/feed-harvester` with health, readiness, metrics, refresh, and status endpoints plus PostgreSQL-backed `feed_snapshots` persistence. Fixture-backed ingestion exists for OSV, GHSA, OpenSSF Malicious Packages, OpenSSF Package Analysis, CISA KEV, FIRST EPSS, deps.dev, and OpenSSF Scorecard. deps.dev and Scorecard also support env-configured live HTTP refresh (`FEED_HARVESTER_DEPS_DEV_URL`, `FEED_HARVESTER_OPENSSF_SCORECARD_URL`): a live fetch or payload-validation failure falls back to a valid local fixture snapshot as `degraded`, and the feed remains `unavailable` only when neither live nor fixture data is usable. For deps.dev, the configured metadata snapshot can now be enriched by fan-out requests against the canonical `GET /v3/systems/{system}/packages/{name}/versions/{version}:dependencies` endpoint, using `FEED_HARVESTER_DEPS_DEV_API_BASE_URL` to override the deps.dev API base when needed. The checked-in fixture includes matching graph coverage. Normalized records now persist for deps.dev packages and dependency edges (`deps_dev_packages`, `deps_dev_dependency_edges`), OpenSSF Scorecard repo-level results and per-check details (`openssf_scorecard_results`, `openssf_scorecard_checks`), and cross-ecosystem IOC observations (`cross_ecosystem_ioc_records`) extracted from OpenSSF Malicious Packages and OpenSSF Package Analysis. Triage Counter uses those normalized rows for Scorecard repo resolution, package-scoped transitive dependency signals across the full reachable graph of the latest package-or-edge snapshot, and latest usable IOC-snapshot correlation on package names, maintainer identities, domains, IPs, URLs, and behavioral fingerprints. Targeted freshness assertions now cover stale `deps.dev`, degraded `openssf-scorecard`, and degraded `openssf-package-analysis` snapshots in triage-counter. Circuit breakers, conditional requests, and end-to-end freshness alerting deployment remain follow-up work.