# Feed Harvester Operations Guide

Feed Harvester ingests external intelligence asynchronously and persists normalized snapshots for request-time services to consume from local storage. It must never be placed in a request-time dependency path.

## Runtime Contract

Feed Harvester exposes:

- `GET /healthz`: service health.
- `GET /readyz`: readiness probe.
- `GET /metrics`: Prometheus metrics.
- `POST /v1/feeds/refresh`: refresh all configured feeds.
- `GET /v1/feeds/status`: latest snapshot state for each feed.

Current feed coverage includes OSV, GHSA, OpenSSF Malicious Packages, OpenSSF Package Analysis, CISA KEV, FIRST EPSS, deps.dev, and OpenSSF Scorecard.

## Configuration

The service requires PostgreSQL and a fixture directory mounted with feed payloads. Fixture-backed feeds remain available for deterministic local and CI validation.

Optional live-source variables:

- `FEED_HARVESTER_DEPS_DEV_URL`: metadata snapshot URL for deps.dev refresh.
- `FEED_HARVESTER_DEPS_DEV_API_BASE_URL`: deps.dev API base for dependency graph fan-out. Defaults to `https://api.deps.dev/v3`.
- `FEED_HARVESTER_OPENSSF_SCORECARD_URL`: OpenSSF Scorecard snapshot URL.

When a supported live source fails but the local fixture is valid, the feed records a `degraded` snapshot instead of failing closed. A feed is `unavailable` only when neither live data nor fixture data can be used.

## Refresh Operations

Run a manual refresh with:

```bash
curl -fsS -X POST http://localhost:8080/v1/feeds/refresh | jq
```

Check status with:

```bash
curl -fsS http://localhost:8080/v1/feeds/status | jq
```

Operators should verify these fields per feed:

- `state`: expected values are `fresh`, `stale`, `degraded`, or `unavailable`.
- `normalized_record_count`: non-zero for active feeds with usable payloads.
- `snapshot_digest`: stable digest for repeated identical fixture refreshes.
- `last_success_at`: present for fresh snapshots.

## Metrics

Prometheus metrics exposed by `/metrics`:

- `aegiscudo_feed_refresh_total{service,outcome}`: refresh attempts by outcome.
- `aegiscudo_feed_refresh_duration_ms{service,outcome}`: duration of the latest refresh attempt.
- `aegiscudo_feed_last_success_timestamp_seconds{service,feed_name}`: last successful feed snapshot timestamp.
- `aegiscudo_feed_snapshot_record_count{service,feed_name,state}`: normalized records in the latest snapshot.

Alerting should treat feeds older than 24 hours as stale for production policy. The repository currently exposes the metrics needed for that alert; production alert rules and notification routing depend on the monitoring stack deployment.

## Incident Handling

If a feed becomes `degraded`, confirm whether the live source is unavailable or returning an invalid payload, then compare the fallback fixture freshness with policy requirements. Request-time services may continue using the last successful snapshot.

If a feed becomes `unavailable`, keep request-time services on cached decisions and investigate fixture availability, database writes, and external source reachability. Do not wire direct public feed calls into Mosquito Net or Triage Counter as a workaround.

If cross-ecosystem IOC counts unexpectedly drop, refresh OpenSSF Malicious Packages and OpenSSF Package Analysis first, then inspect `cross_ecosystem_ioc_records` for package names, maintainer identities, domains, IPs, URLs, and behavioral fingerprints tied to the latest usable snapshots.

## Validation

Focused checks for the current implementation:

```bash
cargo test -p feed-harvester counts_package_analysis_results -- --test-threads=1
cargo test -p feed-harvester package_analysis_ioc_records_capture_behavioral_fingerprint -- --test-threads=1
```
