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

A Python service placeholder and feed fixtures exist. Language choice is finalized in favor of Python for faster adapter development on top of the existing FastAPI/httpx/tenacity stack. Ingestion scheduler, feed clients, persistence, and tests remain open.