---
Status: Accepted
Category: control-plane
Date: 2026-05-07
Supersedes:
---

# ADR 0008: Analysis Job Request Context Before Artifact Persistence

## Context

Phase 1A requires Triage Counter to queue asynchronous analysis when an artifact digest is requested but no stored artifact match exists. The shared [AnalysisJob](../../crates/aegiscudo-core/src/lib.rs) contract already models queued work by normalized package coordinate, artifact digest, policy snapshot ID, and trace ID. The database schema in [migrations/0001_init.sql](../../migrations/0001_init.sql) still required every `analysis_jobs` row to reference a non-null `artifact_id`, which only exists after artifact persistence and object-storage placement.

That schema shape blocked the request-time unknown-artifact path: Triage Counter can see a normalized request plus an optional digest at decision time, but it must not synchronously fetch, persist, or store package contents just to enqueue analysis. Request-time enforcement belongs in Triage Counter and Mosquito Net, while heavy artifact handling remains asynchronous under the broader MVP architecture.

## Decision

- `analysis_jobs` store the normalized package coordinate and requested artifact digest directly.
- `analysis_jobs.artifact_id` becomes optional so a job can be queued before artifact persistence exists.
- When an artifact row already exists for the same tenant and digest, `analysis_jobs.artifact_id` may still be populated.
- Triage Counter identifies an unknown artifact when a request carries a digest that does not match any stored artifact for that tenant, and queues an analysis job when the policy engine returns `create_analysis_job = true`.

## Rationale And Evidence

- The shared [AnalysisJob](../../crates/aegiscudo-core/src/lib.rs) contract already uses coordinate and artifact digest as the stable request-time identity, so the previous schema was lagging the contract rather than defining it.
- The initial schema in [migrations/0001_init.sql](../../migrations/0001_init.sql) required a non-null `artifact_id`, which is incompatible with request-time queueing before object storage and artifact persistence complete.
- [docs/plan/002-mvp-control-plane.md](../plan/002-mvp-control-plane.md) explicitly requires asynchronous analysis job creation for unknown artifacts without blocking request-time threads on heavy work.
- The updated Triage Counter repository tests validate both sides of the new boundary: unknown digest requests queue `QUARANTINE_PENDING_ANALYSIS` jobs, while known digest requests do not.

## Consequences

- Request-time decisioning can enqueue analysis work using normalized request context alone.
- Artifact persistence and object-storage placement remain asynchronous and can attach `artifact_id` later when available.
- Existing downstream analysis tables keep their stronger `artifact_id` requirements because static analysis, sandbox, and evidence persistence operate only after artifact materialization.
- Request paths that do not yet provide a digest, including the current Mosquito Net scaffold, will not queue analysis jobs until real artifact proxying and digest capture exist.

## Acceptance Evidence And Metrics

- `cargo test -p triage-counter`
- `cargo clippy -p triage-counter --all-targets -- -D warnings`