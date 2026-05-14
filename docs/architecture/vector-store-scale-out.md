# Vector Store Scale-Out Path

Source PRD sections: [3.6 AI Stack](../prd/aegiescudo-prd.md).

## Current Phase 2 State

Phase 2 activates the MVP pgvector path on the existing `static_analysis_reports.embedding` column.

- Surgeon derives a deterministic 1536-dimension embedding from normalized static indicator text and stores it with each persisted static analysis report.
- AI Analyst uses the stored vector for tenant-scoped nearest-neighbor lookup so final summaries can include historical similar cases.
- The embedding is advisory context only. It does not affect request-time enforcement or override deterministic policy decisions.

This implementation keeps the full retrieval path inside the existing PostgreSQL control-plane boundary:

- no new service dependency
- no cross-system consistency problem for initial rollout
- no extra evidence egress path
- simple backup and restore using existing database procedures

## Why Pgvector Remains The Phase 2 Default

Pgvector remains the correct default until at least one of these conditions becomes true:

- nearest-neighbor queries on `static_analysis_reports` become a measurable latency contributor for AI Analyst finalization
- the number of embedded reports grows enough that PostgreSQL vacuum and index maintenance materially affect control-plane performance
- operators need separate retention, replication, or regional placement rules for embeddings that differ from the primary control-plane database
- retrieval use cases expand beyond a small number of tenant-scoped historical cases per analysis

Until then, pgvector is the lowest-risk choice because it preserves the current trust boundary and operational model.

## Evaluation Criteria For A Scale-Out Store

Any scale-out option must improve on pgvector without weakening Aegiscudo requirements:

- tenant isolation must remain explicit and query-enforced
- sensitive evidence slices must not leave an approved security boundary
- retrieval must support filtering by tenant and, when needed later, ecosystem or policy version
- backfill and rollback must be possible without interrupting analysis-job processing
- operations must support snapshots, disaster recovery, and auditability comparable to PostgreSQL
- local-only deployments must remain possible

## Qdrant Migration Path

Qdrant is the preferred scale-out target if Aegiscudo outgrows pgvector.

Reasons:

- self-hosted deployment fits the PRD security posture better than a cloud-only vector service
- approximate nearest-neighbor indexing and payload filtering are strong fits for large historical-case corpora
- operational ownership remains with the platform operator rather than an external provider
- it can coexist with the current PostgreSQL source of truth during migration

Suggested migration sequence:

1. Keep PostgreSQL as the authoritative store for report metadata and artifact relationships.
2. Introduce a small embedding repository interface in AI Analyst so retrieval can swap between pgvector and an external store.
3. Dual-write new embeddings from Surgeon to PostgreSQL and Qdrant.
4. Backfill existing `static_analysis_reports` embeddings into Qdrant in tenant-bounded batches.
5. Run shadow queries and compare top-k overlap before cutover.
6. Switch AI Analyst historical-case retrieval to Qdrant only after overlap and latency targets are met.

Qdrant should be the default Phase 3 recommendation for self-hosted, higher-volume deployments.

## Vertex AI Vector Search Path

Vertex AI Vector Search is viable only for operators that already accept a managed Google Cloud dependency for AI workloads and have approved the data-processing boundary.

Caveats:

- embeddings are derived from security-sensitive evidence, so cloud export must be treated as an explicit compliance decision
- local-only provider mode and air-gapped deployments cannot depend on Vertex
- cross-service egress, IAM, and network policy become materially more complex than the pgvector or Qdrant paths

Vertex is therefore an optional enterprise deployment path, not the default evolution path.

## Migration Trigger

Stay on pgvector through Phase 2. Re-open the storage choice when both of the following are true:

- the historical-case corpus is large enough that pgvector query latency or maintenance cost shows up in production SLO review
- the AI Analyst retrieval contract has stabilized enough that a storage abstraction will not churn every sprint

Until that trigger is met, new work should target the current PostgreSQL-backed embedding path rather than introducing a second vector system prematurely.
