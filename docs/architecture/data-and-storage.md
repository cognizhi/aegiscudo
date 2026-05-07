# Data And Storage

Source PRD sections: 3.5, 3.7, 4.3, 4.5, 4.8.

Aegiscudo stores durable state in PostgreSQL, low-latency state in Redis, and large artifacts or reports in object storage. The accepted MVP substrate choices are recorded in [ADR 0004](../adr/0004-mvp-cache-queue-and-object-storage-substrates.md).

## PostgreSQL

PostgreSQL stores tenants, users, roles, registry configs, package requests, artifacts, policy versions, policy decisions, analysis jobs, static reports, sandbox runs, attestations, AI explanations, vulnerability matches, malware matches, overrides, audit events, AI provider configs, encrypted runtime integration credential material, credential metadata, feed snapshots, and user settings.

The initial schema includes `pgvector` so evidence embeddings can be added later for clustering similar malicious slices and historical case retrieval.

## Redis / Queue

Redis is the MVP cache and queue choice for decision cache, metadata cache, rate-limit counters, analysis queue, and feed-ingestion coordination. A later NATS JetStream transition requires a superseding ADR if queue durability or replay requirements grow beyond the MVP cut.

## Object Storage

S3/GCS-compatible object storage holds original package archives, large evidence payloads, raw attestation snapshots, sandbox logs, SBOM exports, and reports. Local development uses MinIO-compatible storage as defined by [ADR 0004](../adr/0004-mvp-cache-queue-and-object-storage-substrates.md).

## Data Boundaries

- Tenant scoping is required at repository and API layers.
- Bootstrap credentials may come from environment variables or a secret manager at startup, but encrypted database overrides take precedence at runtime when present.
- API responses expose credential metadata and configured state only. Secret material must not be returned after write.
- Credential values are not stored in plain filesystem storage and must never appear in logs or audit events.
- Audit records are append-only evidence for decisions and administrative mutations.

## Current Implementation State

The initial SQL migration, MinIO local infrastructure, bucket bootstrap script, and schema fixtures exist. Migration dry-run tests, repository layer enforcement, and object-storage integration tests remain open.