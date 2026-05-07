---
Status: Accepted
Category: platform
Date: 2026-05-07
Supersedes:
---

# ADR 0004: MVP Cache, Queue, and Object-Storage Substrates

## Context

The MVP needs a queue or cache substrate for decision caching, metadata caching, rate-limit counters, feed coordination, and lightweight async job handoff. It also needs object storage for artifacts, evidence payloads, and reports. The tracker had embedded the Redis versus NATS and MinIO versus generic local object-storage decisions directly in the governance file.

## Decision

- Redis is the sole MVP cache and lightweight queue substrate.
- Local development uses MinIO as the object-storage emulator.
- Deployed environments target an S3-compatible object-storage abstraction.
- NATS JetStream is deferred until a later phase explicitly needs stronger replay, fan-out, or queue durability guarantees than Redis can provide for MVP.

## Rationale And Evidence

- [infra/docker-compose.yml](../../infra/docker-compose.yml) already provisions Redis and MinIO for local development.
- [README.md](../../README.md) describes Redis and MinIO as the local infrastructure defaults.
- [docs/architecture/data-and-storage.md](../architecture/data-and-storage.md) already describes Redis as the MVP cache and queue choice and MinIO-compatible storage as the local object-store implementation.
- Keeping one queue or cache substrate and one local object-store emulator reduces MVP operational surface area while preserving a clean abstraction boundary for later evolution.

## Consequences

- MVP infrastructure and code paths do not add NATS JetStream complexity.
- Queue, cache, and rate-limit state can share one operational substrate in local and early deployed environments.
- Object-storage integrations target an S3-compatible contract instead of a provider-specific API.

## Acceptance Evidence And Metrics

- Local infrastructure starts Redis and MinIO without additional queue or object-store dependencies.
- Control-plane acceptance keeps using the Phase 1A latency targets for cached decision lookup, cached proxy overhead, and known-artifact allow paths.
- Local validation anchors:
  - `docker compose -f infra/docker-compose.yml config`
  - `make up`