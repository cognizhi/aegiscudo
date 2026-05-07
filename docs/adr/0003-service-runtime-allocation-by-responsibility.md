---
Status: Accepted
Category: platform
Date: 2026-05-07
Supersedes:
---

# ADR 0003: Service Runtime Allocation by Responsibility

## Context

Aegiscudo intentionally mixes Rust and Python. That split only works if runtime allocation follows clear responsibility boundaries rather than per-team preference.

The open tracker had embedded two finalized decisions that belonged to a single architectural rule:

- Feed Harvester should optimize adapter velocity for diverse external feed clients.
- SBOM Service should stay aligned with the typed evidence and backend contract pipeline.

## Decision

Runtime allocation follows responsibility boundaries:

- Rust owns request-time enforcement, shared DTOs, static analysis, typed backend contracts, and SBOM aggregation or export paths that benefit from strict typing and close coupling to the evidence pipeline.
- Python owns asynchronous ingestion or orchestration paths where adapter velocity and HTTP integration ergonomics matter more than request-time latency.

For current services, this means:

- Feed Harvester remains a Python service.
- SBOM Service remains a Rust service.

## Rationale And Evidence

- [docs/architecture/components/feed-harvester.md](../architecture/components/feed-harvester.md) already records the Python choice for feed adapter velocity on top of FastAPI, httpx, and tenacity.
- [docs/architecture/components/sbom-service.md](../architecture/components/sbom-service.md) already records the Rust choice to align SBOM aggregation with typed evidence contracts.
- The repository architecture keeps Mosquito Net and Triage Counter in Rust on the request path while asynchronous orchestration surfaces already exist in Python, which matches the intended split.

## Consequences

- No Python service is introduced into the request-time enforcement path without an explicit superseding ADR.
- Feed-specific client logic can iterate faster without reshaping the low-latency request path.
- SBOM export and evidence aggregation stay close to the Rust domain model and schema contracts.

## Acceptance Evidence And Metrics

- Request-time services remain Rust-based.
- Feed Harvester uses the Python runtime and its associated lint and test gates.
- SBOM Service stays within the Rust workspace and Rust validation gates.
- Local validation anchors:
  - `cargo test --workspace`
  - `uv run pytest`