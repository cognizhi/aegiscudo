# Architecture Decision Records

This directory is the canonical location for Aegiscudo architecture decisions that change system shape, operating model, or external contracts.

Use an ADR when a choice affects one or more of the following:

- Request-time or asynchronous service boundaries.
- Control-plane behavior, degraded-operation policy, or tenant isolation.
- Platform substrates such as caches, queues, object storage, or runtime allocation.
- Authentication, contract generation, or other cross-cutting interface boundaries.

Do not use ADRs for:

- Phase backlog or implementation tasks.
- Routine refactors or library swaps that do not change architecture.
- Validation thresholds or release-gate policy that belong in governance or release docs.

## ADR Conventions

- Number ADRs sequentially as `0001`, `0002`, and so on.
- Keep file names stable after acceptance.
- Use frontmatter with `Status`, `Category`, `Date`, and `Supersedes` when needed.
- Prefer `Proposed`, `Accepted`, `Superseded`, or `Rejected` as status values.
- Update the affected architecture and plan docs with links to the accepted ADR.

## Index

| ADR | Title | Status | Category |
|---|---|---|---|
| [0001](0001-control-plane-routing-scope-and-mount-path-uniqueness.md) | Control-Plane Routing Scope and Mount-Path Uniqueness | Accepted | control-plane |
| [0002](0002-degraded-operation-and-fail-mode-precedence.md) | Degraded Operation and Fail-Mode Precedence | Accepted | control-plane |
| [0003](0003-service-runtime-allocation-by-responsibility.md) | Service Runtime Allocation by Responsibility | Accepted | platform |
| [0004](0004-mvp-cache-queue-and-object-storage-substrates.md) | MVP Cache, Queue, and Object-Storage Substrates | Accepted | platform |
| [0005](0005-interface-auth-boundary-for-local-alpha-and-production.md) | Interface Auth Boundary for Local Alpha and Production | Accepted | interface |
| [0006](0006-openapi-contract-source-of-truth-and-generated-type-workflow.md) | OpenAPI Contract Source of Truth and Generated Type Workflow | Accepted | interface |
| [0007](0007-request-time-triage-client-and-outage-binding.md) | Request-Time Triage Client and Outage Binding | Accepted | control-plane |
| [0008](0008-analysis-job-request-context-before-artifact-persistence.md) | Analysis Job Request Context Before Artifact Persistence | Accepted | control-plane |
| [0009](0009-phase-1a-known-vulnerability-threshold-policy-contract.md) | Phase 1A Known Vulnerability Threshold Policy Contract | Accepted | control-plane |

Use [the ADR template](_template.md) for new records.