---
Status: Accepted
Category: control-plane
Date: 2026-05-07
Supersedes:
---

# ADR 0001: Control-Plane Routing Scope and Mount-Path Uniqueness

## Context

Phase 1A needs Mosquito Net to route package-manager traffic deterministically before adapter dispatch, policy evaluation, or upstream credential selection. The control-plane tracker had been carrying an unresolved architectural blocker: whether request routing should depend on authenticated tenant context or on a globally unique mount path.

The PRD makes `mount_path` the client-facing routing key for registry proxy configurations and defines each registry configuration as tenant-owned. Package-manager traffic is expected to point to `<aegiscudo-host>/proxy/<mount-path>/...`, but npm, pip, and similar clients do not reliably provide an Aegiscudo-specific tenant identity on every request. Requiring request-time tenant authentication in Phase 1A would add a new compatibility boundary before the MVP proxy path is even functional.

The repository already contains partial evidence in this direction:

- [migrations/0002_control_plane_constraints.sql](../../migrations/0002_control_plane_constraints.sql) adds canonical `/proxy/...` mount-path validation, upstream URL userinfo rejection, and a global unique index over active mount paths.
- [services/mosquito-net/src/registry_config.rs](../../services/mosquito-net/src/registry_config.rs) rejects duplicate effective mounts at startup and resolves the longest matching mount deterministically.
- [docs/plan/002-mvp-control-plane.md](../plan/002-mvp-control-plane.md) had been calling out the routing model as the remaining open design choice in the blocker note.

## Decision

For Phase 1A, Mosquito Net resolves requests by globally unique non-deleted `mount_path`.

- The effective request route is the configured `/proxy/<mount-path>` prefix.
- The matched `registry_config` supplies tenant, policy, and upstream credential context.
- Package-manager requests do not depend on authenticated tenant routing in Phase 1A.
- Two non-deleted registry configurations may not share the same effective mount path, even across tenants.
- Tenant-aware mount reuse is deferred until a later design explicitly introduces authenticated tenant routing, host-based partitioning, or another unambiguous request discriminator.

## Rationale And Evidence

- The multi-registry proxy model in [docs/prd/aegiescudo-prd.md](../prd/aegiescudo-prd.md) defines `mount_path` as the package-manager-facing route key and `tenant_id` as registry ownership metadata, which supports deriving tenant context from the matched registry config rather than from package-manager auth.
- The current SQL constraints in [migrations/0002_control_plane_constraints.sql](../../migrations/0002_control_plane_constraints.sql) already enforce the accepted MVP model: canonical `/proxy/...` paths, no embedded upstream credentials, and global uniqueness for non-deleted mount paths.
- The startup validation in [services/mosquito-net/src/registry_config.rs](../../services/mosquito-net/src/registry_config.rs) rejects duplicate effective mounts and ambiguous paths before request handling begins.
- This choice keeps npm and PyPI client compatibility on the critical request-time path and removes an otherwise blocking architectural dependency from Phase 1A.

## Consequences

- Phase 1A request routing is deterministic before adapter dispatch, Triage calls, or upstream proxying.
- Tenant attribution for package requests comes from the resolved `registry_config`, not from package-manager authentication.
- Two tenants cannot reuse the same friendly mount name while this ADR remains in force, even if only one configuration is currently enabled.
- Admin validation and integration tests must reject mount collisions across tenants.
- Future authenticated tenant routing, if introduced, must supersede this ADR explicitly rather than weakening the uniqueness guarantee implicitly.

## Acceptance Evidence And Metrics

- Database guarantee: exactly one non-deleted registry configuration may own a given `mount_path`.
- Startup validation: duplicate effective mounts fail fast during configuration loading.
- Routing validation: request resolution remains longest-prefix deterministic for nested mounts.
- Local validation commands:
  - `make migrate-check`
  - `cargo test -p mosquito-net`