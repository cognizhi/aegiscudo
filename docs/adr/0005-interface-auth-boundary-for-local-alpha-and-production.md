---
Status: Accepted
Category: interface
Date: 2026-05-07
Supersedes:
---

# ADR 0005: Interface Auth Boundary for Local Alpha and Production

## Context

The Command Center and CLI need a stable auth boundary for MVP development. The PRD requires local development mock auth while preserving the production identity boundary around enterprise OIDC or SAML. The same decision had been duplicated across multiple phase trackers.

## Decision

- Local alpha uses mock OIDC with seeded personas only.
- Local development does not include a dedicated IdP container.
- Production remains bounded by enterprise OIDC or SAML integration.
- Backend RBAC is authoritative; UI filtering and CLI affordances are secondary to backend enforcement.
- CLI auth commands target API auth endpoints that work against mock auth in local alpha and against enterprise identity in later environments.

## Rationale And Evidence

- [docs/prd/aegiescudo-prd.md](../prd/aegiescudo-prd.md) requires enterprise OIDC or SAML integration in production and local dev mock auth.
- [docs/prd/aegiescudo-prd.md](../prd/aegiescudo-prd.md) also defines the CLI auth surface, which should remain compatible with the same backend auth boundary.
- Duplicating the auth decision across phase trackers made it easy for interface docs to drift from control-plane or API assumptions.

## Consequences

- Local infrastructure stays lighter and avoids a dev IdP dependency during MVP delivery.
- Seeded personas become the required auth test fixture for UI and CLI flows.
- Any introduction of a local IdP container later must be justified by a new ADR, not by incremental plan drift.

## Acceptance Evidence And Metrics

- Local infra does not require an IdP container.
- UI and CLI tests cover seeded personas and backend RBAC outcomes.
- Backend-protected admin routes reject unauthorized users even when the UI hides navigation correctly.
- Local validation anchors after implementation:
  - `pnpm test`
  - `pnpm --filter @aegiscudo/command-center playwright`