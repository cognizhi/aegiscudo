# Authentication And Identity

Source PRD sections: 2.1, 3.4.3, 3.6, 4.9, 4.10, 4.12.5.

Aegiscudo keeps identity as a cross-cutting interface boundary rather than a UI-only concern. The control plane owns authoritative caller identity and role evaluation. Command Center navigation and CLI affordances can adapt to that identity, but they must not become the enforcement authority.

## Local Alpha Boundary

- Local alpha uses seeded mock identities only.
- Local alpha does not run a dedicated IdP container.
- Command Center may persist the selected mock persona locally, but backend RBAC remains authoritative.
- The stable backend session contract is `/v1/auth/session`, even when the current local implementation remains stateless and header-driven.

## Production Boundary

- Production identity is bounded by enterprise OIDC or SAML.
- Enterprise login choreography, callback handling, session issuance, and logout semantics belong to the backend auth surface, not to ad hoc frontend state.
- Tenant-scoped control-plane routes remain downstream of auth. Identity is established first via `/v1/auth/*`, then tenant-scoped authorization applies on `/v1/tenants/{tenant_id}/...` routes.

## MVP Session Contract

Phase 1C introduces a minimal cross-environment contract without over-building production SSO:

- `GET /v1/auth/session` returns the current auth mode plus resolved subject when available.
- `GET /v1/auth/mock-identities` lists seeded mock identities in local alpha only.
- `PUT /v1/auth/session/mock` resolves a selected local identity and returns the matching session payload in local alpha only.
- `DELETE /v1/auth/session` is a no-op logout boundary for stateless local clients and a stable future hook for enterprise-backed session termination.

These endpoints are intentionally thin. They do not introduce a local token issuer, browser callback flow, SCIM, group sync, or a dedicated IdP dependency.

## Role Model

- Backend roles are resolved from persisted users, roles, and user-role assignments.
- Mock identity selection may influence which actor header the local client forwards, but it does not override backend role checks.
- Audit records should preserve raw actor labels for traceability while also resolving display names and roles where the backend can do so safely.

## CLI Boundary

- `aedo-cli` keeps local config persistence in Phase 1C.
- The stable long-term compatibility point is the backend auth surface, not a CLI-specific identity mechanism.
- Any future CLI use of `/v1/auth/session` should remain status-oriented until enterprise login choreography is explicitly designed.

## Non-Goals For Phase 1C

- No local IdP container.
- No Aegiscudo-issued long-lived token system.
- No OIDC redirect or SAML ACS implementation.
- No user CRUD, SCIM, or identity synchronization.
- No second permission model that diverges from backend roles.