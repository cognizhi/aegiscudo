---
Status: Accepted
Category: interface
Date: 2026-05-10
Supersedes:
---

# ADR 0010: Auth Session And Mock Identity Contract Boundary

## Context

ADR 0005 established that local alpha uses seeded mock identities while production remains bounded by enterprise OIDC or SAML. Phase 1C still lacked a stable backend session contract for the Command Center and CLI to converge on later, and the remaining plan items risked turning local persona state into an implicit permanent auth model.

## Decision

- Keep the production identity boundary at enterprise OIDC or SAML.
- Introduce a thin backend auth contract under `/v1/auth/*`.
- Keep auth endpoints unscoped by tenant path because identity must be established before tenant-scoped authorization.
- Support the following Phase 1C endpoints only:
  - `GET /v1/auth/session`
  - `GET /v1/auth/mock-identities`
  - `PUT /v1/auth/session/mock`
  - `DELETE /v1/auth/session`
- In local alpha, mock identity selection remains stateless and returns a resolved subject payload rather than introducing a backend session store or token issuer.
- Mock-identity endpoints return `409 Conflict` when the configured auth mode is not `mock_oidc`.

## Rationale And Evidence

- [ADR 0005](0005-interface-auth-boundary-for-local-alpha-and-production.md) already rejects a dedicated local IdP container for MVP delivery.
- [docs/plan/004-mvp-command-center-cli.md](../plan/004-mvp-command-center-cli.md) still required both the production OIDC/SAML boundary and auth/session contract definition.
- The CLI auth surface must remain compatible with the same backend boundary even if Phase 1C keeps CLI login as local config persistence.
- Keeping the contract at `/v1/auth/*` prevents tenant-scoped routes from becoming accidental auth bootstrapping points.

## Consequences

- Command Center and CLI gain a stable backend session contract without over-building enterprise SSO.
- Local alpha continues to rely on seeded personas and backend RBAC, not on a separate frontend-only identity model.
- Future enterprise auth work can replace the mock implementation behind the same session endpoint family.
- Phase 1C explicitly does not add callback handlers, session cookies, SCIM, group sync, or local token issuance.

## Acceptance Evidence And Metrics

- OpenAPI defines the `/v1/auth/*` session and mock-identity endpoints.
- `aegiscudo-api` exposes the same contract and enforces `409` on mock-only endpoints when auth mode is not `mock_oidc`.
- Local validation anchors after implementation:
  - `pnpm openapi:generate`
  - `pnpm --filter @aegiscudo/shared-types typecheck`
  - `cargo test -p aegiscudo-api auth_session_route_defaults_to_platform_admin_identity_in_mock_mode -- --ignored`
  - `cargo test -p aegiscudo-api mock_identity_routes_list_select_and_reject_unknown_identities -- --ignored`
  - `cargo test -p aegiscudo-api mock_identity_routes_conflict_when_auth_mode_is_not_mock -- --ignored`