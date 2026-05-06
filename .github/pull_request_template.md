## Scope

- Primary phase file(s):
- PRD or architecture docs touched:
- Related issue, discussion, or design note:

## Governance

- Exact plan rows changed:
- Exact traceability rows changed:
- [ ] I updated [docs/plan/000-delivery-governance.md](docs/plan/000-delivery-governance.md) if governance state, phase gates, or decision log entries changed.
- [ ] I updated the active phase plan file for the work completed in this PR.
- [ ] I updated [docs/plan/008-traceability-matrix.md](docs/plan/008-traceability-matrix.md) if requirement coverage changed.
- [ ] This PR does not move scope across phases without maintainer approval.
- [ ] If this PR changes phase entry or exit state, maintainer approval notes or `none` are recorded here:

## Validation

- Commands run:
- Test reports or screenshots:
- Exceptions requested and approving link:
- [ ] Tests are committed with the code change, or an approved exception is linked above.

## Definition Of Done

- [ ] Unit coverage includes positive, negative, boundary, and adversarial cases for changed logic.
- [ ] Integration coverage is included for changed service boundaries or persistence behavior.
- [ ] E2E or workflow coverage is included for affected user-visible behavior.
- [ ] Command Center changes include Playwright coverage for affected user flows.
- [ ] Security-sensitive changes include regression coverage or explicit security-review notes.
- [ ] JSON schema, OpenAPI, and generated artifacts are versioned and validated when changed.
- [ ] Observability is added or updated for latency, errors, security decisions, and degraded states when runtime behavior changes.
- [ ] Audit events are added or updated for admin actions, policy mutations, overrides, credentials, and package decisions touched by this PR.
- [ ] Documentation and Copilot instructions are updated when architecture or patterns change.
- [ ] CI quality gates pass locally or in CI before merge.

## Engineering Practices

- [ ] I followed the TDD loop or documented why this change could not start from a failing test.
- [ ] Service boundaries use typed DTOs and schemas for new or changed inputs and outputs.
- [ ] Rust changes use explicit error types.
- [ ] Rust changes avoid panics outside startup validation.
- [ ] External calls touched by this PR have timeouts, retries, and circuit-breaker behavior or are explicitly unchanged.
- [ ] Logs, traces, and errors do not include secrets, tokens, auth headers, package-manager credentials, environment variable dumps, or raw credential values.
- [ ] Repository or API changes include tenant scoping and RBAC checks where applicable.
- [ ] Policy decision flows touched by this PR persist policy snapshot ID and feed snapshot age or state where required.
- [ ] Package decisions and admin mutations touched by this PR persist append-only audit evidence where required.

## Reviewer Routing

- [ ] Maintainer review is required for governance, scope, or phase-gate changes.
- [ ] Security review is required for security-sensitive behavior, secrets, trust boundaries, or enforcement logic.
- [ ] Documentation review is required for architecture, operations, onboarding, or workflow changes.