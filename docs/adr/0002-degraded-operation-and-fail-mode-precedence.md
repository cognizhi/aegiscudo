---
Status: Accepted
Category: control-plane
Date: 2026-05-07
Supersedes:
---

# ADR 0002: Degraded Operation and Fail-Mode Precedence

## Context

The PRD requires degraded-operation behavior to be explicit and testable for cache misses, unknown artifacts, stale feeds, unavailable AI providers, unavailable sandbox workers, and upstream outages. The architecture already states the high-level fail-closed rule, but the repository had no single record that defined precedence across tenant defaults, registry overrides, and hard PRD guardrails.

Without a written precedence model, the Phase 1A control-plane can drift into inconsistent fail-open behavior across Mosquito Net, Triage Counter, and future async evidence pipelines.

## Decision

Degraded-operation behavior is resolved by the following precedence order:

1. Non-overridable PRD guardrails.
2. Registry-specific fail-mode overrides.
3. Tenant-level default fail modes.
4. Service startup defaults used only until persisted configuration exists.

The effective behavior for the main outage classes is:

- Triage Counter unavailable for unknown artifacts in `enforce` mode: fail closed.
- Triage Counter unavailable for unknown artifacts in `warn` or `shadow` mode: fail open only with an audit event and developer-visible warning.
- Stale feeds: serve only previously verified known-good cached metadata or artifacts, and record feed state plus feed age on the decision.
- AI explanation or Langfuse outage: never block deterministic allow or block decisions; degrade explanations and alerting only.
- Sandbox worker outage for artifacts that still require deeper analysis: default to quarantine unless an explicit tenant or registry policy chooses a static-only fallback.
- Upstream outage: serve only cached metadata or artifacts whose integrity was already verified; never synthesize packages that were not previously fetched and validated.

## Rationale And Evidence

- [docs/prd/aegiescudo-prd.md](../prd/aegiescudo-prd.md) requires degraded-operation behavior to be explicit and testable and states the hard guardrails for enforce fail-closed, warn or shadow fail-open with audit visibility, stale-feed serving constraints, AI outage handling, sandbox outage behavior, and upstream outage behavior.
- [docs/architecture/policy-and-decisions.md](../architecture/policy-and-decisions.md) already describes the high-level enforcement rules; this ADR makes the precedence and allowed overrides concrete.
- [docs/plan/002-mvp-control-plane.md](../plan/002-mvp-control-plane.md) carries the remaining fail-mode implementation tasks, which should now be treated as execution work rather than unresolved architecture.

## Consequences

- Every request-time decision must record the effective mode, feed state, and feed snapshot age whenever degraded conditions influence the outcome.
- Registry-specific behavior can be more strict than tenant defaults, but it cannot violate PRD-enforced guardrails.
- Warn and shadow behavior remains usable during partial outages without allowing silent fail-open behavior.
- Future configuration schemas and admin APIs must expose tenant defaults separately from registry overrides.

## Acceptance Evidence And Metrics

- Decision records include `mode`, `feed_state`, and `feed_snapshot_age_seconds`.
- Integration tests cover Triage outage, stale-feed serving, AI outage non-blocking behavior, sandbox outage handling, and upstream outage cache behavior.
- Request-time services continue to satisfy the Phase 1A performance target that they do not block on live feed ingestion, sandbox execution, or LLM explanation work.
- Local validation commands after implementation:
  - `cargo test -p triage-counter`
  - `cargo test -p mosquito-net`