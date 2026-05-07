---
Status: Accepted
Category: control-plane
Date: 2026-05-07
Supersedes:
---

# ADR 0007: Request-Time Triage Client and Outage Binding

## Context

Phase 1A needs Mosquito Net to call Triage Counter before serving registry traffic, but full upstream adapter proxying, decision cache lookup, durable audit repositories, and persisted decision records are still open work. That leaves a sequencing question: should Mosquito Net wait for every downstream persistence and cache substrate before introducing request-time Triage calls, or should it bind the request-time fail mode now and let later tasks replace the scaffold response body with real adapter proxying?

ADR 0002 already defines degraded-operation precedence: unknown-artifact or cache-miss style requests in `enforce` mode must fail closed, while `warn` and `shadow` may fail open only with visible warning and audit evidence. The PRD also requires request-time work to avoid synchronous feed ingestion, sandbox execution, and LLM calls.

## Decision

Mosquito Net now owns a bounded HTTP client for request-time Triage Counter evaluation.

- The client posts normalized `DecisionRequest` payloads to `/v1/decisions/evaluate`.
- Triage base URLs must use `http` or `https` and must not contain embedded userinfo.
- Client calls use a configured timeout and a capped retry count.
- The resolved registry configuration supplies tenant, policy profile, adapter, mode, and registry configuration context.
- In `enforce` mode, the current scaffolded request path fails closed for unavailable Triage Counter responses with HTTP 503 and an Aegiscudo advisory header. This is a conservative pre-cache behavior, not a blanket override of ADR 0002's future cached known-good exception.
- In `warn` or `shadow` mode, unavailable Triage Counter responses currently fail open with an Aegiscudo advisory header and structured warning log; ADR 0002's full fail-open requirement remains incomplete until durable audit events are persisted.
- In `warn` or `shadow` mode, blocking Triage decisions remain advisory at Mosquito Net as temporary scaffold behavior until a later policy-mode refinement supersedes this behavior.
- Triage 4xx responses, malformed responses, context mismatches, and registry-mode mismatches are treated as hard errors and do not enter the fail-open outage path.

Until real adapter proxying lands, Mosquito Net returns a decision-gated scaffold response rather than upstream package metadata or artifacts.

## Rationale And Evidence

- [ADR 0002](0002-degraded-operation-and-fail-mode-precedence.md) requires enforce fail-closed behavior for unknown-artifact or cache-miss style requests and warn/shadow fail-open visibility during Triage outages.
- [services/mosquito-net/src/triage_client.rs](../../services/mosquito-net/src/triage_client.rs) implements URL validation, disabled redirects, timeout-bound `reqwest` calls, capped retry behavior, response-context validation, and typed failure reporting that separates outages from hard policy-context errors.
- [services/mosquito-net/src/lib.rs](../../services/mosquito-net/src/lib.rs) builds adapter-aware normalized decision requests, uses the resolved registry configuration as the enforcement-mode authority, and emits `x-aegiscudo-advisory` plus `x-aegiscudo-trace-id` headers.
- Local validation: `cargo test -p mosquito-net` covers allow, enforce block, warn-mode advisory block, enforce outage fail-closed, warn outage fail-open, Triage mode mismatch fail-closed, and Triage 4xx fail-closed behavior.

## Consequences

- Phase 1A can proceed with real npm and PyPI upstream proxy adapters behind a stable decision gate.
- Enforce mode is conservative for the current scaffolded request path before decision-cache, cached known-good serving, and persisted-decision repositories exist.
- Warn and shadow mode remain usable during true Triage outages, and the current scaffold is no longer silent because the response carries a developer-visible advisory header and structured warning log.
- Durable audit events are still required before the tracker item for warn/shadow fail-open with audit can be closed.
- Future upstream adapter integration tests must assert that package metadata and artifacts are served only after this Triage gate returns a non-enforcing outcome.

## Acceptance Evidence And Metrics

- Mosquito Net service tests cover Triage allow, blocking, warn advisory, outage, non-retryable error, and mode-mismatch paths.
- Triage client timeout and retry settings are bounded by startup configuration.
- Triage Counter base URLs reject embedded userinfo.