# Triage Counter

Source PRD sections: Feature 2, 3.3, 3.7.1, 3.7.3, 4.5 through 4.8.

Triage Counter is the deterministic decision API for request-time dependency admission.

## Responsibilities

- Evaluate tenant policy snapshots and deterministic risk signals.
- Look up decision cache, artifact reputation, vulnerability matches, malicious-package matches, and prior organizational verdicts.
- Return one PRD decision state for each normalized request.
- Create asynchronous analysis jobs for unknown artifacts without blocking request-time threads on heavy work.
- Persist decisions with tenant, coordinate, digest, policy snapshot, feed snapshot age, and evidence references.
- Enforce override and HITL lifecycle semantics.

## Decision States

Triage Counter must return exactly these decision states:

- `ALLOW`
- `ALLOW_WITH_WARNING`
- `QUARANTINE_PENDING_ANALYSIS`
- `BLOCK_KNOWN_MALICIOUS`
- `BLOCK_POLICY_VIOLATION`
- `REQUIRE_HITL_APPROVAL`
- `FALLBACK_TO_APPROVED_CANDIDATE`

## Boundaries

- Does not call live public feed APIs during package-manager requests.
- Does not execute package code.
- Does not use LLM output as sole enforcement authority.
- Uses last-successful feed snapshots and records freshness state on decisions.

## Current Implementation State

The Rust service shell and deterministic decision engine exist with unit tests for all decision states, precedence, overrides, stale feed state preservation, known-safe organizational verdict handling, a policy-defined known vulnerability threshold contract under [ADR 0009](../../adr/0009-phase-1a-known-vulnerability-threshold-policy-contract.md), and deferred placeholder inputs for cross-ecosystem IOC, static analysis score, sandbox result, GitHub publish-gap, and Trusted Publisher mismatch signals. Triage Counter now has SQLx-backed PostgreSQL policy profile loading, repository support for immutable policy snapshot creation, a DecisionRequest HTTP boundary that derives registry-bound mode plus snapshot context before evaluation instead of accepting request-supplied engine signals, request-time vulnerability signal binding from persisted `vulnerability_matches` using severity, KEV, and EPSS probability thresholds, request-time provenance or signature verification plus aggregate attestation status binding from persisted `artifact_attestations`, request-time AI agent injection binding from persisted `static_analysis_reports`, decision persistence that writes `package_requests` and `policy_decisions` rows on the current request-time path, reuse of the latest tenant-scoped persisted `ALLOW` decision for the same coordinate and digest as a known-safe verdict input, a `/metrics` endpoint that emits Prometheus decision count/state, latency, and degraded-feed use metrics, and digest-based analysis job queueing for unknown artifacts. Persisted decision records now carry normalized coordinates, optional requested digests, policy snapshot IDs, feed state and age, plus a structured rationale payload that reserves an `evidence_references` array for later signal binding. Analysis jobs now persist normalized coordinate plus artifact digest directly and can leave `artifact_id` empty until artifact storage exists, matching [ADR 0008](../../adr/0008-analysis-job-request-context-before-artifact-persistence.md). Broader prior organizational verdict sourcing, full KEV or EPSS prioritization, snapshot version/hash binding to real evidence, cache lookup, remaining adapter-driven metadata signals, cache-hit metrics, and override persistence remain Phase 1A work.