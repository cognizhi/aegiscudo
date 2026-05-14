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

The Rust service shell and deterministic decision engine exist with unit tests for all decision states, precedence, overrides, stale feed state preservation, known-safe organizational verdict handling, a policy-defined known vulnerability threshold contract under [ADR 0009](../../adr/0009-phase-1a-known-vulnerability-threshold-policy-contract.md), and remaining placeholder inputs for static analysis score and sandbox result. GitHub publish-gap and Trusted Publisher mismatch signal names can bind from `package_signal_observations`, while cross-ecosystem IOC now also binds from Feed Harvester's latest usable normalized IOC feed records rather than remaining a placeholder-only policy bit. Triage Counter now has SQLx-backed PostgreSQL policy profile loading, repository support for immutable policy snapshot creation, a DecisionRequest HTTP boundary that derives registry-bound mode plus snapshot context before evaluation instead of accepting request-supplied engine signals, request-time vulnerability signal binding from persisted `vulnerability_matches` using severity, KEV, and EPSS probability thresholds, request-time provenance or signature verification plus aggregate attestation status binding from persisted `artifact_attestations`, request-time AI agent injection binding from persisted `static_analysis_reports`, request-time deps.dev integration for both Scorecard repo resolution and package-scoped transitive dependency signal propagation through the full reachable dependency graph of the latest normalized package-or-edge snapshot, request-time cross-ecosystem IOC binding from the latest usable feed snapshots when package-name, maintainer-identity, domain, IP, URL, or behavioral-fingerprint indicators recur across ecosystems, sandbox-derived domain/IP/URL correlation from persisted `sandbox_runs` when Emergency Room records structured destination telemetry, and request-time behavioral fingerprint correlation derived from persisted static-analysis indicators plus sandbox telemetry when both evidence sources normalize to the same canonical behavior vocabulary used by Feed Harvester's `behavioral-fingerprint` IOC records, plus latest-snapshot clearing when a newer successful IOC feed refresh removes previously correlated rows, decision persistence that writes `package_requests` and `policy_decisions` rows on the current request-time path, reuse of the latest tenant-scoped persisted `ALLOW` decision for the same coordinate and digest as a known-safe verdict input, a `/metrics` endpoint that emits Prometheus decision count/state, latency, and degraded-feed use metrics, and digest-based analysis job queueing for unknown artifacts. Persisted decision records now carry normalized coordinates, optional requested digests, policy snapshot IDs, feed state and age, plus a structured rationale payload that reserves an `evidence_references` array for later signal binding. Analysis jobs now persist normalized coordinate plus artifact digest directly and can leave `artifact_id` empty until artifact storage exists, matching [ADR 0008](../../adr/0008-analysis-job-request-context-before-artifact-persistence.md). Broader prior organizational verdict sourcing, full KEV or EPSS prioritization, snapshot version/hash binding to real evidence, cache lookup, remaining adapter-driven metadata signals, cache-hit metrics, and override persistence remain Phase 1A work.