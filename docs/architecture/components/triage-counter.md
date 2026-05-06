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

The Rust service shell and in-memory decision engine scaffold exist with unit tests for all decision states, precedence, overrides, and stale feed state preservation. PostgreSQL policy loading, immutable snapshot creation, decision persistence, cache lookup, real signal ingestion, and override persistence remain Phase 1A work.