# Policy And Decisions

Source PRD sections: Feature 2, 3.7.1, 3.7.3, 4.5, 4.6.

Policy profiles are versioned and hashed into immutable snapshots. Every package decision must reference the exact policy snapshot used at evaluation time.

## Decision Model

Allowed decision states are:

- `ALLOW`
- `ALLOW_WITH_WARNING`
- `QUARANTINE_PENDING_ANALYSIS`
- `BLOCK_KNOWN_MALICIOUS`
- `BLOCK_POLICY_VIOLATION`
- `REQUIRE_HITL_APPROVAL`
- `FALLBACK_TO_APPROVED_CANDIDATE`

## Enforcement Rules

- Unknown artifact behavior is controlled by tenant and registry enforcement mode.
- Shadow and warn modes may fail open only with audit evidence and developer-visible warnings.
- Enforcement mode defaults to fail closed for unknown artifacts when Triage Counter is unavailable.
- npm fallback is allowed only for eligible metadata resolution flows.
- Explicit versions, tarball URLs, and integrity-locked artifacts are never silently substituted.
- Emergency bypass and overrides require scope, reason, approver, expiry, and audit events.

## Analysis Result Assimilation

- Triage Counter owns the deterministic merge of policy snapshots, feed intelligence, static evidence, optional sandbox evidence, overrides, and advisory AI output into the final decision record.
- After Surgeon completes static analysis, Triage Counter updates the provisional score, persists the evidence linkage, and decides whether dynamic analysis is required.
- Emergency Room runs only when static findings or policy thresholds require sandbox execution, and its telemetry is merged back into the same package decision flow.
- AI Analyst receives only redacted high-signal evidence and returns advisory explanations for operator review surfaces. AI output never overrides deterministic thresholds on its own.
- Triage Counter generates the final score and recommended decision, persists the outcome, and invalidates or refreshes cached request-time decisions for the affected artifact.

## Current Implementation State

The shared Rust DTOs, decision enum, normalized request contract, advisory header payload, and in-memory decision precedence tests exist. Snapshot persistence, durable policy evaluation, override lifecycle, decision cache, and feed-snapshot backed decisions remain Phase 1A work.