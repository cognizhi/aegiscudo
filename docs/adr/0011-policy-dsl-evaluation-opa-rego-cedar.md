---
Status: Proposed
Category: control-plane
Date: 2026-05-14
Supersedes:
---

# ADR 0011: Policy DSL Evaluation — OPA/Rego vs Cedar vs Current YAML DSL

## Context

Aegiscudo MVP implements package policy evaluation through a custom YAML-based DSL persisted
as versioned, hash-locked `PolicyProfile` snapshots and evaluated by Triage Counter at request
time (ADR 0009). As Phase 2 adds Scorecard signals, OpenVEX suppression, cross-ecosystem IOC
correlation, and per-ecosystem sandbox thresholds, the number of evaluable signal types and
the expected richness of tenant-configurable rules are growing.

Three policy representation options need to be evaluated before deciding whether to extend the
current YAML DSL, adopt an external policy language, or support both in parallel:

1. **Current YAML DSL** — typed `PolicyProfile` struct in `crates/aegiscudo-policy` and
   `services/python-common/src/aegiscudo_common/contracts.py`, enforced by deterministic Rust
   match logic in Triage Counter.

2. **OPA/Rego** — Open Policy Agent with its Rego policy language. OPA operates as a
   sidecar or embedded library evaluated via HTTP or Go/Rust FFI. Rego is a purpose-built
   Datalog-inspired query language for policy decisions. Used widely in Kubernetes admission
   control.

3. **Cedar** — AWS Cedar policy language. A structured attribute-based access control (ABAC)
   language with formal verification properties. A Rust-native `cedar-policy` crate exists.

The decision must respect the following constraints from the PRD and existing architecture:

- Request-time enforcement belongs to Mosquito Net and Triage Counter only (architecture rules).
- LLM output is advisory only and never the sole enforcement authority.
- Overrides require scope, reason, approver, expiry, and audit events.
- Policy profiles must be versioned, hashed into immutable snapshots, and every decision must
  reference the exact snapshot used at evaluation time.
- The policy format must be auditable, diffable, and tenants must be able to review their
  own profiles without understanding an external query language.
- Static analysis, sandbox execution, and feed ingestion are asynchronous; only the merged
  evidence output feeds request-time policy.

## Decision

**Keep the current YAML DSL as the primary policy representation and do not adopt OPA/Rego
or Cedar in Phase 2.** Extend the YAML DSL incrementally to cover Phase 2 signal types
(Scorecard, OpenVEX suppression, cross-ecosystem IOC, sandbox thresholds, and EPSS floor).

If policy complexity or the need for tenant-authored custom logic grows significantly beyond
Phase 2, Cedar is the preferred adoption path over OPA/Rego for the reasons documented in
the Rationale section. Re-evaluate at Phase 3 scoping.

## Rationale And Evidence

### OPA/Rego evaluation

**Strengths**
- Mature ecosystem with extensive Kubernetes/cloud-native adoption.
- Bundles support for versioned, distributable policy packages.
- External sidecar model decouples policy engine version from service releases.

**Weaknesses for Aegiscudo**
- Rego is a non-trivial language; tenants cannot safely author policies without specialized
  knowledge, which conflicts with the requirement for operator-auditable, diffable profiles.
- OPA HTTP sidecar introduces a new request-time service dependency. Triage Counter already
  has strict latency and fail-safe requirements (ADR 0002, ADR 0007). Adding an OPA call on
  the critical path introduces another latency tier and a new outage binding.
- Snapshot semantics are not native to Rego; policy bundles can be updated independently of
  the immutable decision record that must reference the exact policy version.
- No Rust-native embedding path without FFI overhead or spawning the Go binary. The
  `cedar-policy` crate does not have this constraint.
- OWASP relevance: Rego policies are data; a misconfiguration or injection into the OPA
  bundle store could weaken enforcement silently. The YAML DSL is validated at load time by
  the Rust type system and rejected on schema violation.

### Cedar evaluation

**Strengths**
- `cedar-policy` is a first-class Rust crate, satisfying the Rust-at-service-boundary
  architecture rule without FFI or sidecar overhead.
- Cedar's formal verification properties (the Cedar specification includes a Lean 4 proof)
  mean that policy correctness can be machine-checked, which complements the deterministic
  enforcement requirement.
- Cedar is attribute-based: a `PackageRequest` entity with attributes for ecosystem,
  version, Scorecard score, IOC hit, and EPSS probability maps cleanly onto Cedar's entity
  schema model.
- Cedar policies are human-readable permit/forbid statements. Tenants can review their own
  profiles more easily than Rego.
- Snapshot semantics are addressable: policy sets can be serialized, hashed, and stored
  alongside the decision record using the same mechanism as the current YAML DSL.

**Weaknesses**
- Cedar is younger and has less tooling than OPA for audit log export, policy testing
  harnesses, and IDE support.
- Migrating existing `PolicyProfile` structures and Triage Counter evaluation logic would
  require a dual-write period and backward-compatibility tests at all persistence and
  API contract points.
- Cedar authorization model assumes entities and actions. Package risk evaluation is
  closer to a scoring/classification problem than an access-control decision, so the
  conceptual fit is partial.
- Adopting Cedar would require the existing backward-compatibility test fixtures
  (`schemas/fixtures/policy.legacy-phase1.json`) to be re-expressed in Cedar schema,
  adding migration cost with low near-term marginal value.

### Current YAML DSL evaluation

**Strengths**
- Zero external runtime dependencies. Evaluation is pure Rust function calls inside
  Triage Counter with no network hop.
- Types are validated by `serde` + `validator` at profile load time. Schema violations
  are caught before they can affect request-time decisions.
- The existing ADR 0009 contract (version, hash, snapshot, freshness, advisory AI) is
  already implemented and tested.
- Phase 2 extensions (Scorecard thresholds, EPSS floor, IOC correlation, VEX suppression)
  each map to typed struct fields that are backward-compatible when optional with sane
  defaults. Existing backward-compatibility tests exercise the legacy fixture.
- Diffability: YAML diffs are readable in code review without specialized tooling.

**Weaknesses**
- Custom YAML DSL means Aegiscudo owns the policy language semantics, including
  correctness, completeness, and documentation.
- As the rule surface grows, the DSL may develop corner-case evaluation ordering issues
  that a formal language like Cedar would prevent by construction.
- No support for tenant-authored arbitrary rule expressions beyond the fields exposed
  by the struct. Tenants can only configure thresholds and enable/disable signals,
  not write custom rules.

### Summary matrix

| Criterion                        | YAML DSL | OPA/Rego  | Cedar     |
|----------------------------------|----------|-----------|-----------|
| Rust-native, no sidecar          | ✓        | ✗         | ✓         |
| Operator-auditable profiles      | ✓        | Partial   | ✓         |
| Immutable snapshot semantics     | ✓        | Requires work | Achievable |
| Backward compat with Phase 1     | ✓        | Requires migration | Requires migration |
| Formal correctness guarantees    | ✗        | Partial   | ✓ (Lean proof) |
| Tenant custom-rule authoring     | ✗        | ✓         | ✓         |
| Tooling maturity                 | Owned    | High      | Medium    |
| Phase 2 extension cost           | Low      | High      | High      |

### PRD and implementation anchors

- PRD §3.7.1, §3.7.3: policy profiles, enforcement modes, override lifecycle.
- `crates/aegiscudo-policy/`: current typed policy evaluation.
- `services/triage-counter/src/`: request-time evaluation and policy-input assembly.
- `schemas/policy.schema.json`: policy profile JSON schema.
- `schemas/fixtures/policy.legacy-phase1.json`: backward-compatibility fixture.
- ADR 0009: Phase 1A known-vulnerability threshold policy contract.
- `docs/plan/006-phase-2-expansion.md` § Policy Evolution: open items driving this ADR.

## Consequences

**Gets simpler or safer**
- Phase 2 signal types (Scorecard, EPSS, IOC, VEX) are added as typed optional fields
  in `PolicyProfile`, each with a safe default, keeping evaluation logic in one place.
- No new runtime service dependencies on the Triage Counter critical path.
- Existing snapshot, versioning, and backward-compatibility machinery continues to work
  without a migration.

**Deferred or constrained**
- Tenant-authored arbitrary policy expressions remain unsupported. Tenants can configure
  thresholds and enable/disable signals but cannot write custom rule logic.
- A future Phase 3 evaluation of Cedar for tenant-authored policy is explicitly deferred
  but should be re-triggered if the YAML field count exceeds ~30 evaluable signals or if
  tenant requests for custom rule expressions become a product priority.
- OPA/Rego is not on the roadmap. The sidecar latency dependency and Rego authoring
  complexity are incompatible with the Aegiscudo enforcement model.

**Acceptance metrics**
- Phase 2 policy fields (Scorecard thresholds, EPSS floor, IOC weight, sandbox thresholds)
  all pass `validate_policy_file_accepts_*` tests in `aedo-cli`.
- `schemas/fixtures/policy.legacy-phase1.json` continues to validate cleanly in
  `services/python-common/tests/test_contracts.py` and `services/triage-counter` loader tests
  after each new optional field is added.
- `cargo test -p aegiscudo-policy -- --test-threads=1` and
  `cargo test -p triage-counter -- --test-threads=1` pass with no regressions.
