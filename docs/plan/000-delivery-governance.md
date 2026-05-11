# Delivery Governance Tracker

Source PRD sections: 1.4, 2.2, 4.5, 4.6, 4.12, 5, 6.2, Production Readiness Gate.

## Plan Status

- [x] Governance rules accepted by maintainers.
- [x] Tracker ownership assigned.
- [x] PRD traceability matrix initialized and maintained.
- [x] Phase-gate review workflow is defined in repo.

Progress note: 2026-05-05 foundation implementation has been applied and validated locally.
Progress note: 2026-05-06 tracker ownership is assigned to the Tech Lead, the maintainer team includes the Tech Writer, governance acceptance is settled, and repo phase-gate review is routed through the PR template plus required `CI` and `Security` checks.
Progress note: 2026-05-06 OpenAPI source-of-truth now lives in `contracts/openapi`, generated TypeScript contract aliases are committed from `@aegiscudo/shared-types`, and CI enforces `pnpm openapi:check`.
Progress note: 2026-05-06 the PR template now encodes the Definition of Done, engineering-practice acknowledgements, and test-or-exception rule used for maintainer review.

## Governance Record

Tracker ownership means one named maintainer or maintainer team is accountable for keeping `docs/plan/` current, challenging invalid checkbox flips, and approving phase-gate changes or scope moves.

Governance rules acceptance means the maintainer team uses this tracker as the working governance document for phase planning, scope boundaries, and delivery expectations.

Update the record below when governance roles or operating conventions change:

| Governance item | Current record | Update location |
|---|---|---|
| Tracker owner | `Aegiscudo Tech Lead` | This file under Governance Record and Plan Status |
| Maintainer team | `Aegiscudo Tech Lead`, `Aegiscudo Tech Writer` | This file under Governance Record and Plan Status |
| Governance rules accepted by maintainers | `Yes` | This file under Governance Record and Plan Status |
| Phase gate review model | PR template, maintainer review, and required `CI` plus `Security` checks. Hard branch protection and the remaining release gates stay tracked in Phase 1D plus [005-mvp-validation-release.md](005-mvp-validation-release.md). | This file under Governance Record and Plan Status |

- Tracker owner: `Aegiscudo Tech Lead`
- Maintainer team: `Aegiscudo Tech Lead`, `Aegiscudo Tech Writer`
- Effective date: `2026-05-06`

Copilot instructions, agent files, and subagent scaffolding are implementation aids only. They do not assign governance roles by themselves, but the maintainer assignment above now settles tracker ownership and governance acceptance.

Legend: checked governance-policy rows in this file mean the review rule is adopted and wired into maintainer review. Checked phase-gate rows mean the underlying capability is actually delivered. Future phase-exit rows below stay open until the corresponding product work is actually delivered.

## Tracker Conventions

- [x] Use one checkbox per independently verifiable outcome.
- [x] Keep implementation, tests, docs, and observability in the same task group.
- [x] Mark a task complete only after tests are committed or an approved exception is recorded.
- [x] Add a short owner/date note beside long-lived blocked tasks.
- [x] Preserve phase boundaries unless the PRD is revised or maintainers explicitly approve a scope move.
- [x] Keep each phase file focused enough to fit into one implementation context.
- [x] Link from tasks to design decisions, PRs, issues, threat models, schema versions, or test reports when available.

## Scope Guardrails

- [x] MVP remains npm and PyPI first.
- [x] Cargo, Maven, OCI/Docker, IDE extension scanning, GUAC, VSA production, and high-fidelity detonation remain Phase 2/3 unless explicitly re-scoped.
- [x] Mosquito Net is protocol-specific configured proxying, not packet-level transparent proxying.
- [x] Smart fallback is allowed only for eligible resolver metadata flows.
- [x] Explicit pinned versions, tarball URLs, or lockfile integrity references are never silently substituted.
- [x] LLM output is advisory and never the sole enforcement authority.
- [x] Surgeon never calls an AI CLI and never sends whole source files to AI Analyst.
- [x] Attestation, provenance, Trusted Publisher, and signature signals are treated as identity/integrity evidence, not proof of benign code.

## Definition Of Done Review Policy

- [x] PRs include unit tests covering positive, negative, boundary, and adversarial cases for changed logic.
- [x] PRs include integration tests for any service boundary or persistence behavior touched.
- [x] PRs include E2E or workflow tests for user-visible behavior changes.
- [x] PRs include Playwright coverage for affected Command Center user flows.
- [x] PRs include security regression tests for security-sensitive behavior.
- [x] PRs version and validate JSON schema or OpenAPI contract changes.
- [x] PRs add or update observability for latency, errors, security decisions, and degraded states.
- [x] PRs add or update audit events for admin actions, policy mutations, overrides, credentials, and package decisions they touch.
- [x] PRs update documentation and Copilot instructions when architecture or patterns change.
- [x] PRs pass CI quality gates locally or in CI before merge.

## Engineering Review Policy

- [x] PRs follow the TDD loop: failing test, minimal implementation, refactor, re-run tests.
- [x] PRs use typed DTOs and schemas at all service boundaries.
- [x] PRs use explicit error types in Rust service code.
- [x] PRs avoid panics outside startup validation.
- [x] PRs add timeouts, retries, and circuit breakers for all external calls they touch.
- [x] PRs never log secrets, tokens, auth headers, package-manager credentials, environment variables, or raw credential values.
- [x] PRs include tenant scoping and RBAC checks in repository and API layers where applicable.
- [x] PRs store every policy decision they touch with policy snapshot ID and feed snapshot age or state.
- [x] PRs store every package decision and admin mutation they touch as append-only audit evidence.

## Gate Enforcement

Repo-side enforcement should use the following path:

1. Pull requests must use the repository PR template to declare affected phase files, validation commands, documentation updates, and any requested exceptions.
	The template also captures Definition of Done and engineering-practice acknowledgements for maintainer review.
2. Required status checks on `main` should include at least the `CI` and `Security` workflows.
3. Phase entry or exit checkbox changes, scope moves, and governance record changes require maintainer review.
4. The active phase file and [008-traceability-matrix.md](008-traceability-matrix.md) must be updated whenever requirement coverage or gate state changes.
5. Project-management enforcement may mirror the tracker by using a GitHub Project field, milestone rule, or equivalent workflow when maintainers want stronger process automation.

For this repository, phase-gate review is considered satisfied by the PR template, maintainer review, and required `CI` plus `Security` checks. Hard merge protection and the remaining Phase 1D release gating stay tracked in [005-mvp-validation-release.md](005-mvp-validation-release.md).

## Phase Gate Checklist

### Phase 0 Entry

- [x] PRD is accepted as source of truth.
- [x] Initial repository is initialized.
- [x] Plan tracker files exist under `docs/plan`.
- [x] Maintainers agree on MVP scope and implementation stack.
	- Note: current MVP scope and stable implementation stack are the PRD-aligned Rust 2024, Python 3.12, and Next.js 16 foundations already recorded across this tracker, [001-foundation.md](001-foundation.md), and the repository instructions.

### Phase 0 Exit

- [x] Monorepo scaffolding exists for Rust, Python, Next.js, migrations, schemas, infra, testdata, docs, and CI placeholders.
- [x] Shared domain models compile and serialize correctly.
- [x] Local Docker Compose starts backing dependencies.
- [x] Baseline lint, format, unit-test, and schema-validation commands exist.
- [x] `.env.example`, `.gitignore`, and secret-handling rules are present.

### Phase 1A Exit

- [ ] Mosquito Net can serve npm/PyPI fixture metadata and artifacts through configured proxy records.
- [ ] Triage Counter returns deterministic allow, warn, quarantine, block, HITL, and fallback decisions.
- [ ] npm fallback is implemented only for eligible metadata flows.
- [ ] PyPI candidate filtering preserves valid Simple API behavior.
- [ ] Audit and override flows are persisted and enforce expiry.
- [ ] Feed Harvester supplies last-successful snapshots for MVP feeds.

### Phase 1B Exit

- [ ] Surgeon produces schema-valid evidence for npm and PyPI artifacts.
- [ ] Emergency Room executes npm and PyPI sandbox profiles with canaries and telemetry.
- [ ] AI Analyst returns schema-valid advisory explanations from redacted evidence only.
- [ ] Langfuse self-hosting and trace IDs are wired into explanations.
- [ ] Analysis outputs update Triage Counter decisions or HITL state.

### Phase 1C Exit

- [x] Command Center supports quarantine/evidence review, registry proxies, policy simulator, audit, AI providers, integrations, and core dashboards.
  - [x] Registry Proxies admin panel with adapter badge, mode badge, enabled state, delete with confirm
  - [x] AI Providers admin panel with provider type, model, local/cloud badge, active state
  - [x] Integrations & Credentials panel with configured state, test-connection action, delete
  - [x] Audit Log panel with action/actor filters, expandable metadata, refresh
  - [x] Policy Simulator panel with profile selection, 7/14/30-day replay, ecosystem filter, and before/after decision diff table
  - [x] Shell nav wired with typed `NavKey` state machine routing to each admin panel
  - [x] Playwright E2E spec for all four admin panels with route mocking
  - [x] Focused Playwright E2E spec for the policy simulator workflow with route-mocked replay/profile responses
- [x] `aedo-cli` supports auth, npm/PyPI scans, explain, policy test, CI preflight, JSON/text/SARIF output, and correct exit codes.
- [ ] RBAC-protected admin workflows and mock identity are covered by tests.

### Phase 1D Exit

- [ ] Mandatory E2E scenarios pass against fixture registries.
- [ ] Production readiness gate is fully checked or explicitly deferred with owner approval.
- [ ] Release, Docker publish, security scan, and quality-gate workflows are operational.
- [ ] Alpha runbook and operations docs are complete.

## Architecture Decisions

- [x] Architecture decisions are recorded under [docs/adr](../adr/README.md).
- [x] Service runtime allocation is recorded in [ADR 0003](../adr/0003-service-runtime-allocation-by-responsibility.md).
- [x] MVP cache, queue, and object-storage substrates are recorded in [ADR 0004](../adr/0004-mvp-cache-queue-and-object-storage-substrates.md).
- [x] Local alpha and production auth boundary is recorded in [ADR 0005](../adr/0005-interface-auth-boundary-for-local-alpha-and-production.md).
- [x] OpenAPI contract source-of-truth and generated type workflow is recorded in [ADR 0006](../adr/0006-openapi-contract-source-of-truth-and-generated-type-workflow.md).

Coverage thresholds remain a governance and release-gate policy, not an ADR. The machine-readable source of truth for CI is `scripts/coverage-thresholds.json`, and the baseline ratchet below mirrors that file. Raise floors when new tests land; do not lower them without maintainer approval plus a tracker update in this file and [005-mvp-validation-release.md](005-mvp-validation-release.md).

## Coverage Thresholds

Generated packages without handwritten runtime behavior are currently excluded from line-coverage gates. That means the generated TypeScript contract package is not part of the active threshold set.

| Runtime | Target | Minimum line coverage |
|---|---|---|
| TypeScript | `apps/command-center` | `60.0%` |
| Python | `services/ai-analyst` | `80.0%` |
| Python | `services/emergency-room` | `85.0%` |
| Python | `services/python-common` | `95.0%` |
| Rust | `cli/aedo-cli` | `78.5%` |
| Rust | `crates/aegiscudo-core` | `92.0%` |
| Rust | `crates/aegiscudo-policy` | `93.5%` |
| Rust | `crates/aegiscudo-protocol` | `77.5%` |
| Rust | `crates/aegiscudo-telemetry` | `75.0%` |
| Rust | `services/aegiscudo-api` | `5.5%` |
| Rust | `services/feed-harvester` | `13.5%` |
| Rust | `services/mosquito-net` | `71.5%` |
| Rust | `services/surgeon` | `76.0%` |
| Rust | `services/triage-counter` | `69.0%` |
