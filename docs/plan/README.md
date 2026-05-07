<p align="center">
	<img src="../../assets/aegiscudo-logo.png" alt="Aegiscudo logo" width="220" />
</p>

# Aegiscudo Implementation Plans

Source PRD: [docs/prd/aegiescudo-prd.md](../prd/aegiescudo-prd.md)

This folder breaks the PRD into smaller implementation trackers so future work can load only the plan file that matters for the current phase. Each file is meant to be updated as work lands. Keep checkboxes current and add links to PRs, issues, design notes, or test reports when they exist.

Legend: checked rows in the operating sections below mean the planning rule is adopted. Checked roadmap or tracker status rows mean the linked phase or tracker is complete by its own exit criteria.

Progress note: 2026-05-06 the initial baseline was pushed to the GitHub `main` branch. Phase 0 remains open pending the remaining service-wiring items and formal maintainer exit process.

## How To Use These Plans

- [x] Start each work session from this index and the single phase file being implemented.
- [x] Update checkboxes in the relevant phase file when code, tests, and docs are complete.
- [x] Update [008-traceability-matrix.md](008-traceability-matrix.md) when a PRD requirement is implemented, deferred, or intentionally changed.
- [x] Keep tasks small enough that one checkbox can be completed by one focused PR or a small PR series.
- [x] Do not treat a task as complete until its tests and observability requirements are done.
- [x] Re-read the PRD before changing phase scope or moving a Phase 2/3 item into MVP.

## Phase Roadmap

- [ ] **Phase 0 - Foundation:** repository scaffolding, shared schemas, local infrastructure, security baseline, test harnesses.
- [ ] **Phase 1A - MVP Control Plane:** Triage Counter, Mosquito Net, npm/PyPI proxying, registry configs, audit, overrides, feed snapshots.
- [ ] **Phase 1B - MVP Analysis Plane:** Surgeon static analysis, Emergency Room sandbox profiles, AI Analyst, Langfuse instrumentation.
- [ ] **Phase 1C - MVP Interfaces:** Command Center dashboard, admin workflows, `aedo-cli`, generated/validated API clients.
- [ ] **Phase 1D - MVP Validation and Release:** end-to-end tests, production readiness gates, CI/CD, Docker publication, alpha operations.
- [ ] **Phase 2 - Ecosystem and Compliance Expansion:** SBOM/VEX, deps.dev/Scorecard, Cargo, Maven, GitHub Actions scanning, expanded CLI.
- [ ] **Phase 3 - Enterprise and Deep Detonation:** OCI/Docker, IDE extension scanning, high-fidelity detonation, CRA reporting, enterprise scale.

## Plan Files

| Tracker | Scope | Status |
|---|---|---|
| [000-delivery-governance.md](000-delivery-governance.md) | Tracker rules, Definition of Done, release discipline, scope hygiene | [x] |
| [001-foundation.md](001-foundation.md) | Monorepo scaffolding, shared types, schemas, migrations, local infra, fixture harnesses | [ ] |
| [002-mvp-control-plane.md](002-mvp-control-plane.md) | Request-time services, policy, proxy adapters, feed snapshots, audit, overrides | [ ] |
| [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md) | Static analysis, sandbox orchestration, AI explanation, Langfuse, evidence lifecycle | [ ] |
| [004-mvp-command-center-cli.md](004-mvp-command-center-cli.md) | Dashboard, admin UI, CLI, auth/RBAC surfaces, user workflows | [ ] |
| [005-mvp-validation-release.md](005-mvp-validation-release.md) | CI gates, security tests, E2E, performance budgets, Docker/release workflows | [ ] |
| [006-phase-2-expansion.md](006-phase-2-expansion.md) | SBOM/VEX, Cargo/Maven, expanded feeds, GitHub Actions scan, policy evolution | [ ] |
| [007-phase-3-enterprise.md](007-phase-3-enterprise.md) | OCI/Docker, IDE scanners, high-fidelity workers, enterprise compliance and scale | [ ] |
| [008-traceability-matrix.md](008-traceability-matrix.md) | PRD-to-plan coverage and acceptance scenario tracking | [ ] |

## Dependency Order

- [x] Complete Phase 0 contracts before implementing service-specific persistence or UI API clients.
- [x] Complete Triage Counter decision DTOs before Mosquito Net request enforcement.
- [x] Complete evidence schemas before Surgeon, Emergency Room, AI Analyst, and Evidence Viewer work begins.
- [x] Complete audit/event schema before admin, override, credential, and policy mutation endpoints.
- [x] Complete fixture registries before npm/PyPI protocol compatibility testing.
- [x] Complete local Docker Compose dependencies before integration and E2E suites become required gates.
- [x] Complete MVP request-time happy path before enabling expensive sandbox or LLM paths by default.

## Completion Rules

- [x] A checkbox means implemented, tested, documented where relevant, and verified in CI or a local equivalent.
- [x] A parent checkbox is complete only when all nested work in the same section is complete.
- [x] A deferred checkbox must include a short note explaining why it moved phases.
- [x] A blocked checkbox must name the missing decision, dependency, credential, fixture, or platform capability.
- [x] Production readiness gates in [005-mvp-validation-release.md](005-mvp-validation-release.md) are required before alpha exit.
