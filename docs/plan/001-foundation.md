# Phase 0 Foundation Plan

Source PRD sections: 3.1 through 3.7, 3.4, 3.5, 4.8, 4.12, 5, 6.

Goal: create the repository, contracts, local infrastructure, and safety rails that all later implementation depends on.

## Phase Status

- [x] Phase 0 has an owner: `Aegiscudo Tech Lead`.
- [ ] Exit criteria are approved.
- [ ] All foundation tasks are tracked in issues or PRs.
- [ ] Phase 0 exit review is complete.

Progress note: 2026-05-05 implementation completed the foundation scaffold and local validation suite. Formal owner assignment, issue/PR tracking, approval, and exit review remain maintainer actions.
Progress note: 2026-05-06 validated local Docker Compose boot with current Langfuse v3 dependencies, added a containerized migration dry-run check, closed missing-ID DTO validation coverage, and recorded Feed Harvester plus SBOM Service language decisions.
Progress note: 2026-05-06 added shared Python logging configuration with default sensitive-key redaction, wired it into Emergency Room and AI Analyst, covered adversarial redaction cases with tests, and added Python service trace ID plus metrics shell routes.

## Exit Criteria

- [x] Repository structure matches the PRD bootstrap tree or a documented equivalent.
- [x] Shared domain models compile and have serialization tests.
- [x] JSON schemas exist for policy, evidence, decision, sandbox telemetry, audit events, and attestation evidence.
- [x] Initial database migrations create core tenant, user, policy, registry, package, artifact, analysis, sandbox, AI, feed, credential, override, and audit tables.
- [x] Local Docker Compose starts PostgreSQL, Redis or NATS, object storage emulator, telemetry collector, and Langfuse dependencies.
- [x] Test fixture directories and deterministic fake registry strategy are in place.
- [x] Baseline CI jobs exist for Rust, Python, Node, schema validation, and security audit.
- [x] Secret handling and `.env.example` are implemented without committing real credentials.

## Repository Bootstrap

- [x] Create root `Cargo.toml` workspace.
- [x] Create `crates/aegiscudo-core`.
- [x] Create `crates/aegiscudo-policy`.
- [x] Create `crates/aegiscudo-protocol`.
- [x] Create `crates/aegiscudo-telemetry`.
- [x] Create `services/mosquito-net`.
- [x] Create `services/triage-counter`.
- [x] Create `services/surgeon`.
- [x] Create `services/aegiscudo-api`.
- [x] Create `services/emergency-room` Python package.
- [x] Create `services/ai-analyst` Python package.
- [x] Create placeholder for `services/feed-harvester` with final language decision recorded.
- [x] Create placeholder for `services/sbom-service` with final language decision recorded.
- [x] Create `cli/aedo-cli`.
- [x] Create `apps/command-center` Next.js workspace.
- [x] Create `packages/shared-types` for generated or shared TypeScript types.
- [x] Create `infra`, `migrations`, `schemas`, `sandbox-images`, `testdata`, and `docs` subfolders.
- [x] Create `infra/terraform/gcp/` and `infra/terraform/modules/` placeholder directories.
- [x] Create `infra/k8s/base/` and `infra/k8s/overlays/` placeholder directories.
- [x] Create `sandbox-images/npm-runner/Dockerfile` stub for the npm install sandbox container.
- [x] Create `sandbox-images/pypi-runner/Dockerfile` stub for the Python install sandbox container.
- [x] Create `apps/docs-site/` placeholder directory for future documentation site.
- [x] Create `pnpm-workspace.yaml` declaring all npm workspace packages.
- [x] Create root `package.json` with `pnpm@10.33.3` packageManager field and `node>=20.9.0` engine constraint.
- [x] Create component-level architecture docs under `docs/architecture/` with a master document, Mermaid high-level architecture diagram, and PRD section references.
- [x] Add root `.gitignore` covering `.env`, local DB volumes, build artifacts, package caches, coverage, Playwright output, and temporary sandboxes.
 - [x] Add `.env.example` matching PRD bootstrap credentials and comments.
 - [x] Include explicit Langfuse bootstrap variables in `.env.example`: `LANGFUSE_PUBLIC_KEY`, `LANGFUSE_SECRET_KEY`, and `LANGFUSE_HOST`.
 	- Note: local infrastructure defaults now use higher localhost ports to reduce collisions with existing developer services while remaining overridable through `.env`.
- [x] Add `README.md`, `SECURITY.md`, and bootstrap developer docs.
- [x] Add `.github/copilot-instructions.md` from the PRD §6.2 bootstrap guide including all six sections: Architecture Rules, Stack Preferences, Security Requirements, Testing Requirements, Coding Style, and Do Not Do.

## Shared Rust Foundation

- [x] Add workspace dependencies from the PRD with pinned or policy-approved versions.
- [x] Define `PackageEcosystem` with MVP and future enum values.
- [x] Define `PackageCoordinate` with ecosystem, name, version, namespace, and normalized purl support.
- [x] Define `ArtifactDigest` with algorithm and hex value validation.
- [x] Define `PolicyDecision` states exactly as the PRD names them.
- [x] Define `PolicySnapshot` with ID, version, effective time, tenant, and immutable rule hash.
- [x] Define `AuditEvent` with actor, action, resource, tenant, trace ID, timestamp, and redacted metadata.
- [x] Define `AnalysisJob` with package coordinate, artifact digest, tenant, policy snapshot, job state, retry count, and timestamps.
- [x] Define `StaticEvidence`, `SandboxEvidence`, `AiExplanation`, `AttestationEvidence`, and `FeedSnapshot` DTOs.
- [x] Implement serde serialization and deserialization tests for all shared DTOs.
- [x] Implement validation tests for invalid ecosystems, malformed digests, invalid decision states, and missing required IDs.
- [x] Add tracing initialization helper with JSON log formatting and env-filter support.
- [x] Add service health, readiness, metrics, and trace ID helpers in `aegiscudo-telemetry`.

## Python Foundation

- [x] Create root or per-service `pyproject.toml` with Python 3.12 requirement.
- [x] Add `fastapi`, `pydantic`, `httpx`, `tenacity`, `structlog`, `orjson`, cloud SDKs, provider SDKs, and `langfuse` as needed.
- [x] Add `ruff`, `mypy`, `pytest`, and `pytest-asyncio` dev dependencies.
- [ ] Add base Pydantic models aligned with JSON schemas.
- [x] Add logging configuration that redacts sensitive keys by default.
- [ ] Add test helpers for fake HTTP feeds, fake LLM providers, and fake sandbox jobs.
- [x] Add mypy and ruff configuration.
- [x] Add minimal health endpoint tests for Python services.
- [x] Create root `pyproject.toml` with pinned dependency versions from PRD §6.4 (`fastapi>=0.115`, `pydantic>=2.10`, `langfuse>=3.0`, `google-genai>=1.0`, etc.) and `requires-python = ">=3.12"`.
	- Blocker: shared log and structured-event redaction is wired and tested; schema-aligned Pydantic contract models and fake feed/LLM/sandbox helpers are still needed. AI prompt redaction and prompt secret validation remain Phase 1B work.

## Command Center Foundation

- [x] Scaffold Next.js App Router application.
- [x] Use ESLint CLI with flat config, not `next lint`.
- [x] Configure Tailwind CSS v4 with `@tailwindcss/postcss`.
- [x] Use `@import "tailwindcss";` in global CSS.
- [x] Add shadcn/Radix-compatible component structure.
- [x] Add TanStack Query provider.
- [x] Add TanStack Table dependency and sample typed table test.
- [x] Add Framer Motion dependency and reduced-motion utility.
- [x] Add theme CSS custom properties for dark, light, and dim themes.
- [ ] Add command palette dependency and placeholder root provider.
- [x] Add Vitest and Testing Library setup.
- [x] Add Playwright configuration placeholder for Phase 1C/1D.
- [ ] Commit lockfile after dependency installation.
	- Blocker: `cmdk` is installed and lockfiles are generated; command palette root provider/UI wiring and actual VCS commit are still pending.

## Schema And Contract Foundation

- [x] Create `schemas/policy.schema.json`.
- [x] Create `schemas/decision.schema.json`.
- [x] Create `schemas/evidence.schema.json`.
- [x] Create `schemas/sandbox-telemetry.schema.json`.
- [x] Create `schemas/audit-event.schema.json`.
- [x] Create `schemas/attestation-evidence.schema.json`.
- [x] Create `schemas/ai-explanation.schema.json`.
- [x] Create `schemas/feed-snapshot.schema.json`.
- [x] Add schema validation fixtures for every decision state.
- [x] Add schema validation fixtures for static, sandbox, AI, feed, and attestation evidence.
- [x] Add CI command to validate every fixture against schemas.
- [x] Decide OpenAPI authoring or generation workflow.
- [x] Add initial OpenAPI skeleton for public API and internal service APIs.
- [x] Add generated or validated TypeScript contract placeholder.
	- Note: `contracts/openapi/aegiscudo.openapi.yaml` is the source of truth, `pnpm openapi:generate` produces the committed `packages/shared-types/src/generated/aegiscudo-api.ts` artifact, and richer request-client wiring remains Phase 1C work.

## Database And Storage Foundation

- [x] Add `migrations/0001_init.sql` for tenants, users, roles, and RBAC joins.
- [x] Add registry configuration table with all PRD fields.
- [x] Add package requests table with tenant, registry config, client type, coordinate, trace ID, and timestamps.
- [x] Add artifacts and artifact files tables with digest uniqueness.
- [x] Add policy versions and policy decisions tables.
- [x] Add analysis jobs and static analysis reports tables.
- [x] Add sandbox runs table.
- [x] Add artifact attestations table.
- [x] Add AI explanations table with Langfuse trace ID fields.
- [x] Add vulnerability and malware match tables.
- [x] Add overrides table with reason, approver, scope, and expiry.
- [x] Add integration credentials metadata table without storing raw credential values.
- [x] Add AI provider configs table.
- [x] Add audit events table with append-only expectations.
- [x] Add feed snapshots table with `fresh`, `stale`, `degraded`, and `unavailable` states.
- [x] Add `user_settings` table for persisted personalization (theme, density, glow intensity, animation speed, sidebar mode, dashboard layout) per user.
- [x] Add `pgvector` extension to the initial migration for future embedding support (used for clustering malicious code slices and historical case retrieval in Phase 2).
- [x] Add tenant scoping indexes for common dashboard and request-time queries.
- [x] Add migration tests or dry-run checks.
- [x] Choose local object storage emulator and create bucket bootstrap script.

## Local Infrastructure

- [x] Create `infra/docker-compose.yml` with PostgreSQL for Aegiscudo.
- [x] Add separate PostgreSQL database or instance for Langfuse.
- [x] Add Redis or NATS service.
- [x] Add object storage emulator or local filesystem abstraction.
- [x] Add OpenTelemetry collector or documented local trace/log path.
- [x] Add Langfuse service and required environment variables.
- [x] Add fake npm registry fixture service strategy.
- [x] Add fake PyPI Simple API fixture service strategy.
 - [x] Add Makefile targets for `up`, `down`, `test`, `lint`, `fmt`, `typecheck`, `migrate`, `seed`, `build`, `docker-build`, `integration-test`, and `e2e-test`.
 - [x] Implement `make typecheck` to run `tsc --noEmit` for `apps/command-center` and any TypeScript workspace packages.
- [x] Implement `make integration-test` as a Docker-Compose-based target that starts backing services and runs service integration tests.
- [x] Implement `make e2e-test` as a target that starts all services with seeded fixture registries and runs Playwright + aedo-cli E2E scenarios.
- [x] Add health check commands for each local dependency.
	- Blocker: Make targets and Compose health checks exist; `integration-test` and `e2e-test` still need full service implementation before they can be treated as passing release gates.

## Testdata And Fixture Strategy

- [x] Create benign npm package fixture.
- [ ] Create benign PyPI wheel fixture.
- [x] Create npm postinstall malicious fixture.
- [x] Create Python `exec` or import-time behavior fixture.
- [x] Create archive traversal fixture.
- [x] Create decompression bomb or oversized package fixture with safe test generation.
- [ ] Create npm packument fixture with signed, unsigned, and bad-signature versions.
- [ ] Create PyPI Simple API fixture with `data-provenance` and bad provenance references.
- [x] Create known-malicious feed fixture.
- [ ] Create OSV/GHSA vulnerability fixture.
- [ ] Create canary-access sandbox fixture.
- [x] Document fixture generation and update process.
	- Blocker: benign PyPI source fixture plus OSV and OpenSSF fixture examples exist; built wheel, GHSA, canary sandbox, signed npm packument, and PyPI provenance fixtures remain before adapter/E2E tasks can start.

## Security And Observability Baseline

- [x] Add redaction utility for logs and structured events.
- [x] Add trace ID propagation conventions and shared Python service middleware.
- [x] Add `/healthz`, `/readyz`, and `/metrics` route conventions plus Python shell routes.
- [ ] Add default Prometheus metric names for request, decision, analysis, sandbox, feed, and LLM operations.
- [ ] Add startup validation for required environment variables.
- [ ] Add rule that missing required bootstrap credentials fail fast where required by PRD.
- [x] Add local secrets guidance and production secrets-manager guidance.
- [ ] Add secure defaults for fail-closed enforcement mode.
	- Blocker: route conventions, Python shell routes, trace IDs, and log/structured-event redaction utilities exist; operation-specific metric names, startup env validation, and enforcement-mode wiring remain Phase 1 work.

## Phase 0 Validation

- [x] `cargo fmt --all --check` passes.
- [x] `cargo clippy --workspace -- -D warnings` passes for scaffold code.
- [x] `cargo test --workspace` passes.
- [x] `pnpm lint` passes.
- [x] `pnpm test` passes.
- [x] `uv run ruff check services/emergency-room services/ai-analyst` passes.
- [x] `uv run mypy services/emergency-room services/ai-analyst` passes.
- [x] `uv run pytest` passes.
- [x] Schema validation command passes.
- [x] Local Docker Compose boots required services.
