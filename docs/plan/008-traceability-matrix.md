# PRD Traceability Matrix

Source PRD: [docs/prd/aegiescudo-prd.md](../prd/aegiescudo-prd.md)

Use this matrix to keep the implementation plans tied to the PRD. Mark a row complete only when the linked implementation, tests, docs, and acceptance evidence are complete.

Progress note: 2026-05-05 Phase 0 foundation and a first Phase 1 scaffold are implemented and locally validated. Rows below remain open unless their full PRD acceptance evidence is complete; partial scaffold progress is noted in the linked phase trackers.
Progress note: 2026-05-06 initial baseline was pushed to GitHub `main`; a reviewed foundation slice added Python contract models, deterministic fixture coverage, default metric catalogs, config/fail-closed helpers, and the request-time decision `mode` field. Phase rows remain open unless their full acceptance evidence exists.

Legend: a checked row in this matrix means the linked requirement has acceptance evidence, not just a review policy or scaffold. Open rows may still include partial-progress notes.

## Feature Traceability

| PRD Area | Primary Plan | Status |
|---|---|---|
| Feasibility corrections and MVP scope | [000-delivery-governance.md](000-delivery-governance.md), [README.md](README.md) | [x] |
| The Surgeon agent rules and autonomy limits | [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md) | [ ] |
| npm registry-compatible proxy | [002-mvp-control-plane.md](002-mvp-control-plane.md) | [ ] |
| PyPI Simple API-compatible proxy | [002-mvp-control-plane.md](002-mvp-control-plane.md) | [ ] |
| Provenance, signature, attestation semantics | [002-mvp-control-plane.md](002-mvp-control-plane.md), [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md) | [ ] |
| Threat intelligence feeds | [002-mvp-control-plane.md](002-mvp-control-plane.md), [006-phase-2-expansion.md](006-phase-2-expansion.md) | [ ] |
| Surgeon static analysis engine | [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md) | [ ] |
| Emergency Room sandbox engine | [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md), [007-phase-3-enterprise.md](007-phase-3-enterprise.md) | [ ] |
| Command Center dashboard | [004-mvp-command-center-cli.md](004-mvp-command-center-cli.md) | [ ] Shell and seeded dashboard scaffold implemented; full workflows pending. |
| `aedo-cli` MVP commands | [004-mvp-command-center-cli.md](004-mvp-command-center-cli.md) | [ ] Command surface and parser scaffold implemented; API integration pending. |
| `aedo-cli` Phase 2 commands | [006-phase-2-expansion.md](006-phase-2-expansion.md) | [ ] |
| `aedo-cli` Phase 3 Docker commands | [007-phase-3-enterprise.md](007-phase-3-enterprise.md) | [ ] |
| Registry Proxies admin UI | [004-mvp-command-center-cli.md](004-mvp-command-center-cli.md) | [ ] |
| AI Providers admin UI | [004-mvp-command-center-cli.md](004-mvp-command-center-cli.md) | [ ] |
| Integrations admin UI | [004-mvp-command-center-cli.md](004-mvp-command-center-cli.md) | [ ] |
| Multi-provider LLM support | [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md), [004-mvp-command-center-cli.md](004-mvp-command-center-cli.md) | [ ] |
| Langfuse observability and prompt management | [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md), [004-mvp-command-center-cli.md](004-mvp-command-center-cli.md) | [ ] |
| SBOM generation | [006-phase-2-expansion.md](006-phase-2-expansion.md) | [ ] |
| OpenVEX suppression | [006-phase-2-expansion.md](006-phase-2-expansion.md) | [ ] |
| Cargo support | [006-phase-2-expansion.md](006-phase-2-expansion.md) | [ ] |
| Maven/JVM support | [006-phase-2-expansion.md](006-phase-2-expansion.md) | [ ] |
| OCI/Docker support | [007-phase-3-enterprise.md](007-phase-3-enterprise.md) | [ ] |
| IDE/extension scanning | [007-phase-3-enterprise.md](007-phase-3-enterprise.md) | [ ] |
| High-fidelity detonation worker | [007-phase-3-enterprise.md](007-phase-3-enterprise.md) | [ ] |
| Compliance mapping and reports | [006-phase-2-expansion.md](006-phase-2-expansion.md), [007-phase-3-enterprise.md](007-phase-3-enterprise.md) | [ ] |
| CI/CD pipeline | [005-mvp-validation-release.md](005-mvp-validation-release.md) | [ ] CI/security/release workflow scaffolds implemented; dry runs and full gates pending. |
| TDD and quality gates | [000-delivery-governance.md](000-delivery-governance.md), [005-mvp-validation-release.md](005-mvp-validation-release.md) | [ ] Baseline local gates pass, the PR template encodes Definition of Done plus engineering-practice review, schema validation and OpenAPI contract sync are wired, and integration/E2E/coverage gates remain pending. |

## MVP Cut Line Traceability

| MVP Requirement | Plan Task Location | Status |
|---|---|---|
| npm proxy with metadata filtering and tarball cache | [002-mvp-control-plane.md](002-mvp-control-plane.md) | [ ] |
| npm lifecycle script detection | [002-mvp-control-plane.md](002-mvp-control-plane.md), [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md) | [ ] |
| npm fallback only for safe resolver flows | [002-mvp-control-plane.md](002-mvp-control-plane.md), [005-mvp-validation-release.md](005-mvp-validation-release.md) | [ ] |
| npm provenance attestation verification | [002-mvp-control-plane.md](002-mvp-control-plane.md) | [ ] |
| PyPI candidate filtering and distribution cache | [002-mvp-control-plane.md](002-mvp-control-plane.md) | [ ] |
| PyPI install/import sandbox profile | [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md) | [ ] |
| PyPI digital attestation verification | [002-mvp-control-plane.md](002-mvp-control-plane.md) | [ ] |
| Triage Counter deterministic policy engine | [002-mvp-control-plane.md](002-mvp-control-plane.md) | [ ] In-memory decision-state engine, full MVP decision states, response `mode`, DecisionRequest HTTP binding, PostgreSQL policy loading, and repository-backed immutable snapshot creation implemented; persisted decisions, cache, analysis jobs, metrics, and real signal derivation pending. |
| npm/PyPI candidate metadata maintainer signals (account age, recent changes, count, new-maintainer ratio) | [002-mvp-control-plane.md](002-mvp-control-plane.md) | [ ] |
| Surgeon npm/PyPI static analyzer | [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md) | [ ] Directory scanner and MVP regex indicators implemented; archive unpacking/AST parsing pending. |
| Sleeper pattern detection | [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md) | [ ] |
| AI agent injection detection | [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md) | [ ] |
| Emergency Room Cloud Run Jobs MVP profile | [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md) | [ ] |
| Phase A–H sandbox execution phase attribution in evidence records | [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md) | [ ] |
| AI agent canary files | [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md) | [ ] |
| Feed Harvester OSV, GHSA, OpenSSF Malicious Packages | [002-mvp-control-plane.md](002-mvp-control-plane.md) | [ ] |
| Dashboard quarantine queue and evidence viewer | [004-mvp-command-center-cli.md](004-mvp-command-center-cli.md) | [x] |
| Policy simulator with 30-day historical replay | [004-mvp-command-center-cli.md](004-mvp-command-center-cli.md) | [x] |
| `aedo-cli` package-lock and requirements scans | [004-mvp-command-center-cli.md](004-mvp-command-center-cli.md) | [x] |
| AI explanation from redacted evidence only | [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md) | [ ] |
| Audit logging, RBAC, shadow mode, and time-bound overrides | [002-mvp-control-plane.md](002-mvp-control-plane.md), [004-mvp-command-center-cli.md](004-mvp-command-center-cli.md) | [ ] |

## User Story Acceptance Traceability

| User Story | Acceptance Evidence | Status |
|---|---|---|
| Developer installs known safe package | npm fixture E2E, cached decision benchmark, audit event assertion in [005-mvp-validation-release.md](005-mvp-validation-release.md) | [ ] |
| CI requests newly published npm latest version | npm fallback E2E and lockfile substitution regression in [005-mvp-validation-release.md](005-mvp-validation-release.md) | [ ] |
| Security specialist reviews suspicious evidence | Evidence viewer Playwright test and analysis integration test in [004-mvp-command-center-cli.md](004-mvp-command-center-cli.md) and [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md) | [ ] |
| Administrator configures onboarding in shadow mode | Registry config UI test, shadow-mode E2E, policy simulator test in [004-mvp-command-center-cli.md](004-mvp-command-center-cli.md) and [005-mvp-validation-release.md](005-mvp-validation-release.md) | [ ] |
| CISO views organizational risk reduction | Executive/KPI dashboard seeded tests and export tests in [004-mvp-command-center-cli.md](004-mvp-command-center-cli.md) | [ ] |

## Non-Functional Requirement Traceability

| NFR | Plan Location | Status |
|---|---|---|
| Prompt injection defenses | [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md), [005-mvp-validation-release.md](005-mvp-validation-release.md) | [ ] |
| Data privacy and PII handling | [001-foundation.md](001-foundation.md), [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md) | [ ] Redaction utilities, strict Python DTOs, audit metadata sensitive-key rejection, and local LLM URL boundary helpers exist; prompt construction/redaction and service wiring remain pending. |
| Sandbox security boundaries | [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md), [005-mvp-validation-release.md](005-mvp-validation-release.md) | [ ] |
| Policy guardrails | [002-mvp-control-plane.md](002-mvp-control-plane.md) | [ ] |
| Rate limiting — per-tenant API and per-client package request limits | [002-mvp-control-plane.md](002-mvp-control-plane.md), [007-phase-3-enterprise.md](007-phase-3-enterprise.md) | [ ] |
| External dependency failure policy | [002-mvp-control-plane.md](002-mvp-control-plane.md), [005-mvp-validation-release.md](005-mvp-validation-release.md) | [ ] |
| Reliability and latency budgets | [002-mvp-control-plane.md](002-mvp-control-plane.md), [005-mvp-validation-release.md](005-mvp-validation-release.md) | [ ] |
| Observability | [001-foundation.md](001-foundation.md), [002-mvp-control-plane.md](002-mvp-control-plane.md), [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md), [005-mvp-validation-release.md](005-mvp-validation-release.md) | [ ] Trace/log/health foundations and default Prometheus metric catalogs implemented; service-specific metric emission and traces pending. |
| LLM observability | [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md), [004-mvp-command-center-cli.md](004-mvp-command-center-cli.md) | [ ] |
| TypeScript typecheck (`tsc --noEmit`) in CI and local validation | [004-mvp-command-center-cli.md](004-mvp-command-center-cli.md), [005-mvp-validation-release.md](005-mvp-validation-release.md) | [x] |
| Dockerfile naming convention and base images (distroless/slim/alpine) | [005-mvp-validation-release.md](005-mvp-validation-release.md) | [ ] Dockerfiles exist; Python multi-stage hardening and build verification pending. |
| pgvector embedding store (MVP schema placeholder; Phase 2 population) | [001-foundation.md](001-foundation.md), [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md), [006-phase-2-expansion.md](006-phase-2-expansion.md) | [x] |
| LLM-as-judge evaluation via Langfuse | [006-phase-2-expansion.md](006-phase-2-expansion.md) | [ ] |
| Notification and alerting webhook integrations (Slack/PagerDuty/Jira) | [007-phase-3-enterprise.md](007-phase-3-enterprise.md) | [ ] |
| SBOM and VEX | [006-phase-2-expansion.md](006-phase-2-expansion.md) | [ ] |
| Compliance mapping | [006-phase-2-expansion.md](006-phase-2-expansion.md), [007-phase-3-enterprise.md](007-phase-3-enterprise.md) | [ ] |
| TDD, coverage, and CI quality gates | [000-delivery-governance.md](000-delivery-governance.md), [005-mvp-validation-release.md](005-mvp-validation-release.md) | [ ] Baseline gates pass, review policy and coverage targets are defined, and coverage enforcement plus full release gates remain pending. |

## Revision Gap Traceability

| Gap ID | Implementation Location | Status |
|---|---|---|
| G1 npm provenance attestation | [002-mvp-control-plane.md](002-mvp-control-plane.md) | [ ] |
| G2 PyPI digital attestation | [002-mvp-control-plane.md](002-mvp-control-plane.md) | [ ] |
| G3 GCVE and NVD degradation context | [002-mvp-control-plane.md](002-mvp-control-plane.md), [006-phase-2-expansion.md](006-phase-2-expansion.md) | [ ] |
| G4 deps.dev API | [006-phase-2-expansion.md](006-phase-2-expansion.md) | [ ] |
| G5 SLSA v1.2 tracking | [002-mvp-control-plane.md](002-mvp-control-plane.md), [007-phase-3-enterprise.md](007-phase-3-enterprise.md) | [ ] |
| G6 sleeper, AI agent injection, worm detection | [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md) | [ ] |
| G7 Feed Harvester and SBOM architecture | [002-mvp-control-plane.md](002-mvp-control-plane.md), [006-phase-2-expansion.md](006-phase-2-expansion.md) | [ ] |
| G8 Feed Harvester and SBOM service definitions | [001-foundation.md](001-foundation.md), [002-mvp-control-plane.md](002-mvp-control-plane.md), [006-phase-2-expansion.md](006-phase-2-expansion.md) | [ ] |
| G9 expanded threat model | [000-delivery-governance.md](000-delivery-governance.md), [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md) | [ ] |
| G10 AI agent canary strategy | [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md) | [ ] |
| G11 SBOM and VEX | [006-phase-2-expansion.md](006-phase-2-expansion.md) | [ ] |
| G12 compliance mapping | [007-phase-3-enterprise.md](007-phase-3-enterprise.md) | [ ] |
| G13 expanded policy signals | [002-mvp-control-plane.md](002-mvp-control-plane.md), [006-phase-2-expansion.md](006-phase-2-expansion.md) | [ ] |
| G14 Surgeon expanded detections and SBOM fragments | [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md), [006-phase-2-expansion.md](006-phase-2-expansion.md) | [ ] |
| G15 expanded CLI commands | [004-mvp-command-center-cli.md](004-mvp-command-center-cli.md), [006-phase-2-expansion.md](006-phase-2-expansion.md), [007-phase-3-enterprise.md](007-phase-3-enterprise.md) | [ ] |
| G16 MVP cut line | [README.md](README.md), [005-mvp-validation-release.md](005-mvp-validation-release.md) | [ ] |
| G17 production readiness gate expansion | [005-mvp-validation-release.md](005-mvp-validation-release.md) | [ ] |
| G18 multi-provider LLM | [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md), [004-mvp-command-center-cli.md](004-mvp-command-center-cli.md) | [ ] |
| G19 no AI CLI and Langfuse | [003-mvp-analysis-ai-sandbox.md](003-mvp-analysis-ai-sandbox.md) | [ ] Surgeon has no AI CLI usage and Langfuse infra exists; LLM trace wiring pending. |
| G20 frontend design system | [004-mvp-command-center-cli.md](004-mvp-command-center-cli.md) | [ ] Theme/sidebar/tooltip scaffold implemented; personalization and visual regression pending. |
| G21 multi-registry proxy | [002-mvp-control-plane.md](002-mvp-control-plane.md), [004-mvp-command-center-cli.md](004-mvp-command-center-cli.md), [ADR 0001](../adr/0001-control-plane-routing-scope-and-mount-path-uniqueness.md) | [ ] Mosquito Net startup loading, configured `/proxy/...` mount-path resolution, loaded enabled mount de-duplication, non-deleted mount-path uniqueness, tenant-scoped FK constraints, and upstream URL userinfo rejection exist. [ADR 0001](../adr/0001-control-plane-routing-scope-and-mount-path-uniqueness.md) closes the Phase 1A routing scope; Admin CRUD, dynamic reload, real adapters, and UI workflows remain pending. |
| G22 CI/CD pipeline | [005-mvp-validation-release.md](005-mvp-validation-release.md) | [ ] Workflow scaffolds implemented; branch protection and dry-run evidence pending. |
| G23 provenance semantics and attestation records | [002-mvp-control-plane.md](002-mvp-control-plane.md) | [ ] |
| G24 KEV, EPSS, quota-aware feeds | [002-mvp-control-plane.md](002-mvp-control-plane.md), [006-phase-2-expansion.md](006-phase-2-expansion.md) | [ ] |
| G25 SBOM standards compatibility | [006-phase-2-expansion.md](006-phase-2-expansion.md) | [ ] |
| G26 degraded-operation policy | [002-mvp-control-plane.md](002-mvp-control-plane.md), [005-mvp-validation-release.md](005-mvp-validation-release.md), [ADR 0002](../adr/0002-degraded-operation-and-fail-mode-precedence.md) | [ ] [ADR 0002](../adr/0002-degraded-operation-and-fail-mode-precedence.md) fixes fail-mode precedence; request-time implementation and validation evidence remain pending. |
| G27 heading consistency | [README.md](README.md) | [ ] |
| G28 Next.js/Tailwind scaffold corrections | [001-foundation.md](001-foundation.md), [004-mvp-command-center-cli.md](004-mvp-command-center-cli.md) | [x] |
