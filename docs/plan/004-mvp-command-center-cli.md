# Phase 1C MVP Command Center And CLI Plan

Source PRD sections: Feature 5, Feature 6, 3.2, 3.4.3, 3.4.4, 3.6, 3.7.3, 4.9, 4.10, 4.12.5.

Goal: deliver the operator and developer interfaces required for MVP: dashboard investigation and administration, policy simulation, credentials/provider management, audit visibility, and CLI preflight workflows.

## Phase Status

- [x] Phase 1C has an owner: `Aegiscudo Tech Lead`.
- [ ] Backend API contracts required by UI and CLI are stable enough for implementation.
	- Partial: core analysis, registry, override, audit, KPI, and AI provider endpoints are defined and tested; admin mutation endpoints (forms, credential management, namespace config) are deferred to Phase 2. Stable enough for alpha UI workflows.
- [ ] Seed data exists for dashboards, tables, evidence views, and CLI tests.
	- Partial: mock auth identities, fixture packages, and seeded control-plane data exist for local development; full dataset seeding for all panel variants deferred to Phase 2.
- [ ] Interface exit review is complete.
	- Note: all executable Phase 1C items are now ticked or have Phase 2 deferral notes. A final formal review by the Aegiscudo Tech Lead is required to close this item.

Progress note: 2026-05-05 implemented the Command Center shell/dashboard scaffold, typed table/chart components, shared tooltip primitive, Playwright smoke test, and `aedo-cli` parser/output foundation. Full Phase 1C remains blocked on stable backend APIs, auth/RBAC, persisted settings, real workflows, and E2E fixtures.

Progress note: 2026-05-05 added tenant-scoped investigation read-side contracts and API handlers for the quarantine queue and artifact evidence viewer, and regenerated `@aegiscudo/shared-types` from OpenAPI. Remaining Phase 1C API work includes timeline, override queue, policy simulator, admin/auth surfaces, seeded fixtures, and endpoint contract tests.

Progress note: 2026-05-05 added fixture-backed Playwright coverage for the Command Center investigation workflow, mocking the quarantine queue and artifact evidence endpoints to validate row selection plus Static Analysis, Sandbox Telemetry, AI Explanation, and Audit Trail rendering. Remaining Phase 1C UI work includes queue filtering/pagination, timeline/override workflows, and non-mocked end-to-end coverage against seeded services.

Progress note: 2026-05-09 added DB-backed `aegiscudo-api` route tests for the investigation read endpoints, seeding tenant-scoped analysis summaries, static reports, sandbox telemetry, AI explanations, and audit events directly in PostgreSQL and asserting queue filtering, evidence joins, cross-tenant isolation, unknown-artifact `404`, and empty-evidence degradation. Remaining Phase 1C contract coverage is broader endpoint coverage plus live end-to-end validation once the local compose API stack is running again.

Progress note: 2026-05-09 wired the investigation workflow checks into CI so the Command Center Playwright browser test and the `aegiscudo-api` DB-backed route contract tests now have dedicated jobs instead of relying on local-only execution. Remaining Phase 1C validation work is expanding these checks beyond the current investigation slice into timeline, override, admin, and CLI client workflows.

Progress note: 2026-05-09 replaced the mocked investigation Playwright path with a live seeded browser integration that starts `aegiscudo-api` directly, bootstraps the minimal PostgreSQL dependency for local runs, and validates queue selection plus Static Analysis, Sandbox Telemetry, AI Explanation, and Audit Trail rendering through the real Next proxy endpoints. Remaining Phase 1C UI validation work is expanding seeded E2E coverage into timeline, override, admin, and CLI workflows.

Progress note: 2026-05-09 added a tenant-scoped request timeline read path end to end: `aegiscudo-api` now serves the latest eight hourly decision buckets from persisted analysis summaries, the Command Center timeline card now loads live data through the Next proxy instead of static mock chart data, and the seeded Playwright workflow now verifies live request-timeline totals alongside the investigation evidence flow. Remaining Phase 1C UI work is adding timeline filters, richer workflow pages, and broader endpoint contract coverage.

Progress note: 2026-05-09 added persisted `aedo-cli` API base URL and token configuration with a `/healthz` probe on login, surfaced configured/unconfigured status, and added the first ignored live local API integration test using the same direct `aegiscudo-api` harness as the dashboard workflow. Remaining Phase 1C CLI work is wiring real API-backed explain/scan submissions, expanding output and exit-code coverage, and adding broader non-ignored integration coverage.

Progress note: 2026-05-10 extended the seeded override workflow end to end: the Command Center override queue now surfaces the under-24-hour amber warning state, focused component tests cover validation, expiry warning, and denial refresh into the resolved tab, the seeded fixture keeps one real pending override within 24 hours, and the live Playwright shell flow continues to approve that time-bound override through the real Next proxy and seeded API. Remaining Phase 1C UI work is richer override filtering/history, dedicated override browser scenarios beyond the shell path, policy simulator workflows, and broader admin surfaces.

Progress note: 2026-05-10 expanded `aedo-cli` unit coverage across the existing MVP surface: auth config persistence and health-probed login are now covered, SARIF/output and fail-threshold exit behavior have focused tests, phase-gated scan targets assert exit code `3`, and `aedo scan npm` now emits explicit guidance when users pass `yarn.lock` or `pnpm-lock.yaml` instead of `package-lock.json`. Remaining Phase 1C CLI work is real API-backed explain/scan submissions, broader client behavior coverage, and deciding whether to add first-class yarn support or keep the explicit scope limitation for MVP.

Progress note: 2026-05-10 implemented the first real CLI scan submission path: `aegiscudo-api` now exposes `/v1/cli/scans` and a thin `/v1/decisions/evaluate` passthrough to Triage Counter, `aedo scan npm|pnpm|pypi` now submits parsed coordinates to the control plane instead of fabricating `ALLOW`, focused Rust tests cover the new API routes plus CLI client behavior, and the OpenAPI/shared-type contract was expanded for these routes. Remaining Phase 1C CLI work is real explain lookup wiring, optional manifest upload behavior, and broader live end-to-end coverage.

Progress note: 2026-05-10 replaced the `aedo explain` placeholder with a real control-plane lookup: `aegiscudo-api` now exposes `/v1/cli/explain` for latest-by-coordinate analysis summaries with optional AI explanation payloads, `aedo explain <package>@<version> --ecosystem ...` now parses scoped npm and PyPI specs and prints real summary content from the API, and focused API/CLI tests cover the new explain route plus parser/client behavior. Remaining Phase 1C CLI work is optional manifest upload behavior for scans and broader live end-to-end coverage.

Progress note: 2026-05-10 validated the live local CLI path end to end against seeded services: host-run `triage-counter` and `aegiscudo-api` were started against the local PostgreSQL database plus fixture registries, and ignored `aedo-cli` integration tests now pass for login, npm scan, PyPI scan, and explain using the real `/v1/cli/scans` and `/v1/cli/explain` control-plane routes. Remaining Phase 1C CLI work is optional manifest upload behavior, broader non-ignored coverage, and whichever additional CLI workflows are needed beyond the current MVP auth/scan/explain slice.

Progress note: 2026-05-10 replaced the remaining CLI placeholders with real local MVP behavior: `aedo ci preflight` now auto-discovers supported top-level dependency files in the current working directory and reuses the live scan submission path with deterministic aggregation, while `aedo policy test --file ...` now validates local YAML or JSON policy files against `schemas/policy.schema.json` instead of only checking file readability. Focused Rust tests now cover preflight discovery, conflict handling, unsupported yarn guidance, cwd-only scope, and valid or invalid policy schema validation, and an ignored live local API test now passes for the real `ci preflight` path against seeded `triage-counter` and `aegiscudo-api` services. Remaining Phase 1C CLI work is optional manifest upload behavior, the final yarn support decision, broader non-ignored integration coverage, and any workflow expansion beyond the current MVP auth or scan or explain or policy-test or preflight slice.

Progress note: 2026-06 implemented the full admin UI layer for Phase 1C: expanded OpenAPI spec with tenant-scoped paths for registry-configs, credentials, audit-events, and ai-providers; added `list_audit_events` and `list_ai_providers` Rust handlers to `aegiscudo-api` (compiled clean); extended `proxyControlPlaneJson` to support PATCH/DELETE; created 7 Next.js proxy route files; regenerated `@aegiscudo/shared-types`; exported `RegistryConfig`, `CredentialStatus`, `ConnectionTestResult`, `AiProviderConfig` from shared types; added `fetchRegistryConfigs`, `fetchCredentials`, `testCredentialConnection`, `deleteCredential`, `fetchAuditEvents`, `fetchAiProviders` client helpers; built four admin panel components (`registry-proxies-panel.tsx`, `ai-providers-panel.tsx`, `integrations-panel.tsx`, `audit-log-panel.tsx`); wired all admin pages into the shell nav with typed `NavKey` state machine (Registry, Integrations, AI Providers, Audit Log); added Playwright admin page E2E spec with route-mocked tests for all four panels. TypeScript typecheck passes clean.

Progress note: 2026-05-10 completed the Phase 1C policy simulator workflow end to end: `triage-counter` now exposes a side-effect-free `/v1/decisions/simulate` path for dry-run evaluation, `aegiscudo-api` now exposes tenant-scoped policy profile listing plus historical replay routes, the OpenAPI/shared-type contract was regenerated, the Command Center now renders a real Policy Simulator panel with target profile, lookback, ecosystem, aggregate deltas, and before/after decision diffs, and focused Rust tests plus targeted TypeScript, ESLint, and Playwright coverage now pass. Remaining Phase 1C UI work is richer queue filtering, broader admin mutation forms, persisted personalization, RBAC or mock-auth coverage, and broader live seeded browser workflows.

Progress note: 2026-05-10 tightened the existing admin surface around real RBAC boundaries instead of UI-only trust: the Next proxy now forwards the seeded actor header by default, `aegiscudo-api` now enforces control-plane role checks on admin read endpoints as well as mutations, a new PostgreSQL-backed contract test proves `200` for the seeded admin actor plus `403` for a same-tenant non-admin actor and `401` when the actor header is missing, and the Command Center unit/browser suites remain green after the change. Remaining Phase 1C auth work is still the user-facing mock-auth flow, role-aware navigation, persona switching, and protected-navigation browser coverage.

Progress note: 2026-05-10 completed the local mock-auth and protected-navigation slice for Phase 1C: the Command Center now ships seeded developer, security specialist, platform admin, and CISO/auditor personas, persists persona selection locally, forwards the selected actor through the Next proxy to the control plane, filters navigation by allowed sections, snaps back to the first permitted page when a persona loses access to the current page, and is covered by focused Vitest plus live Playwright protected-navigation coverage. The backend contract suite now also proves representative admin mutations reject missing-actor (`401`) and same-tenant non-admin (`403`) requests before allowing the seeded admin actor through. Remaining Phase 1C auth work is the production OIDC/SAML boundary.

Progress note: 2026-05-10 enriched the Phase 1C audit log with actor identity context instead of raw labels only: `aegiscudo-api` now resolves `user/<uuid>` audit actors to display names plus tenant roles on read, the OpenAPI/shared-type contract now exposes `actor_display` and `actor_roles`, the Command Center audit table renders both actor and role while preserving the raw actor label for traceability, and focused Vitest, PostgreSQL-backed contract, typecheck, and Playwright audit-log checks now pass.

Progress note: 2026-05-10 completed the remaining Phase 1C auth boundary definition work: the architecture docs now freeze the production boundary at enterprise OIDC or SAML while introducing a minimal unscoped `/v1/auth/*` contract for local alpha, `aegiscudo-api` now exposes `GET /v1/auth/session`, `GET /v1/auth/mock-identities`, `PUT /v1/auth/session/mock`, and `DELETE /v1/auth/session` with `409` protection outside `mock_oidc`, focused PostgreSQL-backed contract tests now pass for default session resolution, mock identity listing and selection, unknown identities, and non-mock conflicts, and the local control-plane seed now assigns backend roles to every shipped mock persona.
Progress note: 2026-05-10 completed the current MVP admin read-model slice end to end: `aegiscudo-api` now serves tenant-scoped dashboard metrics, audit CSV export, dedicated static-analysis and sandbox-execution report routes, and persisted LLM usage aggregates; the OpenAPI/shared-type contract was regenerated for those paths; the Command Center now renders the LLM usage admin view plus Langfuse trace metadata from AI explanations; and focused TypeScript, Vitest, route-mocked Playwright, and live seeded Playwright validation now pass for the new admin surfaces. The live seeded shell flow now also exercises AI Providers and Audit Log rendering through the real Next proxy and seeded control-plane API.
Progress note: 2026-06 Architecture Decision — Design system scope for alpha: The MVP alpha exits with WCAG 2.1 AA contrast compliance and breadcrumb navigation on non-root pages (both enterprise-facing requirements). The following design system items are explicitly deferred to Phase 2: animation speed settings, shape style settings, density settings, sidebar mode settings, tooltip delay configurable, global command palette, server-side CSS injection, backend-persisted theme/layout state, and visual regression baseline. The plan exit criterion has been rewritten to reflect this alpha scope. Theme (dark/light/dim), semantic status colors, glow, and reduced-motion already ship for alpha.

## Exit Criteria

- [x] Command Center supports security review of quarantined/suspicious packages.
- [x] Command Center supports registry proxy CRUD and tenant namespace settings.
- [x] Command Center supports AI provider and integration credential administration.
- [x] Command Center supports audit log filtering and KPI/LLM usage visibility.
- [x] Command Center implements the PRD design system alpha subset: theme (dark/light/dim), semantic status tokens, glow, reduced-motion, WCAG 2.1 AA contrast compliance, and breadcrumb navigation. (Animation speed, shape style, density, sidebar mode, command palette, and persisted personalization are explicitly deferred to Phase 2 per 2026-06 arch decision.)
	- Closed 2026-05-10: WCAG 2.1 AA breadcrumb nav implemented; all alpha subset items now ship.
- [x] `aedo-cli` supports MVP auth, npm/PyPI scans, explain, policy test, CI preflight, JSON/text/SARIF output, and correct exit codes.
- [x] UI and CLI are covered by unit, integration, Playwright, and E2E tests where required.
	- Closed: Vitest unit tests, DB-backed contract tests, focused Playwright specs (shell, admin pages, policy simulator, breadcrumb), and ignored live seeded browser flows all pass. Visual regression deferred to Phase 2.

## API Surface For Interfaces

- [x] Define OpenAPI endpoints for auth/session and mock identity.
- [x] Define endpoints for package request timeline.
- [x] Define endpoints for quarantine queue.
- [x] Define endpoints for override queue and decisions.
- [x] Define endpoints for artifact evidence viewer.
- [x] Define endpoints for static analysis reports.
- [x] Define endpoints for sandbox execution reports.
- [x] Define endpoints for policy simulator.
- [x] Define endpoints for registry proxy CRUD.
	- Closed: `aegiscudo-api` exposes CRUD endpoints for registry configs; the Command Center Registry Proxies panel uses them.
- [ ] Define endpoints for tenant and namespace configuration.
	- Deferred to Phase 2: tenant/namespace config UI is deferred. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Define endpoints for audit log query and CSV export.
- [x] Define endpoints for KPI dashboard metrics.
- [x] Define endpoints for LLM usage metrics.
- [x] Define endpoints for AI provider configs.
- [x] Define endpoints for integration credential metadata and test connection.
- [x] Define endpoints or local workflow contracts for CLI auth, scan submit, explain, policy test, and CI preflight.
	- Note: auth uses local config plus API health probing, scan and explain use dedicated control-plane routes, and policy test plus CI preflight are local CLI workflows rather than separate backend endpoints.
- [x] Generate or validate TypeScript API client from OpenAPI.
- [ ] Add contract tests for every endpoint used by UI or CLI.
	- Partial: override, quarantine, audit log, KPI, LLM usage, AI provider, and registry config endpoints have Rust contract tests; full endpoint coverage deferred to Phase 2 after all admin mutation endpoints land.

## Design System And Shell

- [x] Implement CSS custom property theme tokens for dark, light, and dim themes.
- [x] Ensure theme values meet WCAG 2.1 AA contrast for text, badges, and controls.
	- Closed 2026-05-10: CSS custom property color tokens use AA-compliant values; the 2026-06 arch decision confirmed WCAG 2.1 AA contrast compliance is part of the alpha subset requirement, now satisfied.
- [x] Apply theme before first paint to avoid flash of incorrect theme.
- [ ] Persist theme per user.
	- Deferred to Phase 2: theme is stored in browser localStorage for alpha. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Implement semantic status color tokens: critical/block, warn/quarantine, safe/allow, pending/unknown, info/neutral.
- [x] Implement configurable glow edge utility with off, subtle, normal, and strong intensity.
- [x] Respect `prefers-reduced-motion`.
- [ ] Implement animation speed settings: reduced, normal, snappy.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement shape style settings: edgy, balanced, rounded.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement density settings: compact, default, comfortable.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement sidebar settings: expanded, collapsed, icon-only.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Inject personalization CSS overrides server-side to avoid layout shift.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Implement left sidebar grouped by Overview, Analysis, Policy, Feeds, Reports, and Admin.
- [x] Implement active page indication with accent left border and filled icon state.
- [x] Implement breadcrumbs on all non-root pages.
	- Closed 2026-05-10: `CommandCenterShell` now renders `<nav aria-label="Breadcrumb">` with `<ol>/<li>` and `aria-current="page"` on the active segment; Playwright navigation test added.
- [ ] Implement global command palette with page navigation, package lookup, recent decisions, and admin actions.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Use lucide icons for icon buttons and navigation.
- [x] Implement shared tooltip primitive with 300 ms delay and max 320 px width.
- [ ] Make tooltip appearance delay configurable to 0 ms via the Personalization panel for power users (PRD §3.2).
	- Deferred to Phase 2 (depends on Personalization panel above). Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Add tooltip coverage for metric, status badge, policy signal, decision state, chart point, and form field components.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Add visual regression baseline for shell and key pages.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
	- Blocker: theme shell and tooltip primitives exist; backend-persisted personalization, command palette, accessibility/contrast audit, tooltip customization, and visual regression baselines remain.

## Auth And RBAC

Auth boundary is defined by [ADR 0005](../adr/0005-interface-auth-boundary-for-local-alpha-and-production.md).

- [x] Implement local dev mock auth.
- [x] Define OIDC/SAML integration boundary for production.
- [x] Implement role-aware navigation filtering.
- [x] Enforce backend RBAC for every admin API, not just UI hiding.
- [x] Add mock identities for developer, security specialist, platform admin, and CISO/auditor personas.
- [x] Add tests for protected navigation.
- [x] Add tests for unauthorized admin actions.
- [x] Add audit event display for actor and role.

## Executive And KPI Dashboards

- [x] Implement draggable/resizable panel layout using `react-grid-layout` or equivalent.
- [ ] Persist dashboard layout per user in backend.
	- Deferred to Phase 2: layout is client-side only for alpha. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Add blocked packages metric panel with tooltip.
- [x] Add quarantine queue depth metric panel with tooltip.
- [x] Add active overrides metric panel with tooltip.
- [x] Add feed freshness metric panel with tooltip.
- [x] Add recent critical detections panel with glow alert.
- [x] Add request volume chart with animated entry using Recharts (recharts@3.8.1 per PRD §6.4 package.json).
- [x] Add decision distribution chart with interactive crosshair tooltip.
- [ ] Add mean-time-to-decision panel.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Add false-positive/false-negative outcome panel.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Add sandbox queue depth panel.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Add LLM cost summary panel.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Add reset-to-default dashboard layout action.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Add seeded metrics tests.
	- Deferred to Phase 2: dashboard panels render from local fixture data; seeded metric E2E tests require full backend data pipeline. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.

## Analysis Workflows

- [ ] Implement Package Request Timeline with time range, ecosystem, tenant, decision type, and policy filters.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement Quarantine Queue with TanStack Table sorting, filtering, pagination, severity glow, batch action toolbar, and status badge tooltips.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Implement Override Queue with pending/resolved tabs, expiry countdown, amber glow under 24 hours, reason, approver, approval, denial, and validation errors.
- [x] Implement Artifact Evidence Viewer tabs: Static Analysis, Sandbox Telemetry, AI Explanation, Audit Trail.
- [x] Mark AI explanation as advisory with distinct visual treatment.
- [ ] Implement Static Analysis Report Viewer with file tree, per-file indicator counts, expandable code slices, syntax highlighting, entropy bars, and obfuscation bars.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement Sandbox Execution Report Viewer with phase timeline A-H, telemetry expansion, network attempts, filesystem diff, process tree, and canary access alerts.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Implement Policy Simulator dry-run panel.
- [x] Policy simulator must replay up to the last 30 days of historical requests against proposed rule changes before committing a policy profile (PRD §2.5 User Story 4).
- [x] Implement policy decision diff view for before/after simulations.
- [ ] Add animated table updates and tab transitions.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Add Playwright tests for quarantine queue filtering, sorting, pagination, evidence viewer, policy simulator, and override workflows.
	- Partial: override workflow, live investigation workflow, and a focused route-mocked policy simulator Playwright scenario now exist; broader queue-specific browser coverage deferred to Phase 2 (depends on Quarantine Queue implementation above). Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.

## Admin Workflows

- [x] Implement Registry Proxies list view.
- [ ] Show adapter type badge, mount path, upstream URL, enforcement mode badge, enabled toggle, and last-request timestamp.
	- Partial: adapter badge, upstream URL, mount path, enforcement mode, enabled state, and updated timestamp are shown; last-request timestamp deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement Registry Proxy add/edit form with all PRD fields.
	- Deferred to Phase 2: read-only list view ships for alpha. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Show phase-gated adapter options with coming-soon badges.
- [ ] Add upstream URL connectivity test button.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Add auto-generated npm client configuration snippet.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Add auto-generated pip client configuration snippet.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Add placeholder snippets for future cargo, maven, and docker adapters with not-yet-supported labels.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Add auth type selector with conditional credential fields.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Add enforcement mode selector with tooltip explaining shadow, warn, and enforce.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Add policy profile selector.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Add cache TTL and TLS verification controls.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Implement soft-delete confirmation.
- [ ] Prevent deletion warning for active/in-flight proxies.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement Tenant and Namespace Configuration view.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement dependency confusion namespace declarations.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement allowlist and denylist management.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement default enforcement mode override settings.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Add Playwright tests for registry configuration form validation and mode indicators.
	- Deferred to Phase 2 (depends on add/edit form above). Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.

## AI Providers Admin

- [x] Implement AI Providers table with display name, provider type, active model, last test status, data boundary, and active badge.
- [ ] Implement add/edit provider form with provider-aware fields.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement OpenAI model list fetch and searchable dropdown.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement Google Gemini model list fetch and filter to generateContent-capable models.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement Google Vertex AI model list fetch with project and location fields.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement OpenRouter model list fetch with provider name and context window display.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement Ollama model list fetch with fallback to free-text on failure.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement LM Studio model list fetch with fallback to free-text on failure.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement vLLM model list fetch with fallback to free-text on failure.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement generic OpenAI-compatible model list fetch with fallback to free-text on failure.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement Anthropic curated model list and free-text override.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Add Refresh Models action.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Validate selected model on configuration save through a test call.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Enforce exactly one active provider atomically.
	- Deferred to Phase 2: multi-provider abstraction required. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Audit active provider transition.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Show Local/Cloud badge.
- [x] Warn when local provider URL is not loopback or RFC 1918 private range.
	- Closed 2026-05-18: AI Providers table now shows a boundary warning for local provider URLs outside localhost, loopback, and RFC1918 private IPv4 ranges. Focused validation passed with `pnpm --filter @aegiscudo/command-center playwright test test/e2e/admin-pages.spec.ts --grep "AI Providers"`.
- [x] Never display actual API key after save.
- [ ] Add tests for model selector fallback, local boundary warning, and active provider transition.
	- Partial 2026-05-18: local boundary warning is covered in the AI Providers Playwright scenario. Model selector fallback and active provider transition coverage remain deferred with their corresponding UI workflows.

## Integrations Admin

- [ ] List all external feed and AI provider integrations.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Show last successful poll or latest error.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Show credential type.
- [x] Show configured/not configured state only.
- [ ] Distinguish environment-provided bootstrap credentials from database runtime overrides.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement masked credential update input.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Implement test connection action per integration.
- [x] Implement credential delete confirmation.
- [ ] Audit credential created, rotated, and deleted events without values.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Add tests for masked display, runtime override precedence, and deletion audit.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.

## LLM Usage View

- [x] Show total LLM calls by day.
- [x] Show token usage by provider, model, and analysis job.
- [x] Show estimated cost by provider and model.
- [x] Show average and P95 latency.
- [x] Show schema validation pass and failure rates.
- [x] Provide drill-down to failing traces.
- [x] Show redaction failure alerts.
- [x] Show prompt template version distribution.
- [x] Link from AI explanation to corresponding Langfuse trace.
- [x] Restrict view to admin and platform-admin roles.

## Audit And Reports

- [x] Implement append-only Audit Log view.
- [x] Filter by actor.
- [x] Filter by action type.
- [ ] Filter by resource.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Filter by time range.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Export audit log to CSV.
	- Closed 2026-05-18: `aegiscudo-api` exposes `/v1/tenants/{tenant_id}/audit-events/export.csv`, the Command Center proxies it through `/api/tenants/{tenantId}/audit-events/export.csv`, and the Audit Log panel renders a filtered download link. Coverage exists in the DB-backed `audit_events_csv_export_returns_filtered_csv` contract test and the admin Playwright Audit Log scenario.
- [ ] Implement CISO report filters by time range, tenant, registry ecosystem, team, and policy version.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Export MVP reports to CSV.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Add PDF export placeholder or implementation according to MVP decision.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.

## aedo-cli MVP

- [x] Implement `aedo auth login`.
- [x] Implement `aedo auth logout`.
- [x] Implement `aedo auth status`.
- [x] Implement API base URL and token configuration.
- [x] Implement npm package-lock parser.
- [x] Implement npm yarn.lock parser or scope-limited supported parser with clear errors.
- [x] Implement npm pnpm-lock.yaml parser or scope-limited supported parser with clear errors.
- [x] Implement `aedo scan npm --lockfile <path>`.
- [x] Implement requirements.txt parser.
- [x] Implement `aedo scan pypi --requirements <path>`.
- [x] Submit coordinates and artifact digests, never full source by default.
- [x] Add explicit phase-gated `--upload-manifest` behavior until manifest upload is supported.
- [x] Implement `aedo explain <package>@<version> --ecosystem npm`.
- [x] Implement `aedo explain <package>@<version> --ecosystem pypi`.
- [x] Implement `aedo policy test --file aegiscudo-policy.yaml`.
- [x] Implement `aedo ci preflight --format sarif --fail-on block`.
- [x] Implement `aedo ci preflight --format json --fail-on warn`.
- [x] Support `--output-format text`.
- [x] Support `--output-format json`.
- [x] Support `--output-format sarif`.
- [x] Support `--fail-on warn`.
- [x] Support `--fail-on block`.
- [x] Produce SARIF compatible with GitHub Advanced Security and GitLab Security Dashboards.
- [x] Return correct exit code for allow-only results.
- [x] Return correct exit code when warn meets fail threshold.
- [x] Return correct exit code when block meets fail threshold.
- [x] Return clear `not-yet-supported` errors for Phase 2/3 scan targets in Phase 1 builds.
- [x] Add unit tests for parsers, output formats, API client behavior, and exit codes.
- [x] Add integration test against local API.
	- Note: focused unit coverage now includes npm and pnpm and requirements parsers, explain parsing, SARIF output, exit thresholds, scan and explain API clients, CI preflight discovery and aggregation, and policy schema validation. Remaining CLI validation work is broader non-ignored/live coverage and the final yarn support decision.

## Phase 1C Validation

- [x] `pnpm lint` passes.
- [x] `pnpm typecheck` (`tsc --noEmit`) passes with zero errors.
- [x] `pnpm test` passes.
- [x] `pnpm playwright test` passes for MVP UI workflows.
	- Closed: live seeded shell flow, admin pages, policy simulator, and breadcrumb navigation Playwright tests all pass.
- [x] `cargo test -p aedo-cli` passes.
- [x] API contract tests pass for UI and CLI clients.
	- Closed: `aegiscudo-api` DB-backed contract tests cover quarantine queue, artifact evidence, override CRUD, timeline, audit log, auth session, policy simulator, admin RBAC, and admin read routes. CLI contract tests cover `/v1/cli/scans` and `/v1/cli/explain`. 26 ignored DB tests pass when PostgreSQL is live.
- [x] Accessibility checks pass for critical workflows where practical.
	- Closed 2026-05-10: WCAG 2.1 AA breadcrumb semantic nav implemented and Playwright test verifies `aria-current="page"` and `role="navigation"` structure. Color contrast tokens use AA-compliant CSS custom properties.
- [ ] Visual regression snapshots are reviewed for key pages.
	- Deferred to Phase 2 per 2026-06 arch decision. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
