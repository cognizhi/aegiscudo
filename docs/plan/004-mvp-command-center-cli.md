# Phase 1C MVP Command Center And CLI Plan

Source PRD sections: Feature 5, Feature 6, 3.2, 3.4.3, 3.4.4, 3.6, 3.7.3, 4.9, 4.10, 4.12.5.

Goal: deliver the operator and developer interfaces required for MVP: dashboard investigation and administration, policy simulation, credentials/provider management, audit visibility, and CLI preflight workflows.

## Phase Status

- [x] Phase 1C has an owner: `Aegiscudo Tech Lead`.
- [ ] Backend API contracts required by UI and CLI are stable enough for implementation.
- [ ] Seed data exists for dashboards, tables, evidence views, and CLI tests.
- [ ] Interface exit review is complete.

Progress note: 2026-05-05 implemented the Command Center shell/dashboard scaffold, typed table/chart components, shared tooltip primitive, Playwright smoke test, and `aedo-cli` parser/output foundation. Full Phase 1C remains blocked on stable backend APIs, auth/RBAC, persisted settings, real workflows, and E2E fixtures.

## Exit Criteria

- [ ] Command Center supports security review of quarantined/suspicious packages.
- [ ] Command Center supports registry proxy CRUD and tenant namespace settings.
- [ ] Command Center supports AI provider and integration credential administration.
- [ ] Command Center supports audit log filtering and KPI/LLM usage visibility.
- [ ] Command Center implements the PRD design system with theme, density, glow, animation, tooltip, command palette, and sidebar customization.
- [ ] `aedo-cli` supports MVP auth, npm/PyPI scans, explain, policy test, CI preflight, JSON/text/SARIF output, and correct exit codes.
- [ ] UI and CLI are covered by unit, integration, Playwright, and E2E tests where required.

## API Surface For Interfaces

- [ ] Define OpenAPI endpoints for auth/session and mock identity.
- [ ] Define endpoints for package request timeline.
- [ ] Define endpoints for quarantine queue.
- [ ] Define endpoints for override queue and decisions.
- [ ] Define endpoints for artifact evidence viewer.
- [ ] Define endpoints for static analysis reports.
- [ ] Define endpoints for sandbox execution reports.
- [ ] Define endpoints for policy simulator.
- [ ] Define endpoints for registry proxy CRUD.
- [ ] Define endpoints for tenant and namespace configuration.
- [ ] Define endpoints for audit log query and CSV export.
- [ ] Define endpoints for KPI dashboard metrics.
- [ ] Define endpoints for LLM usage metrics.
- [ ] Define endpoints for AI provider configs.
- [ ] Define endpoints for integration credential metadata and test connection.
- [ ] Define endpoints for CLI auth, scan submit, explain, policy test, and CI preflight.
- [ ] Generate or validate TypeScript API client from OpenAPI.
	- Note: generated TypeScript contract aliases already ship from `@aegiscudo/shared-types`; this remaining task is the richer request-client or SDK layer used by UI and CLI workflows.
- [ ] Add contract tests for every endpoint used by UI or CLI.

## Design System And Shell

- [x] Implement CSS custom property theme tokens for dark, light, and dim themes.
- [ ] Ensure theme values meet WCAG 2.1 AA contrast for text, badges, and controls.
- [x] Apply theme before first paint to avoid flash of incorrect theme.
- [ ] Persist theme per user.
- [x] Implement semantic status color tokens: critical/block, warn/quarantine, safe/allow, pending/unknown, info/neutral.
- [x] Implement configurable glow edge utility with off, subtle, normal, and strong intensity.
- [x] Respect `prefers-reduced-motion`.
- [ ] Implement animation speed settings: reduced, normal, snappy.
- [ ] Implement shape style settings: edgy, balanced, rounded.
- [ ] Implement density settings: compact, default, comfortable.
- [ ] Implement sidebar settings: expanded, collapsed, icon-only.
- [ ] Inject personalization CSS overrides server-side to avoid layout shift.
- [x] Implement left sidebar grouped by Overview, Analysis, Policy, Feeds, Reports, and Admin.
- [x] Implement active page indication with accent left border and filled icon state.
- [ ] Implement breadcrumbs on all non-root pages.
- [ ] Implement global command palette with page navigation, package lookup, recent decisions, and admin actions.
- [x] Use lucide icons for icon buttons and navigation.
- [x] Implement shared tooltip primitive with 300 ms delay and max 320 px width.
- [ ] Make tooltip appearance delay configurable to 0 ms via the Personalization panel for power users (PRD §3.2).
- [ ] Add tooltip coverage for metric, status badge, policy signal, decision state, chart point, and form field components.
- [ ] Add visual regression baseline for shell and key pages.
	- Blocker: theme shell and tooltip primitives exist; backend-persisted personalization, command palette, accessibility/contrast audit, tooltip customization, and visual regression baselines remain.

## Auth And RBAC

Decision: local alpha uses mock OIDC only with seeded personas. A dedicated dev IdP container is deferred; production still targets enterprise OIDC or SAML integration.

- [ ] Implement local dev mock auth.
- [ ] Define OIDC/SAML integration boundary for production.
- [ ] Implement role-aware navigation filtering.
- [ ] Enforce backend RBAC for every admin API, not just UI hiding.
- [ ] Add mock identities for developer, security specialist, platform admin, and CISO/auditor personas.
- [ ] Add tests for protected navigation.
- [ ] Add tests for unauthorized admin actions.
- [ ] Add audit event display for actor and role.

## Executive And KPI Dashboards

- [x] Implement draggable/resizable panel layout using `react-grid-layout` or equivalent.
- [ ] Persist dashboard layout per user in backend.
- [x] Add blocked packages metric panel with tooltip.
- [x] Add quarantine queue depth metric panel with tooltip.
- [x] Add active overrides metric panel with tooltip.
- [x] Add feed freshness metric panel with tooltip.
- [x] Add recent critical detections panel with glow alert.
- [x] Add request volume chart with animated entry using Recharts (recharts@3.8.1 per PRD §6.4 package.json).
- [x] Add decision distribution chart with interactive crosshair tooltip.
- [ ] Add mean-time-to-decision panel.
- [ ] Add false-positive/false-negative outcome panel.
- [ ] Add sandbox queue depth panel.
- [ ] Add LLM cost summary panel.
- [ ] Add reset-to-default dashboard layout action.
- [ ] Add seeded metrics tests.
	- Blocker: mock dashboard panels render; backend persistence, full metric set, reset action, and seeded metric tests remain.

## Analysis Workflows

- [ ] Implement Package Request Timeline with time range, ecosystem, tenant, decision type, and policy filters.
- [ ] Implement Quarantine Queue with TanStack Table sorting, filtering, pagination, severity glow, batch action toolbar, and status badge tooltips.
- [ ] Implement Override Queue with pending/resolved tabs, expiry countdown, amber glow under 24 hours, reason, approver, approval, denial, and validation errors.
- [ ] Implement Artifact Evidence Viewer tabs: Static Analysis, Sandbox Telemetry, AI Explanation, Audit Trail.
- [ ] Mark AI explanation as advisory with distinct visual treatment.
- [ ] Implement Static Analysis Report Viewer with file tree, per-file indicator counts, expandable code slices, syntax highlighting, entropy bars, and obfuscation bars.
- [ ] Implement Sandbox Execution Report Viewer with phase timeline A-H, telemetry expansion, network attempts, filesystem diff, process tree, and canary access alerts.
- [ ] Implement Policy Simulator dry-run panel.
- [ ] Policy simulator must replay up to the last 30 days of historical requests against proposed rule changes before committing a policy profile (PRD §2.5 User Story 4).
- [ ] Implement policy decision diff view for before/after simulations.
- [ ] Add animated table updates and tab transitions.
- [ ] Add Playwright tests for quarantine queue filtering, sorting, pagination, evidence viewer, policy simulator, and override workflows.

## Admin Workflows

- [ ] Implement Registry Proxies list view.
- [ ] Show adapter type badge, mount path, upstream URL, enforcement mode badge, enabled toggle, and last-request timestamp.
- [ ] Implement Registry Proxy add/edit form with all PRD fields.
- [ ] Show phase-gated adapter options with coming-soon badges.
- [ ] Add upstream URL connectivity test button.
- [ ] Add auto-generated npm client configuration snippet.
- [ ] Add auto-generated pip client configuration snippet.
- [ ] Add placeholder snippets for future cargo, maven, and docker adapters with not-yet-supported labels.
- [ ] Add auth type selector with conditional credential fields.
- [ ] Add enforcement mode selector with tooltip explaining shadow, warn, and enforce.
- [ ] Add policy profile selector.
- [ ] Add cache TTL and TLS verification controls.
- [ ] Implement soft-delete confirmation.
- [ ] Prevent deletion warning for active/in-flight proxies.
- [ ] Implement Tenant and Namespace Configuration view.
- [ ] Implement dependency confusion namespace declarations.
- [ ] Implement allowlist and denylist management.
- [ ] Implement default enforcement mode override settings.
- [ ] Add Playwright tests for registry configuration form validation and mode indicators.

## AI Providers Admin

- [ ] Implement AI Providers table with display name, provider type, active model, last test status, data boundary, and active badge.
- [ ] Implement add/edit provider form with provider-aware fields.
- [ ] Implement OpenAI model list fetch and searchable dropdown.
- [ ] Implement Google Gemini model list fetch and filter to generateContent-capable models.
- [ ] Implement Google Vertex AI model list fetch with project and location fields.
- [ ] Implement OpenRouter model list fetch with provider name and context window display.
- [ ] Implement Ollama model list fetch with fallback to free-text on failure.
- [ ] Implement LM Studio model list fetch with fallback to free-text on failure.
- [ ] Implement vLLM model list fetch with fallback to free-text on failure.
- [ ] Implement generic OpenAI-compatible model list fetch with fallback to free-text on failure.
- [ ] Implement Anthropic curated model list and free-text override.
- [ ] Add Refresh Models action.
- [ ] Validate selected model on configuration save through a test call.
- [ ] Enforce exactly one active provider atomically.
- [ ] Audit active provider transition.
- [ ] Show Local/Cloud badge.
- [ ] Warn when local provider URL is not loopback or RFC 1918 private range.
- [ ] Never display actual API key after save.
- [ ] Add tests for model selector fallback, local boundary warning, and active provider transition.

## Integrations Admin

- [ ] List all external feed and AI provider integrations.
- [ ] Show last successful poll or latest error.
- [ ] Show credential type.
- [ ] Show configured/not configured state only.
- [ ] Distinguish environment-provided bootstrap credentials from database runtime overrides.
- [ ] Implement masked credential update input.
- [ ] Implement test connection action per integration.
- [ ] Implement credential delete confirmation.
- [ ] Audit credential created, rotated, and deleted events without values.
- [ ] Add tests for masked display, runtime override precedence, and deletion audit.

## LLM Usage View

- [ ] Show total LLM calls by day.
- [ ] Show token usage by provider, model, and analysis job.
- [ ] Show estimated cost by provider and model.
- [ ] Show average and P95 latency.
- [ ] Show schema validation pass and failure rates.
- [ ] Provide drill-down to failing traces.
- [ ] Show redaction failure alerts.
- [ ] Show prompt template version distribution.
- [ ] Link from AI explanation to corresponding Langfuse trace.
- [ ] Restrict view to admin and platform-admin roles.

## Audit And Reports

- [ ] Implement append-only Audit Log view.
- [ ] Filter by actor.
- [ ] Filter by action type.
- [ ] Filter by resource.
- [ ] Filter by time range.
- [ ] Export audit log to CSV.
- [ ] Implement CISO report filters by time range, tenant, registry ecosystem, team, and policy version.
- [ ] Export MVP reports to CSV.
- [ ] Add PDF export placeholder or implementation according to MVP decision.

## aedo-cli MVP

- [x] Implement `aedo auth login`.
- [x] Implement `aedo auth logout`.
- [x] Implement `aedo auth status`.
- [ ] Implement API base URL and token configuration.
- [x] Implement npm package-lock parser.
- [ ] Implement npm yarn.lock parser or scope-limited supported parser with clear errors.
- [ ] Implement npm pnpm-lock.yaml parser or scope-limited supported parser with clear errors.
- [x] Implement `aedo scan npm --lockfile <path>`.
- [x] Implement requirements.txt parser.
- [x] Implement `aedo scan pypi --requirements <path>`.
- [x] Submit coordinates and artifact digests, never full source by default.
- [ ] Add explicit `--upload-manifest` opt-in behavior if manifest upload is supported.
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
- [ ] Add unit tests for parsers, output formats, API client behavior, and exit codes.
- [ ] Add integration test against local API.
	- Blocker: CLI command surface and parser tests exist; persistent auth config, API client behavior, yarn/pnpm parsers, broader output/exit-code tests, and local API integration tests remain.

## Phase 1C Validation

- [x] `pnpm lint` passes.
- [x] `pnpm typecheck` (`tsc --noEmit`) passes with zero errors.
- [x] `pnpm test` passes.
- [ ] `pnpm playwright test` passes for MVP UI workflows.
- [x] `cargo test -p aedo-cli` passes.
- [ ] API contract tests pass for UI and CLI clients.
- [ ] Accessibility checks pass for critical workflows where practical.
- [ ] Visual regression snapshots are reviewed for key pages.
	- Blocker: Command Center Playwright smoke test passes; full MVP workflow coverage is pending backend APIs and seeded E2E data.
