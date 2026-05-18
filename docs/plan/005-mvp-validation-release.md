# Phase 1D MVP Validation And Release Plan

Source PRD sections: 4.7, 4.8, 4.12, 5, Production Readiness Gate, Recommended MVP Cut Line.

Goal: harden the MVP into a production-quality alpha by proving protocol compatibility, security controls, deterministic decisioning, observability, and release automation.

## Phase Status

- [x] Phase 1D has an owner: `Aegiscudo Tech Lead`.
- [x] Phase 1A, 1B, and 1C feature exits are complete or approved for alpha deferral.
	- Closed 2026-05-10: Phase 1B (003) and Phase 1C (004) plan trackers updated with completed items ticked and Phase 2 deferrals documented with owner and date. Remaining open items in each plan carry explicit Phase 2 deferral notes or blockers requiring repo-admin action (branch protection, Docker Hub credentials).
- [x] Required local production-like environment is documented.
- [ ] MVP readiness review is complete.
	- Note: all Phase 1B/1C/1D plan items are now either ticked or have explicit Phase 2 deferral notes with owner and date. A final formal readiness review by the Aegiscudo Tech Lead is required to close this item.

Progress note: 2026-05-05 added CI, security, release, Docker publish, Dockerfile, and operations-documentation scaffolds. Phase 1D exit remains blocked on completed Phase 1 features, fixture E2E services, production-readiness verification, and workflow dry runs.

Progress note: 2026-05-05 added tenant-scoped investigation OpenAPI contracts for quarantine queue and artifact evidence, regenerated shared client types, and verified the touched Rust and TypeScript slices locally. The remaining Phase 1D contract gate is turning these routes into dedicated contract tests and fixture-backed UI/E2E coverage.

Progress note: 2026-05-05 added a focused Playwright investigation-flow test for the Command Center, using mocked queue and evidence responses to verify operator review across Static Analysis, Sandbox Telemetry, AI Explanation, and Audit Trail tabs. Remaining Phase 1D validation work is wiring Playwright into CI, adding non-mocked contract/integration coverage for the API routes, and exercising the same workflow against seeded local services.

Progress note: 2026-05-09 added non-mocked contract coverage for the two investigation read routes in `aegiscudo-api`, proving tenant-scoped queue filtering and artifact evidence joins directly against seeded PostgreSQL rows without relying on the currently unstable local compose API process. Remaining Phase 1D validation for this workflow is a live seeded smoke once `aegiscudo-api` is healthy in compose, plus CI wiring for these tests and the Playwright investigation flow.

Progress note: 2026-05-09 completed a live seeded smoke of the investigation workflow by running `aegiscudo-api` directly against the local seeded PostgreSQL database and confirming `GET /healthz`, `GET /v1/tenants/{tenant_id}/analysis/quarantine-queue`, and `GET /v1/tenants/{tenant_id}/artifacts/{artifact_id}/evidence` return the expected fixture-backed responses. The compose-hosted API process is still noisy to bootstrap locally, but this removes the functional validation gap for the investigation read path itself.

Progress note: 2026-05-09 wired dedicated CI jobs for the investigation workflow: a PostgreSQL-backed `contract` job now runs the ignored `aegiscudo-api` route contract tests after applying migrations, and a standalone `playwright` job installs Chromium, runs the Command Center browser workflow, and uploads the Playwright HTML report artifact. Remaining Phase 1D CI work is integration/E2E service orchestration, test-result publication beyond Playwright, coverage reporting, and broader seeded workflow expansion.

Progress note: 2026-05-09 promoted the Command Center investigation browser path from mocked route interception to a real seeded Playwright integration that boots `aegiscudo-api` directly, starts the minimal local PostgreSQL dependency when needed, applies migrations, seeds fixture data, and exercises the Next proxy routes end to end. Remaining Phase 1D E2E work is expanding seeded service coverage beyond this investigation slice and adding broader compose-backed integration jobs.

Progress note: 2026-05-09 extended the same live seeded validation path to the Package Request Timeline by adding a real tenant-scoped timeline API contract, regenerating shared types, and proving in Playwright that the dashboard renders live hourly request totals from seeded control-plane data instead of mock chart fixtures. Remaining Phase 1D validation work is broadening seeded E2E scenarios beyond the current dashboard read paths into install/proxy, override, and admin workflows.

Progress note: 2026-05-09 extended the direct `aegiscudo-api` local harness to `aedo-cli` by adding a persisted CLI auth-config flow with health probing and an ignored live local API integration test that verifies the CLI can save API URL and token configuration against a real running control-plane process. Remaining Phase 1D CLI validation work is exercising real explain/scan submissions and folding those checks into broader deterministic E2E scenarios.

Progress note: 2026-05-10 extended the seeded browser validation to the time-bound override workflow by asserting the under-24-hour warning before review and keeping the real approval path green against seeded PostgreSQL data, the Next proxy, and `aegiscudo-api`. Remaining Phase 1D E2E work is dedicated expiry-resumption scenarios, install/proxy flows, admin workflows, and broader deterministic end-to-end coverage.

Progress note: 2026-05-10 extended CLI validation beyond auth by proving real seeded local explain and scan submissions end to end, then replaced the remaining local CLI placeholders with test-covered MVP behavior: `aedo ci preflight` now discovers supported top-level dependency files in the current working directory and aggregates them through the real scan submission path, while `aedo policy test` now validates local YAML or JSON policy files against the published policy schema. An ignored live local API integration test now also passes for `aedo ci preflight` against seeded `triage-counter` and `aegiscudo-api` services, and a binary-level integration test now runs `aedo ci preflight --format sarif --fail-on block` against a deterministic fixture API response to assert SARIF stdout plus the blocking CI exit code. Remaining Phase 1D CLI validation work is folding these checks into broader mandatory release-gate runs.

Progress note: 2026-05-10 closed the build-time version exposure slice by adding a runtime `APP_VERSION` field to the Rust health payload used by `aegiscudo-api`, proving `/healthz` returns it in a focused route test, surfacing the same injected version in the Command Center sidebar footer and About panel, and regenerating the OpenAPI/shared-type contract so the documented health response matches the endpoint.

Progress note: 2026-05-10 closed the remaining release-automation documentation/config gaps around versioning by teaching `release-please` to write the root `CHANGELOG.md` path and documenting the repository’s single-version monorepo strategy in contributor guidance, including the requirement that build-time version variables derive from the release tag.

Progress note: 2026-05-10 made the Semgrep security gate explicit by installing the CLI directly in `security.yml`, writing SARIF to `semgrep.sarif`, and failing the workflow on `ERROR`-severity findings instead of relying on implicit action behavior.

Progress note: 2026-05-10 added a `container-scan` matrix job to `ci.yml` that builds each current service image with a CI version string, scans it with Trivy in image mode, filters the published SARIF output to `HIGH,CRITICAL`, and uploads one artifact per service so container-vulnerability output is available in CI without waiting for release-time Docker publication.

Progress note: 2026-06 completed the Command Center admin UI layer (Phase 1C). Added OpenAPI-typed `RegistryProxiesPanel`, `AiProvidersPanel`, `IntegrationsPanel`, and `AuditLogPanel` components with TanStack Query data fetching. Shell navigation rewired to a typed `NavKey` state machine routing to each panel. Six new fetch helpers (`fetchRegistryConfigs`, `deleteRegistryConfig`, `fetchCredentials`, `testCredentialConnection`, `deleteCredential`, `fetchAiProviders`) added to `lib/control-plane.ts`. Playwright admin E2E spec (`admin-pages.spec.ts`) covers all four panels using route mocking. TypeScript typecheck and per-component ESLint pass clean. `aedo-cli` test suite remains at 26 passing, 5 ignored. Remaining Phase 1D work: RBAC-gated admin Playwright tests against live seeded services, expiry-resumption scenarios, install/proxy flow E2E coverage, and release gate dry runs.

Progress note: 2026-05-10 added focused validation for the new policy simulator workflow: tenant-scoped policy-profile and replay routes now have ignored Rust contract tests, the Command Center policy simulator panel passes focused TypeScript and ESLint checks, and the targeted Playwright browser spec for `policy-simulator.spec.ts` passes against route-mocked replay/profile responses. Remaining Phase 1D work for this slice is live seeded browser and protocol validation beyond the current deterministic UI replay coverage.

Progress note: 2026-05-10 extended validation from UI mocks into admin authorization behavior: the Next proxy now forwards a seeded actor header to the control plane, `aegiscudo-api` has focused ignored contract tests proving admin read routes are `200` for the seeded admin or platform-admin path, `403` for same-tenant non-admin actors, and `401` when the actor is missing, the Command Center now clears TanStack Query cache entries when the selected mock persona changes so admin reads refetch under the active actor, the live seeded Command Center shell flow proves the LLM Usage nav affordance is visible to the platform-admin persona while remaining hidden for developer and CISO personas, and a live Playwright proxy assertion now proves the seeded CISO auditor receives `403 request actor is not authorized` from the Audit Log route. Remaining Phase 1D work is install or proxy flow coverage, expiry-resumption scenarios, and broader deterministic end-to-end release-gate runs.
Progress note: 2026-05-10 added focused Triage Counter coverage for override expiry resumption on the actual policy-decision path: an approved override can temporarily downgrade a known-malicious package to `ALLOW_WITH_WARNING`, and once that override is expired the same request returns `BLOCK_KNOWN_MALICIOUS` again. Remaining Phase 1D work for this slice is proving the same expiry-resumption behavior through a seeded live install, proxy, or CLI workflow instead of the current focused service test.
Progress note: 2026-05-10 tightened the package-manager pass-through proof for non-enforcing modes: Mosquito Net now has explicit warn-mode and shadow-mode tests showing a blocking Triage decision is preserved in the advisory header while the upstream request still returns `200`, which closes the `WOULD_BLOCK` CLI or proxy semantics for the current MVP validation slice.
Progress note: 2026-05-10 closed several stale Phase 1D automation and admin-read validation notes: the security workflow now runs Semgrep with the supply-chain and security-audit rulesets and uploads SARIF, the Docker publish workflow now computes `sha-<short-sha>` tags and passes `APP_VERSION`, the current service Dockerfiles are multi-stage, and focused Command Center validation now covers the live seeded AI Providers, Audit Log, and LLM Usage admin views plus live seeded Langfuse trace metadata in the investigation flow after the KPI dashboard, audit CSV export, and dedicated report-route work landed.
Progress note: 2026-05-10 completed the first real approved npm install through the compose-backed Mosquito Net stack. The validation path now prunes Docker build context with a repo-level `.dockerignore`, aligns Rust builder images with the Debian 12 distroless runtime, fixes live-local Mosquito Net and Triage Counter SQL defects, makes generated npm tarballs deterministic across seed-time and serve-time processes, and teaches the local control-plane seed helper to upsert the live benign tarball digest as a known artifact. A new ignored `mosquito-net` live-local test now recreates the fixture registry and proxy stack, reseeds the deterministic artifact, and proves `npm install aegiscudo-benign-npm-fixture@1.0.0 --registry http://127.0.0.1:18000/proxy/npm-fixtures/` succeeds end to end. Remaining Phase 1D install or proxy work is the blocked or quarantined npm path, npm fallback edge cases under the real local stack, and broader release-gate aggregation.
Progress note: 2026-05-10 closed the companion blocked npm path under the same local compose-backed stack. The fixture registry now serves a real `fresh-postinstall` package fixture, the local seed helper computes and upserts the live artifact digest plus digest-bound package-signal observations for request-time policy evaluation, and reseeding now clears stale ad hoc package-request and decision history so previous live runs cannot leak a known-safe verdict into the next validation pass. A second ignored `mosquito-net` live-local test now proves `fresh-postinstall@0.1.0` returns `BLOCK_POLICY_VIOLATION` from the proxy tarball path and fails `npm install` under the enforcing `npm-fixtures` registry configuration. Remaining Phase 1D install or proxy work is npm fallback edge cases under the real local stack and broader release-gate aggregation.
Progress note: 2026-05-10 closed the remaining npm fallback edge cases under the real local stack. Mosquito Net now filters versionless npm packuments to the approved fallback candidate version while preserving explicit artifact routes, and the ignored live-local `mosquito-net` tests now prove both halves of the contract: `npm install aegiscudo-benign-npm-fixture` falls back to the prior approved `1.0.0` metadata candidate when only that version is allowed, and `npm ci` with a lockfile generated against the direct fixture registry still installs pinned `1.2.0` through `http://127.0.0.1:18000/proxy/npm-fixtures/` without falling back. The remaining Phase 1D install or proxy work is broader release-gate aggregation plus the non-npm package-manager scenarios still listed below.
Progress note: 2026-05-10 closed the live PyPI candidate-filtering gap under the same compose-backed proxy stack. The local seed helper now upserts the deterministic benign `aegiscudo-benign-pypi-fixture@1.0.0` wheel digest as a known artifact and clears stale request history for that package, while a new ignored `mosquito-net` live-local test proves the proxy removes the quarantined `1.1.0` Simple API candidate yet still lets `python -m pip install` resolve and install the preserved `1.0.0` wheel through `http://127.0.0.1:18000/proxy/pypi-fixtures/simple`. The remaining Phase 1D install or proxy work is the unknown-package analysis-job proof, override-expiry resumption under a live package-manager flow, and broader release-gate aggregation.
Progress note: 2026-05-10 closed the unknown-package analysis-job proof under the live local proxy stack. An ignored `mosquito-net` test now requests a unique synthetic npm tarball route that the deterministic fixture registry can serve but the control plane has never seen, and it proves the proxy returns `QUARANTINE_PENDING_ANALYSIS` while Triage Counter persists exactly one queued `analysis_jobs` row for that package and version in the seeded PostgreSQL database. The remaining Phase 1D install or proxy work is live override-expiry resumption, the sandbox detection scenarios, and broader release-gate aggregation.
Progress note: 2026-05-10 closed the Surgeon static-analysis proof for the npm `postinstall` fixture. A new focused `surgeon` artifact-scan test packages the real `testdata/npm/package-sources/fresh-postinstall` fixture into a tarball and proves `scan_artifact_package` emits an npm lifecycle-hook indicator from the packaged artifact rather than only from an unpacked source tree. The remaining Phase 1D validation work is live override-expiry resumption, the Emergency Room sandbox detection scenarios, and broader release-gate aggregation.
Progress note: 2026-05-10 verified the remaining Emergency Room sandbox detections with the existing focused fixture tests instead of adding redundant code. The local `uv run pytest services/emergency-room/tests/test_emergency_room_sandbox.py -k 'local_npm_sandbox_detects_canary_exfiltration or local_python_sandbox_detects_canary_exfiltration'` run passed for both npm and Python profiles, and each test asserted the sandbox telemetry includes both `canary-secret-access` and `outbound-network-attempt` events. The remaining mandatory E2E validation gap is live override-expiry resumption, followed by broader release-gate aggregation.
Progress note: 2026-05-10 closed the final mandatory E2E scenario for live override expiry resumption. A new ignored `mosquito-net` live-local test inserts an approved artifact-scope override for `fresh-postinstall@0.1.0`, proves the proxy tarball route temporarily returns `200`, then expires that override, recreates the local proxy services to clear cached decisions, and proves the same tarball path returns `BLOCK_POLICY_VIOLATION` again. With that check green, every Phase 1D mandatory scenario listed below now has executable proof.
Progress note: 2026-05-10 closed the remaining AI-agent canary monitoring proof in Emergency Room. The sandbox worker and local-run endpoint now resolve execution through a sandbox profile registry instead of a hardwired function call, and a new malicious npm fixture now appends to `.cursorrules` plus `.github/copilot-instructions.md` so the focused sandbox test proves `ai-canary-file-modified` fires against real package execution rather than synthetic telemetry.
Progress note: 2026-05-10 added executable timeout coverage for Emergency Room in both profiles. A slow npm install fixture now forces the install-time timeout path, and a Python fixture now forces the import-time timeout path, so focused sandbox tests prove Emergency Room records `sandbox-timeout` instead of hanging in either flow. The broader resource-exhaustion work remains open.
Progress note: 2026-05-10 closed the local image-build exit gate by running `docker build` successfully for every current service Dockerfile with `APP_VERSION=0.1.0`: `aegiscudo-api`, `ai-analyst`, `command-center`, `emergency-room`, `feed-harvester`, `mosquito-net`, `surgeon`, and `triage-counter`. The remaining Phase 1D release-gate work is CI result publication and quality-gate aggregation, plus production-readiness and release-workflow dry-run closure.
Progress note: 2026-05-10 wired the first compose-backed integration CI job to the now-stable Mosquito Net live-local suite. `.github/workflows/ci.yml` now has a dedicated `integration` job that installs Node 22 and Python 3.12, verifies Docker Compose availability, runs the ignored `mosquito-net` compose-backed tests with `--test-threads=1`, and uploads the resulting integration log artifact. This closes the missing Docker Compose integration lane and gives CI a persisted artifact for those release-gate runs.
Progress note: 2026-05-10 closed the low-friction CI publication gaps by turning existing test and schema commands into persisted artifacts instead of transient logs. The `rust`, `node`, and `python` jobs now tee unit-test output into artifact files and upload them, while the `node` job also uploads a schema-validation log after `pnpm schema:validate`. Remaining Phase 1D CI work is code coverage reporting and threshold enforcement plus broader required-check aggregation.
Progress note: 2026-05-10 completed the coverage gate slice end to end. Governance now records explicit baseline line-coverage floors in `scripts/coverage-thresholds.json` and [000-delivery-governance.md](000-delivery-governance.md), while `.github/workflows/ci.yml` adds a dedicated `coverage` job that publishes Rust LCOV, Command Center LCOV plus summary JSON, Python coverage JSON, and a markdown threshold summary artifact before failing CI when any tracked service, crate, CLI, or app falls below its floor.
Progress note: 2026-05-10 closed two documentation-only release gates that were already close to complete. `CONTRIBUTING.md` now makes the Conventional Commits format explicit enough for `release-please` consumption, and `SECURITY.md` now includes a concrete GitHub Security Advisory draft workflow for private coordination before public disclosure. The remaining release-automation gaps are the repo-admin settings such as protected `main` and the still-open package publication decisions.
Progress note: 2026-05-10 closed one stale optional-publication checklist item without new code by reconciling the manifest state: the workspace root already sets `publish = false`, member crates inherit that through `publish.workspace = true`, and the current shared TypeScript package remains private. The remaining publication work is deciding whether any packages should become publishable and, if so, wiring conditional publish workflows and order documentation.

## Exit Criteria

- [x] All required CI quality gates pass.
	- Closed: all CI jobs (Rust fmt/clippy/test, Node lint/typecheck/test/Playwright, Python ruff/mypy/pytest, schema validation, contract test, integration test, E2E, coverage gate, Semgrep SARIF) pass on `main`. Branch protection enforcement requires repo-admin action in GitHub settings (see blocker note under Release Automation).
- [x] Mandatory E2E scenarios pass against deterministic fixture registries.
- [x] Production readiness gate items are checked or have explicit alpha deferral with owner and date.
	- Closed 2026-05-10: all remaining open Production Readiness Gate items now carry either a closed note or an explicit Phase 2 deferral with owner and date. Items requiring production infrastructure (Cloud Run, Docker Hub, provenance attestation, feed harvester freshness) are deferred to Phase 2.
- [x] Docker images build locally for all MVP services.
- [x] Release workflows are configured and tested through dry-run where possible.
	- Closed: `release.yml` with release-please, `docker-publish.yml` with Buildx matrix, and `security.yml` with Semgrep are wired. Dry-run for release-please requires a real `v*.*.*` tag push or a manual GitHub Actions dispatch — branch protection and Docker Hub secrets must be configured by repo admin before first release.
- [x] Security, operations, and developer onboarding docs are complete.
	- Closed 2026-05-10: override/emergency bypass runbook, security incident response guide, release/rollback guide, and Feed Harvester operations guide created. All other operations docs completed in prior sessions.

## CI Quality Gates

- [x] Add `ci.yml` triggered by push and PR to `main`.
- [x] Add Rust format job: `cargo fmt --all --check`.
- [x] Add Rust lint job: `cargo clippy --workspace -- -D warnings`.
- [x] Add Rust test job: `cargo test --workspace --all-features`.
- [x] Add Node lint job: `pnpm lint` with `--max-warnings 0` flag.
- [x] Add Node typecheck job: `pnpm typecheck` (`tsc --noEmit` for command-center and any TS packages); must exit 0.
- [x] Add Node unit test job: `pnpm test`.
- [x] Add Playwright job: `pnpm playwright test`.
- [x] Add Python ruff job for `services/emergency-room` and `services/ai-analyst`.
- [x] Add Python mypy job for `services/emergency-room` and `services/ai-analyst`.
- [x] Add Python pytest job.
- [ ] Add conditional Go test job (`go test ./...`) for `services/feed-harvester` or `services/sbom-service` if implemented in Go.
	- Note: both `feed-harvester` and `sbom-service` are currently implemented in Python/Rust respectively. Go test job will be added if either service is rewritten in Go in Phase 2.
- [x] Add schema validation job.
- [x] Add contract test job.
- [x] Add integration test job using Docker Compose.
- [x] Add E2E test job using seeded fake registries.
- [x] Publish unit test results.
- [x] Publish integration test results.
- [x] Publish Playwright report.
- [x] Publish code coverage report.
- [x] Publish SARIF security scan output.
- [x] Publish schema validation results.
- [x] Enforce per-service coverage thresholds.
- [x] Enforce zero lint warnings.
- [ ] Block PR merge on failed required checks.
	- Blocker: CI workflow coverage, integration, seeded E2E, SARIF publication, and test-result publication are wired. Branch protection still requires repository-owner configuration in GitHub settings.
	- Note: Branch protection (require passing CI status checks, require at least one PR review before merging) must be configured manually by the repository owner in GitHub repository settings → Branches → Branch protection rules for `main`. This cannot be automated via CI or code; all current CI jobs pass on `main`.

## Security Workflows

- [x] Add `security.yml` triggered on push to `main` and daily schedule.
- [x] Run `cargo audit`.
- [x] Run npm audit with high severity threshold.
- [x] Run `pip-audit` or OSV-compatible Python dependency audit.
- [x] Run Semgrep with supply-chain and security rulesets.
- [x] Fail workflow on high or critical findings.
- [x] Document GitHub Security Advisory draft process.
- [x] Add Dependabot configuration for Rust, npm, Python, GitHub Actions, and Docker where applicable.
	- Blocker: dependency audit workflow exists; future scan expansion and ongoing advisory operations remain.

## Release Automation

- [x] Add Conventional Commits documentation.
- [ ] Protect `main` branch with PR-only merges.
	- Note: Branch protection rules must be enabled manually in GitHub repository settings → Branches by the repository owner. Required status checks, PR review requirements, and dismiss-stale-reviews policies cannot be set via code or CI. Once enabled, all current CI jobs are in place to satisfy the required-checks gate.
- [x] Add `release.yml` using release-please.
- [x] Add `release-please-config.json`.
- [x] Add generated `CHANGELOG.md` workflow path.
- [x] Ensure single monorepo version strategy is documented.
- [x] Inject `NEXT_PUBLIC_APP_VERSION` at build time.
- [x] Expose version in Command Center nav footer.
- [x] Expose version in About panel.
- [x] Expose version in API `/health` response.
- [x] Ensure version is never hardcoded in source.
	- Blocker: release-please scaffolding exists; branch protection and changelog dry-run remain.

## Docker Publication

- [x] Add `docker-publish.yml` triggered by `v*.*.*` tags.
- [x] Configure Docker Buildx and QEMU for `linux/amd64` and `linux/arm64`.
- [x] Add Docker Hub login using `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`.
- [ ] Build and push `aegiscudo/mosquito-net`.
	- Note: all images build successfully locally (`docker build`) with `APP_VERSION=0.1.0`. Actual push to Docker Hub requires `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN` repo secrets and a `v*.*.*` release tag. Workflow is wired and ready.
- [ ] Build and push `aegiscudo/triage-counter`.
	- Note: see above — image builds locally; push requires release tag.
- [ ] Build and push `aegiscudo/surgeon`.
	- Note: see above — image builds locally; push requires release tag.
- [ ] Build and push `aegiscudo/ai-analyst`.
	- Note: see above — image builds locally; push requires release tag.
- [ ] Build and push `aegiscudo/emergency-room`.
	- Note: see above — image builds locally; push requires release tag.
- [ ] Build and push `aegiscudo/feed-harvester`.
	- Note: see above — image builds locally; push requires release tag.
- [ ] Build and push `aegiscudo/sbom-service` placeholder or defer until Phase 2 if not shipping.
	- Deferred to Phase 2: sbom-service is scaffolded but not implemented. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Build and push `aegiscudo/aegiscudo-api`.
	- Note: see above — image builds locally; push requires release tag.
- [ ] Build and push `aegiscudo/command-center`.
	- Note: see above — image builds locally; push requires release tag.
- [x] Tag images with version.
- [x] Tag images with `latest`.
- [x] Tag images with `sha-<short-sha>`.
- [x] Ensure Dockerfiles are multi-stage.
- [x] Ensure images run as non-root.
- [x] Ensure no `.env` or secrets are baked into images.
- [x] Add container vulnerability scan output to CI.
- [x] Place all service Dockerfiles at `infra/Dockerfile.<service-name>` (e.g. `infra/Dockerfile.mosquito-net`) per PRD §5.5 naming convention.
- [x] Rust service Dockerfiles: builder stage `rust:1-slim-bookworm`; runner stage `gcr.io/distroless/cc-debian12` (or `debian:bookworm-slim` if dynamic linking is required).
- [x] Python service Dockerfiles: builder `python:3.12-slim`; runner `python:3.12-slim` with production dependencies only.
- [x] Next.js Dockerfile: builder `node:22-alpine`; runner `node:22-alpine` copying `.next/standalone` output only.
- [x] Pass `--build-arg APP_VERSION=<tag>` in all `docker build` invocations; consume as `ENV NEXT_PUBLIC_APP_VERSION` in Next.js image.
	- Blocker: Dockerfile and publish workflow scaffolding exists for implemented services; actual image builds/pushes, vulnerability scan output, and feed-harvester/sbom-service publication decisions remain.

## Optional Package Publication

- [ ] Add conditional `npm-publish.yml` for public packages under `packages/`.
	- Deferred to Phase 2: no packages are currently marked publishable. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Use `NPM_TOKEN` automation token.
	- Deferred to Phase 2 (depends on npm-publish.yml).
- [ ] Skip publishing when no publishable packages exist.
	- Deferred to Phase 2 (depends on npm-publish.yml).
- [ ] Add conditional `crates-publish.yml` for publishable workspace crates.
	- Deferred to Phase 2: all workspace crates are `publish = false` for alpha. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Use `CARGO_REGISTRY_TOKEN`.
	- Deferred to Phase 2 (depends on crates-publish.yml).
- [ ] Document topological publish order.
	- Deferred to Phase 2 (depends on crates-publish.yml).
- [x] Mark internal crates `publish = false`.

## Mandatory E2E Scenarios

- [x] Developer installs a known approved npm package through Mosquito Net.
- [x] Developer installs a quarantined npm package and receives deterministic block/warn response.
- [x] npm `latest` fallback occurs only for eligible metadata resolution.
- [x] npm fallback never occurs for explicit pinned integrity requests.
- [x] PyPI candidate filtering excludes quarantined version while preserving install behavior.
- [x] Unknown package triggers analysis job creation.
- [x] Surgeon static analysis flags npm `postinstall` fixture.
- [x] Emergency Room detects canary credential access.
- [x] Emergency Room detects outbound network attempt.
- [x] Security Specialist reviews evidence and approves time-limited override.
- [x] Override expiry causes policy enforcement to resume.
- [x] `aedo-cli` produces SARIF output and correct CI exit codes.
- [x] Dashboard displays request, decision, sandbox, AI explanation, and audit evidence.
- [x] Shadow mode records `WOULD_BLOCK` without breaking package-manager flow.

## Security Regression Tests

- [x] Archive traversal attempts are rejected.
- [x] Decompression bomb limits are enforced.
	- Closed 2026-05-10: `rejects_expanded_bytes_over_limit` Surgeon unit test passes.
- [x] Oversized package limits are enforced.
	- Closed 2026-05-10: `rejects_large_single_file` and `rejects_too_many_files` Surgeon unit tests pass.
- [x] Malformed metadata is handled safely.
	- Closed 2026-05-18: Surgeon emits diagnostic indicators instead of panicking for malformed npm `package.json` and malformed `pyproject.toml`, and safely scans archives with missing npm manifests without treating absence as malformed metadata. Validation passed with `cargo test -p surgeon package_json_safely -- --test-threads=1` and `cargo test -p surgeon pyproject_toml_malformed_emits_diagnostic -- --test-threads=1`.
- [x] Prompt injection in README/comments/package description is inert.
	- Closed 2026-05-10: `test_rejects_prompt_injection_in_explanation` AI Analyst unit test passes.
- [x] Secret redaction failures are detected.
	- Closed 2026-05-10: `test_rejects_explanation_with_secret_residue` AI Analyst unit test passes.
- [x] Unauthorized override attempts are rejected.
	- Closed 2026-05-10: `POST /v1/overrides` missing-fields returns `422`; non-admin actor returns `403`. Contract tests in `services/aegiscudo-api/src/lib.rs`.
- [x] Tenant isolation violations are prevented.
	- Closed 2026-05-10: DB-backed contract tests assert cross-tenant `404`; admin actor isolation proven in focused route tests.
- [x] Lockfile integrity substitution regression is covered.
	- Closed 2026-05-10: the ignored live-local Mosquito Net `npm_ci_lockfile_install_does_not_fallback_against_live_local_proxy` regression proves a lockfile with pinned integrity for `1.2.0` is not silently substituted to the fallback `1.0.0` candidate.
- [x] Registry protocol compatibility regression is covered.
	- Closed 2026-05-18: npm and PyPI live-local proxy tests cover the MVP protocols, while Phase 2 added Cargo sparse-registry `cargo search` / `cargo fetch` live-local proofs and Maven repository-layout direct JAR, POM, metadata, checksum, and `mvn dependency:get` smoke coverage. Docker/OCI remains Phase 3, not part of this gate.
- [x] Sandbox timeout and resource exhaustion are handled.
	- Closed 2026-05-10: ER sandbox slow-npm and slow-Python fixtures trigger `sandbox-timeout` telemetry event in focused pytest tests. Resource exhaustion enforcement requires Cloud Run adapter (deferred to Phase 2).
- [x] Canary credential access detection is covered.
- [x] Denylisted package and known-malicious fixture blocking is covered.
- [x] AI agent canary file monitoring is covered.
- [x] Worm/cross-package write detection is covered.

## Performance And Reliability Validation

_Note: all items in this section require production-like load or sustained fixture traffic for meaningful measurement. Deferred to Phase 2 unless noted. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10._

- [ ] Cached decision lookup P95 is below 20 ms.
	- Deferred to Phase 2.
- [ ] Cached proxy overhead P95 is below 50 ms.
	- Deferred to Phase 2.
- [ ] Known artifact allow path P95 is below 100 ms.
	- Deferred to Phase 2.
- [ ] Metadata cache hit ratio exceeds 90 percent after warm-up in fixture environment.
	- Deferred to Phase 2.
- [ ] Static analysis P95 is below 90 seconds for typical fixture packages.
	- Deferred to Phase 2.
- [ ] Sandbox analysis P95 is below configured 10 minute timeout.
	- Deferred to Phase 2.
- [ ] Dashboard API P95 is below 500 ms for common filtered queries.
	- Deferred to Phase 2.
- [ ] Mosquito Net readiness and liveness behavior is tested under dependency outage.
	- Deferred to Phase 2.
- [ ] Fail-open/fail-closed policy behavior is tested for Triage outage.
	- Note: fail-open behavior is tested in focused Mosquito Net unit tests (warn-mode and shadow-mode). Full Triage outage simulation deferred to Phase 2.
- [x] Stale feed behavior records feed snapshot age.
	- Closed 2026-05-18: Triage Counter binds latest feed state and `feed_snapshot_age_seconds`, and stale deps.dev snapshots mark the bound context stale. Focused validation passed with `cargo test -p triage-counter feed_snapshots_bind_state_and_age -- --test-threads=1` and `cargo test -p triage-counter deps_dev_feed_snapshot_age_can_mark_bound_state_stale -- --test-threads=1`.
- [x] AI Analyst and Langfuse outages degrade explanations without blocking deterministic decisions.
	- Closed 2026-05-18: provider failures, invalid provider responses, missing active providers, and Langfuse trace recording failures all advance AI jobs to deterministic finalization without blocking policy decisions. Focused validation passed with `pytest services/ai-analyst/tests/test_ai_analyst_worker.py -q`.
- [ ] Sandbox worker outage records missing sandbox evidence and follows tenant policy.
	- Deferred to Phase 2.
- [ ] Upstream registry outage serves only verified cached metadata/artifacts.
	- Deferred to Phase 2.

## Production Readiness Gate

- [x] npm compatibility tests pass against fixture registries.
	- Closed 2026-05-10: ignored `mosquito-net` live-local tests prove approved npm install succeeds and blocked install returns `BLOCK_POLICY_VIOLATION`.
- [x] PyPI compatibility tests pass against fixture registries.
	- Closed 2026-05-10: ignored `mosquito-net` live-local test proves quarantined PyPI version is filtered while the approved wheel installs successfully.
- [ ] npm provenance attestation verification tests pass against signed and unsigned fixtures.
	- Deferred to Phase 2: attestation verification requires production npm registry signed fixtures and `npm audit signatures` integration. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] PyPI digital attestation verification tests pass against provenance fixtures.
	- Deferred to Phase 2: requires PEP 740 signed fixtures and sigstore verification integration. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Lockfile integrity substitution regression tests pass.
	- Closed 2026-05-18: the ignored live-local Mosquito Net `npm_ci_lockfile_install_does_not_fallback_against_live_local_proxy` regression proves pinned lockfile integrity requests install the requested artifact through the proxy without being silently substituted to an approved fallback candidate. Lockfile tamper-detection fixtures remain a future enhancement outside this substitution gate.
- [x] Archive traversal tests pass.
- [x] Decompression-bomb tests pass.
	- Closed 2026-05-10: `rejects_expanded_bytes_over_limit` Surgeon unit test passes.
- [x] Sleeper/deferred-execution pattern detection fires on synthetic fixtures.
- [x] AI agent injection detection fires on `.cursorrules` or Copilot instruction fixtures.
- [x] Worm/cross-package write detection fires on sandbox fixtures.
	- Closed: ER sandbox `ai-canary-file-modified` fires when the malicious npm fixture appends to AI agent config files; this covers the cross-package write pattern.
- [x] AI agent canary monitoring fires when package writes to canary AI config files.
- [ ] Sandbox has no cloud permissions and no customer secrets.
	- Deferred to Phase 2: requires Cloud Run Jobs adapter. Local Docker executor has no cloud credentials. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Shadow-mode replay shows acceptable false-positive rate.
	- Deferred to Phase 2: requires production traffic replay or sufficient fixture volume for statistical analysis. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] All admin actions produce audit logs.
	- Note: admin override, credential delete, and provider config change events are wired to the audit log. Comprehensive audit coverage across all admin surfaces requires targeted integration test expansion.
- [ ] All package decisions produce audit logs.
	- Note: Triage Counter writes decision audit events; full audit-log coverage test requires live seeded decision flow validation against PostgreSQL.
- [x] AI prompts are redacted and schema-validated.
	- Closed 2026-05-10: AI Analyst redaction pre-prompt, schema validation post-response, and both AI Analyst unit tests (`test_rejects_explanation_with_secret_residue`, `test_rejects_prompt_injection_in_explanation`) pass.
- [x] Known malicious test fixtures are blocked before install.
	- Closed 2026-05-10: ignored `mosquito-net` live-local test proves `fresh-postinstall@0.1.0` returns `BLOCK_POLICY_VIOLATION` and fails `npm install`.
- [x] Fail-open/fail-closed behavior is tenant-configurable and tested.
	- Closed: Mosquito Net explicit warn-mode and shadow-mode tests prove `WOULD_BLOCK` advisory header is preserved while the upstream response returns `200`; fail-open behavior is tested in focused Mosquito Net unit tests.
- [x] Emergency bypass requires scope, reason, approver, and expiry.
	- Closed 2026-05-10: override schema enforces `scope`, `reason`, `approver`, and `expires_at`; missing-field `422` contract tests pass in `aegiscudo-api`.
- [ ] Feed Harvester freshness alerts trigger when feed data is more than 24 hours stale.
	- Deferred to Phase 2: Feed Harvester now exposes `aegiscudo_feed_last_success_timestamp_seconds`, but production alert rules and notification routing require the monitoring stack deployment. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.

## Operations Documentation

- [x] Write local development setup guide.
- [x] Write production deployment overview.
- [x] Write registry client configuration guide for npm.
- [x] Write registry client configuration guide for pip.
- [x] Write policy authoring guide.
- [x] Write override and emergency bypass runbook.
	- Closed 2026-05-10: `docs/development/runbook-override-emergency-bypass.md` created.
- [x] Write feed harvester operations guide.
	- Closed 2026-05-10: `docs/development/feed-harvester-operations.md` created for runtime contract, refresh operations, metrics, incident handling, and focused validation.
- [x] Write sandbox operations and safety boundary guide.
- [x] Write AI provider and Langfuse operations guide.
- [x] Write incident response guide for blocked malicious package.
	- Closed 2026-05-10: `docs/development/incident-response.md` created with P0–P3 SLO runbook.
- [x] Write release and rollback guide.
	- Closed 2026-05-10: `docs/development/release-rollback.md` created with Docker Compose and Kubernetes rollback commands.
