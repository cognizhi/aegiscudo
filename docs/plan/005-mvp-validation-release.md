# Phase 1D MVP Validation And Release Plan

Source PRD sections: 4.7, 4.8, 4.12, 5, Production Readiness Gate, Recommended MVP Cut Line.

Goal: harden the MVP into a production-quality alpha by proving protocol compatibility, security controls, deterministic decisioning, observability, and release automation.

## Phase Status

- [x] Phase 1D has an owner: `Aegiscudo Tech Lead`.
- [ ] Phase 1A, 1B, and 1C feature exits are complete or approved for alpha deferral.
- [x] Required local production-like environment is documented.
- [ ] MVP readiness review is complete.

Progress note: 2026-05-05 added CI, security, release, Docker publish, Dockerfile, and operations-documentation scaffolds. Phase 1D exit remains blocked on completed Phase 1 features, fixture E2E services, production-readiness verification, and workflow dry runs.

## Exit Criteria

- [ ] All required CI quality gates pass.
- [ ] Mandatory E2E scenarios pass against deterministic fixture registries.
- [ ] Production readiness gate items are checked or have explicit alpha deferral with owner and date.
- [ ] Docker images build locally for all MVP services.
- [ ] Release workflows are configured and tested through dry-run where possible.
- [ ] Security, operations, and developer onboarding docs are complete.

## CI Quality Gates

- [x] Add `ci.yml` triggered by push and PR to `main`.
- [x] Add Rust format job: `cargo fmt --all --check`.
- [x] Add Rust lint job: `cargo clippy --workspace -- -D warnings`.
- [x] Add Rust test job: `cargo test --workspace --all-features`.
- [x] Add Node lint job: `pnpm lint` with `--max-warnings 0` flag.
- [x] Add Node typecheck job: `pnpm typecheck` (`tsc --noEmit` for command-center and any TS packages); must exit 0.
- [x] Add Node unit test job: `pnpm test`.
- [ ] Add Playwright job: `pnpm playwright test`.
- [x] Add Python ruff job for `services/emergency-room` and `services/ai-analyst`.
- [x] Add Python mypy job for `services/emergency-room` and `services/ai-analyst`.
- [x] Add Python pytest job.
- [ ] Add conditional Go test job (`go test ./...`) for `services/feed-harvester` or `services/sbom-service` if implemented in Go.
- [x] Add schema validation job.
- [ ] Add contract test job.
- [ ] Add integration test job using Docker Compose.
- [ ] Add E2E test job using seeded fake registries.
- [ ] Publish unit test results.
- [ ] Publish integration test results.
- [ ] Publish Playwright report.
- [ ] Publish code coverage report.
- [ ] Publish SARIF security scan output.
- [ ] Publish schema validation results.
- [ ] Enforce per-service coverage thresholds.
	- Note: threshold targets are now recorded in [000-delivery-governance.md](000-delivery-governance.md); this remaining task is the coverage-report and CI gate implementation.
- [x] Enforce zero lint warnings.
- [ ] Block PR merge on failed required checks.
	- Blocker: CI workflow scaffold exists; Playwright, contract, integration, E2E, coverage, SARIF publication, and branch protection still need full wiring.

## Security Workflows

- [x] Add `security.yml` triggered on push to `main` and daily schedule.
- [x] Run `cargo audit`.
- [x] Run npm audit with high severity threshold.
- [x] Run `pip-audit` or OSV-compatible Python dependency audit.
- [ ] Run Semgrep with supply-chain and security rulesets.
- [ ] Fail workflow on high or critical findings.
- [ ] Document GitHub Security Advisory draft process.
- [x] Add Dependabot configuration for Rust, npm, Python, GitHub Actions, and Docker where applicable.
	- Blocker: dependency audit workflow exists; Semgrep, severity fail policy coverage for every scanner, and advisory process documentation remain.

## Release Automation

- [ ] Add Conventional Commits documentation.
- [ ] Protect `main` branch with PR-only merges.
- [x] Add `release.yml` using release-please.
- [x] Add `release-please-config.json`.
- [ ] Add generated `CHANGELOG.md` workflow path.
- [ ] Ensure single monorepo version strategy is documented.
- [ ] Inject `NEXT_PUBLIC_APP_VERSION` at build time.
- [ ] Expose version in Command Center nav footer.
- [ ] Expose version in About panel.
- [ ] Expose version in API `/health` response.
- [ ] Ensure version is never hardcoded in source.
	- Blocker: release-please scaffolding exists; branch protection, version exposure, changelog dry-run, and docs remain.

## Docker Publication

- [x] Add `docker-publish.yml` triggered by `v*.*.*` tags.
- [x] Configure Docker Buildx and QEMU for `linux/amd64` and `linux/arm64`.
- [x] Add Docker Hub login using `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`.
- [ ] Build and push `aegiscudo/mosquito-net`.
- [ ] Build and push `aegiscudo/triage-counter`.
- [ ] Build and push `aegiscudo/surgeon`.
- [ ] Build and push `aegiscudo/ai-analyst`.
- [ ] Build and push `aegiscudo/emergency-room`.
- [ ] Build and push `aegiscudo/feed-harvester`.
- [ ] Build and push `aegiscudo/sbom-service` placeholder or defer until Phase 2 if not shipping.
- [ ] Build and push `aegiscudo/aegiscudo-api`.
- [ ] Build and push `aegiscudo/command-center`.
- [x] Tag images with version.
- [x] Tag images with `latest`.
- [ ] Tag images with `sha-<short-sha>`.
- [ ] Ensure Dockerfiles are multi-stage.
- [x] Ensure images run as non-root.
- [x] Ensure no `.env` or secrets are baked into images.
- [ ] Add container vulnerability scan output to CI.
- [x] Place all service Dockerfiles at `infra/Dockerfile.<service-name>` (e.g. `infra/Dockerfile.mosquito-net`) per PRD §5.5 naming convention.
- [x] Rust service Dockerfiles: builder stage `rust:1-slim`; runner stage `gcr.io/distroless/cc-debian12` (or `debian:bookworm-slim` if dynamic linking is required).
- [ ] Python service Dockerfiles: builder `python:3.12-slim`; runner `python:3.12-slim` with production dependencies only.
- [x] Next.js Dockerfile: builder `node:22-alpine`; runner `node:22-alpine` copying `.next/standalone` output only.
- [ ] Pass `--build-arg APP_VERSION=<tag>` in all `docker build` invocations; consume as `ENV NEXT_PUBLIC_APP_VERSION` in Next.js image.
	- Blocker: Dockerfile and publish workflow scaffolding exists for implemented services; actual image builds/pushes, Python multi-stage hardening, Makefile APP_VERSION build args, vulnerability scan output, and feed-harvester/sbom-service publication decisions remain.

## Optional Package Publication

- [ ] Add conditional `npm-publish.yml` for public packages under `packages/`.
- [ ] Use `NPM_TOKEN` automation token.
- [ ] Skip publishing when no publishable packages exist.
- [ ] Add conditional `crates-publish.yml` for publishable workspace crates.
- [ ] Use `CARGO_REGISTRY_TOKEN`.
- [ ] Document topological publish order.
- [ ] Mark internal crates `publish = false`.

## Mandatory E2E Scenarios

- [ ] Developer installs a known approved npm package through Mosquito Net.
- [ ] Developer installs a quarantined npm package and receives deterministic block/warn response.
- [ ] npm `latest` fallback occurs only for eligible metadata resolution.
- [ ] npm fallback never occurs for explicit pinned integrity requests.
- [ ] PyPI candidate filtering excludes quarantined version while preserving install behavior.
- [ ] Unknown package triggers analysis job creation.
- [ ] Surgeon static analysis flags npm `postinstall` fixture.
- [ ] Emergency Room detects canary credential access.
- [ ] Emergency Room detects outbound network attempt.
- [ ] Security Specialist reviews evidence and approves time-limited override.
- [ ] Override expiry causes policy enforcement to resume.
- [ ] `aedo-cli` produces SARIF output and correct CI exit codes.
- [ ] Dashboard displays request, decision, sandbox, AI explanation, and audit evidence.
- [ ] Shadow mode records `WOULD_BLOCK` without breaking package-manager flow.

## Security Regression Tests

- [x] Archive traversal attempts are rejected.
- [ ] Decompression bomb limits are enforced.
- [ ] Oversized package limits are enforced.
- [ ] Malformed metadata is handled safely.
- [ ] Prompt injection in README/comments/package description is inert.
- [ ] Secret redaction failures are detected.
- [ ] Unauthorized override attempts are rejected.
- [ ] Tenant isolation violations are prevented.
- [ ] Lockfile integrity substitution regression is covered.
- [ ] Registry protocol compatibility regression is covered.
- [ ] Sandbox timeout and resource exhaustion are handled.
- [ ] Canary credential access detection is covered.
- [ ] Denylisted package and known-malicious fixture blocking is covered.
- [ ] AI agent canary file monitoring is covered.
- [ ] Worm/cross-package write detection is covered.

## Performance And Reliability Validation

- [ ] Cached decision lookup P95 is below 20 ms.
- [ ] Cached proxy overhead P95 is below 50 ms.
- [ ] Known artifact allow path P95 is below 100 ms.
- [ ] Metadata cache hit ratio exceeds 90 percent after warm-up in fixture environment.
- [ ] Static analysis P95 is below 90 seconds for typical fixture packages.
- [ ] Sandbox analysis P95 is below configured 10 minute timeout.
- [ ] Dashboard API P95 is below 500 ms for common filtered queries.
- [ ] Mosquito Net readiness and liveness behavior is tested under dependency outage.
- [ ] Fail-open/fail-closed policy behavior is tested for Triage outage.
- [ ] Stale feed behavior records feed snapshot age.
- [ ] AI Analyst and Langfuse outages degrade explanations without blocking deterministic decisions.
- [ ] Sandbox worker outage records missing sandbox evidence and follows tenant policy.
- [ ] Upstream registry outage serves only verified cached metadata/artifacts.

## Production Readiness Gate

- [ ] npm compatibility tests pass against fixture registries.
- [ ] PyPI compatibility tests pass against fixture registries.
- [ ] npm provenance attestation verification tests pass against signed and unsigned fixtures.
- [ ] PyPI digital attestation verification tests pass against provenance fixtures.
- [ ] Lockfile integrity substitution regression tests pass.
- [x] Archive traversal tests pass.
- [ ] Decompression-bomb tests pass.
- [ ] Sleeper/deferred-execution pattern detection fires on synthetic fixtures.
- [ ] AI agent injection detection fires on `.cursorrules` or Copilot instruction fixtures.
- [ ] Worm/cross-package write detection fires on sandbox fixtures.
- [ ] AI agent canary monitoring fires when package writes to canary AI config files.
- [ ] Sandbox has no cloud permissions and no customer secrets.
- [ ] Shadow-mode replay shows acceptable false-positive rate.
- [ ] All admin actions produce audit logs.
- [ ] All package decisions produce audit logs.
- [ ] AI prompts are redacted and schema-validated.
- [ ] Known malicious test fixtures are blocked before install.
- [ ] Fail-open/fail-closed behavior is tenant-configurable and tested.
- [ ] Emergency bypass requires scope, reason, approver, and expiry.
- [ ] Feed Harvester freshness alerts trigger when feed data is more than 24 hours stale.

## Operations Documentation

- [x] Write local development setup guide.
- [x] Write production deployment overview.
- [x] Write registry client configuration guide for npm.
- [x] Write registry client configuration guide for pip.
- [x] Write policy authoring guide.
- [ ] Write override and emergency bypass runbook.
- [ ] Write feed harvester operations guide.
- [x] Write sandbox operations and safety boundary guide.
- [x] Write AI provider and Langfuse operations guide.
- [ ] Write incident response guide for blocked malicious package.
- [ ] Write release and rollback guide.
