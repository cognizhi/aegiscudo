# Phase 3 Enterprise And Deep Detonation Plan

Source PRD sections: Phase 3 ecosystem integrations, Feature 4.6, Feature 6 Phase 3, 4.10, 4.11, deferred roadmap items in Revision History.

Goal: extend Aegiscudo into container/image supply chain protection, IDE/tooling ecosystem scanning, high-fidelity native and binary detonation, and enterprise compliance/reporting at scale.

## Phase Status

- [x] Phase 3 has an owner: `Aegiscudo Tech Lead`.
- [ ] Phase 2 expansion is stable enough for enterprise work.
- [ ] Enterprise deployment assumptions are documented.
- [ ] Phase 3 exit review is complete.

## Exit Criteria

- [ ] OCI/Docker scanning or registry proxying evaluates image manifests, layers, embedded package ecosystems, SBOMs, and provenance.
- [ ] IDE and extension ecosystem scanning covers VS Code/OpenVSX and selected future extension sources.
- [ ] High-fidelity detonation worker captures deeper telemetry for suspicious binary/native artifacts.
- [ ] SLSA v1.2 build level tracking is visible in policy and dashboard.
- [ ] CRA compliance reports and enterprise audit exports are available.
- [ ] Enterprise reliability, scale, and multi-region readiness are validated.

## OCI And Docker Support

- [x] Decide scanner-only, registry proxy, or hybrid OCI strategy.
- [ ] Implement OCI Distribution API v1.1 client/proxy path.
- [ ] Pull image manifest by tag.
- [ ] Pull image manifest by digest.
- [x] Inspect image config.
- [x] Inspect layer metadata.
- [x] Identify embedded npm dependencies in layers.
- [x] Identify embedded PyPI dependencies in layers.
- [ ] Identify OS package manager dependencies where in scope.
- [x] Identify embedded Cargo/Maven dependencies where available.
- [x] Generate image-level SBOM.
- [ ] Evaluate discovered dependencies against Aegiscudo policy.
- [x] Verify Sigstore/Cosign image attestations.
- [x] Preserve manifest and layer digest integrity.
- [ ] Add dashboard image scan evidence view.
- [ ] Add fixture image registry and layer analysis tests.
- Progress 2026-05-18: Chose scanner-only as the first Phase 3 Docker/OCI slice. `aedo` now delegates image inspection to Syft JSON, extracts supported embedded npm, PyPI, Cargo, and Maven package purls, preserves image ID, manifest digest, repo digest, config digest, and layer digest evidence as SBOM root properties, and generates CycloneDX/SPDX image SBOMs for the image root plus supported embedded application package ecosystems. `aedo scan docker` enriches embedded npm/PyPI findings through the existing CLI scan endpoint by ecosystem group when API config is available; embedded Cargo/Maven findings remain local report entries until `/v1/cli/scans` or a dedicated image scan API supports those ecosystems.
- Blocker 2026-05-18: OCI Distribution API v1.1 proxy/client work is intentionally not started in this slice because the scanner-only strategy avoids request-time proxy semantics. Next action: define the OCI proxy threat model, upstream credential handling, tenant registry mount behavior, and dashboard evidence model before opening registry proxy implementation.
- Blocker 2026-05-18: OS package manager dependency policy evaluation is contract-blocked. `PackageEcosystem` and `/v1/cli/scans` do not currently represent apk/deb/rpm ecosystems, so Syft OS package artifacts are skipped rather than forced into misleading Docker coordinates. Next action: add explicit OS package ecosystem contracts and policy semantics before enabling OS package findings.

## CLI Phase 3 Docker Commands

- [x] Implement `aedo scan docker --image <name>:<tag>`.
- [x] Implement `aedo scan docker --image <name>@sha256:<digest>`.
- [x] Implement `aedo scan docker --dockerfile Dockerfile --build-context .`.
- [x] Implement `aedo attest verify --image <name>:<tag> --ecosystem docker`.
- [x] Implement `aedo sbom generate --image <name>:<tag> --format cyclonedx-json`.
- [x] Add Docker command SARIF/JSON/text output tests.
- [x] Add CI workflow example for Docker image scanning.
- Progress 2026-05-18: `aedo scan docker` now accepts tagged images, digest-pinned images, mixed tag-plus-digest references, or Dockerfile plus build context, runs Syft, emits Docker root findings plus supported embedded package findings, cleans up temporary Dockerfile build tags after scanning, supports text/JSON/SARIF output, and preserves blocking exit-code behavior. `aedo sbom generate --image` renders image SBOMs through the existing CLI SBOM renderer. `aedo attest verify --ecosystem docker` shells out to `cosign verify-attestation` only after the caller provides an explicit trust selector (`--key`, identity plus issuer, or identity/issuer regex pair), avoiding unsafe broad keyless verification defaults. CI usage is documented in `docs/development/docker-image-scanning.md`.

## IDE And Developer Tooling Ecosystem Scanning

- [x] Define supported IDE extension sources for first release.
- [x] Add VS Code Marketplace metadata scanner design.
- [x] Add OpenVSX metadata scanner design.
- [x] Identify extension package formats and unpacking requirements.
- [x] Detect AI agent instruction injection in extension payloads.
- [x] Detect extension activation scripts and postinstall behavior.
- [x] Detect suspicious network, credential, and workspace file access patterns.
- [ ] Add extension SBOM fragment support.
- [ ] Add policy signals for publisher reputation and extension age.
- [ ] Add dashboard view for extension findings.
- [x] Add fixtures for malicious extension injection patterns.
- Progress 2026-05-18: Added the first local scanner-only IDE extension slice. `aedo scan vscode-extension --path <dir-or-vsix>` scans unpacked VS Code/OpenVSX-compatible extension directories and VSIX archives without executing extension code or extracting archives to disk. The scanner bounds file count and text file size, skips directory symlinks, rejects archive path traversal entries, emits `vscode-extension` coordinates, and flags AI agent instruction payloads, prompt-injection text, lifecycle scripts, broad activation events, network access, credential access, workspace file access, and process execution patterns. Architecture is documented in `docs/architecture/ide-extension-scanning.md`.
- Blocker 2026-05-18: Extension SBOM fragment support is not started because the SBOM contract does not yet model extension roots, bundled Node dependencies, and payload files as a first-class graph. Next action: define extension SBOM component and dependency semantics before adding `aedo sbom generate --vscode-extension`.
- Blocker 2026-05-18: Publisher reputation and extension age policy signals are not started because marketplace metadata ingestion/read-model storage is not implemented. Next action: add asynchronous VS Code Marketplace/OpenVSX metadata ingestion and normalized publisher identity before enforcing publisher reputation policy.
- Blocker 2026-05-18: Dashboard extension findings are not started because there is no persisted extension scan result read model or tenant-scoped API route. Next action: persist scanner findings and add a Command Center evidence panel once the API contract exists.

## High-Fidelity Detonation Worker

- [x] Select runtime: GKE Sandbox/gVisor, Firecracker/Kata microVM, disposable VM workers, or hybrid.
- [x] Define isolation threat model for high-fidelity workers.
- [x] Define worker lifecycle and teardown guarantees.
- [ ] Implement disposable worker provisioning.
- [ ] Implement strict identity with no customer secrets.
- [ ] Implement syscall-level tracing.
- [ ] Implement network packet metadata capture.
- [ ] Implement DNS capture.
- [ ] Implement process tree capture.
- [ ] Implement file open/read/write events.
- [ ] Implement dynamic library load events.
- [ ] Implement JVM class-load events.
- [ ] Implement native symbol and section-level observations.
- [ ] Implement canary credential access and exfiltration detection.
- [ ] Implement escalation path from MVP sandbox to high-fidelity worker.
- [ ] Add cost and concurrency quotas.
- [ ] Add tests with suspicious native and JVM fixtures.
- Progress 2026-05-18: High-fidelity detonation architecture is documented in `docs/architecture/high-fidelity-detonation.md`. Runtime selection is hybrid: GKE Sandbox/gVisor worker pools for scalable single-use Linux detonations, dedicated disposable VM workers for packet metadata, host-side tracing, and malware-style detonation, with Kata/Firecracker treated as an implementation option only where the deployment substrate supports it. The threat model, per-job identity constraints, no-customer-secret boundary, egress posture, telemetry families, lifecycle, and teardown verification requirements are defined.
- Blocker 2026-05-18: Disposable worker provisioning cannot start safely until infra contracts exist for GKE Sandbox/VM worker pools, per-job identity, object-storage prefixes, network policy, telemetry ingestion, and teardown verification. Next action: add Terraform/Kubernetes design and control-plane job tables before implementing provisioners.
- Blocker 2026-05-18: Syscall, packet metadata, DNS, process tree, file event, dynamic-library, JVM class-load, and native symbol/section capture cannot start until the tracing implementation is selected and validated per runtime. Next action: run a tracing spike comparing gVisor-observable signals, host eBPF/Tracee, ptrace/strace, tcpdump, and disposable VM host-side capture against the no-secret isolation model.
- Blocker 2026-05-18: Strict identity, quotas, and escalation queue handoff cannot start until the control plane has high-fidelity job state, tenant quotas, and evidence ingestion routes. Next action: add migrations and API contracts for high-fidelity jobs, quota counters, and report read models.
- Blocker 2026-05-18: High-fidelity telemetry emission cannot start until the sandbox telemetry/report schema has versioned event families, field budgets, redaction rules, fixtures, and backwards-compatible evidence-reader behavior. Next action: add schema fixtures for syscall, packet metadata, DNS, process tree, file access, library load, JVM class-load, native symbol/section, and canary events.

## Advanced Provenance And SLSA

- [x] Track SLSA v1.2 build level per package where provenance is available.
	- Progress 2026-05-18: `AttestationEvidence` now has optional SLSA/VSA contract fields for verified levels, normalized Build Track level, SLSA version, verifier ID, resource URI, policy URI, and dependency-level counts. The JSON schema, Python contract, and Rust core DTO accept these fields for passing evidence, reject out-of-range or inconsistent normalized levels, and reject VSA-only fields on non-VSA predicates. Persistence and ingestion remain blocked below.
- [ ] Display SLSA build level in evidence viewer and policy signals.
	- Blocker 2026-05-18: dashboard evidence viewer and request-time policy signal wiring cannot start until `artifact_attestations` persistence and evidence read models expose SLSA/VSA fields. Next action: add a migration/API read model for normalized SLSA evidence and then bind Command Center plus Triage Counter to that read model.
- [ ] Add SLSA consumer policy thresholds.
	- Blocker 2026-05-18: threshold behavior depends on verified SLSA field persistence and tenant trust-root policy. Next action: add policy schema fields for minimum accepted SLSA Build Track level after evidence persistence lands.
- [x] Evaluate SLSA Verification Summary Attestation production requirements.
	- Progress 2026-05-18: `docs/architecture/slsa-and-vsa.md` defines VSA consumer requirements, production prerequisites, and edge cases for pass, fail, missing, stale key, verifier/resource mismatch, dependency-level claims, and unsupported SLSA result strings.
- [x] Design Aegiscudo-generated VSA key management.
	- Progress 2026-05-18: `docs/architecture/slsa-and-vsa.md` requires dedicated verifier identities, KMS/HSM-backed non-exportable keys, tenant trust-root policy, key-version audit metadata, rotation windows, revocation handling, and non-production key isolation.
- [ ] Implement VSA production only after verification pipeline is stable.
	- Blocker 2026-05-18: VSA production cannot start until the provenance verification pipeline has stable subject/resource canonicalization, tenant trust-root policy, raw input attestation storage, and audit events. Next action: implement verifier pipeline contracts and fixtures before adding any signing path.
- [ ] Add audit evidence for generated verification summaries.
	- Blocker 2026-05-18: generated VSA audit evidence depends on the VSA production path. Next action: add audit-event schema fields for verifier ID, signing key version, policy digest, subject digest, resource URI, and generated VSA digest when VSA generation begins.
- [ ] Add tests for SLSA level parsing and policy behavior.
	- Progress 2026-05-18: Rust core tests cover SLSA Build Track level parsing, including highest-level selection, level 0, unevaluated/failed values, custom strings, Source Track strings, and unsupported Build Level 4. Python and schema contract tests validate the SLSA/VSA fixture and reject out-of-range build levels, failed evidence with SLSA fields, mismatched normalized levels, and VSA fields on non-VSA predicates. Full policy behavior remains blocked until consumer thresholds are defined.

## Compliance And Reporting

- [x] Implement EU Cyber Resilience Act report export.
	- Progress 2026-05-18: `aedo compliance cra --evidence-file <json> --output-format json|text` now exports a deterministic CRA supply-chain risk report from an explicit 1 MiB-capped evidence bundle. The CLI validates RFC3339 timestamps, ordered periods, SLSA level consistency, SBOM digest shape, and URL userinfo absence. CLI usage and the bundle shape are documented in `docs/development/compliance-reporting.md`.
- [x] Include supply chain risk management evidence in CRA report.
	- Progress 2026-05-18: CRA reports carry `risk_management_evidence` entries with control, evidence reference, and status, and surface missing evidence as open report items.
- [x] Include SBOM references in CRA report.
	- Progress 2026-05-18: CRA reports carry SBOM URI, format, and optional digest references from the evidence bundle.
- [x] Include audit log summaries in CRA report.
	- Progress 2026-05-18: CRA reports carry action-count audit summaries with optional first/last-seen timestamps, intentionally avoiding raw audit metadata dumps.
- [x] Implement NIST SSDF mapping report.
	- Progress 2026-05-18: `aedo compliance ssdf --evidence-file <json> --output-format json|text` maps available evidence to PO.1, PS.3, RV.1, and PW.4 with evidence-provided or evidence-missing status.
- [x] Implement SLSA consumer requirements mapping view.
	- Progress 2026-05-18: the compliance evidence bundle and CRA/SSDF reports include SLSA consumer requirement mappings with minimum and observed Build Track levels capped at 0 through 3.
- [ ] Surface OpenSSF Best Practices Badge status as policy signal.
	- Blocker 2026-05-18: OpenSSF Best Practices Badge cannot become a policy signal until package-to-project resolution and badge ingestion are defined for each supported ecosystem. Next action: add a feed/adapter contract that records project badge status and freshness before binding it in Triage Counter.
- [ ] Add PDF export for compliance reports if not completed in MVP.
	- Blocker 2026-05-18: PDF export requires an approved rendering engine, template governance, and redaction rules for report bundles. Next action: choose a server-side renderer and define a no-secret report template contract.
- [ ] Add CSV export for compliance reports.
	- Blocker 2026-05-18: compliance CSV exports require a stable column contract for CRA and SSDF report rows. Next action: define CSV schema after the API-backed report read model is settled.
- [ ] Add report retention and deletion workflows.
	- Blocker 2026-05-18: retention/deletion workflows require persisted report records, tenant retention policy fields, and audit events for report deletion. Next action: add migrations and API contracts for generated report metadata before implementing deletion.
- [ ] Add tests for report filters and export payloads.
	- Progress 2026-05-18: CLI unit tests cover CRA export payload composition, missing-evidence open items, SSDF mapping payloads, invalid SLSA build levels, invalid/reversed timestamps, inconsistent SLSA `met` status, malformed SBOM digests, URL userinfo rejection, and text output open-item details. Filter tests remain blocked until API or Command Center report filters exist.

## Enterprise Scale And Reliability

- [x] Design multi-region Mosquito Net deployment.
	- Progress 2026-05-18: `docs/architecture/enterprise-scale-reliability.md` defines regional Mosquito Net fleets, tenant residency routing, health/latency fallback ordering, request-time fail-closed behavior, trusted client identity requirements behind load balancers, bounded policy/override replication staleness, and regional audit/metrics boundaries.
- [x] Design regional artifact cache strategy.
	- Progress 2026-05-18: the enterprise reliability design defines region-local digest-addressed object storage, tenant-approved replication classes, sensitive header stripping, and cache rehydration through protocol-specific adapters.
- [x] Design feed snapshot replication strategy.
	- Progress 2026-05-18: the reliability design keeps live feed ingestion asynchronous, consumes only latest usable local snapshots at request time, and replicates normalized snapshot metadata while preserving regional stale/degraded state.
- [x] Design tenant-level data residency controls.
	- Progress 2026-05-18: tenant home region is defined as a control-plane policy property; artifacts, raw evidence, attestations, audit events, reports, and summaries remain home-region scoped unless explicit tenant policy permits replication.
- [x] Implement higher availability target path toward 99.99 percent enterprise uptime.
	- Progress 2026-05-18: the reliability design documents the 99.99 percent path as active-active regional Mosquito Net and Triage Counter capacity, health probes, policy snapshot replication SLOs, tested failover, and regional cache rehydration. The uptime target is not claimed until load/failover tests pass.
- [ ] Add rate limit dashboards and tenant quotas.
	- Progress 2026-05-18: Mosquito Net now emits `aegiscudo_rate_limit_events_total` labeled by tenant, registry, adapter, limiter, and outcome for dashboarding tenant API and client package-request limiter rejections. Both tenant and client limiter label paths are covered by focused tests. Dashboard panels, near-limit saturation metrics, trusted proxy identity extraction, and durable tenant quota administration remain open.
- [ ] Add sandbox and high-fidelity worker concurrency quotas.
	- Blocker 2026-05-18: worker concurrency quotas require durable tenant quota counters, high-fidelity job state, and queue admission controls. Next action: add control-plane quota schemas and queue admission contracts.
- [ ] Add LLM budget quotas per tenant and package.
	- Blocker 2026-05-18: LLM budget quotas require persisted budget windows, token/cost accounting, provider pricing metadata, and deterministic degradation behavior in AI Analyst. Next action: add budget schema and pre-request accounting before provider calls.
- [ ] Add customer-managed key encryption option if required.
	- Blocker 2026-05-18: CMK support requires envelope-encryption metadata, tenant key policy, rotation/revocation behavior, and recovery handling. Next action: write a key-management ADR before implementing storage changes.
- [x] Add disaster recovery runbook.
	- Progress 2026-05-18: `docs/development/disaster-recovery-runbook.md` defines recovery objectives, trigger conditions, response steps, validation checks, and current blockers for DB restore, object digest verification, feed degradation, and request-time proxy smoke tests.
- [ ] Add backup and restore tests.
	- Blocker 2026-05-18: backup/restore tests require a staging or CI service orchestration target with PostgreSQL backups and object-storage fixture buckets. Next action: add environment-gated restore tests once report/evidence retention metadata exists.
- [ ] Add load tests for request-time proxy paths.
	- Blocker 2026-05-18: load tests require stable seeded registries, rate-limit budgets, and a non-production performance environment. Next action: add k6 or equivalent request-time proxy scenarios after multi-region ingress topology is chosen.
- [ ] Add chaos tests for upstream registry, feed, sandbox, and AI outages.
	- Blocker 2026-05-18: chaos tests require failure-injection hooks for fixture registries, feed snapshots, worker queues, and AI providers. Next action: add environment-gated outage scenarios that prove request-time enforcement remains bounded to Mosquito Net and Triage Counter.

## Optional Supply Chain Graph Integration

- [x] Re-evaluate OpenSSF GUAC maturity and operational cost.
	- Progress 2026-05-18: `docs/architecture/supply-chain-graph-integration.md` records GUAC as an OpenSSF Incubating supply-chain graph option and documents the operational cost of adding a graph datastore, collectors, tenant isolation, backup/restore, and query authorization.
- [x] Decide whether SBOM Service remains sufficient internal graph for enterprise needs.
	- Progress 2026-05-18: SBOM Service remains the Phase 3 internal graph of record, backed by generated SBOMs, stored package fragments, dependency relationships, tenant-scoped exports, and deps.dev snapshots for request-time transitive signal propagation.
- [x] Design export/import bridge if GUAC is adopted.
	- Progress 2026-05-18: the bridge design is asynchronous only, tenant-approved, digest-traceable, no raw payload or secret export, tokenized by opaque graph namespace, advisory on import, quota-governed, and audit logged. Imported summaries must carry source digests, graph/query version, import time, and freshness/expiry, and cannot mutate enforcement state.
- [x] Add graph query use cases for auditors and security analysts.
	- Progress 2026-05-18: auditor/security analyst use cases are documented for vulnerable component reachability, shared maintainer/repository/provenance/infrastructure indicators, SBOM release diffs, blocked decision evidence tracing, and SLSA/VSA evidence gaps.
- [ ] Add tests for graph consistency and tenant isolation.
	- Blocker 2026-05-18: runtime graph consistency and tenant-isolation tests cannot start until there is a graph query API or GUAC bridge contract. Next action: define tenant-scoped graph export schemas and redaction fixtures before standing up any external graph runtime; add schema/fixture tests immediately once that contract exists.

## Deferred Integrations

- [x] Notification and alerting webhook integrations (Slack, PagerDuty, Jira) are explicitly deferred to Phase 3 or post-Phase 3; architecture must not block webhook output from override events, critical detections, and policy violations.
	- Progress 2026-05-18: `docs/architecture/outbound-webhooks.md` defines webhook delivery as asynchronous notification only, after override, critical detection, or policy violation records already exist. Request-time enforcement remains limited to Mosquito Net and Triage Counter.
- [x] Design outbound webhook event schema and tenant-configurable endpoint registration.
	- Progress 2026-05-18: `schemas/webhook-event.schema.json` and `schemas/webhook-endpoint.schema.json` define versioned outbound event payloads and tenant endpoint registration metadata with encrypted endpoint URL references, non-sensitive destination host hints, HMAC signing by secret reference, credential references only, bounded retry policy, opaque tenant references in outbound payloads, event-type semantic constraints, and fixtures for valid and adversarial cases.
- [x] Add webhook integration placeholder in admin UI (Phase 1C) with coming-soon state; implement in Phase 3.
	- Progress 2026-05-18: Command Center Admin / Integrations now shows coming-soon placeholders for Slack, PagerDuty, and Jira webhook destinations next to credential metadata.
	- Blocker 2026-05-18: provider-specific delivery adapters and editable endpoint forms cannot start until endpoint persistence, delivery queue tables, secret rotation behavior, RBAC routes, and delivery attempt retention are implemented. Next action: add migrations and API routes for webhook endpoint CRUD and delivery history before enabling tenant configuration.

## Additional Ecosystem Extension Points

- [x] Reassess RubyGems support.
	- Progress 2026-05-18: `docs/architecture/ecosystem-extension-points.md` recommends RubyGems lockfile/static scanning before registry proxy work, using purl type `gem` and proposed ecosystem ID `rubygems`.
	- Blocker 2026-05-18: implementation cannot start safely until shared contracts, DB enum migrations, `Gemfile.lock`/`.gemspec` fixtures, checksum semantics, and RubyGems compact-index/API behavior are defined. Next action: add an ecosystem descriptor contract and RubyGems fixtures before CLI or proxy code.
- [x] Reassess PHP Packagist support.
	- Progress 2026-05-18: Composer/Packagist is planned as a lockfile/static scanner first because Composer `dist` and `source` references can point to external archives or VCS sources. The proposed ecosystem ID is `composer`, with Packagist represented as a registry/source kind rather than conflated with all Composer repositories.
	- Blocker 2026-05-18: implementation cannot start safely until `composer.lock` identity rules, plugin/script risk signals, URL allowlists, archive digest capture, and Packagist/VCS source handling are defined. Next action: add Composer descriptor fields and adversarial fixtures.
- [x] Reassess NuGet support.
	- Progress 2026-05-18: NuGet is planned as a lockfile/project-assets scanner first, with deps.dev already mapping `NUGET` to purl type `nuget` for asynchronous enrichment.
	- Blocker 2026-05-18: NuGet registry/feed proxying cannot start until NuGet v3 service-index discovery, package-base-address behavior, private-feed credentials, `.nupkg` digest validation, and DB/API ecosystem contracts are defined. Next action: add NuGet descriptor, contracts, and fixtures.
- [x] Reassess Go Modules support.
	- Progress 2026-05-18: Go Modules are planned as a module graph scanner first, with deps.dev already mapping `GO` to purl type `golang` for asynchronous enrichment.
	- Blocker 2026-05-18: GOPROXY enforcement cannot start until module zip checksum semantics, `go.sum` handling, direct VCS fallback behavior, checksum database interaction, and DB/API ecosystem contracts are defined. `go list -m -json all` is allowed only as precomputed input or from an explicitly no-network/read-only resolver. Next action: add Go descriptor, fixtures, and a no-network module graph scanner design.
- [x] Define adapter interface changes needed for additional ecosystems.
	- Progress 2026-05-18: the ecosystem extension design defines descriptor fields for ecosystem ID, purl type, external feed system IDs, registry/source kind, protocol family, coordinate parser, lockfile parser, digest source of truth, lifecycle risks, feed mapping, SBOM mapping, and required fixtures.
- [x] Keep new ecosystems phase-gated and not coupled to OCI/Docker delivery unless explicitly approved.
	- Progress 2026-05-18: the phase gates require Rust/Python/TypeScript/OpenAPI/schema/database contract parity, scanner or adapter fixtures, explicit Triage Counter policy behavior, SBOM mapping, dashboard/API unavailable states, and adversarial tests before enabling a new ecosystem. OCI/Docker delivery remains independent.

## Phase 3 Validation

- [ ] OCI fixture registry tests pass.
	- Blocker 2026-05-18: dedicated OCI fixture registry tests cannot start until the OCI Distribution API proxy/client threat model and fixture registry harness exist. Scanner-only Docker/OCI unit coverage passed in the full Rust workspace test run. Next action: add a fixture registry and proxy contract before enabling registry-level OCI tests.
- [ ] Docker image SBOM and policy evaluation tests pass.
	- Progress 2026-05-18: Docker scanner/SBOM unit coverage passed in `cargo test --workspace -- --test-threads=1`. Full image policy evaluation remains partially blocked for unsupported embedded Cargo/Maven and OS package API contracts, as recorded in the OCI section.
- [ ] Cosign/Sigstore image attestation tests pass.
	- Progress 2026-05-18: CLI attestation trust-selector coverage passed in the full Rust workspace test run. Live Cosign/Sigstore integration tests remain environment-gated until test trust roots and fixture attestations are available.
- [ ] IDE extension malicious fixture tests pass.
	- Progress 2026-05-18: VS Code/OpenVSX extension scanner malicious fixture coverage passed in `cargo test --workspace -- --test-threads=1`.
- [ ] High-fidelity telemetry tests pass.
	- Blocker 2026-05-18: high-fidelity telemetry tests cannot start until worker provisioning, tracing implementation, and versioned telemetry schemas exist. Next action: add telemetry event schemas and fixtures after the high-fidelity tracing spike.
- [ ] Enterprise compliance export tests pass.
	- Progress 2026-05-18: CRA/SSDF compliance export unit coverage passed in `cargo test --workspace -- --test-threads=1`.
- [ ] Multi-region or scale test report is reviewed.
	- Blocker 2026-05-18: multi-region/scale reports cannot be produced until a non-production performance environment, seeded registries, and ingress topology are available. Next action: create environment-gated k6 or equivalent request-time proxy scenarios.
- [ ] Disaster recovery test report is reviewed.
	- Blocker 2026-05-18: DR test reports cannot be produced until staging/CI service orchestration provides PostgreSQL backups and object-storage fixture buckets. Next action: add environment-gated restore tests tied to report/evidence retention metadata.

Final validation 2026-05-18:

- `cargo fmt --all --check` passed.
- `cargo test --workspace -- --test-threads=1` passed.
- `uv run pytest` passed with 123 tests after removing a stale npm-sandbox assertion that expected JVM telemetry from an npm profile.
- `pnpm schema:validate` passed with 29 fixtures.
- `pnpm --recursive --if-present typecheck` passed after strict indexed-access fixes in Playwright fixtures.
- `pnpm --recursive --if-present test` passed with 131 frontend/shared-type tests.
- `PLAYWRIGHT_HTML_OPEN=never pnpm exec playwright test` passed from `apps/command-center` with 39 tests after making the live audit-log e2e check use action filters and adding denied override status coverage.
