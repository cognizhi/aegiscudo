# Phase 1A MVP Control Plane Plan

Source PRD sections: Feature 1, Feature 2, 2.3.1, 2.3.2, 3.3, 3.4, 3.5, 3.7.1, 3.7.3, 4.5, 4.6, 4.7, 4.8.

Goal: implement request-time dependency admission for npm and PyPI with deterministic policy decisions, compatible proxy behavior, auditability, and degraded-operation controls.

## Phase Status

- [x] Phase 1A has an owner: `Aegiscudo Tech Lead`.
- [ ] Phase 0 dependencies are complete or explicitly waived.
- [x] npm and PyPI fixture registries are available.
- [ ] Control-plane exit review is complete.

Progress note: 2026-05-05 implemented Phase 1A scaffolding for request DTOs, normalization, deterministic decision states, and HTTP service shells. Full Phase 1A remains blocked on booted backing services, fixture registries, persistence repositories, real adapters, and feed ingestion.
Progress note: 2026-05-06 decision responses now include tenant ID, policy profile ID, policy snapshot ID, enforcement mode, feed state, feed snapshot age, and trace ID across Rust DTOs, JSON schema fixtures, and Python contract models. Public OpenAPI/client workflow remains Phase 1C work.
Progress note: 2026-05-07 added SQLx-backed Triage Counter policy profile loading, repository-backed immutable policy snapshot creation, DecisionRequest-based HTTP evaluation with registry-bound policy context, SQLx-backed Mosquito Net enabled registry configuration loading, configured `/proxy/...` mount-path resolution, and the accepted Phase 1A routing model in [ADR 0001](../adr/0001-control-plane-routing-scope-and-mount-path-uniqueness.md). Full Phase 1A remains blocked on served fixture registries, real protocol adapters, persistence of decisions and audit, feed ingestion, caches, and performance evidence.
Progress note: 2026-05-07 added Mosquito Net decision-gated proxy scaffold calls to Triage Counter with bounded timeout/retry configuration, adapter-aware normalized decision request construction, advisory headers, conservative enforce-mode Triage outage fail-closed behavior for the current scaffolded request path, warn/shadow outage fail-open scaffolding for true outages, hard-fail handling for invalid Triage responses, and the accepted fail-mode binding in [ADR 0007](../adr/0007-request-time-triage-client-and-outage-binding.md). Full Phase 1A remains blocked on real upstream adapter proxying, durable audit/decision persistence, decision caches, fixture registries, feed ingestion, and performance evidence.
Progress note: 2026-05-07 Mosquito Net now persists shared-DTO audit events to PostgreSQL and emits matching structured service logs for request receipt and final proxy outcomes, with trace IDs propagated even on early request rejections and warn/shadow outage fail-open decisions. Full Phase 1A remains blocked on real upstream adapter proxying, decision caches, fixture registries, feed ingestion, and performance evidence.
Progress note: 2026-05-07 Mosquito Net now emits Prometheus metrics for request count and latency, decision state count and latency, and Triage latency on the current request-time decision path. Cache-hit and upstream-latency metrics remain blocked on cache abstractions and real upstream proxying.
Progress note: 2026-05-07 Mosquito Net service tests now cover allow, warn, quarantine, block, fallback, and Triage outage behavior on the current fake-Triage proxy path. Real adapter and fixture-registry integration coverage remains Phase 1A work.
Progress note: 2026-05-07 Triage Counter now persists decision records by inserting `package_requests` and `policy_decisions` rows with normalized coordinates, optional requested digests, policy snapshot IDs, feed freshness state and age, and a structured rationale payload that reserves `evidence_references` for later signal binding. Real evidence-reference population and cache lookup remain open.
Progress note: 2026-05-07 Triage Counter now exposes `/metrics` and emits Prometheus metrics for decision count, decision state, decision latency, and degraded-feed decision use on the request-time evaluation path. Cache-hit metrics remain blocked on a real decision cache.
Progress note: 2026-05-07 Triage Counter now treats a requested digest with no stored artifact match as an unknown artifact, queues `analysis_jobs` from normalized request context under [ADR 0008](../adr/0008-analysis-job-request-context-before-artifact-persistence.md), and keeps `artifact_id` optional until artifact persistence exists. The current Mosquito Net scaffold still does not forward request-time digests, so end-to-end proxy-triggered analysis jobs remain blocked on real artifact proxying and digest capture.
Progress note: 2026-05-07 Triage Counter now binds persisted vulnerability matches against a policy-defined `known_vulnerability_threshold` contract under [ADR 0009](../adr/0009-phase-1a-known-vulnerability-threshold-policy-contract.md), respects the `vulnerable_above_threshold` rule action for warn versus block behavior, and carries placeholder request-time inputs for deferred static analysis, sandbox, GitHub publish-gap, Trusted Publisher, and provenance or signature verification signals. Full feed-backed KEV or EPSS prioritization, metadata-derived minimum age, and evidence-backed signal population remain open.
Progress note: 2026-05-07 Triage Counter now binds `missing_or_failed_attestation` and `provenance_or_signature_verification_failed` from persisted `artifact_attestations`, and binds `ai_agent_injection_indicator` from persisted `static_analysis_reports` when Surgeon evidence contains the stable `ai-agent-injection` indicator type. Adapter-side evidence retrieval and broader static or sandbox policy thresholds remain open.
Progress note: 2026-05-07 Phase 1A request-time path now includes fixture registry services, local seed data, real npm/PyPI upstream proxying, artifact digest prefetch, in-process decision/metadata/artifact caches with metrics, dynamic registry reload, upstream credential injection from configured environment references, artifact size limits, PyPI HTML/JSON candidate filtering, and npm fallback guards for explicit version and tarball routes.
Progress note: 2026-05-07 Admin API now owns override lifecycle, emergency bypass, registry configuration CRUD, credential metadata CRUD/test endpoints, RBAC checks, audit events, and Mosquito Net reload notifications. Triage Counter now binds override/HITL, known malicious, prior allow verdicts, package signal observations, feed snapshot freshness, vulnerability threshold, attestation status, and AI-agent injection evidence.
Progress note: 2026-05-07 Feed Harvester MVP service ingests deterministic OSV, GHSA, OpenSSF malicious package, CISA KEV, and FIRST EPSS fixtures into last-successful feed snapshots, exposes refresh/status/metrics endpoints, and is wired into local Docker Compose. Remaining feed work is live-source scheduling, conditional requests, backoff, and circuit breakers.

## Exit Criteria

- [x] Mosquito Net serves npm and PyPI fixture metadata through registry configuration records.
- [x] Mosquito Net serves cached artifacts only after non-block Triage Counter decisions.
- [x] Triage Counter evaluates deterministic policy signals and returns all MVP decision states.
- [x] Unknown artifacts create analysis jobs without blocking request-time threads on heavy work.
- [x] npm fallback rewrites eligible metadata only and never substitutes explicit artifacts or integrity-pinned requests.
- [x] PyPI filtering removes disallowed candidates while preserving valid Simple API and JSON Simple API responses.
- [x] Feed Harvester provides last-successful snapshots for OSV, GHSA, OpenSSF Malicious Packages, CISA KEV, and FIRST EPSS where in MVP scope.
- [ ] All requests, decisions, overrides, policy mutations, and credential references are audit logged.
- [ ] Cached decision lookup and cached proxy overhead meet MVP latency budgets in local benchmark tests.

## Shared Request-Time Contracts

- [x] Define internal normalized request DTO for package-manager metadata requests.
- [x] Define internal normalized request DTO for artifact download requests.
- [x] Define package coordinate normalization rules for npm scoped/unscoped names.
- [x] Define package coordinate normalization rules for PyPI canonical names.
- [x] Define artifact digest lookup and missing-digest behavior.
- [x] Define Triage Counter decision request schema.
- [x] Define Triage Counter decision response schema.
- [x] Include registry configuration ID in every decision request.
- [x] Include tenant ID, policy profile ID, mode, feed snapshot state, and trace ID in every decision response.
- [x] Include advisory header payload format for warn, shadow, quarantine, and fallback cases.
- [x] Add contract tests for all decision states.
	- Note: decision response now carries tenant, policy profile, policy snapshot, `mode`, feed state, feed snapshot age, and trace ID. OpenAPI and generated UI/CLI request-client coverage remain Phase 1C work.

## Triage Counter Policy Engine

- [x] Implement policy profile loading from PostgreSQL.
- [x] Implement immutable policy snapshot creation.
- [x] Implement policy snapshot hash and version binding.
- [x] Implement rule evaluation order and precedence.
- [x] Implement decision cache lookup.
- [x] Implement known-safe organizational verdict allow.
- [x] Implement known-malicious match block.
- [x] Implement known-vulnerable warn/block decision based on policy threshold.
- [x] Implement minimum release age signal.
	- Triage Counter binds this from `package_signal_observations`; adapter-side extraction remains tracked in the adapter sections.
- [x] Implement install script or lifecycle hook signal ingestion.
	- Triage Counter binds this from `package_signal_observations`; npm metadata extraction remains tracked below.
- [x] Implement dependency confusion namespace signal.
	- Triage Counter binds this from `package_signal_observations`; namespace/source derivation remains adapter/feed work.
- [x] Implement typosquatting similarity signal against internal allowlist and popular names.
	- Triage Counter binds this from `package_signal_observations`; scorer population remains feed-side work.
- [x] Implement artifact digest reputation signal.
	- Triage Counter binds this from `package_signal_observations` and digest-specific request context.
- [x] Implement previous organizational verdict signal.
	- Triage Counter now looks up the latest prior tenant-scoped decision for the same coordinate, and digest when present, and binds `known_safe_verdict` when that latest persisted verdict was `ALLOW`. Broader verdict history and manual-approval scoring remain future enrichment.
- [x] Implement static analysis score signal placeholder.
	- Placeholder: Triage Counter now carries a thresholded `static_analysis_score_violation` input in `PolicyInput` and maps it to `BLOCK_POLICY_VIOLATION`. Real Surgeon-produced score calculation and evidence binding remain deferred.
- [x] Implement dynamic sandbox result signal placeholder.
	- Placeholder: Triage Counter now carries a thresholded `dynamic_sandbox_policy_violation` input in `PolicyInput` and maps it to `BLOCK_POLICY_VIOLATION`. Real Emergency Room or sandbox telemetry binding remains deferred.
- [x] Implement provenance/signature/attestation status signal.
	- Triage Counter now binds `missing_or_failed_attestation` and `provenance_or_signature_verification_failed` from persisted `artifact_attestations` for matching artifacts and coordinates. npm and PyPI adapter retrieval and persistence of those attestation records remain tracked in the adapter sections below.
- [x] Implement Trusted Publisher match signal placeholder.
	- Placeholder: Triage Counter now carries a `trusted_publisher_identity_mismatch` warning input so future attestation and provenance ingestion can populate the request-time signal without another `PolicyInput` contract change.
- [x] Implement GitHub-to-registry publish gap signal placeholder.
	- Placeholder: Triage Counter now carries a thresholded `github_to_registry_publish_gap_risk` input in `PolicyInput` and maps it to `BLOCK_POLICY_VIOLATION`. Real metadata-derived publish-gap computation remains deferred to adapter and feed work.
- [x] Implement CISA KEV and EPSS prioritization signals for mapped CVEs.
	- Triage Counter combines severity, CISA KEV, and EPSS probability from persisted vulnerability matches using the policy snapshot threshold. Broader feed-to-match materialization remains deferred.
- [x] Implement AI agent injection indicator signal from static evidence.
	- Triage Counter now inspects persisted `static_analysis_reports` for Surgeon's stable `ai-agent-injection` indicator type and binds the request-time `ai_agent_injection_indicator` when that evidence exists for the matching artifact or coordinate.
- [x] Implement maintainer account age signal where available from registry metadata.
	- Triage Counter binds the signal once observed; registry metadata extraction remains adapter work.
- [x] Implement recent maintainer change signal where available from registry metadata.
	- Triage Counter binds the signal once observed; registry metadata extraction remains adapter work.
- [x] Implement number of maintainers and ratio of recently publishing new maintainers signal (PRD §2.4 policy signal: flag packages with high proportion of new maintainers as elevated risk).
	- Triage Counter binds the high-new-maintainer-ratio signal once observed; registry metadata extraction remains adapter work.
- [x] Implement cross-ecosystem IOC correlation signal placeholder (deferred feed-side implementation to Phase 2; signal field is now wired into `PolicyInput` and decision evaluation so Feed Harvester can populate it later without a schema break).
- [x] Implement `ALLOW` response.
- [x] Implement `ALLOW_WITH_WARNING` response.
- [x] Implement `QUARANTINE_PENDING_ANALYSIS` response.
- [x] Implement `BLOCK_KNOWN_MALICIOUS` response.
- [x] Implement `BLOCK_POLICY_VIOLATION` response.
- [x] Implement `REQUIRE_HITL_APPROVAL` response.
- [x] Implement `FALLBACK_TO_APPROVED_CANDIDATE` response.
- [x] Create analysis job when unknown artifact requires asynchronous analysis.
- [x] Persist decision record with tenant, coordinate, digest, policy snapshot, feed snapshot age, and evidence references.
	- Triage Counter writes `package_requests` and `policy_decisions` rows with normalized coordinates, optional requested digests, policy snapshot IDs, feed state and age, and a structured rationale payload that includes an `evidence_references` array. Population of richer evidence-reference IDs remains tied to future signal persistence.
- [x] Emit metrics for decision count, state, latency, cache hit, and degraded feed use.
	- Triage Counter exposes `/metrics` and emits decision count/state/latency, decision cache hit/miss, and degraded-feed decision metrics.
- [x] Add unit tests for rule precedence.
- [x] Add unit tests for override precedence.
- [x] Add unit tests for feed stale/degraded behavior.
- [x] Add unit tests for every decision state.
	- Status: deterministic in-memory decision evaluation, precedence tests, DecisionRequest HTTP binding, PostgreSQL policy profile loading, registry-bound policy context, repository-backed immutable policy snapshot creation, known-safe organizational verdict handling, prior safe-verdict reuse from persisted `ALLOW` decisions, a policy-defined known vulnerability threshold contract under [ADR 0009](../adr/0009-phase-1a-known-vulnerability-threshold-policy-contract.md), real request-time bindings for vulnerability matches, package signal observations, feed freshness, override/HITL, attestation status, provenance or signature verification status, and AI agent injection evidence, schema-wired placeholder inputs for cross-ecosystem IOC, static analysis score, dynamic sandbox results, GitHub publish-gap, and Trusted Publisher mismatch, persisted decision records, decision cache/metrics, and digest-based analysis job queueing exist. Snapshot evidence-reference population and remaining adapter/feed-backed signal extraction remain before final exit.

## Override And HITL Control

- [x] Implement override request creation.
- [x] Implement override approval with required reason, approver, scope, and expiry.
- [x] Implement override denial with reason.
- [x] Implement override expiry enforcement.
- [x] Implement emergency bypass flow with expiry and audit reason.
- [ ] Implement global allowlist dual-control placeholder or enforcement flag.
- [ ] Implement developer-readable remediation guidance on blocks.
- [x] Add unauthorized override attempt tests.
- [x] Add expiry regression tests.
- [x] Add audit tests for override lifecycle.

## Registry Configuration Service

- [x] Implement CRUD for `registry_configs` through Admin API.
- [x] Validate globally unique non-deleted mount path for Phase 1A; Mosquito Net only loads enabled configs at startup, and tenant-aware mount reuse requires a future ADR.
- [x] Validate adapter enum and phase availability.
- [x] Validate upstream URL scheme and TLS verification setting.
- [x] Validate auth type and credential reference consistency.
- [ ] Prevent deletion of active registry config with in-flight requests.
- [x] Implement soft-delete behavior.
- [x] Implement dynamic reload notification for Mosquito Net.
- [x] Audit create, update, enable, disable, and delete actions.
- [x] Add integration tests for CRUD and tenant isolation.

## Mosquito Net Core

- [x] Implement Axum HTTP service shell.
- [x] Expose `/healthz`.
- [x] Expose `/readyz`.
- [x] Expose `/metrics` in Prometheus format.
- [x] Load registry configurations at startup.
- [x] Dynamically reload registry configurations without restart.
- [x] Dispatch incoming `/proxy/<mount-path>/...` requests to the configured adapter.
- [x] Inject upstream credentials without logging values.
- [x] Rewrite upstream metadata URLs to remain under the Mosquito Net base URL.
- [x] Rewrite redirect headers to remain under the Mosquito Net base URL.
- [x] Implement metadata cache abstraction.
- [x] Implement artifact cache abstraction keyed by digest.
- [x] Implement decision cache abstraction.
- [x] Implement Triage Counter client with timeout and retry policy.
- [x] Implement enforcement-mode fail-closed when Triage Counter is unavailable for unknown artifacts.
- [x] Implement shadow/warn fail-open with audit and warning header.
- [ ] Implement cached known-good serving when feeds are stale, with feed snapshot age recorded.
	- Note: degraded-operation precedence is defined by [ADR 0002](../adr/0002-degraded-operation-and-fail-mode-precedence.md).
- [x] Implement per-tenant API rate limits enforced at proxy entry (PRD §4.6).
- [x] Implement per-client package request rate limits with configurable window and burst settings.
- [ ] Implement circuit breakers for upstream registry outages.
- [x] Implement artifact size limit: reject downloads exceeding configured maximum bytes before analysis begins.
- [ ] Emit audit events for every inbound request and final decision.
	- Partial: Mosquito Net now persists shared-DTO audit events for resolved, tenant-bound proxy requests and emits matching structured service logs for final outcomes. Unresolved proxy paths still lack durable audit persistence because `audit_events` is tenant-scoped and registry resolution can fail before a tenant is known.
- [x] Emit metrics for request count, adapter, decision state, cache hit, upstream latency, and Triage latency.
	- Mosquito Net emits request/latency, decision state/latency, cache event, upstream latency, and Triage latency metrics.
- [x] Add integration tests for allow, warn, quarantine, block, fallback, and Triage outage behavior.

## npm Adapter

- [x] Implement npm packument metadata route.
- [x] Implement scoped package route normalization.
- [x] Implement tarball download proxy route.
- [x] Preserve npm package-manager compatibility for npm, yarn, pnpm, and bun fixture clients where practical.
- [x] Preserve `dist.integrity`, `dist.shasum`, and tarball digest evidence.
- [ ] Implement dist-tag policy rewrite for eligible `latest` resolution.
- [x] Implement fallback to newest approved candidate when policy permits.
- [x] Add explicit guard preventing fallback for explicit version route.
- [x] Add explicit guard preventing fallback for tarball URL requests.
- [x] Add explicit guard preventing substitution when lockfile integrity is known or provided.
- [x] Add Aegiscudo advisory header or side-channel event when fallback occurs.
- [ ] Detect and extract npm lifecycle scripts from metadata where available.
- [ ] Capture maintainer and publish timestamp metadata.
- [ ] Capture registry signature data from packument `dist.signatures`.
- [ ] Fetch npm registry public keys with caching and rotation handling.
- [ ] Verify npm ECDSA signatures where present.
- [ ] Retrieve npm provenance/publish attestation evidence where available.
- [ ] Store normalized attestation evidence and raw attestation object digest.
- [ ] Treat missing attestation as configurable risk signal, not automatic block.
- [ ] Add fixture tests for signed, unsigned, stale-key, invalid-signature, and missing-provenance packages.
- [ ] Add fixture tests for `latest` fallback and lockfile substitution regression.
	- Partial: Mosquito Net regression tests now cover fallback metadata substitution and explicit version/tarball non-substitution. End-to-end package-manager fixture client coverage remains open.

## PyPI Adapter

- [x] Implement PEP 503 HTML Simple API project page route.
- [x] Implement PEP 691 JSON Simple API route.
- [x] Implement file download proxy route for wheels and source distributions.
- [x] Canonicalize package names according to PyPI rules.
- [x] Filter candidate files by decision while preserving valid page structure.
- [x] Preserve hashes and links for allowed candidates.
- [x] Never rewrite PyPI as if it had npm-style `latest` dist-tags.
- [x] Capture wheel/sdist metadata and digests.
- [ ] Capture `data-provenance` and JSON `provenance` references.
- [ ] Validate provenance URLs are secure and fully qualified.
- [ ] Retrieve PyPI digital attestations using PEP 740 semantics.
- [ ] Verify in-toto subject filename and SHA-256 digest against the exact served distribution file.
- [ ] Store normalized attestation evidence and raw attestation object digest.
- [ ] Treat missing attestation for popular packages as configurable risk signal.
- [x] Add fixture tests for HTML Simple API filtering.
- [x] Add fixture tests for JSON Simple API filtering.
- [ ] Add fixture tests for provenance pass, fail, missing, and mismatched subject digest.

## Feed Harvester MVP

- [x] Implement feed source registry and schedule configuration.
- [x] Implement OSV batch ingestion and normalization.
- [ ] Prefer HTTP/2 for the OSV batch API (`/v1/querybatch`) to avoid the 32 MiB HTTP/1.1 response limit when fetching large batches.
- [x] Implement GHSA GraphQL ingestion with point-limit handling and pagination.
	- Fixture-backed normalization is implemented; live GraphQL point-limit and pagination handling remain open.
- [x] Implement OpenSSF Malicious Packages ingestion.
- [x] Implement CISA KEV catalog ingestion; record catalog version and `dateReleased` field for audit.
- [x] Implement FIRST EPSS batch or CSV ingestion; support historic-date queries for trend data where practical.
	- Fixture-backed CSV ingestion is implemented; historic-date live queries remain open.
- [ ] Implement optional GCVE ingestion if MVP capacity permits.
- [ ] Add OpenSSF Package Analysis (GCS public bucket) ingestion as an optional Phase 1A feed; defer to Phase 2 if capacity is insufficient.
- [x] Persist normalized last-successful snapshot per feed.
- [x] Expose feed state as `fresh`, `stale`, `degraded`, or `unavailable`.
- [ ] Implement conditional requests where supported.
- [ ] Implement exponential backoff with jitter.
- [ ] Implement per-feed circuit breakers.
- [x] Emit metrics for last success time, record counts, failures, and stale age.
- [x] Add tests with OSV, GHSA, malicious package, KEV, and EPSS fixtures.
- [x] Verify request-time policy never calls live public feed APIs synchronously.

## Credential Configuration MVP

- [x] Load bootstrap credentials from `.env` or environment.
- [ ] Validate required feed and AI credentials at service startup where applicable.
- [x] Store runtime credential metadata in `integration_credentials`.
- [ ] Store credential values encrypted, outside plain filesystem storage.
- [x] Implement Admin API credential create, rotate, delete, and test-connection endpoints.
- [x] Push credential changes to relevant services through internal reload endpoint.
- [x] Ensure credential values never appear in logs or audit events.
- [x] Audit credential create, rotate, and delete events.
- [ ] Add tests for masked status, deletion confirmation, and runtime override precedence.
	- Partial: Admin API and Mosquito Net tests cover credential metadata/runtime injection behavior without asserting the full masked-status and deletion UX matrix.

## Control-Plane Integration Tests

Progress note: 2026-05-07 Mosquito Net service-level tests cover fake-Triage allow, enforce block, warn advisory block, enforce outage fail-closed, and warn outage fail-open behavior. Full control-plane integration tests still require served fixture registries and real npm/PyPI adapter proxying.

- [x] Mosquito Net calls Triage Counter for allow decision.
- [x] Mosquito Net calls Triage Counter for warn decision.
- [x] Mosquito Net calls Triage Counter for quarantine decision.
- [x] Mosquito Net calls Triage Counter for known-malicious block decision.
- [x] Mosquito Net handles fallback decision on npm metadata.
- [x] Explicit npm tarball request is never substituted.
- [x] PyPI candidate filtering preserves allowed candidates.
- [x] Unknown artifact creates analysis job.
- [x] Policy decision persists with policy snapshot ID.
- [x] Audit trace propagates from request to decision.
- [x] Registry config tenant isolation is enforced.
- [x] Triage outage fail mode follows tenant and registry policy.

## Control-Plane Performance Checks

- [ ] Cached decision lookup P95 is below 20 ms in local benchmark.
- [ ] Cached proxy overhead P95 is below 50 ms excluding upstream latency.
- [ ] Known artifact allow path P95 is below 100 ms in local fixture test.
- [x] Metadata cache hit ratio can be measured per tenant and registry.
- [x] Request-time services do not block on live feed ingestion, sandbox, or LLM calls.
