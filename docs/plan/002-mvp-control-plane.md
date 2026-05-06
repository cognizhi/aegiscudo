# Phase 1A MVP Control Plane Plan

Source PRD sections: Feature 1, Feature 2, 2.3.1, 2.3.2, 3.3, 3.4, 3.5, 3.7.1, 3.7.3, 4.5, 4.6, 4.7, 4.8.

Goal: implement request-time dependency admission for npm and PyPI with deterministic policy decisions, compatible proxy behavior, auditability, and degraded-operation controls.

## Phase Status

- [x] Phase 1A has an owner: `Aegiscudo Tech Lead`.
- [ ] Phase 0 dependencies are complete or explicitly waived.
- [ ] npm and PyPI fixture registries are available.
- [ ] Control-plane exit review is complete.

Progress note: 2026-05-05 implemented Phase 1A scaffolding for request DTOs, normalization, deterministic decision states, and HTTP service shells. Full Phase 1A remains blocked on booted backing services, fixture registries, persistence repositories, real adapters, and feed ingestion.

## Exit Criteria

- [ ] Mosquito Net serves npm and PyPI fixture metadata through registry configuration records.
- [ ] Mosquito Net serves cached artifacts only after non-block Triage Counter decisions.
- [ ] Triage Counter evaluates deterministic policy signals and returns all MVP decision states.
- [ ] Unknown artifacts create analysis jobs without blocking request-time threads on heavy work.
- [ ] npm fallback rewrites eligible metadata only and never substitutes explicit artifacts or integrity-pinned requests.
- [ ] PyPI filtering removes disallowed candidates while preserving valid Simple API and JSON Simple API responses.
- [ ] Feed Harvester provides last-successful snapshots for OSV, GHSA, OpenSSF Malicious Packages, CISA KEV, and FIRST EPSS where in MVP scope.
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
- [ ] Include tenant ID, policy profile ID, mode, feed snapshot state, and trace ID in every decision response.
- [x] Include advisory header payload format for warn, shadow, quarantine, and fallback cases.
- [x] Add contract tests for all decision states.
	- Blocker: decision response includes tenant, policy profile, feed state, and trace ID; an explicit enforcement `mode` field still needs to be added before this line can close.

## Triage Counter Policy Engine

- [ ] Implement policy profile loading from PostgreSQL.
- [ ] Implement immutable policy snapshot creation.
- [ ] Implement policy snapshot hash and version binding.
- [x] Implement rule evaluation order and precedence.
- [ ] Implement decision cache lookup.
- [ ] Implement known-safe organizational verdict allow.
- [x] Implement known-malicious match block.
- [ ] Implement known-vulnerable warn/block decision based on policy threshold.
- [ ] Implement minimum release age signal.
- [ ] Implement install script or lifecycle hook signal ingestion.
- [ ] Implement dependency confusion namespace signal.
- [ ] Implement typosquatting similarity signal against internal allowlist and popular names.
- [ ] Implement artifact digest reputation signal.
- [ ] Implement previous organizational verdict signal.
- [ ] Implement static analysis score signal placeholder.
- [ ] Implement dynamic sandbox result signal placeholder.
- [ ] Implement provenance/signature/attestation status signal.
- [ ] Implement Trusted Publisher match signal placeholder.
- [ ] Implement GitHub-to-registry publish gap signal placeholder.
- [ ] Implement CISA KEV and EPSS prioritization signals for mapped CVEs.
- [ ] Implement AI agent injection indicator signal from static evidence.
- [ ] Implement maintainer account age signal where available from registry metadata.
- [ ] Implement recent maintainer change signal where available from registry metadata.
- [ ] Implement number of maintainers and ratio of recently publishing new maintainers signal (PRD §2.4 policy signal: flag packages with high proportion of new maintainers as elevated risk).
- [ ] Implement cross-ecosystem IOC correlation signal placeholder (deferred feed-side implementation to Phase 2; wire signal field in decision schema now so Phase 2 can populate without schema changes).
- [x] Implement `ALLOW` response.
- [x] Implement `ALLOW_WITH_WARNING` response.
- [x] Implement `QUARANTINE_PENDING_ANALYSIS` response.
- [x] Implement `BLOCK_KNOWN_MALICIOUS` response.
- [x] Implement `BLOCK_POLICY_VIOLATION` response.
- [x] Implement `REQUIRE_HITL_APPROVAL` response.
- [x] Implement `FALLBACK_TO_APPROVED_CANDIDATE` response.
- [ ] Create analysis job when unknown artifact requires asynchronous analysis.
- [ ] Persist decision record with tenant, coordinate, digest, policy snapshot, feed snapshot age, and evidence references.
- [ ] Emit metrics for decision count, state, latency, cache hit, and degraded feed use.
- [x] Add unit tests for rule precedence.
- [x] Add unit tests for override precedence.
- [x] Add unit tests for feed stale/degraded behavior.
- [x] Add unit tests for every decision state.
	- Blocker: deterministic in-memory decision evaluation and precedence tests exist; PostgreSQL policy loading/snapshots, cache, persisted decisions, metrics, and real signal ingestion/calculation remain before Phase 1A exit.

## Override And HITL Control

- [ ] Implement override request creation.
- [ ] Implement override approval with required reason, approver, scope, and expiry.
- [ ] Implement override denial with reason.
- [ ] Implement override expiry enforcement.
- [ ] Implement emergency bypass flow with expiry and audit reason.
- [ ] Implement global allowlist dual-control placeholder or enforcement flag.
- [ ] Implement developer-readable remediation guidance on blocks.
- [ ] Add unauthorized override attempt tests.
- [ ] Add expiry regression tests.
- [ ] Add audit tests for override lifecycle.

## Registry Configuration Service

- [ ] Implement CRUD for `registry_configs` through Admin API.
- [ ] Validate unique mount path per tenant.
- [ ] Validate adapter enum and phase availability.
- [ ] Validate upstream URL scheme and TLS verification setting.
- [ ] Validate auth type and credential reference consistency.
- [ ] Prevent deletion of active registry config with in-flight requests.
- [ ] Implement soft-delete behavior.
- [ ] Implement dynamic reload notification for Mosquito Net.
- [ ] Audit create, update, enable, disable, and delete actions.
- [ ] Add integration tests for CRUD and tenant isolation.

## Mosquito Net Core

- [x] Implement Axum HTTP service shell.
- [x] Expose `/healthz`.
- [x] Expose `/readyz`.
- [x] Expose `/metrics` in Prometheus format.
- [ ] Load registry configurations at startup.
- [ ] Dynamically reload registry configurations without restart.
- [ ] Dispatch incoming `/proxy/<mount-path>/...` requests to the configured adapter.
- [ ] Inject upstream credentials without logging values.
- [ ] Rewrite upstream metadata URLs to remain under the Mosquito Net base URL.
- [ ] Rewrite redirect headers to remain under the Mosquito Net base URL.
- [ ] Implement metadata cache abstraction.
- [ ] Implement artifact cache abstraction keyed by digest.
- [ ] Implement decision cache abstraction.
- [ ] Implement Triage Counter client with timeout and retry policy.
- [ ] Implement enforcement-mode fail-closed when Triage Counter is unavailable for unknown artifacts.
- [ ] Implement shadow/warn fail-open with audit and warning header.
- [ ] Implement cached known-good serving when feeds are stale, with feed snapshot age recorded.
- [ ] Implement per-tenant API rate limits enforced at proxy entry (PRD §4.6).
- [ ] Implement per-client package request rate limits with configurable window and burst settings.
- [ ] Implement circuit breakers for upstream registry outages.
- [ ] Implement artifact size limit: reject downloads exceeding configured maximum bytes before analysis begins.
- [ ] Emit audit events for every inbound request and final decision.
- [ ] Emit metrics for request count, adapter, decision state, cache hit, upstream latency, and Triage latency.
- [ ] Add integration tests for allow, warn, quarantine, block, fallback, and Triage outage behavior.
	- Blocker: proxy route shell and npm/PyPI name normalization exist; real registry config loading, upstream proxying, caches, Triage client, audit, rate limits, and adapter integration tests remain.

## npm Adapter

- [ ] Implement npm packument metadata route.
- [ ] Implement scoped package route normalization.
- [ ] Implement tarball download proxy route.
- [ ] Preserve npm package-manager compatibility for npm, yarn, pnpm, and bun fixture clients where practical.
- [ ] Preserve `dist.integrity`, `dist.shasum`, and tarball digest evidence.
- [ ] Implement dist-tag policy rewrite for eligible `latest` resolution.
- [ ] Implement fallback to newest approved candidate when policy permits.
- [ ] Add explicit guard preventing fallback for explicit version route.
- [ ] Add explicit guard preventing fallback for tarball URL requests.
- [ ] Add explicit guard preventing substitution when lockfile integrity is known or provided.
- [ ] Add Aegiscudo advisory header or side-channel event when fallback occurs.
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

## PyPI Adapter

- [ ] Implement PEP 503 HTML Simple API project page route.
- [ ] Implement PEP 691 JSON Simple API route.
- [ ] Implement file download proxy route for wheels and source distributions.
- [ ] Canonicalize package names according to PyPI rules.
- [ ] Filter candidate files by decision while preserving valid page structure.
- [ ] Preserve hashes and links for allowed candidates.
- [ ] Never rewrite PyPI as if it had npm-style `latest` dist-tags.
- [ ] Capture wheel/sdist metadata and digests.
- [ ] Capture `data-provenance` and JSON `provenance` references.
- [ ] Validate provenance URLs are secure and fully qualified.
- [ ] Retrieve PyPI digital attestations using PEP 740 semantics.
- [ ] Verify in-toto subject filename and SHA-256 digest against the exact served distribution file.
- [ ] Store normalized attestation evidence and raw attestation object digest.
- [ ] Treat missing attestation for popular packages as configurable risk signal.
- [ ] Add fixture tests for HTML Simple API filtering.
- [ ] Add fixture tests for JSON Simple API filtering.
- [ ] Add fixture tests for provenance pass, fail, missing, and mismatched subject digest.

## Feed Harvester MVP

- [ ] Implement feed source registry and schedule configuration.
- [ ] Implement OSV batch ingestion and normalization.
- [ ] Prefer HTTP/2 for the OSV batch API (`/v1/querybatch`) to avoid the 32 MiB HTTP/1.1 response limit when fetching large batches.
- [ ] Implement GHSA GraphQL ingestion with point-limit handling and pagination.
- [ ] Implement OpenSSF Malicious Packages ingestion.
- [ ] Implement CISA KEV catalog ingestion; record catalog version and `dateReleased` field for audit.
- [ ] Implement FIRST EPSS batch or CSV ingestion; support historic-date queries for trend data where practical.
- [ ] Implement optional GCVE ingestion if MVP capacity permits.
- [ ] Add OpenSSF Package Analysis (GCS public bucket) ingestion as an optional Phase 1A feed; defer to Phase 2 if capacity is insufficient.
- [ ] Persist normalized last-successful snapshot per feed.
- [ ] Expose feed state as `fresh`, `stale`, `degraded`, or `unavailable`.
- [ ] Implement conditional requests where supported.
- [ ] Implement exponential backoff with jitter.
- [ ] Implement per-feed circuit breakers.
- [ ] Emit metrics for last success time, record counts, failures, and stale age.
- [ ] Add tests with OSV, GHSA, malicious package, KEV, and EPSS fixtures.
- [ ] Verify request-time policy never calls live public feed APIs synchronously.

## Credential Configuration MVP

- [ ] Load bootstrap credentials from `.env` or environment.
- [ ] Validate required feed and AI credentials at service startup where applicable.
- [ ] Store runtime credential metadata in `integration_credentials`.
- [ ] Store credential values encrypted, outside plain filesystem storage.
- [ ] Implement Admin API credential create, rotate, delete, and test-connection endpoints.
- [ ] Push credential changes to relevant services through internal reload endpoint.
- [ ] Ensure credential values never appear in logs or audit events.
- [ ] Audit credential create, rotate, and delete events.
- [ ] Add tests for masked status, deletion confirmation, and runtime override precedence.

## Control-Plane Integration Tests

- [ ] Mosquito Net calls Triage Counter for allow decision.
- [ ] Mosquito Net calls Triage Counter for warn decision.
- [ ] Mosquito Net calls Triage Counter for quarantine decision.
- [ ] Mosquito Net calls Triage Counter for known-malicious block decision.
- [ ] Mosquito Net handles fallback decision on npm metadata.
- [ ] Explicit npm tarball request is never substituted.
- [ ] PyPI candidate filtering preserves allowed candidates.
- [ ] Unknown artifact creates analysis job.
- [ ] Policy decision persists with policy snapshot ID.
- [ ] Audit trace propagates from request to decision.
- [ ] Registry config tenant isolation is enforced.
- [ ] Triage outage fail mode follows tenant and registry policy.

## Control-Plane Performance Checks

- [ ] Cached decision lookup P95 is below 20 ms in local benchmark.
- [ ] Cached proxy overhead P95 is below 50 ms excluding upstream latency.
- [ ] Known artifact allow path P95 is below 100 ms in local fixture test.
- [ ] Metadata cache hit ratio can be measured per tenant and registry.
- [ ] Request-time services do not block on live feed ingestion, sandbox, or LLM calls.
