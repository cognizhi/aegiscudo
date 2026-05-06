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

- [ ] Decide scanner-only, registry proxy, or hybrid OCI strategy.
- [ ] Implement OCI Distribution API v1.1 client/proxy path.
- [ ] Pull image manifest by tag.
- [ ] Pull image manifest by digest.
- [ ] Inspect image config.
- [ ] Inspect layer metadata.
- [ ] Identify embedded npm dependencies in layers.
- [ ] Identify embedded PyPI dependencies in layers.
- [ ] Identify OS package manager dependencies where in scope.
- [ ] Identify embedded Cargo/Maven dependencies where available.
- [ ] Generate image-level SBOM.
- [ ] Evaluate discovered dependencies against Aegiscudo policy.
- [ ] Verify Sigstore/Cosign image attestations.
- [ ] Preserve manifest and layer digest integrity.
- [ ] Add dashboard image scan evidence view.
- [ ] Add fixture image registry and layer analysis tests.

## CLI Phase 3 Docker Commands

- [ ] Implement `aedo scan docker --image <name>:<tag>`.
- [ ] Implement `aedo scan docker --image <name>@sha256:<digest>`.
- [ ] Implement `aedo scan docker --dockerfile Dockerfile --build-context .`.
- [ ] Implement `aedo attest verify --image <name>:<tag> --ecosystem docker`.
- [ ] Implement `aedo sbom generate --image <name>:<tag> --format cyclonedx-json`.
- [ ] Add Docker command SARIF/JSON/text output tests.
- [ ] Add CI workflow example for Docker image scanning.

## IDE And Developer Tooling Ecosystem Scanning

- [ ] Define supported IDE extension sources for first release.
- [ ] Add VS Code Marketplace metadata scanner design.
- [ ] Add OpenVSX metadata scanner design.
- [ ] Identify extension package formats and unpacking requirements.
- [ ] Detect AI agent instruction injection in extension payloads.
- [ ] Detect extension activation scripts and postinstall behavior.
- [ ] Detect suspicious network, credential, and workspace file access patterns.
- [ ] Add extension SBOM fragment support.
- [ ] Add policy signals for publisher reputation and extension age.
- [ ] Add dashboard view for extension findings.
- [ ] Add fixtures for malicious extension injection patterns.

## High-Fidelity Detonation Worker

- [ ] Select runtime: GKE Sandbox/gVisor, Firecracker/Kata microVM, disposable VM workers, or hybrid.
- [ ] Define isolation threat model for high-fidelity workers.
- [ ] Define worker lifecycle and teardown guarantees.
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

## Advanced Provenance And SLSA

- [ ] Track SLSA v1.2 build level per package where provenance is available.
- [ ] Display SLSA build level in evidence viewer and policy signals.
- [ ] Add SLSA consumer policy thresholds.
- [ ] Evaluate SLSA Verification Summary Attestation production requirements.
- [ ] Design Aegiscudo-generated VSA key management.
- [ ] Implement VSA production only after verification pipeline is stable.
- [ ] Add audit evidence for generated verification summaries.
- [ ] Add tests for SLSA level parsing and policy behavior.

## Compliance And Reporting

- [ ] Implement EU Cyber Resilience Act report export.
- [ ] Include supply chain risk management evidence in CRA report.
- [ ] Include SBOM references in CRA report.
- [ ] Include audit log summaries in CRA report.
- [ ] Implement NIST SSDF mapping report.
- [ ] Implement SLSA consumer requirements mapping view.
- [ ] Surface OpenSSF Best Practices Badge status as policy signal.
- [ ] Add PDF export for compliance reports if not completed in MVP.
- [ ] Add report retention and deletion workflows.
- [ ] Add tests for report filters and export payloads.

## Enterprise Scale And Reliability

- [ ] Design multi-region Mosquito Net deployment.
- [ ] Design regional artifact cache strategy.
- [ ] Design feed snapshot replication strategy.
- [ ] Design tenant-level data residency controls.
- [ ] Implement higher availability target path toward 99.99 percent enterprise uptime.
- [ ] Add rate limit dashboards and tenant quotas.
- [ ] Add sandbox and high-fidelity worker concurrency quotas.
- [ ] Add LLM budget quotas per tenant and package.
- [ ] Add customer-managed key encryption option if required.
- [ ] Add disaster recovery runbook.
- [ ] Add backup and restore tests.
- [ ] Add load tests for request-time proxy paths.
- [ ] Add chaos tests for upstream registry, feed, sandbox, and AI outages.

## Optional Supply Chain Graph Integration

- [ ] Re-evaluate OpenSSF GUAC maturity and operational cost.
- [ ] Decide whether SBOM Service remains sufficient internal graph for enterprise needs.
- [ ] Design export/import bridge if GUAC is adopted.
- [ ] Add graph query use cases for auditors and security analysts.
- [ ] Add tests for graph consistency and tenant isolation.

## Deferred Integrations

- [ ] Notification and alerting webhook integrations (Slack, PagerDuty, Jira) are explicitly deferred to Phase 3 or post-Phase 3; architecture must not block webhook output from override events, critical detections, and policy violations.
- [ ] Design outbound webhook event schema and tenant-configurable endpoint registration.
- [ ] Add webhook integration placeholder in admin UI (Phase 1C) with coming-soon state; implement in Phase 3.

## Additional Ecosystem Extension Points

- [ ] Reassess RubyGems support.
- [ ] Reassess PHP Packagist support.
- [ ] Reassess NuGet support.
- [ ] Reassess Go Modules support.
- [ ] Define adapter interface changes needed for additional ecosystems.
- [ ] Keep new ecosystems phase-gated and not coupled to OCI/Docker delivery unless explicitly approved.

## Phase 3 Validation

- [ ] OCI fixture registry tests pass.
- [ ] Docker image SBOM and policy evaluation tests pass.
- [ ] Cosign/Sigstore image attestation tests pass.
- [ ] IDE extension malicious fixture tests pass.
- [ ] High-fidelity telemetry tests pass.
- [ ] Enterprise compliance export tests pass.
- [ ] Multi-region or scale test report is reviewed.
- [ ] Disaster recovery test report is reviewed.
