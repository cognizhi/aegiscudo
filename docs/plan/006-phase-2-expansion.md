# Phase 2 Ecosystem And Compliance Expansion Plan

Source PRD sections: Phase 2 ecosystem integrations, Feature 4.4, Feature 4.5, Feature 6 Phase 2, 4.10, 4.11, deferred gaps in Revision History.

Goal: expand beyond npm/PyPI MVP into SBOM/VEX, Cargo, Maven, richer intelligence feeds, GitHub Actions integrity scanning, and deeper compliance workflows while preserving the MVP control-plane safety model.

## Phase Status

- [x] Phase 2 has an owner: `Aegiscudo Tech Lead`.
- [ ] MVP alpha readiness gates are complete or approved for parallel Phase 2 work.
- [ ] Phase 2 scope is confirmed against the latest PRD.
- [ ] Phase 2 exit review is complete.

## Exit Criteria

- [ ] SBOM Service generates current CycloneDX JSON plus CycloneDX 1.6 and SPDX 2.3 compatibility exports.
- [ ] OpenVEX v0.2.0 documents can suppress vulnerability matches with audit evidence and expiry.
- [ ] deps.dev and OpenSSF Scorecard are integrated as policy signals.
- [ ] Cross-ecosystem IOC correlation exists in Feed Harvester.
- [ ] Cargo sparse registry proxy and `cargo-build-profile` are implemented.
- [ ] Maven repository proxy and `jvm-binary-profile` are implemented.
- [ ] `aedo-cli` supports SBOM generation, attestation verification, Cargo/Maven scans, Rush scans, and GitHub Actions workflow scans.
- [ ] Dashboard exposes SBOM/VEX state and Phase 2 ecosystem evidence.

## SBOM Service

- [ ] Finalize service language and architecture.
- [ ] Aggregate per-package SBOM fragments from Surgeon evidence.
- [ ] Generate CycloneDX JSON using CycloneDX 1.7 as the current supported default profile (PRD §4.10; CycloneDX 1.7 is current as of May 2026).
- [ ] Generate CycloneDX 1.6 JSON compatibility export.
- [ ] Generate SPDX 2.3 JSON compatibility export.
- [ ] Track SPDX 3.0 as compatibility target without blocking Phase 2.
- [ ] Include purl, name, version, SHA-256 digest, ecosystem, Aegiscudo decision, and decision timestamp per component.
- [ ] Preserve dependency relationship graph.
- [ ] Store SBOMs in object storage with versioned key per tenant and scan.
- [ ] Serve SBOM documents through API.
- [ ] Support dashboard export.
- [ ] Support CLI export.
- [ ] Validate NTIA minimum SBOM elements.
- [ ] Add schema tests for CycloneDX and SPDX output.
- [ ] Add integration tests from resolved npm, PyPI, Cargo, and Maven dependency graphs.

## OpenVEX Support

- [ ] Accept tenant-provided OpenVEX v0.2.0 documents through API.
- [ ] Accept OpenVEX documents through CLI.
- [ ] Store OpenVEX documents with tenant, source, digest, import time, and expiry policy.
- [ ] Match VEX statements against affected components.
- [ ] Suppress vulnerability matches for `fixed` status where applicable.
- [ ] Suppress vulnerability matches for `not_affected` status where applicable.
- [ ] Track `under_investigation` status distinctly from fixed/not affected.
- [ ] Record VEX-suppressed vulnerabilities in audit log with VEX document reference.
- [ ] Display VEX suppression state in dashboard vulnerability views.
- [ ] Include VEX suppression in policy simulator replay.
- [ ] Re-evaluate suppressed vulnerabilities after configurable period.
- [ ] Add tests for expired VEX, malformed VEX, tenant isolation, and conflicting statements.

## Expanded Feed Intelligence

- [ ] Implement deps.dev package metadata ingestion.
- [ ] Implement deps.dev versioned dependency graph ingestion.
- [ ] Implement deps.dev license metadata ingestion.
- [ ] Implement OpenSSF Scorecard ingestion.
- [ ] Persist Scorecard score and individual checks.
- [ ] Integrate Scorecard code review, branch protection, CI/CD, maintained, and signed releases signals into policy.
- [ ] Implement OpenSSF Package Analysis (GCS public bucket) ingestion for behavioral pre-classification signals.
- [ ] Implement cross-ecosystem IOC schema for identities, domains, IPs, URLs, package names, and behavioral fingerprints.
- [ ] Correlate malicious maintainer identity across ecosystems.
- [ ] Correlate destination domain/IP across sandbox reports.
- [ ] Correlate behavioral fingerprint across static and dynamic evidence.
- [ ] Add Feed Harvester freshness alerts for every Phase 2 feed.
- [ ] Add policy tests for cross-ecosystem IOC elevation.

## Cargo Support

- [ ] Implement Cargo sparse registry adapter in Mosquito Net.
- [ ] Support Cargo source replacement configuration docs.
- [ ] Proxy sparse index files.
- [ ] Filter sparse index candidates according to policy.
- [ ] Proxy crate downloads.
- [ ] Preserve Cargo.lock digest semantics.
- [ ] Parse `.crate` archives in Surgeon.
- [ ] Parse `Cargo.toml`.
- [ ] Parse `Cargo.lock`.
- [ ] Analyze feature graph.
- [ ] Analyze target-specific dependencies.
- [ ] Analyze build dependencies.
- [ ] Analyze dev dependencies.
- [ ] Analyze optional dependencies.
- [ ] Analyze patch and replacement configuration.
- [ ] Detect `build.rs`.
- [ ] Detect procedural macro crates.
- [ ] Detect vendored native code.
- [ ] Detect bundled object files and precompiled libraries.
- [ ] Run controlled `cargo fetch`.
- [ ] Run controlled `cargo metadata`.
- [ ] Run controlled `cargo tree`.
- [ ] Run isolated `cargo build`.
- [ ] Deny network after dependency fetch.
- [ ] Diff `OUT_DIR`, project directory, cargo home, target directory, and user-home canary paths.
- [ ] Inspect generated native artifacts using `strings`, `readelf`, `nm`, `ldd`, and `llvm-objdump` where available.
- [ ] Demangle symbols where possible.
- [ ] Escalate suspicious native artifacts to high-fidelity detonation backlog when needed.
- [ ] Add Cargo fixture registry and malicious `build.rs` tests.

## Maven And JVM Support

- [ ] Implement Maven repository layout adapter in Mosquito Net.
- [ ] Proxy POM and JAR metadata.
- [ ] Preserve Maven checksums and signatures.
- [ ] Parse POM dependencies, scopes, plugins, repositories, parent POMs, classifiers, and relocation.
- [ ] Inspect JAR structure including manifest, signatures, service loader files, nested JARs, shaded classes, resources, and native libraries.
- [ ] Verify Maven repository checksums.
- [ ] Verify JAR signature metadata where available.
- [ ] Disassemble bytecode using `javap -c -v` or ASM visitors.
- [ ] Evaluate licensing and operational fit for CFR, FernFlower, or Ghidra optional decompilation.
- [ ] Detect `Runtime.exec`.
- [ ] Detect `ProcessBuilder`.
- [ ] Detect socket and HTTP clients.
- [ ] Detect reflection and dynamic class loading.
- [ ] Detect `ClassLoader#defineClass`.
- [ ] Detect deserialization APIs.
- [ ] Detect filesystem and credential-path access.
- [ ] Detect JNI loading.
- [ ] Detect hardcoded domains, IPs, webhook URLs, and token names.
- [ ] Load selected classes in isolated JVM profile.
- [ ] Capture class loading, process execution, filesystem writes, and network attempts.
- [ ] Distinguish dangerous operations from merely exposed APIs.
- [ ] Attribute behavior to bytecode, class loading, Maven plugins, or transitive dependencies.
- [ ] Add Maven fixture repository and malicious plugin/JAR tests.

## Generic HTTP Adapter

- [ ] Define generic artifact capture semantics.
- [ ] Implement passthrough HTTP proxy with artifact digest capture.
- [ ] Apply Triage Counter hold pattern before serving captured artifact where practical.
- [ ] Record limited protocol metadata and upstream headers with redaction.
- [ ] Document limitations compared with ecosystem-specific adapters.
- [ ] Add tests for private/non-standard registry passthrough.

## CLI Phase 2

- [ ] Implement `aedo scan cargo --lockfile Cargo.lock`.
- [ ] Implement `aedo scan maven --pom pom.xml`.
- [ ] Implement `aedo scan maven --dependency-tree <path>`.
- [ ] Implement `aedo scan rush --config rush.json`.
- [ ] Implement `aedo scan github-actions --workflow-dir .github/workflows`.
- [ ] Resolve GitHub Actions tags to commit SHAs.
- [ ] Flag mutable action tags.
- [ ] Cross-reference action tag/SHA against Aegiscudo threat feed.
- [ ] Implement `aedo attest verify --lockfile package-lock.json --ecosystem npm`.
- [ ] Implement `aedo attest verify --requirements requirements.txt --ecosystem pypi`.
- [ ] Implement `aedo attest verify --lockfile Cargo.lock --ecosystem cargo`.
- [ ] Implement `aedo attest verify --pom pom.xml --ecosystem maven`.
- [ ] Implement `aedo sbom generate --format cyclonedx-json`.
- [ ] Implement `aedo sbom generate --format cyclonedx-1.6-json`.
- [ ] Implement `aedo sbom generate --format spdx-2.3-json`.
- [ ] Implement `aedo risk <package>@<version> --ecosystem npm`.
- [ ] Implement `aedo risk <crate>@<version> --ecosystem cargo`.
- [ ] Implement `aedo risk <group-id>:<artifact-id>@<version> --ecosystem maven`.
- [ ] Note: `aedo risk` commands are Phase 2 CLI additions; the underlying Triage Counter verdict exists in MVP but the CLI subcommand is intentionally deferred to Phase 2 to keep aedo-cli MVP scope tight.
- [ ] Add output and exit-code tests for every Phase 2 command.

## Dashboard Phase 2

- [ ] Add SBOM export view.
- [ ] Add VEX import and suppression state view.
- [ ] Add Cargo evidence viewer panels.
- [ ] Add Maven/JVM evidence viewer panels.
- [ ] Add GitHub Actions workflow integrity scan results.
- [ ] Add Scorecard signal tooltips and policy thresholds.
- [ ] Add deps.dev dependency graph visualization or table.
- [ ] Add cross-ecosystem IOC correlation view.
- [ ] Add Phase 2 policy simulator support for VEX and Scorecard.
- [ ] Add Playwright coverage for SBOM, VEX, Cargo/Maven evidence, and GitHub Actions scan results.

## AI And Embedding Evolution

- [ ] Introduce pgvector-backed embedding store for clustering similar malicious code slices and historical case retrieval; populate embeddings for static evidence records (PRD §3.6 — optional in MVP, activated in Phase 2).
- [ ] Evaluate migration path to Qdrant or Vertex AI Vector Search for higher-volume embedding needs (PRD §3.6: pgvector for MVP; scale-out in later phases).
- [ ] Evaluate LLM-as-judge evaluation pipeline in Langfuse against a golden dataset of manually reviewed package analyses (PRD §4.9: may be introduced in Phase 2).
- [ ] Define acceptance criteria for LLM-as-judge pass rate before enabling it as a blocking quality gate.

## Policy Evolution

- [ ] Evaluate OPA/Rego or Cedar against MVP policy DSL lessons.
- [ ] Decide whether to keep YAML DSL, add policy-as-code, or support both.
- [ ] Add migration notes for any policy format change.
- [ ] Add backward compatibility tests for existing policy profiles.
- [ ] Add reachability analysis design for JavaScript/TypeScript.
- [ ] Add reachability analysis design for Python.
- [ ] Implement reachability only after ecosystem-specific call graph assumptions are validated.

## Phase 2 Validation

- [ ] SBOM schema validation passes for all export formats.
- [ ] OpenVEX suppression tests pass.
- [ ] Cargo protocol compatibility tests pass against fixture sparse registry.
- [ ] Maven protocol compatibility tests pass against fixture repository.
- [ ] GitHub Actions mutable tag detection tests pass.
- [ ] Scorecard/deps.dev feed staleness tests pass.
- [ ] Cross-ecosystem IOC policy tests pass.
- [ ] Phase 2 E2E scenarios pass locally and in CI.
