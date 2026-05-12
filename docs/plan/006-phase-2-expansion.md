# Phase 2 Ecosystem And Compliance Expansion Plan

Source PRD sections: Phase 2 ecosystem integrations, Feature 4.4, Feature 4.5, Feature 6 Phase 2, 4.10, 4.11, deferred gaps in Revision History.

Goal: expand beyond npm/PyPI MVP into SBOM/VEX, Cargo, Maven, richer intelligence feeds, GitHub Actions integrity scanning, and deeper compliance workflows while preserving the MVP control-plane safety model.

## Phase Status

- [x] Phase 2 has an owner: `Aegiscudo Tech Lead`.
- [ ] MVP alpha readiness gates are complete or approved for parallel Phase 2 work.
- [ ] Phase 2 scope is confirmed against the latest PRD.
- [ ] Phase 2 exit review is complete.

## Exit Criteria

- [x] SBOM Service generates current CycloneDX JSON plus CycloneDX 1.6 and SPDX 2.3 compatibility exports.
- [ ] OpenVEX v0.2.0 documents can suppress vulnerability matches with audit evidence and expiry.
- [ ] deps.dev and OpenSSF Scorecard are integrated as policy signals.
- [ ] Cross-ecosystem IOC correlation exists in Feed Harvester.
- [ ] Cargo sparse registry proxy and `cargo-build-profile` are implemented.
- [ ] Maven repository proxy and `jvm-binary-profile` are implemented.
- [ ] `aedo-cli` supports SBOM generation, attestation verification, Cargo/Maven scans, Rush scans, and GitHub Actions workflow scans.
- [ ] Dashboard exposes SBOM/VEX state and Phase 2 ecosystem evidence.

## SBOM Service

- [x] Finalize service language and architecture (Rust, axum, Postgres — `services/sbom-service/`).
- [ ] Aggregate per-package SBOM fragments from Surgeon evidence.
- [x] Generate CycloneDX JSON using CycloneDX 1.7 as the current supported default profile (PRD §4.10; CycloneDX 1.7 is current as of May 2026).
- [x] Generate CycloneDX 1.6 JSON compatibility export.
- [x] Generate SPDX 2.3 JSON compatibility export.
- [ ] Track SPDX 3.0 as compatibility target without blocking Phase 2.
- [x] Include purl, name, version, SHA-256 digest, ecosystem, Aegiscudo decision, and decision timestamp per component.
- [x] Preserve dependency relationship graph (CycloneDX `dependencies` section; SPDX `relationships` section).
- [x] Store SBOMs in object storage with versioned key per tenant and scan (local filesystem, `file://` URI pattern matching Surgeon; remote S3/MinIO is future work).
- [x] Serve SBOM documents through API (`POST /v1/sbom/generate`, `GET /v1/sbom/{id}`, `GET /v1/sbom/{id}/metadata`).
- [ ] Support dashboard export.
- [x] Support CLI export.
- [x] Validate NTIA minimum SBOM elements.
- [x] Add schema tests for CycloneDX and SPDX output.
- Progress 2026-05-12: `services/sbom-service` bootstrapped. Generates CycloneDX 1.7, 1.6 and SPDX 2.3 JSON. Stores documents to local filesystem under a digest-addressed per-tenant path. Persists metadata to `sbom_documents` table (migration 0011). Exposes generate/retrieve/metadata API endpoints.
- Progress 2026-05-12: SBOM service component metadata now matches CLI conventions more closely: each component carries explicit ecosystem metadata, integrity metadata, Aegiscudo decision metadata, SPDX `supplier` / `comment` fields, and CycloneDX root/component properties. Request validation now rejects purl/ecosystem/name/namespace/version mismatches so explicit component fields cannot drift from purl coordinates, and export generation backfills missing version/namespace from the purl when available. `POST /v1/sbom/generate` and `GET /v1/sbom/{id}/metadata` now return `ntia_validation` with per-field issues when required minimum elements are missing. 30 unit tests, all passing.
- Blocker 2026-05-12: aggregation from Surgeon evidence is still blocked because Surgeon currently persists static-analysis reports and artifact manifests, but not normalized per-package SBOM fragments or dependency-edge records that `sbom-service` can consume. Next action: extend Surgeon persistence to emit either stored SBOM fragment payloads or normalized component/dependency tables keyed by `analysis_job_id`.
- Progress 2026-05-11: schema-backed export coverage now exercises npm package-lock, pnpm lockfile, requirements.txt, manifest-assisted single-package Cargo.lock, and default-member virtual-workspace Cargo.lock inputs. Cargo root discovery also covers common globbed-member virtual workspaces, including exclude-filtered members, and Cargo dependency specs without a disambiguating source retain all matching same-name same-version targets. Requirements parsing now also applies nested pip constraint files during scan and SBOM generation while collapsing conflicting duplicate requirement hashes to a single unhashed identity. Standalone Cargo.lock root inference without an adjacent manifest and advanced local editable-path semantics remain follow-up work; Maven graph coverage remains open.
- Blocker 2026-05-11: editable local path requirements without `#egg=` metadata, such as `-e .` or `--editable ./pkg`, still do not resolve to package identities because the current parser has no reliable local project metadata lookup for unnamed editable targets. Next action: derive names from adjacent Python project metadata (`pyproject.toml`, `setup.cfg`, or equivalent) before emitting editable-path findings/components.
- [ ] Add integration tests from resolved npm, PyPI, Cargo, and Maven dependency graphs.

## OpenVEX Support

- [x] Accept tenant-provided OpenVEX v0.2.0 documents through API.
- [x] Accept OpenVEX documents through CLI.
- [x] Store OpenVEX documents with tenant, source, digest, import time, and expiry policy.
- [ ] Match VEX statements against affected components.
- [ ] Suppress vulnerability matches for `fixed` status where applicable.
- [ ] Suppress vulnerability matches for `not_affected` status where applicable.
- [ ] Track `under_investigation` status distinctly from fixed/not affected.
- [ ] Record VEX-suppressed vulnerabilities in audit log with VEX document reference.
- [ ] Display VEX suppression state in dashboard vulnerability views.
- [ ] Include VEX suppression in policy simulator replay.
- [ ] Re-evaluate suppressed vulnerabilities after configurable period.
- [ ] Add tests for expired VEX, malformed VEX, tenant isolation, and conflicting statements.
- Progress 2026-05-12: `aegiscudo-api` now exposes tenant-scoped `openvex-documents` create/list/get routes backed by migration `0013_openvex_documents.sql`. Imported OpenVEX v0.2.0 documents are validated for required top-level identity fields and statement structure, stored with raw JSON plus digest/import metadata, and normalized into `openvex_statements` rows keyed by tenant, vulnerability, and product ID for later suppression lookup. Audit events are emitted on import. Focused `aegiscudo-api` OpenVEX validation passed with 3 unit tests green and 3 migrated-DB route tests compiled as ignored coverage.
- Progress 2026-05-12: `aedo-cli` now supports `aedo vex import --file <openvex.json> --tenant-id <uuid> --actor-id <uuid> [--source <label>] [--expires-at <rfc3339>]`, reusing the saved API config and bearer token while sending the required actor header for the privileged control-plane route. Focused CLI validation passed with 2 OpenVEX import tests green.
- Progress 2026-05-12: Verified the importer against the current upstream OpenVEX release, which is still v0.2.0. Validation now enforces current statement rules (`not_affected` requires `justification` or `impact_statement`; `affected` requires `action_statement`), rejects duplicate `products[].@id` values within a statement before hitting the DB uniqueness constraint, keeps the import audit event in the same transaction as document persistence, and defaults CLI `source` to the file name instead of the full local path.
- Progress 2026-05-12: A request-time suppression prototype in `triage-counter` was reviewed and intentionally not kept. The review confirmed that joining stored OpenVEX `product_id` values to the request coordinate PURL is still unsafe with the current schema because `vulnerability_matches` rows do not identify the affected component that produced each advisory hit.
- Blocker 2026-05-12: statement matching and suppression remain blocked because stored `vulnerability_matches` rows currently carry advisory identity only, not affected component PURLs or another direct join key to OpenVEX `products[].@id` entries. Applying suppression before that join exists can over-suppress artifact findings that share an advisory across multiple components. Next action: extend vulnerability persistence or downstream evidence joins so each vulnerability match can be correlated to component identities before applying `fixed`, `not_affected`, or `under_investigation` status logic, expiry-aware suppression, and suppression audit trails.

## Expanded Feed Intelligence

- [x] Implement deps.dev package metadata ingestion (fixture-based; testdata/feeds/deps-dev.json).
- [ ] Implement deps.dev versioned dependency graph ingestion (live HTTP fetch deferred — see blocker).
- [x] Implement deps.dev license metadata ingestion (fixture carries license field).
- [x] Implement OpenSSF Scorecard ingestion (fixture-based; testdata/feeds/openssf-scorecard.json).
- [x] Persist Scorecard score and individual checks.
- [x] Integrate Scorecard code review, branch protection, CI/CD, maintained, and signed releases signals into policy.
- [x] Implement OpenSSF Package Analysis (GCS public bucket) ingestion for behavioral pre-classification signals (fixture-based; testdata/feeds/openssf-package-analysis.json).
- Progress 2026-05-12: feed-harvester now supports env-configured live HTTP fetch for deps.dev and OpenSSF Scorecard via `FEED_HARVESTER_DEPS_DEV_URL` and `FEED_HARVESTER_OPENSSF_SCORECARD_URL`. When live fetch or payload validation fails, the harvester falls back to a valid local fixture snapshot and records the feed as `degraded`; if neither live nor fixture data is usable, the feed remains `unavailable` instead of aborting the full refresh. 16 feed-harvester tests pass, including invalid-live-payload fallback coverage.
- Progress 2026-05-12: migration `0012_feed_intelligence_records.sql` now persists normalized feed records in `deps_dev_packages`, `deps_dev_dependency_edges`, `openssf_scorecard_results`, and `openssf_scorecard_checks`. deps.dev package metadata is stored durably, dependency edges are captured from package-local dependencies, top-level edge payloads, and deps.dev node-indexed graph payloads (`nodes` with `fromNode` / `toNode`) when present, and Scorecard score plus per-check details are persisted for downstream consumers. 22 feed-harvester tests pass.
- Progress 2026-05-12: triage-counter now maps package coordinates to deps.dev `SOURCE_REPO` links, derives OpenSSF Scorecard code review, branch protection, CI/CD, maintained, and signed releases signals from the latest harvested check set, and applies policy-snapshot-configured thresholds plus allow/warn/block/hitl actions at request time. Decision freshness now includes both `deps.dev` and `openssf-scorecard`, and contract consumers accept `scorecard_thresholds`. Validation passed with `cargo test -p aegiscudo-policy -- --test-threads=1`, `cargo test -p triage-counter -- --test-threads=1`, `cargo test -p aedo-cli validate_policy_file_accepts_scorecard_thresholds -- --test-threads=1`, and `pytest services/python-common/tests/test_contracts.py -q`.
- Blocker 2026-05-12: deps.dev versioned dependency graph ingestion is still incomplete because the current fixture/live URL path is not yet pinned to a canonical deps.dev graph payload that guarantees full edge coverage for every package version, and request-time policy still does not consume `deps_dev_dependency_edges`. Next action: point live refresh at the exact deps.dev versioned dependency graph endpoint, add fixture coverage for its edge schema, then wire policy to `deps_dev_dependency_edges` records.
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

- [x] Implement `aedo scan cargo --lockfile Cargo.lock`.
- [x] Implement `aedo scan maven --pom pom.xml`.
- [x] Implement `aedo scan maven --dependency-tree <path>`.
- [x] Implement `aedo scan rush --config rush.json`.
- [x] Implement `aedo scan github-actions --workflow-dir .github/workflows`.
- [x] Resolve GitHub Actions tags to commit SHAs via `--resolve-tags`.
- [x] Flag mutable action tags.
- [ ] Cross-reference action tag/SHA against Aegiscudo threat feed.
- [ ] Implement `aedo attest verify --lockfile package-lock.json --ecosystem npm`.
- [ ] Implement `aedo attest verify --requirements requirements.txt --ecosystem pypi`.
- [ ] Implement `aedo attest verify --lockfile Cargo.lock --ecosystem cargo`.
- [ ] Implement `aedo attest verify --pom pom.xml --ecosystem maven`.
- [x] Implement `aedo sbom generate --format cyclonedx-json`.
- [x] Implement `aedo sbom generate --format cyclonedx-1.6-json`.
- [x] Implement `aedo sbom generate --format spdx-2.3-json`.
- [ ] Implement `aedo risk <package>@<version> --ecosystem npm`.
- [ ] Implement `aedo risk <crate>@<version> --ecosystem cargo`.
- [ ] Implement `aedo risk <group-id>:<artifact-id>@<version> --ecosystem maven`.
- [ ] Note: `aedo risk` commands are Phase 2 CLI additions; the underlying Triage Counter verdict exists in MVP but the CLI subcommand is intentionally deferred to Phase 2 to keep aedo-cli MVP scope tight.
- [x] Add output and exit-code tests for every Phase 2 command.
- Progress 2026-05-12: `aedo scan cargo --lockfile`, `aedo scan maven --dependency-tree`, `aedo scan rush --config`, and `aedo scan github-actions --workflow-dir` all implemented and validated (128 passed, 0 failed). `GithubActions` added to `PackageEcosystem` in aegiscudo-core. Mutable action tag detection implemented (AllowWithWarning for non-SHA refs, Allow for 40-char hex SHA). `submit_scan_report` now skips API enrichment for non-npm/pypi ecosystems. Rush scan supports npm and pnpm lockfiles via the common/config/rush/ and common/temp/ search paths.
- Progress 2026-05-12: `aedo scan maven --pom pom.xml` implemented with `roxmltree` parser. Extracts direct compile/runtime dependencies, resolves `${property}`, `${project.version}`, and `${project.groupId}` substitutions. Skips `<dependencyManagement>` and test/system scopes. 8 new tests added. Total 140 CLI tests passing.
- Progress 2026-05-12: Tech lead review applied — Maven `first_line` root-skip now only fires when the stripped line parses as a Maven coordinate (prevents mvn preamble lines from consuming the slot); Maven namespace now set via direct `ScanFinding` construction (no more fragile `last_mut()` post-hoc mutation); `any_finding_api_enrichable` documented with single-ecosystem invariant assumption; 4 missing tests added (Maven preamble lines, Rush npm temp fallback, GitHub Actions `.yaml` extension, malformed workflow YAML). 132 tests pass, 0 failed.
- Progress 2026-05-12: `aedo scan github-actions --resolve-tags` now resolves mutable GitHub action refs through the GitHub refs API, follows nested annotated tag objects through `/git/tags/{sha}` until a commit is reached, honors optional `GITHUB_TOKEN`, and degrades back to mutable-tag warnings when resolution fails. Added targeted resolution tests, auth-header coverage, and CLI exit-code coverage. `cargo test -p aedo-cli --lib -- --test-threads=1` passed with 147 passed, 0 failed, 5 ignored; `cargo build --workspace` passed.
- Blocker 2026-05-12: `aedo attest verify` commands require an attestation storage and verification API layer not yet implemented in the control plane. Next action: unblock after attestation service endpoints are defined in the OpenAPI contract.
- Blocker 2026-05-12: GitHub Actions threat-feed correlation is still blocked after tag resolution because `aedo-cli` only submits npm/pypi findings for API enrichment today, and `aegiscudo-api` explicitly rejects `githubactions` as a registry adapter. Next action: add a control-plane enrichment/query path for `githubactions` coordinates keyed by owner/repo/ref so CLI scan findings can merge feed intelligence without going through registry-adapter assumptions.
- Blocker 2026-05-12: `aedo risk` commands require Triage Counter CLI integration; verdict API exists in MVP but CLI subcommand is intentionally deferred to Phase 2 per the plan note. Next action: implement once Phase 2 API route for `/v1/cli/risk` is defined.

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

- [x] SBOM schema validation passes for all export formats.
- [ ] OpenVEX suppression tests pass.
- [ ] Cargo protocol compatibility tests pass against fixture sparse registry.
- [ ] Maven protocol compatibility tests pass against fixture repository.
- [x] GitHub Actions mutable tag detection tests pass.
- [ ] Scorecard/deps.dev feed staleness tests pass.
- [ ] Cross-ecosystem IOC policy tests pass.
- [ ] Phase 2 E2E scenarios pass locally and in CI.
