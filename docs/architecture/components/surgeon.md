# Surgeon

Source PRD sections: Feature 3, 3.3, 3.7.2, 4.1 through 4.4.

Surgeon is the static analysis component for package artifacts. It is asynchronous and never runs on the package-manager request path.

## Responsibilities

- Fetch artifacts only through controlled fetchers.
- Safely unpack npm, PyPI, and Cargo artifacts with archive traversal, size, file-count, symlink, and timeout controls.
- Compute artifact and extracted-file SHA-256 digests.
- Parse manifests and metadata without executing package-provided code.
- Extract suspicious static indicators and targeted redacted code slices.
- Emit schema-valid static evidence linked to analysis jobs and artifact digests.
- Emit per-package SBOM fragments keyed by artifact digest and analysis job for later aggregation by [SBOM Service](sbom-service.md).

## AI Boundary

Surgeon never calls an AI CLI and never sends full package source files to AI Analyst. It emits structured evidence records containing targeted indicators, line spans, summaries, and redaction state.

## Output Contract

Target Phase 2 contract: Surgeon produces durable static evidence and package-level SBOM fragments as versioned analysis outputs. Static-analysis reports, artifact manifests, and a minimal per-package SBOM fragment now persist with artifact identity and analysis-job linkage. The current fragment payload stores the analyzed package root component plus integrity metadata, and `sbom-service` can now generate SBOM documents from those stored fragments via `analysis_job_id`. Richer dependency-edge population remains follow-up work for ecosystem-specific parsers.

## Current Implementation State

The Rust scanner foundation validates unsafe paths, scans directories with file-count and single-file limits, and detects MVP indicator examples such as JavaScript `eval`, Node child processes, Python `exec`, credential paths, AI-agent injection text, sleeper triggers, cross-package write patterns, large base64-like payloads, vendored native source files, and bundled precompiled native artifacts. Archive handling now covers npm/PyPI packages, Cargo `.crate` artifacts, and Maven `.jar` / `.war` / `.ear` artifacts through the packaged-artifact worker path, and structured manifest extraction now includes Cargo `Cargo.toml` / `Cargo.lock` signals for build scripts, procedural macro crates, build-dependencies, dev-dependencies, target-specific dependency sections, optional dependencies, feature graphs, source overrides, and non-crates.io dependency sources, plus Maven `pom.xml` signals for dependency declarations, non-compile scopes, build plugins, custom repositories, parent POMs, dependency classifiers, and relocation metadata. For compiled JVM artifacts, Surgeon no longer relies solely on printable-string extraction: valid `.class` files are parsed in-process with a Rust-native classfile parser, method bytecode is walked to recover invoke/new member references, and that structured bytecode view is fed back into the existing JVM indicator rules before string-extraction fallback for malformed classes. The JAR scanner also surfaces structural archive signals including manifest presence and selected manifest attributes, service-loader registration files, nested archives, shaded or relocated class namespaces, embedded resource files, bundled native libraries, and JAR signing metadata structure when `META-INF/MANIFEST.MF` plus matching `.SF` and signature-block entries are present. JVM runtime attribution remains follow-up work. Static-analysis reports, artifact manifests, embeddings, and minimal package-level SBOM fragment persistence now exist, but richer dependency-edge SBOM data, higher-fidelity Cargo/JVM execution analysis, full indicator coverage, and broader adversarial archive tests remain follow-up work.