# Surgeon

Source PRD sections: Feature 3, 3.3, 3.7.2, 4.1 through 4.4.

Surgeon is the static analysis component for package artifacts. It is asynchronous and never runs on the package-manager request path.

## Responsibilities

- Fetch artifacts only through controlled fetchers.
- Safely unpack npm and PyPI artifacts with archive traversal, size, file-count, symlink, and timeout controls.
- Compute artifact and extracted-file SHA-256 digests.
- Parse manifests and metadata without executing package-provided code.
- Extract suspicious static indicators and targeted redacted code slices.
- Emit schema-valid static evidence linked to analysis jobs and artifact digests.
- Emit per-package SBOM fragments keyed by artifact digest and analysis job for later aggregation by [SBOM Service](sbom-service.md).

## AI Boundary

Surgeon never calls an AI CLI and never sends full package source files to AI Analyst. It emits structured evidence records containing targeted indicators, line spans, summaries, and redaction state.

## Output Contract

Target Phase 2 contract: Surgeon produces durable static evidence and package-level SBOM fragments as versioned analysis outputs. Today, static-analysis reports and artifact manifests persist with artifact identity and analysis-job linkage, but normalized package-level SBOM fragments are not yet stored, so downstream aggregation must not assume they exist.

## Current Implementation State

The Rust scanner foundation validates unsafe paths, scans directories with file-count and single-file limits, and detects MVP indicator examples such as JavaScript `eval`, Node child processes, Python `exec`, credential paths, AI-agent injection text, sleeper triggers, cross-package write patterns, and large base64-like payloads. Static-analysis report and artifact-manifest persistence now exist, but package-level SBOM fragment persistence, full archive unpacking, broader manifest extraction, full indicator coverage, and adversarial archive tests remain follow-up work.