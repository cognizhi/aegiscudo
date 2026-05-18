# aedo-cli

Source PRD sections: Feature 6, 3.3, 3.7.3, 4.12.5.

`aedo-cli` is the developer and CI interface for preflight dependency checks, explanations, policy tests, and exception workflows.

## Responsibilities

- Authenticate against Aegiscudo API.
- Parse npm and PyPI manifests or lockfiles without uploading full source by default.
- Submit package coordinates and artifact digests for scan and preflight workflows.
- Explain package decisions and policy outcomes.
- Emit text, JSON, and SARIF output with deterministic exit codes for CI.
- Scan Docker/OCI images through the Phase 3 scanner-only Syft integration and generate image SBOMs.
- Scan local VS Code/OpenVSX extension artifacts with bounded static payload checks.
- Return explicit not-yet-supported errors for unopened phase-gated ecosystems.

## Boundaries

- Does not upload package source by default.
- Does not substitute package-manager behavior or bypass Mosquito Net in enforcement flows.
- Phase-gated ecosystem support follows the [Capability By Phase](../README.md#capability-by-phase) matrix. Docker/OCI is currently a scanner-only CLI path, not a request-time registry proxy.

## Current Implementation State

The Rust CLI now supports persisted auth commands with API health probing, npm `package-lock.json` scans, pnpm `pnpm-lock.yaml` scans, PyPI `requirements.txt` scans, Cargo and Maven scans, GitHub Actions workflow scans, Docker/OCI image scans through Syft, local VS Code/OpenVSX extension artifact scans, real control-plane scan submission and explain lookups, local policy-file schema validation for `aedo policy test`, cwd-only CI preflight discovery across supported top-level dependency files, deterministic JSON or text or SARIF output, fail thresholds, image SBOM generation for supported embedded application ecosystems, and Cosign-backed Docker attestation verification with explicit trust selectors. Remaining CLI work is optional manifest upload behavior, the MVP yarn support decision, broader non-ignored/live integration coverage, OS package policy contracts, marketplace extension metadata enrichment, extension SBOM fragments, and request-time support for Phase 3 ecosystems beyond scanner-only Docker image analysis.