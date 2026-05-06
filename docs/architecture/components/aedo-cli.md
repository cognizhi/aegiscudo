# aedo-cli

Source PRD sections: Feature 6, 3.3, 3.7.3, 4.12.5.

`aedo-cli` is the developer and CI interface for preflight dependency checks, explanations, policy tests, and exception workflows.

## Responsibilities

- Authenticate against Aegiscudo API.
- Parse npm and PyPI manifests or lockfiles without uploading full source by default.
- Submit package coordinates and artifact digests for scan and preflight workflows.
- Explain package decisions and policy outcomes.
- Emit text, JSON, and SARIF output with deterministic exit codes for CI.
- Return explicit not-yet-supported errors for phase-gated ecosystems.

## Boundaries

- Does not upload package source by default.
- Does not substitute package-manager behavior or bypass Mosquito Net in enforcement flows.
- Phase-gated ecosystem support follows the [Capability By Phase](../README.md#capability-by-phase) matrix. Phase 2 and Phase 3 ecosystems remain disabled unless their plan gates open.

## Current Implementation State

The Rust CLI scaffold supports auth commands, npm `package-lock.json` scans, PyPI `requirements.txt` scans, explanation command preparation, policy test preparation, CI preflight output formats, fail thresholds, SARIF, and phase-gated unsupported targets. Persistent auth config, API client wiring, yarn/pnpm lock parsers, broader output tests, and API integration tests remain Phase 1C work.