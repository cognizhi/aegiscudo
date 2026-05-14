# SBOM Service

Phase 2 implementation language decision: Rust. This keeps SBOM aggregation aligned with the existing Rust DTOs, artifact evidence pipeline, and future API plus CLI export paths.

Phase 2 service placeholder. Surgeon emits package-level SBOM fragments in MVP evidence; full CycloneDX/SPDX aggregation is intentionally phase-gated to Phase 2 per the PRD.

Current compatibility targets:

- CycloneDX 1.7 is the primary export profile.
- CycloneDX 1.6 and SPDX 2.3 are the current compatibility exports.
- SPDX 3.0 is tracked as the next non-blocking compatibility target and stays outside the supported export set until a validated 3.0 export path and vendored validation assets are in place.