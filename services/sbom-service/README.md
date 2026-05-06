# SBOM Service

Phase 2 implementation language decision: Rust. This keeps SBOM aggregation aligned with the existing Rust DTOs, artifact evidence pipeline, and future API plus CLI export paths.

Phase 2 service placeholder. Surgeon emits package-level SBOM fragments in MVP evidence; full CycloneDX/SPDX aggregation is intentionally phase-gated to Phase 2 per the PRD.