# SBOM Service

Source PRD sections: 3.3, 3.5, Phase 2 expansion.

SBOM Service aggregates package-level evidence into tenant-level software bills of materials and vulnerability suppression outputs.

## Responsibilities

- Consume versioned per-package SBOM fragments produced by [Surgeon](surgeon.md) and keyed by artifact digest plus analysis job.
- Export CycloneDX and SPDX documents.
- Integrate with OpenVEX suppression workflows where policy permits.
- Store exported SBOMs and reports in object storage.
- Serve SBOM data through the public API for dashboards, reports, and CI integrations.

## Boundaries

- Capability timing follows the [Capability By Phase](../README.md#capability-by-phase) matrix.
- MVP stores schema placeholders for SBOM-compatible evidence, but full aggregation is Phase 2.
- VEX import must not silently suppress findings without policy and audit evidence.

## Current Implementation State

The Rust service now exists under `services/sbom-service` and exposes health/readiness plus generate, retrieve, and metadata API endpoints for CycloneDX 1.7, CycloneDX 1.6, and SPDX 2.3 JSON exports. Generated SBOMs are stored in local filesystem-backed object storage and indexed in `sbom_documents`. Tenant-provided OpenVEX document import now lands through control-plane API routes backed by `openvex_documents` and `openvex_statements`; suppression matching remains pending until vulnerability persistence can join advisory matches back to component identities. Aggregation from Surgeon evidence is still blocked until Surgeon persists normalized per-package SBOM fragments or equivalent component/dependency records keyed by `analysis_job_id`.