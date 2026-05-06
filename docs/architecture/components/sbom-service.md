# SBOM Service

Source PRD sections: 3.3, 3.5, Phase 2 expansion.

SBOM Service aggregates package-level evidence into tenant-level software bills of materials and vulnerability suppression outputs.

## Responsibilities

- Consume versioned per-package SBOM fragments produced by [Surgeon](surgeon.md) and keyed by artifact digest plus analysis job.
- Export CycloneDX and SPDX documents.
- Import OpenVEX records for false-positive suppression where policy permits.
- Store exported SBOMs and reports in object storage.
- Serve SBOM and VEX data through the public API for dashboards, reports, and CI integrations.

## Boundaries

- Capability timing follows the [Capability By Phase](../README.md#capability-by-phase) matrix.
- MVP stores schema placeholders for SBOM-compatible evidence, but full aggregation is Phase 2.
- VEX import must not silently suppress findings without policy and audit evidence.

## Current Implementation State

A placeholder service directory exists. Language choice is finalized in favor of Rust so aggregation can stay aligned with the typed evidence pipeline and backend contracts. Aggregation model, exports, VEX import, and API endpoints remain Phase 2 work.