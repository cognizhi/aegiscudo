# Compliance Report Exports

The first Phase 3 compliance slice is an offline CLI export path. It turns a bounded JSON evidence bundle into deterministic JSON or text reports for EU Cyber Resilience Act supply-chain evidence and NIST SSDF control mapping.

```bash
aedo compliance cra --evidence-file compliance-evidence.json --output-format json
aedo compliance ssdf --evidence-file compliance-evidence.json --output-format text
```

## Evidence Bundle

The evidence bundle is intentionally explicit and capped by the CLI at 1 MiB. It must not contain secrets, auth headers, raw package contents, raw audit metadata dumps, or unredacted sandbox payloads. Timestamp fields must be RFC3339 strings, report periods must be ordered, SBOM digests use `sha256:<lowercase-hex>`, and report URIs must not contain URL userinfo.

```json
{
  "tenant_id": "018f4a6f-55d0-7000-8000-000000000001",
  "generated_at": "2026-05-18T00:00:00Z",
  "period": {
    "start": "2026-05-01T00:00:00Z",
    "end": "2026-05-18T00:00:00Z"
  },
  "risk_management_evidence": [
    {
      "control": "tenant-policy-default",
      "evidence_ref": "policy:default@2026-05-18",
      "status": "implemented"
    }
  ],
  "sbom_references": [
    {
      "uri": "s3://reports/sbom.cdx.json",
      "format": "cyclonedx-1.7",
      "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  ],
  "audit_log_summary": [
    {
      "action": "policy.decision.block",
      "count": 3,
      "first_seen_at": "2026-05-01T00:00:00Z",
      "last_seen_at": "2026-05-18T00:00:00Z"
    }
  ],
  "slsa_consumer_requirements": [
    {
      "requirement": "SLSA Build Level 2 or higher for release artifacts",
      "minimum_build_level": 2,
      "observed_build_level": 3,
      "status": "met",
      "evidence_ref": "attestation:slsa-vsa:widget"
    }
  ],
  "policy_decision_counts": {
    "allow": 42,
    "block": 3
  }
}
```

## Current Scope

The CRA export includes supply-chain risk management evidence, SBOM references, audit-log summaries, SLSA consumer requirement mappings, policy decision counts, and open items for missing evidence categories. Text output includes tenant scope, report period, policy-decision count coverage, and each open item.

The SSDF export maps available evidence to a first control set: PO.1, PS.3, RV.1, and PW.4. The mapping is evidence-oriented and does not certify compliance by itself.

CSV/PDF export, scheduled report retention/deletion, Command Center report filters, API-backed report generation, and OpenSSF Best Practices Badge policy signals remain Phase 3 follow-up work.