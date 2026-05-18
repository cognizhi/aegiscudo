# Supply Chain Graph Integration

Phase 3 keeps Aegiscudo's internal supply-chain graph centered on SBOM Service, stored SBOM fragments, and deps.dev package-or-edge snapshots. OpenSSF GUAC remains an optional integration target rather than a required runtime dependency.

## GUAC Re-Evaluation

GUAC is an OpenSSF Incubating project for ingesting software metadata such as SBOMs and mapping relationships across artifacts, packages, vulnerabilities, attestations, and related evidence. It is a strong fit for organizations that already operate a dedicated supply-chain graph and want broad cross-tool correlation.

For Aegiscudo Phase 3, adopting GUAC directly would add a new graph datastore, collectors, ingestion operations, tenant-isolation model, backup/restore surface, and query authorization layer. That cost is not justified until customers need graph queries beyond what SBOM Service and deps.dev snapshots provide.

## Decision

SBOM Service remains the internal graph of record for Phase 3. It already owns generated SBOM documents, component metadata, stored package-level fragments, dependency relationships, and tenant-scoped export APIs. Triage Counter separately consumes deps.dev graph snapshots for request-time transitive signal propagation.

GUAC adoption is deferred until at least one of these conditions is true:

- enterprise customers require cross-tenant isolated graph analytics over SBOMs, attestations, vulnerabilities, VEX, and provenance beyond existing report APIs
- auditor/security analyst workflows need graph traversal that cannot be served from SBOM documents plus deps.dev package snapshots
- operations accepts the cost of running and backing up a dedicated graph service under Aegiscudo tenant isolation and data-residency rules

## Bridge Design If Adopted

If GUAC is adopted later, Aegiscudo should integrate through asynchronous export/import jobs only.

- Export only normalized SBOM documents, OpenVEX documents, attestation metadata, package coordinates, artifact digests, and vulnerability references that a tenant has approved for graph export.
- SBOM, OpenVEX, and attestation exports must redact or omit free-text notes, internal repository URLs, emails, customer names, and tenant-specific metadata unless the tenant approval explicitly allows that field class.
- Never export raw package contents, raw sandbox payloads, customer secrets, auth headers, or unredacted audit metadata.
- Use an opaque graph namespace or tokenized tenant label; the canonical tenant ID remains only in Aegiscudo's internal mapping.
- Preserve source document digests so GUAC graph nodes can be traced back to immutable Aegiscudo evidence.
- Tenant approval must record approver, scope and object classes, destination graph instance, residency/region, expiry, reason, and revocation/deletion behavior.
- Import graph-derived summaries as advisory evidence only; request-time enforcement must continue to use Mosquito Net and Triage Counter policy inputs.
- Imported summaries must be bound to tenant, export job, source document digests, graph instance/query version, import time, and freshness or expiry. They must never mutate policy decisions, VEX suppression state, attestation verification state, or request-time caches.
- Analyst access must go through an Aegiscudo tenant/RBAC query facade rather than direct shared graph backend access.
- Run bridge jobs asynchronously with per-tenant quotas and audit events for export start, export completion, import completion, failure, and deletion.

## Auditor And Security Analyst Use Cases

- Find all artifacts that include a vulnerable component and list the SBOM document, decision, and VEX status that support the answer.
- Show which packages share a maintainer, repository, provenance verifier, or suspicious infrastructure indicator.
- Compare current SBOM components against prior release SBOMs to explain newly introduced transitive dependencies.
- Trace a blocked package decision to static evidence, sandbox evidence, attestation status, vulnerability intelligence, and policy version.
- Identify packages whose SLSA/VSA evidence is missing, stale, or below a tenant requirement.

The suspicious infrastructure and blocked-decision tracing use cases are internal-only until Aegiscudo defines a normalized signal/evidence-reference export contract. A GUAC bridge must not improvise by exporting raw static reports, sandbox payloads, audit metadata, or LLM text.

## Current Blockers

Runtime graph consistency tests and tenant-isolation tests cannot start until Aegiscudo has a graph query API or a GUAC bridge contract. Schema and fixture tests for tenant-scoped export redaction must be added as soon as a bridge contract is drafted. The next implementation step, if this integration is reactivated, is to define tenant-scoped graph export schemas and fixtures before standing up any external graph runtime.