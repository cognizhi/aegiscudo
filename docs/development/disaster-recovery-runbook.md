# Disaster Recovery Runbook

This runbook defines the Phase 3 disaster-recovery path for enterprise readiness. It is a design gate until backup/restore automation and failover tests exist.

## Recovery Objectives

- Mosquito Net request-time recovery target: regional failover path designed for the 99.99 percent enterprise target, not claimed until tested.
- Control-plane PostgreSQL recovery target: restore the latest validated backup and replay migrations before accepting writes.
- Object storage recovery target: verify digest-addressed artifacts, reports, SBOMs, and raw attestation snapshots before serving recovered evidence.

## Trigger Conditions

- Regional Mosquito Net or Triage Counter outage.
- PostgreSQL primary corruption or loss.
- Object storage bucket loss or integrity mismatch.
- Feed snapshot corruption or stale snapshot beyond tenant policy.
- Sandbox, high-fidelity worker, or AI provider outage affecting asynchronous analysis.

## Response Procedure

1. Freeze non-critical admin mutations for affected tenants.
2. Fence the old PostgreSQL writer or failed primary before promoting a replica or restoring from backup to prevent split-brain writes.
3. Confirm tenant home-region and data-residency policy before routing traffic.
4. Shift request-time traffic to a healthy approved region only when tenant policy permits it.
5. Restore PostgreSQL from the latest validated backup, then apply migrations in order.
6. Verify object storage by digest before exposing artifacts, reports, SBOMs, or raw attestations.
7. Mark feed snapshots degraded when local freshness cannot be proven; request-time enforcement must continue from the latest usable validated snapshot.
8. Resume asynchronous analysis queues only after worker identity, quotas, and evidence stores are healthy.
9. Emit audit events for failover start, recovery steps, validation results, and service restoration.

## Validation Checklist

- Restore database backup into an empty environment and run schema validation.
- Verify at least one artifact, SBOM, report, raw attestation digest, and audit query after restore.
- Run a request-time proxy smoke test against the restored Triage Counter and Mosquito Net path.
- Confirm stale feed behavior and policy-decision behavior during feed outage simulation.
- Confirm sandbox and AI outages degrade asynchronous evidence only and do not become request-time enforcement dependencies.

## Current Blockers

Backup/restore tests, failover automation, report retention/deletion workflows, tenant data-residency policy fields, and chaos/load test harnesses are not implemented yet. Do not claim DR readiness until those validations pass in CI or an approved staging environment.