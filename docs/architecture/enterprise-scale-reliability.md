# Enterprise Scale And Reliability

This Phase 3 design describes the path from the current single-region alpha stack to enterprise multi-region operation. It does not change request-time enforcement boundaries: Mosquito Net and Triage Counter remain the only request-time enforcement services, while heavy analysis, sandboxing, feed ingestion, and LLM explanation remain asynchronous.

## Multi-Region Mosquito Net

- Deploy one Mosquito Net fleet per tenant-approved region behind regional load balancers.
- Keep registry adapter configuration, policy snapshots, override state, and decision cache metadata region-local with asynchronous control-plane replication.
- Each replicated policy and override snapshot must carry policy version, generated-at time, expiry horizon, source region, and replication watermark. Enforce-mode decisions fail closed or follow an explicit tenant degradation policy when the regional snapshot exceeds the approved replication staleness SLO.
- Route tenants by data-residency policy first, then health, then latency.
- Fail closed for enforce-mode package decisions when the regional Triage Counter is unavailable; use configured fallback behavior only where policy explicitly allows it.
- Pin audit events to the tenant home region and replicate only redacted operational metrics across regions.
- Client package rate limiting behind enterprise load balancers must use a configured trusted client identity source, such as PROXY protocol or forwarded-header parsing from trusted proxy CIDRs only. Raw `X-Forwarded-For` from untrusted peers must be ignored, with TCP peer IP as the fallback.

## Regional Artifact Cache

- Store original package artifacts and SBOM/report payloads in region-local object storage buckets.
- Use content-addressed keys by SHA-256 digest and keep tenant metadata outside the object key where possible.
- Replicate only tenant-approved object classes to secondary regions; package artifacts for restricted tenants remain home-region only.
- Continue stripping sensitive upstream headers before cache writes.
- Treat cache misses during regional failover as normal and rehydrate through protocol-specific adapters rather than cross-region secret sharing.

## Feed Snapshot Replication

- Feed Harvester writes immutable feed snapshots with digest, source, state, and last-success timestamps.
- Request-time services consume the latest usable local snapshot and do not call live feeds.
- Replicate normalized snapshots and digest metadata to read-only regional stores after validation.
- Preserve degraded/stale state per region so failover does not hide feed freshness gaps.

## Tenant Data Residency

- Tenant home region is a control-plane policy property, not a request override.
- Package artifacts, raw evidence, raw attestations, audit events, reports, and generated summaries stay in the tenant home region unless an explicit tenant policy permits replication.
- Aggregated metrics may leave the region only after tenant IDs and package coordinates are removed or tokenized according to the enterprise observability policy.

## 99.99 Percent Uptime Path

The enterprise target requires active-active regional Mosquito Net and Triage Counter capacity, regional dependency health probes, policy snapshot replication SLOs, tested failover, and regional artifact cache rehydration. The alpha deployment is not yet eligible for a 99.99 percent claim.

## Quotas And Metrics

Mosquito Net already enforces tenant API and client package-request sliding-window limits. Phase 3 adds the `aegiscudo_rate_limit_events_total` Prometheus counter labeled by tenant, registry, adapter, limiter, and outcome so dashboards can show tenant and client limiter rejections. Raw tenant-labeled metrics stay regional; global dashboards must consume recording rules or exports that remove or tokenize tenant and registry identifiers.

Additional quota families remain blocked until durable control-plane counters exist:

- sandbox and high-fidelity worker concurrency by tenant, ecosystem, and job class
- LLM spend and request budgets by tenant and package coordinate
- per-region artifact-cache storage budgets

## Customer-Managed Keys

Customer-managed key support requires envelope-encryption metadata, tenant key policy, rotation and revocation behavior, and recovery handling before implementation. Until then, Aegiscudo must not claim CMK support.

## Validation Gates

Enterprise readiness requires backup/restore tests, request-time load tests, and chaos tests for upstream registry outages, stale feed snapshots, sandbox unavailability, and AI provider failures. These tests should be environment-gated because they need live service orchestration and failure injection.