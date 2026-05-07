# Mosquito Net

Source PRD sections: Feature 1, 3.3, 3.7.1, 4.5 through 4.8.

Mosquito Net is the request-time registry proxy. It is the only component that package managers should talk to directly during npm and PyPI installs.

## Responsibilities

- Dispatch configured registry mount paths to protocol-specific adapters.
- Normalize package-manager metadata and artifact requests into package coordinates.
- Call Triage Counter before serving metadata candidates or artifacts.
- Inject upstream credentials without logging credential values.
- Reload registry mounts, upstream credentials, and active proxy settings without restart when control-plane configuration changes.
- Rewrite upstream metadata and redirects so clients remain under the Mosquito Net base URL.
- Cache metadata and artifacts by content digest.
- Emit audit events and request metrics for every inbound request and final decision.

## Configuration Reload

Mosquito Net consumes registry configuration and credential changes through no-restart reload behavior coordinated by Aegiscudo API. Database-stored runtime overrides take precedence over bootstrap environment values. See [External Integrations And Feeds](../external-integrations.md) for the shared control-plane contract.

## Related ADRs

- [ADR 0001: Control-Plane Routing Scope and Mount-Path Uniqueness](../../adr/0001-control-plane-routing-scope-and-mount-path-uniqueness.md)
- [ADR 0002: Degraded Operation and Fail-Mode Precedence](../../adr/0002-degraded-operation-and-fail-mode-precedence.md)
- [ADR 0007: Request-Time Triage Client and Outage Binding](../../adr/0007-request-time-triage-client-and-outage-binding.md)

## Boundaries

- Does not perform heavy static analysis, sandbox execution, feed ingestion, or LLM explanation.
- Does not silently substitute explicit pinned versions, tarball URLs, or integrity-locked artifacts.
- Does not act as a transparent packet-level proxy.
- Must fail closed for unknown artifacts in enforcement mode when Triage Counter is unavailable.

## Current Implementation State

The Rust Axum service shell exists with `/healthz`, `/readyz`, `/metrics`, and a decision-gated proxy scaffold. Mosquito Net loads enabled registry configurations from PostgreSQL at startup, rejects upstream URLs with embedded credentials, rejects authenticated cleartext upstreams, enforces auth-type versus `credential_ref` consistency, and resolves configured `/proxy/...` mount paths, including nested mount prefixes, before adapter-aware handling. Loaded enabled mounts are de-duplicated at startup, and Phase 1A routing scope is fixed by [ADR 0001](../../adr/0001-control-plane-routing-scope-and-mount-path-uniqueness.md): non-deleted mount paths are globally unique at the database layer while tenant context comes from the resolved registry configuration, and Mosquito Net only loads enabled configs at startup. Mosquito Net now calls Triage Counter through a bounded client, emits advisory headers, persists shared-DTO audit events to PostgreSQL for resolved tenant-bound proxy requests while emitting matching structured service logs for request receipt and final proxy outcomes, emits Prometheus metrics for request count and latency, decision state count and latency, and Triage latency on the current request-time path, and enforces proxy-entry sliding-window rate limits for tenant API traffic and client package requests. Those limiters use the resolved tenant ID and socket peer IP address, emit `429 Too Many Requests` with `Retry-After`, and are configured through `MOSQUITO_NET_TENANT_RATE_LIMIT_WINDOW_SECS`, `MOSQUITO_NET_TENANT_RATE_LIMIT_BURST`, `MOSQUITO_NET_CLIENT_RATE_LIMIT_WINDOW_SECS`, and `MOSQUITO_NET_CLIENT_RATE_LIMIT_BURST`. It also fails closed for the current scaffolded enforce-mode request path when Triage is unavailable, and fails open with visible advisory scaffolding for true warn/shadow outages as recorded in [ADR 0007](../../adr/0007-request-time-triage-client-and-outage-binding.md). Unresolved proxy paths still lack durable audit persistence because the current audit store is tenant-scoped and registry resolution can fail before a tenant is known. Cached known-good serving, cache-hit metrics, upstream-latency metrics, and broader mode refinement are still incomplete, so that outage and observability behavior remain partial Phase 1A implementations. No-restart adapter reload, upstream proxying, credential injection, caches, persisted decisions, circuit breakers, response rewriting, and adapter integration tests remain Phase 1A work.