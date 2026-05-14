# Mosquito Net

Source PRD sections: Feature 1, 3.3, 3.7.1, 4.5 through 4.8.

Mosquito Net is the request-time registry proxy. It is the only component that package managers should talk to directly during npm, PyPI, and the current Phase 2 Cargo sparse-registry path.

## Responsibilities

- Dispatch configured registry mount paths to protocol-specific adapters.
- Normalize package-manager metadata and artifact requests into package coordinates.
- Call Triage Counter before serving metadata candidates or artifacts.
- Inject upstream credentials without logging credential values.
- Reload registry mounts, upstream credentials, and active proxy settings without restart when control-plane configuration changes.
- Rewrite upstream metadata and redirects so clients remain under the Mosquito Net base URL.
- Cache most metadata by request path and artifacts by content digest; the current Cargo `config.json` fast path is handled separately.
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

The Rust Axum service shell exists with `/healthz`, `/readyz`, `/metrics`, and a decision-gated proxy scaffold. Mosquito Net loads enabled registry configurations from PostgreSQL at startup, rejects upstream URLs with embedded credentials, rejects authenticated cleartext upstreams, enforces auth-type versus `credential_ref` consistency, and resolves configured `/proxy/...` mount paths, including nested mount prefixes, before adapter-aware handling. Loaded enabled mounts are de-duplicated at startup, and Phase 1A routing scope is fixed by [ADR 0001](../../adr/0001-control-plane-routing-scope-and-mount-path-uniqueness.md): non-deleted mount paths are globally unique at the database layer while tenant context comes from the resolved registry configuration, and Mosquito Net only loads enabled configs at startup. Mosquito Net now calls Triage Counter through a bounded client, emits advisory headers, persists shared-DTO audit events to PostgreSQL for resolved tenant-bound proxy requests while emitting matching structured service logs for request receipt and final proxy outcomes, emits Prometheus metrics for request count and latency, decision state count and latency, and Triage latency on the current request-time path, and enforces proxy-entry sliding-window rate limits for tenant API traffic and client package requests. Those limiters use the resolved tenant ID and socket peer IP address, emit `429 Too Many Requests` with `Retry-After`, and are configured through `MOSQUITO_NET_TENANT_RATE_LIMIT_WINDOW_SECS`, `MOSQUITO_NET_TENANT_RATE_LIMIT_BURST`, `MOSQUITO_NET_CLIENT_RATE_LIMIT_WINDOW_SECS`, and `MOSQUITO_NET_CLIENT_RATE_LIMIT_BURST`. It also fails closed for the current scaffolded enforce-mode request path when Triage is unavailable, and fails open with visible advisory scaffolding for true warn/shadow outages as recorded in [ADR 0007](../../adr/0007-request-time-triage-client-and-outage-binding.md). Unresolved proxy paths still lack durable audit persistence because the current audit store is tenant-scoped and registry resolution can fail before a tenant is known. Phase 2 now adds an initial Cargo sparse-registry adapter slice: `config.json` responses are proxied and rewrite registry-local default `dl` bases plus same-origin Cargo `api` bases back under the configured mount, including rooted, dot-segment, query/fragment-bearing, and same-origin absolute bases, even when valid upstream response headers are mislabelled, while invalid Cargo config payloads fail closed. Cargo download bases may now also resolve to explicitly allowlisted off-origin download hosts, and Cargo download redirects are followed only when each hop stays on the registry origin or one of those allowlisted download origins. Off-origin Cargo download hops never inherit the registry-config upstream credential. Encoded Cargo `dl` and `api` paths are revalidated at request time with HMAC-SHA256 signatures derived from the operator-held bootstrap-only `MOSQUITO_NET_CARGO_DOWNLOAD_MAC_KEY`, so sparse metadata cannot steer request-time egress or credential forwarding away from approved hosts and cached Cargo `config.json` route bases remain valid across Mosquito Net restarts when that secret stays stable. Rotating that secret intentionally invalidates previously issued Cargo proxy URLs until clients refetch `config.json`. Non-default markerized Cargo `dl` templates are also rejected until Mosquito Net can normalize them safely. Sparse package index paths normalize to Cargo package metadata requests, sparse metadata candidates are filtered through per-version artifact decisions using required `name`, `vers`, and `cksum` fields, mixed-case names are accepted when they canonicalize cleanly, malformed sparse metadata or candidate hard errors fail closed like the main proxy path, and upstream non-success sparse responses are preserved instead of being reparsed as candidate lists. Explicit default Cargo download paths that end in `/{crate}/{version}/download` normalize to Cargo artifact requests that prefetch upstream `.crate` files, require the served bytes to match the sparse index `cksum`, and only then proceed to Triage and response release. Explicit Cargo registry API endpoints now passthrough without Triage when they arrive beneath a signed Cargo `api` base, but that path forwards only allowlisted Cargo headers and never falls back to the registry-config upstream credential, so the rewritten Cargo `api` base cannot become a generic same-origin proxy. Operator guidance for Cargo source replacement now lives in [Cargo Source Replacement With Mosquito Net](../../development/cargo-source-replacement.md). Remaining Cargo follow-up in this area is non-default Cargo `dl` templates plus cross-origin Cargo `api` origins.