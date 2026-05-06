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

## Boundaries

- Does not perform heavy static analysis, sandbox execution, feed ingestion, or LLM explanation.
- Does not silently substitute explicit pinned versions, tarball URLs, or integrity-locked artifacts.
- Does not act as a transparent packet-level proxy.
- Must fail closed for unknown artifacts in enforcement mode when Triage Counter is unavailable.

## Current Implementation State

The Rust Axum service shell exists with `/healthz`, `/readyz`, `/metrics`, and a placeholder proxy route. Real registry config loading, no-restart adapter reload, upstream proxying, caches, Triage client calls, and adapter integration tests are Phase 1A work.