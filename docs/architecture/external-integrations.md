# External Integrations And Feeds

Source PRD sections: 3.4, 3.6, 4.6, 4.9.

Aegiscudo integrates with package registries, intelligence feeds, AI providers, and observability systems through explicit adapters and credentials.

## Registry Integrations

MVP registry proxying is scoped to npm and PyPI. Phase 2 now adds an initial Cargo sparse-registry path in Mosquito Net for `config.json`, sparse index files, per-version sparse candidate filtering, non-redirecting crate downloads for registry-local default `dl` bases, and explicit Cargo registry API flows when the upstream `api` base resolves to the configured registry origin. Proxied Cargo `config.json` responses now rewrite both signed `dl` and signed `api` bases under the configured mount. Cargo download-route signatures now derive from HMAC-SHA256 keyed by the operator-held bootstrap-only `MOSQUITO_NET_CARGO_DOWNLOAD_MAC_KEY`, so cached proxied `config.json` download bases remain valid across proxy restarts when that secret stays stable. Rotating that secret invalidates previously issued download URLs until clients refetch `config.json`. Cargo artifact downloads also preserve Cargo.lock checksum semantics for registry-local default `dl` bases by validating the sparse index `cksum` against the exact `.crate` bytes before release. Cargo API passthrough forwards only allowlisted Cargo request headers and never falls back to the registry-config upstream credential, so the signed Cargo `api` base cannot become a generic same-origin proxy. Operator guidance for configuring Cargo source replacement through the proxy lives in [Cargo Source Replacement With Mosquito Net](../development/cargo-source-replacement.md). Cross-origin absolute Cargo `dl` or `api` bases and redirecting Cargo download endpoints remain follow-up work. Generic HTTP passthrough is now implemented with the bounded capture semantics documented in [Generic HTTP Adapter](components/generic-http-adapter.md). Maven repository-layout proxying is also implemented for artifact, POM, metadata, and checksum paths. OCI/Docker remains represented in shared enums and admin contracts but still returns phase-gated not-yet-supported behavior until later phases.

The canonical cross-ecosystem rollout summary lives in the [Capability By Phase](README.md#capability-by-phase) matrix.

## Intelligence Feeds

MVP feed scope includes OSV, GHSA, OpenSSF Malicious Packages, CISA KEV, and FIRST EPSS where capacity permits. Feed Harvester persists last-successful snapshots, freshness state, and normalized records so request-time policy never depends on live feed calls.

## AI Providers

AI Analyst supports OpenAI, Anthropic, Google Vertex AI, Google Gemini, OpenRouter, and OpenAI-compatible local providers such as Ollama, LM Studio, and vLLM. Provider configuration and model selection are managed through Command Center and stored in the database.

## Credential Handling

- Bootstrap credentials are provided through `.env` or orchestration secrets.
- Runtime credential overrides are stored encrypted in PostgreSQL, while API surfaces expose metadata and configured status only.
- Credential create, rotate, delete, and test-connection actions are audit logged without values.
- Services must validate required credentials at startup where applicable.

## Configuration Reload And Credential Precedence

- Database-stored runtime credential overrides take precedence over bootstrap environment values whenever both exist.
- Aegiscudo API validates credential format, persists encrypted runtime overrides, audits the change, and triggers the relevant internal reload or test-connection workflow without requiring a service restart.
- Mosquito Net must apply new registry mounts, upstream credentials, and disabled configs through no-restart reload behavior so newly added registries become active immediately.
- AI Analyst and Feed Harvester must refresh provider or feed client settings from the latest database-backed config while retaining the previous known-good config if reload validation fails.
- Command Center must distinguish bootstrap-only credentials from active runtime overrides in admin views without ever exposing secret values.

## Current Implementation State

The `.env.example`, credential metadata schema, AI provider config schema, local Langfuse infrastructure, and feed fixtures exist. Feed Harvester already supports live deps.dev and OpenSSF Scorecard fetch with fixture fallback, while runtime credential API, provider discovery, and test-connection workflows remain follow-up work.