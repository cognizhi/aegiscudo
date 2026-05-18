# Ecosystem Extension Points

Source PRD sections: Phase 3 additional ecosystem extension points, deferred RubyGems, PHP Packagist, NuGet, and Go Modules support.

Aegiscudo can add more package ecosystems, but each new ecosystem must enter through explicit contracts. `PackageEcosystem` enum variants, database enum migrations, CLI parsers, registry adapter behavior, policy semantics, SBOM mapping, feed enrichment, dashboard views, and fixtures must land together or behind a feature gate. Generic HTTP remains a bounded fallback for byte-serving private sources; it is not a substitute for ecosystem-specific semantics.

## Reassessment Matrix

| Ecosystem | Recommended Phase 3 Entry Point | Package Identity | Primary Inputs | Request-Time Proxy Notes | Current Status |
| --- | --- | --- | --- | --- | --- |
| RubyGems | Lockfile/static scanner first, registry proxy later | purl type `gem`, proposed Aegiscudo ID `rubygems` | `Gemfile.lock`, `.gemspec`, `.gem` metadata | RubyGems compact index and API proxying need candidate filtering and checksum handling before request-time enforcement | Planned, partially visible to deps.dev only; blocked on contracts and fixtures |
| PHP Composer/Packagist | Composer lockfile/static scanner first | purl type `composer`, proposed Aegiscudo ID `composer`, registry source kind `packagist` | `composer.lock`, `composer.json`, dist/source refs | Packagist often points to VCS/source archives, so proxying needs URL allowlists, archive digest capture, and plugin/script risk modeling | Planned, blocked on contracts and fixtures |
| NuGet | Lockfile/project-assets scanner first, feed proxy later | purl type `nuget`, proposed Aegiscudo ID `nuget` | `packages.lock.json`, `project.assets.json`, `.nuspec`, `.nupkg` | NuGet v3 service index and package-base-address endpoints need explicit feed discovery and private-feed credential handling | Planned, partially visible to deps.dev only |
| Go Modules | Module graph scanner first, GOPROXY proxy later | purl type `golang`, proposed Aegiscudo ID `go` | `go.mod`, `go.sum`, precomputed `go list -m -json all`, module zip metadata | GOPROXY and checksum database semantics must preserve module zip hashes and must not bypass tenant policy through direct VCS fallback | Planned, partially visible to deps.dev only |

## Required Adapter Interface Changes

Before adding any of these ecosystems to shared runtime contracts, define an ecosystem descriptor that captures:

- Stable Aegiscudo ecosystem ID and package-url type.
- External feed system IDs and registry/source kind, kept separate from the ecosystem ID when one package manager can use public registries, private registries, path repositories, or VCS sources.
- Registry or source protocol family, including whether request-time support is lockfile-only, metadata-only, artifact-proxy, or full registry proxy.
- Coordinate parser rules, namespace semantics, version normalization, and case sensitivity.
- Lockfile and manifest parser entry points.
- Artifact digest source of truth and whether upstream integrity metadata is required before release.
- Lifecycle execution risks such as install scripts, Composer plugins, build hooks, native extensions, generated code, or VCS fallback.
- Feed mapping for OSV, GHSA, deps.dev, malicious-package feeds, and cross-ecosystem IOC correlation.
- SBOM component mapping and dependency edge semantics.
- Required fixtures for normal, malformed, adversarial, private-registry, and dependency-confusion cases.

Per-ecosystem adversarial fixtures must include RubyGems multi-source/dependency-confusion and missing-checksum cases; Composer plugin/script execution plus `dist` URL userinfo, link-local, and private-host cases; NuGet case-insensitive ID collisions and content-hash mismatch cases; and Go `replace`, direct fallback, checksum mismatch, and `/v2` module path cases.

Go module graph scanners may accept `go list -m -json all` only as precomputed input or when generated in an explicitly no-network, read-only resolver environment. Scanner execution must not perform direct VCS resolution or checksum database calls outside tenant policy.

The descriptor should be consumed by CLI scanners, SBOM generation, feed normalization, policy evaluation, and Command Center display code. Request-time adapters must still implement protocol-specific configured proxies; do not introduce transparent packet-level proxying.

## Phase Gates

Adding enum variants alone is not sufficient. A new ecosystem may be enabled only after these gates pass:

1. Shared Rust, Python, TypeScript, OpenAPI, JSON schema, and database contracts agree on the ecosystem ID.
2. CLI scanner or registry adapter produces normalized coordinates and fixtures without executing package code.
3. Triage Counter policy behavior is explicit for missing metadata, stale feed data, dependency confusion, and malicious feed hits.
4. SBOM output and evidence references use the correct package-url type and preserve source digests.
5. Dashboard and API read models either render the ecosystem correctly or hide unsupported views behind explicit unavailable states.
6. Unit, schema, and integration tests cover positive, negative, boundary, and adversarial fixtures.

## Blocked Work

Implementation for RubyGems, Packagist, NuGet, and Go Modules cannot start from the request-time proxy layer because the shared contracts and persistence enums do not yet represent these ecosystems. The next safe step is an ecosystem descriptor contract plus migrations and fixtures, followed by lockfile/static scanners before any registry proxy work.