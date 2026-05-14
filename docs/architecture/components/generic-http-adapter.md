# Generic HTTP Adapter

Source PRD sections: Feature 1, Phase 2 ecosystem expansion.

The Generic HTTP adapter is a Mosquito Net fallback for private or non-standard package sources that expose downloadable artifacts over HTTP but do not match a supported ecosystem protocol such as npm, PyPI, Cargo, or Maven.

## Purpose

- Provide a bounded fallback proxy path when a tenant still needs request-time protection for an HTTP-hosted artifact source.
- Capture a stable artifact digest before release when the response is a byte-serving artifact request.
- Preserve enough upstream context for audit, evidence, and later higher-fidelity adapter work without pretending the source has ecosystem-specific semantics.

## Artifact Capture Semantics

- The adapter is request-time only. It does not attempt protocol discovery, dependency graph extraction, lockfile semantics, or metadata candidate filtering.
- `GET` and `HEAD` are the only request methods in scope. In the current Phase 2 implementation, all `GET` requests beneath a Generic HTTP mount take the bounded byte-capture plus hold path, while `HEAD` is limited to existence and header probes for the same bounded artifact URLs. Write-side HTTP APIs remain out of scope until the source has explicit authenticated mutation semantics.
- Explicit `HEAD` probe handling is only implemented for Generic HTTP mounts. Other ecosystem adapters keep their own method semantics and should not assume Generic HTTP-style `HEAD` passthrough unless they add it deliberately.
- Operators should mount Generic HTTP adapters on stable byte-serving paths. The current implementation does not inspect response type to downgrade HTML or JSON `GET` responses into a lighter metadata passthrough path.
- For artifact candidates, Mosquito Net must fetch the upstream body into bounded memory or temporary storage, enforce artifact-size limits, compute a SHA-256 digest over the exact served bytes, and then request a Triage Counter decision before release. If the adapter cannot fully buffer the candidate within the configured bounds, it must fail closed instead of streaming unvetted bytes.
- The normalized request-time coordinate uses `PackageEcosystem::GenericHttp`, the upstream host as the namespace, the normalized request path as the name, and no version unless a future protocol-aware layer can derive one safely. The full upstream URL remains request context rather than becoming the coordinate identity.

## Metadata And Audit Semantics

- Current Phase 2 behavior preserves only limited protocol metadata needed for request-time handling and replay-safe passthrough: upstream host, normalized path, query string when it changes artifact identity, HTTP method, response status, and a redacted subset of upstream response headers used by the proxy path.
- Preserve query-bearing upstream URLs in request context, upstream fetches, and cache keys when the query selects the artifact, even though the normalized coordinate identity remains host plus path.
- Durable audit storage still records basic request/outcome metadata only. Richer Generic HTTP protocol metadata persistence remains follow-up work.
- Never persist or log inbound or upstream credential values, cookies, authorization headers, or full opaque header dumps.
- HTML landing pages, JSON indexes, and other non-artifact `GET` responses currently still flow through the bounded capture plus hold path if they are requested through a Generic HTTP mount. A protocol-aware metadata bypass remains follow-up work.

## Boundaries And Limitations

- This adapter is intentionally lower fidelity than ecosystem-specific adapters. It is for byte capture and request-time hold behavior, not package-manager compatibility.
- It must not silently follow unbounded redirect chains or become a transparent tunnel for arbitrary HTTP methods.
- It does not infer maintainers, versions, dependency graphs, or provenance statements from arbitrary HTTP payloads.
- Private or custom registries that need richer semantics should graduate to a dedicated adapter instead of accumulating protocol-specific exceptions here.