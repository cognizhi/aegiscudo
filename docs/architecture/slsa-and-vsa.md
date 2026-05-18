# SLSA And Verification Summary Attestations

Aegiscudo treats SLSA provenance and Verification Summary Attestations as identity and integrity evidence. They can raise confidence that an artifact was built by an expected system under a verified policy, but they do not prove the artifact is benign.

## Evidence Model

Normalized attestation evidence may now carry optional SLSA fields:

- `slsa_verified_levels`: SLSA result strings from a verified VSA, such as `SLSA_BUILD_LEVEL_3`.
- `slsa_build_level`: the highest supported Build Track level, currently 0 through 3.
- `slsa_version`: the SLSA specification version used by the verifier.
- `vsa_verifier_id`, `vsa_resource_uri`, `vsa_policy_uri`, and `vsa_dependency_levels`: the verifier identity, artifact resource URI, policy reference, and dependency-level counts from a VSA.

Only verified attestations should populate these fields. Missing provenance, failed verification, unverifiable signatures, subject digest mismatch, verifier mismatch, resource URI mismatch, or an unexpected VSA predicate must leave SLSA level fields absent and preserve the underlying failure result.

## Consumer Requirements

Aegiscudo-generated policy decisions may consume a SLSA build level only after the verification pipeline has established all of the following:

- The attestation envelope signature chains to a tenant-approved root of trust.
- The in-toto statement subject digest matches the artifact digest being evaluated.
- The predicate type is either SLSA build provenance or `https://slsa.dev/verification_summary/v1`, according to the evidence type being stored.
- For VSA evidence, `verifier.id` is an explicitly trusted verifier, `resourceUri` matches the artifact coordinate or download URI, `verificationResult` is `PASSED`, and `verifiedLevels` contains the required Build Track level.
- Dependency-level counts are interpreted as claims by the trusted verifier, not as independently verified transitive evidence unless the verifier policy says so.

## Aegiscudo VSA Production

Aegiscudo should produce VSAs only after the provenance verification pipeline is stable, observable, and audited. Production requirements are:

- Versioned verification policy with immutable policy digest recorded in every generated VSA.
- Raw input attestation digests stored before summary generation.
- Tenant-scoped trust roots and verifier allowlists.
- Deterministic subject and resource URI canonicalization for each ecosystem.
- Audit events for VSA generation, signing-key use, policy version, verifier version, subject digest, resource URI, and generated statement digest.
- A regression fixture set covering pass, fail, missing, stale key, wrong verifier, wrong resource URI, subject mismatch, dependency-level-only claims, and unsupported SLSA result strings.

## Key Management

Aegiscudo-generated VSAs must be signed by a dedicated verifier identity, not by adapter or service runtime credentials. The production design is:

- Use per-environment KMS/HSM-backed signing keys with no exportable private material.
- Separate tenant trust policy from physical key storage so tenant policy decides which verifier identity and key versions are trusted.
- Record key ID and key version in audit events and verifier metadata; never log signatures, credentials, or raw key material.
- Rotate signing keys with overlapping verification windows, revocation metadata, and explicit stale-key tests.
- Keep development keys isolated from production trust roots and label all non-production VSAs as non-production evidence.

## Current Blockers

SLSA fields can be represented in the evidence contract today. Request-time policy thresholds, dashboard rendering, persisted VSA fields, generated VSA audit evidence, and VSA production remain blocked until migrations, OpenAPI/read-model contracts, UI evidence routes, and the verifier pipeline are implemented.