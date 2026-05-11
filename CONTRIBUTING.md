# Contributing To Aegiscudo

Thanks for contributing to Aegiscudo.

This project sits at the intersection of software supply chain security, registry protocol behavior, static analysis, sandboxing, threat intelligence, and operator tooling. That combination makes correctness and restraint more important than raw feature velocity.

## Start Here

Before making non-trivial changes, read:

- [README.md](README.md)
- [docs/prd/aegiescudo-prd.md](docs/prd/aegiescudo-prd.md)
- [docs/architecture/README.md](docs/architecture/README.md)
- [docs/plan/README.md](docs/plan/README.md)
- [SECURITY.md](SECURITY.md)

The PRD is the product source of truth. The architecture docs explain current boundaries. The plan files show what phase a change belongs to.

## What Good Contributions Look Like

Good contributions usually do one or more of the following:

- improve registry protocol correctness without loosening trust boundaries
- improve evidence quality, determinism, or operator explainability
- add focused tests for positive, negative, boundary, and adversarial cases
- tighten secret handling, logging redaction, or auditability
- improve documentation, onboarding, or architecture clarity
- expand fixtures, schemas, and contracts in ways that reduce ambiguity

## Contribution Paths

### Fast Path For Small Changes

For contained changes such as documentation fixes, typo corrections, narrow tests, localized fixture updates, or small non-architectural cleanup:

- you usually do **not** need to open an issue first
- keep the PR tightly scoped
- explain the local impact clearly
- run the smallest relevant validation and say exactly what you ran

### Full Design Path For Security-Sensitive Or Architectural Work

For changes that affect service boundaries, policy semantics, registry behavior, sandbox behavior, trust assumptions, or roadmap scope:

- check whether the change belongs to an existing plan item or issue
- open or comment on an issue before implementation when direction is unclear
- call out threat-model and operational impact explicitly in the PR

## Non-Negotiable Rules

These rules are here because this is a security product, not a generic app scaffold.

- Treat package content, metadata, README files, comments, and AI-agent instruction files as adversarial input.
- Do not execute untrusted package code outside Emergency Room sandbox profiles.
- Do not make LLM output the sole authority for a security decision.
- Do not send whole package source files to AI Analyst or external LLM providers.
- Do not silently substitute pinned artifacts, tarball URLs, or integrity-locked dependencies.
- Do not log tokens, auth headers, raw secrets, or environment dumps.
- Do not weaken audit trails, override requirements, or policy snapshot references for convenience.

## Development Setup

### Prerequisites

- Rust toolchain compatible with the workspace
- Node.js 20.9+
- `pnpm` 10.33.3+
- Python 3.12
- `uv`
- Docker and Docker Compose
- GNU Make

### Bootstrap

```bash
cp .env.example .env
pnpm install
uv sync
make up
make migrate
pnpm openapi:generate
```

## Typical Workflow

1. Check whether the change already belongs to an existing plan item or open issue.
2. For larger or security-sensitive changes, open or comment on an issue before implementation so the phase fit and design direction are clear.
3. Create a focused branch.
4. Keep the change scoped. Avoid mixing refactors, feature work, and unrelated cleanup in one PR.
5. Add or update tests and fixtures with the change.
6. Update docs when behavior, contracts, architecture, or operational assumptions change.
7. Submit a PR with a precise summary, validation notes, and any remaining risks.

## Validation Expectations

Run the narrowest relevant validation first, then the broader checks that apply to your slice.

Common commands:

```bash
cargo test --workspace
pnpm lint
pnpm typecheck
pnpm test
pnpm schema:validate
uv run pytest
uv run ruff check services/python-common services/emergency-room services/ai-analyst
uv run mypy services/emergency-room services/ai-analyst
make migrate-check
```

If you touch only one slice, say exactly what you ran and what you did not run.

## Documentation Expectations

Update documentation when your change affects any of these:

- user-facing behavior
- service boundaries
- policy or decision semantics
- schemas or contracts
- local setup or operational workflows
- security assumptions

That often means updating one or more of:

- [README.md](README.md)
- [docs/architecture](docs/architecture)
- [docs/plan](docs/plan)
- [docs/prd/aegiescudo-prd.md](docs/prd/aegiescudo-prd.md)

## Commit And PR Guidance

Conventional Commits are preferred because the repo is already structured around release automation expectations:

- format commits as `type(scope): summary` when a scope adds clarity, for example `fix(mosquito-net): preserve explicit artifact routes during fallback`
- keep the first line imperative and specific enough that release notes are readable without opening the PR
- `feat:` for user-visible capability additions
- `fix:` for behavior corrections
- `docs:` for documentation-only changes
- `test:` for fixture and validation additions
- `refactor:` for internal structure changes without behavior changes

If a change spans multiple concerns, prefer splitting it into multiple commits instead of collapsing unrelated work under one broad summary. This helps `release-please` group changes into meaningful release notes.

## Release Version Strategy

Aegiscudo currently uses a single monorepo release version.

- `release-please` tracks the repository root package at `.` using `.release-please-manifest.json`
- release PRs and tags advance one shared version for the repository instead of separate per-service versions
- the generated root changelog lives at `CHANGELOG.md`
- build-time surfaces such as `APP_VERSION` and `NEXT_PUBLIC_APP_VERSION` must derive from that Git tag rather than hardcoded source literals

Until the PRD changes, do not introduce independent application-version streams for individual services or packages.

PRs should include:

- what changed
- why it changed
- how it was validated
- any follow-up work or intentional omissions

## Security-Sensitive Contributions

If your change touches any of the following, expect higher review scrutiny:

- registry proxy behavior
- request-time decisioning
- sandbox execution
- credential handling
- audit or override models
- AI evidence flows
- provenance, attestation, or SBOM logic
- logging and telemetry

When changing those areas, include explicit notes about:

- threat model impact
- new trust assumptions
- fail-open or fail-closed behavior
- auditability implications

## Vulnerability Reporting

Do **not** open a public issue for a security vulnerability.

Use the private workflow described in [SECURITY.md](SECURITY.md).

## License

By contributing to this repository, you agree that your contributions are licensed under the [MIT License](LICENSE).