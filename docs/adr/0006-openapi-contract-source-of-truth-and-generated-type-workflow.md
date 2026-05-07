---
Status: Accepted
Category: interface
Date: 2026-05-07
Supersedes:
---

# ADR 0006: OpenAPI Contract Source of Truth and Generated Type Workflow

## Context

The API, UI, and CLI need one canonical contract source and a reproducible generated-type workflow. The tracker had already settled this, but the decision belonged in an ADR rather than in a phase-specific placeholder log.

## Decision

- OpenAPI source files live under `contracts/openapi`.
- Generated TypeScript contract aliases are committed into `packages/shared-types/src/generated`.
- Contract drift is blocked by `pnpm openapi:check`.
- Richer request clients or SDK layers for the UI and CLI remain separate from the source-of-truth contract generation step and can continue in Phase 1C.

## Rationale And Evidence

- [package.json](../../package.json) defines both `openapi:generate` and `openapi:check` using `openapi-typescript`.
- [README.md](../../README.md) and [docs/development.md](../development.md) already treat `pnpm openapi:check` as a standard validation command.
- Keeping generated aliases committed makes contract drift visible in code review and keeps TypeScript consumers synchronized with the OpenAPI source.

## Consequences

- The repo has one contract source of truth and one explicit drift gate.
- UI and CLI developers can rely on shared generated aliases without inventing parallel contract definitions.
- Client-specific request wrappers remain free to evolve without weakening contract governance.

## Acceptance Evidence And Metrics

- `pnpm openapi:check` passes locally and in CI.
- Contract drift is visible as a git diff in `packages/shared-types/src/generated/aegiscudo-api.ts`.
- The workspace continues to use one committed generated alias file for the public API surface.