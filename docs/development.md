# Development Guide

1. Install Rust 1.95 or newer, Node 22 or newer, pnpm 10.33.3, Python 3.12, and uv.
2. Run `pnpm install` and `uv sync`.
3. Run `make up` once for local dependencies, then use `make migrate-check` to validate SQL migrations against the local PostgreSQL container.
4. Run `make migrate` to apply the SQL migrations to the local Aegiscudo database.
5. When changing [contracts/openapi/aegiscudo.openapi.yaml](contracts/openapi/aegiscudo.openapi.yaml), run `pnpm openapi:generate` and commit the regenerated `packages/shared-types/src/generated/aegiscudo-api.ts` artifact.
6. Run `cargo test --workspace`, `pnpm test`, `uv run pytest`, `pnpm schema:validate`, and `pnpm openapi:check` before marking plan tasks complete.
7. Keep phase tracker checkboxes honest: only implemented, tested, and documented work is checked.