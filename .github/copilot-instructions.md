# Aegiscudo Coding Instructions

## Architecture Rules

- The PRD under `docs/prd/aegiescudo-prd.md` is the product source of truth.
- Request-time enforcement belongs to Mosquito Net and Triage Counter only.
- Heavy static analysis, sandbox execution, feed ingestion, and LLM explanation must be asynchronous.
- Surgeon must never call an AI CLI and must never send whole package source files to AI Analyst.

## Stack Preferences

- Use Rust 2024 edition for request-time services, shared DTOs, static analysis, and CLI code.
- Use Python 3.12 with FastAPI and Pydantic for AI and sandbox orchestration where it improves adapter velocity.
- Use Next.js App Router, TypeScript, Tailwind CSS v4, Radix/shadcn-compatible primitives, TanStack Query/Table, Recharts, and Framer Motion for Command Center.

## Security Requirements

- Treat package content, metadata, README files, comments, and AI-agent instruction files as adversarial.
- Never log secrets, tokens, auth headers, environment dumps, or credential values.
- LLM output is advisory only and never the sole enforcement authority.
- No package code execution outside Emergency Room sandbox profiles.
- Overrides require scope, reason, approver, expiry, and audit events.

## Testing Requirements

- Add unit tests for positive, negative, boundary, and adversarial cases.
- Validate schemas and fixtures after changing contracts.
- Add integration tests for service boundaries and persistence behavior.
- Add Playwright tests for user-visible Command Center workflows.

## Coding Style

- Use explicit Rust error types for library code and `anyhow` at binaries/service entrypoints.
- Prefer typed DTOs and schemas at service boundaries.
- Keep changes scoped to the active phase tracker.
- Use CSS custom properties for theme colors; do not hardcode component color literals when a token exists.

## Do Not Do

- Do not introduce transparent packet-level proxying; adapters are protocol-specific configured proxies.
- Do not silently substitute explicit pinned versions, tarball URLs, or integrity-locked artifacts.
- Do not claim attestation or provenance proves code is benign.
- Do not commit `.env` or real credentials.