# AI Analyst

Source PRD sections: 3.3, 3.4.4, 3.6, 3.7.2, 4.2, 4.3, 4.9.

AI Analyst produces advisory explanations from redacted analysis evidence. It is never an enforcement authority by itself.

## Responsibilities

- Receive redacted evidence slices from Surgeon and Emergency Room outputs.
- Construct structured JSON prompts that clearly separate observed behavior from inference.
- Support configured cloud and local LLM providers through a provider abstraction.
- Validate LLM responses against the AI explanation schema.
- Reject outputs that attempt to change policy, bypass guardrails, request secrets, or self-authorize.
- Store explanation metadata, evidence hash, output hash, provider, model, prompt template version, redaction status, and Langfuse trace ID.

## Provider Boundary

Local providers must enforce a local-only evidence boundary. Cloud providers require an explicit privacy boundary notice in health details and Command Center administration.

## Current Implementation State

The Python FastAPI service shell, health/readiness/metrics routes, trace ID middleware, and shared log plus structured-event redaction utility exist. Provider abstractions, prompt template loading, prompt-level secret validation, schema validation, Langfuse trace wiring, budget quotas, local/cloud boundary enforcement, and persistence remain Phase 1B work.