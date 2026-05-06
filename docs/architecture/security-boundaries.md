# Security Boundaries

Source PRD sections: 2.1, 2.3.3, 2.3.4, 4.1 through 4.6, 4.8, 4.12.

Aegiscudo treats dependency content and metadata as hostile. Security boundaries are designed so untrusted package behavior cannot influence request-time enforcement except through validated evidence and deterministic policy.

## Threat Model

Adversarial inputs include package archives, metadata, install scripts, READMEs, comments, AI-agent instruction files, registry responses, attestations, and feed payloads. Attacks may include maintainer compromise, lifecycle hooks, import-time execution, sleeper behavior, sandbox detection, prompt injection, AI-agent injection, credential discovery, dependency confusion, typosquatting, and cross-package writes.

## Prompt Injection Defenses

- Treat package-provided text as inert evidence.
- Never pass full READMEs, comments, or source files as instructions to an LLM.
- Redact secrets and PII before prompt construction.
- Require schema-validated LLM output.
- Ignore LLM output that attempts to change policy, bypass guardrails, request secrets, or self-authorize.

## Sandbox Boundaries

- No customer credentials.
- No privileged containers.
- No host mounts.
- Strict CPU, memory, timeout, and egress controls.
- Single-use execution environments.
- Telemetry-only write path.

## Policy Boundaries

- Every decision references an immutable policy snapshot.
- Overrides require reason, approver, scope, expiry, and audit evidence.
- Shadow mode cannot silently become enforcement mode.
- Fail-open behavior must be explicit, audited, and developer-visible.

## Current Implementation State

Log and structured-event redaction utilities, schema fixtures, safe archive path validation, service health conventions, and security docs exist. Full prompt construction guardrails, sandbox runtime boundaries, RBAC enforcement, tenant isolation tests, and policy override lifecycle remain open.