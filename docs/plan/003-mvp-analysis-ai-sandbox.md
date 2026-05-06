# Phase 1B MVP Analysis, AI, And Sandbox Plan

Source PRD sections: Feature 3, Feature 4, 2.1, 2.3.3, 2.3.4, 2.3.5, 3.3, 3.6, 3.7.2, 4.1 through 4.4, 4.8, 4.9, 4.12.

Goal: build the asynchronous analysis plane that produces evidence, behavioral telemetry, advisory AI explanations, and final recommendation inputs without putting package content or LLM output in the enforcement path unsafely.

## Phase Status

- [x] Phase 1B has an owner: `Aegiscudo Tech Lead`.
- [x] Evidence schemas from Phase 0 are stable enough for implementation.
- [ ] Control-plane analysis job creation is available.
- [ ] Analysis-plane exit review is complete.

Progress note: 2026-05-05 implemented the initial Surgeon static scan library and Python redaction service shells. Full Phase 1B remains blocked on analysis job orchestration, controlled artifact fetching, real archive unpacking, sandbox adapters/profiles, provider abstractions, Langfuse client wiring, and persistence.

## Exit Criteria

- [ ] Surgeon safely unpacks npm and PyPI artifacts and emits schema-valid evidence.
- [ ] Surgeon detects MVP suspicious indicators, sleeper/deferred patterns, AI agent injection patterns, and worm/cross-package write patterns.
- [ ] Emergency Room runs npm and PyPI sandbox profiles with no customer secrets and no privileged host access.
- [ ] Emergency Room plants canary secret and AI agent config files and records access or modification events.
- [ ] AI Analyst receives redacted evidence slices only and produces schema-valid advisory explanations.
- [ ] Langfuse traces are created for every LLM call with required metadata, token, cost, hash, redaction, and schema-validation fields.
- [ ] Analysis results are persisted and can update Triage Counter scoring or HITL review state.

## Analysis Job Orchestration

- [ ] Define analysis job state machine: queued, fetching, static-running, sandbox-pending, sandbox-running, ai-pending, finalizing, completed, failed, cancelled.
- [ ] Implement idempotent job claiming.
- [ ] Implement retry cap and backoff.
- [ ] Implement artifact fetch through controlled fetcher only.
- [ ] Store original artifact in object storage keyed by SHA-256 digest.
- [ ] Record package coordinate, tenant, registry config, policy snapshot, trace ID, and source URL on each job.
- [ ] Prevent package-provided URLs from bypassing configured fetch controls.
- [ ] Emit job lifecycle audit events.
- [ ] Emit queue depth, latency, retry, and failure metrics.
- [ ] Add tests for duplicate job submission and idempotent completion.

## Surgeon Archive Safety

- [ ] Implement safe unpacking for npm `.tgz` artifacts.
- [ ] Implement safe unpacking for Python wheels.
- [ ] Implement safe unpacking for Python source distributions.
- [x] Reject archive traversal paths.
- [x] Reject absolute paths.
- [ ] Reject symlink or hardlink escapes.
- [ ] Enforce max expanded bytes.
- [x] Enforce max file count.
- [x] Enforce max single file size.
- [ ] Enforce timeout for unpack and scan operations.
- [ ] Compute SHA-256 for original artifact.
- [ ] Compute SHA-256 for every extracted file.
- [ ] Generate normalized file manifest.
- [ ] Add tests for traversal, oversized archive, decompression bomb, too many files, large single file, and symlink escape.
	- Blocker: safe path validation and directory scan limits exist; actual npm/PyPI archive unpacking, symlink/hardlink escape enforcement during extraction, expanded-byte accounting, timeouts, per-file manifest generation, and full adversarial archive tests remain.

## Surgeon Manifest And Metadata Analysis

- [ ] Select and integrate JavaScript/TypeScript AST parser: use SWC (`swc-core`) or OXC (`oxc-parser`) for performant AST traversal (PRD §2.3.3).
- [ ] Select and integrate Python AST parser: use `tree-sitter-python` for structured Python parsing (PRD §2.3.3).
- [ ] Parse npm `package.json`.
- [ ] Extract npm lifecycle scripts.
- [ ] Extract npm executable entry points.
- [ ] Extract npm dependencies, optional dependencies, peer dependencies, and dev dependencies where relevant.
- [ ] Parse Python wheel metadata.
- [ ] Parse Python `pyproject.toml`.
- [ ] Parse Python `setup.cfg` where practical.
- [ ] Treat `setup.py` as text evidence and never execute it.
- [ ] Extract Python package top-level module hints.
- [ ] Extract package repository URL, maintainers, publish time, license, and classifiers where available.
- [ ] Compute minimum release age signal from metadata timestamp and request time.
- [ ] Compute GitHub-to-registry publish gap when source release metadata is available.
- [ ] Generate package-level SBOM fragment fields needed by Phase 2 SBOM service.
- [ ] SBOM fragment must include `purl`, name, version, SHA-256 digest, ecosystem, and dependency relationships to be compatible with Phase 2 SBOM Service aggregation.
- [ ] Add tests for valid, malformed, and missing manifests.

## Surgeon Suspicious Indicator Extraction

- [x] Detect JavaScript `eval` usage.
- [x] Detect JavaScript `Function` constructor usage.
- [ ] Detect dynamic import patterns.
- [x] Detect Node.js `child_process` usage.
- [ ] Detect shell command construction.
- [ ] Detect network calls to non-registry destinations.
- [x] Detect credential file path access patterns.
- [ ] Detect npm, PyPI, GitHub, cloud, SSH, and Kubernetes token discovery patterns.
- [x] Detect Python `exec` usage.
- [x] Detect Python `eval` usage.
- [ ] Detect Python dynamic import abuse.
- [ ] Detect Python `subprocess`, `socket`, `requests`, and `urllib` suspicious patterns.
- [ ] Detect import-time network behavior patterns statically where possible.
- [ ] Detect high-entropy strings.
- [x] Detect large base64-like blobs.
- [ ] Detect hex-encoded or folded suspicious strings.
- [ ] Detect minified payloads embedded in metadata.
- [ ] Detect unexpected binary blobs.
- [ ] Detect sleeper and deferred execution gates using date, environment, hostname, CI markers, counters, and remote configuration fetches.
- [ ] Detect AI agent injection content in `.cursorrules`, `AGENTS.md`, `.github/copilot-instructions.md`, `.claude/`, README, descriptions, and comments.
- [x] Detect attempts to write to other packages, `node_modules`, `.npmrc`, shell profiles, `.gitconfig`, or global configuration files.
- [x] Generate semantic code slices with file path, line span, indicator type, severity, and redaction status.
- [x] Ensure evidence does not include full source files.
- [ ] Add malicious fixture tests for every MVP indicator category.
	- Blocker: regex MVP scanner covers several indicator classes; AST-backed parsing, network/import abuse coverage, high-entropy/hex/minified/binary detection, and fixture tests for every MVP category are still required.

## Evidence Persistence

- [ ] Persist static analysis report JSON in PostgreSQL or object storage according to size.
- [ ] Store large evidence payloads in object storage with digest reference.
- [ ] Link every evidence record to artifact digest and analysis job ID.
- [ ] Link every evidence record to policy snapshot where used for a decision.
- [ ] Validate evidence JSON against schema before persistence.
- [ ] Record analyzer version and rule set version.
- [ ] Emit metrics for evidence count, severity distribution, scan duration, and failures.
- [ ] Add backward compatibility test for evidence schema fixtures.

## Emergency Room Sandbox Orchestrator

- [ ] Define sandbox run state machine.
- [ ] Implement sandbox profile registry.
- [ ] Implement Cloud Run Jobs adapter for MVP coarse dynamic analysis.
- [ ] Implement local mocked sandbox adapter for integration tests.
- [ ] Enforce per-execution service account with no cloud permissions except telemetry write.
- [ ] Ensure no customer secrets are mounted.
- [ ] Enforce no privileged container mode for standard profiles.
- [ ] Enforce no host mounts.
- [ ] Enforce strict CPU, memory, and timeout limits.
- [ ] Support egress modes: deny-all, registry-only, monitored proxy.
- [ ] Write telemetry only to narrow append-only ingestion endpoint.
- [ ] Implement sandbox run cancellation and timeout handling.
- [ ] Emit metrics for queue depth, run duration, profile, result, and failure reason.
- [ ] Add tests for profile selection, timeout handling, retry cap, and telemetry ingestion.

## npm Install Profile

- [ ] Create temporary project baseline.
- [ ] Plant canary secrets and config files.
- [ ] Resolve package through controlled registry path.
- [ ] Install dependencies with scripts disabled where supported.
- [ ] Install target with scripts disabled.
- [ ] Install target with scripts enabled.
- [ ] Trace npm `preinstall`, `install`, and `postinstall` lifecycle scripts.
- [ ] Capture process tree.
- [ ] Capture environment access attempts where practical.
- [ ] Capture filesystem snapshot before and after each phase.
- [ ] Capture network attempts through controlled proxy or deny log.
- [ ] Capture exit code and stderr/stdout with redaction.
- [ ] Attribute suspicious behavior to root package, lifecycle script, transitive dependency, or package manager where possible.
- [ ] Label evidence records with the originating execution phase (A=baseline, B=resolve-no-exec, C=install-scripts-disabled, D=target-scripts-disabled, E=target-scripts-enabled, F=build, G=import-load, H=smoke-probe) for precise attribution in the Evidence Viewer phase timeline (PRD §2.3.4).
- [ ] Add fixture test for canary credential access.
- [ ] Add fixture test for outbound network attempt.
- [ ] Add fixture test for AI agent canary file modification.

## Python Install Profile

- [ ] Create isolated virtual environment baseline.
- [ ] Plant canary secrets and config files.
- [ ] Install wheel/sdist through controlled index path.
- [ ] Compare dependency-disabled and dependency-enabled flows where practical.
- [ ] Import selected top-level modules under timeout.
- [ ] Capture process behavior.
- [ ] Capture filesystem diff.
- [ ] Capture import-time exceptions.
- [ ] Capture network attempts.
- [ ] Attribute behavior to root package, transitive package, build tool, or import probe where possible.
- [ ] Add fixture test for import-time network attempt.
- [ ] Add fixture test for canary config access.
- [ ] Add fixture test for sandbox timeout.

## Canary Strategy

- [ ] Plant fake npm token.
- [ ] Plant fake PyPI token.
- [ ] Plant fake GitHub token.
- [ ] Plant fake AWS credential values.
- [ ] Plant fake Google application credentials path.
- [ ] Plant fake `.npmrc`.
- [ ] Plant fake `.pypirc`.
- [ ] Plant fake `.gitconfig`.
- [ ] Plant fake SSH private key path.
- [ ] Plant fake cloud metadata endpoint response where feasible.
- [ ] Plant fake `.env` with structured key-value pairs.
- [ ] Plant fake KUBECONFIG.
- [ ] Plant fake Cursor and VS Code settings paths.
- [ ] Plant `.github/copilot-instructions.md` canary.
- [ ] Plant `.cursorrules` canary.
- [ ] Plant `AGENTS.md` canary.
- [ ] Plant `.claude/settings.json` canary.
- [ ] Flag read, copy, encode, exfiltration attempt, write, or append behavior.
- [ ] Map canary events to high-severity policy signals.

## AI Analyst Service

- [x] Define evidence input schema accepted from Surgeon/Emergency Room.
- [ ] Implement redaction before prompt construction.
- [ ] Validate no secrets remain in prompt input.
- [ ] Implement provider abstraction for OpenAI.
- [ ] Implement provider abstraction for Anthropic.
- [ ] Implement provider abstraction for Google Gemini.
- [ ] Implement provider abstraction for Google Vertex AI.
- [ ] Implement provider abstraction for OpenRouter.
- [ ] Implement provider abstraction for Ollama.
- [ ] Implement provider abstraction for LM Studio.
- [ ] Implement provider abstraction for vLLM.
- [ ] Implement provider abstraction for generic OpenAI-compatible endpoints.
- [ ] Enforce local-only evidence boundary for local providers.
 - [ ] Verify `is_local` provider flag at startup and before each LLM request, not only at startup (PRD §3.6 data-exfiltration risk).
 - [ ] Emit an explicit startup log and health-detail field stating whether evidence is routed to a local provider or a cloud provider.
 - [ ] Implement cloud-provider privacy boundary notice fields.
 - [ ] Enforce tenant-level and package-level LLM budget quotas before issuing AI requests; quota exhaustion must degrade explanations without blocking deterministic policy decisions.
- [ ] Fetch active provider config from database.
- [ ] Require at least one active provider before AI jobs execute.
- [ ] Build structured JSON prompts from redacted evidence only.
- [ ] Clearly separate observed behavior from inference in output schema.
- [ ] Validate LLM response against JSON schema.
- [ ] Reject outputs that attempt to change policy, bypass guardrails, request secrets, or self-authorize.
- [ ] Store explanation with model, provider, prompt template version, redaction result, output hash, and evidence hash.
- [ ] Add unit tests for redaction, schema validation, provider failures, local boundary enforcement, and hallucination guardrails.
	- Blocker: shared log and structured-event redaction utilities plus tests exist; prompt construction, prompt-level secret validation, provider abstractions, schema validation of LLM output, quota enforcement, guardrail rejection, and persistence remain.

## Langfuse Instrumentation

- [x] Include self-hosted Langfuse in local infrastructure.
- [x] Use separate Langfuse database from Aegiscudo application database.
- [ ] Store Langfuse public and secret keys in credential store or local secret env.
- [ ] Restrict dashboard access to admin and platform-admin roles.
- [ ] Fetch prompt templates from Langfuse at startup.
- [ ] Cache active prompt template for process lifetime with periodic refresh.
- [ ] Provide last-known-good fallback prompt template in source.
- [ ] Alert when fallback prompt is used.
- [ ] Wrap every LLM call in a Langfuse trace.
- [ ] Record trace ID, session ID, provider, model, prompt template name, prompt template version, token counts, estimated cost, latency, redaction flag, schema validation flag, evidence hash, and output hash.
- [ ] Store Langfuse trace ID on `ai_explanations`.
- [ ] Write `schema_valid` score.
- [ ] Write `redaction_complete` score.
- [ ] Write `hallucination_flag` score.
- [ ] Support optional human `analyst_review` score.
- [ ] Add integration tests with a fake Langfuse client.
	- Blocker: local infrastructure includes Langfuse; client wiring, prompt template workflow, trace fields, scores, access restrictions, and fake-client integration tests remain.

## Analysis Result Finalization

- [ ] Combine static indicators, sandbox telemetry, feed matches, and AI advisory explanation into final analysis summary.
- [ ] Keep deterministic score generation outside the LLM.
- [ ] Update Triage Counter with static score signal.
- [ ] Update Triage Counter with sandbox result signal.
- [ ] Mark artifacts requiring HITL review.
- [ ] Persist final recommendation with confidence and limitations.
- [ ] Record missing sandbox evidence if sandbox worker is unavailable.
- [ ] Record missing AI explanation if AI Analyst or Langfuse is unavailable.
- [ ] Ensure AI outage never blocks deterministic allow/block decisions.
- [x] Add pgvector embedding store placeholder: schema column `embedding vector(1536)` on evidence records; population deferred to Phase 2 for clustering similar malicious code slices and historical case retrieval (PRD §3.6).
- [ ] Add integration tests for static-only, sandbox-enhanced, AI-degraded, and full-analysis flows.

## Phase 1B Validation

- [x] Archive traversal tests pass.
- [ ] Decompression limit tests pass.
- [ ] npm postinstall detection fixture passes.
- [ ] Python exec detection fixture passes.
- [ ] Obfuscated payload fixture passes.
- [ ] Sleeper pattern fixture passes.
- [ ] AI agent injection fixture passes.
- [ ] Worm/cross-package write fixture passes.
- [ ] Canary credential access sandbox fixture passes.
- [ ] AI agent canary file sandbox fixture passes.
- [ ] Redaction failure tests pass.
- [ ] Prompt injection tests pass.
- [x] Schema validation tests pass.
- [ ] Sandbox profile integration tests pass locally with mocked adapter.
