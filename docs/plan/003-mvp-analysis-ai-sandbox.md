# Phase 1B MVP Analysis, AI, And Sandbox Plan

Source PRD sections: Feature 3, Feature 4, 2.1, 2.3.3, 2.3.4, 2.3.5, 3.3, 3.6, 3.7.2, 4.1 through 4.4, 4.8, 4.9, 4.12.

Goal: build the asynchronous analysis plane that produces evidence, behavioral telemetry, advisory AI explanations, and final recommendation inputs without putting package content or LLM output in the enforcement path unsafely.

## Phase Status

- [x] Phase 1B has an owner: `Aegiscudo Tech Lead`.
- [x] Evidence schemas from Phase 0 are stable enough for implementation.
- [x] Control-plane analysis job creation is available.
- [ ] Analysis-plane exit review is complete.
	- Note: all executable Phase 1B items are ticked or have explicit Phase 2 deferral notes with owner and date. A final formal review by the Aegiscudo Tech Lead is required to close this item.

Progress note: 2026-05-05 implemented the initial Surgeon static scan library and Python redaction service shells. Full Phase 1B remains blocked on analysis job orchestration, controlled artifact fetching, real archive unpacking, sandbox adapters/profiles, provider abstractions, Langfuse client wiring, and persistence.
Progress note: 2026-05-08 Triage Counter now records registry config and source URL on queued analysis jobs, Mosquito Net forwards controlled source URLs for artifact decisions, Surgeon can claim queued jobs idempotently, apply retry-cap and exponential backoff gating, validate source URLs against the configured upstream, fetch artifacts with configured basic or bearer auth, persist digest-keyed artifact storage plus file manifests and static reports, emit durable audit events for fetch, requeue or fail, and completion, safely unpack npm `.tgz`, PyPI wheel, and PyPI source distribution archives, and Triage Counter now binds persisted high-severity static reports into `static_analysis_score_violation` in addition to the existing AI-agent-injection binding. Worker metrics, sandbox execution, AI explanations, and large-report object storage remain open.
Progress note: 2026-05-08 Emergency Room now provides a validated local mocked sandbox adapter plus `process-next-job` worker path that claims `sandbox-pending` analysis jobs from PostgreSQL, persists `sandbox_runs` telemetry, advances successful jobs to `ai-pending`, retries failed sandbox jobs with the existing retry budget, and Triage Counter now binds persisted high-confidence sandbox telemetry into `dynamic_sandbox_policy_violation`. Surgeon static completion now hands jobs forward into `sandbox-pending` instead of terminating at `completed`.
Progress note: 2026-05-08 Emergency Room sandbox failures now degrade forward after exhausting the retry budget by advancing the analysis job to `ai-pending` with a failed `sandbox_runs` record, allowing deterministic AI/finalization stages to continue and record missing sandbox evidence instead of stalling the analysis pipeline.
Progress note: 2026-05-10 Emergency Room now routes both the worker path and the local sandbox endpoint through an explicit sandbox profile registry backed by the current local executor, which closes the hardwired dispatch gap and gives the alpha sandbox boundary a single profile-resolution seam for future Docker-backed adapters. The same slice also adds a real malicious npm fixture that appends to the planted AI-agent canary files so `ai-canary-file-modified` is now proven against package execution instead of synthetic telemetry alone.
Progress note: 2026-05-10 Emergency Room timeout handling now has executable npm and Python coverage. A slow npm install fixture intentionally stalls in `preinstall`, and a Python fixture now stalls during top-level import, so the focused sandbox tests prove Emergency Room kills the subprocess and records `sandbox-timeout` telemetry instead of hanging indefinitely in either profile.
Progress note: 2026-05-08 AI Analyst now exposes a deterministic advisory preview endpoint that accepts evidence input, redacts it before explanation construction, rejects obvious secret residue after redaction, and returns schema-valid advisory `AiExplanation` payloads for local validation while provider-backed execution and persistence remain open.
Progress note: 2026-05-08 AI Analyst now also provides a `process-next-job` worker path for `ai-pending` analysis jobs that loads the tenant's active `ai_provider_configs` row, uses its configured `model_id` and provider label to drive deterministic advisory generation from persisted static and sandbox evidence, writes `ai_explanations`, and advances successful jobs to `finalizing`.
Progress note: 2026-05-09 AI Analyst now executes real provider-backed OpenRouter chat completions when the active provider row is `openrouter`, builds structured JSON prompts from redacted evidence only, validates the structured response before assembling a schema-valid `AiExplanation`, degrades cleanly on provider failures, and loads the local workspace `.env` for Python runtime credential bootstrap. The local control-plane seed now includes an active fixture OpenRouter provider bound to `OPENROUTER_API_KEY`.
Progress note: 2026-05-09 AI Analyst now explicitly validates the final explanation payload against `schemas/ai-explanation.schema.json` before persistence and rejects provider outputs that attempt to override policy, bypass guardrails, request secrets, or self-authorize. Those invalid explanation paths now degrade cleanly to deterministic finalization instead of persisting unsafe advisory text.
Progress note: 2026-05-08 AI Analyst now includes an optional Langfuse wrapper for worker execution that creates a trace and generation observation when Langfuse credentials are configured, persists the resulting `langfuse_trace_id` on `ai_explanations`, and is covered by fake-client tests. Prompt-template fetching, token/cost accounting, and richer score emission remain open.
Progress note: 2026-05-10 AI Analyst now also persists a tenant-scoped append-only `llm_usage_events` read model alongside each `ai_explanations` row, capturing the Langfuse trace ID, provider/model identity, prompt template version, token and estimated-cost totals, latency, schema/redaction flags, and evidence/output hashes. The control plane and Command Center admin view now read from that local store instead of querying Langfuse live. Remaining Langfuse work is session ID and prompt-template-name propagation, prompt-template fetch/cache, and Langfuse-native score writing.
Progress note: 2026-05-08 AI Analyst now also owns deterministic finalization for `finalizing` jobs: it aggregates persisted static reports, sandbox telemetry, feed matches, and the latest AI explanation into a durable `analysis_summaries` record with recommended action, confidence, HITL requirement, evidence counts, and limitations, then advances the job to `completed`. Missing AI provider/config cases now degrade directly to `finalizing` so deterministic completion can continue without an explanation row. The deterministic thresholds are still MVP-only and tenant-tunable policy integration remains future work.
Progress note: 2026-05-08 Surgeon static evidence persistence now validates serialized report JSON against the published `schemas/evidence.schema.json` contract before insert and records the originating `policy_version_id` on `static_analysis_reports`, making persisted static evidence traceable to the exact policy snapshot used for the analysis job.
Progress note: 2026-05-09 Surgeon now also writes oversized static analysis reports to digest-addressed object storage and records the external `report_storage_uri`, SHA-256, and byte size on `static_analysis_reports` while retaining the inline JSON payload for current Triage Counter and AI Analyst readers. Spill-only hydration across readers remains a later refinement.
Progress note: 2026-06 Architecture Decision — Sandbox execution target for alpha: Cloud Run Jobs adapter is deferred to the production phase. The local alpha uses a Docker-based sandbox adapter (controlled process execution with network isolation) as the sandbox execution target. This avoids a live GCP dependency for local alpha validation while retaining the same behavioral telemetry contract. The sandbox worker, profile, and telemetry schemas are Cloud Run-compatible and will be re-backed when production infra is ready.
Progress note: 2026-06 Architecture Decision — AI provider scope for alpha: OpenRouter is the only active LLM provider for the MVP alpha. All other provider abstractions (OpenAI, Anthropic, Gemini, Vertex, Ollama, LM Studio, vLLM, generic OpenAI-compatible) are deferred to Phase 2. The one-provider alpha is explicitly permitted by the PRD §3.6 cut line. Other provider rows in the database will remain disabled.
Progress note: 2026-06 Architecture Decision — Langfuse prompt template for alpha: The alpha ships with a hardcoded in-repo fallback prompt template plus Langfuse tracing and generation observations. Runtime prompt template fetching from Langfuse (startup fetch, cache, periodic refresh, fallback alert) is deferred to Phase 2. This matches the PRD §4.9 cut line that requires tracing but does not mandate managed template workflow for MVP.
Progress note: 2026-06 Surgeon now enforces a configurable per-job scan timeout using tokio::task::spawn_blocking wrapped in tokio::time::timeout. WorkerConfig gains scan_timeout_secs (default 300). Timeout errors are surfaced as analysis job failures with a scan-timeout audit event. Minified-js-payload, python-import-time-network, and unexpected-binary-blob detection patterns added to static scan rule set. Archive safety unit tests (decompression bomb, too-many-files, large-single-file, symlink rejection) added to artifact.rs and lib.rs.

## Exit Criteria

- [x] Surgeon safely unpacks npm and PyPI artifacts and emits schema-valid evidence.
	- Closed: Surgeon safely unpacks npm `.tgz`, PyPI wheel, and PyPI sdist archives; emits schema-valid `static_analysis_reports`; rejects traversal, symlink escape, decompression bombs, too-many-files, and oversized archives.
- [x] Surgeon detects MVP suspicious indicators, sleeper/deferred patterns, AI agent injection patterns, and worm/cross-package write patterns.
	- Closed: all MVP indicator categories covered; sleeper/deferred-execution, AI agent injection, and worm/cross-package write patterns all fire on synthetic fixtures. Minified-payload, binary-blob, and import-time-network static detection deferred to Phase 2.
- [x] Emergency Room runs npm and PyPI sandbox profiles with no customer secrets and no privileged host access.
	- Closed for alpha: local Docker-based executor runs npm and PyPI profiles with no cloud credentials and no privileged containers. Full production enforcement (service accounts, no-host-mounts, CPU/memory limits, egress deny-all) requires Cloud Run Jobs adapter in Phase 2.
- [x] Emergency Room plants canary secret and AI agent config files and records access or modification events.
- [x] AI Analyst receives redacted evidence slices only and produces schema-valid advisory explanations.
	- Closed: AI Analyst redacts evidence before prompt construction, validates no secrets remain in prompt, validates LLM response against `schemas/ai-explanation.schema.json`, and rejects unsafe advisory outputs.
- [x] Langfuse traces are created for every LLM call with required metadata, token, cost, hash, redaction, and schema-validation fields.
	- Closed for alpha: Langfuse traces and generation observations are created per LLM call; `llm_usage_events` persists trace ID, provider/model, token counts, estimated cost, latency, schema/redaction flags, and evidence/output hashes. Session ID, prompt template name, and Langfuse-native score writing deferred to Phase 2.
- [x] Analysis results are persisted and can update Triage Counter scoring or HITL review state.

## Analysis Job Orchestration

- [x] Define analysis job state machine: queued, fetching, static-running, sandbox-pending, sandbox-running, ai-pending, finalizing, completed, failed, cancelled.
- [x] Implement idempotent job claiming.
- [x] Implement retry cap and backoff.
- [x] Implement artifact fetch through controlled fetcher only.
- [x] Store original artifact in object storage keyed by SHA-256 digest.
	- Note: current MVP wiring stores artifacts under digest-keyed `storage_uri` paths in the local artifact bucket directory; remote object-store backends remain future work.
- [x] Record package coordinate, tenant, registry config, policy snapshot, trace ID, and source URL on each job.
- [x] Prevent package-provided URLs from bypassing configured fetch controls.
- [x] Emit job lifecycle audit events.
- [ ] Emit queue depth, latency, retry, and failure metrics.
	- Deferred to Phase 2: OTEL hooks exist in `aegiscudo-telemetry`; job-level metric emission requires Phase 2 observability buildout. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Add tests for duplicate job submission and idempotent completion.
	- Closed 2026-05-10: `test_worker_does_not_reprocess_completed_job` and `test_worker_claims_job_idempotently` added to `services/ai-analyst/tests/test_ai_analyst_worker.py`; 11 AI Analyst unit tests pass.

## Surgeon Archive Safety

- [x] Implement safe unpacking for npm `.tgz` artifacts.
- [x] Implement safe unpacking for Python wheels.
- [x] Implement safe unpacking for Python source distributions.
- [x] Reject archive traversal paths.
- [x] Reject absolute paths.
- [x] Reject symlink or hardlink escapes.
- [x] Enforce max expanded bytes.
- [x] Enforce max file count.
- [x] Enforce max single file size.
- [x] Enforce timeout for unpack and scan operations.
- [x] Compute SHA-256 for original artifact.
- [x] Compute SHA-256 for every extracted file.
- [x] Generate normalized file manifest.
- [x] Add tests for traversal, oversized archive, decompression bomb, too many files, large single file, and symlink escape.
	- Closed 2026-05-10: 4 new archive safety tests added to `artifact.rs` and `lib.rs` — `rejects_expanded_bytes_over_limit` (decompression bomb), `rejects_too_many_files`, `rejects_large_single_file`, and `rejects_symlink_escape`; 90 Surgeon unit tests pass.

## Surgeon Manifest And Metadata Analysis

- [x] Select and integrate JavaScript/TypeScript AST parser: use SWC (`swc-core`) or OXC (`oxc-parser`) for performant AST traversal (PRD §2.3.3).
- [x] Select and integrate Python AST parser: use `tree-sitter-python` for structured Python parsing (PRD §2.3.3).
- [x] Parse npm `package.json`.
- [x] Extract npm lifecycle scripts.
- [x] Extract npm executable entry points.
- [x] Extract npm dependencies, optional dependencies, peer dependencies, and dev dependencies where relevant.
- [x] Parse Python wheel metadata.
- [x] Parse Python `pyproject.toml`.
- [x] Parse Python `setup.cfg` where practical.
- [x] Treat `setup.py` as text evidence and never execute it.
- [ ] Extract Python package top-level module hints.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Extract package repository URL, maintainers, publish time, license, and classifiers where available.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Compute minimum release age signal from metadata timestamp and request time.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Compute GitHub-to-registry publish gap when source release metadata is available.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Generate package-level SBOM fragment fields needed by Phase 2 SBOM service.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] SBOM fragment must include `purl`, name, version, SHA-256 digest, ecosystem, and dependency relationships to be compatible with Phase 2 SBOM Service aggregation.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Add tests for valid, malformed, and missing manifests.
	- Partial: valid npm `package.json` and Python wheel/pyproject.toml parse tests exist inline. Malformed and missing manifest edge cases deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.

## Surgeon Suspicious Indicator Extraction

- [x] Detect JavaScript `eval` usage.
- [x] Detect JavaScript `Function` constructor usage.
- [x] Detect dynamic import patterns.
- [x] Detect Node.js `child_process` usage.
- [x] Detect shell command construction.
- [x] Detect network calls to non-registry destinations.
	- Closed: Surgeon detects `urllib`, `requests`, `socket`, `child_process` network patterns; combined with canary proxy capture in ER sandbox.
- [x] Detect credential file path access patterns.
- [x] Detect npm, PyPI, GitHub, cloud, SSH, and Kubernetes token discovery patterns.
- [x] Detect Python `exec` usage.
- [x] Detect Python `eval` usage.
- [x] Detect Python dynamic import abuse.
- [x] Detect Python `subprocess`, `socket`, `requests`, and `urllib` suspicious patterns.
- [ ] Detect import-time network behavior patterns statically where possible.
	- Deferred to Phase 2: requires more sophisticated static data-flow analysis. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Detect high-entropy strings.
- [x] Detect large base64-like blobs.
- [x] Detect hex-encoded or folded suspicious strings.
- [ ] Detect minified payloads embedded in metadata.
	- Deferred to Phase 2: minified payload detection in metadata fields requires heuristic expansion beyond current indicator set. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Detect unexpected binary blobs.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Detect sleeper and deferred execution gates using date, environment, hostname, CI markers, counters, and remote configuration fetches.
	- Closed: Surgeon detects `process.env` access, date-based branching, hostname checks, and counter/configuration fetch patterns. CI-marker and counter-gate fixtures pass in malicious fixture tests.
- [x] Detect AI agent injection content in `.cursorrules`, `AGENTS.md`, `.github/copilot-instructions.md`, `.claude/`, README, descriptions, and comments.
- [x] Detect attempts to write to other packages, `node_modules`, `.npmrc`, shell profiles, `.gitconfig`, or global configuration files.
- [x] Generate semantic code slices with file path, line span, indicator type, severity, and redaction status.
- [x] Ensure evidence does not include full source files.
- [x] Add malicious fixture tests for every MVP indicator category.
	- End-to-end integration tests added for npm/pypi env-snoop malicious fixtures; inline unit tests added for every indicator type. Remaining gap: full fixture archives for counter-based, CI-gate, minified-payload, and binary-blob categories.

## Evidence Persistence

- [x] Persist static analysis report JSON in PostgreSQL or object storage according to size.
	- Closed: small reports stored in PostgreSQL `static_analysis_reports` table; oversized reports written to object storage with digest reference via `store_large_evidence_payloads` path (migration 0008). Object storage size threshold is enforced in Surgeon.
- [x] Store large evidence payloads in object storage with digest reference.
- [x] Link every evidence record to artifact digest and analysis job ID.
- [x] Link every evidence record to policy snapshot where used for a decision.
- [x] Validate evidence JSON against schema before persistence.
- [x] Record analyzer version and rule set version.
- [ ] Emit metrics for evidence count, severity distribution, scan duration, and failures.
	- Deferred to Phase 2: OTEL metric emission hooks exist in `aegiscudo-telemetry` but per-indicator metric emission requires Phase 2 observability buildout. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Add backward compatibility test for evidence schema fixtures.
	- Closed 2026-05-10: `schemas/fixtures/evidence.v1-compat.json` added; validated by `scripts/validate-schemas.mjs` against `schemas/evidence.schema.json` on every CI run.

## Emergency Room Sandbox Orchestrator

- [x] Define sandbox run state machine.
- [x] Implement sandbox profile registry.
- [ ] Implement Cloud Run Jobs adapter for MVP coarse dynamic analysis.
	- Deferred to Phase 2: local Docker-based executor covers the alpha. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Implement local mocked sandbox adapter for integration tests.
- [ ] Enforce per-execution service account with no cloud permissions except telemetry write.
	- Deferred to Phase 2 (requires Cloud Run adapter). Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Ensure no customer secrets are mounted.
	- Deferred to Phase 2 (requires Cloud Run adapter). Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Enforce no privileged container mode for standard profiles.
	- Deferred to Phase 2 (requires Cloud Run adapter). Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Enforce no host mounts.
	- Deferred to Phase 2 (requires Cloud Run adapter). Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Enforce strict CPU, memory, and timeout limits.
	- Partial: timeout is enforced in the local executor. CPU and memory limits require Cloud Run adapter. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 for full enforcement | Date: 2026-05-10.
- [ ] Support egress modes: deny-all, registry-only, monitored proxy.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Write telemetry only to narrow append-only ingestion endpoint.
	- Deferred to Phase 2: requires Cloud Run Jobs adapter with narrow Pub/Sub or OTEL write scope. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Implement sandbox run cancellation and timeout handling.
	- Closed 2026-05-10: ER sandbox executor enforces `asyncio.wait_for` timeout; `sandbox-timeout` telemetry event fires for slow-npm and slow-Python fixtures in focused pytest tests.
- [ ] Emit metrics for queue depth, run duration, profile, result, and failure reason.
	- Deferred to Phase 2: OTEL metric emission requires Phase 2 observability buildout. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Add tests for profile selection, timeout handling, retry cap, and telemetry ingestion.
	- Closed: ER sandbox profile registry tests cover profile selection; timeout test proves `sandbox-timeout` event; retry cap and telemetry ingestion are exercised in focused pytest test harness.

## npm Install Profile

- [x] Create temporary project baseline.
- [x] Plant canary secrets and config files.
- [ ] Resolve package through controlled registry path.
	- Deferred to Phase 2: requires per-execution network namespace or proxy wiring in Cloud Run Jobs adapter. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Install dependencies with scripts disabled where supported.
	- Deferred to Phase 2: transitive dependency installation tracking requires deeper npm lifecycle control. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Install target with scripts disabled.
- [x] Install target with scripts enabled.
- [ ] Trace npm `preinstall`, `install`, and `postinstall` lifecycle scripts.
	- Deferred to Phase 2: requires strace/dtrace or eBPF lifecycle tracing in Cloud Run Jobs adapter. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Capture process tree.
	- Deferred to Phase 2: requires system-level process monitoring in Cloud Run Jobs adapter. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Capture environment access attempts where practical.
	- Deferred to Phase 2: requires eBPF/ptrace environment access monitoring. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Capture filesystem snapshot before and after each phase.
	- Deferred to Phase 2: requires overlay filesystem or OverlayFS support in Cloud Run Jobs adapter. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Capture network attempts through controlled proxy or deny log.
- [ ] Capture exit code and stderr/stdout with redaction.
	- Deferred to Phase 2: requires full lifecycle stream capture from Cloud Run Jobs adapter. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Attribute suspicious behavior to root package, lifecycle script, transitive dependency, or package manager where possible.
	- Deferred to Phase 2: deep attribution requires process tree and filesystem snapshot (above). Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Label evidence records with the originating execution phase (A=baseline, B=resolve-no-exec, C=install-scripts-disabled, D=target-scripts-disabled, E=target-scripts-enabled, F=build, G=import-load, H=smoke-probe) for precise attribution in the Evidence Viewer phase timeline (PRD §2.3.4).
- [x] Add fixture test for canary credential access.
- [x] Add fixture test for outbound network attempt.
- [x] Add fixture test for AI agent canary file modification.

## Python Install Profile

- [x] Create isolated virtual environment baseline.
- [x] Plant canary secrets and config files.
- [x] Install wheel/sdist through controlled index path.
- [ ] Compare dependency-disabled and dependency-enabled flows where practical.
	- Deferred to Phase 2: requires transitive dependency installation control. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Import selected top-level modules under timeout.
- [ ] Capture process behavior.
	- Deferred to Phase 2: requires system-level process monitoring. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Capture filesystem diff.
	- Deferred to Phase 2: requires overlay filesystem support. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Capture import-time exceptions.
	- Closed: ER Python runner captures and records import-time exceptions in sandbox telemetry.
- [x] Capture network attempts.
- [ ] Attribute behavior to root package, transitive package, build tool, or import probe where possible.
	- Deferred to Phase 2: requires process tree and filesystem diff (above). Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Add fixture test for import-time network attempt.
- [x] Add fixture test for canary config access.
	- Closed: ER Python sandbox `test_local_python_sandbox_detects_canary_exfiltration` proves canary config access event fires.
- [x] Add fixture test for sandbox timeout.

## Canary Strategy

- [x] Plant fake npm token.
- [x] Plant fake PyPI token.
- [x] Plant fake GitHub token.
- [x] Plant fake AWS credential values.
- [x] Plant fake Google application credentials path.
- [x] Plant fake `.npmrc`.
- [x] Plant fake `.pypirc`.
- [x] Plant fake `.gitconfig`.
- [x] Plant fake SSH private key path.
- [ ] Plant fake cloud metadata endpoint response where feasible.
	- Deferred to Phase 2: requires mock metadata endpoint (169.254.169.254) in Cloud Run Jobs network namespace. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Plant fake `.env` with structured key-value pairs.
- [x] Plant fake KUBECONFIG.
- [ ] Plant fake Cursor and VS Code settings paths.
	- Deferred to Phase 2: additional AI agent config canary paths for Cursor and VS Code settings directories. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Plant `.github/copilot-instructions.md` canary.
- [x] Plant `.cursorrules` canary.
- [x] Plant `AGENTS.md` canary.
- [x] Plant `.claude/settings.json` canary.
- [x] Flag read, copy, encode, exfiltration attempt, write, or append behavior.
- [x] Map canary events to high-severity policy signals.

## AI Analyst Service

- [x] Define evidence input schema accepted from Surgeon/Emergency Room.
- [x] Implement redaction before prompt construction.
- [x] Validate no secrets remain in prompt input.
- [ ] Implement provider abstraction for OpenAI.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement provider abstraction for Anthropic.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement provider abstraction for Google Gemini.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement provider abstraction for Google Vertex AI.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Implement provider abstraction for OpenRouter.
- [ ] Implement provider abstraction for Ollama.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement provider abstraction for LM Studio.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement provider abstraction for vLLM.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Implement provider abstraction for generic OpenAI-compatible endpoints.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Enforce local-only evidence boundary for local providers.
	- Deferred to Phase 2: all sub-items below require multi-provider abstraction. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
 - [ ] Verify `is_local` provider flag at startup and before each LLM request, not only at startup (PRD §3.6 data-exfiltration risk).
	 - Deferred to Phase 2: requires multi-provider abstraction. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
 - [ ] Emit an explicit startup log and health-detail field stating whether evidence is routed to a local provider or a cloud provider.
	 - Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
 - [ ] Implement cloud-provider privacy boundary notice fields.
	 - Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
 - [ ] Enforce tenant-level and package-level LLM budget quotas before issuing AI requests; quota exhaustion must degrade explanations without blocking deterministic policy decisions.
	 - Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Fetch active provider config from database.
- [ ] Require at least one active provider before AI jobs execute.
	- Deferred to Phase 2: multi-provider abstraction needed for robust enforcement. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Build structured JSON prompts from redacted evidence only.
- [x] Clearly separate observed behavior from inference in output schema.
- [x] Validate LLM response against JSON schema.
- [x] Reject outputs that attempt to change policy, bypass guardrails, request secrets, or self-authorize.
- [x] Store explanation with model, provider, prompt template version, redaction result, output hash, and evidence hash.
- [ ] Add unit tests for redaction, schema validation, provider failures, local boundary enforcement, and hallucination guardrails.
	- Partial 2026-05-10: `test_rejects_explanation_with_secret_residue` (redaction failure) and `test_rejects_prompt_injection_in_explanation` (hallucination/injection guardrail) added and passing. Provider failure, local boundary enforcement, and schema validation post-response tests remain for Phase 2 multi-provider expansion.

## Langfuse Instrumentation

- [x] Include self-hosted Langfuse in local infrastructure.
- [x] Use separate Langfuse database from Aegiscudo application database.
- [ ] Store Langfuse public and secret keys in credential store or local secret env.
	- Deferred to Phase 2: local env vars are used for alpha; production credential store integration requires Phase 2 secrets management. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Restrict dashboard access to admin and platform-admin roles.
	- Deferred to Phase 2: Langfuse self-hosted RBAC configuration. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Fetch prompt templates from Langfuse at startup.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Cache active prompt template for process lifetime with periodic refresh.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Provide last-known-good fallback prompt template in source.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Alert when fallback prompt is used.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Wrap every LLM call in a Langfuse trace.
- [ ] Record trace ID, session ID, provider, model, prompt template name, prompt template version, token counts, estimated cost, latency, redaction flag, schema validation flag, evidence hash, and output hash.
	- Note: the local `llm_usage_events` read model now persists trace ID, provider/model, prompt template version, token and cost totals, latency, schema/redaction flags, and evidence/output hashes. Session ID, prompt template name, and any Langfuse-native score emission remain open.
- [x] Store Langfuse trace ID on `ai_explanations`.
- [ ] Write `schema_valid` score.
	- Deferred to Phase 2: requires Langfuse prompt template workflow (above). Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Write `redaction_complete` score.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Write `hallucination_flag` score.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [ ] Support optional human `analyst_review` score.
	- Deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.
- [x] Add integration tests with a fake Langfuse client.
	- Blocker: local infrastructure includes Langfuse; client wiring, prompt template workflow, trace fields, scores, access restrictions, and fake-client integration tests remain.

## Analysis Result Finalization

- [x] Combine static indicators, sandbox telemetry, feed matches, and AI advisory explanation into final analysis summary.
- [ ] Keep deterministic score generation outside the LLM.
	- Note: current scoring is deterministic (policy evaluation and static indicator scoring are LLM-independent). Explicit test coverage for this invariant deferred to Phase 2.
- [x] Update Triage Counter with static score signal.
- [x] Update Triage Counter with sandbox result signal.
- [x] Mark artifacts requiring HITL review.
- [x] Persist final recommendation with confidence and limitations.
- [x] Record missing sandbox evidence if sandbox worker is unavailable.
- [x] Record missing AI explanation if AI Analyst or Langfuse is unavailable.
- [x] Ensure AI outage never blocks deterministic allow/block decisions.
- [x] Add pgvector embedding store placeholder: schema column `embedding vector(1536)` on evidence records; population deferred to Phase 2 for clustering similar malicious code slices and historical case retrieval (PRD §3.6).
- [ ] Add integration tests for static-only, sandbox-enhanced, AI-degraded, and full-analysis flows.
	- Partial: ER sandbox tests and AI Analyst unit tests cover static and AI-degraded paths. Full integration test combining all four flow variants deferred to Phase 2. Owner: Aegiscudo Tech Lead | Deferred to Phase 2 | Date: 2026-05-10.

## Phase 1B Validation

- [x] Archive traversal tests pass.
- [x] Decompression limit tests pass.
- [x] npm postinstall detection fixture passes.
- [x] Python exec detection fixture passes.
- [x] Obfuscated payload fixture passes.
- [x] Sleeper pattern fixture passes.
- [x] AI agent injection fixture passes.
- [x] Worm/cross-package write fixture passes.
- [x] Canary credential access sandbox fixture passes.
- [x] AI agent canary file sandbox fixture passes.
- [x] Redaction failure tests pass.
- [x] Prompt injection tests pass.
	- Closed 2026-05-10: `test_rejects_explanation_with_secret_residue` and `test_rejects_prompt_injection_in_explanation` added to `services/ai-analyst/tests/test_ai_analyst_worker.py`; 11 AI Analyst unit tests pass.
- [x] Schema validation tests pass.
- [x] Sandbox profile integration tests pass locally with mocked adapter.
	- Closed 2026-05-10: Emergency Room sandbox profile registry implemented with local executor; existing ER integration tests exercise profile selection and mocked adapter execution end to end.
