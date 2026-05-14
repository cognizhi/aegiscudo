# LLM-As-Judge Langfuse Evaluation

Source PRD sections: [3.6 AI Stack](../prd/aegiescudo-prd.md) and [4.9 LLM Observability and Evaluation](../prd/aegiescudo-prd.md).

## Scope

Phase 2 may evaluate LLM-as-judge for explanation-quality measurement. It must not become a request-time enforcement input.

The only blocking gate LLM-as-judge may control is release quality for AI Analyst prompts, models, or explanation workflows. It must never be used as the sole authority for package allow or block decisions.

## Dataset Requirements

The evaluation dataset must be built from manually reviewed package analyses and stored inside the Aegiscudo trust boundary.

Minimum dataset requirements before any blocking quality gate is considered:

- at least 240 manually reviewed analyses
- at least 50 reviewed analyses each for npm, PyPI, Cargo, and Maven
- at least 40 known-malicious or clearly policy-violating cases
- at least 40 benign or allow-with-warning cases
- at least 40 ambiguous or HITL-worthy cases
- adversarial coverage for prompt injection, obfuscated network destinations, misleading README text, and empty or partial evidence cases

Each dataset row should capture:

- redacted static evidence slice
- redacted sandbox evidence slice when present
- AI Analyst output under test
- human-reviewed expected quality labels
- final policy outcome and analyst rationale
- traceability back to the originating analysis job and package coordinate

## Langfuse Evaluation Flow

1. Instrument every AI Analyst call with the PRD-mandated Langfuse trace fields.
2. Continue writing deterministic online scores for `schema_valid`, `redaction_complete`, and `hallucination_flag`.
3. Run judge evaluations offline or in a post-processing job against the golden dataset, not inline with request-time analysis.
4. Store judge scores back into Langfuse traces or linked experiment runs so prompt and model versions are comparable over time.
5. Review low-scoring or disagreeing samples manually before promoting a new prompt template or model.

The judge prompt should score explanation quality dimensions that humans can audit:

- evidence groundedness
- explanation completeness
- action consistency with deterministic evidence
- clarity for analyst review

## Acceptance Criteria For A Blocking Quality Gate

Before LLM-as-judge is allowed to block promotion of a prompt, model, or explanation pipeline change, all of the following must hold for two consecutive evaluation runs:

- `schema_valid` pass rate is 100 percent
- `redaction_complete` pass rate is 100 percent
- `hallucination_flag` clean rate is at least 99 percent
- judge agreement with human review is at least 0.90 overall
- judge agreement with human review is at least 0.85 for each supported ecosystem
- false-pass rate on known-bad explanations is at most 1 percent
- sample count per run remains at or above the minimum dataset thresholds
- no severe regression is observed relative to the currently deployed prompt and model pair

If any threshold fails, the evaluation remains advisory and cannot block a rollout.

## Operating Rules

- Judge experiments must use redacted evidence only.
- Langfuse remains self-hosted and must not share the primary Aegiscudo application database.
- Prompt versions under evaluation must be explicit and reproducible.
- Analysts must be able to inspect disagreement examples before any rollout decision is made.

## Phase 2 Decision

Phase 2 should implement the dataset shape, Langfuse trace plumbing, and offline experiment workflow first. Keep LLM-as-judge advisory until the acceptance criteria above are satisfied and reviewed by platform engineering plus security operations.
