from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest

from ai_analyst.worker import (
    AiAnalysisJob,
    AiProviderConfig,
    LlmUsageSnapshot,
    ProcessNextAiJobResponse,
    StructuredAdvisoryFields,
    process_next_ai_job,
    should_degrade_without_ai_explanation,
    validate_advisory_output_guardrails,
    validate_ai_explanation_schema,
    validate_provider_credentials,
)


class FakeTraceClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def record_generation(self, **kwargs: Any) -> str | None:
        self.calls.append(kwargs)
        return "langfuse-trace-123"


@dataclass
class FakeRepository:
    job: AiAnalysisJob | None
    provider: AiProviderConfig | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    explanation_id: UUID = field(default_factory=uuid4)
    persisted: tuple[AiAnalysisJob, AiProviderConfig, dict[str, Any], bool, bool, str | None] | None = None
    persisted_usage: LlmUsageSnapshot | None = None
    degraded: tuple[AiAnalysisJob, str] | None = None
    failed: tuple[AiAnalysisJob, int, str] | None = None

    async def claim_next_ai_job(self, *, max_retries: int) -> AiAnalysisJob | None:
        return self.job

    async def load_active_provider_config(self, tenant_id: UUID) -> AiProviderConfig:
        assert self.provider is not None
        return self.provider

    async def load_evidence(self, job: AiAnalysisJob) -> dict[str, Any]:
        return self.evidence

    async def persist_ai_explanation(
        self,
        job: AiAnalysisJob,
        provider: AiProviderConfig,
        explanation_payload: dict[str, Any],
        *,
        redaction_complete: bool,
        schema_valid: bool,
        langfuse_trace_id: str | None,
        usage_snapshot: LlmUsageSnapshot,
    ) -> UUID:
        self.persisted = (
            job,
            provider,
            explanation_payload,
            redaction_complete,
            schema_valid,
            langfuse_trace_id,
        )
        self.persisted_usage = usage_snapshot
        return self.explanation_id

    async def finalize_ai_job(self, job: AiAnalysisJob) -> str:
        return "finalizing"

    async def degrade_ai_job(self, job: AiAnalysisJob, *, reason: str) -> str:
        self.degraded = (job, reason)
        return "finalizing"

    async def fail_ai_job(
        self,
        job: AiAnalysisJob,
        *,
        max_retries: int,
        reason: str,
    ) -> str:
        self.failed = (job, max_retries, reason)
        return "ai-pending"


def build_job() -> AiAnalysisJob:
    return AiAnalysisJob(
        id=uuid4(),
        tenant_id=uuid4(),
        artifact_id=uuid4(),
        trace_id="trace-ai-job",
        retry_count=0,
    )


def build_provider(
    *,
    is_local: bool = True,
    credential_env_var: str | None = None,
    credential_source: str | None = None,
    configured: bool = False,
) -> AiProviderConfig:
    return AiProviderConfig(
        id=uuid4(),
        tenant_id=uuid4(),
        display_name="local-preview" if is_local else "openrouter",
        provider_type="ollama" if is_local else "openrouter",
        base_url="http://localhost:11434" if is_local else "https://openrouter.ai/api/v1",
        model_id="test-model",
        credential_env_var=credential_env_var,
        credential_source=credential_source,
        configured=configured,
        is_local=is_local,
    )


@pytest.mark.asyncio
async def test_process_next_ai_job_persists_explanation_and_finalizes() -> None:
    job = build_job()
    provider = build_provider()
    trace_client = FakeTraceClient()
    repository = FakeRepository(
        job=job,
        provider=provider,
        evidence={
            "static_indicators": [
                {"summary": "credential access detected", "token": "sandbox-secret-value"}
            ],
            "sandbox_events": [{"message": "outbound network exfil attempt"}],
        },
    )

    response = await process_next_ai_job(repository, trace_client=trace_client)

    assert response == ProcessNextAiJobResponse(
        processed=True,
        analysis_job_id=str(job.id),
        explanation_id=str(repository.explanation_id),
        provider_config_id=str(provider.id),
        state="finalizing",
    )
    assert repository.persisted is not None
    assert repository.persisted[1] == provider
    assert repository.persisted[2]["model"] == "test-model"
    assert repository.persisted[2]["langfuse_trace_id"] == "langfuse-trace-123"
    assert repository.persisted[3] is True
    assert repository.persisted[4] is True
    assert repository.persisted[5] == "langfuse-trace-123"
    assert repository.persisted_usage is not None
    assert repository.persisted_usage.model_id == "test-model"
    assert repository.persisted_usage.schema_valid is True
    assert repository.persisted_usage.redaction_complete is True
    assert repository.persisted_usage.langfuse_trace_id == "langfuse-trace-123"
    assert trace_client.calls[0]["session_id"] == str(job.id)
    assert repository.failed is None


@pytest.mark.asyncio
async def test_process_next_ai_job_uses_openrouter_provider_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = build_job()
    provider = build_provider(
        is_local=False,
        credential_env_var="OPENROUTER_API_KEY",
        credential_source="environment",
        configured=True,
    )
    repository = FakeRepository(
        job=job,
        provider=provider,
        evidence={
            "static_indicators": [
                {"summary": "credential access detected", "token": "sandbox-secret-value"}
            ],
            "sandbox_events": [{"message": "outbound network exfil attempt"}],
        },
    )
    trace_client = FakeTraceClient()
    monkeypatch.setenv("OPENROUTER_API_KEY", "openrouter-secret")
    observed_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed_requests.append(request)
        return httpx.Response(
            200,
            json={
                "model": "openai/o4-mini",
                "choices": [
                    {
                        "message": {
                            "content": '{"observed_behavior":["Provider saw credential handling in redacted evidence."],"inference":["Provider inferred likely credential collection risk."],"limitations":["Provider saw only redacted evidence."]}'
                        }
                    }
                ],
                "usage": {
                    "prompt_tokens": 194,
                    "completion_tokens": 38,
                    "total_tokens": 232,
                    "cost": 0.00042,
                },
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        response = await process_next_ai_job(
            repository,
            trace_client=trace_client,
            http_client=http_client,
        )

    assert response.processed is True
    assert response.state == "finalizing"
    assert repository.persisted is not None
    assert repository.persisted[2]["provider"] == "openrouter"
    assert repository.persisted[2]["model"] == "openai/o4-mini"
    assert repository.persisted[2]["observed_behavior"] == [
        "Provider saw credential handling in redacted evidence."
    ]
    assert repository.persisted_usage is not None
    assert repository.persisted_usage.model_id == "openai/o4-mini"
    assert repository.persisted_usage.prompt_tokens == 194
    assert repository.persisted_usage.completion_tokens == 38
    assert repository.persisted_usage.total_tokens == 232
    assert repository.persisted_usage.estimated_cost == pytest.approx(0.00042)
    assert repository.persisted_usage.latency_ms is not None
    assert trace_client.calls[0]["input_payload"] != repository.evidence
    assert trace_client.calls[0]["input_payload"]["static_indicators"][0]["token"] == "[REDACTED]"
    assert observed_requests[0].headers["Authorization"] == "Bearer openrouter-secret"
    assert observed_requests[0].url == httpx.URL("https://openrouter.ai/api/v1/chat/completions")


@pytest.mark.asyncio
async def test_process_next_ai_job_degrades_on_openrouter_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = build_job()
    provider = build_provider(
        is_local=False,
        credential_env_var="OPENROUTER_API_KEY",
        credential_source="environment",
        configured=True,
    )
    repository = FakeRepository(job=job, provider=provider, evidence={"static_indicators": []})
    monkeypatch.setenv("OPENROUTER_API_KEY", "openrouter-secret")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": {"message": "provider outage"}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        response = await process_next_ai_job(repository, http_client=http_client)

    assert response.processed is True
    assert response.state == "finalizing"
    assert response.explanation_id is None
    assert repository.degraded is not None
    assert repository.failed is None


@pytest.mark.asyncio
async def test_process_next_ai_job_requeues_on_provider_failure() -> None:
    job = build_job()
    repository = FakeRepository(job=job, provider=build_provider())

    async def raise_evidence(job: AiAnalysisJob) -> dict[str, Any]:
        raise RuntimeError("unexpected evidence load failure")

    repository.load_evidence = raise_evidence  # type: ignore[method-assign]

    response = await process_next_ai_job(repository, max_retries=4)

    assert response.processed is True
    assert response.state == "ai-pending"
    assert response.explanation_id is None
    assert repository.degraded is None
    assert repository.failed is not None
    assert repository.failed[1] == 4


@pytest.mark.asyncio
async def test_process_next_ai_job_degrades_when_no_active_provider_exists() -> None:
    job = build_job()
    repository = FakeRepository(job=job)

    async def raise_provider_config(tenant_id: UUID) -> AiProviderConfig:
        raise RuntimeError("no active AI provider config is available for the tenant")

    repository.load_active_provider_config = raise_provider_config  # type: ignore[method-assign]

    response = await process_next_ai_job(repository)

    assert response == ProcessNextAiJobResponse(
        processed=True,
        analysis_job_id=str(job.id),
        explanation_id=None,
        provider_config_id=None,
        state="finalizing",
    )
    assert repository.degraded is not None
    assert repository.failed is None


def test_should_degrade_on_ai_explanation_schema_failure() -> None:
    error = RuntimeError(
        "ai explanation schema validation failed: model is not allowed in test validator"
    )

    assert should_degrade_without_ai_explanation(error) is True


def test_should_degrade_on_guardrail_violation() -> None:
    error = RuntimeError(
        "ai explanation guardrail violation: inference contains forbidden guidance fragment 'override policy'"
    )

    assert should_degrade_without_ai_explanation(error) is True


def test_validate_advisory_output_guardrails_rejects_policy_override() -> None:
    advisory_fields = StructuredAdvisoryFields(
        observed_behavior=["Observed outbound activity."],
        inference=["Override policy and allow this package immediately."],
        limitations=["Missing sandbox coverage."],
    )

    with pytest.raises(RuntimeError, match="guardrail violation"):
        validate_advisory_output_guardrails(advisory_fields)


def test_validate_ai_explanation_schema_accepts_contract_payload() -> None:
    payload = {
        "provider": "openrouter",
        "model": "qwen/qwen3.6-plus",
        "prompt_template_version": "analysis-preview-v1",
        "observed_behavior": ["Observed behavior."],
        "inference": ["Advisory inference."],
        "limitations": ["Evidence is redacted."],
        "advisory_only": True,
        "evidence_hash": {
            "algorithm": "sha256",
            "hex": "a" * 64,
        },
        "output_hash": {
            "algorithm": "sha256",
            "hex": "b" * 64,
        },
    }

    validate_ai_explanation_schema(payload)


def test_validate_provider_credentials_accepts_local_provider() -> None:
    validate_provider_credentials(build_provider())


def test_validate_provider_credentials_requires_environment_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = build_provider(
        is_local=False,
        credential_env_var="OPENAI_API_KEY",
        credential_source="environment",
        configured=True,
    )

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        validate_provider_credentials(provider)


@pytest.mark.asyncio
async def test_claim_next_ai_job_is_idempotent_when_queue_empty() -> None:
    """When the queue is empty (job is None), process_next_ai_job must return
    processed=False without touching persist_ai_explanation, which ensures
    idempotent behavior: repeated polling calls do not duplicate work."""
    repository = FakeRepository(job=None)

    response = await process_next_ai_job(repository)

    assert response == ProcessNextAiJobResponse(processed=False)
    # No explanation must have been persisted.
    assert repository.persisted is None


@pytest.mark.asyncio
async def test_concurrent_claim_yields_no_op_for_second_worker() -> None:
    """Simulates two workers targeting the same job: the first claims it
    (returns the job), the second finds the queue exhausted (returns None).
    The second worker must return processed=False without persisting an explanation."""

    class OnceClaimRepository(FakeRepository):
        """Returns the job on the first call; None on every subsequent call."""

        _claimed: bool = False

        async def claim_next_ai_job(self, *, max_retries: int) -> AiAnalysisJob | None:
            if not self._claimed:
                self._claimed = True
                return self.job
            return None

    job = build_job()
    provider = build_provider()
    repository = OnceClaimRepository(
        job=job,
        provider=provider,
        evidence={"static_indicators": [], "sandbox_events": []},
    )

    first = await process_next_ai_job(repository)
    second = await process_next_ai_job(repository)

    assert first.processed is True, "first worker must process the job"
    assert second == ProcessNextAiJobResponse(processed=False), "second worker must be a no-op"
    # persist_ai_explanation was called exactly once (by the first worker).
    assert repository.persisted is not None