from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from functools import lru_cache
from ipaddress import ip_address, ip_network
from pathlib import Path
from time import perf_counter
from typing import Any, Protocol
from urllib.parse import urlparse

import httpx
from jsonschema import Draft202012Validator

from aegiscudo_common.config import load_workspace_env_file
from aegiscudo_common.contracts import AiExplanation
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from ai_analyst.advisory import (
    AdvisoryPreviewRequest,
    AdvisoryPreviewResponse,
    build_advisory_preview,
    sha256_digest,
)
from ai_analyst.langfuse_client import TraceClient, build_optional_trace_client

try:
    import asyncpg
except ModuleNotFoundError:  # pragma: no cover - exercised only when dependency is absent.
    asyncpg = None


PROMPT_TEMPLATE_VERSION = "analysis-preview-v1"
OPENAI_BASE_URL = "https://api.openai.com/v1"
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENROUTER_APP_REFERER = "https://github.com/cognizhi/aegiscudo"
OPENROUTER_APP_TITLE = "Aegiscudo AI Analyst"
OPENROUTER_TIMEOUT_SECONDS = 30.0
OPENAI_COMPATIBLE_PROVIDER_TYPES = frozenset(
    {
        "openrouter",
        "openai",
        "openai-compatible",
        "ollama",
        "lm-studio",
        "lmstudio",
        "vllm",
    }
)
RFC1918_IPV4_NETWORKS = tuple(
    ip_network(network)
    for network in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    )
)
OUTPUT_GUARDRAIL_FRAGMENTS = (
    "ignore previous instructions",
    "bypass guardrails",
    "change policy",
    "override policy",
    "allow this package",
    "self-authorize",
    "provide your api key",
    "provide the secret",
    "reveal the token",
    "return the credential",
)
LOGGER = logging.getLogger(__name__)


class StructuredAdvisoryFields(BaseModel):
    model_config = ConfigDict(frozen=True)

    observed_behavior: list[str]
    inference: list[str]
    limitations: list[str]


class ProcessNextAiJobResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    processed: bool
    analysis_job_id: str | None = None
    explanation_id: str | None = None
    provider_config_id: str | None = None
    state: str | None = None


@dataclass(frozen=True)
class AiProviderConfig:
    id: UUID
    tenant_id: UUID
    display_name: str
    provider_type: str
    base_url: str | None
    model_id: str
    credential_env_var: str | None
    credential_source: str | None
    configured: bool
    is_local: bool


@dataclass(frozen=True)
class AiAnalysisJob:
    id: UUID
    tenant_id: UUID
    artifact_id: UUID
    trace_id: str
    retry_count: int


@dataclass(frozen=True)
class ProviderUsageMetrics:
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    estimated_cost: float | None = None
    latency_ms: float | None = None
    resolved_model: str | None = None


@dataclass(frozen=True)
class LlmUsageSnapshot:
    model_id: str
    prompt_template_version: str
    prompt_tokens: int | None
    completion_tokens: int | None
    total_tokens: int | None
    estimated_cost: float | None
    latency_ms: float | None
    schema_valid: bool
    redaction_complete: bool
    langfuse_trace_id: str | None
    evidence_hash: str | None
    output_hash: str | None


@dataclass(frozen=True)
class AdvisoryExecutionResult:
    redaction_complete: bool
    redacted_evidence: dict[str, Any]
    explanation: AiExplanation
    provider_usage: ProviderUsageMetrics


@dataclass(frozen=True)
class OpenRouterAdvisoryResult:
    advisory_fields: StructuredAdvisoryFields
    provider_usage: ProviderUsageMetrics


class AiJobRepository(Protocol):
    async def claim_next_ai_job(self, *, max_retries: int) -> AiAnalysisJob | None: ...

    async def load_active_provider_config(self, tenant_id: UUID) -> AiProviderConfig: ...

    async def load_evidence(self, job: AiAnalysisJob) -> dict[str, Any]: ...

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
    ) -> UUID: ...

    async def finalize_ai_job(self, job: AiAnalysisJob) -> str: ...

    async def degrade_ai_job(self, job: AiAnalysisJob, *, reason: str) -> str: ...

    async def fail_ai_job(
        self,
        job: AiAnalysisJob,
        *,
        max_retries: int,
        reason: str,
    ) -> str: ...


class PostgresAiJobRepository:
    def __init__(self, pool: Any) -> None:
        self._pool = pool

    async def claim_next_ai_job(self, *, max_retries: int) -> AiAnalysisJob | None:
        row = await self._pool.fetchrow(
            """
            WITH candidate AS (
              SELECT id
              FROM analysis_jobs
              WHERE state = 'ai-pending'::analysis_job_state
                AND artifact_id IS NOT NULL
                AND retry_count < $1
                AND (
                  retry_count = 0
                  OR updated_at <= now()
                      - make_interval(
                          secs => LEAST(
                            300,
                            CAST(power(2::numeric, GREATEST(retry_count - 1, 0)) AS integer)
                          )
                        )
                )
              ORDER BY created_at ASC
              FOR UPDATE SKIP LOCKED
              LIMIT 1
            )
            UPDATE analysis_jobs AS jobs
            SET updated_at = now()
            FROM candidate
            WHERE jobs.id = candidate.id
            RETURNING jobs.id,
                      jobs.tenant_id,
                      jobs.artifact_id,
                      jobs.trace_id,
                      jobs.retry_count
            """,
            max_retries,
        )
        if row is None:
            return None
        return AiAnalysisJob(
            id=row["id"],
            tenant_id=row["tenant_id"],
            artifact_id=row["artifact_id"],
            trace_id=row["trace_id"],
            retry_count=row["retry_count"],
        )

    async def load_active_provider_config(self, tenant_id: UUID) -> AiProviderConfig:
        row = await self._pool.fetchrow(
            """
            SELECT provider.id,
                   provider.tenant_id,
                   provider.display_name,
                   provider.provider_type,
                   provider.base_url,
                   provider.model_id,
                   provider.is_local,
                   credential.name AS credential_env_var,
                   credential.source AS credential_source,
                   COALESCE(credential.configured, false) AS configured
            FROM ai_provider_configs provider
            LEFT JOIN integration_credentials credential
              ON credential.tenant_id = provider.tenant_id
             AND credential.id = provider.credential_ref
            WHERE provider.tenant_id = $1
              AND provider.active = true
            ORDER BY provider.updated_at DESC
            LIMIT 1
            """,
            tenant_id,
        )
        if row is None:
            raise RuntimeError("no active AI provider config is available for the tenant")
        provider = AiProviderConfig(
            id=row["id"],
            tenant_id=row["tenant_id"],
            display_name=row["display_name"],
            provider_type=row["provider_type"],
            base_url=row["base_url"],
            model_id=row["model_id"],
            credential_env_var=row["credential_env_var"],
            credential_source=row["credential_source"],
            configured=row["configured"],
            is_local=row["is_local"],
        )
        validate_provider_credentials(provider)
        return provider

    async def load_evidence(self, job: AiAnalysisJob) -> dict[str, Any]:
        static_rows = await self._pool.fetch(
            """
            SELECT report
            FROM static_analysis_reports
            WHERE analysis_job_id = $1 AND artifact_id = $2
            ORDER BY created_at ASC
            """,
            job.id,
            job.artifact_id,
        )
        sandbox_rows = await self._pool.fetch(
            """
            SELECT telemetry
            FROM sandbox_runs
            WHERE analysis_job_id = $1
              AND artifact_id = $2
              AND state = 'completed'
            ORDER BY started_at ASC NULLS LAST
            """,
            job.id,
            job.artifact_id,
        )

        static_indicators: list[dict[str, Any]] = []
        for row in static_rows:
            report = row["report"]
            indicators = report.get("indicators") if isinstance(report, dict) else None
            if isinstance(indicators, list):
                static_indicators.extend(indicator for indicator in indicators if isinstance(indicator, dict))

        sandbox_events: list[dict[str, Any]] = []
        for row in sandbox_rows:
            telemetry = row["telemetry"]
            phases = telemetry.get("phases") if isinstance(telemetry, dict) else None
            if isinstance(phases, list):
                for phase in phases:
                    events = phase.get("events") if isinstance(phase, dict) else None
                    if isinstance(events, list):
                        sandbox_events.extend(event for event in events if isinstance(event, dict))

        return {
            "static_indicators": static_indicators,
            "sandbox_events": sandbox_events,
        }

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
        explanation_document = dict(explanation_payload)
        if langfuse_trace_id is not None:
            explanation_document["langfuse_trace_id"] = langfuse_trace_id

        row = await self._pool.fetchrow(
            """
            INSERT INTO ai_explanations (
              analysis_job_id,
              provider_config_id,
              langfuse_trace_id,
              prompt_template_version,
              redaction_complete,
              schema_valid,
              explanation
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
            RETURNING id
            """,
            job.id,
            provider.id,
            langfuse_trace_id,
            PROMPT_TEMPLATE_VERSION,
            redaction_complete,
            schema_valid,
            json.dumps(explanation_document),
        )
        explanation_id = row["id"]
        await self._pool.execute(
            """
            INSERT INTO llm_usage_events (
              tenant_id,
              analysis_job_id,
              artifact_id,
              ai_explanation_id,
              provider_config_id,
              trace_id,
              provider_display_name,
              provider_type,
              model_id,
              langfuse_trace_id,
              prompt_template_version,
              prompt_tokens,
              completion_tokens,
              total_tokens,
              estimated_cost,
              latency_ms,
              schema_valid,
              redaction_complete,
              evidence_hash,
              output_hash
            )
            VALUES (
              $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
              $11, $12, $13, $14, $15, $16, $17, $18, $19, $20
            )
            """,
            job.tenant_id,
            job.id,
            job.artifact_id,
            explanation_id,
            provider.id,
            job.trace_id,
            provider.display_name,
            provider.provider_type,
            usage_snapshot.model_id,
            usage_snapshot.langfuse_trace_id,
            usage_snapshot.prompt_template_version,
            usage_snapshot.prompt_tokens,
            usage_snapshot.completion_tokens,
            usage_snapshot.total_tokens,
            usage_snapshot.estimated_cost,
            usage_snapshot.latency_ms,
            usage_snapshot.schema_valid,
            usage_snapshot.redaction_complete,
            usage_snapshot.evidence_hash,
            usage_snapshot.output_hash,
        )
        return explanation_id

    async def finalize_ai_job(self, job: AiAnalysisJob) -> str:
        await self._pool.execute(
            """
            UPDATE analysis_jobs
            SET state = 'finalizing'::analysis_job_state,
                updated_at = now()
            WHERE id = $1
            """,
            job.id,
        )
        return "finalizing"

    async def degrade_ai_job(self, job: AiAnalysisJob, *, reason: str) -> str:
        await self._pool.execute(
            """
            UPDATE analysis_jobs
            SET state = 'finalizing'::analysis_job_state,
                updated_at = now()
            WHERE id = $1
            """,
            job.id,
        )
        return "finalizing"

    async def fail_ai_job(
        self,
        job: AiAnalysisJob,
        *,
        max_retries: int,
        reason: str,
    ) -> str:
        next_retry_count = job.retry_count + 1
        next_state = "failed" if next_retry_count >= max_retries else "ai-pending"
        await self._pool.execute(
            """
            UPDATE analysis_jobs
            SET state = $2::analysis_job_state,
                retry_count = retry_count + 1,
                updated_at = now()
            WHERE id = $1
            """,
            job.id,
            next_state,
        )
        return next_state


async def process_next_ai_job(
    repository: AiJobRepository,
    *,
    max_retries: int = 3,
    trace_client: TraceClient | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> ProcessNextAiJobResponse:
    job = await repository.claim_next_ai_job(max_retries=max_retries)
    if job is None:
        return ProcessNextAiJobResponse(processed=False)

    try:
        provider = await repository.load_active_provider_config(job.tenant_id)
        evidence = await repository.load_evidence(job)
        active_trace_client = trace_client or build_optional_trace_client()
        advisory_response = await build_advisory_response(
            provider,
            evidence,
            http_client=http_client,
        )
        explanation_payload = advisory_response.explanation.model_dump(
            mode="json",
            exclude_none=True,
        )
        validate_ai_explanation_schema(explanation_payload)
        langfuse_trace_id = advisory_response.explanation.langfuse_trace_id
        if active_trace_client is not None:
            try:
                langfuse_trace_id = active_trace_client.record_generation(
                    trace_name="ai-analyst-job",
                    session_id=str(job.id),
                    provider=provider.display_name,
                    model=provider.model_id,
                    prompt_template_version=PROMPT_TEMPLATE_VERSION,
                    input_payload=advisory_response.redacted_evidence,
                    output_payload=explanation_payload,
                    metadata={
                        "analysis_job_id": str(job.id),
                        "tenant_id": str(job.tenant_id),
                        "trace_id": job.trace_id,
                        "provider_type": provider.provider_type,
                    },
                )
            except Exception:
                LOGGER.warning("langfuse trace recording failed; continuing without trace id")
        if langfuse_trace_id is not None:
            explanation_payload["langfuse_trace_id"] = langfuse_trace_id
            validate_ai_explanation_schema(explanation_payload)
        usage_snapshot = build_llm_usage_snapshot(
            provider,
            advisory_response,
            explanation_payload,
            schema_valid=True,
            langfuse_trace_id=langfuse_trace_id,
        )
        explanation_id = await repository.persist_ai_explanation(
            job,
            provider,
            explanation_payload,
            redaction_complete=advisory_response.redaction_complete,
            schema_valid=True,
            langfuse_trace_id=langfuse_trace_id,
            usage_snapshot=usage_snapshot,
        )
        state = await repository.finalize_ai_job(job)
    except Exception as error:
        if should_degrade_without_ai_explanation(error):
            state = await repository.degrade_ai_job(job, reason=str(error))
            return ProcessNextAiJobResponse(
                processed=True,
                analysis_job_id=str(job.id),
                explanation_id=None,
                provider_config_id=None,
                state=state,
            )
        state = await repository.fail_ai_job(job, max_retries=max_retries, reason=str(error))
        return ProcessNextAiJobResponse(
            processed=True,
            analysis_job_id=str(job.id),
            explanation_id=None,
            provider_config_id=None,
            state=state,
        )

    return ProcessNextAiJobResponse(
        processed=True,
        analysis_job_id=str(job.id),
        explanation_id=str(explanation_id),
        provider_config_id=str(provider.id),
        state=state,
    )


async def process_next_ai_job_from_database(
    database_url: str | None = None,
    *,
    max_retries: int = 3,
) -> ProcessNextAiJobResponse:
    if asyncpg is None:
        raise RuntimeError("asyncpg is required to process AI jobs from PostgreSQL")

    load_workspace_env_file()
    resolved_database_url = database_url or os.environ.get("DATABASE_URL")
    if not resolved_database_url:
        raise RuntimeError("DATABASE_URL is required to process AI jobs")

    pool = await asyncpg.create_pool(resolved_database_url, min_size=1, max_size=4)
    try:
        repository = PostgresAiJobRepository(pool)
        return await process_next_ai_job(repository, max_retries=max_retries)
    finally:
        await pool.close()


def validate_provider_credentials(provider: AiProviderConfig) -> None:
    if provider.is_local:
        validate_local_provider_boundary(provider)
        return
    if provider.credential_env_var is None:
        raise RuntimeError("active AI provider config is missing a credential reference")
    if provider.credential_source != "environment":
        raise RuntimeError("database-runtime-override credentials are not supported by AI Analyst yet")
    if not provider.configured:
        raise RuntimeError("active AI provider credential is not configured")
    if not os.environ.get(provider.credential_env_var):
        raise RuntimeError(
            f"active AI provider credential environment variable {provider.credential_env_var} is not set"
        )


def should_degrade_without_ai_explanation(error: Exception) -> bool:
    message = str(error).lower()
    degradable_fragments = (
        "no active ai provider config",
        "missing a credential reference",
        "database-runtime-override credentials are not supported",
        "credential environment variable",
        "credential is not configured",
        "provider request failed",
        "provider response invalid",
        "local provider boundary violation",
        "ai explanation schema validation failed",
        "ai explanation guardrail violation",
        "redaction incomplete",
    )
    return any(fragment in message for fragment in degradable_fragments)


def validate_local_provider_boundary(provider: AiProviderConfig) -> None:
    if provider.base_url is None:
        raise RuntimeError("local provider boundary violation: base_url is required")
    parsed = urlparse(provider.base_url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise RuntimeError("local provider boundary violation: base_url must be an HTTP URL")
    if parsed.username is not None or parsed.password is not None:
        raise RuntimeError("local provider boundary violation: userinfo is not allowed")
    if not is_allowed_local_provider_host(parsed.hostname):
        raise RuntimeError(
            "local provider boundary violation: base_url host must be localhost, loopback, or RFC1918 private IPv4"
        )


def is_allowed_local_provider_host(hostname: str) -> bool:
    normalized = hostname.strip("[]").lower()
    if normalized == "localhost":
        return True
    try:
        address = ip_address(normalized)
    except ValueError:
        return False
    if address.is_loopback:
        return True
    if address.version == 4:
        return any(address in network for network in RFC1918_IPV4_NETWORKS)
    return False


def validate_ai_explanation_schema(payload: dict[str, Any]) -> None:
    errors = sorted(
        ai_explanation_schema_validator().iter_errors(payload),
        key=lambda error: list(error.path),
    )
    if not errors:
        return
    details = "; ".join(error.message for error in errors)
    raise RuntimeError(f"ai explanation schema validation failed: {details}")


def validate_advisory_output_guardrails(advisory_fields: StructuredAdvisoryFields) -> None:
    for section_name, values in (
        ("observed_behavior", advisory_fields.observed_behavior),
        ("inference", advisory_fields.inference),
        ("limitations", advisory_fields.limitations),
    ):
        for value in values:
            lowered = value.lower()
            fragment = next(
                (candidate for candidate in OUTPUT_GUARDRAIL_FRAGMENTS if candidate in lowered),
                None,
            )
            if fragment is not None:
                raise RuntimeError(
                    "ai explanation guardrail violation: "
                    f"{section_name} contains forbidden guidance fragment '{fragment}'"
                )


@lru_cache(maxsize=1)
def ai_explanation_schema_validator() -> Draft202012Validator:
    schema_path = Path(__file__).resolve().parents[4] / "schemas" / "ai-explanation.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    validator.check_schema(schema)
    return validator


async def build_advisory_response(
    provider: AiProviderConfig,
    evidence: dict[str, Any],
    *,
    http_client: httpx.AsyncClient | None = None,
) -> AdvisoryExecutionResult:
    validate_provider_credentials(provider)
    started = perf_counter()
    preview = build_advisory_preview(
        AdvisoryPreviewRequest(
            provider=provider.display_name,
            model=provider.model_id,
            prompt_template_version=PROMPT_TEMPLATE_VERSION,
            evidence=evidence,
        )
    )
    if normalized_provider_type(provider) not in OPENAI_COMPATIBLE_PROVIDER_TYPES:
        return AdvisoryExecutionResult(
            redaction_complete=preview.redaction_complete,
            redacted_evidence=preview.redacted_evidence,
            explanation=preview.explanation,
            provider_usage=ProviderUsageMetrics(
                latency_ms=round((perf_counter() - started) * 1000, 2),
                resolved_model=provider.model_id,
            ),
        )

    advisory_result = await request_openai_compatible_advisory_fields(
        provider,
        preview.redacted_evidence,
        http_client=http_client,
    )
    validate_advisory_output_guardrails(advisory_result.advisory_fields)
    explanation = build_provider_explanation(
        provider,
        preview.redacted_evidence,
        advisory_result.advisory_fields,
        fallback=preview.explanation,
        model_id=advisory_result.provider_usage.resolved_model or provider.model_id,
    )
    return AdvisoryExecutionResult(
        redaction_complete=preview.redaction_complete,
        redacted_evidence=preview.redacted_evidence,
        explanation=explanation,
        provider_usage=advisory_result.provider_usage,
    )


async def request_openai_compatible_advisory_fields(
    provider: AiProviderConfig,
    redacted_evidence: dict[str, Any],
    *,
    http_client: httpx.AsyncClient | None = None,
) -> OpenRouterAdvisoryResult:
    request_payload = build_openai_compatible_request_payload(provider.model_id, redacted_evidence)
    headers = build_openai_compatible_headers(provider)

    owns_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=OPENROUTER_TIMEOUT_SECONDS)
    started = perf_counter()
    try:
        response = await client.post(
            openai_compatible_chat_completions_url(provider),
            headers=headers,
            json=request_payload,
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as error:
        raise RuntimeError(
            f"provider request failed with status {error.response.status_code}"
        ) from error
    except httpx.HTTPError as error:
        raise RuntimeError("provider request failed") from error
    finally:
        if owns_client:
            await client.aclose()

    try:
        payload = response.json()
        content = extract_openrouter_message_content(payload)
        parsed = json.loads(content) if isinstance(content, str) else content
        advisory_fields = StructuredAdvisoryFields.model_validate(parsed)
    except (ValueError, TypeError) as error:
        raise RuntimeError("provider response invalid") from error

    usage = parse_openrouter_usage(payload)
    return OpenRouterAdvisoryResult(
        advisory_fields=advisory_fields,
        provider_usage=ProviderUsageMetrics(
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
            total_tokens=usage.total_tokens,
            estimated_cost=usage.estimated_cost,
            latency_ms=round((perf_counter() - started) * 1000, 2),
            resolved_model=extract_openrouter_model_id(payload) or provider.model_id,
        ),
    )


def build_provider_explanation(
    provider: AiProviderConfig,
    redacted_evidence: dict[str, Any],
    advisory_fields: StructuredAdvisoryFields,
    *,
    fallback: AiExplanation,
    model_id: str,
) -> AiExplanation:
    observed_behavior = advisory_fields.observed_behavior or fallback.observed_behavior
    inference = advisory_fields.inference or fallback.inference
    limitations = dedupe_strings(
        [
            *advisory_fields.limitations,
            "AI output is advisory only and cannot override deterministic policy enforcement.",
            "The response reflects only the redacted evidence supplied to AI Analyst.",
        ]
    )
    explanation_payload: dict[str, Any] = {
        "provider": provider.display_name,
        "model": model_id,
        "prompt_template_version": PROMPT_TEMPLATE_VERSION,
        "observed_behavior": observed_behavior,
        "inference": inference,
        "limitations": limitations,
        "advisory_only": True,
        "evidence_hash": sha256_digest(redacted_evidence).model_dump(mode="json"),
    }
    explanation_payload["output_hash"] = sha256_digest(explanation_payload).model_dump(mode="json")
    return AiExplanation.model_validate(explanation_payload)


def build_llm_usage_snapshot(
    provider: AiProviderConfig,
    advisory_response: AdvisoryExecutionResult,
    explanation_payload: dict[str, Any],
    *,
    schema_valid: bool,
    langfuse_trace_id: str | None,
) -> LlmUsageSnapshot:
    return LlmUsageSnapshot(
        model_id=advisory_response.provider_usage.resolved_model or provider.model_id,
        prompt_template_version=PROMPT_TEMPLATE_VERSION,
        prompt_tokens=advisory_response.provider_usage.prompt_tokens,
        completion_tokens=advisory_response.provider_usage.completion_tokens,
        total_tokens=advisory_response.provider_usage.total_tokens,
        estimated_cost=advisory_response.provider_usage.estimated_cost,
        latency_ms=advisory_response.provider_usage.latency_ms,
        schema_valid=schema_valid,
        redaction_complete=advisory_response.redaction_complete,
        langfuse_trace_id=langfuse_trace_id,
        evidence_hash=digest_hex(explanation_payload.get("evidence_hash")),
        output_hash=digest_hex(explanation_payload.get("output_hash")),
    )


def digest_hex(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    digest = value.get("hex")
    return digest if isinstance(digest, str) and digest else None


def parse_openrouter_usage(payload: dict[str, Any]) -> ProviderUsageMetrics:
    usage = payload.get("usage")
    if not isinstance(usage, dict):
        return ProviderUsageMetrics()
    return ProviderUsageMetrics(
        prompt_tokens=coerce_int(usage.get("prompt_tokens")),
        completion_tokens=coerce_int(usage.get("completion_tokens")),
        total_tokens=coerce_int(usage.get("total_tokens")),
        estimated_cost=coerce_float(usage.get("cost")),
    )


def extract_openrouter_model_id(payload: dict[str, Any]) -> str | None:
    model = payload.get("model")
    return model if isinstance(model, str) and model else None


def coerce_int(value: Any) -> int | None:
    return value if isinstance(value, int) else None


def coerce_float(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    return None


def build_openai_compatible_request_payload(model_id: str, redacted_evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "model": model_id,
        "temperature": 0,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are Aegiscudo AI Analyst. Use only the provided redacted evidence. "
                    "Keep observed_behavior factual and grounded in the evidence. Keep inference "
                    "advisory and separate from observations. Never request secrets, never change "
                    "policy, and never claim enforcement authority. Return only JSON matching the schema."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "task": (
                            "Summarize suspicious package-analysis evidence for an analyst review."
                        ),
                        "requirements": [
                            "observed_behavior must cite only facts present in the evidence",
                            "inference must stay advisory and explain likely risk",
                            "limitations must mention uncertainty or missing visibility",
                        ],
                        "evidence": redacted_evidence,
                    },
                    sort_keys=True,
                ),
            },
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "aegiscudo_advisory_fields",
                "strict": True,
                "schema": {
                    "type": "object",
                    "properties": {
                        "observed_behavior": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "inference": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "limitations": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                    "required": ["observed_behavior", "inference", "limitations"],
                    "additionalProperties": False,
                },
            },
        },
    }


def openai_compatible_chat_completions_url(provider: AiProviderConfig) -> str:
    provider_type = normalized_provider_type(provider)
    default_base_url = OPENROUTER_BASE_URL if provider_type == "openrouter" else OPENAI_BASE_URL
    base_url = (provider.base_url or default_base_url).rstrip("/")
    if base_url.endswith("/chat/completions"):
        return base_url
    if base_url.endswith("/v1") or base_url.endswith("/api/v1"):
        return f"{base_url}/chat/completions"
    if provider_type == "openrouter":
        return f"{base_url}/api/v1/chat/completions"
    return f"{base_url}/v1/chat/completions"


def build_openai_compatible_headers(provider: AiProviderConfig) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if provider.credential_env_var is not None:
        headers["Authorization"] = f"Bearer {resolve_provider_api_key(provider)}"
    if normalized_provider_type(provider) == "openrouter":
        headers["HTTP-Referer"] = OPENROUTER_APP_REFERER
        headers["X-OpenRouter-Title"] = OPENROUTER_APP_TITLE
    return headers


def normalized_provider_type(provider: AiProviderConfig) -> str:
    return provider.provider_type.strip().lower().replace("_", "-").replace(" ", "-")


def resolve_provider_api_key(provider: AiProviderConfig) -> str:
    if provider.credential_env_var is None:
        raise RuntimeError("active AI provider config is missing a credential reference")
    api_key = os.environ.get(provider.credential_env_var, "").strip()
    if not api_key:
        raise RuntimeError(
            f"active AI provider credential environment variable {provider.credential_env_var} is not set"
        )
    return api_key


def extract_openrouter_message_content(payload: dict[str, Any]) -> str | dict[str, Any]:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("missing OpenRouter choices")
    message = choices[0].get("message")
    if not isinstance(message, dict):
        raise ValueError("missing OpenRouter message")
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        return content
    if isinstance(content, list):
        parts = [part.get("text") for part in content if isinstance(part, dict)]
        joined = "".join(part for part in parts if isinstance(part, str))
        if joined:
            return joined
    raise ValueError("missing OpenRouter content")


def dedupe_strings(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            deduped.append(value)
    return deduped