from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID

from aegiscudo_common.contracts import PolicyDecision
from pydantic import BaseModel, ConfigDict

try:
    import asyncpg
except ModuleNotFoundError:  # pragma: no cover - exercised only when dependency is absent.
    asyncpg = None


SIMILAR_CASE_LIMIT = 3


class ProcessNextFinalizationJobResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    processed: bool
    analysis_job_id: str | None = None
    summary_id: str | None = None
    state: str | None = None
    recommended_action: PolicyDecision | None = None
    confidence: str | None = None
    requires_hitl: bool | None = None


@dataclass(frozen=True)
class FinalizationJob:
    id: UUID
    tenant_id: UUID
    artifact_id: UUID
    trace_id: str
    retry_count: int


@dataclass(frozen=True)
class FinalizationSummary:
    recommended_action: PolicyDecision
    confidence: str
    requires_hitl: bool
    payload: dict[str, Any]


class FinalizationRepository(Protocol):
    async def claim_next_finalization_job(self, *, max_retries: int) -> FinalizationJob | None: ...

    async def load_finalization_inputs(self, job: FinalizationJob) -> dict[str, Any]: ...

    async def persist_analysis_summary(
        self,
        job: FinalizationJob,
        summary: FinalizationSummary,
    ) -> UUID: ...

    async def complete_finalization_job(self, job: FinalizationJob) -> str: ...

    async def fail_finalization_job(
        self,
        job: FinalizationJob,
        *,
        max_retries: int,
        reason: str,
    ) -> str: ...


class PostgresFinalizationRepository:
    def __init__(self, pool: Any) -> None:
        self._pool = pool

    async def claim_next_finalization_job(self, *, max_retries: int) -> FinalizationJob | None:
        row = await self._pool.fetchrow(
            """
            WITH candidate AS (
              SELECT id
              FROM analysis_jobs
              WHERE state = 'finalizing'::analysis_job_state
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
        return FinalizationJob(
            id=row["id"],
            tenant_id=row["tenant_id"],
            artifact_id=row["artifact_id"],
            trace_id=row["trace_id"],
            retry_count=row["retry_count"],
        )

    async def load_finalization_inputs(self, job: FinalizationJob) -> dict[str, Any]:
        static_rows = await self._pool.fetch(
            """
            SELECT report,
                   embedding::text AS embedding_literal
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
            WHERE analysis_job_id = $1 AND artifact_id = $2
            ORDER BY started_at ASC NULLS LAST
            """,
            job.id,
            job.artifact_id,
        )
        ai_row = await self._pool.fetchrow(
            """
            SELECT explanation
            FROM ai_explanations
            WHERE analysis_job_id = $1
            ORDER BY created_at DESC
            LIMIT 1
            """,
            job.id,
        )
        vulnerability_rows = await self._pool.fetch(
            """
            SELECT advisory_id, severity, cisa_kev
            FROM vulnerability_matches
            WHERE artifact_id = $1
            ORDER BY created_at ASC
            """,
            job.artifact_id,
        )
        malware_rows = await self._pool.fetch(
            """
            SELECT source, indicator, confidence
            FROM malware_matches
            WHERE artifact_id = $1
            ORDER BY created_at ASC
            """,
            job.artifact_id,
        )
        similar_cases = await self._load_similar_cases(job, static_rows)

        return {
            "static_reports": [decode_json_value(row["report"]) for row in static_rows],
            "sandbox_runs": [decode_json_value(row["telemetry"]) for row in sandbox_rows],
            "ai_explanation": decode_json_value(ai_row["explanation"]) if ai_row is not None else None,
            "vulnerabilities": [dict(row) for row in vulnerability_rows],
            "malware_matches": [dict(row) for row in malware_rows],
            "similar_cases": similar_cases,
        }

    async def _load_similar_cases(
        self,
        job: FinalizationJob,
        static_rows: list[Any],
    ) -> list[dict[str, Any]]:
        embedding_literal = next(
            (
                row["embedding_literal"]
                for row in static_rows
                if row["embedding_literal"] is not None
            ),
            None,
        )
        if embedding_literal is None:
            return []

        similar_rows = await self._pool.fetch(
            """
            SELECT reports.analysis_job_id,
                   reports.artifact_id,
                   reports.created_at,
                   reports.report,
                   reports.embedding <=> $2::vector AS distance,
                   artifacts.ecosystem::text AS ecosystem,
                   artifacts.namespace,
                   artifacts.package_name,
                   artifacts.package_version,
                   summaries.recommended_action::text AS recommended_action,
                   summaries.confidence
            FROM static_analysis_reports AS reports
            JOIN analysis_jobs AS jobs
              ON jobs.id = reports.analysis_job_id
            JOIN artifacts
              ON artifacts.id = reports.artifact_id
            LEFT JOIN LATERAL (
              SELECT recommended_action, confidence
              FROM analysis_summaries
              WHERE artifact_id = reports.artifact_id
              ORDER BY created_at DESC
              LIMIT 1
            ) AS summaries ON TRUE
            WHERE jobs.tenant_id = $1
              AND reports.embedding IS NOT NULL
              AND reports.artifact_id <> $3
            ORDER BY reports.embedding <=> $2::vector ASC,
                     reports.created_at DESC
            LIMIT $4
            """,
            job.tenant_id,
            embedding_literal,
            job.artifact_id,
            SIMILAR_CASE_LIMIT,
        )
        return [summarize_historical_case(dict(row)) for row in similar_rows]

    async def persist_analysis_summary(
        self,
        job: FinalizationJob,
        summary: FinalizationSummary,
    ) -> UUID:
        row = await self._pool.fetchrow(
            """
            INSERT INTO analysis_summaries (
              analysis_job_id,
              artifact_id,
              recommended_action,
              confidence,
              requires_hitl,
              summary
            )
            VALUES ($1, $2, $3::policy_decision, $4, $5, $6::jsonb)
            RETURNING id
            """,
            job.id,
            job.artifact_id,
            summary.recommended_action.value,
            summary.confidence,
            summary.requires_hitl,
            json.dumps(summary.payload),
        )
        return row["id"]

    async def complete_finalization_job(self, job: FinalizationJob) -> str:
        await self._pool.execute(
            """
            UPDATE analysis_jobs
            SET state = 'completed'::analysis_job_state,
                updated_at = now()
            WHERE id = $1
            """,
            job.id,
        )
        return "completed"

    async def fail_finalization_job(
        self,
        job: FinalizationJob,
        *,
        max_retries: int,
        reason: str,
    ) -> str:
        next_retry_count = job.retry_count + 1
        next_state = "failed" if next_retry_count >= max_retries else "finalizing"
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


async def process_next_finalization_job(
    repository: FinalizationRepository,
    *,
    max_retries: int = 3,
) -> ProcessNextFinalizationJobResponse:
    job = await repository.claim_next_finalization_job(max_retries=max_retries)
    if job is None:
        return ProcessNextFinalizationJobResponse(processed=False)

    try:
        inputs = await repository.load_finalization_inputs(job)
        summary = build_final_analysis_summary(inputs)
        summary_id = await repository.persist_analysis_summary(job, summary)
        state = await repository.complete_finalization_job(job)
    except Exception as error:
        state = await repository.fail_finalization_job(
            job,
            max_retries=max_retries,
            reason=str(error),
        )
        return ProcessNextFinalizationJobResponse(
            processed=True,
            analysis_job_id=str(job.id),
            state=state,
        )

    return ProcessNextFinalizationJobResponse(
        processed=True,
        analysis_job_id=str(job.id),
        summary_id=str(summary_id),
        state=state,
        recommended_action=summary.recommended_action,
        confidence=summary.confidence,
        requires_hitl=summary.requires_hitl,
    )


async def process_next_finalization_job_from_database(
    database_url: str | None = None,
    *,
    max_retries: int = 3,
) -> ProcessNextFinalizationJobResponse:
    if asyncpg is None:
        raise RuntimeError("asyncpg is required to process finalization jobs from PostgreSQL")

    resolved_database_url = database_url or os.environ.get("DATABASE_URL")
    if not resolved_database_url:
        raise RuntimeError("DATABASE_URL is required to process finalization jobs")

    pool = await asyncpg.create_pool(resolved_database_url, min_size=1, max_size=4)
    try:
        repository = PostgresFinalizationRepository(pool)
        return await process_next_finalization_job(repository, max_retries=max_retries)
    finally:
        await pool.close()


def build_final_analysis_summary(inputs: dict[str, Any]) -> FinalizationSummary:
    static_indicators = collect_static_indicators(inputs.get("static_reports", []))
    sandbox_events = collect_sandbox_events(inputs.get("sandbox_runs", []))
    vulnerabilities = list(inputs.get("vulnerabilities", []))
    malware_matches = list(inputs.get("malware_matches", []))
    ai_explanation = inputs.get("ai_explanation")
    has_completed_sandbox_evidence = any(
        isinstance(run, dict) and isinstance(run.get("phases"), list)
        for run in inputs.get("sandbox_runs", [])
    )

    limitations: list[str] = []
    if not has_completed_sandbox_evidence:
        limitations.append("Sandbox evidence is missing for this artifact.")
    if ai_explanation is None:
        limitations.append("AI explanation is missing for this artifact.")
    else:
        explanation_limitations = ai_explanation.get("limitations")
        if isinstance(explanation_limitations, list):
            limitations.extend(str(item) for item in explanation_limitations)

    has_critical_sandbox = any(
        event.get("type") in {"canary-secret-access", "ai-canary-file-modified"}
        or event.get("severity") == "critical"
        for event in sandbox_events
        if isinstance(event, dict)
    )
    has_high_sandbox_network = any(
        event.get("type") == "outbound-network-attempt"
        and event.get("severity") in {"high", "critical"}
        for event in sandbox_events
        if isinstance(event, dict)
    )
    has_high_static = any(
        indicator.get("severity") in {"high", "critical"}
        for indicator in static_indicators
        if isinstance(indicator, dict)
    )

    if malware_matches:
        recommended_action = PolicyDecision.BLOCK_KNOWN_MALICIOUS
        confidence = "high"
        requires_hitl = False
    elif has_critical_sandbox or has_high_sandbox_network:
        recommended_action = PolicyDecision.BLOCK_POLICY_VIOLATION
        confidence = "high"
        requires_hitl = False
    elif has_high_static or vulnerabilities:
        recommended_action = PolicyDecision.REQUIRE_HITL_APPROVAL
        confidence = "medium"
        requires_hitl = True
    else:
        recommended_action = PolicyDecision.ALLOW_WITH_WARNING
        confidence = "low"
        requires_hitl = False

    payload = {
        "recommended_action": recommended_action.value,
        "confidence": confidence,
        "requires_hitl": requires_hitl,
        "evidence": {
            "static_indicator_count": len(static_indicators),
            "sandbox_event_count": len(sandbox_events),
            "vulnerability_count": len(vulnerabilities),
            "malware_match_count": len(malware_matches),
        },
        "limitations": dedupe_preserve_order(limitations),
        "ai_observed_behavior": ai_explanation.get("observed_behavior", []) if isinstance(ai_explanation, dict) else [],
        "ai_inference": ai_explanation.get("inference", []) if isinstance(ai_explanation, dict) else [],
        "historical_similar_cases": normalize_similar_cases(inputs.get("similar_cases", [])),
    }
    return FinalizationSummary(
        recommended_action=recommended_action,
        confidence=confidence,
        requires_hitl=requires_hitl,
        payload=payload,
    )


def collect_static_indicators(reports: list[Any]) -> list[dict[str, Any]]:
    indicators: list[dict[str, Any]] = []
    for report in reports:
        if isinstance(report, dict):
            report_indicators = report.get("indicators")
            if isinstance(report_indicators, list):
                indicators.extend(item for item in report_indicators if isinstance(item, dict))
    return indicators


def collect_sandbox_events(sandbox_runs: list[Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for run in sandbox_runs:
        if not isinstance(run, dict):
            continue
        phases = run.get("phases")
        if not isinstance(phases, list):
            continue
        for phase in phases:
            if not isinstance(phase, dict):
                continue
            phase_events = phase.get("events")
            if isinstance(phase_events, list):
                events.extend(item for item in phase_events if isinstance(item, dict))
    return events


def decode_json_value(value: Any) -> Any:
    if isinstance(value, str):
        return json.loads(value)
    return value


def summarize_historical_case(row: dict[str, Any]) -> dict[str, Any]:
    report = decode_json_value(row.get("report"))
    indicators = collect_static_indicators([report]) if isinstance(report, dict) else []
    created_at = row.get("created_at")

    return {
        "artifact_id": str(row["artifact_id"]),
        "analysis_job_id": str(row["analysis_job_id"]),
        "distance": round(float(row["distance"]), 4) if row.get("distance") is not None else None,
        "package_coordinate": {
            "ecosystem": row.get("ecosystem"),
            "namespace": row.get("namespace"),
            "name": row.get("package_name"),
            "version": row.get("package_version"),
        },
        "recommended_action": row.get("recommended_action"),
        "confidence": row.get("confidence"),
        "indicator_summaries": [
            indicator["summary"]
            for indicator in indicators
            if isinstance(indicator.get("summary"), str)
        ][:3],
        "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else created_at,
    }


def normalize_similar_cases(cases: list[Any]) -> list[dict[str, Any]]:
    return [case for case in cases if isinstance(case, dict)]


def dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result