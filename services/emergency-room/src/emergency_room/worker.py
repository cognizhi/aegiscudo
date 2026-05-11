from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID

from aegiscudo_common.contracts import PackageEcosystem, SandboxProfile
from pydantic import BaseModel, ConfigDict

from emergency_room.sandbox import (
    LocalSandboxRunRequest,
    LocalSandboxRunResponse,
    SandboxProfileRegistry,
    infer_python_import_name,
    run_sandbox_profile,
)

try:
    import asyncpg
except ModuleNotFoundError:  # pragma: no cover - exercised only when dependency is absent.
    asyncpg = None


class ProcessNextSandboxJobResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    processed: bool
    analysis_job_id: str | None = None
    sandbox_run_id: str | None = None
    state: str | None = None
    violation_detected: bool | None = None


@dataclass(frozen=True)
class SandboxJob:
    id: UUID
    tenant_id: UUID
    artifact_id: UUID
    artifact_uri: str
    ecosystem: PackageEcosystem
    package_name: str
    trace_id: str
    retry_count: int


class SandboxJobRepository(Protocol):
    async def claim_next_sandbox_job(self, *, max_retries: int) -> SandboxJob | None: ...

    async def create_sandbox_run(self, job: SandboxJob, profile: SandboxProfile) -> UUID: ...

    async def complete_sandbox_run(
        self,
        job: SandboxJob,
        sandbox_run_id: UUID,
        result: LocalSandboxRunResponse,
    ) -> None: ...

    async def fail_sandbox_run(
        self,
        job: SandboxJob,
        sandbox_run_id: UUID | None,
        *,
        max_retries: int,
        reason: str,
    ) -> str: ...


class PostgresSandboxJobRepository:
    def __init__(self, pool: Any) -> None:
        self._pool = pool

    async def claim_next_sandbox_job(self, *, max_retries: int) -> SandboxJob | None:
        row = await self._pool.fetchrow(
            """
            WITH candidate AS (
              SELECT id
              FROM analysis_jobs
              WHERE state = 'sandbox-pending'::analysis_job_state
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
            SET state = 'sandbox-running'::analysis_job_state,
                updated_at = now()
            FROM candidate
            WHERE jobs.id = candidate.id
            RETURNING jobs.id,
                      jobs.tenant_id,
                      jobs.artifact_id,
                      jobs.ecosystem::text AS ecosystem,
                      jobs.package_name,
                      jobs.trace_id,
                      jobs.retry_count
            """,
            max_retries,
        )
        if row is None:
            return None

        artifact_row = await self._pool.fetchrow(
            """
            SELECT storage_uri
            FROM artifacts
            WHERE id = $1 AND tenant_id = $2
            """,
            row["artifact_id"],
            row["tenant_id"],
        )
        if artifact_row is None:
            raise RuntimeError("claimed sandbox job is missing artifact storage")

        return SandboxJob(
            id=row["id"],
            tenant_id=row["tenant_id"],
            artifact_id=row["artifact_id"],
            artifact_uri=artifact_row["storage_uri"],
            ecosystem=PackageEcosystem(row["ecosystem"]),
            package_name=row["package_name"],
            trace_id=row["trace_id"],
            retry_count=row["retry_count"],
        )

    async def create_sandbox_run(self, job: SandboxJob, profile: SandboxProfile) -> UUID:
        row = await self._pool.fetchrow(
            """
            INSERT INTO sandbox_runs (
              analysis_job_id,
              artifact_id,
              profile,
              state,
              telemetry,
              started_at
            )
            VALUES ($1, $2, $3, 'running', '{}'::jsonb, now())
            RETURNING id
            """,
            job.id,
            job.artifact_id,
            profile.value,
        )
        return row["id"]

    async def complete_sandbox_run(
        self,
        job: SandboxJob,
        sandbox_run_id: UUID,
        result: LocalSandboxRunResponse,
    ) -> None:
        payload = {
            "run_id": result.run_id,
            "state": result.state,
            "violation_detected": result.violation_detected,
            "phases": [entry.model_dump(mode="json") for entry in result.telemetry],
        }
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute(
                    """
                    UPDATE sandbox_runs
                    SET state = 'completed',
                        telemetry = $2::jsonb,
                        completed_at = now()
                    WHERE id = $1
                    """,
                    sandbox_run_id,
                    json.dumps(payload),
                )
                await connection.execute(
                    """
                    UPDATE analysis_jobs
                    SET state = 'ai-pending'::analysis_job_state,
                        updated_at = now()
                    WHERE id = $1
                    """,
                    job.id,
                )

    async def fail_sandbox_run(
        self,
        job: SandboxJob,
        sandbox_run_id: UUID | None,
        *,
        max_retries: int,
        reason: str,
    ) -> str:
        next_retry_count = job.retry_count + 1
        next_state = "ai-pending" if next_retry_count >= max_retries else "sandbox-pending"
        payload = {"reason": reason}
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                if sandbox_run_id is not None:
                    await connection.execute(
                        """
                        UPDATE sandbox_runs
                        SET state = 'failed',
                            telemetry = $2::jsonb,
                            completed_at = now()
                        WHERE id = $1
                        """,
                        sandbox_run_id,
                        json.dumps(payload),
                    )
                await connection.execute(
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


async def process_next_sandbox_job(
    repository: SandboxJobRepository,
    *,
    max_retries: int = 3,
    sandbox_profile_registry: SandboxProfileRegistry | None = None,
) -> ProcessNextSandboxJobResponse:
    job = await repository.claim_next_sandbox_job(max_retries=max_retries)
    if job is None:
        return ProcessNextSandboxJobResponse(processed=False)

    profile = profile_for_job(job)
    sandbox_run_id = await repository.create_sandbox_run(job, profile)
    try:
        result = await run_sandbox_profile(
            LocalSandboxRunRequest(
                profile=profile,
                artifact_uri=job.artifact_uri,
                import_name=infer_import_name(job),
            ),
            profile_registry=sandbox_profile_registry,
        )
    except Exception as error:
        state = await repository.fail_sandbox_run(
            job,
            sandbox_run_id,
            max_retries=max_retries,
            reason=str(error),
        )
        return ProcessNextSandboxJobResponse(
            processed=True,
            analysis_job_id=str(job.id),
            sandbox_run_id=str(sandbox_run_id),
            state=state,
            violation_detected=None,
        )

    await repository.complete_sandbox_run(job, sandbox_run_id, result)
    return ProcessNextSandboxJobResponse(
        processed=True,
        analysis_job_id=str(job.id),
        sandbox_run_id=str(sandbox_run_id),
        state="ai-pending",
        violation_detected=result.violation_detected,
    )


async def process_next_sandbox_job_from_database(
    database_url: str | None = None,
    *,
    max_retries: int = 3,
) -> ProcessNextSandboxJobResponse:
    if asyncpg is None:
        raise RuntimeError("asyncpg is required to process sandbox jobs from PostgreSQL")

    resolved_database_url = database_url or os.environ.get("DATABASE_URL")
    if not resolved_database_url:
        raise RuntimeError("DATABASE_URL is required to process sandbox jobs")

    pool = await asyncpg.create_pool(resolved_database_url, min_size=1, max_size=4)
    try:
        repository = PostgresSandboxJobRepository(pool)
        return await process_next_sandbox_job(repository, max_retries=max_retries)
    finally:
        await pool.close()


def profile_for_job(job: SandboxJob) -> SandboxProfile:
    if job.ecosystem == PackageEcosystem.NPM:
        return SandboxProfile.NPM_INSTALL
    if job.ecosystem == PackageEcosystem.PYPI:
        return SandboxProfile.PYTHON_INSTALL
    raise RuntimeError(f"unsupported sandbox ecosystem: {job.ecosystem.value}")


def infer_import_name(job: SandboxJob) -> str | None:
    if job.ecosystem != PackageEcosystem.PYPI:
        return None
    return job.package_name.replace("-", "_")