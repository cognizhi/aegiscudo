from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID, uuid4

import pytest
from aegiscudo_common.contracts import PackageEcosystem, SandboxProfile
from emergency_room.sandbox import LocalSandboxRunRequest, LocalSandboxRunResponse
from emergency_room.worker import (
    ProcessNextSandboxJobResponse,
    SandboxJob,
    infer_import_name,
    process_next_sandbox_job,
    profile_for_job,
)


@dataclass
class FakeRepository:
    job: SandboxJob | None
    sandbox_run_id: UUID = field(default_factory=uuid4)
    failure_state: str = "sandbox-pending"
    created_profile: SandboxProfile | None = None
    completed: tuple[SandboxJob, UUID, LocalSandboxRunResponse] | None = None
    failed: tuple[SandboxJob, UUID | None, int, str] | None = None

    async def claim_next_sandbox_job(self, *, max_retries: int) -> SandboxJob | None:
        return self.job

    async def create_sandbox_run(self, job: SandboxJob, profile: SandboxProfile) -> UUID:
        self.created_profile = profile
        return self.sandbox_run_id

    async def complete_sandbox_run(
        self,
        job: SandboxJob,
        sandbox_run_id: UUID,
        result: LocalSandboxRunResponse,
    ) -> None:
        self.completed = (job, sandbox_run_id, result)

    async def fail_sandbox_run(
        self,
        job: SandboxJob,
        sandbox_run_id: UUID | None,
        *,
        max_retries: int,
        reason: str,
    ) -> str:
        self.failed = (job, sandbox_run_id, max_retries, reason)
        return self.failure_state


@dataclass
class FakeExecutor:
    result: LocalSandboxRunResponse | None = None
    error: Exception | None = None
    requests: list[LocalSandboxRunRequest] = field(default_factory=list)

    async def run(self, request: LocalSandboxRunRequest) -> LocalSandboxRunResponse:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        assert self.result is not None
        return self.result


@dataclass
class FakeProfileRegistry:
    executor: FakeExecutor
    profiles: list[SandboxProfile] = field(default_factory=list)

    def resolve(self, profile: SandboxProfile) -> FakeExecutor:
        self.profiles.append(profile)
        return self.executor


def build_job(ecosystem: PackageEcosystem = PackageEcosystem.NPM) -> SandboxJob:
    return SandboxJob(
        id=uuid4(),
        tenant_id=uuid4(),
        artifact_id=uuid4(),
        artifact_uri="/tmp/artifact.bin",
        ecosystem=ecosystem,
        package_name="env-snoop",
        trace_id="trace-sandbox-job",
        retry_count=0,
    )


@pytest.mark.asyncio
async def test_process_next_sandbox_job_persists_completed_run() -> None:
    repository = FakeRepository(job=build_job())
    expected_result = LocalSandboxRunResponse.model_validate(
        {
            "run_id": str(uuid4()),
            "state": "completed",
            "violation_detected": True,
            "telemetry": [],
        }
    )
    registry = FakeProfileRegistry(executor=FakeExecutor(result=expected_result))

    response = await process_next_sandbox_job(repository, sandbox_profile_registry=registry)

    assert response == ProcessNextSandboxJobResponse(
        processed=True,
        analysis_job_id=str(repository.job.id),
        sandbox_run_id=str(repository.sandbox_run_id),
        state="ai-pending",
        violation_detected=True,
    )
    assert repository.created_profile == SandboxProfile.NPM_INSTALL
    assert repository.completed == (repository.job, repository.sandbox_run_id, expected_result)
    assert repository.failed is None
    assert registry.profiles == [SandboxProfile.NPM_INSTALL]


@pytest.mark.asyncio
async def test_process_next_sandbox_job_reports_failure() -> None:
    repository = FakeRepository(job=build_job())
    registry = FakeProfileRegistry(executor=FakeExecutor(error=RuntimeError("sandbox execution failed")))

    response = await process_next_sandbox_job(repository, max_retries=4, sandbox_profile_registry=registry)

    assert response.processed is True
    assert response.state == "sandbox-pending"
    assert response.violation_detected is None
    assert repository.completed is None
    assert repository.failed is not None
    assert repository.failed[2] == 4
    assert repository.created_profile == SandboxProfile.NPM_INSTALL
    assert registry.profiles == [SandboxProfile.NPM_INSTALL]


@pytest.mark.asyncio
async def test_process_next_sandbox_job_degrades_to_ai_pending_after_retry_budget() -> None:
    repository = FakeRepository(job=build_job(), failure_state="ai-pending")
    registry = FakeProfileRegistry(executor=FakeExecutor(error=RuntimeError("sandbox execution failed")))

    response = await process_next_sandbox_job(repository, max_retries=3, sandbox_profile_registry=registry)

    assert response.processed is True
    assert response.state == "ai-pending"
    assert response.violation_detected is None
    assert repository.failed is not None
    assert repository.created_profile == SandboxProfile.NPM_INSTALL
    assert registry.profiles == [SandboxProfile.NPM_INSTALL]


@pytest.mark.asyncio
async def test_process_next_sandbox_job_resolves_runner_from_profile_registry() -> None:
    repository = FakeRepository(job=build_job(PackageEcosystem.PYPI))
    expected_result = LocalSandboxRunResponse.model_validate(
        {
            "run_id": str(uuid4()),
            "state": "completed",
            "violation_detected": False,
            "telemetry": [],
        }
    )
    executor = FakeExecutor(result=expected_result)
    registry = FakeProfileRegistry(executor=executor)

    response = await process_next_sandbox_job(repository, sandbox_profile_registry=registry)

    assert response.processed is True
    assert response.state == "ai-pending"
    assert repository.created_profile == SandboxProfile.PYTHON_INSTALL
    assert registry.profiles == [SandboxProfile.PYTHON_INSTALL]
    assert len(executor.requests) == 1
    assert executor.requests[0].profile == SandboxProfile.PYTHON_INSTALL
    assert executor.requests[0].artifact_uri == repository.job.artifact_uri
    assert executor.requests[0].import_name == "env_snoop"


def test_profile_selection_and_import_name() -> None:
    npm_job = build_job(PackageEcosystem.NPM)
    pypi_job = build_job(PackageEcosystem.PYPI)

    assert profile_for_job(npm_job) == SandboxProfile.NPM_INSTALL
    assert profile_for_job(pypi_job) == SandboxProfile.PYTHON_INSTALL
    assert infer_import_name(npm_job) is None
    assert infer_import_name(pypi_job) == "env_snoop"