from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID, uuid4

import pytest

from aegiscudo_common.contracts import PolicyDecision
from ai_analyst.finalizer import (
    FinalizationJob,
    FinalizationSummary,
    ProcessNextFinalizationJobResponse,
    build_final_analysis_summary,
    process_next_finalization_job,
)


@dataclass
class FakeRepository:
    job: FinalizationJob | None
    inputs: dict[str, Any] = field(default_factory=dict)
    summary_id: UUID = field(default_factory=uuid4)
    persisted: tuple[FinalizationJob, FinalizationSummary] | None = None
    failed: tuple[FinalizationJob, int, str] | None = None

    async def claim_next_finalization_job(self, *, max_retries: int) -> FinalizationJob | None:
        return self.job

    async def load_finalization_inputs(self, job: FinalizationJob) -> dict[str, Any]:
        return self.inputs

    async def persist_analysis_summary(
        self,
        job: FinalizationJob,
        summary: FinalizationSummary,
    ) -> UUID:
        self.persisted = (job, summary)
        return self.summary_id

    async def complete_finalization_job(self, job: FinalizationJob) -> str:
        return "completed"

    async def fail_finalization_job(
        self,
        job: FinalizationJob,
        *,
        max_retries: int,
        reason: str,
    ) -> str:
        self.failed = (job, max_retries, reason)
        return "finalizing"


def build_job() -> FinalizationJob:
    return FinalizationJob(
        id=uuid4(),
        tenant_id=uuid4(),
        artifact_id=uuid4(),
        trace_id="trace-finalizer-job",
        retry_count=0,
    )


def test_build_final_analysis_summary_blocks_on_high_sandbox_evidence() -> None:
    summary = build_final_analysis_summary(
        {
            "static_reports": [],
            "sandbox_runs": [
                {
                    "phases": [
                        {
                            "events": [
                                {
                                    "type": "outbound-network-attempt",
                                    "severity": "high",
                                    "message": "loopback exfiltration detected",
                                }
                            ]
                        }
                    ]
                }
            ],
            "ai_explanation": {"limitations": [], "observed_behavior": [], "inference": []},
            "vulnerabilities": [],
            "malware_matches": [],
        }
    )

    assert summary.recommended_action == PolicyDecision.BLOCK_POLICY_VIOLATION
    assert summary.confidence == "high"
    assert summary.requires_hitl is False


def test_build_final_analysis_summary_requires_hitl_for_static_only_high_risk() -> None:
    summary = build_final_analysis_summary(
        {
            "static_reports": [
                {
                    "indicators": [
                        {
                            "indicator_type": "node-child-process",
                            "severity": "high",
                            "summary": "child process execution detected",
                        }
                    ]
                }
            ],
            "sandbox_runs": [],
            "ai_explanation": None,
            "vulnerabilities": [],
            "malware_matches": [],
        }
    )

    assert summary.recommended_action == PolicyDecision.REQUIRE_HITL_APPROVAL
    assert summary.confidence == "medium"
    assert summary.requires_hitl is True
    assert "Sandbox evidence is missing for this artifact." in summary.payload["limitations"]
    assert "AI explanation is missing for this artifact." in summary.payload["limitations"]


def test_build_final_analysis_summary_treats_failed_only_sandbox_run_as_missing_evidence() -> None:
    summary = build_final_analysis_summary(
        {
            "static_reports": [],
            "sandbox_runs": [{"reason": "sandbox worker unavailable"}],
            "ai_explanation": None,
            "vulnerabilities": [],
            "malware_matches": [],
        }
    )

    assert summary.recommended_action == PolicyDecision.ALLOW_WITH_WARNING
    assert "Sandbox evidence is missing for this artifact." in summary.payload["limitations"]


@pytest.mark.asyncio
async def test_process_next_finalization_job_persists_summary_and_completes() -> None:
    job = build_job()
    repository = FakeRepository(
        job=job,
        inputs={
            "static_reports": [],
            "sandbox_runs": [],
            "ai_explanation": None,
            "vulnerabilities": [],
            "malware_matches": [{"indicator": "known-malicious", "confidence": "high"}],
        },
    )

    response = await process_next_finalization_job(repository)

    assert response == ProcessNextFinalizationJobResponse(
        processed=True,
        analysis_job_id=str(job.id),
        summary_id=str(repository.summary_id),
        state="completed",
        recommended_action=PolicyDecision.BLOCK_KNOWN_MALICIOUS,
        confidence="high",
        requires_hitl=False,
    )
    assert repository.persisted is not None
    assert repository.persisted[1].recommended_action == PolicyDecision.BLOCK_KNOWN_MALICIOUS
    assert repository.failed is None


@pytest.mark.asyncio
async def test_process_next_finalization_job_requeues_on_failure() -> None:
    job = build_job()
    repository = FakeRepository(job=job)

    async def raise_inputs(job: FinalizationJob) -> dict[str, Any]:
        raise RuntimeError("summary build failed")

    repository.load_finalization_inputs = raise_inputs  # type: ignore[method-assign]

    response = await process_next_finalization_job(repository, max_retries=4)

    assert response.processed is True
    assert response.state == "finalizing"
    assert response.summary_id is None
    assert repository.failed is not None
    assert repository.failed[1] == 4