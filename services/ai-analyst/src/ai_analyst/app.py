from aegiscudo_common.config import load_workspace_env_file
from aegiscudo_common.logging_config import configure_logging
from aegiscudo_common.service import install_request_context, metrics_text
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict

from ai_analyst.advisory import AdvisoryPreviewRequest, AdvisoryPreviewResponse, build_advisory_preview
from ai_analyst.finalizer import (
    ProcessNextFinalizationJobResponse,
    process_next_finalization_job_from_database,
)
from ai_analyst.worker import ProcessNextAiJobResponse, process_next_ai_job_from_database

load_workspace_env_file()
configure_logging("ai-analyst")


class HealthResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: str
    service: str
    evidence_boundary: str


app = FastAPI(title="Aegiscudo AI Analyst", version="0.1.0")
install_request_context(app)


@app.get("/healthz", response_model=HealthResponse)
async def healthz() -> HealthResponse:
    return HealthResponse(status="ok", service="ai-analyst", evidence_boundary="redacted-only")


@app.get("/readyz", response_model=HealthResponse)
async def readyz() -> HealthResponse:
    return HealthResponse(status="ok", service="ai-analyst", evidence_boundary="redacted-only")


@app.get("/metrics", response_class=PlainTextResponse)
async def metrics() -> str:
    return metrics_text("ai-analyst")


@app.post("/v1/explanations/advisory-preview", response_model=AdvisoryPreviewResponse)
async def advisory_preview(request: AdvisoryPreviewRequest) -> AdvisoryPreviewResponse:
    try:
        return build_advisory_preview(request)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@app.post("/v1/explanations/process-next-job", response_model=ProcessNextAiJobResponse)
async def process_next_job() -> ProcessNextAiJobResponse:
    try:
        return await process_next_ai_job_from_database()
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error


@app.post("/v1/analysis/process-next-finalization-job", response_model=ProcessNextFinalizationJobResponse)
async def process_next_finalization_job() -> ProcessNextFinalizationJobResponse:
    try:
        return await process_next_finalization_job_from_database()
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error