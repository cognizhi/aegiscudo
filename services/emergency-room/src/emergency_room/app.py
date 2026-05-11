from aegiscudo_common.logging_config import configure_logging
from aegiscudo_common.service import install_request_context, metrics_text
from fastapi import FastAPI
from fastapi import HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict

from emergency_room.sandbox import LocalSandboxRunRequest, LocalSandboxRunResponse, run_sandbox_profile
from emergency_room.worker import (
    ProcessNextSandboxJobResponse,
    process_next_sandbox_job_from_database,
)

configure_logging("emergency-room")


class HealthResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: str
    service: str
    sandbox_boundary: str


app = FastAPI(title="Aegiscudo Emergency Room", version="0.1.0")
install_request_context(app)


@app.get("/healthz", response_model=HealthResponse)
async def healthz() -> HealthResponse:
    return HealthResponse(status="ok", service="emergency-room", sandbox_boundary="local-mock")


@app.get("/readyz", response_model=HealthResponse)
async def readyz() -> HealthResponse:
    return HealthResponse(status="ok", service="emergency-room", sandbox_boundary="local-mock")


@app.get("/metrics", response_class=PlainTextResponse)
async def metrics() -> str:
    return metrics_text("emergency-room")


@app.post("/v1/sandbox/local-run", response_model=LocalSandboxRunResponse)
async def sandbox_local_run(request: LocalSandboxRunRequest) -> LocalSandboxRunResponse:
    return await run_sandbox_profile(request)


@app.post("/v1/sandbox/process-next-job", response_model=ProcessNextSandboxJobResponse)
async def sandbox_process_next_job() -> ProcessNextSandboxJobResponse:
    try:
        return await process_next_sandbox_job_from_database()
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error