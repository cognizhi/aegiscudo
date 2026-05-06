from aegiscudo_common.logging_config import configure_logging
from aegiscudo_common.service import install_request_context, metrics_text
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict

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