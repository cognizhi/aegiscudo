from aegiscudo_common.logging_config import configure_logging
from aegiscudo_common.service import install_request_context, metrics_text
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict

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