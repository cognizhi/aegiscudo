import importlib

emergency_room_app_module = importlib.import_module("emergency_room.app")

from emergency_room.app import app
from emergency_room.security import redact_mapping
from emergency_room.worker import ProcessNextSandboxJobResponse
from fastapi.testclient import TestClient


def test_healthz() -> None:
    response = TestClient(app).get("/healthz")
    assert response.status_code == 200
    assert response.json()["service"] == "emergency-room"
    assert response.headers["x-trace-id"]


def test_readyz_and_metrics() -> None:
    client = TestClient(app)

    ready = client.get("/readyz", headers={"x-trace-id": "trace-er"})
    metrics = client.get("/metrics")

    assert ready.status_code == 200
    assert ready.headers["x-trace-id"] == "trace-er"
    assert metrics.status_code == 200
    assert "aegiscudo_emergency_room_up" in metrics.text


def test_redaction_utility() -> None:
    assert redact_mapping({"token": "abc", "nested": {"private-key": "abc"}, "safe": "ok"}) == {
        "token": "[REDACTED]",
        "nested": {"private-key": "[REDACTED]"},
        "safe": "ok",
    }


def test_process_next_job_returns_503_when_database_is_unavailable(monkeypatch) -> None:
    async def fake_process_next_job_from_database() -> ProcessNextSandboxJobResponse:
        raise RuntimeError("DATABASE_URL is required to process sandbox jobs")

    monkeypatch.setattr(emergency_room_app_module, "process_next_sandbox_job_from_database", fake_process_next_job_from_database)

    response = TestClient(app).post("/v1/sandbox/process-next-job")

    assert response.status_code == 503
    assert response.json()["detail"] == "DATABASE_URL is required to process sandbox jobs"


def test_process_next_job_returns_worker_response(monkeypatch) -> None:
    async def fake_process_next_job_from_database() -> ProcessNextSandboxJobResponse:
        return ProcessNextSandboxJobResponse(
            processed=True,
            analysis_job_id="analysis-job-1",
            sandbox_run_id="sandbox-run-1",
            state="ai-pending",
            violation_detected=True,
        )

    monkeypatch.setattr(emergency_room_app_module, "process_next_sandbox_job_from_database", fake_process_next_job_from_database)

    response = TestClient(app).post("/v1/sandbox/process-next-job")

    assert response.status_code == 200
    assert response.json() == {
        "processed": True,
        "analysis_job_id": "analysis-job-1",
        "sandbox_run_id": "sandbox-run-1",
        "state": "ai-pending",
        "violation_detected": True,
    }