from ai_analyst.app import app
from ai_analyst.redaction import redact_evidence
from fastapi.testclient import TestClient


def test_healthz() -> None:
    response = TestClient(app).get("/healthz")
    assert response.status_code == 200
    assert response.json()["evidence_boundary"] == "redacted-only"
    assert response.headers["x-trace-id"]


def test_readyz_and_metrics() -> None:
    client = TestClient(app)

    ready = client.get("/readyz", headers={"x-trace-id": "trace-ai"})
    metrics = client.get("/metrics")

    assert ready.status_code == 200
    assert ready.headers["x-trace-id"] == "trace-ai"
    assert metrics.status_code == 200
    assert "aegiscudo_ai_analyst_up" in metrics.text


def test_redaction_utility() -> None:
    assert redact_evidence(
        {"api_key": "abc", "headers": [{"Authorization": "Bearer token"}], "safe": "ok"}
    ) == {
        "api_key": "[REDACTED]",
        "headers": [{"Authorization": "[REDACTED]"}],
        "safe": "ok",
    }