from emergency_room.app import app
from emergency_room.security import redact_mapping
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