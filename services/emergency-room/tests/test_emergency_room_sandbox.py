from pathlib import Path

import pytest
from aegiscudo_common.contracts import SandboxProfile
from emergency_room.app import app
from emergency_room.sandbox import infer_python_import_name, resolve_artifact_uri
from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[3]
NPM_FIXTURE = ROOT / "samples" / "malicious" / "npm" / "env-snoop" / "env-snoop-1.0.0.tgz"
AI_CANARY_FIXTURE = ROOT / "samples" / "malicious" / "npm" / "ai-canary-scribbler"
TIMEOUT_FIXTURE = ROOT / "samples" / "malicious" / "npm" / "timeout-sleeper"
PYPI_FIXTURE = ROOT / "samples" / "malicious" / "pypi" / "env-snoop" / "dist" / "env_snoop-1.0.0.tar.gz"
PYPI_TIMEOUT_FIXTURE = ROOT / "samples" / "malicious" / "pypi" / "timeout-sleeper"


def test_resolve_file_uri_and_import_name() -> None:
    resolved = resolve_artifact_uri(PYPI_FIXTURE.as_uri())
    assert resolved == PYPI_FIXTURE
    assert infer_python_import_name(PYPI_FIXTURE) == "env_snoop"


@pytest.mark.skipif(not NPM_FIXTURE.exists(), reason="npm fixture missing")
def test_local_npm_sandbox_detects_canary_exfiltration() -> None:
    if not shutil_which("npm"):
        pytest.skip("npm is not installed")

    response = TestClient(app).post(
        "/v1/sandbox/local-run",
        json={
            "profile": SandboxProfile.NPM_INSTALL.value,
            "artifact_uri": NPM_FIXTURE.as_uri(),
            "timeout_seconds": 30,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["violation_detected"] is True
    event_types = {
        event["type"]
        for phase in body["telemetry"]
        for event in phase["events"]
    }
    assert "outbound-network-attempt" in event_types
    assert "canary-secret-access" in event_types


@pytest.mark.skipif(not AI_CANARY_FIXTURE.exists(), reason="ai canary fixture missing")
def test_local_npm_sandbox_detects_ai_canary_file_modification() -> None:
    if not shutil_which("npm"):
        pytest.skip("npm is not installed")

    response = TestClient(app).post(
        "/v1/sandbox/local-run",
        json={
            "profile": SandboxProfile.NPM_INSTALL.value,
            "artifact_uri": AI_CANARY_FIXTURE.as_uri(),
            "timeout_seconds": 30,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["violation_detected"] is True
    ai_canary_events = [
        event
        for phase in body["telemetry"]
        for event in phase["events"]
        if event["type"] == "ai-canary-file-modified"
    ]
    assert ai_canary_events
    assert ".cursorrules" in ai_canary_events[0]["message"]
    assert ".github/copilot-instructions.md" in ai_canary_events[0]["message"]


@pytest.mark.skipif(not TIMEOUT_FIXTURE.exists(), reason="timeout fixture missing")
def test_local_npm_sandbox_records_timeout_event() -> None:
    if not shutil_which("npm"):
        pytest.skip("npm is not installed")

    response = TestClient(app).post(
        "/v1/sandbox/local-run",
        json={
            "profile": SandboxProfile.NPM_INSTALL.value,
            "artifact_uri": TIMEOUT_FIXTURE.as_uri(),
            "timeout_seconds": 1,
        },
    )

    assert response.status_code == 200
    body = response.json()
    event_types = {
        event["type"]
        for phase in body["telemetry"]
        for event in phase["events"]
    }
    assert "sandbox-timeout" in event_types


@pytest.mark.skipif(not PYPI_TIMEOUT_FIXTURE.exists(), reason="python timeout fixture missing")
def test_local_python_sandbox_records_timeout_event() -> None:
    response = TestClient(app).post(
        "/v1/sandbox/local-run",
        json={
            "profile": SandboxProfile.PYTHON_INSTALL.value,
            "artifact_uri": PYPI_TIMEOUT_FIXTURE.as_uri(),
            "import_name": "timeout_sleeper",
            "timeout_seconds": 1,
        },
    )

    assert response.status_code == 200
    body = response.json()
    event_types = {
        event["type"]
        for phase in body["telemetry"]
        for event in phase["events"]
    }
    assert "sandbox-timeout" in event_types


@pytest.mark.skipif(not PYPI_FIXTURE.exists(), reason="pypi fixture missing")
def test_local_python_sandbox_detects_canary_exfiltration() -> None:
    response = TestClient(app).post(
        "/v1/sandbox/local-run",
        json={
            "profile": SandboxProfile.PYTHON_INSTALL.value,
            "artifact_uri": PYPI_FIXTURE.as_uri(),
            "import_name": "env_snoop",
            "timeout_seconds": 45,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["violation_detected"] is True
    phases = {phase["phase"] for phase in body["telemetry"]}
    assert "D" in phases
    assert "G" in phases
    event_types = {
        event["type"]
        for phase in body["telemetry"]
        for event in phase["events"]
    }
    assert "outbound-network-attempt" in event_types
    assert "canary-secret-access" in event_types


def shutil_which(name: str) -> str | None:
    import shutil

    return shutil.which(name)