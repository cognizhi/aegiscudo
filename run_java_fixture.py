import sys
import os
from pathlib import Path

ROOT = Path("/home/cyyeong/ws/cognizhi/aegiscudo")
sys.path.append(str(ROOT / "services" / "emergency-room" / "src"))
sys.path.append(str(ROOT / "services" / "python-common" / "src"))

try:
    from emergency_room.app import app
    from fastapi.testclient import TestClient
    from aegiscudo_common.contracts import SandboxProfile
except ImportError as e:
    print(f"Import Error: {e}")
    sys.exit(1)

JAVA_FIXTURE = ROOT / "samples" / "malicious" / "java" / "env-snoop" / "target" / "env-snoop-1.0.0.jar"

client = TestClient(app)
if not JAVA_FIXTURE.exists():
    print(f"Fixture not found at {JAVA_FIXTURE}")
    sys.exit(1)

# Using "java_run" profile as it's the likely name for Java sandbox
response = client.post(
    "/v1/sandbox/local-run",
    json={
        "profile": "java_run",
        "artifact_uri": JAVA_FIXTURE.as_uri(),
        "timeout_seconds": 60,
    },
)

if response.status_code != 200:
    print(f"Error: {response.status_code}")
    print(response.text)
else:
    body = response.json()
    # Handle both potential telemetry formats
    telemetry = body.get("telemetry", [])
    if isinstance(telemetry, dict):
        events = telemetry.get("events", [])
    else:
        events = [event for phase in telemetry for event in phase.get("events", [])]
        
    event_types = sorted(list({event["type"] for event in events}))
    print(f"Event Types: {event_types}")
    
    for event in events:
        if event["type"] == "outbound-network-attempt":
            print(f"Outbound Network Attempt: {event.get('message', 'No message')}")
