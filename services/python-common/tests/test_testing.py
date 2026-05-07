from __future__ import annotations

import httpx
from aegiscudo_common.contracts import SandboxPhase, SandboxProfile, SandboxTelemetryEvent
from aegiscudo_common.logging_config import REDACTED
from aegiscudo_common.testing import FakeHttpFeed, FakeLlmProvider, FakeSandboxJobRunner


def test_fake_http_feed_returns_registered_routes() -> None:
    feed = FakeHttpFeed({"/osv": {"vulns": []}})

    with feed.client() as client:
        response = client.get("/osv")

    assert response.json() == {"vulns": []}
    assert feed.requests == ["/osv"]


def test_fake_http_feed_returns_404_for_unregistered_routes() -> None:
    feed = FakeHttpFeed({})

    with httpx.Client(transport=feed.transport(), base_url="https://fixture.local") as client:
        response = client.get("/missing")

    assert response.status_code == 404


async def test_fake_llm_provider_records_redacted_prompt() -> None:
    provider = FakeLlmProvider()
    explanation = await provider.explain({"observed": "Authorization: Bearer secret-token"})

    assert explanation.advisory_only is True
    assert provider.prompts[0]["observed"] == f"Authorization: {REDACTED}"


async def test_fake_sandbox_job_runner_returns_schema_aligned_telemetry() -> None:
    runner = FakeSandboxJobRunner()
    telemetry = await runner.run(
        profile=SandboxProfile.NPM_INSTALL,
        phase=SandboxPhase.E,
        events=[
            SandboxTelemetryEvent(
                type="canary-read",
                severity="critical",
                message="fixture accessed fake token",
            )
        ],
    )

    assert telemetry.profile == SandboxProfile.NPM_INSTALL
    assert telemetry.phase == SandboxPhase.E
    assert telemetry.events[0].type == "canary-read"
