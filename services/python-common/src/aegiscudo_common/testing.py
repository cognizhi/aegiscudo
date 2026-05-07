from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any
from uuid import UUID, uuid4

import httpx

from aegiscudo_common.contracts import (
    AiExplanation,
    ArtifactDigest,
    EgressMode,
    SandboxPhase,
    SandboxProfile,
    SandboxTelemetry,
    SandboxTelemetryEvent,
)
from aegiscudo_common.logging_config import REDACTED, redact_sensitive_data


class FakeHttpFeed:
    def __init__(self, routes: Mapping[str, Any]) -> None:
        self.routes = dict(routes)
        self.requests: list[str] = []

    def transport(self) -> httpx.MockTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            self.requests.append(path)
            if path not in self.routes:
                return httpx.Response(404, json={"error": "fixture route not found"})
            return httpx.Response(200, json=self.routes[path])

        return httpx.MockTransport(handler)

    def client(self, base_url: str = "https://fixtures.aegiscudo.local") -> httpx.Client:
        return httpx.Client(base_url=base_url, transport=self.transport())


class FakeLlmProvider:
    def __init__(self, *, provider: str = "fake-local", model: str = "fixture-model") -> None:
        self.provider = provider
        self.model = model
        self.prompts: list[Mapping[str, Any]] = []

    async def explain(self, evidence: Mapping[str, Any]) -> AiExplanation:
        redacted = redact_sensitive_data(dict(evidence))
        self.prompts.append(redacted)
        output = {
            "observed_behavior": ["fixture evidence accepted"],
            "inference": ["fixture provider does not infer maliciousness"],
            "limitations": ["fake provider is for deterministic tests only"],
        }
        return AiExplanation(
            provider=self.provider,
            model=self.model,
            prompt_template_version="fixture-v1",
            observed_behavior=output["observed_behavior"],
            inference=output["inference"],
            limitations=output["limitations"],
            advisory_only=True,
            evidence_hash=sha256_digest(redacted),
            output_hash=sha256_digest(output),
            langfuse_trace_id="fixture-trace",
        )


class FakeSandboxJobRunner:
    async def run(
        self,
        *,
        profile: SandboxProfile,
        phase: SandboxPhase = SandboxPhase.A,
        egress_mode: EgressMode = EgressMode.DENY_ALL,
        events: Sequence[SandboxTelemetryEvent] = (),
        run_id: UUID | None = None,
    ) -> SandboxTelemetry:
        return SandboxTelemetry(
            run_id=run_id or uuid4(),
            profile=profile,
            phase=phase,
            egress_mode=egress_mode,
            events=list(events),
        )


def sha256_digest(payload: Any) -> ArtifactDigest:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return ArtifactDigest(algorithm="sha256", hex=hashlib.sha256(serialized.encode()).hexdigest())


def has_redacted_value(payload: Any) -> bool:
    if payload == REDACTED:
        return True
    if isinstance(payload, Mapping):
        return any(has_redacted_value(value) for value in payload.values())
    if isinstance(payload, list | tuple):
        return any(has_redacted_value(value) for value in payload)
    return False
