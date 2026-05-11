from __future__ import annotations

import hashlib
import json
from typing import Any

from aegiscudo_common.contracts import AiExplanation, ArtifactDigest
from pydantic import BaseModel, ConfigDict, Field

from ai_analyst.redaction import redact_evidence


class AdvisoryPreviewRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    prompt_template_version: str = Field(min_length=1)
    evidence: dict[str, Any]
    langfuse_trace_id: str | None = Field(default=None, min_length=1)


class AdvisoryPreviewResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    redaction_complete: bool
    redacted_evidence: dict[str, Any]
    explanation: AiExplanation


def build_advisory_preview(request: AdvisoryPreviewRequest) -> AdvisoryPreviewResponse:
    redacted_evidence = redact_evidence(request.evidence)
    redaction_complete = redaction_is_complete(redacted_evidence)
    if not redaction_complete:
        raise ValueError("redaction incomplete; sensitive residue remains in evidence payload")

    observed_behavior = summarize_observed_behavior(redacted_evidence)
    inference = summarize_inference(observed_behavior)
    limitations = [
        "This preview is deterministic and advisory only; provider-backed reasoning is not enabled yet.",
        "The response reflects only the redacted evidence supplied to AI Analyst.",
    ]
    evidence_hash = sha256_digest(redacted_evidence)

    explanation_payload = {
        "provider": request.provider,
        "model": request.model,
        "prompt_template_version": request.prompt_template_version,
        "observed_behavior": observed_behavior,
        "inference": inference,
        "limitations": limitations,
        "advisory_only": True,
        "evidence_hash": evidence_hash.model_dump(mode="json"),
    }
    if request.langfuse_trace_id is not None:
        explanation_payload["langfuse_trace_id"] = request.langfuse_trace_id
    output_hash = sha256_digest(explanation_payload)
    explanation_payload["output_hash"] = output_hash.model_dump(mode="json")

    return AdvisoryPreviewResponse(
        redaction_complete=True,
        redacted_evidence=redacted_evidence,
        explanation=AiExplanation.model_validate(explanation_payload),
    )


def summarize_observed_behavior(redacted_evidence: dict[str, Any]) -> list[str]:
    observations: list[str] = []
    static_indicators = redacted_evidence.get("static_indicators")
    if isinstance(static_indicators, list):
        for indicator in static_indicators[:3]:
            if isinstance(indicator, dict):
                summary = indicator.get("summary")
                if isinstance(summary, str) and summary:
                    observations.append(summary)

    sandbox_events = redacted_evidence.get("sandbox_events")
    if isinstance(sandbox_events, list):
        for event in sandbox_events[:3]:
            if isinstance(event, dict):
                message = event.get("message")
                if isinstance(message, str) and message:
                    observations.append(message)

    if not observations:
        observations.append("No structured suspicious behavior was supplied in the redacted evidence.")
    return observations


def summarize_inference(observed_behavior: list[str]) -> list[str]:
    if any("credential" in observation.lower() or "token" in observation.lower() for observation in observed_behavior):
        return ["The redacted evidence suggests credential discovery or handling behavior that warrants follow-up review."]
    if any("network" in observation.lower() or "exfil" in observation.lower() for observation in observed_behavior):
        return ["The redacted evidence suggests outbound communication behavior that may indicate exfiltration or staging."]
    return ["The supplied evidence contains suspicious signals that should be reviewed alongside deterministic policy inputs."]


def redaction_is_complete(payload: Any) -> bool:
    if isinstance(payload, dict):
        return all(redaction_is_complete(value) for value in payload.values())
    if isinstance(payload, list):
        return all(redaction_is_complete(value) for value in payload)
    if isinstance(payload, str):
        lowered = payload.lower()
        forbidden_fragments = (
            "bearer ",
            "basic ",
            "_authtoken=",
            "api_key=",
            "client_secret=",
            "password=",
            "aws-secret-canary-001",
            "github-canary-token-001",
            "npm-canary-token-001",
            "pypi-canary-token-001",
        )
        return not any(fragment in lowered for fragment in forbidden_fragments)
    return True


def sha256_digest(payload: Any) -> ArtifactDigest:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return ArtifactDigest(algorithm="sha256", hex=hashlib.sha256(encoded).hexdigest())