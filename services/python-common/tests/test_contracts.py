from __future__ import annotations

import json
from pathlib import Path

import pytest
from aegiscudo_common.contracts import (
    AiExplanation,
    ArtifactDigest,
    AttestationEvidence,
    AuditEvent,
    DecisionResponse,
    FeedSnapshot,
    PolicyProfile,
    SandboxTelemetry,
    StaticEvidence,
    StaticIndicator,
)
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "schemas" / "fixtures"


def load_fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text())


@pytest.mark.parametrize(
    ("model", "fixture_name"),
    [
        (PolicyProfile, "policy.default.json"),
        (DecisionResponse, "decision.allow.json"),
        (StaticEvidence, "evidence.static.json"),
        (SandboxTelemetry, "sandbox-telemetry.canary.json"),
        (AiExplanation, "ai-explanation.advisory.json"),
        (AttestationEvidence, "attestation-evidence.missing.json"),
        (FeedSnapshot, "feed-snapshot.osv.json"),
        (AuditEvent, "audit-event.registry-create.json"),
    ],
)
def test_schema_fixtures_load_into_contract_models(model: type, fixture_name: str) -> None:
    assert model.model_validate(load_fixture(fixture_name))


def test_digest_rejects_non_sha256_hex() -> None:
    with pytest.raises(ValidationError):
        ArtifactDigest(algorithm="sha256", hex="z" * 64)

    with pytest.raises(ValidationError):
        ArtifactDigest(algorithm="sha256", hex="A" * 64)


def test_contract_models_reject_unknown_fields() -> None:
    payload = load_fixture("decision.allow.json")
    payload["credential_value"] = "must-not-be-accepted"

    with pytest.raises(ValidationError):
        DecisionResponse.model_validate(payload)


def test_contract_models_reject_schema_invalid_coercions_and_nulls() -> None:
    payload = load_fixture("decision.allow.json")
    payload["feed_snapshot_age_seconds"] = "60"

    with pytest.raises(ValidationError):
        DecisionResponse.model_validate(payload)

    payload = load_fixture("decision.fallback.json")
    payload["fallback_coordinate"] = None

    with pytest.raises(ValidationError):
        DecisionResponse.model_validate(payload)


def test_policy_profile_requires_explicit_fail_closed() -> None:
    payload = load_fixture("policy.default.json")
    del payload["fail_closed"]

    with pytest.raises(ValidationError):
        PolicyProfile.model_validate(payload)


def test_policy_profile_accepts_scorecard_thresholds() -> None:
    payload = load_fixture("policy.default.json")
    payload["scorecard_thresholds"] = {
        "code_review": 9.5,
        "branch_protection": 8.0,
        "ci_cd": 9.0,
        "maintained": 7.0,
        "signed_releases": -1.0,
    }

    policy = PolicyProfile.model_validate(payload)

    assert policy.scorecard_thresholds is not None
    assert policy.scorecard_thresholds.branch_protection == 8.0


def test_policy_profile_rejects_null_scorecard_threshold_value() -> None:
    payload = load_fixture("policy.default.json")
    payload["scorecard_thresholds"] = {"code_review": None}

    with pytest.raises(ValidationError):
        PolicyProfile.model_validate(payload)


def test_audit_event_rejects_sensitive_metadata_keys() -> None:
    payload = load_fixture("audit-event.registry-create.json")
    payload["metadata"] = {"credential_ref": "id-only", "credential_value": "raw-value"}

    with pytest.raises(ValidationError):
        AuditEvent.model_validate(payload)

    payload = load_fixture("audit-event.registry-create.json")
    payload["metadata"] = {"credential_ref": "id-only", "safe": "value"}

    assert AuditEvent.model_validate(payload)

    payload = load_fixture("audit-event.registry-create.json")
    payload["metadata"] = {"nested": [{"Authorization": "Bearer value"}]}

    with pytest.raises(ValidationError):
        AuditEvent.model_validate(payload)


def test_ai_explanation_must_be_advisory_only() -> None:
    payload = load_fixture("ai-explanation.advisory.json")
    payload["advisory_only"] = False

    with pytest.raises(ValidationError):
        AiExplanation.model_validate(payload)


def test_static_indicator_requires_ordered_line_span() -> None:
    with pytest.raises(ValidationError):
        StaticIndicator(
            indicator_type="eval",
            severity="high",
            file_path="index.js",
            start_line=10,
            end_line=2,
            redacted=True,
            summary="bad span",
        )
