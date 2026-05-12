from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SENSITIVE_METADATA_KEY_FRAGMENTS = (
    "api_key",
    "apikey",
    "auth_header",
    "authorization",
    "client_secret",
    "cookie",
    "credential",
    "password",
    "private_key",
    "secret",
    "session",
    "token",
)
SENSITIVE_METADATA_EXACT_KEYS = frozenset({"env", "environ", "environment"})
SAFE_REFERENCE_KEYS = frozenset({"credential_ref", "credential_id"})


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="before")
    @classmethod
    def reject_explicit_null_fields(cls, data: object) -> object:
        if isinstance(data, dict):
            null_fields = sorted(key for key, value in data.items() if value is None)
            if null_fields:
                joined = ", ".join(null_fields)
                raise ValueError(f"explicit null is not allowed for fields: {joined}")
        return data


class PackageEcosystem(StrEnum):
    NPM = "npm"
    PYPI = "pypi"
    CARGO = "cargo"
    MAVEN = "maven"
    DOCKER_OCI = "docker-oci"
    GENERIC_HTTP = "generic-http"


class PolicyDecision(StrEnum):
    ALLOW = "ALLOW"
    ALLOW_WITH_WARNING = "ALLOW_WITH_WARNING"
    QUARANTINE_PENDING_ANALYSIS = "QUARANTINE_PENDING_ANALYSIS"
    BLOCK_KNOWN_MALICIOUS = "BLOCK_KNOWN_MALICIOUS"
    BLOCK_POLICY_VIOLATION = "BLOCK_POLICY_VIOLATION"
    REQUIRE_HITL_APPROVAL = "REQUIRE_HITL_APPROVAL"
    FALLBACK_TO_APPROVED_CANDIDATE = "FALLBACK_TO_APPROVED_CANDIDATE"


class PolicyMode(StrEnum):
    SHADOW = "shadow"
    WARN = "warn"
    ENFORCE = "enforce"


class FeedState(StrEnum):
    FRESH = "fresh"
    STALE = "stale"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyRuleAction(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    QUARANTINE = "quarantine"
    BLOCK = "block"
    HITL = "hitl"
    FALLBACK = "fallback"


class AttestationResult(StrEnum):
    PASS = "pass"  # noqa: S105 - verification outcome, not a credential.
    FAIL = "fail"
    MISSING = "missing"
    UNVERIFIABLE = "unverifiable"


class SandboxProfile(StrEnum):
    NPM_INSTALL = "npm-install-profile"
    PYTHON_INSTALL = "python-install-profile"


class SandboxPhase(StrEnum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"
    G = "G"
    H = "H"


class EgressMode(StrEnum):
    DENY_ALL = "deny-all"
    REGISTRY_ONLY = "registry-only"
    MONITORED_PROXY = "monitored-proxy"


class ArtifactDigest(StrictModel):
    algorithm: Literal["sha256"]
    hex: str = Field(pattern=r"^[a-f0-9]{64}$")


class PackageCoordinate(StrictModel):
    ecosystem: PackageEcosystem
    name: Annotated[str, Field(min_length=1)]
    version: Annotated[str | None, Field(min_length=1)] = None
    namespace: Annotated[str | None, Field(min_length=1)] = None


class PolicyRule(StrictModel):
    id: Annotated[str, Field(min_length=1)]
    signal: Annotated[str, Field(min_length=1)]
    action: PolicyRuleAction
    enabled: Annotated[bool, Field(strict=True)]


class VulnerabilitySeverityFloor(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class KnownVulnerabilityThreshold(StrictModel):
    severity_floor: VulnerabilitySeverityFloor
    kev_override: Annotated[bool, Field(strict=True)]
    epss_probability_floor: Annotated[float | None, Field(ge=0, le=1)] = None


class ScorecardThresholds(StrictModel):
    code_review: Annotated[float | None, Field(ge=-1, le=10)] = None
    branch_protection: Annotated[float | None, Field(ge=-1, le=10)] = None
    ci_cd: Annotated[float | None, Field(ge=-1, le=10)] = None
    maintained: Annotated[float | None, Field(ge=-1, le=10)] = None
    signed_releases: Annotated[float | None, Field(ge=-1, le=10)] = None


class PolicyProfile(StrictModel):
    id: UUID
    tenant_id: UUID
    version: Annotated[str, Field(min_length=1)]
    mode: PolicyMode
    minimum_release_age_hours: Annotated[int, Field(ge=0, strict=True)]
    known_vulnerability_threshold: KnownVulnerabilityThreshold
    scorecard_thresholds: ScorecardThresholds | None = None
    fail_closed: Annotated[bool, Field(strict=True)]
    rules: list[PolicyRule]


class DecisionResponse(StrictModel):
    decision: PolicyDecision
    tenant_id: UUID
    policy_profile_id: UUID
    policy_snapshot_id: UUID
    mode: PolicyMode
    feed_state: FeedState
    feed_snapshot_age_seconds: Annotated[int, Field(ge=0, strict=True)]
    trace_id: Annotated[str, Field(min_length=1)]
    rationale: list[str]
    fallback_coordinate: PackageCoordinate | None = None
    create_analysis_job: Annotated[bool, Field(strict=True)]


class IndicatorDetails(StrictModel):
    destination: str | None = None
    destination_encoding: str | None = None
    destination_raw: str | None = None
    payload_hint: str | None = None


class StaticIndicator(StrictModel):
    indicator_type: Annotated[str, Field(min_length=1)]
    severity: Severity
    file_path: Annotated[str, Field(min_length=1)]
    start_line: Annotated[int, Field(ge=1, strict=True)]
    end_line: Annotated[int, Field(ge=1, strict=True)]
    redacted: Annotated[bool, Field(strict=True)]
    summary: Annotated[str, Field(min_length=1)]
    details: IndicatorDetails | None = None

    @model_validator(mode="after")
    def line_span_must_be_ordered(self) -> StaticIndicator:
        if self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")
        return self


class StaticEvidence(StrictModel):
    artifact_digest: ArtifactDigest
    analyzer_version: Annotated[str, Field(min_length=1)]
    rule_set_version: Annotated[str, Field(min_length=1)]
    indicators: list[StaticIndicator]


class SandboxTelemetryEvent(StrictModel):
    type: Annotated[str, Field(min_length=1)]
    severity: Severity
    message: Annotated[str, Field(min_length=1)]


class SandboxTelemetry(StrictModel):
    run_id: UUID
    profile: SandboxProfile
    phase: SandboxPhase
    egress_mode: EgressMode
    events: list[SandboxTelemetryEvent]


class AiExplanation(StrictModel):
    provider: Annotated[str, Field(min_length=1)]
    model: Annotated[str, Field(min_length=1)]
    prompt_template_version: Annotated[str, Field(min_length=1)]
    observed_behavior: list[str]
    inference: list[str]
    limitations: list[str]
    advisory_only: Literal[True]
    evidence_hash: ArtifactDigest
    output_hash: ArtifactDigest
    langfuse_trace_id: Annotated[str | None, Field(min_length=1)] = None


class AttestationEvidence(StrictModel):
    coordinate: PackageCoordinate
    artifact_digest: ArtifactDigest
    attestation_type: Annotated[str, Field(min_length=1)]
    predicate_type: Annotated[str, Field(min_length=1)]
    issuer: str
    subject_digest: ArtifactDigest
    result: AttestationResult
    verified_at: datetime
    verifier_version: Annotated[str, Field(min_length=1)]
    raw_document_digest: ArtifactDigest


class FeedSnapshot(StrictModel):
    id: UUID
    feed_name: Annotated[str, Field(min_length=1)]
    state: FeedState
    normalized_record_count: Annotated[int, Field(ge=0, strict=True)]
    snapshot_digest: ArtifactDigest
    last_success_at: datetime | None = None


class AuditEvent(StrictModel):
    id: UUID
    tenant_id: UUID
    actor: Annotated[str, Field(min_length=1)]
    action: Annotated[str, Field(min_length=1)]
    resource: Annotated[str, Field(min_length=1)]
    trace_id: Annotated[str, Field(min_length=1)]
    occurred_at: datetime
    metadata: dict[str, Any]

    @field_validator("metadata")
    @classmethod
    def metadata_must_not_contain_sensitive_keys(cls, metadata: dict[str, Any]) -> dict[str, Any]:
        sensitive_path = find_sensitive_metadata_path(metadata)
        if sensitive_path:
            raise ValueError(f"audit metadata contains sensitive key: {sensitive_path}")
        return metadata


def find_sensitive_metadata_path(value: Any, *, prefix: str = "metadata") -> str | None:
    if isinstance(value, dict):
        for key, nested in value.items():
            key_text = str(key)
            path = f"{prefix}.{key_text}"
            if is_sensitive_metadata_key(key_text):
                return path
            nested_path = find_sensitive_metadata_path(nested, prefix=path)
            if nested_path:
                return nested_path
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            nested_path = find_sensitive_metadata_path(nested, prefix=f"{prefix}[{index}]")
            if nested_path:
                return nested_path
    return None


def is_sensitive_metadata_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    if normalized in SAFE_REFERENCE_KEYS:
        return False
    return normalized in SENSITIVE_METADATA_EXACT_KEYS or any(
        fragment in normalized for fragment in SENSITIVE_METADATA_KEY_FRAGMENTS
    )
