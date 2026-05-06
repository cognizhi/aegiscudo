use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use uuid::Uuid;

pub type Metadata = BTreeMap<String, serde_json::Value>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PackageEcosystem {
    Npm,
    Pypi,
    Cargo,
    Maven,
    DockerOci,
    GenericHttp,
}

impl fmt::Display for PackageEcosystem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Npm => "npm",
            Self::Pypi => "pypi",
            Self::Cargo => "cargo",
            Self::Maven => "maven",
            Self::DockerOci => "docker-oci",
            Self::GenericHttp => "generic-http",
        };
        formatter.write_str(value)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("unsupported package ecosystem: {0}")]
pub struct ParsePackageEcosystemError(String);

impl FromStr for PackageEcosystem {
    type Err = ParsePackageEcosystemError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "npm" => Ok(Self::Npm),
            "pypi" => Ok(Self::Pypi),
            "cargo" => Ok(Self::Cargo),
            "maven" => Ok(Self::Maven),
            "docker-oci" => Ok(Self::DockerOci),
            "generic-http" => Ok(Self::GenericHttp),
            other => Err(ParsePackageEcosystemError(other.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct PackageCoordinate {
    pub ecosystem: PackageEcosystem,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

impl PackageCoordinate {
    pub fn new(
        ecosystem: PackageEcosystem,
        name: impl Into<String>,
        version: Option<impl Into<String>>,
        namespace: Option<impl Into<String>>,
    ) -> Self {
        Self {
            ecosystem,
            name: name.into(),
            version: version.map(Into::into),
            namespace: namespace.map(Into::into),
        }
    }

    pub fn purl(&self) -> String {
        let package_path = match &self.namespace {
            Some(namespace) if !namespace.is_empty() => format!("{namespace}/{}", self.name),
            _ => self.name.clone(),
        };
        match &self.version {
            Some(version) => format!("pkg:{}/{package_path}@{version}", self.ecosystem),
            None => format!("pkg:{}/{package_path}", self.ecosystem),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DigestAlgorithm {
    Sha256,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DigestError {
    #[error("sha256 digest must contain exactly 64 hex characters")]
    InvalidSha256Length,
    #[error("digest contains non-hex characters")]
    InvalidHex,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, JsonSchema)]
pub struct ArtifactDigest {
    pub algorithm: DigestAlgorithm,
    pub hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ArtifactDigestRepr {
    algorithm: DigestAlgorithm,
    hex: String,
}

impl ArtifactDigest {
    pub fn new(
        algorithm: DigestAlgorithm,
        hex_value: impl AsRef<str>,
    ) -> Result<Self, DigestError> {
        let normalized = hex_value.as_ref().to_ascii_lowercase();
        match algorithm {
            DigestAlgorithm::Sha256 => {
                if normalized.len() != 64 {
                    return Err(DigestError::InvalidSha256Length);
                }
            }
        }
        if !normalized
            .chars()
            .all(|character| character.is_ascii_hexdigit())
        {
            return Err(DigestError::InvalidHex);
        }
        Ok(Self {
            algorithm,
            hex: normalized,
        })
    }

    pub fn sha256(hex_value: impl AsRef<str>) -> Result<Self, DigestError> {
        Self::new(DigestAlgorithm::Sha256, hex_value)
    }
}

impl Serialize for ArtifactDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ArtifactDigestRepr {
            algorithm: self.algorithm.clone(),
            hex: self.hex.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ArtifactDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = ArtifactDigestRepr::deserialize(deserializer)?;
        ArtifactDigest::new(repr.algorithm, repr.hex).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum PolicyDecision {
    #[serde(rename = "ALLOW")]
    Allow,
    #[serde(rename = "ALLOW_WITH_WARNING")]
    AllowWithWarning,
    #[serde(rename = "QUARANTINE_PENDING_ANALYSIS")]
    QuarantinePendingAnalysis,
    #[serde(rename = "BLOCK_KNOWN_MALICIOUS")]
    BlockKnownMalicious,
    #[serde(rename = "BLOCK_POLICY_VIOLATION")]
    BlockPolicyViolation,
    #[serde(rename = "REQUIRE_HITL_APPROVAL")]
    RequireHitlApproval,
    #[serde(rename = "FALLBACK_TO_APPROVED_CANDIDATE")]
    FallbackToApprovedCandidate,
}

impl PolicyDecision {
    pub fn is_blocking(&self) -> bool {
        matches!(
            self,
            Self::QuarantinePendingAnalysis
                | Self::BlockKnownMalicious
                | Self::BlockPolicyViolation
                | Self::RequireHitlApproval
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PolicySnapshot {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub version: String,
    pub effective_at: DateTime<Utc>,
    pub immutable_rule_hash: ArtifactDigest,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AuditEvent {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub actor: String,
    pub action: String,
    pub resource: String,
    pub trace_id: String,
    pub occurred_at: DateTime<Utc>,
    #[serde(default)]
    pub metadata: Metadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum JobState {
    Queued,
    Fetching,
    StaticRunning,
    SandboxPending,
    SandboxRunning,
    AiPending,
    Finalizing,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AnalysisJob {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub coordinate: PackageCoordinate,
    pub artifact_digest: ArtifactDigest,
    pub policy_snapshot_id: Uuid,
    pub state: JobState,
    pub retry_count: u16,
    pub trace_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StaticIndicator {
    pub indicator_type: String,
    pub severity: Severity,
    pub file_path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub redacted: bool,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StaticEvidence {
    pub artifact_digest: ArtifactDigest,
    pub analyzer_version: String,
    pub rule_set_version: String,
    pub indicators: Vec<StaticIndicator>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SandboxEvidence {
    pub artifact_digest: ArtifactDigest,
    pub sandbox_profile: String,
    pub observed_verdict: String,
    pub telemetry_digest: ArtifactDigest,
    pub canary_events: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AiExplanation {
    pub provider: String,
    pub model: String,
    pub prompt_template_version: String,
    pub observed_behavior: Vec<String>,
    pub inference: Vec<String>,
    pub limitations: Vec<String>,
    pub advisory_only: bool,
    pub evidence_hash: ArtifactDigest,
    pub output_hash: ArtifactDigest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub langfuse_trace_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum AttestationResult {
    Pass,
    Fail,
    Missing,
    Unverifiable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AttestationEvidence {
    pub coordinate: PackageCoordinate,
    pub artifact_digest: ArtifactDigest,
    pub attestation_type: String,
    pub predicate_type: String,
    pub issuer: String,
    pub subject_digest: ArtifactDigest,
    pub result: AttestationResult,
    pub verified_at: DateTime<Utc>,
    pub verifier_version: String,
    pub raw_document_digest: ArtifactDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum FeedState {
    Fresh,
    Stale,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FeedSnapshot {
    pub id: Uuid,
    pub feed_name: String,
    pub state: FeedState,
    pub normalized_record_count: u64,
    pub last_success_at: Option<DateTime<Utc>>,
    pub snapshot_digest: ArtifactDigest,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_digest() -> ArtifactDigest {
        ArtifactDigest::sha256("a".repeat(64)).expect("valid digest")
    }

    #[test]
    fn package_coordinate_has_purl() {
        let coordinate = PackageCoordinate::new(
            PackageEcosystem::Npm,
            "left-pad",
            Some("1.3.0"),
            Some("scope"),
        );
        assert_eq!(coordinate.purl(), "pkg:npm/scope/left-pad@1.3.0");
    }

    #[test]
    fn digest_validation_rejects_bad_sha256() {
        assert_eq!(
            ArtifactDigest::sha256("1234").unwrap_err(),
            DigestError::InvalidSha256Length
        );
        assert_eq!(
            ArtifactDigest::sha256(format!("{}z", "a".repeat(63))).unwrap_err(),
            DigestError::InvalidHex
        );
    }

    #[test]
    fn serde_rejects_invalid_ecosystem_and_decision() {
        assert!(serde_json::from_str::<PackageEcosystem>("\"rubygems\"").is_err());
        assert!(serde_json::from_str::<PolicyDecision>("\"BLOCK_UNKNOWN\"").is_err());
    }

    #[test]
    fn serde_rejects_missing_required_ids() {
        let missing_snapshot_id = serde_json::json!({
            "tenant_id": Uuid::now_v7(),
            "version": "2026.05.0",
            "effective_at": Utc::now(),
            "immutable_rule_hash": sample_digest(),
        });
        let snapshot_err = serde_json::from_value::<PolicySnapshot>(missing_snapshot_id)
            .expect_err("policy snapshot should require id");
        assert!(snapshot_err.to_string().contains("id"));

        let missing_audit_tenant_id = serde_json::json!({
            "id": Uuid::now_v7(),
            "actor": "platform-admin",
            "action": "credential.rotate",
            "resource": "integration:github",
            "trace_id": "trace-001",
            "occurred_at": Utc::now(),
            "metadata": {},
        });
        let audit_err = serde_json::from_value::<AuditEvent>(missing_audit_tenant_id)
            .expect_err("audit event should require tenant_id");
        assert!(audit_err.to_string().contains("tenant_id"));

        let missing_analysis_policy_snapshot_id = serde_json::json!({
            "id": Uuid::now_v7(),
            "tenant_id": Uuid::now_v7(),
            "coordinate": {
                "ecosystem": "npm",
                "name": "left-pad",
            },
            "artifact_digest": sample_digest(),
            "state": "queued",
            "retry_count": 0,
            "trace_id": "trace-002",
            "created_at": Utc::now(),
            "updated_at": Utc::now(),
        });
        let analysis_err = serde_json::from_value::<AnalysisJob>(missing_analysis_policy_snapshot_id)
            .expect_err("analysis job should require policy_snapshot_id");
        assert!(analysis_err.to_string().contains("policy_snapshot_id"));

        let missing_feed_snapshot_id = serde_json::json!({
            "feed_name": "osv",
            "state": "fresh",
            "normalized_record_count": 10,
            "last_success_at": Utc::now(),
            "snapshot_digest": sample_digest(),
        });
        let feed_err = serde_json::from_value::<FeedSnapshot>(missing_feed_snapshot_id)
            .expect_err("feed snapshot should require id");
        assert!(feed_err.to_string().contains("id"));
    }

    #[test]
    fn dto_round_trip_serializes_decision_names() {
        let snapshot = PolicySnapshot {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            version: "2026.05.0".to_owned(),
            effective_at: Utc::now(),
            immutable_rule_hash: sample_digest(),
        };
        let json = serde_json::to_string(&snapshot).expect("serialize snapshot");
        let decoded: PolicySnapshot = serde_json::from_str(&json).expect("deserialize snapshot");
        assert_eq!(snapshot, decoded);

        let decision = serde_json::to_string(&PolicyDecision::RequireHitlApproval).unwrap();
        assert_eq!(decision, "\"REQUIRE_HITL_APPROVAL\"");
    }
}
