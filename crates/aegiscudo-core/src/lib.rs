use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use uuid::Uuid;

pub type Metadata = BTreeMap<String, serde_json::Value>;

const SENSITIVE_METADATA_KEY_FRAGMENTS: &[&str] = &[
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
];
const SENSITIVE_METADATA_EXACT_KEYS: &[&str] = &["env", "environ", "environment"];
const SAFE_REFERENCE_KEYS: &[&str] = &["credential_ref", "credential_id"];

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PackageEcosystem {
    Npm,
    Pypi,
    Cargo,
    Maven,
    DockerOci,
    GenericHttp,
    #[serde(rename = "githubactions")]
    GithubActions,
    VscodeExtension,
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
            Self::GithubActions => "githubactions",
            Self::VscodeExtension => "vscode-extension",
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
            "githubactions" => Ok(Self::GithubActions),
            "vscode-extension" => Ok(Self::VscodeExtension),
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyMode {
    Shadow,
    Warn,
    #[default]
    Enforce,
}

pub fn default_fail_closed() -> bool {
    true
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
    #[serde(default, deserialize_with = "deserialize_audit_metadata")]
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
    pub registry_config_id: Uuid,
    pub coordinate: PackageCoordinate,
    pub artifact_digest: ArtifactDigest,
    pub source_url: String,
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

/// Contextual details extracted near a network-related indicator match.
/// All fields are optional — absent means the information could not be determined.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct IndicatorDetails {
    /// Destination URL or host:port found in the surrounding code context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    /// How the destination was recovered: `"plaintext"`, `"base64-decoded"`, or `"url-decoded"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_encoding: Option<String>,
    /// The raw (pre-decode) form of the destination when decoding was applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_raw: Option<String>,
    /// Hint about the data being transmitted, inferred from surrounding context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_hint: Option<String>,
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
    /// Contextual details extracted near the match — destination, payload hint, encoding.
    /// Present only for network-related indicators where context could be extracted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<IndicatorDetails>,
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
    #[serde(
        serialize_with = "serialize_advisory_only",
        deserialize_with = "deserialize_advisory_only"
    )]
    pub advisory_only: bool,
    pub evidence_hash: ArtifactDigest,
    pub output_hash: ArtifactDigest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub langfuse_trace_id: Option<String>,
}

fn deserialize_audit_metadata<'de, D>(deserializer: D) -> Result<Metadata, D::Error>
where
    D: Deserializer<'de>,
{
    let metadata = Metadata::deserialize(deserializer)?;
    validate_audit_metadata(&metadata).map_err(D::Error::custom)?;
    Ok(metadata)
}

pub fn validate_audit_metadata(metadata: &Metadata) -> Result<(), String> {
    if let Some(path) = find_sensitive_metadata_path(metadata, "metadata") {
        return Err(format!("audit metadata contains sensitive key: {path}"));
    }
    Ok(())
}

fn find_sensitive_metadata_path(value: &Metadata, prefix: &str) -> Option<String> {
    for (key, nested) in value {
        let path = format!("{prefix}.{key}");
        if is_sensitive_metadata_key(key) {
            return Some(path);
        }
        if let Some(nested_path) = find_sensitive_metadata_value_path(nested, &path) {
            return Some(nested_path);
        }
    }
    None
}

fn find_sensitive_metadata_value_path(value: &serde_json::Value, prefix: &str) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, nested) in map {
                let path = format!("{prefix}.{key}");
                if is_sensitive_metadata_key(key) {
                    return Some(path);
                }
                if let Some(nested_path) = find_sensitive_metadata_value_path(nested, &path) {
                    return Some(nested_path);
                }
            }
            None
        }
        serde_json::Value::Array(items) => items.iter().enumerate().find_map(|(index, nested)| {
            find_sensitive_metadata_value_path(nested, &format!("{prefix}[{index}]"))
        }),
        _ => None,
    }
}

fn is_sensitive_metadata_key(key: &str) -> bool {
    let normalized = key.to_lowercase().replace('-', "_");
    if SAFE_REFERENCE_KEYS.contains(&normalized.as_str()) {
        return false;
    }
    SENSITIVE_METADATA_EXACT_KEYS.contains(&normalized.as_str())
        || SENSITIVE_METADATA_KEY_FRAGMENTS
            .iter()
            .any(|fragment| normalized.contains(fragment))
}

fn serialize_advisory_only<S>(_value: &bool, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bool(true)
}

fn deserialize_advisory_only<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let value = bool::deserialize(deserializer)?;
    if value {
        Ok(true)
    } else {
        Err(D::Error::custom("advisory_only must be true"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum AttestationResult {
    Pass,
    Fail,
    Missing,
    Unverifiable,
}

pub const SLSA_VSA_PREDICATE_TYPE: &str = "https://slsa.dev/verification_summary/v1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AttestationEvidenceValidationError {
    #[error("SLSA and VSA fields require a passing attestation result")]
    SlsaFieldsRequirePassingResult,
    #[error("SLSA build level must match the highest supported SLSA Build Track level")]
    SlsaBuildLevelMismatch,
    #[error("VSA fields require predicate_type https://slsa.dev/verification_summary/v1")]
    VsaFieldsRequireVsaPredicate,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub slsa_verified_levels: Vec<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_slsa_build_level_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub slsa_build_level: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slsa_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vsa_verifier_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vsa_resource_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vsa_policy_uri: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vsa_dependency_levels: BTreeMap<String, u64>,
}

impl AttestationEvidence {
    pub fn validate_slsa_fields(&self) -> Result<(), AttestationEvidenceValidationError> {
        if self.has_slsa_or_vsa_fields() && self.result != AttestationResult::Pass {
            return Err(AttestationEvidenceValidationError::SlsaFieldsRequirePassingResult);
        }

        if let Some(level) = self.slsa_build_level {
            if slsa_build_level_from_verified_levels(&self.slsa_verified_levels) != Some(level) {
                return Err(AttestationEvidenceValidationError::SlsaBuildLevelMismatch);
            }
        }

        if self.has_vsa_fields() && self.predicate_type != SLSA_VSA_PREDICATE_TYPE {
            return Err(AttestationEvidenceValidationError::VsaFieldsRequireVsaPredicate);
        }

        Ok(())
    }

    fn has_slsa_or_vsa_fields(&self) -> bool {
        !self.slsa_verified_levels.is_empty()
            || self.slsa_build_level.is_some()
            || self.slsa_version.is_some()
            || self.has_vsa_fields()
    }

    fn has_vsa_fields(&self) -> bool {
        self.vsa_verifier_id.is_some()
            || self.vsa_resource_uri.is_some()
            || self.vsa_policy_uri.is_some()
            || !self.vsa_dependency_levels.is_empty()
    }
}

fn deserialize_slsa_build_level_option<'de, D>(deserializer: D) -> Result<Option<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<u8>::deserialize(deserializer)?;
    match value {
        Some(level) if level > 3 => Err(D::Error::custom(
            "slsa_build_level must be an integer from 0 through 3",
        )),
        _ => Ok(value),
    }
}

pub fn slsa_build_level_from_verified_levels<I, S>(verified_levels: I) -> Option<u8>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    verified_levels
        .into_iter()
        .filter_map(|level| slsa_build_level_from_verified_level(level.as_ref()))
        .max()
}

fn slsa_build_level_from_verified_level(level: &str) -> Option<u8> {
    let value = level.strip_prefix("SLSA_BUILD_LEVEL_")?;
    if value == "UNEVALUATED" {
        return None;
    }
    let parsed = value.parse::<u8>().ok()?;
    (parsed <= 3).then_some(parsed)
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
        assert_eq!(
            PackageEcosystem::from_str("vscode-extension").unwrap(),
            PackageEcosystem::VscodeExtension
        );
        assert!(serde_json::from_str::<PackageEcosystem>("\"rubygems\"").is_err());
        assert!(serde_json::from_str::<PolicyDecision>("\"BLOCK_UNKNOWN\"").is_err());
    }

    #[test]
    fn slsa_build_level_parser_uses_highest_supported_build_level() {
        assert_eq!(
            slsa_build_level_from_verified_levels([
                "SLSA_BUILD_LEVEL_1",
                "SLSA_BUILD_LEVEL_3",
                "SLSA_SOURCE_LEVEL_4",
            ]),
            Some(3)
        );
        assert_eq!(
            slsa_build_level_from_verified_levels(["SLSA_BUILD_LEVEL_0"]),
            Some(0)
        );
        assert_eq!(
            slsa_build_level_from_verified_levels([
                "SLSA_BUILD_LEVEL_UNEVALUATED",
                "FAILED",
                "CUSTOM_BUILD_LEVEL_4",
                "SLSA_BUILD_LEVEL_4",
            ]),
            None
        );
    }

    #[test]
    fn attestation_evidence_rejects_out_of_range_slsa_build_level() {
        let payload = r#"{
            "coordinate": { "ecosystem": "npm", "name": "left-pad", "version": "1.3.0" },
            "artifact_digest": { "algorithm": "sha256", "hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
            "attestation_type": "slsa-verification-summary",
            "predicate_type": "https://slsa.dev/verification_summary/v1",
            "issuer": "https://verifier.aegiscudo.local",
            "subject_digest": { "algorithm": "sha256", "hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
            "result": "pass",
            "verified_at": "2026-05-18T00:00:00Z",
            "verifier_version": "0.1.0",
            "raw_document_digest": { "algorithm": "sha256", "hex": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
            "slsa_verified_levels": ["SLSA_BUILD_LEVEL_4"],
            "slsa_build_level": 4
        }"#;

        assert!(serde_json::from_str::<AttestationEvidence>(payload).is_err());
    }

    #[test]
    fn attestation_evidence_validates_slsa_field_consistency() {
        let mut evidence: AttestationEvidence = serde_json::from_str(include_str!(
            "../../../schemas/fixtures/attestation-evidence.slsa-vsa.json"
        ))
        .expect("fixture should deserialize");

        assert!(evidence.validate_slsa_fields().is_ok());

        evidence.result = AttestationResult::Fail;
        assert_eq!(
            evidence.validate_slsa_fields(),
            Err(AttestationEvidenceValidationError::SlsaFieldsRequirePassingResult)
        );

        evidence.result = AttestationResult::Pass;
        evidence.slsa_build_level = Some(2);
        assert_eq!(
            evidence.validate_slsa_fields(),
            Err(AttestationEvidenceValidationError::SlsaBuildLevelMismatch)
        );

        evidence.slsa_build_level = Some(3);
        evidence.predicate_type = "https://slsa.dev/provenance/v1".to_owned();
        assert_eq!(
            evidence.validate_slsa_fields(),
            Err(AttestationEvidenceValidationError::VsaFieldsRequireVsaPredicate)
        );
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
            "registry_config_id": Uuid::now_v7(),
            "coordinate": {
                "ecosystem": "npm",
                "name": "left-pad",
            },
            "artifact_digest": sample_digest(),
            "source_url": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            "state": "queued",
            "retry_count": 0,
            "trace_id": "trace-002",
            "created_at": Utc::now(),
            "updated_at": Utc::now(),
        });
        let analysis_err =
            serde_json::from_value::<AnalysisJob>(missing_analysis_policy_snapshot_id)
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

        let mode = serde_json::to_string(&PolicyMode::Enforce).unwrap();
        assert_eq!(mode, "\"enforce\"");
        assert!(default_fail_closed());
    }

    #[test]
    fn audit_metadata_rejects_sensitive_keys_recursively() {
        let event = serde_json::json!({
            "id": Uuid::now_v7(),
            "tenant_id": Uuid::now_v7(),
            "actor": "platform-admin@example.com",
            "action": "registry_config.created",
            "resource": "registry_config/npm-public",
            "trace_id": "trace-audit",
            "occurred_at": Utc::now(),
            "metadata": { "nested": [{ "Authorization": "Bearer value" }] },
        });

        let error = serde_json::from_value::<AuditEvent>(event)
            .expect_err("audit event should reject sensitive metadata keys");
        assert!(
            error
                .to_string()
                .contains("metadata.nested[0].Authorization")
        );

        let allowed = serde_json::json!({
            "id": Uuid::now_v7(),
            "tenant_id": Uuid::now_v7(),
            "actor": "platform-admin@example.com",
            "action": "registry_config.created",
            "resource": "registry_config/npm-public",
            "trace_id": "trace-audit",
            "occurred_at": Utc::now(),
            "metadata": { "credential_ref": "00000000-0000-0000-0000-000000000501" },
        });

        assert!(serde_json::from_value::<AuditEvent>(allowed).is_ok());
    }

    #[test]
    fn ai_explanation_is_always_advisory_only() {
        let false_advisory = serde_json::json!({
            "provider": "fixture",
            "model": "fixture-model",
            "prompt_template_version": "v1",
            "observed_behavior": [],
            "inference": [],
            "limitations": [],
            "advisory_only": false,
            "evidence_hash": sample_digest(),
            "output_hash": sample_digest(),
        });
        let error = serde_json::from_value::<AiExplanation>(false_advisory)
            .expect_err("AI explanations should require advisory_only true");
        assert!(error.to_string().contains("advisory_only must be true"));

        let explanation = AiExplanation {
            provider: "fixture".to_owned(),
            model: "fixture-model".to_owned(),
            prompt_template_version: "v1".to_owned(),
            observed_behavior: vec![],
            inference: vec![],
            limitations: vec![],
            advisory_only: false,
            evidence_hash: sample_digest(),
            output_hash: sample_digest(),
            langfuse_trace_id: None,
        };
        let serialized = serde_json::to_value(explanation).expect("serialize explanation");
        assert_eq!(serialized["advisory_only"], true);
    }
}
