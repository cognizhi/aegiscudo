use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use aegiscudo_core::{
    AnalysisJob, ArtifactDigest, AttestationResult, DigestError, FeedState, JobState,
    PackageCoordinate, PolicyDecision, PolicyMode, PolicySnapshot, Severity, StaticEvidence,
};
use aegiscudo_policy::{PolicyInput, SignalPolicyAction, VulnerabilityPolicyAction};
use aegiscudo_protocol::{DecisionRequest, DecisionResponse, PackageRequestKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row, postgres::PgPoolOptions, types::Json};
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

const MVP_FEED_NAMES: &[&str] = &[
    "osv",
    "ghsa",
    "openssf-malicious-packages",
    "cisa-kev",
    "first-epss",
    "deps.dev",
    "openssf-scorecard",
];
const FRESH_FEED_MAX_AGE_SECONDS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, PartialEq)]
pub struct LoadedPolicyProfile {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub mode: PolicyMode,
    pub latest_snapshot: PolicySnapshot,
    pub signal_configuration: PolicySignalConfiguration,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PolicySignalConfiguration {
    pub known_vulnerability_threshold: KnownVulnerabilityThreshold,
    pub vulnerable_above_threshold_action: VulnerabilityPolicyAction,
    pub scorecard: ScorecardPolicyConfiguration,
}

impl Default for PolicySignalConfiguration {
    fn default() -> Self {
        Self {
            known_vulnerability_threshold: KnownVulnerabilityThreshold::default(),
            vulnerable_above_threshold_action: VulnerabilityPolicyAction::Warn,
            scorecard: ScorecardPolicyConfiguration::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScorecardPolicyConfiguration {
    pub code_review: ScorecardCheckPolicy,
    pub branch_protection: ScorecardCheckPolicy,
    pub ci_cd: ScorecardCheckPolicy,
    pub maintained: ScorecardCheckPolicy,
    pub signed_releases: ScorecardCheckPolicy,
}

impl Default for ScorecardPolicyConfiguration {
    fn default() -> Self {
        Self {
            code_review: ScorecardCheckPolicy::default(),
            branch_protection: ScorecardCheckPolicy::default(),
            ci_cd: ScorecardCheckPolicy::default(),
            maintained: ScorecardCheckPolicy::default(),
            signed_releases: ScorecardCheckPolicy::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScorecardCheckPolicy {
    pub min_score: f64,
    pub action: SignalPolicyAction,
}

impl Default for ScorecardCheckPolicy {
    fn default() -> Self {
        Self {
            min_score: 10.0,
            action: SignalPolicyAction::Warn,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct KnownVulnerabilityThreshold {
    pub severity_floor: VulnerabilitySeverity,
    pub kev_override: bool,
    pub epss_probability_floor: Option<f64>,
}

impl Default for KnownVulnerabilityThreshold {
    fn default() -> Self {
        Self {
            severity_floor: VulnerabilitySeverity::High,
            kev_override: true,
            epss_probability_floor: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VulnerabilitySeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
struct PolicyDocumentSignalConfiguration {
    known_vulnerability_threshold: PolicyDocumentKnownVulnerabilityThreshold,
    #[serde(default)]
    scorecard_thresholds: PolicyDocumentScorecardThresholds,
    #[serde(default)]
    rules: Vec<PolicyDocumentRule>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
struct PolicyDocumentKnownVulnerabilityThreshold {
    severity_floor: VulnerabilitySeverity,
    kev_override: bool,
    #[serde(default)]
    epss_probability_floor: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
struct PolicyDocumentScorecardThresholds {
    #[serde(default = "default_scorecard_min_score")]
    code_review: f64,
    #[serde(default = "default_scorecard_min_score")]
    branch_protection: f64,
    #[serde(default = "default_scorecard_min_score")]
    ci_cd: f64,
    #[serde(default = "default_scorecard_min_score")]
    maintained: f64,
    #[serde(default = "default_scorecard_min_score")]
    signed_releases: f64,
}

impl Default for PolicyDocumentScorecardThresholds {
    fn default() -> Self {
        Self {
            code_review: default_scorecard_min_score(),
            branch_protection: default_scorecard_min_score(),
            ci_cd: default_scorecard_min_score(),
            maintained: default_scorecard_min_score(),
            signed_releases: default_scorecard_min_score(),
        }
    }
}

fn default_scorecard_min_score() -> f64 {
    10.0
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct PolicyDocumentRule {
    signal: String,
    action: PolicyDocumentRuleAction,
    enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum PolicyDocumentRuleAction {
    Allow,
    Warn,
    Quarantine,
    Block,
    Hitl,
    Fallback,
}

impl PolicyDocumentRuleAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Quarantine => "quarantine",
            Self::Block => "block",
            Self::Hitl => "hitl",
            Self::Fallback => "fallback",
        }
    }
}

impl VulnerabilitySeverity {
    fn from_db(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct VulnerabilityMatchRecord {
    severity: Option<VulnerabilitySeverity>,
    epss_probability: Option<f64>,
    cisa_kev: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AttestationSignalStatus {
    missing_or_failed_attestation: bool,
    provenance_or_signature_verification_failed: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct OverrideSignalStatus {
    active_override: bool,
    emergency_bypass: bool,
    hitl_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OverrideRecord {
    tenant_id: Uuid,
    scope: Value,
    status: String,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct PackageSignalStatus {
    minimum_release_age_violation: bool,
    install_script_detected: bool,
    dependency_confusion_risk: bool,
    typosquat_risk: bool,
    artifact_digest_reputation_risk: bool,
    github_to_registry_publish_gap_risk: bool,
    trusted_publisher_identity_mismatch: bool,
    scorecard_code_review_risk: bool,
    scorecard_branch_protection_risk: bool,
    scorecard_ci_cd_risk: bool,
    scorecard_maintained_risk: bool,
    scorecard_signed_releases_risk: bool,
    maintainer_account_age_risk: bool,
    recent_maintainer_change_risk: bool,
    new_maintainer_ratio_risk: bool,
    known_malicious: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
struct ScorecardSignalStatus {
    code_review_risk: bool,
    branch_protection_risk: bool,
    ci_cd_risk: bool,
    maintained_risk: bool,
    signed_releases_risk: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PackageSignalRecord {
    tenant_id: Uuid,
    coordinate: PackageCoordinate,
    artifact_digest: Option<ArtifactDigest>,
    signal: String,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq)]
struct DepsDevPackageRecord {
    coordinate: PackageCoordinate,
    project_links: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq)]
struct ScorecardResultRecord {
    repo_name: String,
    checks: Vec<(String, f64)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FeedSnapshotRecord {
    feed_name: String,
    state: FeedState,
    last_success_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FeedSnapshotStatus {
    state: FeedState,
    age_seconds: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PolicySnapshotDraft {
    pub tenant_id: Uuid,
    pub policy_profile_id: Uuid,
    pub version: String,
    pub document: Value,
    pub created_by: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryPolicyBinding {
    pub tenant_id: Uuid,
    pub registry_config_id: Uuid,
    pub policy_profile_id: Uuid,
    pub mode: PolicyMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedPackageRequest {
    pub registry_config_id: Uuid,
    pub client_type: String,
    pub coordinate: PackageCoordinate,
    pub source_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PersistedDecisionRecord {
    pub tenant_id: Uuid,
    pub package_request: PersistedPackageRequest,
    pub artifact_digest: Option<ArtifactDigest>,
    pub policy_snapshot_id: Uuid,
    pub decision: PolicyDecision,
    pub feed_state: FeedState,
    pub feed_snapshot_age_seconds: u64,
    pub rationale: Vec<String>,
    pub evidence_references: Vec<String>,
    pub trace_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct DecisionPersistencePayload {
    rationale: Vec<String>,
    coordinate: PackageCoordinate,
    requested_digest: Option<ArtifactDigest>,
    evidence_references: Vec<String>,
}

#[derive(Debug, Error)]
pub enum PolicyRepositoryError {
    #[error("policy profile was not found")]
    ProfileNotFound,
    #[error("policy profile has no immutable policy snapshot")]
    SnapshotNotFound,
    #[error("policy profile mode is invalid")]
    InvalidPolicyMode,
    #[error("registry configuration was not found")]
    RegistryConfigNotFound,
    #[error("decision request does not match its normalized request context")]
    InconsistentDecisionRequest,
    #[error("decision request policy profile does not match registry configuration")]
    RegistryPolicyMismatch,
    #[error("policy document could not be serialized for hashing")]
    InvalidPolicyDocument(#[from] serde_json::Error),
    #[error("policy snapshot hash is invalid")]
    InvalidSnapshotHash(#[from] DigestError),
    #[error("decision response does not match the decision request context")]
    InconsistentDecisionResponse,
    #[error("feed snapshot age exceeds supported persistence range")]
    InvalidFeedSnapshotAge,
    #[error("analysis job requires an artifact digest")]
    MissingArtifactDigestForAnalysisJob,
    #[error("analysis job requires a source URL")]
    MissingArtifactSourceUrlForAnalysisJob,
    #[error("policy rule action `{action}` is not supported for signal `{signal}`")]
    UnsupportedPolicyRuleAction { signal: String, action: String },
    #[error("policy repository is unavailable")]
    Database(#[from] sqlx::Error),
}

#[derive(Debug, Clone)]
pub enum PolicyRepository {
    Postgres(PostgresPolicyRepository),
    InMemory(InMemoryPolicyRepository),
}

impl PolicyRepository {
    pub async fn bind_decision_request(
        &self,
        request: DecisionRequest,
    ) -> Result<PolicyInput, PolicyRepositoryError> {
        self.bind_request(request, false).await
    }

    pub async fn bind_simulation_request(
        &self,
        request: DecisionRequest,
    ) -> Result<PolicyInput, PolicyRepositoryError> {
        self.bind_request(request, true).await
    }

    async fn bind_request(
        &self,
        request: DecisionRequest,
        allow_profile_override: bool,
    ) -> Result<PolicyInput, PolicyRepositoryError> {
        if request.tenant_id != request.request.tenant_id
            || request.registry_config_id != request.request.registry_config_id
            || request.policy_profile_id != request.request.policy_profile_id
        {
            return Err(PolicyRepositoryError::InconsistentDecisionRequest);
        }
        let binding = self
            .load_registry_policy_binding(request.tenant_id, request.registry_config_id)
            .await?;
        if !allow_profile_override && binding.policy_profile_id != request.policy_profile_id {
            return Err(PolicyRepositoryError::RegistryPolicyMismatch);
        }
        let profile = self
            .load_profile(request.tenant_id, request.policy_profile_id)
            .await?;
        let artifact_exists = match &request.request.requested_digest {
            Some(artifact_digest) => {
                self.load_artifact_exists(request.tenant_id, artifact_digest)
                    .await?
            }
            None => false,
        };
        let package_signal_status = self
            .load_package_signal_status(
                request.tenant_id,
                &request.request.coordinate,
                request.request.requested_digest.as_ref(),
                &profile.signal_configuration.scorecard,
            )
            .await?;
        let known_malicious = package_signal_status.known_malicious
            || self
                .load_known_malicious_match(
                    request.tenant_id,
                    &request.request.coordinate,
                    request.request.requested_digest.as_ref(),
                )
                .await?;
        let feed_snapshot_status = self.load_feed_snapshot_status(request.tenant_id).await?;
        let known_safe_verdict = self
            .load_known_safe_verdict(
                request.tenant_id,
                &request.request.coordinate,
                request.request.requested_digest.as_ref(),
            )
            .await?;
        let vulnerable_above_threshold = self
            .load_vulnerable_above_threshold(
                request.tenant_id,
                &request.request.coordinate,
                request.request.requested_digest.as_ref(),
                &profile.signal_configuration.known_vulnerability_threshold,
            )
            .await?;
        let attestation_signal_status = self
            .load_attestation_signal_status(
                request.tenant_id,
                &request.request.coordinate,
                request.request.requested_digest.as_ref(),
            )
            .await?;
        let static_analysis_score_violation = self
            .load_static_analysis_score_violation(
                request.tenant_id,
                &request.request.coordinate,
                request.request.requested_digest.as_ref(),
            )
            .await?;
        let dynamic_sandbox_policy_violation = self
            .load_dynamic_sandbox_policy_violation(
                request.tenant_id,
                &request.request.coordinate,
                request.request.requested_digest.as_ref(),
            )
            .await?;
        let ai_agent_injection_indicator = self
            .load_ai_agent_injection_indicator(
                request.tenant_id,
                &request.request.coordinate,
                request.request.requested_digest.as_ref(),
            )
            .await?;
        let override_signal_status = self
            .load_override_signal_status(
                request.tenant_id,
                &request.request.coordinate,
                request.request.requested_digest.as_ref(),
                &request.request.kind,
            )
            .await?;
        let fallback_candidate = if matches!(request.request.kind, PackageRequestKind::Metadata)
            && !request.request.explicit_version_or_integrity
            && request.request.coordinate.ecosystem == aegiscudo_core::PackageEcosystem::Npm
        {
            self.load_fallback_candidate(request.tenant_id, &request.request.coordinate)
                .await?
        } else {
            None
        };
        Ok(PolicyInput {
            tenant_id: request.tenant_id,
            policy_profile_id: request.policy_profile_id,
            policy_snapshot_id: profile.latest_snapshot.id,
            coordinate: request.request.coordinate,
            trace_id: request.request.trace_id,
            mode: profile.mode,
            known_safe_verdict,
            known_malicious,
            vulnerable_above_threshold,
            vulnerable_above_threshold_action: profile
                .signal_configuration
                .vulnerable_above_threshold_action,
            minimum_release_age_violation: package_signal_status.minimum_release_age_violation,
            install_script_detected: package_signal_status.install_script_detected,
            dependency_confusion_risk: package_signal_status.dependency_confusion_risk,
            typosquat_risk: package_signal_status.typosquat_risk,
            artifact_digest_reputation_risk: package_signal_status.artifact_digest_reputation_risk,
            cross_ecosystem_ioc_correlation_risk: false,
            static_analysis_score_violation,
            dynamic_sandbox_policy_violation,
            github_to_registry_publish_gap_risk: package_signal_status
                .github_to_registry_publish_gap_risk,
            trusted_publisher_identity_mismatch: package_signal_status
                .trusted_publisher_identity_mismatch,
            scorecard_code_review_risk: package_signal_status.scorecard_code_review_risk,
            scorecard_branch_protection_risk: package_signal_status
                .scorecard_branch_protection_risk,
            scorecard_ci_cd_risk: package_signal_status.scorecard_ci_cd_risk,
            scorecard_maintained_risk: package_signal_status.scorecard_maintained_risk,
            scorecard_signed_releases_risk: package_signal_status
                .scorecard_signed_releases_risk,
            scorecard_code_review_action: profile.signal_configuration.scorecard.code_review.action,
            scorecard_branch_protection_action: profile
                .signal_configuration
                .scorecard
                .branch_protection
                .action,
            scorecard_ci_cd_action: profile.signal_configuration.scorecard.ci_cd.action,
            scorecard_maintained_action: profile.signal_configuration.scorecard.maintained.action,
            scorecard_signed_releases_action: profile
                .signal_configuration
                .scorecard
                .signed_releases
                .action,
            provenance_or_signature_verification_failed: attestation_signal_status
                .provenance_or_signature_verification_failed,
            missing_or_failed_attestation: attestation_signal_status.missing_or_failed_attestation,
            ai_agent_injection_indicator,
            maintainer_account_age_risk: package_signal_status.maintainer_account_age_risk,
            recent_maintainer_change_risk: package_signal_status.recent_maintainer_change_risk,
            new_maintainer_ratio_risk: package_signal_status.new_maintainer_ratio_risk,
            unknown_artifact: request.request.requested_digest.is_some() && !artifact_exists,
            hitl_required: override_signal_status.hitl_required,
            active_override: override_signal_status.active_override,
            emergency_bypass: override_signal_status.emergency_bypass,
            fallback_eligible: fallback_candidate.is_some(),
            fallback_candidate,
            feed_state: feed_snapshot_status.state,
            feed_snapshot_age_seconds: feed_snapshot_status.age_seconds,
        })
    }

    pub async fn load_profile(
        &self,
        tenant_id: Uuid,
        policy_profile_id: Uuid,
    ) -> Result<LoadedPolicyProfile, PolicyRepositoryError> {
        match self {
            Self::Postgres(repository) => {
                repository.load_profile(tenant_id, policy_profile_id).await
            }
            Self::InMemory(repository) => {
                repository.load_profile(tenant_id, policy_profile_id).await
            }
        }
    }

    pub async fn create_snapshot(
        &self,
        draft: PolicySnapshotDraft,
    ) -> Result<PolicySnapshot, PolicyRepositoryError> {
        match self {
            Self::Postgres(repository) => repository.create_snapshot(draft).await,
            Self::InMemory(repository) => repository.create_snapshot(draft).await,
        }
    }

    pub async fn load_registry_policy_binding(
        &self,
        tenant_id: Uuid,
        registry_config_id: Uuid,
    ) -> Result<RegistryPolicyBinding, PolicyRepositoryError> {
        match self {
            Self::Postgres(repository) => {
                repository
                    .load_registry_policy_binding(tenant_id, registry_config_id)
                    .await
            }
            Self::InMemory(repository) => {
                repository
                    .load_registry_policy_binding(tenant_id, registry_config_id)
                    .await
            }
        }
    }

    pub async fn persist_decision_record(
        &self,
        request: &DecisionRequest,
        response: &DecisionResponse,
    ) -> Result<(), PolicyRepositoryError> {
        match self {
            Self::Postgres(repository) => {
                repository.persist_decision_record(request, response).await
            }
            Self::InMemory(repository) => {
                repository.persist_decision_record(request, response).await
            }
        }
    }

    pub async fn create_analysis_job_if_needed(
        &self,
        request: &DecisionRequest,
        response: &DecisionResponse,
    ) -> Result<Option<AnalysisJob>, PolicyRepositoryError> {
        match self {
            Self::Postgres(repository) => {
                repository
                    .create_analysis_job_if_needed(request, response)
                    .await
            }
            Self::InMemory(repository) => {
                repository
                    .create_analysis_job_if_needed(request, response)
                    .await
            }
        }
    }

    async fn load_artifact_exists(
        &self,
        tenant_id: Uuid,
        artifact_digest: &ArtifactDigest,
    ) -> Result<bool, PolicyRepositoryError> {
        match self {
            Self::Postgres(repository) => {
                repository
                    .load_artifact_exists(tenant_id, artifact_digest)
                    .await
            }
            Self::InMemory(repository) => {
                repository
                    .load_artifact_exists(tenant_id, artifact_digest)
                    .await
            }
        }
    }

    async fn load_known_malicious_match(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
    ) -> Result<bool, PolicyRepositoryError> {
        match self {
            Self::Postgres(repository) => {
                repository
                    .load_known_malicious_match(tenant_id, coordinate, artifact_digest)
                    .await
            }
            Self::InMemory(repository) => {
                repository
                    .load_known_malicious_match(tenant_id, coordinate, artifact_digest)
                    .await
            }
        }
    }

    async fn load_package_signal_status(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
        scorecard_policy: &ScorecardPolicyConfiguration,
    ) -> Result<PackageSignalStatus, PolicyRepositoryError> {
        match self {
            Self::Postgres(repository) => {
                repository
                    .load_package_signal_status(
                        tenant_id,
                        coordinate,
                        artifact_digest,
                        scorecard_policy,
                    )
                    .await
            }
            Self::InMemory(repository) => {
                repository
                    .load_package_signal_status(
                        tenant_id,
                        coordinate,
                        artifact_digest,
                        scorecard_policy,
                    )
                    .await
            }
        }
    }

    async fn load_feed_snapshot_status(
        &self,
        tenant_id: Uuid,
    ) -> Result<FeedSnapshotStatus, PolicyRepositoryError> {
        match self {
            Self::Postgres(repository) => repository.load_feed_snapshot_status(tenant_id).await,
            Self::InMemory(repository) => repository.load_feed_snapshot_status(tenant_id).await,
        }
    }

    async fn load_fallback_candidate(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
    ) -> Result<Option<PackageCoordinate>, PolicyRepositoryError> {
        match self {
            Self::Postgres(repository) => {
                repository
                    .load_fallback_candidate(tenant_id, coordinate)
                    .await
            }
            Self::InMemory(repository) => {
                repository
                    .load_fallback_candidate(tenant_id, coordinate)
                    .await
            }
        }
    }

    async fn load_known_safe_verdict(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
    ) -> Result<bool, PolicyRepositoryError> {
        match self {
            Self::Postgres(repository) => {
                repository
                    .load_known_safe_verdict(tenant_id, coordinate, artifact_digest)
                    .await
            }
            Self::InMemory(repository) => {
                repository
                    .load_known_safe_verdict(tenant_id, coordinate, artifact_digest)
                    .await
            }
        }
    }

    async fn load_vulnerable_above_threshold(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
        threshold: &KnownVulnerabilityThreshold,
    ) -> Result<bool, PolicyRepositoryError> {
        match self {
            Self::Postgres(repository) => {
                repository
                    .load_vulnerable_above_threshold(
                        tenant_id,
                        coordinate,
                        artifact_digest,
                        threshold,
                    )
                    .await
            }
            Self::InMemory(repository) => {
                repository
                    .load_vulnerable_above_threshold(
                        tenant_id,
                        coordinate,
                        artifact_digest,
                        threshold,
                    )
                    .await
            }
        }
    }

    async fn load_attestation_signal_status(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
    ) -> Result<AttestationSignalStatus, PolicyRepositoryError> {
        match self {
            Self::Postgres(repository) => {
                repository
                    .load_attestation_signal_status(tenant_id, coordinate, artifact_digest)
                    .await
            }
            Self::InMemory(repository) => {
                repository
                    .load_attestation_signal_status(tenant_id, coordinate, artifact_digest)
                    .await
            }
        }
    }

    async fn load_ai_agent_injection_indicator(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
    ) -> Result<bool, PolicyRepositoryError> {
        match self {
            Self::Postgres(repository) => {
                repository
                    .load_ai_agent_injection_indicator(tenant_id, coordinate, artifact_digest)
                    .await
            }
            Self::InMemory(repository) => {
                repository
                    .load_ai_agent_injection_indicator(tenant_id, coordinate, artifact_digest)
                    .await
            }
        }
    }

    async fn load_static_analysis_score_violation(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
    ) -> Result<bool, PolicyRepositoryError> {
        match self {
            Self::Postgres(repository) => {
                repository
                    .load_static_analysis_score_violation(tenant_id, coordinate, artifact_digest)
                    .await
            }
            Self::InMemory(repository) => {
                repository
                    .load_static_analysis_score_violation(tenant_id, coordinate, artifact_digest)
                    .await
            }
        }
    }

    async fn load_dynamic_sandbox_policy_violation(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
    ) -> Result<bool, PolicyRepositoryError> {
        match self {
            Self::Postgres(repository) => {
                repository
                    .load_dynamic_sandbox_policy_violation(tenant_id, coordinate, artifact_digest)
                    .await
            }
            Self::InMemory(repository) => {
                repository
                    .load_dynamic_sandbox_policy_violation(tenant_id, coordinate, artifact_digest)
                    .await
            }
        }
    }

    async fn load_override_signal_status(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
        kind: &PackageRequestKind,
    ) -> Result<OverrideSignalStatus, PolicyRepositoryError> {
        match self {
            Self::Postgres(repository) => {
                repository
                    .load_override_signal_status(tenant_id, coordinate, artifact_digest, kind)
                    .await
            }
            Self::InMemory(repository) => {
                repository
                    .load_override_signal_status(tenant_id, coordinate, artifact_digest, kind)
                    .await
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct PostgresPolicyRepository {
    pool: PgPool,
}

impl PostgresPolicyRepository {
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn load_profile(
        &self,
        tenant_id: Uuid,
        policy_profile_id: Uuid,
    ) -> Result<LoadedPolicyProfile, PolicyRepositoryError> {
        let profile_row = sqlx::query(
            r#"
            SELECT id, tenant_id, mode::text AS mode
            FROM policy_profiles
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(policy_profile_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(PolicyRepositoryError::ProfileNotFound)?;

        let snapshot_row = sqlx::query(
            r#"
            SELECT id, tenant_id, version, effective_at, immutable_rule_hash, document
            FROM policy_versions
            WHERE tenant_id = $1 AND policy_profile_id = $2
            ORDER BY effective_at DESC, version DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(policy_profile_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(PolicyRepositoryError::SnapshotNotFound)?;

        Ok(LoadedPolicyProfile {
            id: profile_row.try_get("id")?,
            tenant_id: profile_row.try_get("tenant_id")?,
            mode: policy_mode_from_db(profile_row.try_get("mode")?)?,
            latest_snapshot: policy_snapshot_from_row(&snapshot_row)?,
            signal_configuration: policy_signal_configuration_from_document(
                &snapshot_row.try_get::<Value, _>("document")?,
            )?,
        })
    }

    async fn create_snapshot(
        &self,
        draft: PolicySnapshotDraft,
    ) -> Result<PolicySnapshot, PolicyRepositoryError> {
        sqlx::query(
            r#"
            SELECT 1
            FROM policy_profiles
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(draft.tenant_id)
        .bind(draft.policy_profile_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(PolicyRepositoryError::ProfileNotFound)?;

        let immutable_rule_hash = immutable_rule_hash(&draft.document)?;
        let row = sqlx::query(
            r#"
            INSERT INTO policy_versions (
              tenant_id, policy_profile_id, version, immutable_rule_hash, document, created_by
            ) VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, tenant_id, version, effective_at, immutable_rule_hash
            "#,
        )
        .bind(draft.tenant_id)
        .bind(draft.policy_profile_id)
        .bind(draft.version)
        .bind(immutable_rule_hash.hex)
        .bind(draft.document)
        .bind(draft.created_by)
        .fetch_one(&self.pool)
        .await?;

        policy_snapshot_from_row(&row)
    }

    async fn load_registry_policy_binding(
        &self,
        tenant_id: Uuid,
        registry_config_id: Uuid,
    ) -> Result<RegistryPolicyBinding, PolicyRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT tenant_id, id, policy_profile_id, mode::text AS mode
            FROM registry_configs
            WHERE tenant_id = $1 AND id = $2 AND enabled = true AND deleted_at IS NULL
            "#,
        )
        .bind(tenant_id)
        .bind(registry_config_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(PolicyRepositoryError::RegistryConfigNotFound)?;

        Ok(RegistryPolicyBinding {
            tenant_id: row.try_get("tenant_id")?,
            registry_config_id: row.try_get("id")?,
            policy_profile_id: row.try_get("policy_profile_id")?,
            mode: policy_mode_from_db(row.try_get("mode")?)?,
        })
    }

    async fn persist_decision_record(
        &self,
        request: &DecisionRequest,
        response: &DecisionResponse,
    ) -> Result<(), PolicyRepositoryError> {
        let record = persisted_decision_record(request, response)?;
        let mut transaction = self.pool.begin().await?;

        let package_request_row = sqlx::query(
            r#"
            INSERT INTO package_requests (
              tenant_id,
              registry_config_id,
              client_type,
              ecosystem,
              namespace,
              package_name,
              package_version,
              trace_id
            )
            VALUES ($1, $2, $3, $4::package_ecosystem, $5, $6, $7, $8)
            RETURNING id
            "#,
        )
        .bind(record.tenant_id)
        .bind(record.package_request.registry_config_id)
        .bind(&record.package_request.client_type)
        .bind(record.package_request.coordinate.ecosystem.to_string())
        .bind(record.package_request.coordinate.namespace.clone())
        .bind(record.package_request.coordinate.name.clone())
        .bind(record.package_request.coordinate.version.clone())
        .bind(&record.trace_id)
        .fetch_one(&mut *transaction)
        .await?;
        let package_request_id: Uuid = package_request_row.try_get("id")?;

        let artifact_id: Option<Uuid> = match &record.artifact_digest {
            Some(artifact_digest) => {
                let row = sqlx::query(
                    r#"
                    SELECT id
                    FROM artifacts
                    WHERE tenant_id = $1 AND sha256 = $2
                    "#,
                )
                .bind(record.tenant_id)
                .bind(&artifact_digest.hex)
                .fetch_optional(&mut *transaction)
                .await?;
                row.map(|artifact_row| artifact_row.try_get("id"))
                    .transpose()?
            }
            None => None,
        };

        sqlx::query(
            r#"
            INSERT INTO policy_decisions (
              tenant_id,
              package_request_id,
              artifact_id,
              policy_version_id,
              decision,
              feed_state,
              feed_snapshot_age_seconds,
              rationale,
              trace_id
            )
            VALUES ($1, $2, $3, $4, $5::policy_decision, $6::feed_state, $7, $8, $9)
            "#,
        )
        .bind(record.tenant_id)
        .bind(package_request_id)
        .bind(artifact_id)
        .bind(record.policy_snapshot_id)
        .bind(policy_decision_db_value(&record.decision))
        .bind(feed_state_db_value(&record.feed_state))
        .bind(
            i32::try_from(record.feed_snapshot_age_seconds)
                .map_err(|_| PolicyRepositoryError::InvalidFeedSnapshotAge)?,
        )
        .bind(Json(decision_persistence_payload(&record)))
        .bind(&record.trace_id)
        .execute(&mut *transaction)
        .await?;

        transaction.commit().await?;
        Ok(())
    }

    async fn create_analysis_job_if_needed(
        &self,
        request: &DecisionRequest,
        response: &DecisionResponse,
    ) -> Result<Option<AnalysisJob>, PolicyRepositoryError> {
        if !response.create_analysis_job {
            return Ok(None);
        }

        let artifact_digest = request
            .request
            .requested_digest
            .clone()
            .ok_or(PolicyRepositoryError::MissingArtifactDigestForAnalysisJob)?;

        let artifact_id: Option<Uuid> = sqlx::query(
            r#"
            SELECT id
            FROM artifacts
            WHERE tenant_id = $1 AND sha256 = $2
            "#,
        )
        .bind(request.tenant_id)
        .bind(&artifact_digest.hex)
        .fetch_optional(&self.pool)
        .await?
        .map(|row| row.try_get("id"))
        .transpose()?;

        let row = sqlx::query(
            r#"
            INSERT INTO analysis_jobs (
              tenant_id,
                  registry_config_id,
              artifact_id,
              policy_version_id,
              ecosystem,
              namespace,
              package_name,
              package_version,
              artifact_sha256,
                  source_url,
              trace_id
            )
                VALUES ($1, $2, $3, $4, $5::package_ecosystem, $6, $7, $8, $9, $10, $11)
            RETURNING id, created_at, updated_at
            "#,
        )
        .bind(request.tenant_id)
            .bind(request.registry_config_id)
        .bind(artifact_id)
        .bind(response.policy_snapshot_id)
        .bind(request.request.coordinate.ecosystem.to_string())
        .bind(request.request.coordinate.namespace.clone())
        .bind(request.request.coordinate.name.clone())
        .bind(request.request.coordinate.version.clone())
        .bind(&artifact_digest.hex)
            .bind(request.request.source_url.clone())
        .bind(&response.trace_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(Some(AnalysisJob {
            id: row.try_get("id")?,
            tenant_id: request.tenant_id,
            registry_config_id: request.registry_config_id,
            coordinate: request.request.coordinate.clone(),
            artifact_digest,
            source_url: request
                .request
                .source_url
                .clone()
                .ok_or(PolicyRepositoryError::MissingArtifactSourceUrlForAnalysisJob)?,
            policy_snapshot_id: response.policy_snapshot_id,
            state: JobState::Queued,
            retry_count: 0,
            trace_id: response.trace_id.clone(),
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        }))
    }

    async fn load_artifact_exists(
        &self,
        tenant_id: Uuid,
        artifact_digest: &ArtifactDigest,
    ) -> Result<bool, PolicyRepositoryError> {
        Ok(sqlx::query(
            r#"
            SELECT 1
            FROM artifacts
            WHERE tenant_id = $1 AND sha256 = $2
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(&artifact_digest.hex)
        .fetch_optional(&self.pool)
        .await?
        .is_some())
    }

    async fn load_known_malicious_match(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
    ) -> Result<bool, PolicyRepositoryError> {
        let requested_digest_hex = artifact_digest.map(|digest| digest.hex.clone());
        Ok(sqlx::query(
            r#"
            SELECT 1
            FROM malware_matches mm
            JOIN artifacts a ON a.id = mm.artifact_id
            WHERE a.tenant_id = $1
              AND a.ecosystem = $2::package_ecosystem
              AND a.namespace IS NOT DISTINCT FROM $3
              AND a.package_name = $4
              AND a.package_version IS NOT DISTINCT FROM $5
              AND ($6::text IS NULL OR a.sha256 = $6)
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(coordinate.ecosystem.to_string())
        .bind(coordinate.namespace.clone())
        .bind(&coordinate.name)
        .bind(coordinate.version.clone())
        .bind(requested_digest_hex)
        .fetch_optional(&self.pool)
        .await?
        .is_some())
    }

    async fn load_package_signal_status(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
        scorecard_policy: &ScorecardPolicyConfiguration,
    ) -> Result<PackageSignalStatus, PolicyRepositoryError> {
        let requested_digest_hex = artifact_digest.map(|digest| digest.hex.clone());
        let rows = sqlx::query(
            r#"
            SELECT signal
            FROM package_signal_observations
            WHERE tenant_id = $1
              AND ecosystem = $2::package_ecosystem
              AND namespace IS NOT DISTINCT FROM $3
              AND package_name = $4
              AND package_version IS NOT DISTINCT FROM $5
              AND ($6::text IS NULL OR artifact_sha256 IS NULL OR artifact_sha256 = $6)
              AND (expires_at IS NULL OR expires_at > now())
            ORDER BY observed_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(coordinate.ecosystem.to_string())
        .bind(coordinate.namespace.clone())
        .bind(&coordinate.name)
        .bind(coordinate.version.clone())
        .bind(requested_digest_hex)
        .fetch_all(&self.pool)
        .await?;
        let signals = rows
            .into_iter()
            .map(|row| row.try_get::<String, _>("signal"))
            .collect::<Result<Vec<_>, _>>()?;
        let mut status = package_signal_status_from_signals(signals.iter().map(String::as_str));
        merge_scorecard_signal_status(
            &mut status,
            self.load_scorecard_signal_status(coordinate, scorecard_policy)
                .await?,
        );
        Ok(status)
    }

    async fn load_scorecard_signal_status(
        &self,
        coordinate: &PackageCoordinate,
        scorecard_policy: &ScorecardPolicyConfiguration,
    ) -> Result<ScorecardSignalStatus, PolicyRepositoryError> {
        let project_links_row = sqlx::query(
            r#"
            SELECT ddp.project_links
            FROM deps_dev_packages ddp
            JOIN feed_snapshots fs ON fs.id = ddp.snapshot_id
            WHERE fs.feed_name = 'deps.dev'
              AND ddp.ecosystem = $1::package_ecosystem
              AND ddp.namespace IS NOT DISTINCT FROM $2
              AND ddp.package_name = $3
              AND ($4::text IS NULL OR ddp.package_version = $4)
            ORDER BY fs.created_at DESC, ddp.created_at DESC
            LIMIT 1
            "#,
        )
        .bind(coordinate.ecosystem.to_string())
        .bind(coordinate.namespace.clone())
        .bind(&coordinate.name)
        .bind(coordinate.version.clone())
        .fetch_optional(&self.pool)
        .await?;

        let Some(project_links_row) = project_links_row else {
            return Ok(ScorecardSignalStatus::default());
        };
        let project_links = project_links_row.try_get::<Json<Value>, _>("project_links")?.0;
        let Some(repo_name) = project_links
            .as_array()
            .and_then(|links| scorecard_repo_name_from_project_links(links))
        else {
            return Ok(ScorecardSignalStatus::default());
        };

        let latest_result_row = sqlx::query(
            r#"
            SELECT r.id
            FROM openssf_scorecard_results r
            JOIN feed_snapshots fs ON fs.id = r.snapshot_id
            WHERE fs.feed_name = 'openssf-scorecard'
              AND r.repo_name = $1
            ORDER BY r.observed_on DESC NULLS LAST, fs.created_at DESC, r.created_at DESC
            LIMIT 1
            "#,
        )
        .bind(&repo_name)
        .fetch_optional(&self.pool)
        .await?;

        let Some(latest_result_row) = latest_result_row else {
            return Ok(ScorecardSignalStatus::default());
        };
        let result_id = latest_result_row.try_get::<Uuid, _>("id")?;

        let check_rows = sqlx::query(
            r#"
            SELECT check_name, score
            FROM openssf_scorecard_checks
            WHERE result_id = $1
            "#,
        )
        .bind(result_id)
        .fetch_all(&self.pool)
        .await?;

        let checks = check_rows
            .into_iter()
            .map(|row| {
                Ok((
                    row.try_get::<String, _>("check_name")?,
                    row.try_get::<f64, _>("score")?,
                ))
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()?;

        Ok(scorecard_signal_status_from_checks(
            checks.iter().map(|(check_name, score)| (check_name.as_str(), *score)),
            scorecard_policy,
        ))
    }

    async fn load_feed_snapshot_status(
        &self,
        tenant_id: Uuid,
    ) -> Result<FeedSnapshotStatus, PolicyRepositoryError> {
        let feed_names = MVP_FEED_NAMES
            .iter()
            .map(|feed| (*feed).to_owned())
            .collect::<Vec<_>>();
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT ON (feed_name)
              feed_name,
              state::text AS state,
              last_success_at,
              created_at
            FROM feed_snapshots
            WHERE feed_name = ANY($1)
              AND (tenant_id IS NULL OR tenant_id = $2)
            ORDER BY feed_name, created_at DESC
            "#,
        )
        .bind(feed_names)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        let records = rows
            .into_iter()
            .map(|row| {
                Ok(FeedSnapshotRecord {
                    feed_name: row.try_get("feed_name")?,
                    state: feed_state_from_db(row.try_get::<String, _>("state")?)?,
                    last_success_at: row.try_get("last_success_at")?,
                    created_at: row.try_get("created_at")?,
                })
            })
            .collect::<Result<Vec<_>, PolicyRepositoryError>>()?;
        Ok(feed_snapshot_status_from_records(&records, Utc::now()))
    }

    async fn load_fallback_candidate(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
    ) -> Result<Option<PackageCoordinate>, PolicyRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT pr.namespace, pr.package_name, pr.package_version
            FROM policy_decisions pd
            JOIN package_requests pr ON pr.id = pd.package_request_id
            WHERE pd.tenant_id = $1
              AND pr.tenant_id = $1
              AND pr.ecosystem = $2::package_ecosystem
              AND pr.namespace IS NOT DISTINCT FROM $3
              AND pr.package_name = $4
              AND pr.package_version IS NOT NULL
              AND pd.decision = 'ALLOW'::policy_decision
            ORDER BY pd.decided_at DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(coordinate.ecosystem.to_string())
        .bind(coordinate.namespace.clone())
        .bind(&coordinate.name)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|row| {
            Ok(PackageCoordinate {
                ecosystem: coordinate.ecosystem.clone(),
                namespace: row.try_get("namespace")?,
                name: row.try_get("package_name")?,
                version: row.try_get("package_version")?,
            })
        })
        .transpose()
    }

    async fn load_known_safe_verdict(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
    ) -> Result<bool, PolicyRepositoryError> {
        let requested_digest_hex = artifact_digest.map(|digest| digest.hex.clone());
        let row = sqlx::query(
            r#"
            SELECT pd.decision = 'ALLOW'::policy_decision AS known_safe_verdict
            FROM policy_decisions pd
            JOIN package_requests pr ON pr.id = pd.package_request_id
            LEFT JOIN artifacts a ON a.id = pd.artifact_id
            WHERE pd.tenant_id = $1
              AND pr.tenant_id = $1
              AND pr.ecosystem = $2::package_ecosystem
              AND pr.namespace IS NOT DISTINCT FROM $3
              AND pr.package_name = $4
              AND pr.package_version IS NOT DISTINCT FROM $5
              AND (
                $6::text IS NULL
                OR a.sha256 = $6
                OR pd.rationale->'requested_digest'->>'hex' = $6
              )
            ORDER BY pd.decided_at DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(coordinate.ecosystem.to_string())
        .bind(coordinate.namespace.clone())
        .bind(&coordinate.name)
        .bind(coordinate.version.clone())
        .bind(requested_digest_hex)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row
            .map(|decision_row| decision_row.try_get("known_safe_verdict"))
            .transpose()?
            .unwrap_or(false))
    }

    async fn load_vulnerable_above_threshold(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
        threshold: &KnownVulnerabilityThreshold,
    ) -> Result<bool, PolicyRepositoryError> {
        let requested_digest_hex = artifact_digest.map(|digest| digest.hex.clone());
        let rows = sqlx::query(
            r#"
            SELECT vm.severity, vm.epss_probability::double precision AS epss_probability, vm.cisa_kev
            FROM vulnerability_matches vm
            JOIN artifacts a ON a.id = vm.artifact_id
            WHERE a.tenant_id = $1
              AND a.ecosystem = $2::package_ecosystem
              AND a.namespace IS NOT DISTINCT FROM $3
              AND a.package_name = $4
              AND a.package_version IS NOT DISTINCT FROM $5
              AND ($6::text IS NULL OR a.sha256 = $6)
            "#,
        )
        .bind(tenant_id)
        .bind(coordinate.ecosystem.to_string())
        .bind(coordinate.namespace.clone())
        .bind(&coordinate.name)
        .bind(coordinate.version.clone())
        .bind(requested_digest_hex)
        .fetch_all(&self.pool)
        .await?;

        let records = rows
            .into_iter()
            .map(|row| {
                Ok(VulnerabilityMatchRecord {
                    severity: row
                        .try_get::<Option<String>, _>("severity")?
                        .as_deref()
                        .and_then(VulnerabilitySeverity::from_db),
                    epss_probability: row.try_get("epss_probability")?,
                    cisa_kev: row.try_get("cisa_kev")?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()?;

        Ok(records
            .into_iter()
            .any(|record| vulnerability_match_exceeds_threshold(&record, threshold)))
    }

    async fn load_attestation_signal_status(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
    ) -> Result<AttestationSignalStatus, PolicyRepositoryError> {
        let requested_digest_hex = artifact_digest.map(|digest| digest.hex.clone());
        let rows = sqlx::query(
            r#"
            SELECT aa.attestation_type, aa.predicate_type, aa.result
            FROM artifact_attestations aa
            JOIN artifacts a ON a.id = aa.artifact_id
            WHERE a.tenant_id = $1
              AND a.ecosystem = $2::package_ecosystem
              AND a.namespace IS NOT DISTINCT FROM $3
              AND a.package_name = $4
              AND a.package_version IS NOT DISTINCT FROM $5
              AND ($6::text IS NULL OR a.sha256 = $6)
            "#,
        )
        .bind(tenant_id)
        .bind(coordinate.ecosystem.to_string())
        .bind(coordinate.namespace.clone())
        .bind(&coordinate.name)
        .bind(coordinate.version.clone())
        .bind(requested_digest_hex)
        .fetch_all(&self.pool)
        .await?;

        let statuses = rows
            .into_iter()
            .map(|row| {
                Ok((
                    row.try_get::<String, _>("attestation_type")?,
                    row.try_get::<String, _>("predicate_type")?,
                    attestation_result_from_db(&row.try_get::<String, _>("result")?),
                ))
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()?;

        Ok(attestation_signal_status_from_records(
            statuses
                .into_iter()
                .filter_map(|(attestation_type, predicate_type, result)| {
                    result.map(|parsed_result| (attestation_type, predicate_type, parsed_result))
                })
                .collect(),
        ))
    }

    async fn load_ai_agent_injection_indicator(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
    ) -> Result<bool, PolicyRepositoryError> {
        let requested_digest_hex = artifact_digest.map(|digest| digest.hex.clone());
        let rows = sqlx::query(
            r#"
            SELECT sar.report
            FROM static_analysis_reports sar
            JOIN artifacts a ON a.id = sar.artifact_id
            WHERE a.tenant_id = $1
              AND a.ecosystem = $2::package_ecosystem
              AND a.namespace IS NOT DISTINCT FROM $3
              AND a.package_name = $4
              AND a.package_version IS NOT DISTINCT FROM $5
              AND ($6::text IS NULL OR a.sha256 = $6)
            "#,
        )
        .bind(tenant_id)
        .bind(coordinate.ecosystem.to_string())
        .bind(coordinate.namespace.clone())
        .bind(&coordinate.name)
        .bind(coordinate.version.clone())
        .bind(requested_digest_hex)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().any(|row| {
            row.try_get::<Json<Value>, _>("report")
                .ok()
                .and_then(|report| serde_json::from_value::<StaticEvidence>(report.0).ok())
                .is_some_and(|report| static_report_has_ai_agent_injection(&report))
        }))
    }

    async fn load_static_analysis_score_violation(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
    ) -> Result<bool, PolicyRepositoryError> {
        let requested_digest_hex = artifact_digest.map(|digest| digest.hex.clone());
        let rows = sqlx::query(
            r#"
            SELECT sar.report
            FROM static_analysis_reports sar
            JOIN artifacts a ON a.id = sar.artifact_id
            WHERE a.tenant_id = $1
              AND a.ecosystem = $2::package_ecosystem
              AND a.namespace IS NOT DISTINCT FROM $3
              AND a.package_name = $4
              AND a.package_version IS NOT DISTINCT FROM $5
              AND ($6::text IS NULL OR a.sha256 = $6)
            "#,
        )
        .bind(tenant_id)
        .bind(coordinate.ecosystem.to_string())
        .bind(coordinate.namespace.clone())
        .bind(&coordinate.name)
        .bind(coordinate.version.clone())
        .bind(requested_digest_hex)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().any(|row| {
            row.try_get::<Json<Value>, _>("report")
                .ok()
                .and_then(|report| serde_json::from_value::<StaticEvidence>(report.0).ok())
                .is_some_and(|report| static_report_exceeds_policy_threshold(&report))
        }))
    }

    async fn load_dynamic_sandbox_policy_violation(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
    ) -> Result<bool, PolicyRepositoryError> {
        let requested_digest_hex = artifact_digest.map(|digest| digest.hex.clone());
        let rows = sqlx::query(
            r#"
            SELECT sr.telemetry
            FROM sandbox_runs sr
            JOIN artifacts a ON a.id = sr.artifact_id
            WHERE a.tenant_id = $1
              AND a.ecosystem = $2::package_ecosystem
              AND a.namespace IS NOT DISTINCT FROM $3
              AND a.package_name = $4
              AND a.package_version IS NOT DISTINCT FROM $5
              AND ($6::text IS NULL OR a.sha256 = $6)
              AND sr.state = 'completed'
            "#,
        )
        .bind(tenant_id)
        .bind(coordinate.ecosystem.to_string())
        .bind(coordinate.namespace.clone())
        .bind(&coordinate.name)
        .bind(coordinate.version.clone())
        .bind(requested_digest_hex)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().any(|row| {
            row.try_get::<Json<Value>, _>("telemetry")
                .ok()
                .is_some_and(|telemetry| sandbox_run_exceeds_policy_threshold(&telemetry.0))
        }))
    }

    async fn load_override_signal_status(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
        kind: &PackageRequestKind,
    ) -> Result<OverrideSignalStatus, PolicyRepositoryError> {
        sqlx::query(
            r#"
            UPDATE overrides
            SET status = 'expired'
            WHERE tenant_id = $1
              AND status IN ('pending', 'approved')
              AND expires_at <= now()
            "#,
        )
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;

        let requested_digest_hex = artifact_digest.map(|digest| digest.hex.clone());
        let rows = sqlx::query(
            r#"
            SELECT scope, status, expires_at
            FROM overrides
            WHERE tenant_id = $1
              AND status IN ('pending', 'approved')
              AND expires_at > now()
              AND (scope->>'ecosystem' IS NULL OR scope->>'ecosystem' = $2)
              AND (scope->>'name' IS NULL OR scope->>'name' = $3)
              AND (scope->>'namespace' IS NULL OR scope->>'namespace' IS NOT DISTINCT FROM $4)
              AND (scope->>'version' IS NULL OR scope->>'version' IS NOT DISTINCT FROM $5)
              AND (scope->>'digest' IS NULL OR scope->>'digest' IS NOT DISTINCT FROM $6)
              AND (scope->>'kind' IS NULL OR scope->>'kind' = $7)
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(coordinate.ecosystem.to_string())
        .bind(&coordinate.name)
        .bind(coordinate.namespace.clone())
        .bind(coordinate.version.clone())
        .bind(requested_digest_hex)
        .bind(package_request_kind_db_value(kind))
        .fetch_all(&self.pool)
        .await?;

        let records = rows
            .into_iter()
            .map(|row| {
                Ok(OverrideRecord {
                    tenant_id,
                    scope: row.try_get::<Json<Value>, _>("scope")?.0,
                    status: row.try_get("status")?,
                    expires_at: row.try_get("expires_at")?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()?;
        Ok(override_signal_status_from_records(
            records,
            coordinate,
            artifact_digest,
            kind,
        ))
    }
}

#[derive(Debug, Default, Clone)]
pub struct InMemoryPolicyRepository {
    profiles: Arc<RwLock<HashMap<(Uuid, Uuid), LoadedPolicyProfile>>>,
    registry_bindings: Arc<RwLock<HashMap<(Uuid, Uuid), RegistryPolicyBinding>>>,
    decision_records: Arc<RwLock<Vec<PersistedDecisionRecord>>>,
    known_artifacts: Arc<RwLock<HashSet<(Uuid, String)>>>,
    vulnerability_matches: Arc<
        RwLock<
            Vec<(
                Uuid,
                PackageCoordinate,
                Option<ArtifactDigest>,
                VulnerabilityMatchRecord,
            )>,
        >,
    >,
    attestation_records: Arc<
        RwLock<
            Vec<(
                Uuid,
                PackageCoordinate,
                Option<ArtifactDigest>,
                String,
                String,
                AttestationResult,
            )>,
        >,
    >,
    static_analysis_reports: Arc<
        RwLock<
            Vec<(
                Uuid,
                PackageCoordinate,
                Option<ArtifactDigest>,
                StaticEvidence,
            )>,
        >,
    >,
    sandbox_runs: Arc<RwLock<Vec<(Uuid, PackageCoordinate, Option<ArtifactDigest>, Value)>>>,
    override_records: Arc<RwLock<Vec<OverrideRecord>>>,
    package_signal_records: Arc<RwLock<Vec<PackageSignalRecord>>>,
    deps_dev_package_records: Arc<RwLock<Vec<DepsDevPackageRecord>>>,
    scorecard_result_records: Arc<RwLock<Vec<ScorecardResultRecord>>>,
    feed_snapshot_records: Arc<RwLock<Vec<FeedSnapshotRecord>>>,
    analysis_jobs: Arc<RwLock<Vec<AnalysisJob>>>,
}

impl InMemoryPolicyRepository {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    async fn remember_package_signal(
        &self,
        tenant_id: Uuid,
        coordinate: PackageCoordinate,
        artifact_digest: Option<ArtifactDigest>,
        signal: impl Into<String>,
        expires_at: Option<DateTime<Utc>>,
    ) {
        self.package_signal_records
            .write()
            .await
            .push(PackageSignalRecord {
                tenant_id,
                coordinate,
                artifact_digest,
                signal: signal.into(),
                expires_at,
            });
    }

    #[cfg(test)]
    async fn remember_feed_snapshot(
        &self,
        feed_name: impl Into<String>,
        state: FeedState,
        last_success_at: Option<DateTime<Utc>>,
        created_at: DateTime<Utc>,
    ) {
        self.feed_snapshot_records
            .write()
            .await
            .push(FeedSnapshotRecord {
                feed_name: feed_name.into(),
                state,
                last_success_at,
                created_at,
            });
    }

    #[cfg(test)]
    async fn remember_deps_dev_package(
        &self,
        coordinate: PackageCoordinate,
        project_links: Vec<Value>,
    ) {
        self.deps_dev_package_records
            .write()
            .await
            .push(DepsDevPackageRecord {
                coordinate,
                project_links,
            });
    }

    #[cfg(test)]
    async fn remember_scorecard_result(
        &self,
        repo_name: impl Into<String>,
        checks: Vec<(String, f64)>,
    ) {
        self.scorecard_result_records
            .write()
            .await
            .push(ScorecardResultRecord {
                repo_name: repo_name.into(),
                checks,
            });
    }

    pub async fn upsert_profile(&self, profile: LoadedPolicyProfile) {
        self.profiles
            .write()
            .await
            .insert((profile.tenant_id, profile.id), profile);
    }

    pub async fn upsert_registry_binding(&self, binding: RegistryPolicyBinding) {
        self.registry_bindings
            .write()
            .await
            .insert((binding.tenant_id, binding.registry_config_id), binding);
    }

    pub async fn decision_records(&self) -> Vec<PersistedDecisionRecord> {
        self.decision_records.read().await.clone()
    }

    pub async fn remember_artifact(&self, tenant_id: Uuid, artifact_digest: ArtifactDigest) {
        self.known_artifacts
            .write()
            .await
            .insert((tenant_id, artifact_digest.hex));
    }

    #[cfg(test)]
    async fn remember_vulnerability_match(
        &self,
        tenant_id: Uuid,
        coordinate: PackageCoordinate,
        artifact_digest: Option<ArtifactDigest>,
        vulnerability_match: VulnerabilityMatchRecord,
    ) {
        self.vulnerability_matches.write().await.push((
            tenant_id,
            coordinate,
            artifact_digest,
            vulnerability_match,
        ));
    }

    #[cfg(test)]
    async fn remember_attestation_record(
        &self,
        tenant_id: Uuid,
        coordinate: PackageCoordinate,
        artifact_digest: Option<ArtifactDigest>,
        attestation_type: impl Into<String>,
        predicate_type: impl Into<String>,
        result: AttestationResult,
    ) {
        self.attestation_records.write().await.push((
            tenant_id,
            coordinate,
            artifact_digest,
            attestation_type.into(),
            predicate_type.into(),
            result,
        ));
    }

    #[cfg(test)]
    async fn remember_static_analysis_report(
        &self,
        tenant_id: Uuid,
        coordinate: PackageCoordinate,
        artifact_digest: Option<ArtifactDigest>,
        report: StaticEvidence,
    ) {
        self.static_analysis_reports.write().await.push((
            tenant_id,
            coordinate,
            artifact_digest,
            report,
        ));
    }

    #[cfg(test)]
    async fn remember_sandbox_run(
        &self,
        tenant_id: Uuid,
        coordinate: PackageCoordinate,
        artifact_digest: Option<ArtifactDigest>,
        telemetry: Value,
    ) {
        self.sandbox_runs.write().await.push((
            tenant_id,
            coordinate,
            artifact_digest,
            telemetry,
        ));
    }

    #[cfg(test)]
    async fn remember_override(
        &self,
        tenant_id: Uuid,
        scope: Value,
        status: impl Into<String>,
        expires_at: DateTime<Utc>,
    ) {
        self.override_records.write().await.push(OverrideRecord {
            tenant_id,
            scope,
            status: status.into(),
            expires_at,
        });
    }

    pub async fn analysis_jobs(&self) -> Vec<AnalysisJob> {
        self.analysis_jobs.read().await.clone()
    }

    async fn load_profile(
        &self,
        tenant_id: Uuid,
        policy_profile_id: Uuid,
    ) -> Result<LoadedPolicyProfile, PolicyRepositoryError> {
        self.profiles
            .read()
            .await
            .get(&(tenant_id, policy_profile_id))
            .cloned()
            .ok_or(PolicyRepositoryError::ProfileNotFound)
    }

    async fn create_snapshot(
        &self,
        draft: PolicySnapshotDraft,
    ) -> Result<PolicySnapshot, PolicyRepositoryError> {
        let immutable_rule_hash = immutable_rule_hash(&draft.document)?;
        let snapshot = PolicySnapshot {
            id: Uuid::now_v7(),
            tenant_id: draft.tenant_id,
            version: draft.version,
            effective_at: Utc::now(),
            immutable_rule_hash,
        };
        let mut profiles = self.profiles.write().await;
        let profile = profiles
            .get_mut(&(draft.tenant_id, draft.policy_profile_id))
            .ok_or(PolicyRepositoryError::ProfileNotFound)?;
        profile.latest_snapshot = snapshot.clone();
        profile.signal_configuration = policy_signal_configuration_from_document(&draft.document)?;
        Ok(snapshot)
    }

    async fn load_registry_policy_binding(
        &self,
        tenant_id: Uuid,
        registry_config_id: Uuid,
    ) -> Result<RegistryPolicyBinding, PolicyRepositoryError> {
        self.registry_bindings
            .read()
            .await
            .get(&(tenant_id, registry_config_id))
            .cloned()
            .ok_or(PolicyRepositoryError::RegistryConfigNotFound)
    }

    async fn persist_decision_record(
        &self,
        request: &DecisionRequest,
        response: &DecisionResponse,
    ) -> Result<(), PolicyRepositoryError> {
        self.decision_records
            .write()
            .await
            .push(persisted_decision_record(request, response)?);
        Ok(())
    }

    async fn create_analysis_job_if_needed(
        &self,
        request: &DecisionRequest,
        response: &DecisionResponse,
    ) -> Result<Option<AnalysisJob>, PolicyRepositoryError> {
        if !response.create_analysis_job {
            return Ok(None);
        }

        let artifact_digest = request
            .request
            .requested_digest
            .clone()
            .ok_or(PolicyRepositoryError::MissingArtifactDigestForAnalysisJob)?;

        let job = AnalysisJob {
            id: Uuid::now_v7(),
            tenant_id: request.tenant_id,
            registry_config_id: request.registry_config_id,
            coordinate: request.request.coordinate.clone(),
            artifact_digest,
            source_url: request
                .request
                .source_url
                .clone()
                .ok_or(PolicyRepositoryError::MissingArtifactSourceUrlForAnalysisJob)?,
            policy_snapshot_id: response.policy_snapshot_id,
            state: JobState::Queued,
            retry_count: 0,
            trace_id: response.trace_id.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        self.analysis_jobs.write().await.push(job.clone());
        Ok(Some(job))
    }

    async fn load_artifact_exists(
        &self,
        tenant_id: Uuid,
        artifact_digest: &ArtifactDigest,
    ) -> Result<bool, PolicyRepositoryError> {
        Ok(self
            .known_artifacts
            .read()
            .await
            .contains(&(tenant_id, artifact_digest.hex.clone())))
    }

    async fn load_known_malicious_match(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
    ) -> Result<bool, PolicyRepositoryError> {
        let signals = self.package_signal_records.read().await;
        Ok(signals.iter().any(|record| {
            record.tenant_id == tenant_id
                && record.coordinate == *coordinate
                && artifact_digest
                    .map(|digest| record.artifact_digest.as_ref() == Some(digest))
                    .unwrap_or(true)
                && record.signal == "known-malicious"
                && record
                    .expires_at
                    .is_none_or(|expires_at| expires_at > Utc::now())
        }))
    }

    async fn load_package_signal_status(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
        scorecard_policy: &ScorecardPolicyConfiguration,
    ) -> Result<PackageSignalStatus, PolicyRepositoryError> {
        let now = Utc::now();
        let records = self.package_signal_records.read().await;
        let signals = records
            .iter()
            .filter(|record| {
                record.tenant_id == tenant_id
                    && record.coordinate == *coordinate
                    && artifact_digest
                        .map(|digest| record.artifact_digest.as_ref() == Some(digest))
                        .unwrap_or(true)
                    && record.expires_at.is_none_or(|expires_at| expires_at > now)
            })
            .map(|record| record.signal.as_str());
        let mut status = package_signal_status_from_signals(signals);
        merge_scorecard_signal_status(
            &mut status,
            self.load_scorecard_signal_status(coordinate, scorecard_policy)
                .await,
        );
        Ok(status)
    }

    async fn load_scorecard_signal_status(
        &self,
        coordinate: &PackageCoordinate,
        scorecard_policy: &ScorecardPolicyConfiguration,
    ) -> ScorecardSignalStatus {
        let package_records = self.deps_dev_package_records.read().await;
        let Some(package_record) = package_records.iter().rev().find(|record| {
            record.coordinate.ecosystem == coordinate.ecosystem
                && record.coordinate.namespace == coordinate.namespace
                && record.coordinate.name == coordinate.name
                && (coordinate.version.is_none() || record.coordinate.version == coordinate.version)
        }) else {
            return ScorecardSignalStatus::default();
        };
        let Some(repo_name) = scorecard_repo_name_from_project_links(&package_record.project_links)
        else {
            return ScorecardSignalStatus::default();
        };

        let scorecard_results = self.scorecard_result_records.read().await;
        let Some(scorecard_result) = scorecard_results
            .iter()
            .rev()
            .find(|record| record.repo_name == repo_name)
        else {
            return ScorecardSignalStatus::default();
        };
        scorecard_signal_status_from_checks(
            scorecard_result
                .checks
                .iter()
                .map(|(check_name, score)| (check_name.as_str(), *score)),
            scorecard_policy,
        )
    }

    async fn load_feed_snapshot_status(
        &self,
        _tenant_id: Uuid,
    ) -> Result<FeedSnapshotStatus, PolicyRepositoryError> {
        let records = self.feed_snapshot_records.read().await;
        Ok(feed_snapshot_status_from_records(&records, Utc::now()))
    }

    async fn load_fallback_candidate(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
    ) -> Result<Option<PackageCoordinate>, PolicyRepositoryError> {
        let records = self.decision_records.read().await;
        Ok(records
            .iter()
            .rev()
            .find(|record| {
                record.tenant_id == tenant_id
                    && record.decision == PolicyDecision::Allow
                    && record.package_request.coordinate.ecosystem == coordinate.ecosystem
                    && record.package_request.coordinate.namespace == coordinate.namespace
                    && record.package_request.coordinate.name == coordinate.name
                    && record.package_request.coordinate.version.is_some()
            })
            .map(|record| record.package_request.coordinate.clone()))
    }

    async fn load_vulnerable_above_threshold(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
        threshold: &KnownVulnerabilityThreshold,
    ) -> Result<bool, PolicyRepositoryError> {
        let matches = self.vulnerability_matches.read().await;
        Ok(matches
            .iter()
            .filter(|(match_tenant_id, match_coordinate, match_digest, _)| {
                *match_tenant_id == tenant_id
                    && *match_coordinate == *coordinate
                    && artifact_digest
                        .map(|digest| match_digest.as_ref() == Some(digest))
                        .unwrap_or(true)
            })
            .any(|(_, _, _, vulnerability_match)| {
                vulnerability_match_exceeds_threshold(vulnerability_match, threshold)
            }))
    }

    async fn load_attestation_signal_status(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
    ) -> Result<AttestationSignalStatus, PolicyRepositoryError> {
        let records = self.attestation_records.read().await;
        let matching = records
            .iter()
            .filter(
                |(match_tenant_id, match_coordinate, match_digest, _, _, _)| {
                    *match_tenant_id == tenant_id
                        && *match_coordinate == *coordinate
                        && artifact_digest
                            .map(|digest| match_digest.as_ref() == Some(digest))
                            .unwrap_or(true)
                },
            )
            .map(|(_, _, _, attestation_type, predicate_type, result)| {
                (
                    attestation_type.clone(),
                    predicate_type.clone(),
                    result.clone(),
                )
            })
            .collect();

        Ok(attestation_signal_status_from_records(matching))
    }

    async fn load_ai_agent_injection_indicator(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
    ) -> Result<bool, PolicyRepositoryError> {
        let reports = self.static_analysis_reports.read().await;
        Ok(reports
            .iter()
            .filter(|(match_tenant_id, match_coordinate, match_digest, _)| {
                *match_tenant_id == tenant_id
                    && *match_coordinate == *coordinate
                    && artifact_digest
                        .map(|digest| match_digest.as_ref() == Some(digest))
                        .unwrap_or(true)
            })
            .any(|(_, _, _, report)| static_report_has_ai_agent_injection(report)))
    }

    async fn load_static_analysis_score_violation(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
    ) -> Result<bool, PolicyRepositoryError> {
        let reports = self.static_analysis_reports.read().await;
        Ok(reports
            .iter()
            .filter(|(match_tenant_id, match_coordinate, match_digest, _)| {
                *match_tenant_id == tenant_id
                    && *match_coordinate == *coordinate
                    && artifact_digest
                        .map(|digest| match_digest.as_ref() == Some(digest))
                        .unwrap_or(true)
            })
            .any(|(_, _, _, report)| static_report_exceeds_policy_threshold(report)))
    }

    async fn load_dynamic_sandbox_policy_violation(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
    ) -> Result<bool, PolicyRepositoryError> {
        let sandbox_runs = self.sandbox_runs.read().await;
        Ok(sandbox_runs
            .iter()
            .filter(|(match_tenant_id, match_coordinate, match_digest, _)| {
                *match_tenant_id == tenant_id
                    && *match_coordinate == *coordinate
                    && artifact_digest
                        .map(|digest| match_digest.as_ref() == Some(digest))
                        .unwrap_or(true)
            })
            .any(|(_, _, _, telemetry)| sandbox_run_exceeds_policy_threshold(telemetry)))
    }

    async fn load_override_signal_status(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
        kind: &PackageRequestKind,
    ) -> Result<OverrideSignalStatus, PolicyRepositoryError> {
        let now = Utc::now();
        let records = self.override_records.read().await;
        let matching = records
            .iter()
            .filter(|record| {
                record.tenant_id == tenant_id
                    && matches!(record.status.as_str(), "pending" | "approved")
                    && record.expires_at > now
                    && override_scope_matches(&record.scope, coordinate, artifact_digest, kind)
            })
            .cloned()
            .collect();
        Ok(override_signal_status_from_records(
            matching,
            coordinate,
            artifact_digest,
            kind,
        ))
    }

    async fn load_known_safe_verdict(
        &self,
        tenant_id: Uuid,
        coordinate: &PackageCoordinate,
        artifact_digest: Option<&ArtifactDigest>,
    ) -> Result<bool, PolicyRepositoryError> {
        let records = self.decision_records.read().await;
        Ok(records
            .iter()
            .rev()
            .find(|record| {
                record.tenant_id == tenant_id
                    && record.package_request.coordinate == *coordinate
                    && artifact_digest
                        .map(|digest| record.artifact_digest.as_ref() == Some(digest))
                        .unwrap_or(true)
            })
            .map(|record| record.decision == PolicyDecision::Allow)
            .unwrap_or(false))
    }
}

fn persisted_decision_record(
    request: &DecisionRequest,
    response: &DecisionResponse,
) -> Result<PersistedDecisionRecord, PolicyRepositoryError> {
    if response.tenant_id != request.tenant_id
        || response.policy_profile_id != request.policy_profile_id
        || response.trace_id != request.request.trace_id
    {
        return Err(PolicyRepositoryError::InconsistentDecisionResponse);
    }

    Ok(PersistedDecisionRecord {
        tenant_id: request.tenant_id,
        package_request: PersistedPackageRequest {
            registry_config_id: request.registry_config_id,
            client_type: client_type_for_request_kind(request.request.kind.clone()).to_owned(),
            coordinate: request.request.coordinate.clone(),
            source_url: request.request.source_url.clone(),
        },
        artifact_digest: request.request.requested_digest.clone(),
        policy_snapshot_id: response.policy_snapshot_id,
        decision: response.decision.clone(),
        feed_state: response.feed_state.clone(),
        feed_snapshot_age_seconds: response.feed_snapshot_age_seconds,
        rationale: response.rationale.clone(),
        evidence_references: Vec::new(),
        trace_id: response.trace_id.clone(),
    })
}

fn client_type_for_request_kind(kind: PackageRequestKind) -> &'static str {
    match kind {
        PackageRequestKind::Metadata => "metadata",
        PackageRequestKind::Artifact => "artifact",
    }
}

fn policy_decision_db_value(decision: &PolicyDecision) -> &'static str {
    match decision {
        PolicyDecision::Allow => "ALLOW",
        PolicyDecision::AllowWithWarning => "ALLOW_WITH_WARNING",
        PolicyDecision::QuarantinePendingAnalysis => "QUARANTINE_PENDING_ANALYSIS",
        PolicyDecision::BlockKnownMalicious => "BLOCK_KNOWN_MALICIOUS",
        PolicyDecision::BlockPolicyViolation => "BLOCK_POLICY_VIOLATION",
        PolicyDecision::RequireHitlApproval => "REQUIRE_HITL_APPROVAL",
        PolicyDecision::FallbackToApprovedCandidate => "FALLBACK_TO_APPROVED_CANDIDATE",
    }
}

fn feed_state_db_value(feed_state: &FeedState) -> &'static str {
    match feed_state {
        FeedState::Fresh => "fresh",
        FeedState::Stale => "stale",
        FeedState::Degraded => "degraded",
        FeedState::Unavailable => "unavailable",
    }
}

fn decision_persistence_payload(record: &PersistedDecisionRecord) -> Value {
    serde_json::to_value(DecisionPersistencePayload {
        rationale: record.rationale.clone(),
        coordinate: record.package_request.coordinate.clone(),
        requested_digest: record.artifact_digest.clone(),
        evidence_references: record.evidence_references.clone(),
    })
    .unwrap_or_else(|_| {
        json!({
            "rationale": record.rationale,
            "coordinate": record.package_request.coordinate,
            "requested_digest": record.artifact_digest,
            "evidence_references": record.evidence_references,
        })
    })
}

fn policy_mode_from_db(value: String) -> Result<PolicyMode, PolicyRepositoryError> {
    match value.as_str() {
        "shadow" => Ok(PolicyMode::Shadow),
        "warn" => Ok(PolicyMode::Warn),
        "enforce" => Ok(PolicyMode::Enforce),
        _ => Err(PolicyRepositoryError::InvalidPolicyMode),
    }
}

fn policy_snapshot_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<PolicySnapshot, PolicyRepositoryError> {
    Ok(PolicySnapshot {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        version: row.try_get("version")?,
        effective_at: row.try_get::<DateTime<Utc>, _>("effective_at")?,
        immutable_rule_hash: ArtifactDigest::sha256(
            row.try_get::<String, _>("immutable_rule_hash")?,
        )?,
    })
}

pub fn immutable_rule_hash(document: &Value) -> Result<ArtifactDigest, PolicyRepositoryError> {
    let serialized = serde_json::to_vec(document)?;
    let digest = Sha256::digest(serialized);
    ArtifactDigest::sha256(hex::encode(digest)).map_err(PolicyRepositoryError::from)
}

fn policy_signal_configuration_from_document(
    document: &Value,
) -> Result<PolicySignalConfiguration, PolicyRepositoryError> {
    let parsed: PolicyDocumentSignalConfiguration = serde_json::from_value(document.clone())?;
    let vulnerable_above_threshold_action = parsed
        .rules
        .iter()
        .rev()
        .find(|rule| rule.enabled && rule.signal == "vulnerable_above_threshold")
        .map(|rule| match rule.action {
            PolicyDocumentRuleAction::Warn => Ok(VulnerabilityPolicyAction::Warn),
            PolicyDocumentRuleAction::Block => Ok(VulnerabilityPolicyAction::Block),
            action => Err(PolicyRepositoryError::UnsupportedPolicyRuleAction {
                signal: rule.signal.clone(),
                action: action.as_str().to_owned(),
            }),
        })
        .transpose()?
        .unwrap_or(VulnerabilityPolicyAction::Warn);
    let scorecard = ScorecardPolicyConfiguration {
        code_review: ScorecardCheckPolicy {
            min_score: parsed.scorecard_thresholds.code_review,
            action: scorecard_action_from_document_rules(&parsed.rules, "scorecard_code_review_risk")?,
        },
        branch_protection: ScorecardCheckPolicy {
            min_score: parsed.scorecard_thresholds.branch_protection,
            action: scorecard_action_from_document_rules(
                &parsed.rules,
                "scorecard_branch_protection_risk",
            )?,
        },
        ci_cd: ScorecardCheckPolicy {
            min_score: parsed.scorecard_thresholds.ci_cd,
            action: scorecard_action_from_document_rules(&parsed.rules, "scorecard_ci_cd_risk")?,
        },
        maintained: ScorecardCheckPolicy {
            min_score: parsed.scorecard_thresholds.maintained,
            action: scorecard_action_from_document_rules(&parsed.rules, "scorecard_maintained_risk")?,
        },
        signed_releases: ScorecardCheckPolicy {
            min_score: parsed.scorecard_thresholds.signed_releases,
            action: scorecard_action_from_document_rules(
                &parsed.rules,
                "scorecard_signed_releases_risk",
            )?,
        },
    };

    Ok(PolicySignalConfiguration {
        known_vulnerability_threshold: KnownVulnerabilityThreshold {
            severity_floor: parsed.known_vulnerability_threshold.severity_floor,
            kev_override: parsed.known_vulnerability_threshold.kev_override,
            epss_probability_floor: parsed.known_vulnerability_threshold.epss_probability_floor,
        },
        vulnerable_above_threshold_action,
        scorecard,
    })
}

fn scorecard_action_from_document_rules(
    rules: &[PolicyDocumentRule],
    signal: &str,
) -> Result<SignalPolicyAction, PolicyRepositoryError> {
    let Some(rule) = rules.iter().rev().find(|rule| rule.signal == signal) else {
        return Ok(SignalPolicyAction::Allow);
    };

    if !rule.enabled {
        return Ok(SignalPolicyAction::Allow);
    }

    match rule.action {
        PolicyDocumentRuleAction::Allow => Ok(SignalPolicyAction::Allow),
        PolicyDocumentRuleAction::Warn => Ok(SignalPolicyAction::Warn),
        PolicyDocumentRuleAction::Block => Ok(SignalPolicyAction::Block),
        PolicyDocumentRuleAction::Hitl => Ok(SignalPolicyAction::Hitl),
        action => Err(PolicyRepositoryError::UnsupportedPolicyRuleAction {
            signal: signal.to_owned(),
            action: action.as_str().to_owned(),
        }),
    }
}

fn vulnerability_match_exceeds_threshold(
    vulnerability_match: &VulnerabilityMatchRecord,
    threshold: &KnownVulnerabilityThreshold,
) -> bool {
    if threshold.kev_override && vulnerability_match.cisa_kev {
        return true;
    }

    if threshold
        .epss_probability_floor
        .zip(vulnerability_match.epss_probability)
        .is_some_and(|(floor, epss)| epss >= floor)
    {
        return true;
    }

    vulnerability_match
        .severity
        .is_some_and(|severity| severity >= threshold.severity_floor)
}

fn attestation_result_from_db(value: &str) -> Option<AttestationResult> {
    match value.to_ascii_lowercase().as_str() {
        "pass" => Some(AttestationResult::Pass),
        "fail" => Some(AttestationResult::Fail),
        "missing" => Some(AttestationResult::Missing),
        "unverifiable" => Some(AttestationResult::Unverifiable),
        _ => None,
    }
}

fn attestation_signal_status_from_records(
    records: Vec<(String, String, AttestationResult)>,
) -> AttestationSignalStatus {
    let missing_or_failed_attestation = records.iter().any(|(_, _, result)| {
        matches!(
            result,
            AttestationResult::Fail | AttestationResult::Missing | AttestationResult::Unverifiable
        )
    });
    let provenance_or_signature_verification_failed =
        records
            .iter()
            .any(|(attestation_type, predicate_type, result)| {
                matches!(
                    result,
                    AttestationResult::Fail
                        | AttestationResult::Missing
                        | AttestationResult::Unverifiable
                ) && (attestation_type.contains("signature")
                    || attestation_type.contains("provenance")
                    || predicate_type.contains("provenance"))
            });

    AttestationSignalStatus {
        missing_or_failed_attestation,
        provenance_or_signature_verification_failed,
    }
}

fn static_report_has_ai_agent_injection(report: &StaticEvidence) -> bool {
    report
        .indicators
        .iter()
        .any(|indicator| indicator.indicator_type == "ai-agent-injection")
}

fn static_report_exceeds_policy_threshold(report: &StaticEvidence) -> bool {
    report
        .indicators
        .iter()
        .any(|indicator| matches!(indicator.severity, Severity::High | Severity::Critical))
}

fn sandbox_run_exceeds_policy_threshold(telemetry: &Value) -> bool {
    sandbox_telemetry_phases(telemetry).into_iter().any(|phase| {
        let phase_name = phase.get("phase").and_then(Value::as_str);
        if !matches!(phase_name, Some("D" | "E" | "G")) {
            return false;
        }

        phase
            .get("events")
            .and_then(Value::as_array)
            .is_some_and(|events| {
                events.iter().any(|event| sandbox_event_exceeds_policy_threshold(event))
            })
    })
}

fn sandbox_telemetry_phases(telemetry: &Value) -> Vec<&Value> {
    if let Some(phases) = telemetry.get("phases").and_then(Value::as_array) {
        return phases.iter().collect();
    }
    telemetry
        .as_array()
        .map(|phases| phases.iter().collect())
        .unwrap_or_default()
}

fn sandbox_event_exceeds_policy_threshold(event: &Value) -> bool {
    let event_type = event.get("type").and_then(Value::as_str);
    let severity = event.get("severity").and_then(Value::as_str);
    match (event_type, severity) {
        (Some("canary-secret-access"), Some("critical")) => true,
        (Some("ai-canary-file-modified"), Some("critical")) => true,
        (Some("outbound-network-attempt"), Some("high" | "critical")) => true,
        _ => false,
    }
}

fn package_signal_status_from_signals<'a>(
    signals: impl IntoIterator<Item = &'a str>,
) -> PackageSignalStatus {
    let mut status = PackageSignalStatus::default();
    for signal in signals {
        match signal {
            "minimum-release-age-violation" => status.minimum_release_age_violation = true,
            "install-script-detected" => status.install_script_detected = true,
            "dependency-confusion-risk" => status.dependency_confusion_risk = true,
            "typosquat-risk" => status.typosquat_risk = true,
            "artifact-digest-reputation-risk" => status.artifact_digest_reputation_risk = true,
            "github-to-registry-publish-gap-risk" => {
                status.github_to_registry_publish_gap_risk = true;
            }
            "trusted-publisher-identity-mismatch" => {
                status.trusted_publisher_identity_mismatch = true;
            }
            "maintainer-account-age-risk" => status.maintainer_account_age_risk = true,
            "recent-maintainer-change-risk" => status.recent_maintainer_change_risk = true,
            "new-maintainer-ratio-risk" => status.new_maintainer_ratio_risk = true,
            "known-malicious" => status.known_malicious = true,
            _ => {}
        }
    }
    status
}

fn merge_scorecard_signal_status(
    package_signal_status: &mut PackageSignalStatus,
    scorecard_signal_status: ScorecardSignalStatus,
) {
    package_signal_status.scorecard_code_review_risk |= scorecard_signal_status.code_review_risk;
    package_signal_status.scorecard_branch_protection_risk |=
        scorecard_signal_status.branch_protection_risk;
    package_signal_status.scorecard_ci_cd_risk |= scorecard_signal_status.ci_cd_risk;
    package_signal_status.scorecard_maintained_risk |= scorecard_signal_status.maintained_risk;
    package_signal_status.scorecard_signed_releases_risk |=
        scorecard_signal_status.signed_releases_risk;
}

fn scorecard_signal_status_from_checks<'a>(
    checks: impl IntoIterator<Item = (&'a str, f64)>,
    scorecard_policy: &ScorecardPolicyConfiguration,
) -> ScorecardSignalStatus {
    let mut status = ScorecardSignalStatus::default();
    for (check_name, score) in checks {
        match check_name.to_ascii_lowercase().as_str() {
            "code-review" => {
                status.code_review_risk = score < scorecard_policy.code_review.min_score;
            }
            "branch-protection" => {
                status.branch_protection_risk = score < scorecard_policy.branch_protection.min_score;
            }
            "ci-tests" => {
                status.ci_cd_risk = score < scorecard_policy.ci_cd.min_score;
            }
            "maintained" => {
                status.maintained_risk = score < scorecard_policy.maintained.min_score;
            }
            "signed-releases" => {
                status.signed_releases_risk = score < scorecard_policy.signed_releases.min_score;
            }
            _ => {}
        }
    }
    status
}

fn scorecard_repo_name_from_project_links(project_links: &[Value]) -> Option<String> {
    project_links
        .iter()
        .filter(|link| {
            link.get("type")
                .and_then(Value::as_str)
                .is_none_or(|link_type| link_type == "SOURCE_REPO")
        })
        .filter_map(|link| link.get("url").and_then(Value::as_str))
        .find_map(normalize_scorecard_repo_name)
}

fn normalize_scorecard_repo_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let trimmed = trimmed.trim_end_matches('/');
    let trimmed = trimmed.strip_suffix(".git").unwrap_or(trimmed);
    let trimmed = trimmed.strip_prefix("https://").unwrap_or(trimmed);
    let trimmed = trimmed.strip_prefix("http://").unwrap_or(trimmed);
    let trimmed = trimmed.strip_prefix("www.").unwrap_or(trimmed);
    let trimmed = trimmed.strip_prefix("git+").unwrap_or(trimmed);
    let trimmed = trimmed.strip_prefix("https://").unwrap_or(trimmed);
    let trimmed = trimmed.strip_prefix("http://").unwrap_or(trimmed);
    let trimmed = trimmed.strip_prefix("www.").unwrap_or(trimmed);
    let path = trimmed.strip_prefix("github.com/")?;

    let mut segments = path.split('/').filter(|segment| !segment.is_empty());
    let owner = segments.next()?;
    let repo = segments.next()?;
    Some(format!("github.com/{owner}/{repo}"))
}

fn feed_snapshot_status_from_records(
    records: &[FeedSnapshotRecord],
    now: DateTime<Utc>,
) -> FeedSnapshotStatus {
    if records.len() < MVP_FEED_NAMES.len() {
        return FeedSnapshotStatus {
            state: FeedState::Unavailable,
            age_seconds: 0,
        };
    }

    let mut state = FeedState::Fresh;
    let mut max_age_seconds = 0_u64;
    for record in records {
        let timestamp = record.last_success_at.unwrap_or(record.created_at);
        let age_seconds = now.signed_duration_since(timestamp).num_seconds().max(0) as u64;
        max_age_seconds = max_age_seconds.max(age_seconds);

        state = match (&state, &record.state) {
            (_, FeedState::Unavailable) => FeedState::Unavailable,
            (FeedState::Unavailable, _) => FeedState::Unavailable,
            (_, FeedState::Degraded) => FeedState::Degraded,
            (FeedState::Degraded, _) => FeedState::Degraded,
            (_, FeedState::Stale) => FeedState::Stale,
            (FeedState::Stale, _) => FeedState::Stale,
            _ => FeedState::Fresh,
        };
    }

    if matches!(state, FeedState::Fresh) && max_age_seconds > FRESH_FEED_MAX_AGE_SECONDS {
        state = FeedState::Stale;
    }

    FeedSnapshotStatus {
        state,
        age_seconds: max_age_seconds,
    }
}

fn feed_state_from_db(value: String) -> Result<FeedState, PolicyRepositoryError> {
    match value.as_str() {
        "fresh" => Ok(FeedState::Fresh),
        "stale" => Ok(FeedState::Stale),
        "degraded" => Ok(FeedState::Degraded),
        "unavailable" => Ok(FeedState::Unavailable),
        _ => Err(PolicyRepositoryError::InvalidPolicyDocument(
            serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid feed state",
            )),
        )),
    }
}

fn override_signal_status_from_records(
    records: Vec<OverrideRecord>,
    coordinate: &PackageCoordinate,
    artifact_digest: Option<&ArtifactDigest>,
    kind: &PackageRequestKind,
) -> OverrideSignalStatus {
    let mut status = OverrideSignalStatus::default();
    for record in records {
        if !override_scope_matches(&record.scope, coordinate, artifact_digest, kind) {
            continue;
        }
        match record.status.as_str() {
            "pending" => status.hitl_required = true,
            "approved" => match scope_str(&record.scope, "effect").unwrap_or("allow") {
                "emergency-bypass" => status.emergency_bypass = true,
                _ => status.active_override = true,
            },
            _ => {}
        }
    }
    status
}

fn override_scope_matches(
    scope: &Value,
    coordinate: &PackageCoordinate,
    artifact_digest: Option<&ArtifactDigest>,
    kind: &PackageRequestKind,
) -> bool {
    scope_matches(scope, "ecosystem", Some(&coordinate.ecosystem.to_string()))
        && scope_matches(scope, "name", Some(&coordinate.name))
        && scope_matches(scope, "namespace", coordinate.namespace.as_deref())
        && scope_matches(scope, "version", coordinate.version.as_deref())
        && scope_matches(
            scope,
            "digest",
            artifact_digest.map(|digest| digest.hex.as_str()),
        )
        && scope_matches(scope, "kind", Some(package_request_kind_db_value(kind)))
}

fn scope_matches(scope: &Value, key: &str, actual: Option<&str>) -> bool {
    match scope_str(scope, key) {
        Some(expected) => actual == Some(expected),
        None => true,
    }
}

fn scope_str<'a>(scope: &'a Value, key: &str) -> Option<&'a str> {
    scope
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn package_request_kind_db_value(kind: &PackageRequestKind) -> &'static str {
    match kind {
        PackageRequestKind::Metadata => "metadata",
        PackageRequestKind::Artifact => "artifact",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegiscudo_core::{PackageCoordinate, PackageEcosystem, Severity, StaticIndicator};
    use aegiscudo_protocol::{DecisionResponse, PackageRequestKind};

    fn profile(tenant_id: Uuid, policy_profile_id: Uuid, snapshot_id: Uuid) -> LoadedPolicyProfile {
        LoadedPolicyProfile {
            id: policy_profile_id,
            tenant_id,
            mode: PolicyMode::Warn,
            latest_snapshot: PolicySnapshot {
                id: snapshot_id,
                tenant_id,
                version: "2026.05.0".to_owned(),
                effective_at: Utc::now(),
                immutable_rule_hash: ArtifactDigest::sha256("a".repeat(64)).expect("valid hash"),
            },
            signal_configuration: PolicySignalConfiguration::default(),
        }
    }

    fn decision_request(
        tenant_id: Uuid,
        registry_config_id: Uuid,
        policy_profile_id: Uuid,
    ) -> DecisionRequest {
        let coordinate = PackageCoordinate::new(
            PackageEcosystem::Npm,
            "left-pad",
            Some("1.3.0"),
            None::<String>,
        );
        DecisionRequest {
            tenant_id,
            registry_config_id,
            policy_profile_id,
            request: aegiscudo_protocol::NormalizedPackageRequest {
                kind: aegiscudo_protocol::PackageRequestKind::Metadata,
                tenant_id,
                registry_config_id,
                policy_profile_id,
                coordinate,
                trace_id: "trace-policy".to_owned(),
                requested_digest: None,
                source_url: None,
                explicit_version_or_integrity: false,
            },
        }
    }

    #[tokio::test]
    async fn in_memory_repository_binds_mode_and_snapshot_from_loaded_profile() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let repository = InMemoryPolicyRepository::new();
        repository
            .upsert_profile(profile(tenant_id, policy_profile_id, snapshot_id))
            .await;
        repository
            .upsert_registry_binding(RegistryPolicyBinding {
                tenant_id,
                registry_config_id,
                policy_profile_id,
                mode: PolicyMode::Warn,
            })
            .await;

        let bound = PolicyRepository::InMemory(repository)
            .bind_decision_request(decision_request(
                tenant_id,
                registry_config_id,
                policy_profile_id,
            ))
            .await
            .expect("policy context should bind");

        assert_eq!(bound.mode, PolicyMode::Warn);
        assert_eq!(bound.policy_snapshot_id, snapshot_id);
    }

    #[tokio::test]
    async fn in_memory_snapshot_creation_updates_latest_snapshot_with_document_hash() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let repository = InMemoryPolicyRepository::new();
        repository
            .upsert_profile(profile(tenant_id, policy_profile_id, Uuid::now_v7()))
            .await;
        let document = serde_json::json!({
            "known_vulnerability_threshold": {
                "severity_floor": "high",
                "kev_override": true
            },
            "rules": [{"id": "minimum-age", "signal": "minimum_release_age_violation", "action": "warn", "enabled": true}],
            "version": "2026.05.1"
        });

        let snapshot = repository
            .create_snapshot(PolicySnapshotDraft {
                tenant_id,
                policy_profile_id,
                version: "2026.05.1".to_owned(),
                document: document.clone(),
                created_by: None,
            })
            .await
            .expect("snapshot should be created");

        assert_eq!(snapshot.version, "2026.05.1");
        assert_eq!(
            snapshot.immutable_rule_hash,
            immutable_rule_hash(&document).unwrap()
        );
        assert_eq!(
            repository
                .load_profile(tenant_id, policy_profile_id)
                .await
                .unwrap()
                .latest_snapshot
                .id,
            snapshot.id
        );
        assert_eq!(
            repository
                .load_profile(tenant_id, policy_profile_id)
                .await
                .unwrap()
                .signal_configuration
                .known_vulnerability_threshold
                .severity_floor,
            VulnerabilitySeverity::High
        );
    }

    #[test]
    fn policy_signal_configuration_reads_vulnerability_rule_action_and_threshold() {
        let document = serde_json::json!({
            "known_vulnerability_threshold": {
                "severity_floor": "critical",
                "kev_override": true,
                "epss_probability_floor": 0.7
            },
            "rules": [
                {
                    "id": "known-vulnerable",
                    "signal": "vulnerable_above_threshold",
                    "action": "block",
                    "enabled": true
                }
            ]
        });

        let configuration = policy_signal_configuration_from_document(&document)
            .expect("policy signal configuration should parse");

        assert_eq!(
            configuration.vulnerable_above_threshold_action,
            VulnerabilityPolicyAction::Block
        );
        assert_eq!(
            configuration.known_vulnerability_threshold.severity_floor,
            VulnerabilitySeverity::Critical
        );
        assert_eq!(
            configuration
                .known_vulnerability_threshold
                .epss_probability_floor,
            Some(0.7)
        );
    }

    #[test]
    fn policy_signal_configuration_reads_scorecard_thresholds_and_actions() {
        let document = serde_json::json!({
            "known_vulnerability_threshold": {
                "severity_floor": "high",
                "kev_override": true
            },
            "scorecard_thresholds": {
                "code_review": 9.5,
                "branch_protection": 8.0,
                "ci_cd": 9.0,
                "maintained": 7.0,
                "signed_releases": 6.0
            },
            "rules": [
                {
                    "id": "scorecard-branch",
                    "signal": "scorecard_branch_protection_risk",
                    "action": "block",
                    "enabled": true
                },
                {
                    "id": "scorecard-maintained",
                    "signal": "scorecard_maintained_risk",
                    "action": "warn",
                    "enabled": false
                },
                {
                    "id": "scorecard-signed",
                    "signal": "scorecard_signed_releases_risk",
                    "action": "hitl",
                    "enabled": true
                }
            ]
        });

        let configuration = policy_signal_configuration_from_document(&document)
            .expect("policy signal configuration should parse");

        assert_eq!(configuration.scorecard.code_review.min_score, 9.5);
        assert_eq!(configuration.scorecard.branch_protection.min_score, 8.0);
        assert_eq!(configuration.scorecard.branch_protection.action, SignalPolicyAction::Block);
        assert_eq!(configuration.scorecard.maintained.action, SignalPolicyAction::Allow);
        assert_eq!(configuration.scorecard.signed_releases.action, SignalPolicyAction::Hitl);
    }

    #[test]
    fn scorecard_rules_default_to_allow_for_legacy_policy_documents() {
        let document = serde_json::json!({
            "known_vulnerability_threshold": {
                "severity_floor": "high",
                "kev_override": true
            },
            "rules": [
                {
                    "id": "known-vulnerable",
                    "signal": "vulnerable_above_threshold",
                    "action": "warn",
                    "enabled": true
                }
            ]
        });

        let configuration = policy_signal_configuration_from_document(&document)
            .expect("policy signal configuration should parse");

        assert_eq!(configuration.scorecard.code_review.action, SignalPolicyAction::Allow);
        assert_eq!(
            configuration.scorecard.branch_protection.action,
            SignalPolicyAction::Allow
        );
        assert_eq!(configuration.scorecard.ci_cd.action, SignalPolicyAction::Allow);
        assert_eq!(configuration.scorecard.maintained.action, SignalPolicyAction::Allow);
        assert_eq!(
            configuration.scorecard.signed_releases.action,
            SignalPolicyAction::Allow
        );
    }

    #[tokio::test]
    async fn in_memory_repository_binds_vulnerability_signal_when_match_exceeds_threshold() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let repository = InMemoryPolicyRepository::new();
        let mut loaded_profile = profile(tenant_id, policy_profile_id, snapshot_id);
        loaded_profile.signal_configuration = PolicySignalConfiguration {
            known_vulnerability_threshold: KnownVulnerabilityThreshold {
                severity_floor: VulnerabilitySeverity::High,
                kev_override: true,
                epss_probability_floor: None,
            },
            vulnerable_above_threshold_action: VulnerabilityPolicyAction::Block,
            scorecard: ScorecardPolicyConfiguration::default(),
        };
        repository.upsert_profile(loaded_profile).await;
        repository
            .upsert_registry_binding(RegistryPolicyBinding {
                tenant_id,
                registry_config_id,
                policy_profile_id,
                mode: PolicyMode::Warn,
            })
            .await;

        let request = decision_request(tenant_id, registry_config_id, policy_profile_id);
        repository
            .remember_vulnerability_match(
                tenant_id,
                request.request.coordinate.clone(),
                None,
                VulnerabilityMatchRecord {
                    severity: Some(VulnerabilitySeverity::Critical),
                    epss_probability: None,
                    cisa_kev: false,
                },
            )
            .await;

        let bound = PolicyRepository::InMemory(repository)
            .bind_decision_request(request)
            .await
            .expect("policy context should bind");

        assert!(bound.vulnerable_above_threshold);
        assert_eq!(
            bound.vulnerable_above_threshold_action,
            VulnerabilityPolicyAction::Block
        );
    }

    #[tokio::test]
    async fn in_memory_repository_ignores_vulnerability_match_below_threshold() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let repository = InMemoryPolicyRepository::new();
        let mut loaded_profile = profile(tenant_id, policy_profile_id, snapshot_id);
        loaded_profile.signal_configuration = PolicySignalConfiguration {
            known_vulnerability_threshold: KnownVulnerabilityThreshold {
                severity_floor: VulnerabilitySeverity::Critical,
                kev_override: false,
                epss_probability_floor: Some(0.9),
            },
            vulnerable_above_threshold_action: VulnerabilityPolicyAction::Warn,
            scorecard: ScorecardPolicyConfiguration::default(),
        };
        repository.upsert_profile(loaded_profile).await;
        repository
            .upsert_registry_binding(RegistryPolicyBinding {
                tenant_id,
                registry_config_id,
                policy_profile_id,
                mode: PolicyMode::Warn,
            })
            .await;

        let request = decision_request(tenant_id, registry_config_id, policy_profile_id);
        repository
            .remember_vulnerability_match(
                tenant_id,
                request.request.coordinate.clone(),
                None,
                VulnerabilityMatchRecord {
                    severity: Some(VulnerabilitySeverity::High),
                    epss_probability: Some(0.4),
                    cisa_kev: false,
                },
            )
            .await;
        let bound = PolicyRepository::InMemory(repository)
            .bind_decision_request(request)
            .await
            .expect("policy context should bind");

        assert!(!bound.vulnerable_above_threshold);
    }

    #[tokio::test]
    async fn in_memory_repository_binds_attestation_warning_signals_from_records() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let repository = InMemoryPolicyRepository::new();
        repository
            .upsert_profile(profile(tenant_id, policy_profile_id, snapshot_id))
            .await;
        repository
            .upsert_registry_binding(RegistryPolicyBinding {
                tenant_id,
                registry_config_id,
                policy_profile_id,
                mode: PolicyMode::Warn,
            })
            .await;

        let request = decision_request(tenant_id, registry_config_id, policy_profile_id);
        repository
            .remember_attestation_record(
                tenant_id,
                request.request.coordinate.clone(),
                None,
                "npm-publish-attestation",
                "https://slsa.dev/provenance/v1",
                AttestationResult::Fail,
            )
            .await;

        let bound = PolicyRepository::InMemory(repository)
            .bind_decision_request(request)
            .await
            .expect("policy context should bind");

        assert!(bound.missing_or_failed_attestation);
        assert!(bound.provenance_or_signature_verification_failed);
    }

    #[test]
    fn attestation_signal_status_ignores_successful_records() {
        let status = attestation_signal_status_from_records(vec![(
            "npm-publish-attestation".to_owned(),
            "https://slsa.dev/provenance/v1".to_owned(),
            AttestationResult::Pass,
        )]);

        assert!(!status.missing_or_failed_attestation);
        assert!(!status.provenance_or_signature_verification_failed);
    }

    #[tokio::test]
    async fn in_memory_repository_binds_ai_agent_injection_from_static_reports() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let repository = InMemoryPolicyRepository::new();
        repository
            .upsert_profile(profile(tenant_id, policy_profile_id, snapshot_id))
            .await;
        repository
            .upsert_registry_binding(RegistryPolicyBinding {
                tenant_id,
                registry_config_id,
                policy_profile_id,
                mode: PolicyMode::Warn,
            })
            .await;

        let request = decision_request(tenant_id, registry_config_id, policy_profile_id);
        repository
            .remember_static_analysis_report(
                tenant_id,
                request.request.coordinate.clone(),
                None,
                StaticEvidence {
                    artifact_digest: ArtifactDigest::sha256("e".repeat(64)).expect("valid digest"),
                    analyzer_version: "0.1.0".to_owned(),
                    rule_set_version: "mvp-static-rules-2026-05".to_owned(),
                    indicators: vec![StaticIndicator {
                        indicator_type: "ai-agent-injection".to_owned(),
                        severity: Severity::High,
                        file_path: "package/.github/copilot-instructions.md".to_owned(),
                        start_line: 1,
                        end_line: 1,
                        redacted: true,
                        summary: "package content attempts to instruct AI tools".to_owned(),
                        details: None,
                    }],
                },
            )
            .await;

        let bound = PolicyRepository::InMemory(repository)
            .bind_decision_request(request)
            .await
            .expect("policy context should bind");

        assert!(bound.ai_agent_injection_indicator);
    }

    #[tokio::test]
    async fn in_memory_repository_binds_static_analysis_score_violation_from_reports() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let repository = InMemoryPolicyRepository::new();
        repository
            .upsert_profile(profile(tenant_id, policy_profile_id, snapshot_id))
            .await;
        repository
            .upsert_registry_binding(RegistryPolicyBinding {
                tenant_id,
                registry_config_id,
                policy_profile_id,
                mode: PolicyMode::Warn,
            })
            .await;

        let request = decision_request(tenant_id, registry_config_id, policy_profile_id);
        repository
            .remember_static_analysis_report(
                tenant_id,
                request.request.coordinate.clone(),
                None,
                StaticEvidence {
                    artifact_digest: ArtifactDigest::sha256("f".repeat(64)).expect("valid digest"),
                    analyzer_version: "0.1.0".to_owned(),
                    rule_set_version: "mvp-static-rules-2026-05".to_owned(),
                    indicators: vec![StaticIndicator {
                        indicator_type: "node-child-process".to_owned(),
                        severity: Severity::High,
                        file_path: "package/preinstall.js".to_owned(),
                        start_line: 1,
                        end_line: 1,
                        redacted: true,
                        summary: "child process execution detected".to_owned(),
                        details: None,
                    }],
                },
            )
            .await;

        let bound = PolicyRepository::InMemory(repository)
            .bind_decision_request(request)
            .await
            .expect("policy context should bind");

        assert!(bound.static_analysis_score_violation);
    }

    #[tokio::test]
    async fn in_memory_repository_binds_dynamic_sandbox_policy_violation_from_runs() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let repository = InMemoryPolicyRepository::new();
        repository
            .upsert_profile(profile(tenant_id, policy_profile_id, snapshot_id))
            .await;
        repository
            .upsert_registry_binding(RegistryPolicyBinding {
                tenant_id,
                registry_config_id,
                policy_profile_id,
                mode: PolicyMode::Warn,
            })
            .await;

        let request = decision_request(tenant_id, registry_config_id, policy_profile_id);
        repository
            .remember_sandbox_run(
                tenant_id,
                request.request.coordinate.clone(),
                None,
                json!({
                    "run_id": Uuid::now_v7(),
                    "state": "completed",
                    "violation_detected": true,
                    "phases": [
                        {
                            "phase": "E",
                            "events": [
                                {
                                    "type": "outbound-network-attempt",
                                    "severity": "high",
                                    "message": "captured loopback exfiltration during scripts-enabled install"
                                }
                            ]
                        }
                    ]
                }),
            )
            .await;

        let bound = PolicyRepository::InMemory(repository)
            .bind_decision_request(request)
            .await
            .expect("policy context should bind");

        assert!(bound.dynamic_sandbox_policy_violation);
    }

    #[tokio::test]
    async fn in_memory_repository_persists_decision_record_with_coordinate_and_digest() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let repository = InMemoryPolicyRepository::new();
        let digest = ArtifactDigest::sha256("b".repeat(64)).expect("valid digest");
        let mut request = decision_request(tenant_id, registry_config_id, policy_profile_id);
        request.request.kind = PackageRequestKind::Artifact;
        request.request.requested_digest = Some(digest.clone());

        PolicyRepository::InMemory(repository.clone())
            .persist_decision_record(
                &request,
                &DecisionResponse {
                    decision: PolicyDecision::QuarantinePendingAnalysis,
                    tenant_id,
                    policy_profile_id,
                    policy_snapshot_id: snapshot_id,
                    mode: PolicyMode::Warn,
                    feed_state: FeedState::Fresh,
                    feed_snapshot_age_seconds: 12,
                    trace_id: request.request.trace_id.clone(),
                    rationale: vec!["unknown artifact requires asynchronous analysis".to_owned()],
                    fallback_coordinate: None,
                    create_analysis_job: true,
                },
            )
            .await
            .expect("decision record should persist");

        let records = repository.decision_records().await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].package_request.client_type, "artifact");
        assert_eq!(records[0].package_request.coordinate.name, "left-pad");
        assert_eq!(records[0].artifact_digest, Some(digest));
        assert_eq!(records[0].policy_snapshot_id, snapshot_id);
        assert!(records[0].evidence_references.is_empty());
    }

    #[tokio::test]
    async fn in_memory_repository_binds_known_safe_verdict_from_latest_allow() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let repository = InMemoryPolicyRepository::new();
        repository
            .upsert_profile(profile(tenant_id, policy_profile_id, snapshot_id))
            .await;
        repository
            .upsert_registry_binding(RegistryPolicyBinding {
                tenant_id,
                registry_config_id,
                policy_profile_id,
                mode: PolicyMode::Warn,
            })
            .await;

        let request = decision_request(tenant_id, registry_config_id, policy_profile_id);
        PolicyRepository::InMemory(repository.clone())
            .persist_decision_record(
                &request,
                &DecisionResponse {
                    decision: PolicyDecision::Allow,
                    tenant_id,
                    policy_profile_id,
                    policy_snapshot_id: snapshot_id,
                    mode: PolicyMode::Warn,
                    feed_state: FeedState::Fresh,
                    feed_snapshot_age_seconds: 0,
                    trace_id: request.request.trace_id.clone(),
                    rationale: vec!["no blocking policy signal matched".to_owned()],
                    fallback_coordinate: None,
                    create_analysis_job: false,
                },
            )
            .await
            .expect("seed decision should persist");

        let bound = PolicyRepository::InMemory(repository)
            .bind_decision_request(decision_request(
                tenant_id,
                registry_config_id,
                policy_profile_id,
            ))
            .await
            .expect("policy context should bind");

        assert!(bound.known_safe_verdict);
    }

    #[tokio::test]
    async fn in_memory_repository_requires_digest_match_for_known_safe_artifact_verdict() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let repository = InMemoryPolicyRepository::new();
        let prior_digest = ArtifactDigest::sha256("c".repeat(64)).expect("valid digest");
        let new_digest = ArtifactDigest::sha256("d".repeat(64)).expect("valid digest");
        repository
            .upsert_profile(profile(tenant_id, policy_profile_id, snapshot_id))
            .await;
        repository
            .upsert_registry_binding(RegistryPolicyBinding {
                tenant_id,
                registry_config_id,
                policy_profile_id,
                mode: PolicyMode::Warn,
            })
            .await;

        let mut prior_request = decision_request(tenant_id, registry_config_id, policy_profile_id);
        prior_request.request.kind = PackageRequestKind::Artifact;
        prior_request.request.requested_digest = Some(prior_digest);
        prior_request.request.explicit_version_or_integrity = true;

        PolicyRepository::InMemory(repository.clone())
            .persist_decision_record(
                &prior_request,
                &DecisionResponse {
                    decision: PolicyDecision::Allow,
                    tenant_id,
                    policy_profile_id,
                    policy_snapshot_id: snapshot_id,
                    mode: PolicyMode::Warn,
                    feed_state: FeedState::Fresh,
                    feed_snapshot_age_seconds: 0,
                    trace_id: prior_request.request.trace_id.clone(),
                    rationale: vec!["no blocking policy signal matched".to_owned()],
                    fallback_coordinate: None,
                    create_analysis_job: false,
                },
            )
            .await
            .expect("seed artifact decision should persist");

        let mut new_request = decision_request(tenant_id, registry_config_id, policy_profile_id);
        new_request.request.kind = PackageRequestKind::Artifact;
        new_request.request.requested_digest = Some(new_digest);
        new_request.request.explicit_version_or_integrity = true;

        let bound = PolicyRepository::InMemory(repository)
            .bind_decision_request(new_request)
            .await
            .expect("policy context should bind");

        assert!(!bound.known_safe_verdict);
    }

    #[tokio::test]
    async fn npm_metadata_request_can_fallback_to_prior_allowed_version() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let repository = InMemoryPolicyRepository::new();
        repository
            .upsert_profile(profile(tenant_id, policy_profile_id, snapshot_id))
            .await;
        repository
            .upsert_registry_binding(RegistryPolicyBinding {
                tenant_id,
                registry_config_id,
                policy_profile_id,
                mode: PolicyMode::Warn,
            })
            .await;

        let prior_request = decision_request(tenant_id, registry_config_id, policy_profile_id);
        PolicyRepository::InMemory(repository.clone())
            .persist_decision_record(
                &prior_request,
                &DecisionResponse {
                    decision: PolicyDecision::Allow,
                    tenant_id,
                    policy_profile_id,
                    policy_snapshot_id: snapshot_id,
                    mode: PolicyMode::Warn,
                    feed_state: FeedState::Fresh,
                    feed_snapshot_age_seconds: 0,
                    trace_id: prior_request.request.trace_id.clone(),
                    rationale: vec!["no blocking policy signal matched".to_owned()],
                    fallback_coordinate: None,
                    create_analysis_job: false,
                },
            )
            .await
            .expect("seed allow decision should persist");

        let mut metadata_request =
            decision_request(tenant_id, registry_config_id, policy_profile_id);
        metadata_request.request.coordinate.version = None;
        metadata_request.request.explicit_version_or_integrity = false;

        let bound = PolicyRepository::InMemory(repository)
            .bind_decision_request(metadata_request)
            .await
            .expect("policy context should bind");

        assert!(bound.fallback_eligible);
        assert_eq!(
            bound
                .fallback_candidate
                .as_ref()
                .and_then(|candidate| candidate.version.as_deref()),
            Some("1.3.0")
        );
    }

    #[tokio::test]
    async fn explicit_artifact_request_is_not_fallback_eligible() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let repository = InMemoryPolicyRepository::new();
        repository
            .upsert_profile(profile(tenant_id, policy_profile_id, snapshot_id))
            .await;
        repository
            .upsert_registry_binding(RegistryPolicyBinding {
                tenant_id,
                registry_config_id,
                policy_profile_id,
                mode: PolicyMode::Warn,
            })
            .await;
        let prior_request = decision_request(tenant_id, registry_config_id, policy_profile_id);
        PolicyRepository::InMemory(repository.clone())
            .persist_decision_record(
                &prior_request,
                &DecisionResponse {
                    decision: PolicyDecision::Allow,
                    tenant_id,
                    policy_profile_id,
                    policy_snapshot_id: snapshot_id,
                    mode: PolicyMode::Warn,
                    feed_state: FeedState::Fresh,
                    feed_snapshot_age_seconds: 0,
                    trace_id: prior_request.request.trace_id.clone(),
                    rationale: vec!["no blocking policy signal matched".to_owned()],
                    fallback_coordinate: None,
                    create_analysis_job: false,
                },
            )
            .await
            .expect("seed allow decision should persist");

        let mut artifact_request =
            decision_request(tenant_id, registry_config_id, policy_profile_id);
        artifact_request.request.kind = PackageRequestKind::Artifact;
        artifact_request.request.explicit_version_or_integrity = true;
        artifact_request.request.requested_digest =
            Some(ArtifactDigest::sha256("f".repeat(64)).expect("valid digest"));

        let bound = PolicyRepository::InMemory(repository)
            .bind_decision_request(artifact_request)
            .await
            .expect("policy context should bind");

        assert!(!bound.fallback_eligible);
        assert!(bound.fallback_candidate.is_none());
    }

    #[tokio::test]
    async fn approved_override_takes_precedence_over_known_malicious_signal() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let repository = InMemoryPolicyRepository::new();
        repository
            .upsert_profile(profile(tenant_id, policy_profile_id, Uuid::now_v7()))
            .await;
        repository
            .upsert_registry_binding(RegistryPolicyBinding {
                tenant_id,
                registry_config_id,
                policy_profile_id,
                mode: PolicyMode::Enforce,
            })
            .await;
        let request = decision_request(tenant_id, registry_config_id, policy_profile_id);
        repository
            .remember_package_signal(
                tenant_id,
                request.request.coordinate.clone(),
                None,
                "known-malicious",
                None,
            )
            .await;
        repository
            .remember_override(
                tenant_id,
                json!({ "ecosystem": "npm", "name": "left-pad" }),
                "approved",
                Utc::now() + chrono::Duration::hours(1),
            )
            .await;

        let bound = PolicyRepository::InMemory(repository)
            .bind_decision_request(request)
            .await
            .expect("policy context should bind");
        let response = aegiscudo_policy::DecisionEngine.evaluate(bound);

        assert_eq!(response.decision, PolicyDecision::AllowWithWarning);
    }

    #[tokio::test]
    async fn expired_approved_override_restores_known_malicious_blocking() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();

        let build_repository = || async {
            let repository = InMemoryPolicyRepository::new();
            repository
                .upsert_profile(profile(tenant_id, policy_profile_id, Uuid::now_v7()))
                .await;
            repository
                .upsert_registry_binding(RegistryPolicyBinding {
                    tenant_id,
                    registry_config_id,
                    policy_profile_id,
                    mode: PolicyMode::Enforce,
                })
                .await;
            let request = decision_request(tenant_id, registry_config_id, policy_profile_id);
            repository
                .remember_package_signal(
                    tenant_id,
                    request.request.coordinate.clone(),
                    None,
                    "known-malicious",
                    None,
                )
                .await;

            (repository, request)
        };

        let (active_repository, active_request) = build_repository().await;
        active_repository
            .remember_override(
                tenant_id,
                json!({ "ecosystem": "npm", "name": "left-pad" }),
                "approved",
                Utc::now() + chrono::Duration::hours(1),
            )
            .await;

        let active_bound = PolicyRepository::InMemory(active_repository)
            .bind_decision_request(active_request)
            .await
            .expect("active override should bind");
        let active_response = aegiscudo_policy::DecisionEngine.evaluate(active_bound);
        assert_eq!(active_response.decision, PolicyDecision::AllowWithWarning);

        let (expired_repository, expired_request) = build_repository().await;
        expired_repository
            .remember_override(
                tenant_id,
                json!({ "ecosystem": "npm", "name": "left-pad" }),
                "approved",
                Utc::now() - chrono::Duration::minutes(1),
            )
            .await;

        let expired_bound = PolicyRepository::InMemory(expired_repository)
            .bind_decision_request(expired_request)
            .await
            .expect("expired override should bind");
        let expired_response = aegiscudo_policy::DecisionEngine.evaluate(expired_bound);
        assert_eq!(expired_response.decision, PolicyDecision::BlockKnownMalicious);
    }

    #[tokio::test]
    async fn pending_matching_override_requires_hitl() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let repository = InMemoryPolicyRepository::new();
        repository
            .upsert_profile(profile(tenant_id, policy_profile_id, Uuid::now_v7()))
            .await;
        repository
            .upsert_registry_binding(RegistryPolicyBinding {
                tenant_id,
                registry_config_id,
                policy_profile_id,
                mode: PolicyMode::Enforce,
            })
            .await;
        repository
            .remember_override(
                tenant_id,
                json!({ "ecosystem": "npm", "name": "left-pad", "kind": "metadata" }),
                "pending",
                Utc::now() + chrono::Duration::hours(1),
            )
            .await;

        let bound = PolicyRepository::InMemory(repository)
            .bind_decision_request(decision_request(
                tenant_id,
                registry_config_id,
                policy_profile_id,
            ))
            .await
            .expect("policy context should bind");

        assert!(bound.hitl_required);
        assert_eq!(
            aegiscudo_policy::DecisionEngine.evaluate(bound).decision,
            PolicyDecision::RequireHitlApproval
        );
    }

    #[tokio::test]
    async fn expired_and_nonmatching_overrides_are_ignored() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let repository = InMemoryPolicyRepository::new();
        repository
            .upsert_profile(profile(tenant_id, policy_profile_id, Uuid::now_v7()))
            .await;
        repository
            .upsert_registry_binding(RegistryPolicyBinding {
                tenant_id,
                registry_config_id,
                policy_profile_id,
                mode: PolicyMode::Enforce,
            })
            .await;
        repository
            .remember_override(
                tenant_id,
                json!({ "ecosystem": "npm", "name": "left-pad" }),
                "approved",
                Utc::now() - chrono::Duration::minutes(1),
            )
            .await;
        repository
            .remember_override(
                tenant_id,
                json!({ "ecosystem": "npm", "name": "other-package" }),
                "approved",
                Utc::now() + chrono::Duration::hours(1),
            )
            .await;

        let bound = PolicyRepository::InMemory(repository)
            .bind_decision_request(decision_request(
                tenant_id,
                registry_config_id,
                policy_profile_id,
            ))
            .await
            .expect("policy context should bind");

        assert!(!bound.active_override);
        assert!(!bound.emergency_bypass);
        assert!(!bound.hitl_required);
    }

    #[tokio::test]
    async fn emergency_bypass_effect_maps_to_emergency_signal() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let repository = InMemoryPolicyRepository::new();
        repository
            .upsert_profile(profile(tenant_id, policy_profile_id, Uuid::now_v7()))
            .await;
        repository
            .upsert_registry_binding(RegistryPolicyBinding {
                tenant_id,
                registry_config_id,
                policy_profile_id,
                mode: PolicyMode::Enforce,
            })
            .await;
        repository
            .remember_override(
                tenant_id,
                json!({ "ecosystem": "npm", "name": "left-pad", "effect": "emergency-bypass" }),
                "approved",
                Utc::now() + chrono::Duration::minutes(30),
            )
            .await;

        let bound = PolicyRepository::InMemory(repository)
            .bind_decision_request(decision_request(
                tenant_id,
                registry_config_id,
                policy_profile_id,
            ))
            .await
            .expect("policy context should bind");

        assert!(bound.emergency_bypass);
        assert!(!bound.active_override);
    }

    #[tokio::test]
    async fn package_signal_observations_bind_policy_inputs() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let repository = InMemoryPolicyRepository::new();
        repository
            .upsert_profile(profile(tenant_id, policy_profile_id, Uuid::now_v7()))
            .await;
        repository
            .upsert_registry_binding(RegistryPolicyBinding {
                tenant_id,
                registry_config_id,
                policy_profile_id,
                mode: PolicyMode::Warn,
            })
            .await;
        let request = decision_request(tenant_id, registry_config_id, policy_profile_id);
        for signal in [
            "minimum-release-age-violation",
            "install-script-detected",
            "dependency-confusion-risk",
            "typosquat-risk",
            "artifact-digest-reputation-risk",
            "github-to-registry-publish-gap-risk",
            "trusted-publisher-identity-mismatch",
            "maintainer-account-age-risk",
            "recent-maintainer-change-risk",
            "new-maintainer-ratio-risk",
        ] {
            repository
                .remember_package_signal(
                    tenant_id,
                    request.request.coordinate.clone(),
                    None,
                    signal,
                    None,
                )
                .await;
        }

        let bound = PolicyRepository::InMemory(repository)
            .bind_decision_request(request)
            .await
            .expect("policy context should bind");

        assert!(bound.minimum_release_age_violation);
        assert!(bound.install_script_detected);
        assert!(bound.dependency_confusion_risk);
        assert!(bound.typosquat_risk);
        assert!(bound.artifact_digest_reputation_risk);
        assert!(bound.github_to_registry_publish_gap_risk);
        assert!(bound.trusted_publisher_identity_mismatch);
        assert!(bound.maintainer_account_age_risk);
        assert!(bound.recent_maintainer_change_risk);
        assert!(bound.new_maintainer_ratio_risk);
    }

    #[tokio::test]
    async fn deps_dev_and_scorecard_records_bind_policy_inputs() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let repository = InMemoryPolicyRepository::new();
        repository
            .upsert_profile(profile(tenant_id, policy_profile_id, Uuid::now_v7()))
            .await;
        repository
            .upsert_registry_binding(RegistryPolicyBinding {
                tenant_id,
                registry_config_id,
                policy_profile_id,
                mode: PolicyMode::Warn,
            })
            .await;

        let request = decision_request(tenant_id, registry_config_id, policy_profile_id);
        repository
            .remember_deps_dev_package(
                request.request.coordinate.clone(),
                vec![json!({
                    "type": "SOURCE_REPO",
                    "url": "https://github.com/lodash/lodash"
                })],
            )
            .await;
        repository
            .remember_scorecard_result(
                "github.com/lodash/lodash",
                vec![
                    ("Code-Review".to_owned(), 10.0),
                    ("Branch-Protection".to_owned(), 8.0),
                    ("CI-Tests".to_owned(), 10.0),
                    ("Maintained".to_owned(), 10.0),
                    ("Signed-Releases".to_owned(), -1.0),
                ],
            )
            .await;

        let bound = PolicyRepository::InMemory(repository)
            .bind_decision_request(request)
            .await
            .expect("policy context should bind");

        assert!(!bound.scorecard_code_review_risk);
        assert!(bound.scorecard_branch_protection_risk);
        assert!(!bound.scorecard_ci_cd_risk);
        assert!(!bound.scorecard_maintained_risk);
        assert!(bound.scorecard_signed_releases_risk);
    }

    #[tokio::test]
    async fn scorecard_thresholds_control_bound_policy_inputs() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let repository = InMemoryPolicyRepository::new();
        let mut loaded_profile = profile(tenant_id, policy_profile_id, snapshot_id);
        loaded_profile.signal_configuration.scorecard.branch_protection.min_score = 8.0;
        loaded_profile.signal_configuration.scorecard.signed_releases.min_score = -1.0;
        repository.upsert_profile(loaded_profile).await;
        repository
            .upsert_registry_binding(RegistryPolicyBinding {
                tenant_id,
                registry_config_id,
                policy_profile_id,
                mode: PolicyMode::Warn,
            })
            .await;

        let request = decision_request(tenant_id, registry_config_id, policy_profile_id);
        repository
            .remember_deps_dev_package(
                request.request.coordinate.clone(),
                vec![json!({
                    "type": "SOURCE_REPO",
                    "url": "https://github.com/lodash/lodash"
                })],
            )
            .await;
        repository
            .remember_scorecard_result(
                "github.com/lodash/lodash",
                vec![
                    ("Branch-Protection".to_owned(), 8.0),
                    ("Signed-Releases".to_owned(), -1.0),
                ],
            )
            .await;

        let bound = PolicyRepository::InMemory(repository)
            .bind_decision_request(request)
            .await
            .expect("policy context should bind");

        assert!(!bound.scorecard_branch_protection_risk);
        assert!(!bound.scorecard_signed_releases_risk);
    }

    #[tokio::test]
    async fn latest_scorecard_result_wins_in_memory_binding() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let repository = InMemoryPolicyRepository::new();
        repository
            .upsert_profile(profile(tenant_id, policy_profile_id, Uuid::now_v7()))
            .await;
        repository
            .upsert_registry_binding(RegistryPolicyBinding {
                tenant_id,
                registry_config_id,
                policy_profile_id,
                mode: PolicyMode::Warn,
            })
            .await;

        let request = decision_request(tenant_id, registry_config_id, policy_profile_id);
        repository
            .remember_deps_dev_package(
                request.request.coordinate.clone(),
                vec![json!({
                    "type": "SOURCE_REPO",
                    "url": "https://github.com/lodash/lodash"
                })],
            )
            .await;
        repository
            .remember_scorecard_result(
                "github.com/lodash/lodash",
                vec![
                    ("Branch-Protection".to_owned(), 8.0),
                    ("Signed-Releases".to_owned(), -1.0),
                ],
            )
            .await;
        repository
            .remember_scorecard_result(
                "github.com/lodash/lodash",
                vec![
                    ("Branch-Protection".to_owned(), 10.0),
                    ("Signed-Releases".to_owned(), 10.0),
                ],
            )
            .await;

        let bound = PolicyRepository::InMemory(repository)
            .bind_decision_request(request)
            .await
            .expect("policy context should bind");

        assert!(!bound.scorecard_branch_protection_risk);
        assert!(!bound.scorecard_signed_releases_risk);
    }

    #[tokio::test]
    async fn feed_snapshots_bind_state_and_age() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let repository = InMemoryPolicyRepository::new();
        repository
            .upsert_profile(profile(tenant_id, policy_profile_id, Uuid::now_v7()))
            .await;
        repository
            .upsert_registry_binding(RegistryPolicyBinding {
                tenant_id,
                registry_config_id,
                policy_profile_id,
                mode: PolicyMode::Warn,
            })
            .await;
        let created_at = Utc::now() - chrono::Duration::seconds(30);
        for feed_name in MVP_FEED_NAMES {
            repository
                .remember_feed_snapshot(*feed_name, FeedState::Fresh, Some(created_at), created_at)
                .await;
        }

        let bound = PolicyRepository::InMemory(repository)
            .bind_decision_request(decision_request(
                tenant_id,
                registry_config_id,
                policy_profile_id,
            ))
            .await
            .expect("policy context should bind");

        assert_eq!(bound.feed_state, FeedState::Fresh);
        assert!(bound.feed_snapshot_age_seconds >= 30);
    }
}
