pub mod metrics;
pub mod repository;

use aegiscudo_policy::DecisionEngine;
use aegiscudo_protocol::{DecisionQueryRequest, DecisionRequest};
use aegiscudo_telemetry::health;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderValue, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use metrics::DecisionMetrics;
use repository::{BoundDecisionContext, PolicyRepository, PolicyRepositoryError};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

pub const SERVICE_NAME: &str = "triage-counter";

#[derive(Debug)]
pub struct AppState {
    policy_repository: PolicyRepository,
    decision_engine: DecisionEngine,
    decision_cache: DecisionCache,
    metrics: DecisionMetrics,
}

impl AppState {
    pub fn new(policy_repository: PolicyRepository) -> Self {
        Self {
            policy_repository,
            decision_engine: DecisionEngine,
            decision_cache: DecisionCache::new(Duration::from_secs(30)),
            metrics: DecisionMetrics::new().expect("Triage Counter metrics must initialize"),
        }
    }
}

#[derive(Debug, Default)]
struct DecisionCache {
    entries: RwLock<HashMap<String, CachedDecision>>,
    ttl: Duration,
}

impl DecisionCache {
    fn new(ttl: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl,
        }
    }

    async fn get(&self, cache_key: &str) -> Option<CachedDecision> {
        let now = Instant::now();
        self.entries
            .read()
            .await
            .get(cache_key)
            .filter(|entry| entry.expires_at > now)
            .cloned()
    }

    async fn put(
        &self,
        cache_key: String,
        response: &aegiscudo_protocol::DecisionResponse,
        evidence_references: &[String],
    ) {
        self.entries.write().await.insert(
            cache_key,
            CachedDecision {
                response: response.clone(),
                evidence_references: evidence_references.to_vec(),
                expires_at: Instant::now() + self.ttl,
            },
        );
    }
}

#[derive(Debug, Clone)]
struct CachedDecision {
    response: aegiscudo_protocol::DecisionResponse,
    evidence_references: Vec<String>,
    expires_at: Instant,
}

pub fn app(policy_repository: PolicyRepository) -> Router {
    let state = Arc::new(AppState::new(policy_repository));
    Router::new()
        .route("/healthz", get(|| async { Json(health(SERVICE_NAME)) }))
        .route("/readyz", get(|| async { Json(health(SERVICE_NAME)) }))
        .route("/metrics", get(metrics))
        .route("/v1/decisions/evaluate", post(evaluate_decision))
        .route("/v1/decisions/query", post(query_decision))
        .route("/v1/decisions/simulate", post(simulate_decision))
        .with_state(state)
}

async fn metrics(State(state): State<Arc<AppState>>) -> Response {
    match state.metrics.render() {
        Ok(body) => {
            let mut response = body.into_response();
            response.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_str(&state.metrics.content_type())
                    .expect("Prometheus content type must be valid"),
            );
            response
        }
        Err(error) => {
            tracing::error!(error = %error, "failed to render triage-counter metrics");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn evaluate_decision(
    State(state): State<Arc<AppState>>,
    Json(request): Json<DecisionRequest>,
) -> Result<Json<aegiscudo_protocol::DecisionResponse>, ApiError> {
    let started = Instant::now();
    let tenant_id = request.tenant_id;
    let registry_config_id = request.registry_config_id;
    let response = evaluate_with_state(&state, request).await?;
    state.metrics.observe_decision(
        tenant_id,
        registry_config_id,
        &response.decision,
        &response.feed_state,
        started.elapsed(),
    );
    Ok(Json(response))
}

async fn simulate_decision(
    State(state): State<Arc<AppState>>,
    Json(request): Json<DecisionRequest>,
) -> Result<Json<aegiscudo_protocol::DecisionResponse>, ApiError> {
    Ok(Json(simulate_with_state(&state, request).await?))
}

async fn query_decision(
    State(state): State<Arc<AppState>>,
    Json(request): Json<DecisionQueryRequest>,
) -> Result<Json<aegiscudo_protocol::DecisionResponse>, ApiError> {
    Ok(Json(query_with_state(&state, request).await?))
}

async fn evaluate_with_state(
    state: &AppState,
    request: DecisionRequest,
) -> Result<aegiscudo_protocol::DecisionResponse, PolicyRepositoryError> {
    let cache_key = decision_cache_key(&request);
    if let Some(cached) = state.decision_cache.get(&cache_key).await {
        let mut response = cached.response;
        response.trace_id = request.request.trace_id.clone();
        state
            .metrics
            .observe_cache(request.tenant_id, request.registry_config_id, "hit");
        state
            .policy_repository
            .persist_evaluated_decision_record(&request, &response, &cached.evidence_references)
            .await?;
        return Ok(response);
    }
    state
        .metrics
        .observe_cache(request.tenant_id, request.registry_config_id, "miss");
    let evaluated = evaluate_with_policy_repository_with_context(
        &state.policy_repository,
        &state.decision_engine,
        request.clone(),
    )
    .await?;
    state
        .decision_cache
        .put(
            cache_key,
            &evaluated.response,
            &evaluated.evidence_references,
        )
        .await;
    Ok(evaluated.response)
}

async fn simulate_with_state(
    state: &AppState,
    request: DecisionRequest,
) -> Result<aegiscudo_protocol::DecisionResponse, PolicyRepositoryError> {
    let cache_key = decision_cache_key(&request);
    if let Some(cached) = state.decision_cache.get(&cache_key).await {
        let mut response = cached.response;
        response.trace_id = request.request.trace_id.clone();
        return Ok(response);
    }

    let bound_context = state
        .policy_repository
        .bind_simulation_context(request.clone())
        .await?;
    let response = state.decision_engine.evaluate(bound_context.policy_input);
    state
        .decision_cache
        .put(cache_key, &response, &bound_context.evidence_references)
        .await;
    Ok(response)
}

async fn query_with_state(
    state: &AppState,
    request: DecisionQueryRequest,
) -> Result<aegiscudo_protocol::DecisionResponse, PolicyRepositoryError> {
    let cache_key = decision_query_cache_key(&request);
    if let Some(cached) = state.decision_cache.get(&cache_key).await {
        let mut response = cached.response;
        response.trace_id = request.request.trace_id.clone();
        return Ok(response);
    }

    let response = query_with_policy_repository(
        &state.policy_repository,
        &state.decision_engine,
        request.clone(),
    )
    .await?;
    state.decision_cache.put(cache_key, &response, &[]).await;
    Ok(response)
}

fn decision_cache_key(request: &DecisionRequest) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        request.tenant_id,
        request.registry_config_id,
        match request.request.kind {
            aegiscudo_protocol::PackageRequestKind::Metadata => "metadata",
            aegiscudo_protocol::PackageRequestKind::Artifact => "artifact",
        },
        request.request.coordinate.purl(),
        request
            .request
            .requested_digest
            .as_ref()
            .map(|digest| digest.hex.as_str())
            .unwrap_or("none"),
    )
}

fn decision_query_cache_key(request: &DecisionQueryRequest) -> String {
    format!(
        "query:{}:{}:{}:{}",
        request.tenant_id,
        request.policy_profile_id,
        match request.request.kind {
            aegiscudo_protocol::PackageRequestKind::Metadata => "metadata",
            aegiscudo_protocol::PackageRequestKind::Artifact => "artifact",
        },
        request
            .request
            .requested_digest
            .as_ref()
            .map(|digest| format!("{}:{}", request.request.coordinate.purl(), digest.hex))
            .unwrap_or_else(|| request.request.coordinate.purl()),
    )
}

struct EvaluatedDecision {
    response: aegiscudo_protocol::DecisionResponse,
    evidence_references: Vec<String>,
}

async fn evaluate_with_policy_repository_with_context(
    policy_repository: &PolicyRepository,
    decision_engine: &DecisionEngine,
    request: DecisionRequest,
) -> Result<EvaluatedDecision, PolicyRepositoryError> {
    let bound_context = policy_repository
        .bind_evaluation_context(request.clone())
        .await?;
    let evidence_references = bound_context.evidence_references.clone();
    let mut response = decision_engine.evaluate(bound_context.policy_input);
    if bound_context.vulnerability_under_investigation {
        append_openvex_rationale(
            &mut response,
            "vulnerability is under investigation per VEX statement",
        );
    }
    policy_repository
        .persist_evaluated_decision_record(&request, &response, &evidence_references)
        .await?;
    policy_repository
        .create_analysis_job_if_needed(&request, &response)
        .await?;
    Ok(EvaluatedDecision {
        response,
        evidence_references,
    })
}

fn append_openvex_rationale(response: &mut aegiscudo_protocol::DecisionResponse, note: &str) {
    if !response.rationale.iter().any(|r| r == note) {
        response.rationale.push(note.to_owned());
    }
}

#[cfg(test)]
async fn evaluate_with_policy_repository(
    policy_repository: &PolicyRepository,
    decision_engine: &DecisionEngine,
    request: DecisionRequest,
) -> Result<aegiscudo_protocol::DecisionResponse, PolicyRepositoryError> {
    let evaluated =
        evaluate_with_policy_repository_with_context(policy_repository, decision_engine, request)
            .await?;
    Ok(evaluated.response)
}

async fn query_with_policy_repository(
    policy_repository: &PolicyRepository,
    decision_engine: &DecisionEngine,
    request: DecisionQueryRequest,
) -> Result<aegiscudo_protocol::DecisionResponse, PolicyRepositoryError> {
    let bound_input = policy_repository.bind_query_request(request).await?;
    Ok(decision_engine.evaluate(bound_input))
}

struct ApiError(PolicyRepositoryError);

impl From<PolicyRepositoryError> for ApiError {
    fn from(error: PolicyRepositoryError) -> Self {
        Self(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let error = self.0.to_string();
        let (status, message) = match &self.0 {
            PolicyRepositoryError::ProfileNotFound | PolicyRepositoryError::SnapshotNotFound => (
                StatusCode::NOT_FOUND,
                "policy profile or snapshot was not found",
            ),
            PolicyRepositoryError::RegistryConfigNotFound => (
                StatusCode::NOT_FOUND,
                "registry configuration was not found",
            ),
            PolicyRepositoryError::InconsistentDecisionRequest
            | PolicyRepositoryError::RegistryPolicyMismatch => (
                StatusCode::BAD_REQUEST,
                "decision request policy context is invalid",
            ),
            PolicyRepositoryError::InconsistentDecisionResponse
            | PolicyRepositoryError::InvalidFeedSnapshotAge
            | PolicyRepositoryError::MissingArtifactDigestForAnalysisJob
            | PolicyRepositoryError::MissingArtifactSourceUrlForAnalysisJob => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "decision persistence context is invalid",
            ),
            PolicyRepositoryError::InvalidPolicyDocument(_)
            | PolicyRepositoryError::InvalidPolicyMode
            | PolicyRepositoryError::UnsupportedPolicyRuleAction { .. }
            | PolicyRepositoryError::InvalidSnapshotHash(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "policy snapshot is invalid",
            ),
            PolicyRepositoryError::Database(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "policy repository is unavailable",
            ),
        };
        if status.is_server_error() {
            tracing::error!(%status, %error, details = ?self.0, "triage-counter request failed");
        }
        (status, message).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegiscudo_core::{
        ArtifactDigest, PackageCoordinate, PackageEcosystem, PolicyMode, PolicySnapshot,
    };
    use aegiscudo_protocol::{
        DecisionQueryRequest, DecisionRequest, NormalizedPackageRequest, NormalizedQueryRequest,
        PackageRequestKind,
    };
    use repository::{
        InMemoryPolicyRepository, LoadedPolicyProfile, PolicySignalConfiguration,
        RegistryPolicyBinding,
    };
    use uuid::Uuid;

    #[tokio::test]
    async fn evaluate_binds_policy_context_before_decision() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let repository = InMemoryPolicyRepository::new();
        repository
            .upsert_profile(LoadedPolicyProfile {
                id: policy_profile_id,
                tenant_id,
                mode: PolicyMode::Shadow,
                latest_snapshot: PolicySnapshot {
                    id: snapshot_id,
                    tenant_id,
                    version: "2026.05.0".to_owned(),
                    effective_at: chrono::Utc::now(),
                    immutable_rule_hash: ArtifactDigest::sha256("a".repeat(64)).unwrap(),
                },
                signal_configuration: PolicySignalConfiguration::default(),
            })
            .await;
        repository
            .upsert_registry_binding(RegistryPolicyBinding {
                tenant_id,
                registry_config_id,
                policy_profile_id,
                mode: PolicyMode::Shadow,
            })
            .await;

        let request = DecisionRequest {
            tenant_id,
            registry_config_id,
            policy_profile_id,
            request: NormalizedPackageRequest {
                kind: PackageRequestKind::Metadata,
                tenant_id,
                registry_config_id,
                policy_profile_id,
                coordinate: PackageCoordinate::new(
                    PackageEcosystem::Npm,
                    "left-pad",
                    Some("1.3.0"),
                    None::<String>,
                ),
                trace_id: "trace-bind".to_owned(),
                requested_digest: None,
                source_url: None,
                explicit_version_or_integrity: false,
            },
        };

        let response = evaluate_with_policy_repository(
            &PolicyRepository::InMemory(repository.clone()),
            &DecisionEngine,
            request,
        )
        .await
        .expect("decision should evaluate");

        assert_eq!(response.mode, PolicyMode::Shadow);
        assert_eq!(response.policy_snapshot_id, snapshot_id);

        let persisted = repository.decision_records().await;
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].tenant_id, tenant_id);
        assert_eq!(persisted[0].package_request.coordinate.name, "left-pad");
        assert_eq!(persisted[0].policy_snapshot_id, snapshot_id);
        assert!(persisted[0].evidence_references.is_empty());
        assert!(repository.analysis_jobs().await.is_empty());
    }

    #[tokio::test]
    async fn unknown_artifact_digest_creates_analysis_job() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let digest = ArtifactDigest::sha256("c".repeat(64)).expect("valid digest");
        let repository = InMemoryPolicyRepository::new();
        repository
            .upsert_profile(LoadedPolicyProfile {
                id: policy_profile_id,
                tenant_id,
                mode: PolicyMode::Enforce,
                latest_snapshot: PolicySnapshot {
                    id: snapshot_id,
                    tenant_id,
                    version: "2026.05.1".to_owned(),
                    effective_at: chrono::Utc::now(),
                    immutable_rule_hash: ArtifactDigest::sha256("a".repeat(64)).unwrap(),
                },
                signal_configuration: PolicySignalConfiguration::default(),
            })
            .await;
        repository
            .upsert_registry_binding(RegistryPolicyBinding {
                tenant_id,
                registry_config_id,
                policy_profile_id,
                mode: PolicyMode::Enforce,
            })
            .await;

        let request = DecisionRequest {
            tenant_id,
            registry_config_id,
            policy_profile_id,
            request: NormalizedPackageRequest {
                kind: PackageRequestKind::Artifact,
                tenant_id,
                registry_config_id,
                policy_profile_id,
                coordinate: PackageCoordinate::new(
                    PackageEcosystem::Npm,
                    "left-pad",
                    Some("1.3.0"),
                    None::<String>,
                ),
                trace_id: "trace-unknown-artifact".to_owned(),
                requested_digest: Some(digest.clone()),
                source_url: Some(
                    "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz".to_owned(),
                ),
                explicit_version_or_integrity: true,
            },
        };

        let response = evaluate_with_policy_repository(
            &PolicyRepository::InMemory(repository.clone()),
            &DecisionEngine,
            request,
        )
        .await
        .expect("decision should evaluate");

        assert_eq!(
            response.decision,
            aegiscudo_core::PolicyDecision::QuarantinePendingAnalysis
        );
        assert!(response.create_analysis_job);
        let jobs = repository.analysis_jobs().await;
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].artifact_digest, digest);
        assert_eq!(jobs[0].policy_snapshot_id, snapshot_id);
    }

    #[tokio::test]
    async fn query_binds_policy_profile_without_registry_context() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let coordinate = PackageCoordinate::new(
            PackageEcosystem::GithubActions,
            "checkout",
            Some("f".repeat(40)),
            Some("actions"),
        );
        let repository = InMemoryPolicyRepository::new();
        repository
            .upsert_profile(LoadedPolicyProfile {
                id: policy_profile_id,
                tenant_id,
                mode: PolicyMode::Enforce,
                latest_snapshot: PolicySnapshot {
                    id: snapshot_id,
                    tenant_id,
                    version: "2026.05.13".to_owned(),
                    effective_at: chrono::Utc::now(),
                    immutable_rule_hash: ArtifactDigest::sha256("a".repeat(64)).unwrap(),
                },
                signal_configuration: PolicySignalConfiguration::default(),
            })
            .await;
        repository
            .remember_package_signal(tenant_id, coordinate.clone(), None, "known-malicious", None)
            .await;

        let response = query_with_policy_repository(
            &PolicyRepository::InMemory(repository.clone()),
            &DecisionEngine,
            DecisionQueryRequest {
                tenant_id,
                policy_profile_id,
                request: NormalizedQueryRequest {
                    kind: PackageRequestKind::Metadata,
                    tenant_id,
                    policy_profile_id,
                    coordinate,
                    trace_id: "trace-gh-query".to_owned(),
                    requested_digest: None,
                    explicit_version_or_integrity: true,
                },
            },
        )
        .await
        .expect("query should evaluate");

        assert_eq!(
            response.decision,
            aegiscudo_core::PolicyDecision::BlockKnownMalicious
        );
        assert_eq!(response.policy_snapshot_id, snapshot_id);
        assert!(repository.decision_records().await.is_empty());
        assert!(repository.analysis_jobs().await.is_empty());
    }

    #[tokio::test]
    async fn known_artifact_digest_does_not_create_analysis_job() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let digest = ArtifactDigest::sha256("d".repeat(64)).expect("valid digest");
        let repository = InMemoryPolicyRepository::new();
        repository
            .upsert_profile(LoadedPolicyProfile {
                id: policy_profile_id,
                tenant_id,
                mode: PolicyMode::Enforce,
                latest_snapshot: PolicySnapshot {
                    id: snapshot_id,
                    tenant_id,
                    version: "2026.05.1".to_owned(),
                    effective_at: chrono::Utc::now(),
                    immutable_rule_hash: ArtifactDigest::sha256("a".repeat(64)).unwrap(),
                },
                signal_configuration: PolicySignalConfiguration::default(),
            })
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
            .remember_artifact(tenant_id, digest.clone())
            .await;

        let request = DecisionRequest {
            tenant_id,
            registry_config_id,
            policy_profile_id,
            request: NormalizedPackageRequest {
                kind: PackageRequestKind::Artifact,
                tenant_id,
                registry_config_id,
                policy_profile_id,
                coordinate: PackageCoordinate::new(
                    PackageEcosystem::Npm,
                    "left-pad",
                    Some("1.3.0"),
                    None::<String>,
                ),
                trace_id: "trace-known-artifact".to_owned(),
                requested_digest: Some(digest),
                source_url: Some(
                    "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz".to_owned(),
                ),
                explicit_version_or_integrity: true,
            },
        };

        let response = evaluate_with_policy_repository(
            &PolicyRepository::InMemory(repository.clone()),
            &DecisionEngine,
            request,
        )
        .await
        .expect("decision should evaluate");

        assert_eq!(response.decision, aegiscudo_core::PolicyDecision::Allow);
        assert!(!response.create_analysis_job);
        assert!(repository.analysis_jobs().await.is_empty());
    }

    #[tokio::test]
    async fn simulate_route_does_not_persist_decisions_or_create_analysis_jobs() {
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        let simulated_policy_profile_id = Uuid::now_v7();
        let snapshot_id = Uuid::now_v7();
        let simulated_snapshot_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();
        let repository = InMemoryPolicyRepository::new();
        repository
            .upsert_profile(LoadedPolicyProfile {
                id: policy_profile_id,
                tenant_id,
                mode: PolicyMode::Warn,
                latest_snapshot: PolicySnapshot {
                    id: snapshot_id,
                    tenant_id,
                    version: "2026.05.2".to_owned(),
                    effective_at: chrono::Utc::now(),
                    immutable_rule_hash: ArtifactDigest::sha256("e".repeat(64)).unwrap(),
                },
                signal_configuration: PolicySignalConfiguration::default(),
            })
            .await;
        repository
            .upsert_profile(LoadedPolicyProfile {
                id: simulated_policy_profile_id,
                tenant_id,
                mode: PolicyMode::Shadow,
                latest_snapshot: PolicySnapshot {
                    id: simulated_snapshot_id,
                    tenant_id,
                    version: "2026.05.3".to_owned(),
                    effective_at: chrono::Utc::now(),
                    immutable_rule_hash: ArtifactDigest::sha256("f".repeat(64)).unwrap(),
                },
                signal_configuration: PolicySignalConfiguration::default(),
            })
            .await;
        repository
            .upsert_registry_binding(RegistryPolicyBinding {
                tenant_id,
                registry_config_id,
                policy_profile_id,
                mode: PolicyMode::Warn,
            })
            .await;

        let request = DecisionRequest {
            tenant_id,
            registry_config_id,
            policy_profile_id: simulated_policy_profile_id,
            request: NormalizedPackageRequest {
                kind: PackageRequestKind::Metadata,
                tenant_id,
                registry_config_id,
                policy_profile_id: simulated_policy_profile_id,
                coordinate: PackageCoordinate::new(
                    PackageEcosystem::Npm,
                    "left-pad",
                    Some("1.3.0"),
                    None::<String>,
                ),
                trace_id: "trace-simulate".to_owned(),
                requested_digest: None,
                source_url: None,
                explicit_version_or_integrity: false,
            },
        };

        let state = AppState::new(PolicyRepository::InMemory(repository.clone()));
        let decision = simulate_with_state(&state, request)
            .await
            .expect("simulate response");
        assert_eq!(decision.trace_id, "trace-simulate");
        assert_eq!(decision.policy_snapshot_id, simulated_snapshot_id);
        assert_eq!(decision.policy_profile_id, simulated_policy_profile_id);
        assert_ne!(decision.policy_snapshot_id, snapshot_id);

        assert!(repository.decision_records().await.is_empty());
        assert!(repository.analysis_jobs().await.is_empty());
    }
}
