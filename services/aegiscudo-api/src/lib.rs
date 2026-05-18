use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use aegiscudo_core::{
    ArtifactDigest, AuditEvent, Metadata, PackageCoordinate, PackageEcosystem, PolicyDecision,
    PolicyMode, validate_audit_metadata,
};
use aegiscudo_protocol::{
    DecisionQueryRequest, DecisionRequest, DecisionResponse, NormalizedPackageRequest,
    NormalizedQueryRequest, PackageRequestKind,
};
use aegiscudo_telemetry::health;
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, patch, post, put},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row, postgres::PgPoolOptions, types::Json as SqlJson};
#[cfg(test)]
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

pub const SERVICE_NAME: &str = "aegiscudo-api";
const ACTOR_HEADER: &str = "x-aegiscudo-actor-id";
const TRACE_HEADER: &str = "x-aegiscudo-trace-id";
const RELOAD_TIMEOUT: Duration = Duration::from_millis(750);
const DECISION_TIMEOUT: Duration = Duration::from_millis(1_500);
const SBOM_SERVICE_CONNECT_TIMEOUT: Duration = Duration::from_millis(1_500);
const SBOM_SERVICE_LIST_TIMEOUT: Duration = Duration::from_millis(1_500);
const MAX_SBOM_LIST_LIMIT: u32 = 50;
const DEFAULT_TRIAGE_COUNTER_URL: &str = "http://127.0.0.1:18001";
const DEFAULT_SBOM_SERVICE_URL: &str = "http://127.0.0.1:8086";
const DEFAULT_LOCAL_AUTH_TENANT_ID: &str = "018f4a6f-55d0-7000-8000-000000000001";
const DEFAULT_MOCK_IDENTITY_ID: &str = "platform-admin";

struct MockIdentityCatalogEntry {
    id: &'static str,
    email: &'static str,
}

const LOCAL_MOCK_IDENTITIES: &[MockIdentityCatalogEntry] = &[
    MockIdentityCatalogEntry {
        id: "developer",
        email: "dev@aegiscudo.invalid",
    },
    MockIdentityCatalogEntry {
        id: "security-specialist",
        email: "security@aegiscudo.invalid",
    },
    MockIdentityCatalogEntry {
        id: "platform-admin",
        email: "local-admin@aegiscudo.invalid",
    },
    MockIdentityCatalogEntry {
        id: "ciso-auditor",
        email: "ciso@aegiscudo.invalid",
    },
];

#[derive(Debug, Clone)]
pub struct AppState {
    pool: PgPool,
    reload_client: Option<ReloadClient>,
    decision_client: DecisionClient,
    sbom_client: SbomServiceClient,
    auth_mode: AuthMode,
    local_auth_tenant_id: Uuid,
}

#[derive(Debug, Clone)]
pub struct ReloadClient {
    client: reqwest::Client,
    url: String,
}

impl ReloadClient {
    pub fn new(url: impl Into<String>) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder().timeout(RELOAD_TIMEOUT).build()?;
        Ok(Self {
            client,
            url: url.into(),
        })
    }

    async fn notify(&self) -> Result<(), reqwest::Error> {
        self.client
            .post(&self.url)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct DecisionClient {
    inner: DecisionClientInner,
}

#[derive(Clone)]
enum DecisionClientInner {
    Http {
        client: reqwest::Client,
        url: String,
    },
    #[cfg(test)]
    Test {
        evaluate_handler: Arc<
            dyn Fn(DecisionRequest) -> Result<DecisionResponse, DecisionClientError> + Send + Sync,
        >,
        query_handler: Arc<
            dyn Fn(DecisionQueryRequest) -> Result<DecisionResponse, DecisionClientError>
                + Send
                + Sync,
        >,
    },
}

impl std::fmt::Debug for DecisionClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DecisionClient(..)")
    }
}

impl DecisionClient {
    pub fn new(url: impl Into<String>) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .timeout(DECISION_TIMEOUT)
            .build()?;
        Ok(Self {
            inner: DecisionClientInner::Http {
                client,
                url: url.into(),
            },
        })
    }

    fn default_local() -> Self {
        Self::new(DEFAULT_TRIAGE_COUNTER_URL)
            .expect("default triage-counter client must initialize")
    }

    async fn evaluate(
        &self,
        request: DecisionRequest,
    ) -> Result<DecisionResponse, DecisionClientError> {
        self.execute_request("/v1/decisions/evaluate", request)
            .await
    }

    async fn simulate(
        &self,
        request: DecisionRequest,
    ) -> Result<DecisionResponse, DecisionClientError> {
        self.execute_request("/v1/decisions/simulate", request)
            .await
    }

    async fn query(
        &self,
        request: DecisionQueryRequest,
    ) -> Result<DecisionResponse, DecisionClientError> {
        self.execute_query_request("/v1/decisions/query", request)
            .await
    }

    async fn execute_request(
        &self,
        path: &str,
        request: DecisionRequest,
    ) -> Result<DecisionResponse, DecisionClientError> {
        match &self.inner {
            DecisionClientInner::Http { client, url } => {
                let response = client
                    .post(format!("{}{}", url.trim_end_matches('/'), path))
                    .json(&request)
                    .send()
                    .await
                    .map_err(|error| {
                        tracing::warn!(error = %error, "triage-counter decision request failed");
                        DecisionClientError::Unavailable
                    })?;
                if response.status().is_success() {
                    return response.json().await.map_err(|error| {
                        tracing::warn!(error = %error, "triage-counter decision response was invalid");
                        DecisionClientError::Unavailable
                    });
                }

                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                tracing::warn!(%status, body, "triage-counter rejected decision request");
                match status {
                    StatusCode::BAD_REQUEST => Err(DecisionClientError::InvalidRequest),
                    StatusCode::NOT_FOUND => Err(DecisionClientError::NotFound),
                    _ => Err(DecisionClientError::Unavailable),
                }
            }
            #[cfg(test)]
            DecisionClientInner::Test {
                evaluate_handler, ..
            } => evaluate_handler(request),
        }
    }

    async fn execute_query_request(
        &self,
        path: &str,
        request: DecisionQueryRequest,
    ) -> Result<DecisionResponse, DecisionClientError> {
        match &self.inner {
            DecisionClientInner::Http { client, url } => {
                let response = client
                    .post(format!("{}{}", url.trim_end_matches('/'), path))
                    .json(&request)
                    .send()
                    .await
                    .map_err(|error| {
                        tracing::warn!(error = %error, "triage-counter decision query failed");
                        DecisionClientError::Unavailable
                    })?;
                if response.status().is_success() {
                    return response.json().await.map_err(|error| {
                        tracing::warn!(error = %error, "triage-counter decision query response was invalid");
                        DecisionClientError::Unavailable
                    });
                }

                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                tracing::warn!(%status, body, "triage-counter rejected decision query");
                match status {
                    StatusCode::BAD_REQUEST => Err(DecisionClientError::InvalidRequest),
                    StatusCode::NOT_FOUND => Err(DecisionClientError::NotFound),
                    _ => Err(DecisionClientError::Unavailable),
                }
            }
            #[cfg(test)]
            DecisionClientInner::Test { query_handler, .. } => query_handler(request),
        }
    }

    #[cfg(test)]
    fn new_test<F>(handler: F) -> Self
    where
        F: Fn(DecisionRequest) -> Result<DecisionResponse, DecisionClientError>
            + Send
            + Sync
            + 'static,
    {
        Self {
            inner: DecisionClientInner::Test {
                evaluate_handler: Arc::new(handler),
                query_handler: Arc::new(|_| {
                    panic!("decision client query should not be called in this test")
                }),
            },
        }
    }

    #[cfg(test)]
    fn new_query_test<F>(handler: F) -> Self
    where
        F: Fn(DecisionQueryRequest) -> Result<DecisionResponse, DecisionClientError>
            + Send
            + Sync
            + 'static,
    {
        Self {
            inner: DecisionClientInner::Test {
                evaluate_handler: Arc::new(|_| {
                    panic!("decision client evaluate should not be called in this test")
                }),
                query_handler: Arc::new(handler),
            },
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DecisionClientError {
    #[error("decision request policy context is invalid")]
    InvalidRequest,
    #[error("policy profile or snapshot was not found")]
    NotFound,
    #[error("triage counter is unavailable")]
    Unavailable,
}

#[derive(Debug, Clone, Deserialize)]
struct SbomServiceNtiaValidation {
    valid: bool,
    issues: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct SbomServiceDocumentSummary {
    id: Uuid,
    analysis_job_id: Option<Uuid>,
    tenant_id: Option<Uuid>,
    format: String,
    source: String,
    component_count: i32,
    storage_size_bytes: i64,
    created_at: DateTime<Utc>,
    ntia_validation: SbomServiceNtiaValidation,
}

#[derive(Debug)]
struct SbomServiceDownload {
    body: Body,
    headers: HeaderMap,
}

#[derive(Clone)]
struct SbomServiceClient {
    inner: SbomServiceClientInner,
}

#[derive(Clone)]
enum SbomServiceClientInner {
    Http {
        client: reqwest::Client,
        url: String,
    },
    #[cfg(test)]
    Test {
        list_handler: Arc<
            dyn Fn(
                    Uuid,
                    Option<u32>,
                )
                    -> Result<Vec<SbomServiceDocumentSummary>, SbomServiceClientError>
                + Send
                + Sync,
        >,
        download_handler: Arc<
            dyn Fn(Uuid, Uuid) -> Result<SbomServiceDownload, SbomServiceClientError> + Send + Sync,
        >,
    },
}

impl std::fmt::Debug for SbomServiceClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SbomServiceClient(..)")
    }
}

impl SbomServiceClient {
    fn new(url: impl Into<String>) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .connect_timeout(SBOM_SERVICE_CONNECT_TIMEOUT)
            .build()?;
        Ok(Self {
            inner: SbomServiceClientInner::Http {
                client,
                url: url.into(),
            },
        })
    }

    fn default_local() -> Self {
        Self::new(DEFAULT_SBOM_SERVICE_URL).expect("default sbom-service client must initialize")
    }

    async fn list_tenant_sboms(
        &self,
        tenant_id: Uuid,
        limit: Option<u32>,
    ) -> Result<Vec<SbomServiceDocumentSummary>, SbomServiceClientError> {
        match &self.inner {
            SbomServiceClientInner::Http { client, url } => {
                let mut endpoint =
                    format!("{}/v1/tenants/{tenant_id}/sboms", url.trim_end_matches('/'));
                if let Some(limit) = limit {
                    endpoint.push_str(&format!("?limit={limit}"));
                }
                let request = client.get(endpoint).timeout(SBOM_SERVICE_LIST_TIMEOUT);
                let response = request.send().await.map_err(|error| {
                    tracing::warn!(error = %error, "sbom-service list request failed");
                    SbomServiceClientError::Unavailable
                })?;
                if response.status().is_success() {
                    return response.json().await.map_err(|error| {
                        tracing::warn!(error = %error, "sbom-service list response was invalid");
                        SbomServiceClientError::Unavailable
                    });
                }

                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                tracing::warn!(%status, body, "sbom-service rejected list request");
                match status {
                    StatusCode::BAD_REQUEST => Err(SbomServiceClientError::InvalidRequest),
                    StatusCode::NOT_FOUND => Err(SbomServiceClientError::NotFound),
                    _ => Err(SbomServiceClientError::Unavailable),
                }
            }
            #[cfg(test)]
            SbomServiceClientInner::Test { list_handler, .. } => list_handler(tenant_id, limit),
        }
    }

    async fn download_tenant_sbom(
        &self,
        tenant_id: Uuid,
        sbom_id: Uuid,
    ) -> Result<SbomServiceDownload, SbomServiceClientError> {
        match &self.inner {
            SbomServiceClientInner::Http { client, url } => {
                let response = client
                    .get(format!(
                        "{}/v1/tenants/{tenant_id}/sboms/{sbom_id}",
                        url.trim_end_matches('/')
                    ))
                    .send()
                    .await
                    .map_err(|error| {
                        tracing::warn!(error = %error, "sbom-service download request failed");
                        SbomServiceClientError::Unavailable
                    })?;
                if response.status().is_success() {
                    let headers = forwarded_download_headers(response.headers());
                    let body = Body::from_stream(response.bytes_stream());
                    return Ok(SbomServiceDownload { body, headers });
                }

                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                tracing::warn!(%status, body, "sbom-service rejected download request");
                match status {
                    StatusCode::BAD_REQUEST => Err(SbomServiceClientError::InvalidRequest),
                    StatusCode::NOT_FOUND => Err(SbomServiceClientError::NotFound),
                    _ => Err(SbomServiceClientError::Unavailable),
                }
            }
            #[cfg(test)]
            SbomServiceClientInner::Test {
                download_handler, ..
            } => download_handler(tenant_id, sbom_id),
        }
    }

    #[cfg(test)]
    fn new_test<FL, FD>(list_handler: FL, download_handler: FD) -> Self
    where
        FL: Fn(Uuid, Option<u32>) -> Result<Vec<SbomServiceDocumentSummary>, SbomServiceClientError>
            + Send
            + Sync
            + 'static,
        FD: Fn(Uuid, Uuid) -> Result<SbomServiceDownload, SbomServiceClientError>
            + Send
            + Sync
            + 'static,
    {
        Self {
            inner: SbomServiceClientInner::Test {
                list_handler: Arc::new(list_handler),
                download_handler: Arc::new(download_handler),
            },
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
enum SbomServiceClientError {
    #[error("sbom request is invalid")]
    InvalidRequest,
    #[error("sbom document was not found")]
    NotFound,
    #[error("sbom service is unavailable")]
    Unavailable,
}

pub async fn connect(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await
}

pub fn app(pool: PgPool) -> Router {
    app_with_reload(pool, None)
}

pub fn app_with_reload(pool: PgPool, reload_client: Option<ReloadClient>) -> Router {
    app_with_clients(pool, reload_client, DecisionClient::default_local())
}

pub fn app_with_clients(
    pool: PgPool,
    reload_client: Option<ReloadClient>,
    decision_client: DecisionClient,
) -> Router {
    app_with_clients_and_sbom_client(
        pool,
        reload_client,
        decision_client,
        SbomServiceClient::default_local(),
    )
}

fn app_with_clients_and_sbom_client(
    pool: PgPool,
    reload_client: Option<ReloadClient>,
    decision_client: DecisionClient,
    sbom_client: SbomServiceClient,
) -> Router {
    app_with_clients_and_auth_config(
        pool,
        reload_client,
        decision_client,
        sbom_client,
        configured_auth_mode(),
        configured_local_auth_tenant_id(),
    )
}

fn app_with_clients_and_auth_config(
    pool: PgPool,
    reload_client: Option<ReloadClient>,
    decision_client: DecisionClient,
    sbom_client: SbomServiceClient,
    auth_mode: AuthMode,
    local_auth_tenant_id: Uuid,
) -> Router {
    let state = AppState {
        pool,
        reload_client,
        decision_client,
        sbom_client,
        auth_mode,
        local_auth_tenant_id,
    };
    Router::new()
        .route("/healthz", get(|| async { Json(health(SERVICE_NAME)) }))
        .route("/readyz", get(|| async { Json(health(SERVICE_NAME)) }))
        .route(
            "/v1/auth/session",
            get(get_auth_session).delete(clear_auth_session),
        )
        .route("/v1/auth/session/mock", put(set_mock_auth_session))
        .route("/v1/auth/mock-identities", get(list_mock_auth_identities))
        .route("/v1/decisions/evaluate", post(evaluate_decision))
        .route(
            "/v1/cli/github-actions/enrich",
            post(enrich_cli_github_actions),
        )
        .route("/v1/cli/scans", post(submit_cli_scan))
        .route("/v1/cli/risk", post(submit_cli_risk))
        .route("/v1/cli/explain", post(explain_cli_package))
        .route(
            "/v1/tenants/{tenant_id}/analysis/request-timeline",
            get(list_request_timeline),
        )
        .route(
            "/v1/tenants/{tenant_id}/analysis/dashboard-metrics",
            get(get_dashboard_metrics),
        )
        .route(
            "/v1/tenants/{tenant_id}/policy-profiles",
            get(list_policy_profiles),
        )
        .route(
            "/v1/tenants/{tenant_id}/policy-profiles/{policy_profile_id}/scorecard-thresholds",
            get(get_policy_scorecard_thresholds),
        )
        .route(
            "/v1/tenants/{tenant_id}/policy-simulator/replay",
            post(simulate_policy_replay),
        )
        .route(
            "/v1/tenants/{tenant_id}/analysis/quarantine-queue",
            get(list_quarantine_queue),
        )
        .route("/v1/tenants/{tenant_id}/sboms", get(list_tenant_sboms))
        .route(
            "/v1/tenants/{tenant_id}/sboms/{sbom_id}",
            get(download_tenant_sbom),
        )
        .route(
            "/v1/tenants/{tenant_id}/deps-dev/packages",
            get(list_deps_dev_packages),
        )
        .route("/v1/tenants/{tenant_id}/ioc-records", get(list_ioc_records))
        .route(
            "/v1/tenants/{tenant_id}/github-actions/scan-results",
            get(list_github_actions_scan_results),
        )
        .route(
            "/v1/tenants/{tenant_id}/artifacts/{artifact_id}/evidence",
            get(get_artifact_evidence),
        )
        .route(
            "/v1/tenants/{tenant_id}/artifacts/{artifact_id}/static-analysis-reports",
            get(list_artifact_static_analysis_reports),
        )
        .route(
            "/v1/tenants/{tenant_id}/artifacts/{artifact_id}/sandbox-execution-reports",
            get(list_artifact_sandbox_execution_reports),
        )
        .route(
            "/v1/tenants/{tenant_id}/overrides",
            get(list_overrides).post(create_override),
        )
        .route(
            "/v1/tenants/{tenant_id}/overrides/emergency-bypass",
            post(create_emergency_bypass),
        )
        .route(
            "/v1/tenants/{tenant_id}/overrides/{override_id}/approve",
            post(approve_override),
        )
        .route(
            "/v1/tenants/{tenant_id}/overrides/{override_id}/deny",
            post(deny_override),
        )
        .route(
            "/v1/tenants/{tenant_id}/registry-configs",
            get(list_registry_configs).post(create_registry_config),
        )
        .route(
            "/v1/tenants/{tenant_id}/registry-configs/{registry_config_id}",
            get(get_registry_config)
                .patch(update_registry_config)
                .delete(delete_registry_config),
        )
        .route(
            "/v1/tenants/{tenant_id}/credentials",
            get(list_credentials).post(create_credential),
        )
        .route(
            "/v1/tenants/{tenant_id}/credentials/{credential_id}",
            patch(rotate_credential).delete(delete_credential),
        )
        .route(
            "/v1/tenants/{tenant_id}/credentials/{credential_id}/test-connection",
            post(test_credential_connection),
        )
        .route(
            "/v1/tenants/{tenant_id}/audit-events",
            get(list_audit_events),
        )
        .route(
            "/v1/tenants/{tenant_id}/audit-events/export.csv",
            get(export_audit_events_csv),
        )
        .route(
            "/v1/tenants/{tenant_id}/openvex-documents",
            get(list_openvex_documents).post(create_openvex_document),
        )
        .route(
            "/v1/tenants/{tenant_id}/openvex-documents/{openvex_document_id}",
            get(get_openvex_document),
        )
        .route(
            "/v1/tenants/{tenant_id}/ai-providers",
            get(list_ai_providers),
        )
        .route("/v1/tenants/{tenant_id}/llm-usage", get(get_llm_usage))
        .with_state(state)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RegistryAdapterDto {
    Npm,
    Pypi,
    Cargo,
    Maven,
    DockerOci,
    GenericHttp,
}

impl RegistryAdapterDto {
    fn as_db(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pypi => "pypi",
            Self::Cargo => "cargo",
            Self::Maven => "maven",
            Self::DockerOci => "docker-oci",
            Self::GenericHttp => "generic-http",
        }
    }

    fn phase_1a_supported(self) -> bool {
        matches!(self, Self::Npm | Self::Pypi)
    }

    fn from_ecosystem(ecosystem: PackageEcosystem) -> Result<Self, ApiError> {
        match ecosystem {
            PackageEcosystem::Npm => Ok(Self::Npm),
            PackageEcosystem::Pypi => Ok(Self::Pypi),
            PackageEcosystem::Cargo => Ok(Self::Cargo),
            PackageEcosystem::Maven => Ok(Self::Maven),
            PackageEcosystem::DockerOci => Ok(Self::DockerOci),
            PackageEcosystem::GenericHttp => Ok(Self::GenericHttp),
            PackageEcosystem::GithubActions => Err(ApiError::InvalidRequest(
                "githubactions packages do not map to a registry adapter".to_owned(),
            )),
            PackageEcosystem::VscodeExtension => Err(ApiError::InvalidRequest(
                "vscode-extension packages do not map to a registry adapter".to_owned(),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialAuthTypeDto {
    None,
    Basic,
    Bearer,
    Mtls,
}

impl CredentialAuthTypeDto {
    fn as_db(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Basic => "basic",
            Self::Bearer => "bearer",
            Self::Mtls => "mtls",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    MockOidc,
    Oidc,
    Saml,
}

impl AuthMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::MockOidc => "mock_oidc",
            Self::Oidc => "oidc",
            Self::Saml => "saml",
        }
    }

    fn supports_mock_identities(self) -> bool {
        matches!(self, Self::MockOidc)
    }
}

impl std::fmt::Display for AuthMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOverrideRequest {
    pub scope: Value,
    pub reason: String,
    #[serde(default)]
    pub requested_by: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverrideActionRequest {
    pub reason: String,
    #[serde(default)]
    pub actor_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEmergencyBypassRequest {
    pub scope: Value,
    pub reason: String,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub actor_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OverrideResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub scope: Value,
    pub reason: String,
    pub requested_by: Option<Uuid>,
    pub approved_by: Option<Uuid>,
    pub status: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRegistryConfigRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub adapter: RegistryAdapterDto,
    pub upstream_url: String,
    pub mount_path: String,
    #[serde(default = "default_auth_type")]
    pub auth_type: CredentialAuthTypeDto,
    #[serde(default)]
    pub credential_ref: Option<Uuid>,
    #[serde(default)]
    pub mode: PolicyMode,
    pub policy_profile_id: Uuid,
    #[serde(default = "default_cache_ttl_seconds")]
    pub cache_ttl_seconds: i32,
    #[serde(default = "default_true")]
    pub verify_upstream_tls: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateRegistryConfigRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub upstream_url: Option<String>,
    #[serde(default)]
    pub auth_type: Option<CredentialAuthTypeDto>,
    #[serde(default)]
    pub credential_ref: Option<Option<Uuid>>,
    #[serde(default)]
    pub mode: Option<PolicyMode>,
    #[serde(default)]
    pub policy_profile_id: Option<Uuid>,
    #[serde(default)]
    pub cache_ttl_seconds: Option<i32>,
    #[serde(default)]
    pub verify_upstream_tls: Option<bool>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryConfigResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: String,
    pub adapter: RegistryAdapterDto,
    pub upstream_url: String,
    pub mount_path: String,
    pub auth_type: CredentialAuthTypeDto,
    pub credential_ref: Option<Uuid>,
    pub mode: PolicyMode,
    pub policy_profile_id: Uuid,
    pub cache_ttl_seconds: i32,
    pub verify_upstream_tls: bool,
    pub enabled: bool,
    pub deleted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum OpenVexExpiryMode {
    Never,
    ExpiresAt,
}

impl OpenVexExpiryMode {
    fn as_db(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::ExpiresAt => "expires_at",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenVexExpiryPolicyRequest {
    pub mode: OpenVexExpiryMode,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CreateOpenVexDocumentRequest {
    pub source: String,
    pub document: Value,
    #[serde(default = "default_openvex_expiry_policy")]
    pub expiry_policy: OpenVexExpiryPolicyRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenVexExpiryPolicyResponse {
    pub mode: OpenVexExpiryMode,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OpenVexDocumentSummaryResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub source: String,
    pub document_id: String,
    pub author: String,
    pub context: String,
    pub version: i64,
    pub document_timestamp: DateTime<Utc>,
    pub imported_at: DateTime<Utc>,
    pub expiry_policy: OpenVexExpiryPolicyResponse,
    pub document_digest: String,
    pub statement_count: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OpenVexDocumentResponse {
    #[serde(flatten)]
    pub summary: OpenVexDocumentSummaryResponse,
    pub document: Value,
}

#[derive(Debug, Clone)]
struct ValidatedOpenVexDocument {
    context: String,
    document_id: String,
    author: String,
    version: i64,
    document_timestamp: DateTime<Utc>,
    statement_count: i32,
    statements: Vec<ValidatedOpenVexStatement>,
}

#[derive(Debug, Clone)]
struct ValidatedOpenVexStatement {
    statement_index: i32,
    vulnerability_id: String,
    status: String,
    product_id: String,
    justification: Option<String>,
    impact_statement: Option<String>,
    action_statement: Option<String>,
    statement_timestamp: Option<DateTime<Utc>>,
    raw_statement: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliRiskRequest {
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    pub coordinate: PackageCoordinate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CliRiskResponse {
    pub tenant_id: Uuid,
    pub registry_config_id: Uuid,
    pub policy_profile_id: Uuid,
    pub coordinate: PackageCoordinate,
    pub decision: PolicyDecision,
    pub rationale: Vec<String>,
    pub trace_id: String,
    pub create_analysis_job: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliScanRequest {
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    pub packages: Vec<CliScanPackageRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliScanPackageRequest {
    pub coordinate: PackageCoordinate,
    #[serde(default)]
    pub artifact_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliGithubActionsEnrichmentRequest {
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    #[serde(default)]
    pub policy_profile_id: Option<Uuid>,
    pub packages: Vec<CliGithubActionsEnrichmentPackageRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliGithubActionsEnrichmentPackageRequest {
    pub coordinate: PackageCoordinate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CliScanResponse {
    pub tenant_id: Uuid,
    pub registry_config_id: Uuid,
    pub policy_profile_id: Uuid,
    pub findings: Vec<CliScanFindingResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CliGithubActionsEnrichmentResponse {
    pub tenant_id: Uuid,
    pub policy_profile_id: Uuid,
    pub findings: Vec<CliScanFindingResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CliScanFindingResponse {
    pub coordinate: PackageCoordinate,
    #[serde(default)]
    pub artifact_sha256: Option<String>,
    pub decision: PolicyDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_timestamp: Option<DateTime<Utc>>,
    pub trace_id: String,
    pub rationale: Vec<String>,
    #[serde(default)]
    pub fallback_coordinate: Option<PackageCoordinate>,
    pub create_analysis_job: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliExplainRequest {
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    pub coordinate: PackageCoordinate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CliExplainResponse {
    pub tenant_id: Uuid,
    pub analysis_job_id: Uuid,
    pub artifact_id: Uuid,
    pub trace_id: String,
    pub coordinate: PackageCoordinate,
    pub artifact_sha256: String,
    pub recommended_action: String,
    pub confidence: String,
    pub summary: Value,
    pub ai_explanation: Option<Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCredentialRequest {
    pub name: String,
    pub credential_type: String,
    #[serde(default = "default_credential_source")]
    pub source: String,
    #[serde(default)]
    pub encrypted_value_ciphertext: Option<Vec<u8>>,
    #[serde(default)]
    pub encrypted_value_key_id: Option<String>,
    #[serde(default)]
    pub configured: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RotateCredentialRequest {
    #[serde(default)]
    pub encrypted_value_ciphertext: Option<Vec<u8>>,
    #[serde(default)]
    pub encrypted_value_key_id: Option<String>,
    #[serde(default)]
    pub configured: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialStatusResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub credential_type: String,
    pub source: String,
    pub encrypted_value_key_id: Option<String>,
    pub configured: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthSubjectResponse {
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub display_name: String,
    pub email: String,
    pub roles: Vec<String>,
    pub mock_identity_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthSessionResponse {
    pub authenticated: bool,
    pub auth_mode: AuthMode,
    pub mock_identity_supported: bool,
    pub subject: Option<AuthSubjectResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MockIdentityListResponse {
    pub identities: Vec<AuthSubjectResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetMockAuthSessionRequest {
    pub identity_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageCoordinateSummaryResponse {
    pub ecosystem: String,
    pub name: String,
    pub version: Option<String>,
    pub namespace: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceCountsResponse {
    pub static_reports: i64,
    pub sandbox_runs: i64,
    pub ai_explanations: i64,
    pub audit_events: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DashboardFeedFreshness {
    Fresh,
    Stale,
    Missing,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DashboardMetricsResponse {
    pub blocked_packages: i64,
    pub quarantine_queue_depth: i64,
    pub active_overrides: i64,
    pub feed_freshness: DashboardFeedFreshness,
    pub feed_snapshot_age_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestTimelineBucketResponse {
    pub bucket_start: DateTime<Utc>,
    pub allow: i64,
    pub warn: i64,
    pub quarantine: i64,
    pub block: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuarantineQueueItemResponse {
    pub analysis_job_id: Uuid,
    pub artifact_id: Uuid,
    pub trace_id: String,
    pub coordinate: PackageCoordinateSummaryResponse,
    pub artifact_sha256: String,
    pub recommended_action: String,
    pub confidence: String,
    pub requires_hitl: bool,
    pub summary: Value,
    pub evidence_counts: EvidenceCountsResponse,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArtifactEvidenceResponse {
    pub analysis_job_id: Uuid,
    pub artifact_id: Uuid,
    pub trace_id: String,
    pub coordinate: PackageCoordinateSummaryResponse,
    pub artifact_sha256: String,
    pub recommended_action: String,
    pub confidence: String,
    pub requires_hitl: bool,
    pub summary: Value,
    pub static_reports: Vec<Value>,
    pub sandbox_runs: Vec<Value>,
    pub ai_explanation: Option<Value>,
    pub audit_events: Vec<AuditEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArtifactStaticAnalysisReportsResponse {
    pub analysis_job_id: Uuid,
    pub artifact_id: Uuid,
    pub trace_id: String,
    pub reports: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArtifactSandboxExecutionReportsResponse {
    pub analysis_job_id: Uuid,
    pub artifact_id: Uuid,
    pub trace_id: String,
    pub runs: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyProfileSummaryResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub mode: PolicyMode,
    pub latest_version_id: Uuid,
    pub latest_version: String,
    pub latest_effective_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub request_count_last_30_days: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignalPolicyAction {
    Allow,
    Warn,
    Block,
    Hitl,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScorecardCheckThresholdResponse {
    pub min_score: f64,
    pub action: SignalPolicyAction,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DepsDdevPackageSummaryResponse {
    pub purl: String,
    pub ecosystem: String,
    pub namespace: Option<String>,
    pub package_name: String,
    pub package_version: Option<String>,
    pub licenses: Vec<String>,
    pub dependency_count: i64,
    pub source_repo_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DepsDdevPackagesResponse {
    pub packages: Vec<DepsDdevPackageSummaryResponse>,
    pub snapshot_taken_at: Option<DateTime<Utc>>,
    pub total: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyScorecardThresholdsResponse {
    pub policy_profile_id: Uuid,
    pub policy_version_id: Uuid,
    pub code_review: ScorecardCheckThresholdResponse,
    pub branch_protection: ScorecardCheckThresholdResponse,
    pub ci_cd: ScorecardCheckThresholdResponse,
    pub maintained: ScorecardCheckThresholdResponse,
    pub signed_releases: ScorecardCheckThresholdResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySimulationRequest {
    pub policy_profile_id: Uuid,
    #[serde(default = "default_policy_simulation_lookback_days")]
    pub lookback_days: i32,
    #[serde(default)]
    pub ecosystem: Option<PackageEcosystem>,
    #[serde(default = "default_policy_simulation_limit")]
    pub limit: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDecisionCountsResponse {
    pub allow: i64,
    pub allow_with_warning: i64,
    pub quarantine_pending_analysis: i64,
    pub block_known_malicious: i64,
    pub block_policy_violation: i64,
    pub require_hitl_approval: i64,
    pub fallback_to_approved_candidate: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicySimulationDiffItemResponse {
    pub package_request_id: Uuid,
    pub trace_id: String,
    pub requested_at: DateTime<Utc>,
    pub coordinate: PackageCoordinateSummaryResponse,
    pub baseline_policy_profile_id: Uuid,
    pub baseline_policy_profile_name: String,
    pub baseline_decision: PolicyDecision,
    pub baseline_rationale: Vec<String>,
    pub simulated_decision: PolicyDecision,
    pub simulated_rationale: Vec<String>,
    pub changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicySimulationResponse {
    pub tenant_id: Uuid,
    pub target_policy_profile_id: Uuid,
    pub target_policy_profile_name: String,
    pub target_policy_mode: PolicyMode,
    pub target_latest_version_id: Uuid,
    pub target_latest_version: String,
    pub lookback_days: i32,
    pub ecosystem: Option<String>,
    pub replayed_request_count: i64,
    pub changed_request_count: i64,
    pub baseline_counts: PolicyDecisionCountsResponse,
    pub simulated_counts: PolicyDecisionCountsResponse,
    pub items: Vec<PolicySimulationDiffItemResponse>,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OverrideQueueItemResponse {
    pub id: Uuid,
    pub scope: Value,
    pub reason: String,
    pub requested_by: Option<Uuid>,
    pub requested_by_display: Option<String>,
    pub approved_by: Option<Uuid>,
    pub approved_by_display: Option<String>,
    pub status: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SbomNtiaValidationResponse {
    pub valid: bool,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SbomDocumentSummaryResponse {
    pub id: Uuid,
    pub analysis_job_id: Option<Uuid>,
    pub tenant_id: Option<Uuid>,
    pub format: String,
    pub source: String,
    pub component_count: i32,
    pub storage_size_bytes: i64,
    pub created_at: DateTime<Utc>,
    pub ntia_validation: SbomNtiaValidationResponse,
}

#[derive(Debug, Clone, Serialize)]
struct CredentialTestResponse {
    credential_id: Uuid,
    configured: bool,
    message: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ErrorBody {
    message: String,
}

#[derive(Debug, Clone, Copy)]
struct CliScanRegistryContext {
    tenant_id: Uuid,
    registry_config_id: Uuid,
    policy_profile_id: Uuid,
}

#[derive(Debug, Clone, Copy)]
struct CliPolicyContext {
    tenant_id: Uuid,
    policy_profile_id: Uuid,
}

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("request actor is required")]
    MissingActor,
    #[error("request actor is not authorized")]
    Forbidden,
    #[error("requested resource was not found")]
    NotFound,
    #[error("requested resource conflicts with existing state")]
    Conflict,
    #[error("mock identities are unavailable when auth mode is {0}")]
    UnsupportedAuthMode(AuthMode),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error(transparent)]
    DecisionClient(#[from] DecisionClientError),
    #[error(transparent)]
    SbomClient(#[from] SbomServiceClientError),
    #[error("database unavailable")]
    Database(#[from] sqlx::Error),
    #[error("reload notification failed")]
    Reload(#[from] reqwest::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::MissingActor => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict => StatusCode::CONFLICT,
            Self::UnsupportedAuthMode(_) => StatusCode::CONFLICT,
            Self::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            Self::DecisionClient(DecisionClientError::InvalidRequest) => StatusCode::BAD_REQUEST,
            Self::DecisionClient(DecisionClientError::NotFound) => StatusCode::NOT_FOUND,
            Self::DecisionClient(DecisionClientError::Unavailable) => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            Self::SbomClient(SbomServiceClientError::InvalidRequest) => StatusCode::BAD_REQUEST,
            Self::SbomClient(SbomServiceClientError::NotFound) => StatusCode::NOT_FOUND,
            Self::SbomClient(SbomServiceClientError::Unavailable) => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            Self::Database(_) | Self::Reload(_) => StatusCode::SERVICE_UNAVAILABLE,
        };
        let message = self.to_string();
        (status, Json(ErrorBody { message })).into_response()
    }
}

async fn evaluate_decision(
    State(state): State<AppState>,
    Json(request): Json<DecisionRequest>,
) -> Result<Json<DecisionResponse>, ApiError> {
    Ok(Json(state.decision_client.evaluate(request).await?))
}

async fn get_auth_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AuthSessionResponse>, ApiError> {
    if !state.auth_mode.supports_mock_identities() {
        return Ok(Json(AuthSessionResponse {
            authenticated: false,
            auth_mode: state.auth_mode,
            mock_identity_supported: false,
            subject: None,
        }));
    }

    let subject = match actor_id_from_headers(&headers) {
        Some(actor_id) => load_auth_subject_by_user_id(&state.pool, actor_id).await?,
        None if headers.contains_key(ACTOR_HEADER) => return Err(ApiError::MissingActor),
        None => {
            load_mock_identity_subject(
                &state.pool,
                state.local_auth_tenant_id,
                DEFAULT_MOCK_IDENTITY_ID,
            )
            .await?
        }
    };

    Ok(Json(AuthSessionResponse {
        authenticated: subject.is_some(),
        auth_mode: state.auth_mode,
        mock_identity_supported: true,
        subject,
    }))
}

async fn clear_auth_session() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn list_mock_auth_identities(
    State(state): State<AppState>,
) -> Result<Json<MockIdentityListResponse>, ApiError> {
    ensure_mock_auth_mode(state.auth_mode)?;
    Ok(Json(MockIdentityListResponse {
        identities: load_mock_identity_subjects(&state.pool, state.local_auth_tenant_id).await?,
    }))
}

async fn set_mock_auth_session(
    State(state): State<AppState>,
    Json(request): Json<SetMockAuthSessionRequest>,
) -> Result<Json<AuthSessionResponse>, ApiError> {
    ensure_mock_auth_mode(state.auth_mode)?;
    let subject = load_mock_identity_subject(
        &state.pool,
        state.local_auth_tenant_id,
        request.identity_id.trim(),
    )
    .await?
    .ok_or(ApiError::NotFound)?;

    Ok(Json(AuthSessionResponse {
        authenticated: true,
        auth_mode: state.auth_mode,
        mock_identity_supported: true,
        subject: Some(subject),
    }))
}

async fn submit_cli_scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CliScanRequest>,
) -> Result<(StatusCode, Json<CliScanResponse>), ApiError> {
    let ecosystem = validate_cli_scan_request(&request)?;
    let context =
        resolve_cli_scan_registry_context(&state.pool, request.tenant_id, ecosystem).await?;
    let trace_prefix = trace_id(&headers);
    let mut findings = Vec::with_capacity(request.packages.len());

    for (index, package) in request.packages.into_iter().enumerate() {
        let requested_digest = parse_requested_digest(package.artifact_sha256.as_deref())?;
        let decision = state
            .decision_client
            .evaluate(DecisionRequest {
                tenant_id: context.tenant_id,
                registry_config_id: context.registry_config_id,
                policy_profile_id: context.policy_profile_id,
                request: NormalizedPackageRequest {
                    kind: if requested_digest.is_some() {
                        PackageRequestKind::Artifact
                    } else {
                        PackageRequestKind::Metadata
                    },
                    tenant_id: context.tenant_id,
                    registry_config_id: context.registry_config_id,
                    policy_profile_id: context.policy_profile_id,
                    coordinate: package.coordinate.clone(),
                    trace_id: format!("{trace_prefix}-{}", index + 1),
                    requested_digest,
                    source_url: None,
                    explicit_version_or_integrity: package.artifact_sha256.is_some(),
                },
            })
            .await?;
        let decision_timestamp = Utc::now();

        findings.push(CliScanFindingResponse {
            coordinate: package.coordinate,
            artifact_sha256: package.artifact_sha256,
            decision: decision.decision,
            decision_timestamp: Some(decision_timestamp),
            trace_id: decision.trace_id,
            rationale: decision.rationale,
            fallback_coordinate: decision.fallback_coordinate,
            create_analysis_job: decision.create_analysis_job,
        });
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(CliScanResponse {
            tenant_id: context.tenant_id,
            registry_config_id: context.registry_config_id,
            policy_profile_id: context.policy_profile_id,
            findings,
        }),
    ))
}

fn validate_cli_risk_request(request: &CliRiskRequest) -> Result<(), ApiError> {
    if request.coordinate.name.trim().is_empty() {
        return Err(ApiError::InvalidRequest(
            "coordinate name must not be empty".to_owned(),
        ));
    }
    let version_ok = request
        .coordinate
        .version
        .as_deref()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    if !version_ok {
        return Err(ApiError::InvalidRequest(
            "coordinate version must not be empty".to_owned(),
        ));
    }
    Ok(())
}

async fn submit_cli_risk(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CliRiskRequest>,
) -> Result<Json<CliRiskResponse>, ApiError> {
    validate_cli_risk_request(&request)?;
    let ecosystem = request.coordinate.ecosystem.clone();
    let context =
        resolve_cli_scan_registry_context(&state.pool, request.tenant_id, ecosystem).await?;
    let risk_trace_id = format!("{}-risk", trace_id(&headers));
    let decision = state
        .decision_client
        .evaluate(DecisionRequest {
            tenant_id: context.tenant_id,
            registry_config_id: context.registry_config_id,
            policy_profile_id: context.policy_profile_id,
            request: NormalizedPackageRequest {
                kind: PackageRequestKind::Metadata,
                tenant_id: context.tenant_id,
                registry_config_id: context.registry_config_id,
                policy_profile_id: context.policy_profile_id,
                coordinate: request.coordinate.clone(),
                trace_id: risk_trace_id,
                requested_digest: None,
                source_url: None,
                explicit_version_or_integrity: false,
            },
        })
        .await?;

    Ok(Json(CliRiskResponse {
        tenant_id: context.tenant_id,
        registry_config_id: context.registry_config_id,
        policy_profile_id: context.policy_profile_id,
        coordinate: request.coordinate,
        decision: decision.decision,
        rationale: decision.rationale,
        trace_id: decision.trace_id,
        create_analysis_job: decision.create_analysis_job,
    }))
}

fn validate_cli_github_actions_request(
    request: &CliGithubActionsEnrichmentRequest,
) -> Result<(), ApiError> {
    if request.policy_profile_id.is_none() {
        return Err(ApiError::InvalidRequest(
            "cli GitHub Actions enrichment requires policy_profile_id to avoid ambiguous profile selection"
                .to_owned(),
        ));
    }
    let first = request.packages.first().ok_or_else(|| {
        ApiError::InvalidRequest(
            "cli GitHub Actions enrichment request must include at least one package".to_owned(),
        )
    })?;
    if first.coordinate.ecosystem != PackageEcosystem::GithubActions {
        return Err(ApiError::InvalidRequest(
            "cli GitHub Actions enrichment only supports githubactions packages".to_owned(),
        ));
    }
    for package in &request.packages {
        if package.coordinate.ecosystem != PackageEcosystem::GithubActions {
            return Err(ApiError::InvalidRequest(
                "cli GitHub Actions enrichment request packages must all share the githubactions ecosystem"
                    .to_owned(),
            ));
        }
        if package
            .coordinate
            .namespace
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .is_empty()
            || package.coordinate.name.trim().is_empty()
            || package
                .coordinate
                .version
                .as_deref()
                .map(str::trim)
                .unwrap_or("")
                .is_empty()
        {
            return Err(ApiError::InvalidRequest(
                "githubactions coordinates must include owner, repo, and ref".to_owned(),
            ));
        }
        let owner = package
            .coordinate
            .namespace
            .as_deref()
            .map(str::trim)
            .unwrap_or("");
        let repo = package.coordinate.name.trim();
        let reference = package
            .coordinate
            .version
            .as_deref()
            .map(str::trim)
            .unwrap_or("");
        if owner.contains('/')
            || repo.contains('/')
            || owner.chars().any(char::is_whitespace)
            || repo.chars().any(char::is_whitespace)
            || reference.chars().any(char::is_whitespace)
        {
            return Err(ApiError::InvalidRequest(
                "githubactions coordinates must be formatted as owner/repo@ref without whitespace"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

async fn enrich_cli_github_actions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CliGithubActionsEnrichmentRequest>,
) -> Result<Json<CliGithubActionsEnrichmentResponse>, ApiError> {
    validate_cli_github_actions_request(&request)?;
    let context =
        resolve_cli_policy_context(&state.pool, request.tenant_id, request.policy_profile_id)
            .await?;
    let trace_prefix = trace_id(&headers);
    let mut findings = Vec::with_capacity(request.packages.len());

    for (index, package) in request.packages.into_iter().enumerate() {
        let decision = state
            .decision_client
            .query(DecisionQueryRequest {
                tenant_id: context.tenant_id,
                policy_profile_id: context.policy_profile_id,
                request: NormalizedQueryRequest {
                    kind: PackageRequestKind::Metadata,
                    tenant_id: context.tenant_id,
                    policy_profile_id: context.policy_profile_id,
                    coordinate: package.coordinate.clone(),
                    trace_id: format!("{trace_prefix}-{}", index + 1),
                    requested_digest: None,
                    explicit_version_or_integrity: true,
                },
            })
            .await?;
        let decision_timestamp = Utc::now();

        // Capture values needed for persistence before moving them into the finding.
        let decision_str: String = serde_json::to_value(&decision.decision)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| "ALLOW".to_owned());
        let persist_trace_id = decision.trace_id.clone();
        let persist_rationale = decision.rationale.clone();
        let owner = package.coordinate.namespace.clone().unwrap_or_default();
        let repo = package.coordinate.name.clone();
        let ref_ = package.coordinate.version.clone().unwrap_or_default();
        let fallback_ref: Option<String> = decision
            .fallback_coordinate
            .as_ref()
            .and_then(|c| c.version.clone());

        findings.push(CliScanFindingResponse {
            coordinate: package.coordinate,
            artifact_sha256: None,
            decision: decision.decision,
            decision_timestamp: Some(decision_timestamp),
            trace_id: decision.trace_id,
            rationale: decision.rationale,
            fallback_coordinate: decision.fallback_coordinate,
            create_analysis_job: decision.create_analysis_job,
        });

        // Persist the scan result for the Command Center dashboard.
        // Failures are logged as warnings so the enrichment response is unaffected.
        if let Err(err) = sqlx::query(
            r#"
            INSERT INTO github_actions_scan_results
                (tenant_id, policy_profile_id, owner, repo, "ref", decision, rationale, trace_id, fallback_ref)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(context.tenant_id)
        .bind(context.policy_profile_id)
        .bind(&owner)
        .bind(&repo)
        .bind(&ref_)
        .bind(&decision_str)
        .bind(&persist_rationale)
        .bind(&persist_trace_id)
        .bind(fallback_ref.as_deref())
        .execute(&state.pool)
        .await
        {
            tracing::warn!(
                tenant_id = %context.tenant_id,
                trace_id = %persist_trace_id,
                error = %err,
                "failed to persist github actions scan result; enrichment response unaffected"
            );
        }
    }

    Ok(Json(CliGithubActionsEnrichmentResponse {
        tenant_id: context.tenant_id,
        policy_profile_id: context.policy_profile_id,
        findings,
    }))
}

async fn explain_cli_package(
    State(state): State<AppState>,
    Json(request): Json<CliExplainRequest>,
) -> Result<Json<CliExplainResponse>, ApiError> {
    let coordinate = request.coordinate;
    let row = if let Some(tenant_id) = request.tenant_id {
        sqlx::query(
            r#"
            SELECT summaries.analysis_job_id,
                   summaries.artifact_id,
                   jobs.trace_id,
                   artifacts.tenant_id,
                   artifacts.ecosystem::text AS ecosystem,
                   artifacts.namespace,
                   artifacts.package_name,
                   artifacts.package_version,
                   artifacts.sha256,
                   summaries.recommended_action::text AS recommended_action,
                   summaries.confidence,
                   summaries.summary,
                   summaries.created_at
            FROM analysis_summaries summaries
            JOIN analysis_jobs jobs ON jobs.id = summaries.analysis_job_id
            JOIN artifacts ON artifacts.id = summaries.artifact_id
            WHERE artifacts.tenant_id = $1
              AND artifacts.ecosystem::text = $2
              AND artifacts.package_name = $3
              AND artifacts.namespace IS NOT DISTINCT FROM $4
              AND artifacts.package_version IS NOT DISTINCT FROM $5
            ORDER BY summaries.created_at DESC, summaries.analysis_job_id DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(coordinate.ecosystem.to_string())
        .bind(&coordinate.name)
        .bind(coordinate.namespace.as_deref())
        .bind(coordinate.version.as_deref())
        .fetch_optional(&state.pool)
        .await?
    } else {
        sqlx::query(
            r#"
            SELECT summaries.analysis_job_id,
                   summaries.artifact_id,
                   jobs.trace_id,
                   artifacts.tenant_id,
                   artifacts.ecosystem::text AS ecosystem,
                   artifacts.namespace,
                   artifacts.package_name,
                   artifacts.package_version,
                   artifacts.sha256,
                   summaries.recommended_action::text AS recommended_action,
                   summaries.confidence,
                   summaries.summary,
                   summaries.created_at
            FROM analysis_summaries summaries
            JOIN analysis_jobs jobs ON jobs.id = summaries.analysis_job_id
            JOIN artifacts ON artifacts.id = summaries.artifact_id
            WHERE artifacts.ecosystem::text = $1
              AND artifacts.package_name = $2
              AND artifacts.namespace IS NOT DISTINCT FROM $3
              AND artifacts.package_version IS NOT DISTINCT FROM $4
            ORDER BY summaries.created_at DESC, summaries.analysis_job_id DESC
            LIMIT 1
            "#,
        )
        .bind(coordinate.ecosystem.to_string())
        .bind(&coordinate.name)
        .bind(coordinate.namespace.as_deref())
        .bind(coordinate.version.as_deref())
        .fetch_optional(&state.pool)
        .await?
    }
    .ok_or(ApiError::NotFound)?;

    let analysis_job_id: Uuid = row.try_get("analysis_job_id")?;
    let ai_explanation = sqlx::query(
        r#"
        SELECT explanation
        FROM ai_explanations
        WHERE analysis_job_id = $1
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(analysis_job_id)
    .fetch_optional(&state.pool)
    .await?
    .map(|row| {
        row.try_get::<SqlJson<Value>, _>("explanation")
            .map(|value| value.0)
    })
    .transpose()?;

    Ok(Json(CliExplainResponse {
        tenant_id: row.try_get("tenant_id")?,
        analysis_job_id,
        artifact_id: row.try_get("artifact_id")?,
        trace_id: row.try_get("trace_id")?,
        coordinate: PackageCoordinate::new(
            coordinate.ecosystem,
            row.try_get::<String, _>("package_name")?,
            row.try_get::<Option<String>, _>("package_version")?,
            row.try_get::<Option<String>, _>("namespace")?,
        ),
        artifact_sha256: row.try_get("sha256")?,
        recommended_action: row.try_get("recommended_action")?,
        confidence: row.try_get("confidence")?,
        summary: row.try_get::<SqlJson<Value>, _>("summary")?.0,
        ai_explanation,
        created_at: row.try_get("created_at")?,
    }))
}

async fn list_quarantine_queue(
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
) -> Result<Json<Vec<QuarantineQueueItemResponse>>, ApiError> {
    let rows = sqlx::query(
                r#"
                SELECT summaries.analysis_job_id,
                             summaries.artifact_id,
                             jobs.trace_id,
                             jobs.ecosystem::text AS ecosystem,
                             jobs.namespace,
                             jobs.package_name,
                             jobs.package_version,
                             jobs.artifact_sha256,
                             summaries.recommended_action::text AS recommended_action,
                             summaries.confidence,
                             summaries.requires_hitl,
                             summaries.summary,
                             summaries.created_at,
                             (
                                 SELECT COUNT(*)::bigint
                                 FROM static_analysis_reports reports
                                 WHERE reports.analysis_job_id = summaries.analysis_job_id
                                     AND reports.artifact_id = summaries.artifact_id
                             ) AS static_report_count,
                             (
                                 SELECT COUNT(*)::bigint
                                 FROM sandbox_runs runs
                                 WHERE runs.analysis_job_id = summaries.analysis_job_id
                                     AND runs.artifact_id = summaries.artifact_id
                             ) AS sandbox_run_count,
                             (
                                 SELECT COUNT(*)::bigint
                                 FROM ai_explanations explanations
                                 WHERE explanations.analysis_job_id = summaries.analysis_job_id
                             ) AS ai_explanation_count,
                             (
                                 SELECT COUNT(*)::bigint
                                 FROM audit_events events
                                 WHERE events.tenant_id = jobs.tenant_id
                                     AND (
                                         events.resource = ('analysis-job/' || summaries.analysis_job_id::text)
                                         OR events.trace_id = jobs.trace_id
                                     )
                             ) AS audit_event_count
                FROM analysis_summaries summaries
                JOIN analysis_jobs jobs ON jobs.id = summaries.analysis_job_id
                WHERE jobs.tenant_id = $1
                    AND (
                        summaries.requires_hitl = true
                        OR summaries.recommended_action <> 'ALLOW'::policy_decision
                    )
                ORDER BY summaries.created_at DESC, summaries.analysis_job_id DESC
                "#,
        )
        .bind(tenant_id)
        .fetch_all(&state.pool)
        .await?;

    let items = rows
        .iter()
        .map(quarantine_queue_item_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(items))
}

#[derive(Debug, Clone, Deserialize)]
struct SbomListQuery {
    limit: Option<u32>,
}

async fn list_tenant_sboms(
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<SbomListQuery>,
) -> Result<Json<Vec<SbomDocumentSummaryResponse>>, ApiError> {
    let actor_id = actor_id_from_headers(&headers).ok_or(ApiError::MissingActor)?;
    ensure_tenant_user(&state.pool, tenant_id, actor_id).await?;
    let limit = validate_sbom_list_limit(query.limit)?;

    let documents = state
        .sbom_client
        .list_tenant_sboms(tenant_id, limit)
        .await?;

    Ok(Json(
        documents
            .into_iter()
            .map(sbom_document_summary_response)
            .collect(),
    ))
}

async fn download_tenant_sbom(
    State(state): State<AppState>,
    Path((tenant_id, sbom_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let actor_id = actor_id_from_headers(&headers).ok_or(ApiError::MissingActor)?;
    ensure_tenant_user(&state.pool, tenant_id, actor_id).await?;

    let document = state
        .sbom_client
        .download_tenant_sbom(tenant_id, sbom_id)
        .await?;
    let mut response = document.body.into_response();
    for (header_name, header_value) in &document.headers {
        response
            .headers_mut()
            .insert(header_name, header_value.clone());
    }

    if !response.headers().contains_key(header::CONTENT_TYPE) {
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
    }

    Ok(response)
}

fn sbom_document_summary_response(
    document: SbomServiceDocumentSummary,
) -> SbomDocumentSummaryResponse {
    SbomDocumentSummaryResponse {
        id: document.id,
        analysis_job_id: document.analysis_job_id,
        tenant_id: document.tenant_id,
        format: document.format,
        source: document.source,
        component_count: document.component_count,
        storage_size_bytes: document.storage_size_bytes,
        created_at: document.created_at,
        ntia_validation: SbomNtiaValidationResponse {
            valid: document.ntia_validation.valid,
            issues: document.ntia_validation.issues,
        },
    }
}

fn forwarded_download_headers(source: &HeaderMap) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for header_name in [
        header::CONTENT_TYPE,
        header::CONTENT_DISPOSITION,
        header::CONTENT_LENGTH,
        header::CACHE_CONTROL,
        header::ETAG,
        header::CONTENT_ENCODING,
    ] {
        if let Some(value) = source.get(&header_name) {
            headers.insert(header_name, value.clone());
        }
    }
    headers
}

fn validate_sbom_list_limit(limit: Option<u32>) -> Result<Option<u32>, ApiError> {
    match limit {
        Some(limit) if (1..=MAX_SBOM_LIST_LIMIT).contains(&limit) => Ok(Some(limit)),
        Some(_) => Err(ApiError::InvalidRequest(format!(
            "sbom list limit must be between 1 and {MAX_SBOM_LIST_LIMIT}"
        ))),
        None => Ok(None),
    }
}

async fn list_request_timeline(
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
) -> Result<Json<Vec<RequestTimelineBucketResponse>>, ApiError> {
    let rows = sqlx::query(
                r#"
                WITH tenant_summaries AS (
                    SELECT summaries.created_at, summaries.recommended_action
                    FROM analysis_summaries summaries
                    JOIN analysis_jobs jobs ON jobs.id = summaries.analysis_job_id
                    WHERE jobs.tenant_id = $1
                ),
                anchor AS (
                    SELECT date_trunc('hour', MAX(created_at)) AS bucket_end
                    FROM tenant_summaries
                ),
                buckets AS (
                    SELECT generate_series(
                        anchor.bucket_end - interval '7 hours',
                        anchor.bucket_end,
                        interval '1 hour'
                    ) AS bucket_start
                    FROM anchor
                    WHERE anchor.bucket_end IS NOT NULL
                )
                SELECT buckets.bucket_start,
                             COUNT(*) FILTER (
                                 WHERE summaries.recommended_action = 'ALLOW'::policy_decision
                             )::bigint AS allow_count,
                             COUNT(*) FILTER (
                                 WHERE summaries.recommended_action IN (
                                     'ALLOW_WITH_WARNING'::policy_decision,
                                     'REQUIRE_HITL_APPROVAL'::policy_decision,
                                     'FALLBACK_TO_APPROVED_CANDIDATE'::policy_decision
                                 )
                             )::bigint AS warn_count,
                             COUNT(*) FILTER (
                                 WHERE summaries.recommended_action = 'QUARANTINE_PENDING_ANALYSIS'::policy_decision
                             )::bigint AS quarantine_count,
                             COUNT(*) FILTER (
                                 WHERE summaries.recommended_action IN (
                                     'BLOCK_KNOWN_MALICIOUS'::policy_decision,
                                     'BLOCK_POLICY_VIOLATION'::policy_decision
                                 )
                             )::bigint AS block_count
                FROM buckets
                LEFT JOIN tenant_summaries summaries
                    ON summaries.created_at >= buckets.bucket_start
                    AND summaries.created_at < buckets.bucket_start + interval '1 hour'
                GROUP BY buckets.bucket_start
                ORDER BY buckets.bucket_start ASC
                "#,
        )
        .bind(tenant_id)
        .fetch_all(&state.pool)
        .await?;

    let items = rows
        .iter()
        .map(request_timeline_bucket_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(items))
}

async fn get_dashboard_metrics(
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
) -> Result<Json<DashboardMetricsResponse>, ApiError> {
    let blocked_packages: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::bigint
        FROM analysis_summaries summaries
        JOIN analysis_jobs jobs ON jobs.id = summaries.analysis_job_id
        WHERE jobs.tenant_id = $1
          AND summaries.recommended_action IN (
              'BLOCK_KNOWN_MALICIOUS'::policy_decision,
              'BLOCK_POLICY_VIOLATION'::policy_decision
          )
        "#,
    )
    .bind(tenant_id)
    .fetch_one(&state.pool)
    .await?;

    let quarantine_queue_depth: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::bigint
        FROM analysis_summaries summaries
        JOIN analysis_jobs jobs ON jobs.id = summaries.analysis_job_id
        WHERE jobs.tenant_id = $1
          AND (
              summaries.requires_hitl = true
              OR summaries.recommended_action <> 'ALLOW'::policy_decision
          )
        "#,
    )
    .bind(tenant_id)
    .fetch_one(&state.pool)
    .await?;

    let active_overrides: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::bigint
        FROM overrides
        WHERE tenant_id = $1
          AND status IN ('pending', 'approved')
          AND expires_at > now()
        "#,
    )
    .bind(tenant_id)
    .fetch_one(&state.pool)
    .await?;

    let feed_snapshot_row = sqlx::query(
        r#"
        WITH latest_per_feed AS (
            SELECT feed_name, MAX(last_success_at) AS latest_success_at
            FROM feed_snapshots
            WHERE tenant_id = $1
              AND last_success_at IS NOT NULL
            GROUP BY feed_name
        )
        SELECT EXTRACT(EPOCH FROM (now() - MIN(latest_success_at)))::bigint AS snapshot_age_seconds
        FROM latest_per_feed
        "#,
    )
    .bind(tenant_id)
    .fetch_one(&state.pool)
    .await?;

    let feed_snapshot_age_seconds: Option<i64> =
        feed_snapshot_row.try_get("snapshot_age_seconds")?;
    let feed_freshness = match feed_snapshot_age_seconds {
        Some(age_seconds) if age_seconds <= 86_400 => DashboardFeedFreshness::Fresh,
        Some(_) => DashboardFeedFreshness::Stale,
        None => DashboardFeedFreshness::Missing,
    };

    Ok(Json(DashboardMetricsResponse {
        blocked_packages,
        quarantine_queue_depth,
        active_overrides,
        feed_freshness,
        feed_snapshot_age_seconds,
    }))
}

async fn list_policy_profiles(
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
) -> Result<Json<Vec<PolicyProfileSummaryResponse>>, ApiError> {
    let rows = sqlx::query(
        r#"
        SELECT profiles.id,
               profiles.tenant_id,
               profiles.name,
               profiles.mode::text AS mode,
               profiles.created_at,
               latest.id AS latest_version_id,
               latest.version AS latest_version,
               latest.effective_at AS latest_effective_at,
               COALESCE(profile_usage.request_count_last_30_days, 0)::bigint AS request_count_last_30_days
        FROM policy_profiles profiles
        JOIN LATERAL (
            SELECT versions.id, versions.version, versions.effective_at
            FROM policy_versions versions
            WHERE versions.tenant_id = profiles.tenant_id
              AND versions.policy_profile_id = profiles.id
            ORDER BY versions.effective_at DESC, versions.version DESC, versions.id DESC
            LIMIT 1
        ) latest ON TRUE
        LEFT JOIN (
            SELECT versions.policy_profile_id,
                   COUNT(*)::bigint AS request_count_last_30_days
            FROM policy_decisions decisions
            JOIN policy_versions versions ON versions.id = decisions.policy_version_id
            WHERE decisions.tenant_id = $1
              AND decisions.decided_at >= now() - INTERVAL '30 days'
            GROUP BY versions.policy_profile_id
        ) profile_usage ON profile_usage.policy_profile_id = profiles.id
        WHERE profiles.tenant_id = $1
        ORDER BY profiles.created_at ASC, profiles.name ASC
        "#,
    )
    .bind(tenant_id)
    .fetch_all(&state.pool)
    .await?;

    rows.iter()
        .map(policy_profile_summary_from_row)
        .collect::<Result<Vec<_>, _>>()
        .map(Json)
}

async fn get_policy_scorecard_thresholds(
    State(state): State<AppState>,
    Path((tenant_id, policy_profile_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<PolicyScorecardThresholdsResponse>, ApiError> {
    let row = sqlx::query(
        r#"
        SELECT versions.id AS version_id,
               versions.document
        FROM policy_versions versions
        JOIN policy_profiles profiles ON profiles.id = versions.policy_profile_id
        WHERE profiles.tenant_id = $1
          AND profiles.id = $2
        ORDER BY versions.effective_at DESC, versions.version DESC, versions.id DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(policy_profile_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;

    let version_id: Uuid = row.try_get("version_id")?;
    let document: Value = row.try_get::<SqlJson<Value>, _>("document").map(|v| v.0)?;

    let thresholds = document
        .get("scorecard_thresholds")
        .cloned()
        .unwrap_or_default();

    fn check_min_score(thresholds: &Value, key: &str) -> f64 {
        thresholds.get(key).and_then(Value::as_f64).unwrap_or(10.0)
    }

    let rules = document
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    fn rule_action(rules: &[Value], signal: &str) -> (SignalPolicyAction, bool) {
        for rule in rules {
            if rule.get("signal").and_then(Value::as_str) == Some(signal) {
                let enabled = rule.get("enabled").and_then(Value::as_bool).unwrap_or(true);
                let action = match rule.get("action").and_then(Value::as_str) {
                    Some("allow") => SignalPolicyAction::Allow,
                    Some("block") => SignalPolicyAction::Block,
                    Some("hitl") => SignalPolicyAction::Hitl,
                    _ => SignalPolicyAction::Warn,
                };
                return (action, enabled);
            }
        }
        (SignalPolicyAction::Warn, true)
    }

    let (cr_action, cr_enabled) = rule_action(&rules, "scorecard_code_review_risk");
    let (bp_action, bp_enabled) = rule_action(&rules, "scorecard_branch_protection_risk");
    let (cicd_action, cicd_enabled) = rule_action(&rules, "scorecard_ci_cd_risk");
    let (mt_action, mt_enabled) = rule_action(&rules, "scorecard_maintained_risk");
    let (sr_action, sr_enabled) = rule_action(&rules, "scorecard_signed_releases_risk");

    Ok(Json(PolicyScorecardThresholdsResponse {
        policy_profile_id,
        policy_version_id: version_id,
        code_review: ScorecardCheckThresholdResponse {
            min_score: check_min_score(&thresholds, "code_review"),
            action: cr_action,
            enabled: cr_enabled,
        },
        branch_protection: ScorecardCheckThresholdResponse {
            min_score: check_min_score(&thresholds, "branch_protection"),
            action: bp_action,
            enabled: bp_enabled,
        },
        ci_cd: ScorecardCheckThresholdResponse {
            min_score: check_min_score(&thresholds, "ci_cd"),
            action: cicd_action,
            enabled: cicd_enabled,
        },
        maintained: ScorecardCheckThresholdResponse {
            min_score: check_min_score(&thresholds, "maintained"),
            action: mt_action,
            enabled: mt_enabled,
        },
        signed_releases: ScorecardCheckThresholdResponse {
            min_score: check_min_score(&thresholds, "signed_releases"),
            action: sr_action,
            enabled: sr_enabled,
        },
    }))
}

/// Query parameters for the deps.dev packages list endpoint.
#[derive(Debug, serde::Deserialize)]
struct DepsDdevPackagesQuery {
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    ecosystem: Option<String>,
}

/// Query parameters for the cross-ecosystem IOC records list endpoint.
#[derive(Debug, serde::Deserialize)]
struct IocRecordsQuery {
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    indicator_type: Option<String>,
}

const VALID_INDICATOR_TYPES: &[&str] = &[
    "maintainer-identity",
    "domain",
    "ip",
    "url",
    "package-name",
    "behavioral-fingerprint",
];

async fn list_deps_dev_packages(
    State(state): State<AppState>,
    Path(_tenant_id): Path<Uuid>,
    Query(params): Query<DepsDdevPackagesQuery>,
) -> Result<Json<DepsDdevPackagesResponse>, ApiError> {
    let limit = params.limit.unwrap_or(25).max(1).min(100);

    let rows = sqlx::query(
        r#"
        SELECT ddp.purl,
               ddp.ecosystem,
               ddp.namespace,
               ddp.package_name,
               ddp.package_version,
               ddp.licenses,
               ddp.dependency_count::bigint AS dependency_count,
               ddp.project_links,
               fs.created_at AS snapshot_taken_at
        FROM deps_dev_packages ddp
        JOIN feed_snapshots fs ON fs.id = ddp.snapshot_id
        WHERE fs.feed_name = 'deps.dev'
          AND fs.id = (
              SELECT id FROM feed_snapshots
              WHERE feed_name = 'deps.dev'
              ORDER BY created_at DESC
              LIMIT 1
          )
          AND ($1::text IS NULL OR ddp.ecosystem = $1)
        ORDER BY ddp.package_name ASC, ddp.package_version DESC
        LIMIT $2
        "#,
    )
    .bind(params.ecosystem.as_deref())
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    let snapshot_taken_at = rows
        .first()
        .and_then(|row| row.try_get::<DateTime<Utc>, _>("snapshot_taken_at").ok());

    let packages = rows
        .iter()
        .map(|row| {
            let purl: String = row.try_get("purl")?;
            let ecosystem: String = row.try_get("ecosystem")?;
            let namespace: Option<String> = row.try_get("namespace")?;
            let package_name: String = row.try_get("package_name")?;
            let package_version: Option<String> = row.try_get("package_version")?;
            let dependency_count: i64 = row.try_get("dependency_count")?;
            let licenses_json: Option<SqlJson<Value>> = row.try_get("licenses")?;
            let project_links_json: Option<SqlJson<Value>> = row.try_get("project_links")?;

            let licenses: Vec<String> = licenses_json
                .and_then(|j| {
                    j.0.as_array().map(|arr| {
                        arr.iter()
                            .filter_map(|v| {
                                v.as_str().map(ToString::to_string).or_else(|| {
                                    v.get("id").and_then(Value::as_str).map(ToString::to_string)
                                })
                            })
                            .collect()
                    })
                })
                .unwrap_or_default();

            let source_repo_url: Option<String> = project_links_json.and_then(|j| {
                j.0.as_array().and_then(|arr| {
                    arr.iter().find_map(|link| {
                        let label = link.get("label").and_then(Value::as_str)?;
                        if label.eq_ignore_ascii_case("SOURCE_REPO") {
                            link.get("url")
                                .and_then(Value::as_str)
                                .map(ToString::to_string)
                        } else {
                            None
                        }
                    })
                })
            });

            Ok::<_, sqlx::Error>(DepsDdevPackageSummaryResponse {
                purl,
                ecosystem,
                namespace,
                package_name,
                package_version,
                licenses,
                dependency_count,
                source_repo_url,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let total = packages.len() as i64;
    Ok(Json(DepsDdevPackagesResponse {
        packages,
        snapshot_taken_at,
        total,
    }))
}

#[derive(Debug, serde::Serialize)]
struct IocRecordSummary {
    id: Uuid,
    ecosystem: String,
    namespace: Option<String>,
    package_name: String,
    package_version: Option<String>,
    indicator_type: String,
    indicator_value: String,
}

#[derive(Debug, serde::Serialize)]
struct IocRecordsResponse {
    records: Vec<IocRecordSummary>,
    snapshot_taken_at: Option<DateTime<Utc>>,
    total: i64,
}

async fn list_ioc_records(
    State(state): State<AppState>,
    Path(_tenant_id): Path<Uuid>,
    Query(params): Query<IocRecordsQuery>,
) -> Result<Json<IocRecordsResponse>, ApiError> {
    let limit = params.limit.unwrap_or(25).max(1).min(100);

    if let Some(ref it) = params.indicator_type {
        if !VALID_INDICATOR_TYPES.contains(&it.as_str()) {
            return Err(ApiError::InvalidRequest("invalid indicator_type".into()));
        }
    }

    let rows = sqlx::query(
        r#"
        SELECT ioc.id,
               ioc.ecosystem,
               ioc.namespace,
               ioc.package_name,
               ioc.package_version,
               ioc.indicator_type,
               ioc.indicator_value,
               fs.created_at AS snapshot_taken_at
        FROM cross_ecosystem_ioc_records ioc
        JOIN feed_snapshots fs ON fs.id = ioc.snapshot_id
        WHERE fs.id IN (
              SELECT DISTINCT ON (feed_name) id FROM feed_snapshots
              WHERE feed_name IN ('openssf-malicious-packages', 'openssf-package-analysis')
              ORDER BY feed_name, created_at DESC
          )
          AND ($1::text IS NULL OR ioc.indicator_type = $1)
        ORDER BY ioc.indicator_type ASC, ioc.package_name ASC
        LIMIT $2
        "#,
    )
    .bind(params.indicator_type.as_deref())
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    let snapshot_taken_at = rows
        .iter()
        .filter_map(|row| row.try_get::<DateTime<Utc>, _>("snapshot_taken_at").ok())
        .max();

    let records = rows
        .iter()
        .map(|row| {
            let id: Uuid = row.try_get("id")?;
            let ecosystem: String = row.try_get("ecosystem")?;
            let namespace: Option<String> = row.try_get("namespace")?;
            let package_name: String = row.try_get("package_name")?;
            let package_version: Option<String> = row.try_get("package_version")?;
            let indicator_type: String = row.try_get("indicator_type")?;
            let indicator_value: String = row.try_get("indicator_value")?;
            Ok::<_, sqlx::Error>(IocRecordSummary {
                id,
                ecosystem,
                namespace,
                package_name,
                package_version,
                indicator_type,
                indicator_value,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let total = records.len() as i64;
    Ok(Json(IocRecordsResponse {
        records,
        snapshot_taken_at,
        total,
    }))
}

#[derive(Debug, serde::Serialize)]
struct GithubActionsScanResultResponse {
    id: Uuid,
    tenant_id: Uuid,
    policy_profile_id: Uuid,
    owner: String,
    repo: String,
    #[serde(rename = "ref")]
    ref_: String,
    decision: String,
    rationale: Vec<String>,
    trace_id: String,
    fallback_ref: Option<String>,
    scanned_at: DateTime<Utc>,
}

#[derive(Debug, serde::Deserialize)]
struct GithubActionsScanResultsQuery {
    #[serde(default)]
    limit: Option<i64>,
}

async fn list_github_actions_scan_results(
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
    headers: HeaderMap,
    Query(params): Query<GithubActionsScanResultsQuery>,
) -> Result<Json<Vec<GithubActionsScanResultResponse>>, ApiError> {
    let actor_id = actor_id_from_headers(&headers).ok_or(ApiError::MissingActor)?;
    ensure_tenant_user(&state.pool, tenant_id, actor_id).await?;
    let limit = params.limit.unwrap_or(50).max(1).min(100);

    let rows = sqlx::query(
        r#"
        SELECT id, tenant_id, policy_profile_id, owner, repo,
               "ref" AS action_ref, decision, rationale, trace_id, fallback_ref, scanned_at
        FROM github_actions_scan_results
        WHERE tenant_id = $1
        ORDER BY scanned_at DESC
        LIMIT $2
        "#,
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    let results = rows
        .iter()
        .map(|row| {
            let id: Uuid = row.try_get("id")?;
            let tenant_id: Uuid = row.try_get("tenant_id")?;
            let policy_profile_id: Uuid = row.try_get("policy_profile_id")?;
            let owner: String = row.try_get("owner")?;
            let repo: String = row.try_get("repo")?;
            let ref_: String = row.try_get("action_ref")?;
            let decision: String = row.try_get("decision")?;
            let rationale: Vec<String> = row.try_get("rationale")?;
            let trace_id: String = row.try_get("trace_id")?;
            let fallback_ref: Option<String> = row.try_get("fallback_ref")?;
            let scanned_at: DateTime<Utc> = row.try_get("scanned_at")?;
            Ok::<_, sqlx::Error>(GithubActionsScanResultResponse {
                id,
                tenant_id,
                policy_profile_id,
                owner,
                repo,
                ref_,
                decision,
                rationale,
                trace_id,
                fallback_ref,
                scanned_at,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(results))
}

async fn simulate_policy_replay(
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
    Json(request): Json<PolicySimulationRequest>,
) -> Result<Json<PolicySimulationResponse>, ApiError> {
    validate_policy_simulation_request(&request)?;

    let target_profile_row = sqlx::query(
        r#"
        SELECT profiles.id,
               profiles.tenant_id,
               profiles.name,
               profiles.mode::text AS mode,
               profiles.created_at,
               latest.id AS latest_version_id,
               latest.version AS latest_version,
               latest.effective_at AS latest_effective_at,
               0::bigint AS request_count_last_30_days
        FROM policy_profiles profiles
        JOIN LATERAL (
            SELECT versions.id, versions.version, versions.effective_at
            FROM policy_versions versions
            WHERE versions.tenant_id = profiles.tenant_id
              AND versions.policy_profile_id = profiles.id
            ORDER BY versions.effective_at DESC, versions.version DESC, versions.id DESC
            LIMIT 1
        ) latest ON TRUE
        WHERE profiles.tenant_id = $1
          AND profiles.id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(request.policy_profile_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let target_profile = policy_profile_summary_from_row(&target_profile_row)?;

    let ecosystem_filter = request.ecosystem.as_ref().map(ToString::to_string);
    let rows = sqlx::query(
        r#"
        SELECT pr.id AS package_request_id,
               pr.registry_config_id,
               pr.client_type,
               pr.ecosystem::text AS ecosystem,
               pr.namespace,
               pr.package_name,
               pr.package_version,
               pr.trace_id,
               pr.requested_at,
               baseline_profiles.id AS baseline_policy_profile_id,
               baseline_profiles.name AS baseline_policy_profile_name,
               decisions.decision::text AS baseline_decision,
               COALESCE(decisions.rationale->'rationale', '[]'::jsonb) AS baseline_rationale,
               decisions.rationale->'requested_digest'->>'hex' AS requested_digest
        FROM policy_decisions decisions
        JOIN package_requests pr ON pr.id = decisions.package_request_id
        JOIN policy_versions baseline_versions ON baseline_versions.id = decisions.policy_version_id
        JOIN policy_profiles baseline_profiles ON baseline_profiles.id = baseline_versions.policy_profile_id
        WHERE decisions.tenant_id = $1
          AND pr.tenant_id = $1
          AND pr.requested_at >= now() - make_interval(days => $2)
          AND ($3::package_ecosystem IS NULL OR pr.ecosystem = $3::package_ecosystem)
        ORDER BY pr.requested_at DESC, pr.id DESC
        "#,
    )
    .bind(tenant_id)
    .bind(request.lookback_days)
    .bind(ecosystem_filter.as_deref())
    .fetch_all(&state.pool)
    .await?;

    let replayed_request_count = rows.len() as i64;
    let mut baseline_counts = PolicyDecisionCountsResponse::default();
    let mut simulated_counts = PolicyDecisionCountsResponse::default();
    let mut items = Vec::with_capacity(rows.len());

    for (index, row) in rows.iter().enumerate() {
        let package_request_id: Uuid = row.try_get("package_request_id")?;
        let registry_config_id: Uuid = row.try_get("registry_config_id")?;
        let client_type: String = row.try_get("client_type")?;
        let ecosystem = package_ecosystem_from_db(row.try_get("ecosystem")?)?;
        let namespace: Option<String> = row.try_get("namespace")?;
        let package_name: String = row.try_get("package_name")?;
        let package_version: Option<String> = row.try_get("package_version")?;
        let trace_id_value: String = row.try_get("trace_id")?;
        let requested_at: DateTime<Utc> = row.try_get("requested_at")?;
        let baseline_policy_profile_id: Uuid = row.try_get("baseline_policy_profile_id")?;
        let baseline_policy_profile_name: String = row.try_get("baseline_policy_profile_name")?;
        let baseline_decision = policy_decision_from_db(row.try_get("baseline_decision")?)?;
        let baseline_rationale =
            string_list_from_json_value(row.try_get::<SqlJson<Value>, _>("baseline_rationale")?.0);
        let requested_digest = row
            .try_get::<Option<String>, _>("requested_digest")?
            .map(|hex| {
                ArtifactDigest::sha256(hex).map_err(|_| {
                    ApiError::InvalidRequest(
                        "stored requested digest is invalid for policy simulation replay"
                            .to_owned(),
                    )
                })
            })
            .transpose()?;

        baseline_counts.record(&baseline_decision);

        let coordinate = PackageCoordinate::new(
            ecosystem.clone(),
            package_name.clone(),
            package_version.clone(),
            namespace.clone(),
        );
        let simulated = state
            .decision_client
            .simulate(DecisionRequest {
                tenant_id,
                registry_config_id,
                policy_profile_id: target_profile.id,
                request: NormalizedPackageRequest {
                    kind: package_request_kind_from_db(client_type)?,
                    tenant_id,
                    registry_config_id,
                    policy_profile_id: target_profile.id,
                    coordinate,
                    trace_id: format!("policy-sim-{}-{}", target_profile.id, index + 1),
                    requested_digest,
                    source_url: None,
                    explicit_version_or_integrity: package_version.is_some(),
                },
            })
            .await?;

        simulated_counts.record(&simulated.decision);
        let changed = simulated.decision != baseline_decision;
        items.push(PolicySimulationDiffItemResponse {
            package_request_id,
            trace_id: trace_id_value,
            requested_at,
            coordinate: PackageCoordinateSummaryResponse {
                ecosystem: ecosystem.to_string(),
                name: package_name,
                version: package_version,
                namespace,
            },
            baseline_policy_profile_id,
            baseline_policy_profile_name,
            baseline_decision,
            baseline_rationale,
            simulated_decision: simulated.decision,
            simulated_rationale: simulated.rationale,
            changed,
        });
    }

    let changed_request_count = items.iter().filter(|item| item.changed).count() as i64;
    items.sort_by(|left, right| {
        right
            .changed
            .cmp(&left.changed)
            .then_with(|| right.requested_at.cmp(&left.requested_at))
    });
    items.truncate(request.limit as usize);

    Ok(Json(PolicySimulationResponse {
        tenant_id,
        target_policy_profile_id: target_profile.id,
        target_policy_profile_name: target_profile.name,
        target_policy_mode: target_profile.mode,
        target_latest_version_id: target_profile.latest_version_id,
        target_latest_version: target_profile.latest_version,
        lookback_days: request.lookback_days,
        ecosystem: request.ecosystem.map(|ecosystem| ecosystem.to_string()),
        replayed_request_count,
        changed_request_count,
        baseline_counts,
        simulated_counts,
        items,
        generated_at: Utc::now(),
    }))
}

async fn get_artifact_evidence(
    State(state): State<AppState>,
    Path((tenant_id, artifact_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ArtifactEvidenceResponse>, ApiError> {
    let summary_row = sqlx::query(
        r#"
                SELECT summaries.analysis_job_id,
                             summaries.artifact_id,
                             jobs.trace_id,
                             jobs.ecosystem::text AS ecosystem,
                             jobs.namespace,
                             jobs.package_name,
                             jobs.package_version,
                             jobs.artifact_sha256,
                             summaries.recommended_action::text AS recommended_action,
                             summaries.confidence,
                             summaries.requires_hitl,
                             summaries.summary,
                             summaries.created_at
                FROM analysis_summaries summaries
                JOIN analysis_jobs jobs ON jobs.id = summaries.analysis_job_id
                WHERE jobs.tenant_id = $1
                    AND summaries.artifact_id = $2
                ORDER BY summaries.created_at DESC
                LIMIT 1
                "#,
    )
    .bind(tenant_id)
    .bind(artifact_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;

    let analysis_job_id: Uuid = summary_row.try_get("analysis_job_id")?;
    let trace_id: String = summary_row.try_get("trace_id")?;
    let resource = format!("analysis-job/{analysis_job_id}");

    let static_reports = sqlx::query(
        r#"
                SELECT report
                FROM static_analysis_reports
                WHERE analysis_job_id = $1
                    AND artifact_id = $2
                ORDER BY created_at ASC
                "#,
    )
    .bind(analysis_job_id)
    .bind(artifact_id)
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(|row| {
        row.try_get::<SqlJson<Value>, _>("report")
            .map(|value| value.0)
    })
    .collect::<Result<Vec<_>, _>>()?;

    let sandbox_runs = sqlx::query(
        r#"
                SELECT telemetry
                FROM sandbox_runs
                WHERE analysis_job_id = $1
                    AND artifact_id = $2
                ORDER BY started_at ASC NULLS LAST, completed_at ASC NULLS LAST
                "#,
    )
    .bind(analysis_job_id)
    .bind(artifact_id)
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(|row| {
        row.try_get::<SqlJson<Value>, _>("telemetry")
            .map(|value| value.0)
    })
    .collect::<Result<Vec<_>, _>>()?;

    let ai_explanation = sqlx::query(
        r#"
                SELECT explanation
                FROM ai_explanations
                WHERE analysis_job_id = $1
                ORDER BY created_at DESC
                LIMIT 1
                "#,
    )
    .bind(analysis_job_id)
    .fetch_optional(&state.pool)
    .await?
    .map(|row| {
        row.try_get::<SqlJson<Value>, _>("explanation")
            .map(|value| value.0)
    })
    .transpose()?;

    let audit_events = sqlx::query(
        r#"
                SELECT id, tenant_id, actor, action, resource, trace_id, metadata, occurred_at
                FROM audit_events
                WHERE tenant_id = $1
                    AND (resource = $2 OR trace_id = $3)
                ORDER BY occurred_at ASC, id ASC
                "#,
    )
    .bind(tenant_id)
    .bind(&resource)
    .bind(&trace_id)
    .fetch_all(&state.pool)
    .await?
    .iter()
    .map(audit_event_from_row)
    .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(ArtifactEvidenceResponse {
        analysis_job_id,
        artifact_id,
        trace_id,
        coordinate: coordinate_summary_from_row(&summary_row)?,
        artifact_sha256: summary_row.try_get("artifact_sha256")?,
        recommended_action: summary_row.try_get("recommended_action")?,
        confidence: summary_row.try_get("confidence")?,
        requires_hitl: summary_row.try_get("requires_hitl")?,
        summary: summary_row.try_get::<SqlJson<Value>, _>("summary")?.0,
        static_reports,
        sandbox_runs,
        ai_explanation,
        audit_events,
    }))
}

async fn list_artifact_static_analysis_reports(
    State(state): State<AppState>,
    Path((tenant_id, artifact_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ArtifactStaticAnalysisReportsResponse>, ApiError> {
    let summary_row = sqlx::query(
        r#"
        SELECT summaries.analysis_job_id,
               summaries.artifact_id,
               jobs.trace_id
        FROM analysis_summaries summaries
        JOIN analysis_jobs jobs ON jobs.id = summaries.analysis_job_id
        WHERE jobs.tenant_id = $1
          AND summaries.artifact_id = $2
        ORDER BY summaries.created_at DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(artifact_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;

    let analysis_job_id: Uuid = summary_row.try_get("analysis_job_id")?;
    let trace_id: String = summary_row.try_get("trace_id")?;
    let reports = sqlx::query(
        r#"
        SELECT report
        FROM static_analysis_reports
        WHERE analysis_job_id = $1
          AND artifact_id = $2
        ORDER BY created_at ASC
        "#,
    )
    .bind(analysis_job_id)
    .bind(artifact_id)
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(|row| {
        row.try_get::<SqlJson<Value>, _>("report")
            .map(|value| value.0)
    })
    .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(ArtifactStaticAnalysisReportsResponse {
        analysis_job_id,
        artifact_id,
        trace_id,
        reports,
    }))
}

async fn list_artifact_sandbox_execution_reports(
    State(state): State<AppState>,
    Path((tenant_id, artifact_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ArtifactSandboxExecutionReportsResponse>, ApiError> {
    let summary_row = sqlx::query(
        r#"
        SELECT summaries.analysis_job_id,
               summaries.artifact_id,
               jobs.trace_id
        FROM analysis_summaries summaries
        JOIN analysis_jobs jobs ON jobs.id = summaries.analysis_job_id
        WHERE jobs.tenant_id = $1
          AND summaries.artifact_id = $2
        ORDER BY summaries.created_at DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(artifact_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;

    let analysis_job_id: Uuid = summary_row.try_get("analysis_job_id")?;
    let trace_id: String = summary_row.try_get("trace_id")?;
    let runs = sqlx::query(
        r#"
        SELECT telemetry
        FROM sandbox_runs
        WHERE analysis_job_id = $1
          AND artifact_id = $2
        ORDER BY started_at ASC NULLS LAST, completed_at ASC NULLS LAST
        "#,
    )
    .bind(analysis_job_id)
    .bind(artifact_id)
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(|row| {
        row.try_get::<SqlJson<Value>, _>("telemetry")
            .map(|value| value.0)
    })
    .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(ArtifactSandboxExecutionReportsResponse {
        analysis_job_id,
        artifact_id,
        trace_id,
        runs,
    }))
}

async fn list_overrides(
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
) -> Result<Json<Vec<OverrideQueueItemResponse>>, ApiError> {
    let rows = sqlx::query(
                r#"
                SELECT overrides.id,
                             overrides.scope,
                             overrides.reason,
                             overrides.requested_by,
                             requester.display_name AS requested_by_display,
                             overrides.approved_by,
                             approver.display_name AS approved_by_display,
                             CASE
                                 WHEN overrides.status IN ('pending', 'approved') AND overrides.expires_at <= now()
                                     THEN 'expired'
                                 ELSE overrides.status
                             END AS status,
                             overrides.expires_at,
                             overrides.created_at
                FROM overrides
                LEFT JOIN users requester ON requester.id = overrides.requested_by
                LEFT JOIN users approver ON approver.id = overrides.approved_by
                WHERE overrides.tenant_id = $1
                ORDER BY
                    CASE
                        WHEN overrides.status = 'pending' AND overrides.expires_at > now() THEN 0
                        WHEN overrides.status = 'approved' AND overrides.expires_at > now() THEN 1
                        ELSE 2
                    END,
                    overrides.created_at DESC,
                    overrides.id DESC
                "#,
        )
        .bind(tenant_id)
        .fetch_all(&state.pool)
        .await?;

    let items = rows
        .iter()
        .map(override_queue_item_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(items))
}

async fn create_override(
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<CreateOverrideRequest>,
) -> Result<Json<OverrideResponse>, ApiError> {
    let actor_id = request
        .requested_by
        .or_else(|| actor_id_from_headers(&headers))
        .ok_or(ApiError::MissingActor)?;
    ensure_tenant_user(&state.pool, tenant_id, actor_id).await?;
    expire_overrides(
        &state.pool,
        tenant_id,
        actor_label(actor_id),
        trace_id(&headers),
    )
    .await?;
    validate_override_reason(&request.reason)?;
    validate_override_expiry(request.expires_at)?;
    validate_override_scope(&request.scope)?;

    let row = sqlx::query(
        r#"
        INSERT INTO overrides (tenant_id, scope, reason, requested_by, status, expires_at)
        VALUES ($1, $2, $3, $4, 'pending', $5)
        RETURNING id, tenant_id, scope, reason, requested_by, approved_by, status, expires_at, created_at
        "#,
    )
    .bind(tenant_id)
    .bind(SqlJson(request.scope.clone()))
    .bind(&request.reason)
    .bind(actor_id)
    .bind(request.expires_at)
    .fetch_one(&state.pool)
    .await?;
    let response = override_response_from_row(&row)?;
    audit(
        &state.pool,
        tenant_id,
        actor_label(actor_id),
        "override.request.created",
        &format!("override/{}", response.id),
        trace_id(&headers),
        Metadata::from([
            ("status".to_owned(), json!(response.status)),
            ("scope".to_owned(), response.scope.clone()),
            ("expires_at".to_owned(), json!(response.expires_at)),
        ]),
    )
    .await?;
    Ok(Json(response))
}

async fn create_emergency_bypass(
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<CreateEmergencyBypassRequest>,
) -> Result<Json<OverrideResponse>, ApiError> {
    let actor_id = request
        .actor_id
        .or_else(|| actor_id_from_headers(&headers))
        .ok_or(ApiError::MissingActor)?;
    ensure_override_manager(&state.pool, tenant_id, actor_id).await?;
    expire_overrides(
        &state.pool,
        tenant_id,
        actor_label(actor_id),
        trace_id(&headers),
    )
    .await?;
    validate_override_reason(&request.reason)?;
    validate_override_expiry(request.expires_at)?;
    validate_override_scope(&request.scope)?;
    let mut scope = request.scope.clone();
    scope
        .as_object_mut()
        .expect("validated scope is an object")
        .insert(
            "effect".to_owned(),
            Value::String("emergency-bypass".to_owned()),
        );

    let row = sqlx::query(
        r#"
        INSERT INTO overrides (tenant_id, scope, reason, requested_by, approved_by, status, expires_at)
        VALUES ($1, $2, $3, $4, $4, 'approved', $5)
        RETURNING id, tenant_id, scope, reason, requested_by, approved_by, status, expires_at, created_at
        "#,
    )
    .bind(tenant_id)
    .bind(SqlJson(scope))
    .bind(&request.reason)
    .bind(actor_id)
    .bind(request.expires_at)
    .fetch_one(&state.pool)
    .await?;
    let response = override_response_from_row(&row)?;
    audit(
        &state.pool,
        tenant_id,
        actor_label(actor_id),
        "override.emergency-bypass.approved",
        &format!("override/{}", response.id),
        trace_id(&headers),
        Metadata::from([
            ("scope".to_owned(), response.scope.clone()),
            ("expires_at".to_owned(), json!(response.expires_at)),
        ]),
    )
    .await?;
    Ok(Json(response))
}

async fn approve_override(
    State(state): State<AppState>,
    Path((tenant_id, override_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<OverrideActionRequest>,
) -> Result<Json<OverrideResponse>, ApiError> {
    let actor_id = request
        .actor_id
        .or_else(|| actor_id_from_headers(&headers))
        .ok_or(ApiError::MissingActor)?;
    ensure_override_manager(&state.pool, tenant_id, actor_id).await?;
    expire_overrides(
        &state.pool,
        tenant_id,
        actor_label(actor_id),
        trace_id(&headers),
    )
    .await?;
    validate_override_reason(&request.reason)?;

    let row = sqlx::query(
        r#"
        UPDATE overrides
        SET status = 'approved',
            approved_by = $3,
            reason = reason || E'\napproval: ' || $4
        WHERE tenant_id = $1
          AND id = $2
          AND status = 'pending'
          AND expires_at > now()
        RETURNING id, tenant_id, scope, reason, requested_by, approved_by, status, expires_at, created_at
        "#,
    )
    .bind(tenant_id)
    .bind(override_id)
    .bind(actor_id)
    .bind(&request.reason)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let response = override_response_from_row(&row)?;
    audit_override_action(
        &state.pool,
        tenant_id,
        actor_id,
        "override.request.approved",
        &response,
        trace_id(&headers),
    )
    .await?;
    Ok(Json(response))
}

async fn deny_override(
    State(state): State<AppState>,
    Path((tenant_id, override_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<OverrideActionRequest>,
) -> Result<Json<OverrideResponse>, ApiError> {
    let actor_id = request
        .actor_id
        .or_else(|| actor_id_from_headers(&headers))
        .ok_or(ApiError::MissingActor)?;
    ensure_override_manager(&state.pool, tenant_id, actor_id).await?;
    expire_overrides(
        &state.pool,
        tenant_id,
        actor_label(actor_id),
        trace_id(&headers),
    )
    .await?;
    validate_override_reason(&request.reason)?;

    let row = sqlx::query(
        r#"
        UPDATE overrides
        SET status = 'denied',
            approved_by = $3,
            reason = reason || E'\ndenial: ' || $4
        WHERE tenant_id = $1
          AND id = $2
          AND status = 'pending'
        RETURNING id, tenant_id, scope, reason, requested_by, approved_by, status, expires_at, created_at
        "#,
    )
    .bind(tenant_id)
    .bind(override_id)
    .bind(actor_id)
    .bind(&request.reason)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let response = override_response_from_row(&row)?;
    audit_override_action(
        &state.pool,
        tenant_id,
        actor_id,
        "override.request.denied",
        &response,
        trace_id(&headers),
    )
    .await?;
    Ok(Json(response))
}

async fn list_registry_configs(
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Vec<RegistryConfigResponse>>, ApiError> {
    let actor_id = actor_id_from_headers(&headers).ok_or(ApiError::MissingActor)?;
    ensure_override_manager(&state.pool, tenant_id, actor_id).await?;
    let rows = sqlx::query(
        r#"
        SELECT id, tenant_id, name, description, adapter::text AS adapter, upstream_url, mount_path,
               auth_type::text AS auth_type, credential_ref, mode::text AS mode, policy_profile_id,
               cache_ttl_seconds, verify_upstream_tls, enabled, deleted_at, created_at, updated_at
        FROM registry_configs
        WHERE tenant_id = $1 AND deleted_at IS NULL
        ORDER BY mount_path ASC
        "#,
    )
    .bind(tenant_id)
    .fetch_all(&state.pool)
    .await?;
    rows.iter()
        .map(registry_config_response_from_row)
        .collect::<Result<Vec<_>, _>>()
        .map(Json)
}

async fn get_registry_config(
    State(state): State<AppState>,
    Path((tenant_id, registry_config_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<RegistryConfigResponse>, ApiError> {
    let actor_id = actor_id_from_headers(&headers).ok_or(ApiError::MissingActor)?;
    ensure_override_manager(&state.pool, tenant_id, actor_id).await?;
    let query = registry_config_select_sql("id = $2");
    let row = sqlx::query(&query)
        .bind(tenant_id)
        .bind(registry_config_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(registry_config_response_from_row(&row)?))
}

async fn create_registry_config(
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<CreateRegistryConfigRequest>,
) -> Result<Json<RegistryConfigResponse>, ApiError> {
    let actor_id = actor_id_from_headers(&headers).ok_or(ApiError::MissingActor)?;
    ensure_override_manager(&state.pool, tenant_id, actor_id).await?;
    validate_registry_create_request(&request)?;

    let row = sqlx::query(
        r#"
        INSERT INTO registry_configs (
          tenant_id, name, description, adapter, upstream_url, mount_path, auth_type,
          credential_ref, mode, policy_profile_id, cache_ttl_seconds, verify_upstream_tls, enabled
        )
        VALUES ($1, $2, $3, $4::registry_adapter, $5, $6, $7::credential_auth_type,
                $8, $9::enforcement_mode, $10, $11, $12, $13)
        RETURNING id, tenant_id, name, description, adapter::text AS adapter, upstream_url, mount_path,
                  auth_type::text AS auth_type, credential_ref, mode::text AS mode, policy_profile_id,
                  cache_ttl_seconds, verify_upstream_tls, enabled, deleted_at, created_at, updated_at
        "#,
    )
    .bind(tenant_id)
    .bind(request.name.trim())
    .bind(request.description.trim())
    .bind(request.adapter.as_db())
    .bind(request.upstream_url.trim())
    .bind(request.mount_path.trim())
    .bind(request.auth_type.as_db())
    .bind(request.credential_ref)
    .bind(policy_mode_db_value(&request.mode))
    .bind(request.policy_profile_id)
    .bind(request.cache_ttl_seconds)
    .bind(request.verify_upstream_tls)
    .bind(request.enabled)
    .fetch_one(&state.pool)
    .await
    .map_err(map_sql_conflict)?;
    let response = registry_config_response_from_row(&row)?;
    audit_registry_config_action(
        &state.pool,
        tenant_id,
        actor_id,
        "registry-config.created",
        &response,
        trace_id(&headers),
    )
    .await?;
    notify_reload(&state).await?;
    Ok(Json(response))
}

async fn update_registry_config(
    State(state): State<AppState>,
    Path((tenant_id, registry_config_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<UpdateRegistryConfigRequest>,
) -> Result<Json<RegistryConfigResponse>, ApiError> {
    let actor_id = actor_id_from_headers(&headers).ok_or(ApiError::MissingActor)?;
    ensure_override_manager(&state.pool, tenant_id, actor_id).await?;
    let query = registry_config_select_sql("id = $2");
    let current_row = sqlx::query(&query)
        .bind(tenant_id)
        .bind(registry_config_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    let current = registry_config_response_from_row(&current_row)?;
    let merged = merge_registry_update(&current, &request)?;

    let row = sqlx::query(
        r#"
        UPDATE registry_configs
        SET name = $3,
            description = $4,
            upstream_url = $5,
            auth_type = $6::credential_auth_type,
            credential_ref = $7,
            mode = $8::enforcement_mode,
            policy_profile_id = $9,
            cache_ttl_seconds = $10,
            verify_upstream_tls = $11,
            enabled = $12,
            updated_at = now()
        WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
        RETURNING id, tenant_id, name, description, adapter::text AS adapter, upstream_url, mount_path,
                  auth_type::text AS auth_type, credential_ref, mode::text AS mode, policy_profile_id,
                  cache_ttl_seconds, verify_upstream_tls, enabled, deleted_at, created_at, updated_at
        "#,
    )
    .bind(tenant_id)
    .bind(registry_config_id)
    .bind(&merged.name)
    .bind(&merged.description)
    .bind(&merged.upstream_url)
    .bind(merged.auth_type.as_db())
    .bind(merged.credential_ref)
    .bind(policy_mode_db_value(&merged.mode))
    .bind(merged.policy_profile_id)
    .bind(merged.cache_ttl_seconds)
    .bind(merged.verify_upstream_tls)
    .bind(merged.enabled)
    .fetch_one(&state.pool)
    .await
    .map_err(map_sql_conflict)?;
    let response = registry_config_response_from_row(&row)?;
    audit_registry_config_action(
        &state.pool,
        tenant_id,
        actor_id,
        "registry-config.updated",
        &response,
        trace_id(&headers),
    )
    .await?;
    notify_reload(&state).await?;
    Ok(Json(response))
}

async fn delete_registry_config(
    State(state): State<AppState>,
    Path((tenant_id, registry_config_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let actor_id = actor_id_from_headers(&headers).ok_or(ApiError::MissingActor)?;
    ensure_override_manager(&state.pool, tenant_id, actor_id).await?;
    let recent_request_count: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*)
        FROM package_requests
        WHERE tenant_id = $1
          AND registry_config_id = $2
          AND requested_at > now() - interval '1 minute'
        "#,
    )
    .bind(tenant_id)
    .bind(registry_config_id)
    .fetch_one(&state.pool)
    .await?;
    if recent_request_count > 0 {
        return Err(ApiError::Conflict);
    }
    let row = sqlx::query(
        r#"
        UPDATE registry_configs
        SET enabled = false, deleted_at = now(), updated_at = now()
        WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
        RETURNING id, tenant_id, name, description, adapter::text AS adapter, upstream_url, mount_path,
                  auth_type::text AS auth_type, credential_ref, mode::text AS mode, policy_profile_id,
                  cache_ttl_seconds, verify_upstream_tls, enabled, deleted_at, created_at, updated_at
        "#,
    )
    .bind(tenant_id)
    .bind(registry_config_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let response = registry_config_response_from_row(&row)?;
    audit_registry_config_action(
        &state.pool,
        tenant_id,
        actor_id,
        "registry-config.deleted",
        &response,
        trace_id(&headers),
    )
    .await?;
    notify_reload(&state).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_credentials(
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Vec<CredentialStatusResponse>>, ApiError> {
    let actor_id = actor_id_from_headers(&headers).ok_or(ApiError::MissingActor)?;
    ensure_override_manager(&state.pool, tenant_id, actor_id).await?;
    let rows = sqlx::query(
        r#"
        SELECT id, tenant_id, name, credential_type, source, encrypted_value_key_id,
               configured, created_at, updated_at
        FROM integration_credentials
        WHERE tenant_id = $1
        ORDER BY name ASC
        "#,
    )
    .bind(tenant_id)
    .fetch_all(&state.pool)
    .await?;
    rows.iter()
        .map(credential_response_from_row)
        .collect::<Result<Vec<_>, _>>()
        .map(Json)
}

async fn create_credential(
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<CreateCredentialRequest>,
) -> Result<Json<CredentialStatusResponse>, ApiError> {
    let actor_id = actor_id_from_headers(&headers).ok_or(ApiError::MissingActor)?;
    ensure_override_manager(&state.pool, tenant_id, actor_id).await?;
    validate_credential_request(&request.name, &request.credential_type, &request.source)?;
    let configured = request.configured || request.encrypted_value_ciphertext.is_some();
    let row = sqlx::query(
        r#"
        INSERT INTO integration_credentials (
          tenant_id, name, credential_type, source, encrypted_value_ciphertext,
          encrypted_value_key_id, configured
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id, tenant_id, name, credential_type, source, encrypted_value_key_id,
                  configured, created_at, updated_at
        "#,
    )
    .bind(tenant_id)
    .bind(request.name.trim())
    .bind(request.credential_type.trim())
    .bind(request.source.trim())
    .bind(request.encrypted_value_ciphertext)
    .bind(request.encrypted_value_key_id.as_deref())
    .bind(configured)
    .fetch_one(&state.pool)
    .await
    .map_err(map_sql_conflict)?;
    let response = credential_response_from_row(&row)?;
    audit_credential_action(
        &state.pool,
        tenant_id,
        actor_id,
        "credential.created",
        &response,
        trace_id(&headers),
    )
    .await?;
    Ok(Json(response))
}

async fn rotate_credential(
    State(state): State<AppState>,
    Path((tenant_id, credential_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<RotateCredentialRequest>,
) -> Result<Json<CredentialStatusResponse>, ApiError> {
    let actor_id = actor_id_from_headers(&headers).ok_or(ApiError::MissingActor)?;
    ensure_override_manager(&state.pool, tenant_id, actor_id).await?;
    let configured = request
        .configured
        .unwrap_or(request.encrypted_value_ciphertext.is_some());
    let row = sqlx::query(
        r#"
        UPDATE integration_credentials
        SET encrypted_value_ciphertext = COALESCE($3, encrypted_value_ciphertext),
            encrypted_value_key_id = COALESCE($4, encrypted_value_key_id),
            configured = $5,
            updated_at = now()
        WHERE tenant_id = $1 AND id = $2
        RETURNING id, tenant_id, name, credential_type, source, encrypted_value_key_id,
                  configured, created_at, updated_at
        "#,
    )
    .bind(tenant_id)
    .bind(credential_id)
    .bind(request.encrypted_value_ciphertext)
    .bind(request.encrypted_value_key_id.as_deref())
    .bind(configured)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let response = credential_response_from_row(&row)?;
    audit_credential_action(
        &state.pool,
        tenant_id,
        actor_id,
        "credential.rotated",
        &response,
        trace_id(&headers),
    )
    .await?;
    Ok(Json(response))
}

async fn delete_credential(
    State(state): State<AppState>,
    Path((tenant_id, credential_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let actor_id = actor_id_from_headers(&headers).ok_or(ApiError::MissingActor)?;
    ensure_override_manager(&state.pool, tenant_id, actor_id).await?;
    let referenced_count: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*)
        FROM registry_configs
        WHERE tenant_id = $1
          AND credential_ref = $2
          AND deleted_at IS NULL
        "#,
    )
    .bind(tenant_id)
    .bind(credential_id)
    .fetch_one(&state.pool)
    .await?;
    if referenced_count > 0 {
        return Err(ApiError::Conflict);
    }
    let deleted = sqlx::query(
        r#"
        DELETE FROM integration_credentials
        WHERE tenant_id = $1 AND id = $2
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(credential_id)
    .fetch_optional(&state.pool)
    .await?;
    if deleted.is_none() {
        return Err(ApiError::NotFound);
    }
    audit(
        &state.pool,
        tenant_id,
        actor_label(actor_id),
        "credential.deleted",
        &format!("credential/{credential_id}"),
        trace_id(&headers),
        Metadata::from([("credential_id".to_owned(), json!(credential_id))]),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn test_credential_connection(
    State(state): State<AppState>,
    Path((tenant_id, credential_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<CredentialTestResponse>, ApiError> {
    let actor_id = actor_id_from_headers(&headers).ok_or(ApiError::MissingActor)?;
    ensure_override_manager(&state.pool, tenant_id, actor_id).await?;
    let configured: Option<bool> = sqlx::query_scalar(
        r#"
        SELECT configured
        FROM integration_credentials
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(credential_id)
    .fetch_optional(&state.pool)
    .await?;
    let configured = configured.ok_or(ApiError::NotFound)?;
    Ok(Json(CredentialTestResponse {
        credential_id,
        configured,
        message: if configured {
            "credential metadata is configured"
        } else {
            "credential metadata is present but no encrypted value is configured"
        },
    }))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEventResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub actor: String,
    pub actor_display: String,
    pub actor_roles: Vec<String>,
    pub action: String,
    pub resource: String,
    pub trace_id: String,
    pub occurred_at: DateTime<Utc>,
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuditActorIdentity {
    display_name: String,
    roles: Vec<String>,
}

#[derive(Debug, Clone)]
struct AuditEventFilters {
    limit: i64,
    action_filter: Option<String>,
    actor_filter: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiProviderConfigResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub display_name: String,
    pub provider_type: String,
    pub base_url: Option<String>,
    pub model_id: String,
    pub credential_ref: Option<Uuid>,
    pub is_local: bool,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LlmUsageSummaryResponse {
    pub total_calls: i64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
    pub estimated_cost: f64,
    pub avg_latency_ms: Option<f64>,
    pub p95_latency_ms: Option<f64>,
    pub schema_validation_passes: i64,
    pub schema_validation_failures: i64,
    pub redaction_failures: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LlmUsageDailyBucketResponse {
    pub day: String,
    pub total_calls: i64,
    pub total_tokens: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LlmUsageProviderModelResponse {
    pub provider_display_name: String,
    pub provider_type: String,
    pub model_id: String,
    pub total_calls: i64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
    pub estimated_cost: f64,
    pub avg_latency_ms: Option<f64>,
    pub p95_latency_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LlmUsageAnalysisJobResponse {
    pub analysis_job_id: Uuid,
    pub trace_id: String,
    pub provider_display_name: String,
    pub model_id: String,
    pub total_calls: i64,
    pub total_tokens: i64,
    pub estimated_cost: f64,
    pub langfuse_trace_id: Option<String>,
    pub last_called_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LlmUsageFailingTraceResponse {
    pub analysis_job_id: Uuid,
    pub trace_id: String,
    pub provider_display_name: String,
    pub provider_type: String,
    pub model_id: String,
    pub langfuse_trace_id: Option<String>,
    pub prompt_template_version: String,
    pub schema_valid: bool,
    pub redaction_complete: bool,
    pub latency_ms: Option<f64>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LlmUsagePromptTemplateVersionResponse {
    pub prompt_template_version: String,
    pub total_calls: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LlmUsageResponse {
    pub tenant_id: Uuid,
    pub summary: LlmUsageSummaryResponse,
    pub calls_by_day: Vec<LlmUsageDailyBucketResponse>,
    pub provider_models: Vec<LlmUsageProviderModelResponse>,
    pub analysis_jobs: Vec<LlmUsageAnalysisJobResponse>,
    pub failing_traces: Vec<LlmUsageFailingTraceResponse>,
    pub prompt_template_versions: Vec<LlmUsagePromptTemplateVersionResponse>,
}

async fn list_audit_events(
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<Vec<AuditEventResponse>>, ApiError> {
    let actor_id = actor_id_from_headers(&headers).ok_or(ApiError::MissingActor)?;
    ensure_override_manager(&state.pool, tenant_id, actor_id).await?;
    let filters = audit_event_filters(&params);
    Ok(Json(
        load_audit_events(&state.pool, tenant_id, &filters).await?,
    ))
}

async fn export_audit_events_csv(
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Response, ApiError> {
    let actor_id = actor_id_from_headers(&headers).ok_or(ApiError::MissingActor)?;
    ensure_override_manager(&state.pool, tenant_id, actor_id).await?;
    let filters = audit_event_filters(&params);
    let csv = render_audit_events_csv(&load_audit_events(&state.pool, tenant_id, &filters).await?);
    let mut response = csv.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!(
            "attachment; filename=\"audit-events-{tenant_id}.csv\""
        ))
        .expect("valid content disposition"),
    );
    Ok(response)
}

async fn list_openvex_documents(
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Vec<OpenVexDocumentSummaryResponse>>, ApiError> {
    let actor_id = actor_id_from_headers(&headers).ok_or(ApiError::MissingActor)?;
    ensure_override_manager(&state.pool, tenant_id, actor_id).await?;
    let rows = sqlx::query(
        r#"
        SELECT id, tenant_id, source, document_id, author, context, version,
               document_timestamp, imported_at, expiry_mode, expires_at,
               document_digest, statement_count
        FROM openvex_documents
        WHERE tenant_id = $1
        ORDER BY imported_at DESC, id DESC
        "#,
    )
    .bind(tenant_id)
    .fetch_all(&state.pool)
    .await?;

    rows.iter()
        .map(openvex_document_summary_from_row)
        .collect::<Result<Vec<_>, _>>()
        .map(Json)
}

async fn get_openvex_document(
    State(state): State<AppState>,
    Path((tenant_id, openvex_document_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<OpenVexDocumentResponse>, ApiError> {
    let actor_id = actor_id_from_headers(&headers).ok_or(ApiError::MissingActor)?;
    ensure_override_manager(&state.pool, tenant_id, actor_id).await?;
    let row = sqlx::query(
        r#"
        SELECT id, tenant_id, source, document_id, author, context, version,
               document_timestamp, imported_at, expiry_mode, expires_at,
               document_digest, statement_count, document
        FROM openvex_documents
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(openvex_document_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;

    Ok(Json(openvex_document_from_row(&row)?))
}

async fn create_openvex_document(
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<CreateOpenVexDocumentRequest>,
) -> Result<Json<OpenVexDocumentResponse>, ApiError> {
    let actor_id = actor_id_from_headers(&headers).ok_or(ApiError::MissingActor)?;
    ensure_override_manager(&state.pool, tenant_id, actor_id).await?;
    let validated = validate_openvex_request(&request)?;
    let source = request.source.trim().to_owned();
    let document_bytes = serde_json::to_vec(&request.document).map_err(|error| {
        ApiError::InvalidRequest(format!("document must be valid JSON: {error}"))
    })?;
    let document_digest = hex_sha256(&document_bytes);
    let imported_at = Utc::now();
    let openvex_document_id = Uuid::now_v7();
    let audit_event = build_audit_event(
        tenant_id,
        actor_label(actor_id),
        "openvex.document.imported",
        &format!("openvex-document/{openvex_document_id}"),
        trace_id(&headers),
        Metadata::from([
            ("source".to_owned(), json!(source.clone())),
            (
                "document_id".to_owned(),
                json!(validated.document_id.clone()),
            ),
            (
                "statement_count".to_owned(),
                json!(validated.statement_count),
            ),
            (
                "expiry_mode".to_owned(),
                json!(request.expiry_policy.mode.as_db()),
            ),
            (
                "expires_at".to_owned(),
                json!(request.expiry_policy.expires_at),
            ),
            ("document_digest".to_owned(), json!(document_digest.clone())),
        ]),
    )?;

    let mut transaction = state.pool.begin().await?;
    sqlx::query(
        r#"
        INSERT INTO openvex_documents (
          id, tenant_id, source, document_id, author, context, version,
          document_timestamp, imported_at, expiry_mode, expires_at,
          document_digest, statement_count, document
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        "#,
    )
    .bind(openvex_document_id)
    .bind(tenant_id)
    .bind(&source)
    .bind(&validated.document_id)
    .bind(&validated.author)
    .bind(&validated.context)
    .bind(validated.version)
    .bind(validated.document_timestamp)
    .bind(imported_at)
    .bind(request.expiry_policy.mode.as_db())
    .bind(request.expiry_policy.expires_at)
    .bind(&document_digest)
    .bind(validated.statement_count)
    .bind(SqlJson(request.document.clone()))
    .execute(&mut *transaction)
    .await?;

    for statement in &validated.statements {
        sqlx::query(
            r#"
            INSERT INTO openvex_statements (
              id, openvex_document_id, tenant_id, statement_index, vulnerability_id,
              status, product_id, justification, impact_statement, action_statement,
              statement_timestamp, raw_statement
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(openvex_document_id)
        .bind(tenant_id)
        .bind(statement.statement_index)
        .bind(&statement.vulnerability_id)
        .bind(&statement.status)
        .bind(&statement.product_id)
        .bind(statement.justification.as_deref())
        .bind(statement.impact_statement.as_deref())
        .bind(statement.action_statement.as_deref())
        .bind(statement.statement_timestamp)
        .bind(SqlJson(statement.raw_statement.clone()))
        .execute(&mut *transaction)
        .await?;
    }

    insert_audit_event(&mut *transaction, audit_event).await?;

    transaction.commit().await?;

    let response = OpenVexDocumentResponse {
        summary: OpenVexDocumentSummaryResponse {
            id: openvex_document_id,
            tenant_id,
            source,
            document_id: validated.document_id.clone(),
            author: validated.author.clone(),
            context: validated.context.clone(),
            version: validated.version,
            document_timestamp: validated.document_timestamp,
            imported_at,
            expiry_policy: OpenVexExpiryPolicyResponse {
                mode: request.expiry_policy.mode,
                expires_at: request.expiry_policy.expires_at,
            },
            document_digest: document_digest.clone(),
            statement_count: validated.statement_count,
        },
        document: request.document,
    };

    Ok(Json(response))
}

fn audit_event_filters(params: &HashMap<String, String>) -> AuditEventFilters {
    AuditEventFilters {
        limit: params
            .get("limit")
            .and_then(|value| value.parse().ok())
            .unwrap_or(50)
            .min(200),
        action_filter: params.get("action").cloned(),
        actor_filter: params.get("actor").cloned(),
    }
}

async fn load_audit_events(
    pool: &PgPool,
    tenant_id: Uuid,
    filters: &AuditEventFilters,
) -> Result<Vec<AuditEventResponse>, ApiError> {
    let rows = sqlx::query(
        r#"
        SELECT id, tenant_id, actor, action, resource, trace_id, occurred_at, metadata
        FROM audit_events
        WHERE tenant_id = $1
          AND ($2::text IS NULL OR action = $2)
          AND ($3::text IS NULL OR actor = $3)
        ORDER BY occurred_at DESC
        LIMIT $4
        "#,
    )
    .bind(tenant_id)
    .bind(filters.action_filter.clone())
    .bind(filters.actor_filter.clone())
    .bind(filters.limit)
    .fetch_all(pool)
    .await?;

    let actor_identities = load_audit_actor_identities(pool, tenant_id, &rows).await?;

    Ok(rows
        .into_iter()
        .map(|row| {
            let actor: String = row.try_get("actor").unwrap();
            let (actor_display, actor_roles) = actor_user_id_from_label(&actor)
                .and_then(|actor_id| actor_identities.get(&actor_id).cloned())
                .map(|identity| (identity.display_name, identity.roles))
                .unwrap_or_else(|| (actor.clone(), Vec::new()));

            AuditEventResponse {
                id: row.try_get("id").unwrap(),
                tenant_id: row.try_get("tenant_id").unwrap(),
                actor,
                actor_display,
                actor_roles,
                action: row.try_get("action").unwrap(),
                resource: row.try_get("resource").unwrap(),
                trace_id: row.try_get("trace_id").unwrap(),
                occurred_at: row.try_get("occurred_at").unwrap(),
                metadata: row
                    .try_get::<SqlJson<Value>, _>("metadata")
                    .map(|value| value.0)
                    .unwrap_or(Value::Null),
            }
        })
        .collect())
}

fn render_audit_events_csv(events: &[AuditEventResponse]) -> String {
    let mut csv = String::from(
        "occurred_at,action,actor,actor_display,actor_roles,resource,trace_id,metadata\n",
    );
    for event in events {
        let metadata = serde_json::to_string(&event.metadata).unwrap_or_else(|_| "null".to_owned());
        let roles = event.actor_roles.join(";");
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            csv_escape(&event.occurred_at.to_rfc3339()),
            csv_escape(&event.action),
            csv_escape(&event.actor),
            csv_escape(&event.actor_display),
            csv_escape(&roles),
            csv_escape(&event.resource),
            csv_escape(&event.trace_id),
            csv_escape(&metadata),
        ));
    }
    csv
}

fn csv_escape(value: &str) -> String {
    let escaped = value.replace('"', "\"\"");
    if escaped.contains([',', '"', '\n']) {
        format!("\"{escaped}\"")
    } else {
        escaped
    }
}

async fn load_audit_actor_identities(
    pool: &PgPool,
    tenant_id: Uuid,
    rows: &[sqlx::postgres::PgRow],
) -> Result<HashMap<Uuid, AuditActorIdentity>, sqlx::Error> {
    let actor_ids: Vec<Uuid> = rows
        .iter()
        .filter_map(|row| row.try_get::<String, _>("actor").ok())
        .filter_map(|actor| actor_user_id_from_label(&actor))
        .collect();

    if actor_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let identity_rows = sqlx::query(
        r#"
        SELECT
            u.id,
            u.display_name,
            COALESCE(
                array_agg(DISTINCT r.name) FILTER (WHERE r.name IS NOT NULL),
                ARRAY[]::text[]
            ) AS actor_roles
        FROM users u
        LEFT JOIN user_roles ur ON ur.user_id = u.id
        LEFT JOIN roles r ON r.id = ur.role_id AND r.tenant_id = u.tenant_id
        WHERE u.tenant_id = $1
          AND u.id = ANY($2)
        GROUP BY u.id, u.display_name
        "#,
    )
    .bind(tenant_id)
    .bind(&actor_ids)
    .fetch_all(pool)
    .await?;

    Ok(identity_rows
        .into_iter()
        .map(|row| {
            (
                row.try_get("id").unwrap(),
                AuditActorIdentity {
                    display_name: row.try_get("display_name").unwrap(),
                    roles: row.try_get("actor_roles").unwrap_or_default(),
                },
            )
        })
        .collect())
}

async fn list_ai_providers(
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Vec<AiProviderConfigResponse>>, ApiError> {
    let actor_id = actor_id_from_headers(&headers).ok_or(ApiError::MissingActor)?;
    ensure_override_manager(&state.pool, tenant_id, actor_id).await?;
    let rows = sqlx::query(
        r#"
        SELECT id, tenant_id, display_name, provider_type, base_url, model_id,
               credential_ref, is_local, active, created_at, updated_at
        FROM ai_provider_configs
        WHERE tenant_id = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(tenant_id)
    .fetch_all(&state.pool)
    .await?;

    let providers = rows
        .into_iter()
        .map(|row| AiProviderConfigResponse {
            id: row.try_get("id").unwrap(),
            tenant_id: row.try_get("tenant_id").unwrap(),
            display_name: row.try_get("display_name").unwrap(),
            provider_type: row.try_get("provider_type").unwrap(),
            base_url: row.try_get("base_url").unwrap_or(None),
            model_id: row.try_get("model_id").unwrap(),
            credential_ref: row.try_get("credential_ref").unwrap_or(None),
            is_local: row.try_get("is_local").unwrap(),
            active: row.try_get("active").unwrap(),
            created_at: row.try_get("created_at").unwrap(),
            updated_at: row.try_get("updated_at").unwrap(),
        })
        .collect();

    Ok(Json(providers))
}

async fn get_llm_usage(
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<LlmUsageResponse>, ApiError> {
    let actor_id = actor_id_from_headers(&headers).ok_or(ApiError::MissingActor)?;
    ensure_llm_usage_reader(&state.pool, tenant_id, actor_id).await?;

    let summary_row = sqlx::query(
        r#"
        SELECT
            COUNT(*)::bigint AS total_calls,
            COALESCE(SUM(prompt_tokens), 0)::bigint AS prompt_tokens,
            COALESCE(SUM(completion_tokens), 0)::bigint AS completion_tokens,
            COALESCE(SUM(total_tokens), 0)::bigint AS total_tokens,
            COALESCE(SUM(estimated_cost), 0)::double precision AS estimated_cost,
            AVG(latency_ms) AS avg_latency_ms,
            percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95_latency_ms,
            COALESCE(SUM(CASE WHEN schema_valid THEN 1 ELSE 0 END), 0)::bigint AS schema_validation_passes,
            COALESCE(SUM(CASE WHEN NOT schema_valid THEN 1 ELSE 0 END), 0)::bigint AS schema_validation_failures,
            COALESCE(SUM(CASE WHEN NOT redaction_complete THEN 1 ELSE 0 END), 0)::bigint AS redaction_failures
        FROM llm_usage_events
        WHERE tenant_id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_one(&state.pool)
    .await?;

    let calls_by_day = sqlx::query(
        r#"
        SELECT
            TO_CHAR(DATE_TRUNC('day', created_at AT TIME ZONE 'UTC'), 'YYYY-MM-DD') AS day,
            COUNT(*)::bigint AS total_calls,
            COALESCE(SUM(total_tokens), 0)::bigint AS total_tokens
        FROM llm_usage_events
        WHERE tenant_id = $1
          AND created_at >= NOW() - INTERVAL '7 days'
        GROUP BY 1
        ORDER BY day ASC
        "#,
    )
    .bind(tenant_id)
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(|row| LlmUsageDailyBucketResponse {
        day: row.try_get("day").unwrap(),
        total_calls: row.try_get("total_calls").unwrap(),
        total_tokens: row.try_get("total_tokens").unwrap(),
    })
    .collect();

    let provider_models = sqlx::query(
        r#"
        SELECT
            provider_display_name,
            provider_type,
            model_id,
            COUNT(*)::bigint AS total_calls,
            COALESCE(SUM(prompt_tokens), 0)::bigint AS prompt_tokens,
            COALESCE(SUM(completion_tokens), 0)::bigint AS completion_tokens,
            COALESCE(SUM(total_tokens), 0)::bigint AS total_tokens,
            COALESCE(SUM(estimated_cost), 0)::double precision AS estimated_cost,
            AVG(latency_ms) AS avg_latency_ms,
            percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95_latency_ms
        FROM llm_usage_events
        WHERE tenant_id = $1
        GROUP BY provider_display_name, provider_type, model_id
        ORDER BY total_tokens DESC, total_calls DESC, provider_display_name ASC, model_id ASC
        "#,
    )
    .bind(tenant_id)
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(|row| LlmUsageProviderModelResponse {
        provider_display_name: row.try_get("provider_display_name").unwrap(),
        provider_type: row.try_get("provider_type").unwrap(),
        model_id: row.try_get("model_id").unwrap(),
        total_calls: row.try_get("total_calls").unwrap(),
        prompt_tokens: row.try_get("prompt_tokens").unwrap(),
        completion_tokens: row.try_get("completion_tokens").unwrap(),
        total_tokens: row.try_get("total_tokens").unwrap(),
        estimated_cost: row.try_get("estimated_cost").unwrap(),
        avg_latency_ms: row.try_get("avg_latency_ms").unwrap_or(None),
        p95_latency_ms: row.try_get("p95_latency_ms").unwrap_or(None),
    })
    .collect();

    let analysis_jobs = sqlx::query(
        r#"
        SELECT
            analysis_job_id,
            trace_id,
            provider_display_name,
            model_id,
            COUNT(*)::bigint AS total_calls,
            COALESCE(SUM(total_tokens), 0)::bigint AS total_tokens,
            COALESCE(SUM(estimated_cost), 0)::double precision AS estimated_cost,
            MAX(langfuse_trace_id) FILTER (WHERE langfuse_trace_id IS NOT NULL) AS langfuse_trace_id,
            MAX(created_at) AS last_called_at
        FROM llm_usage_events
        WHERE tenant_id = $1
        GROUP BY analysis_job_id, trace_id, provider_display_name, model_id
        ORDER BY last_called_at DESC, analysis_job_id ASC
        LIMIT 20
        "#,
    )
    .bind(tenant_id)
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(|row| LlmUsageAnalysisJobResponse {
        analysis_job_id: row.try_get("analysis_job_id").unwrap(),
        trace_id: row.try_get("trace_id").unwrap(),
        provider_display_name: row.try_get("provider_display_name").unwrap(),
        model_id: row.try_get("model_id").unwrap(),
        total_calls: row.try_get("total_calls").unwrap(),
        total_tokens: row.try_get("total_tokens").unwrap(),
        estimated_cost: row.try_get("estimated_cost").unwrap(),
        langfuse_trace_id: row.try_get("langfuse_trace_id").unwrap_or(None),
        last_called_at: row.try_get("last_called_at").unwrap(),
    })
    .collect();

    let failing_traces = sqlx::query(
        r#"
        SELECT
            analysis_job_id,
            trace_id,
            provider_display_name,
            provider_type,
            model_id,
            langfuse_trace_id,
            prompt_template_version,
            schema_valid,
            redaction_complete,
            latency_ms,
            created_at
        FROM llm_usage_events
        WHERE tenant_id = $1
          AND (NOT schema_valid OR NOT redaction_complete)
        ORDER BY created_at DESC, analysis_job_id ASC
        LIMIT 20
        "#,
    )
    .bind(tenant_id)
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(|row| LlmUsageFailingTraceResponse {
        analysis_job_id: row.try_get("analysis_job_id").unwrap(),
        trace_id: row.try_get("trace_id").unwrap(),
        provider_display_name: row.try_get("provider_display_name").unwrap(),
        provider_type: row.try_get("provider_type").unwrap(),
        model_id: row.try_get("model_id").unwrap(),
        langfuse_trace_id: row.try_get("langfuse_trace_id").unwrap_or(None),
        prompt_template_version: row.try_get("prompt_template_version").unwrap(),
        schema_valid: row.try_get("schema_valid").unwrap(),
        redaction_complete: row.try_get("redaction_complete").unwrap(),
        latency_ms: row.try_get("latency_ms").unwrap_or(None),
        created_at: row.try_get("created_at").unwrap(),
    })
    .collect();

    let prompt_template_versions = sqlx::query(
        r#"
        SELECT prompt_template_version, COUNT(*)::bigint AS total_calls
        FROM llm_usage_events
        WHERE tenant_id = $1
        GROUP BY prompt_template_version
        ORDER BY total_calls DESC, prompt_template_version ASC
        "#,
    )
    .bind(tenant_id)
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(|row| LlmUsagePromptTemplateVersionResponse {
        prompt_template_version: row.try_get("prompt_template_version").unwrap(),
        total_calls: row.try_get("total_calls").unwrap(),
    })
    .collect();

    Ok(Json(LlmUsageResponse {
        tenant_id,
        summary: LlmUsageSummaryResponse {
            total_calls: summary_row.try_get("total_calls")?,
            prompt_tokens: summary_row.try_get("prompt_tokens")?,
            completion_tokens: summary_row.try_get("completion_tokens")?,
            total_tokens: summary_row.try_get("total_tokens")?,
            estimated_cost: summary_row.try_get("estimated_cost")?,
            avg_latency_ms: summary_row.try_get("avg_latency_ms")?,
            p95_latency_ms: summary_row.try_get("p95_latency_ms")?,
            schema_validation_passes: summary_row.try_get("schema_validation_passes")?,
            schema_validation_failures: summary_row.try_get("schema_validation_failures")?,
            redaction_failures: summary_row.try_get("redaction_failures")?,
        },
        calls_by_day,
        provider_models,
        analysis_jobs,
        failing_traces,
        prompt_template_versions,
    }))
}

async fn ensure_tenant_user(
    pool: &PgPool,
    tenant_id: Uuid,
    actor_id: Uuid,
) -> Result<(), ApiError> {
    let exists: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
          SELECT 1 FROM users WHERE tenant_id = $1 AND id = $2
        )
        "#,
    )
    .bind(tenant_id)
    .bind(actor_id)
    .fetch_one(pool)
    .await?;
    if exists {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

async fn ensure_override_manager(
    pool: &PgPool,
    tenant_id: Uuid,
    actor_id: Uuid,
) -> Result<(), ApiError> {
    let roles: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT r.name
        FROM user_roles ur
        JOIN roles r ON r.id = ur.role_id
        WHERE ur.user_id = $1 AND r.tenant_id = $2
        "#,
    )
    .bind(actor_id)
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    if roles.iter().any(|role| role_can_manage_control_plane(role)) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

async fn ensure_llm_usage_reader(
    pool: &PgPool,
    tenant_id: Uuid,
    actor_id: Uuid,
) -> Result<(), ApiError> {
    let roles: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT r.name
        FROM user_roles ur
        JOIN roles r ON r.id = ur.role_id
        WHERE ur.user_id = $1 AND r.tenant_id = $2
        "#,
    )
    .bind(actor_id)
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    if roles.iter().any(|role| role_can_view_llm_usage(role)) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

fn role_can_manage_control_plane(role: &str) -> bool {
    matches!(
        role.trim().to_ascii_lowercase().as_str(),
        "admin" | "security-admin" | "security-specialist" | "platform-admin"
    )
}

fn role_can_view_llm_usage(role: &str) -> bool {
    matches!(
        role.trim().to_ascii_lowercase().as_str(),
        "admin" | "platform-admin"
    )
}

async fn expire_overrides(
    pool: &PgPool,
    tenant_id: Uuid,
    actor: String,
    trace_id: String,
) -> Result<(), ApiError> {
    let rows = sqlx::query(
        r#"
        UPDATE overrides
        SET status = 'expired'
        WHERE tenant_id = $1
          AND status IN ('pending', 'approved')
          AND expires_at <= now()
        RETURNING id, scope, expires_at
        "#,
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    for row in rows {
        let override_id: Uuid = row.try_get("id")?;
        let scope: SqlJson<Value> = row.try_get("scope")?;
        let expires_at: DateTime<Utc> = row.try_get("expires_at")?;
        audit(
            pool,
            tenant_id,
            actor.clone(),
            "override.expired",
            &format!("override/{override_id}"),
            trace_id.clone(),
            Metadata::from([
                ("scope".to_owned(), scope.0),
                ("expires_at".to_owned(), json!(expires_at)),
            ]),
        )
        .await?;
    }
    Ok(())
}

async fn audit_override_action(
    pool: &PgPool,
    tenant_id: Uuid,
    actor_id: Uuid,
    action: &'static str,
    response: &OverrideResponse,
    trace_id: String,
) -> Result<(), ApiError> {
    audit(
        pool,
        tenant_id,
        actor_label(actor_id),
        action,
        &format!("override/{}", response.id),
        trace_id,
        Metadata::from([
            ("status".to_owned(), json!(response.status)),
            ("scope".to_owned(), response.scope.clone()),
            ("expires_at".to_owned(), json!(response.expires_at)),
        ]),
    )
    .await
}

async fn audit_registry_config_action(
    pool: &PgPool,
    tenant_id: Uuid,
    actor_id: Uuid,
    action: &'static str,
    response: &RegistryConfigResponse,
    trace_id: String,
) -> Result<(), ApiError> {
    audit(
        pool,
        tenant_id,
        actor_label(actor_id),
        action,
        &format!("registry-config/{}", response.id),
        trace_id,
        Metadata::from([
            ("adapter".to_owned(), json!(response.adapter)),
            ("mount_path".to_owned(), json!(response.mount_path)),
            ("enabled".to_owned(), json!(response.enabled)),
            (
                "credential_ref".to_owned(),
                response
                    .credential_ref
                    .map_or(Value::Null, |credential_ref| json!(credential_ref)),
            ),
        ]),
    )
    .await
}

async fn audit_credential_action(
    pool: &PgPool,
    tenant_id: Uuid,
    actor_id: Uuid,
    action: &'static str,
    response: &CredentialStatusResponse,
    trace_id: String,
) -> Result<(), ApiError> {
    audit(
        pool,
        tenant_id,
        actor_label(actor_id),
        action,
        &format!("credential/{}", response.id),
        trace_id,
        Metadata::from([
            ("credential_id".to_owned(), json!(response.id)),
            (
                "credential_type".to_owned(),
                json!(response.credential_type),
            ),
            ("source".to_owned(), json!(response.source)),
            ("configured".to_owned(), json!(response.configured)),
        ]),
    )
    .await
}

fn build_audit_event(
    tenant_id: Uuid,
    actor: String,
    action: &'static str,
    resource: &str,
    trace_id: String,
    metadata: Metadata,
) -> Result<AuditEvent, ApiError> {
    validate_audit_metadata(&metadata).map_err(ApiError::InvalidRequest)?;
    Ok(AuditEvent {
        id: Uuid::now_v7(),
        tenant_id,
        actor,
        action: action.to_owned(),
        resource: resource.to_owned(),
        trace_id,
        occurred_at: Utc::now(),
        metadata,
    })
}

async fn insert_audit_event<'a, E>(executor: E, event: AuditEvent) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'a, Database = sqlx::Postgres>,
{
    sqlx::query(
        r#"
        INSERT INTO audit_events (id, tenant_id, actor, action, resource, trace_id, metadata, occurred_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(event.id)
    .bind(event.tenant_id)
    .bind(&event.actor)
    .bind(&event.action)
    .bind(&event.resource)
    .bind(&event.trace_id)
    .bind(SqlJson(event.metadata))
    .bind(event.occurred_at)
    .execute(executor)
    .await?;
    Ok(())
}

async fn audit(
    pool: &PgPool,
    tenant_id: Uuid,
    actor: String,
    action: &'static str,
    resource: &str,
    trace_id: String,
    metadata: Metadata,
) -> Result<(), ApiError> {
    let event = build_audit_event(tenant_id, actor, action, resource, trace_id, metadata)?;
    insert_audit_event(pool, event).await?;
    Ok(())
}

async fn notify_reload(state: &AppState) -> Result<(), ApiError> {
    if let Some(client) = &state.reload_client {
        client.notify().await?;
    }
    Ok(())
}

fn validate_override_reason(reason: &str) -> Result<(), ApiError> {
    if reason.trim().len() < 8 {
        return Err(ApiError::InvalidRequest(
            "override reason must contain at least 8 non-whitespace characters".to_owned(),
        ));
    }
    Ok(())
}

fn validate_override_expiry(expires_at: DateTime<Utc>) -> Result<(), ApiError> {
    if expires_at <= Utc::now() {
        return Err(ApiError::InvalidRequest(
            "override expiry must be in the future".to_owned(),
        ));
    }
    Ok(())
}

fn validate_override_scope(scope: &Value) -> Result<(), ApiError> {
    let Some(object) = scope.as_object() else {
        return Err(ApiError::InvalidRequest(
            "override scope must be a JSON object".to_owned(),
        ));
    };
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "ecosystem" | "name" | "namespace" | "version" | "digest" | "kind" | "effect"
        ) {
            return Err(ApiError::InvalidRequest(format!(
                "override scope key `{key}` is not supported"
            )));
        }
    }
    if let Some(effect) = object.get("effect").and_then(Value::as_str)
        && !matches!(effect, "allow" | "emergency-bypass")
    {
        return Err(ApiError::InvalidRequest(
            "override scope effect must be allow or emergency-bypass".to_owned(),
        ));
    }
    if let Some(kind) = object.get("kind").and_then(Value::as_str)
        && !matches!(kind, "metadata" | "artifact")
    {
        return Err(ApiError::InvalidRequest(
            "override scope kind must be metadata or artifact".to_owned(),
        ));
    }
    Ok(())
}

fn validate_registry_create_request(request: &CreateRegistryConfigRequest) -> Result<(), ApiError> {
    validate_non_empty("registry config name", &request.name)?;
    validate_mount_path(&request.mount_path)?;
    validate_adapter_phase(request.adapter)?;
    validate_upstream_url(&request.upstream_url, request.auth_type)?;
    validate_credential_configuration(request.auth_type, request.credential_ref)?;
    validate_cache_ttl(request.cache_ttl_seconds)?;
    Ok(())
}

fn validate_registry_update_response(request: &RegistryConfigResponse) -> Result<(), ApiError> {
    validate_non_empty("registry config name", &request.name)?;
    validate_adapter_phase(request.adapter)?;
    validate_upstream_url(&request.upstream_url, request.auth_type)?;
    validate_credential_configuration(request.auth_type, request.credential_ref)?;
    validate_cache_ttl(request.cache_ttl_seconds)?;
    Ok(())
}

fn validate_adapter_phase(adapter: RegistryAdapterDto) -> Result<(), ApiError> {
    if adapter.phase_1a_supported() {
        Ok(())
    } else {
        Err(ApiError::InvalidRequest(
            "only npm and PyPI registry adapters are enabled in Phase 1A".to_owned(),
        ))
    }
}

fn validate_cli_scan_request(request: &CliScanRequest) -> Result<PackageEcosystem, ApiError> {
    let first = request.packages.first().ok_or_else(|| {
        ApiError::InvalidRequest("cli scan request must include at least one package".to_owned())
    })?;
    let ecosystem = first.coordinate.ecosystem.clone();
    let adapter = RegistryAdapterDto::from_ecosystem(ecosystem.clone()).map_err(|_| {
        ApiError::InvalidRequest(
            "cli scan currently supports npm and pypi packages only".to_owned(),
        )
    })?;
    if !adapter.phase_1a_supported() {
        return Err(ApiError::InvalidRequest(
            "cli scan currently supports npm and pypi packages only".to_owned(),
        ));
    }
    if request
        .packages
        .iter()
        .any(|package| package.coordinate.ecosystem != ecosystem)
    {
        return Err(ApiError::InvalidRequest(
            "cli scan request packages must all share the same ecosystem".to_owned(),
        ));
    }
    Ok(ecosystem)
}

fn parse_requested_digest(value: Option<&str>) -> Result<Option<ArtifactDigest>, ApiError> {
    value.map(ArtifactDigest::sha256).transpose().map_err(|_| {
        ApiError::InvalidRequest(
            "artifact_sha256 must contain exactly 64 lowercase hexadecimal characters".to_owned(),
        )
    })
}

async fn resolve_cli_scan_registry_context(
    pool: &PgPool,
    tenant_id: Option<Uuid>,
    ecosystem: PackageEcosystem,
) -> Result<CliScanRegistryContext, ApiError> {
    let adapter = RegistryAdapterDto::from_ecosystem(ecosystem)?;
    let row = if let Some(tenant_id) = tenant_id {
        sqlx::query(
            r#"
                SELECT id, tenant_id, policy_profile_id
                FROM registry_configs
                WHERE tenant_id = $1
                  AND adapter::text = $2
                  AND enabled = TRUE
                  AND deleted_at IS NULL
                ORDER BY created_at ASC, id ASC
                LIMIT 1
                "#,
        )
        .bind(tenant_id)
        .bind(adapter.as_db())
        .fetch_optional(pool)
        .await?
    } else {
        sqlx::query(
            r#"
                SELECT id, tenant_id, policy_profile_id
                FROM registry_configs
                WHERE adapter::text = $1
                  AND enabled = TRUE
                  AND deleted_at IS NULL
                ORDER BY created_at ASC, id ASC
                LIMIT 1
                "#,
        )
        .bind(adapter.as_db())
        .fetch_optional(pool)
        .await?
    }
    .ok_or(ApiError::NotFound)?;

    Ok(CliScanRegistryContext {
        registry_config_id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        policy_profile_id: row.try_get("policy_profile_id")?,
    })
}

async fn resolve_cli_policy_context(
    pool: &PgPool,
    tenant_id: Option<Uuid>,
    policy_profile_id: Option<Uuid>,
) -> Result<CliPolicyContext, ApiError> {
    let policy_profile_id = policy_profile_id.ok_or_else(|| {
        ApiError::InvalidRequest(
            "cli GitHub Actions enrichment requires policy_profile_id to avoid ambiguous profile selection"
                .to_owned(),
        )
    })?;

    let row = if let Some(tenant_id) = tenant_id {
        sqlx::query(
            r#"
                SELECT id, tenant_id
                FROM policy_profiles
                WHERE id = $1 AND tenant_id = $2
                LIMIT 1
                "#,
        )
        .bind(policy_profile_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await?
    } else {
        sqlx::query(
            r#"
                SELECT id, tenant_id
                FROM policy_profiles
                WHERE id = $1
                LIMIT 1
                "#,
        )
        .bind(policy_profile_id)
        .fetch_optional(pool)
        .await?
    }
    .ok_or(ApiError::NotFound)?;

    Ok(CliPolicyContext {
        tenant_id: row.try_get("tenant_id")?,
        policy_profile_id: row.try_get("id")?,
    })
}

fn validate_mount_path(mount_path: &str) -> Result<(), ApiError> {
    let trimmed = mount_path.trim();
    if !trimmed.starts_with("/proxy/")
        || trimmed.ends_with('/')
        || trimmed.contains("//")
        || trimmed
            .trim_start_matches("/proxy/")
            .split('/')
            .any(|segment| {
                segment.is_empty()
                    || !segment.chars().all(|character| {
                        character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
                    })
            })
    {
        return Err(ApiError::InvalidRequest(
            "mount path must be canonical /proxy/<segment>[/segment]".to_owned(),
        ));
    }
    Ok(())
}

fn validate_upstream_url(
    upstream_url: &str,
    auth_type: CredentialAuthTypeDto,
) -> Result<(), ApiError> {
    let parsed = url::Url::parse(upstream_url.trim()).map_err(|_| {
        ApiError::InvalidRequest("upstream URL must be an absolute http(s) URL".to_owned())
    })?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(ApiError::InvalidRequest(
            "upstream URL must be http(s) and must not include credentials".to_owned(),
        ));
    }
    if parsed.scheme() == "http" && auth_type != CredentialAuthTypeDto::None {
        return Err(ApiError::InvalidRequest(
            "authenticated upstream registries must use https".to_owned(),
        ));
    }
    Ok(())
}

fn validate_credential_configuration(
    auth_type: CredentialAuthTypeDto,
    credential_ref: Option<Uuid>,
) -> Result<(), ApiError> {
    match (auth_type, credential_ref) {
        (CredentialAuthTypeDto::None, None)
        | (
            CredentialAuthTypeDto::Basic
            | CredentialAuthTypeDto::Bearer
            | CredentialAuthTypeDto::Mtls,
            Some(_),
        ) => Ok(()),
        _ => Err(ApiError::InvalidRequest(
            "auth type and credential reference are inconsistent".to_owned(),
        )),
    }
}

fn validate_cache_ttl(cache_ttl_seconds: i32) -> Result<(), ApiError> {
    if cache_ttl_seconds < 0 {
        return Err(ApiError::InvalidRequest(
            "cache TTL must be zero or positive".to_owned(),
        ));
    }
    Ok(())
}

fn validate_credential_request(
    name: &str,
    credential_type: &str,
    source: &str,
) -> Result<(), ApiError> {
    validate_non_empty("credential name", name)?;
    validate_non_empty("credential type", credential_type)?;
    if !matches!(source, "environment" | "database-runtime-override") {
        return Err(ApiError::InvalidRequest(
            "credential source must be environment or database-runtime-override".to_owned(),
        ));
    }
    Ok(())
}

fn validate_non_empty(label: &'static str, value: &str) -> Result<(), ApiError> {
    if value.trim().is_empty() {
        Err(ApiError::InvalidRequest(format!(
            "{label} must not be empty"
        )))
    } else {
        Ok(())
    }
}

fn merge_registry_update(
    current: &RegistryConfigResponse,
    patch: &UpdateRegistryConfigRequest,
) -> Result<RegistryConfigResponse, ApiError> {
    let merged = RegistryConfigResponse {
        id: current.id,
        tenant_id: current.tenant_id,
        name: patch.name.clone().unwrap_or_else(|| current.name.clone()),
        description: patch
            .description
            .clone()
            .unwrap_or_else(|| current.description.clone()),
        adapter: current.adapter,
        upstream_url: patch
            .upstream_url
            .clone()
            .unwrap_or_else(|| current.upstream_url.clone()),
        mount_path: current.mount_path.clone(),
        auth_type: patch.auth_type.unwrap_or(current.auth_type),
        credential_ref: patch.credential_ref.unwrap_or(current.credential_ref),
        mode: patch.mode.clone().unwrap_or_else(|| current.mode.clone()),
        policy_profile_id: patch.policy_profile_id.unwrap_or(current.policy_profile_id),
        cache_ttl_seconds: patch.cache_ttl_seconds.unwrap_or(current.cache_ttl_seconds),
        verify_upstream_tls: patch
            .verify_upstream_tls
            .unwrap_or(current.verify_upstream_tls),
        enabled: patch.enabled.unwrap_or(current.enabled),
        deleted_at: current.deleted_at,
        created_at: current.created_at,
        updated_at: current.updated_at,
    };
    validate_registry_update_response(&merged)?;
    Ok(merged)
}

fn registry_config_select_sql(predicate: &str) -> String {
    format!(
        r#"
        SELECT id, tenant_id, name, description, adapter::text AS adapter, upstream_url, mount_path,
               auth_type::text AS auth_type, credential_ref, mode::text AS mode, policy_profile_id,
               cache_ttl_seconds, verify_upstream_tls, enabled, deleted_at, created_at, updated_at
        FROM registry_configs
        WHERE tenant_id = $1 AND deleted_at IS NULL AND {predicate}
        "#
    )
}

fn override_response_from_row(row: &sqlx::postgres::PgRow) -> Result<OverrideResponse, ApiError> {
    Ok(OverrideResponse {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        scope: row.try_get::<SqlJson<Value>, _>("scope")?.0,
        reason: row.try_get("reason")?,
        requested_by: row.try_get("requested_by")?,
        approved_by: row.try_get("approved_by")?,
        status: row.try_get("status")?,
        expires_at: row.try_get("expires_at")?,
        created_at: row.try_get("created_at")?,
    })
}

fn registry_config_response_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<RegistryConfigResponse, ApiError> {
    Ok(RegistryConfigResponse {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        adapter: registry_adapter_from_db(row.try_get("adapter")?)?,
        upstream_url: row.try_get("upstream_url")?,
        mount_path: row.try_get("mount_path")?,
        auth_type: auth_type_from_db(row.try_get("auth_type")?)?,
        credential_ref: row.try_get("credential_ref")?,
        mode: policy_mode_from_db(row.try_get("mode")?)?,
        policy_profile_id: row.try_get("policy_profile_id")?,
        cache_ttl_seconds: row.try_get("cache_ttl_seconds")?,
        verify_upstream_tls: row.try_get("verify_upstream_tls")?,
        enabled: row.try_get("enabled")?,
        deleted_at: row.try_get("deleted_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn credential_response_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<CredentialStatusResponse, ApiError> {
    Ok(CredentialStatusResponse {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        name: row.try_get("name")?,
        credential_type: row.try_get("credential_type")?,
        source: row.try_get("source")?,
        encrypted_value_key_id: row.try_get("encrypted_value_key_id")?,
        configured: row.try_get("configured")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn openvex_document_summary_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<OpenVexDocumentSummaryResponse, ApiError> {
    Ok(OpenVexDocumentSummaryResponse {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        source: row.try_get("source")?,
        document_id: row.try_get("document_id")?,
        author: row.try_get("author")?,
        context: row.try_get("context")?,
        version: row.try_get("version")?,
        document_timestamp: row.try_get("document_timestamp")?,
        imported_at: row.try_get("imported_at")?,
        expiry_policy: OpenVexExpiryPolicyResponse {
            mode: openvex_expiry_mode_from_db(row.try_get("expiry_mode")?)?,
            expires_at: row.try_get("expires_at")?,
        },
        document_digest: row.try_get("document_digest")?,
        statement_count: row.try_get("statement_count")?,
    })
}

fn openvex_document_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<OpenVexDocumentResponse, ApiError> {
    Ok(OpenVexDocumentResponse {
        summary: openvex_document_summary_from_row(row)?,
        document: row.try_get::<SqlJson<Value>, _>("document")?.0,
    })
}

fn coordinate_summary_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<PackageCoordinateSummaryResponse, ApiError> {
    Ok(PackageCoordinateSummaryResponse {
        ecosystem: row.try_get("ecosystem")?,
        name: row.try_get("package_name")?,
        version: row.try_get("package_version")?,
        namespace: row.try_get("namespace")?,
    })
}

fn evidence_counts_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<EvidenceCountsResponse, ApiError> {
    Ok(EvidenceCountsResponse {
        static_reports: row.try_get("static_report_count")?,
        sandbox_runs: row.try_get("sandbox_run_count")?,
        ai_explanations: row.try_get("ai_explanation_count")?,
        audit_events: row.try_get("audit_event_count")?,
    })
}

fn request_timeline_bucket_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<RequestTimelineBucketResponse, ApiError> {
    Ok(RequestTimelineBucketResponse {
        bucket_start: row.try_get("bucket_start")?,
        allow: row.try_get("allow_count")?,
        warn: row.try_get("warn_count")?,
        quarantine: row.try_get("quarantine_count")?,
        block: row.try_get("block_count")?,
    })
}

impl PolicyDecisionCountsResponse {
    fn record(&mut self, decision: &PolicyDecision) {
        match decision {
            PolicyDecision::Allow => self.allow += 1,
            PolicyDecision::AllowWithWarning => self.allow_with_warning += 1,
            PolicyDecision::QuarantinePendingAnalysis => self.quarantine_pending_analysis += 1,
            PolicyDecision::BlockKnownMalicious => self.block_known_malicious += 1,
            PolicyDecision::BlockPolicyViolation => self.block_policy_violation += 1,
            PolicyDecision::RequireHitlApproval => self.require_hitl_approval += 1,
            PolicyDecision::FallbackToApprovedCandidate => {
                self.fallback_to_approved_candidate += 1;
            }
        }
    }
}

fn policy_profile_summary_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<PolicyProfileSummaryResponse, ApiError> {
    Ok(PolicyProfileSummaryResponse {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        name: row.try_get("name")?,
        mode: policy_mode_from_db(row.try_get("mode")?)?,
        latest_version_id: row.try_get("latest_version_id")?,
        latest_version: row.try_get("latest_version")?,
        latest_effective_at: row.try_get("latest_effective_at")?,
        created_at: row.try_get("created_at")?,
        request_count_last_30_days: row.try_get("request_count_last_30_days")?,
    })
}

fn override_queue_item_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<OverrideQueueItemResponse, ApiError> {
    Ok(OverrideQueueItemResponse {
        id: row.try_get("id")?,
        scope: row.try_get::<SqlJson<Value>, _>("scope")?.0,
        reason: row.try_get("reason")?,
        requested_by: row.try_get("requested_by")?,
        requested_by_display: row.try_get("requested_by_display")?,
        approved_by: row.try_get("approved_by")?,
        approved_by_display: row.try_get("approved_by_display")?,
        status: row.try_get("status")?,
        expires_at: row.try_get("expires_at")?,
        created_at: row.try_get("created_at")?,
    })
}

fn quarantine_queue_item_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<QuarantineQueueItemResponse, ApiError> {
    Ok(QuarantineQueueItemResponse {
        analysis_job_id: row.try_get("analysis_job_id")?,
        artifact_id: row.try_get("artifact_id")?,
        trace_id: row.try_get("trace_id")?,
        coordinate: coordinate_summary_from_row(row)?,
        artifact_sha256: row.try_get("artifact_sha256")?,
        recommended_action: row.try_get("recommended_action")?,
        confidence: row.try_get("confidence")?,
        requires_hitl: row.try_get("requires_hitl")?,
        summary: row.try_get::<SqlJson<Value>, _>("summary")?.0,
        evidence_counts: evidence_counts_from_row(row)?,
        created_at: row.try_get("created_at")?,
    })
}

fn audit_event_from_row(row: &sqlx::postgres::PgRow) -> Result<AuditEvent, ApiError> {
    let metadata = row.try_get::<SqlJson<Metadata>, _>("metadata")?.0;
    validate_audit_metadata(&metadata).map_err(ApiError::InvalidRequest)?;
    Ok(AuditEvent {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        actor: row.try_get("actor")?,
        action: row.try_get("action")?,
        resource: row.try_get("resource")?,
        trace_id: row.try_get("trace_id")?,
        occurred_at: row.try_get("occurred_at")?,
        metadata,
    })
}

fn registry_adapter_from_db(value: String) -> Result<RegistryAdapterDto, ApiError> {
    match value.as_str() {
        "npm" => Ok(RegistryAdapterDto::Npm),
        "pypi" => Ok(RegistryAdapterDto::Pypi),
        "cargo" => Ok(RegistryAdapterDto::Cargo),
        "maven" => Ok(RegistryAdapterDto::Maven),
        "docker-oci" => Ok(RegistryAdapterDto::DockerOci),
        "generic-http" => Ok(RegistryAdapterDto::GenericHttp),
        _ => Err(ApiError::InvalidRequest(
            "invalid registry adapter".to_owned(),
        )),
    }
}

fn auth_type_from_db(value: String) -> Result<CredentialAuthTypeDto, ApiError> {
    match value.as_str() {
        "none" => Ok(CredentialAuthTypeDto::None),
        "basic" => Ok(CredentialAuthTypeDto::Basic),
        "bearer" => Ok(CredentialAuthTypeDto::Bearer),
        "mtls" => Ok(CredentialAuthTypeDto::Mtls),
        _ => Err(ApiError::InvalidRequest(
            "invalid credential auth type".to_owned(),
        )),
    }
}

fn policy_mode_from_db(value: String) -> Result<PolicyMode, ApiError> {
    match value.as_str() {
        "shadow" => Ok(PolicyMode::Shadow),
        "warn" => Ok(PolicyMode::Warn),
        "enforce" => Ok(PolicyMode::Enforce),
        _ => Err(ApiError::InvalidRequest("invalid policy mode".to_owned())),
    }
}

fn policy_mode_db_value(mode: &PolicyMode) -> &'static str {
    match mode {
        PolicyMode::Shadow => "shadow",
        PolicyMode::Warn => "warn",
        PolicyMode::Enforce => "enforce",
    }
}

fn openvex_expiry_mode_from_db(value: String) -> Result<OpenVexExpiryMode, ApiError> {
    match value.as_str() {
        "never" => Ok(OpenVexExpiryMode::Never),
        "expires_at" => Ok(OpenVexExpiryMode::ExpiresAt),
        _ => Err(ApiError::InvalidRequest(
            "invalid OpenVEX expiry mode in stored data".to_owned(),
        )),
    }
}

fn policy_decision_from_db(value: String) -> Result<PolicyDecision, ApiError> {
    match value.as_str() {
        "ALLOW" => Ok(PolicyDecision::Allow),
        "ALLOW_WITH_WARNING" => Ok(PolicyDecision::AllowWithWarning),
        "QUARANTINE_PENDING_ANALYSIS" => Ok(PolicyDecision::QuarantinePendingAnalysis),
        "BLOCK_KNOWN_MALICIOUS" => Ok(PolicyDecision::BlockKnownMalicious),
        "BLOCK_POLICY_VIOLATION" => Ok(PolicyDecision::BlockPolicyViolation),
        "REQUIRE_HITL_APPROVAL" => Ok(PolicyDecision::RequireHitlApproval),
        "FALLBACK_TO_APPROVED_CANDIDATE" => Ok(PolicyDecision::FallbackToApprovedCandidate),
        _ => Err(ApiError::InvalidRequest(
            "invalid policy decision value in stored replay data".to_owned(),
        )),
    }
}

fn package_request_kind_from_db(value: String) -> Result<PackageRequestKind, ApiError> {
    match value.as_str() {
        "metadata" => Ok(PackageRequestKind::Metadata),
        "artifact" => Ok(PackageRequestKind::Artifact),
        _ => Err(ApiError::InvalidRequest(
            "invalid package request kind in stored replay data".to_owned(),
        )),
    }
}

fn package_ecosystem_from_db(value: String) -> Result<PackageEcosystem, ApiError> {
    match value.as_str() {
        "npm" => Ok(PackageEcosystem::Npm),
        "pypi" => Ok(PackageEcosystem::Pypi),
        "cargo" => Ok(PackageEcosystem::Cargo),
        "maven" => Ok(PackageEcosystem::Maven),
        "docker-oci" => Ok(PackageEcosystem::DockerOci),
        "generic-http" => Ok(PackageEcosystem::GenericHttp),
        _ => Err(ApiError::InvalidRequest(
            "invalid package ecosystem in stored replay data".to_owned(),
        )),
    }
}

fn string_list_from_json_value(value: Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn actor_id_from_headers(headers: &HeaderMap) -> Option<Uuid> {
    headers
        .get(ACTOR_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok())
}

fn trace_id(headers: &HeaderMap) -> String {
    headers
        .get(TRACE_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("api-{}", Uuid::now_v7()))
}

fn actor_label(actor_id: Uuid) -> String {
    format!("user/{actor_id}")
}

fn actor_user_id_from_label(actor: &str) -> Option<Uuid> {
    actor
        .strip_prefix("user/")
        .and_then(|value| Uuid::parse_str(value).ok())
}

fn configured_auth_mode() -> AuthMode {
    match std::env::var("AEGISCUDO_AUTH_MODE")
        .ok()
        .as_deref()
        .map(str::trim)
    {
        Some("oidc") => AuthMode::Oidc,
        Some("saml") => AuthMode::Saml,
        _ => AuthMode::MockOidc,
    }
}

fn configured_local_auth_tenant_id() -> Uuid {
    std::env::var("AEGISCUDO_AUTH_TENANT_ID")
        .ok()
        .and_then(|value| Uuid::parse_str(value.trim()).ok())
        .unwrap_or_else(|| {
            Uuid::parse_str(DEFAULT_LOCAL_AUTH_TENANT_ID)
                .expect("default local auth tenant id must be a UUID")
        })
}

fn ensure_mock_auth_mode(auth_mode: AuthMode) -> Result<(), ApiError> {
    if auth_mode.supports_mock_identities() {
        Ok(())
    } else {
        Err(ApiError::UnsupportedAuthMode(auth_mode))
    }
}

fn mock_identity_id_for_email(email: &str) -> Option<&'static str> {
    LOCAL_MOCK_IDENTITIES
        .iter()
        .find(|identity| identity.email.eq_ignore_ascii_case(email))
        .map(|identity| identity.id)
}

fn mock_identity_email(identity_id: &str) -> Option<&'static str> {
    LOCAL_MOCK_IDENTITIES
        .iter()
        .find(|identity| identity.id == identity_id)
        .map(|identity| identity.email)
}

async fn load_auth_subject_by_user_id(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Option<AuthSubjectResponse>, sqlx::Error> {
    let row = sqlx::query(
        r#"
        SELECT
            u.id,
            u.tenant_id,
            u.display_name,
            u.email,
            COALESCE(
                array_agg(DISTINCT r.name) FILTER (WHERE r.name IS NOT NULL),
                ARRAY[]::text[]
            ) AS roles
        FROM users u
        LEFT JOIN user_roles ur ON ur.user_id = u.id
        LEFT JOIN roles r ON r.id = ur.role_id AND r.tenant_id = u.tenant_id
        WHERE u.id = $1
        GROUP BY u.id, u.tenant_id, u.display_name, u.email
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(auth_subject_from_row))
}

async fn load_mock_identity_subjects(
    pool: &PgPool,
    tenant_id: Uuid,
) -> Result<Vec<AuthSubjectResponse>, sqlx::Error> {
    let emails: Vec<&str> = LOCAL_MOCK_IDENTITIES
        .iter()
        .map(|identity| identity.email)
        .collect();
    let rows = sqlx::query(
        r#"
        SELECT
            u.id,
            u.tenant_id,
            u.display_name,
            u.email,
            COALESCE(
                array_agg(DISTINCT r.name) FILTER (WHERE r.name IS NOT NULL),
                ARRAY[]::text[]
            ) AS roles
        FROM users u
        LEFT JOIN user_roles ur ON ur.user_id = u.id
        LEFT JOIN roles r ON r.id = ur.role_id AND r.tenant_id = u.tenant_id
        WHERE u.tenant_id = $1
          AND u.email = ANY($2)
        GROUP BY u.id, u.tenant_id, u.display_name, u.email
        "#,
    )
    .bind(tenant_id)
    .bind(&emails)
    .fetch_all(pool)
    .await?;

    let identities_by_email: HashMap<String, AuthSubjectResponse> = rows
        .into_iter()
        .map(auth_subject_from_row)
        .map(|subject| (subject.email.to_ascii_lowercase(), subject))
        .collect();

    Ok(LOCAL_MOCK_IDENTITIES
        .iter()
        .filter_map(|identity| {
            identities_by_email
                .get(&identity.email.to_ascii_lowercase())
                .cloned()
        })
        .collect())
}

async fn load_mock_identity_subject(
    pool: &PgPool,
    tenant_id: Uuid,
    identity_id: &str,
) -> Result<Option<AuthSubjectResponse>, sqlx::Error> {
    let Some(email) = mock_identity_email(identity_id) else {
        return Ok(None);
    };

    let row = sqlx::query(
        r#"
        SELECT
            u.id,
            u.tenant_id,
            u.display_name,
            u.email,
            COALESCE(
                array_agg(DISTINCT r.name) FILTER (WHERE r.name IS NOT NULL),
                ARRAY[]::text[]
            ) AS roles
        FROM users u
        LEFT JOIN user_roles ur ON ur.user_id = u.id
        LEFT JOIN roles r ON r.id = ur.role_id AND r.tenant_id = u.tenant_id
        WHERE u.tenant_id = $1
          AND u.email = $2
        GROUP BY u.id, u.tenant_id, u.display_name, u.email
        "#,
    )
    .bind(tenant_id)
    .bind(email)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(auth_subject_from_row))
}

fn auth_subject_from_row(row: sqlx::postgres::PgRow) -> AuthSubjectResponse {
    let email: String = row.try_get("email").unwrap();
    AuthSubjectResponse {
        user_id: row.try_get("id").unwrap(),
        tenant_id: row.try_get("tenant_id").unwrap(),
        display_name: row.try_get("display_name").unwrap(),
        email,
        roles: row.try_get("roles").unwrap_or_default(),
        mock_identity_id: mock_identity_id_for_email(&row.try_get::<String, _>("email").unwrap())
            .map(str::to_owned),
    }
}

fn map_sql_conflict(error: sqlx::Error) -> ApiError {
    if matches!(&error, sqlx::Error::Database(database_error) if database_error.is_unique_violation() || database_error.is_foreign_key_violation() || database_error.is_check_violation())
    {
        ApiError::Conflict
    } else {
        ApiError::Database(error)
    }
}

fn default_true() -> bool {
    true
}

fn default_cache_ttl_seconds() -> i32 {
    300
}

fn default_policy_simulation_lookback_days() -> i32 {
    30
}

fn default_policy_simulation_limit() -> i32 {
    50
}

fn default_auth_type() -> CredentialAuthTypeDto {
    CredentialAuthTypeDto::None
}

fn default_credential_source() -> String {
    "environment".to_owned()
}

fn default_openvex_expiry_policy() -> OpenVexExpiryPolicyRequest {
    OpenVexExpiryPolicyRequest {
        mode: OpenVexExpiryMode::Never,
        expires_at: None,
    }
}

fn validate_openvex_request(
    request: &CreateOpenVexDocumentRequest,
) -> Result<ValidatedOpenVexDocument, ApiError> {
    if request.source.trim().is_empty() {
        return Err(ApiError::InvalidRequest(
            "openvex source must not be blank".to_owned(),
        ));
    }
    validate_openvex_expiry_policy(&request.expiry_policy)?;

    let document = request
        .document
        .as_object()
        .ok_or(ApiError::InvalidRequest(
            "openvex document must be a JSON object".to_owned(),
        ))?;
    let context = required_non_empty_json_string(document.get("@context"), "document.@context")?;
    if context != "https://openvex.dev/ns/v0.2.0" {
        return Err(ApiError::InvalidRequest(
            "document.@context must be https://openvex.dev/ns/v0.2.0".to_owned(),
        ));
    }

    let document_id = required_non_empty_json_string(document.get("@id"), "document.@id")?;
    let author = required_non_empty_json_string(document.get("author"), "document.author")?;
    let version = document
        .get("version")
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .ok_or(ApiError::InvalidRequest(
            "document.version must be a positive integer".to_owned(),
        ))?;
    let document_timestamp =
        parse_required_rfc3339_timestamp(document.get("timestamp"), "document.timestamp")?;

    let statements =
        document
            .get("statements")
            .and_then(Value::as_array)
            .ok_or(ApiError::InvalidRequest(
                "document.statements must be an array".to_owned(),
            ))?;
    if statements.is_empty() {
        return Err(ApiError::InvalidRequest(
            "document.statements must contain at least one statement".to_owned(),
        ));
    }

    let mut normalized_statements = Vec::new();
    for (index, statement) in statements.iter().enumerate() {
        let statement_path = format!("document.statements[{index}]");
        let statement_object = statement
            .as_object()
            .ok_or(ApiError::InvalidRequest(format!(
                "{statement_path} must be an object"
            )))?;

        let vulnerability_id = statement_object
            .get("vulnerability")
            .and_then(Value::as_object)
            .ok_or(ApiError::InvalidRequest(format!(
                "{statement_path}.vulnerability must be an object"
            )))
            .and_then(|vulnerability| {
                required_non_empty_json_string(
                    vulnerability.get("name"),
                    &format!("{statement_path}.vulnerability.name"),
                )
            })?;

        let status = required_non_empty_json_string(
            statement_object.get("status"),
            &format!("{statement_path}.status"),
        )?;
        validate_openvex_status(&status, &format!("{statement_path}.status"))?;

        let products = statement_object
            .get("products")
            .and_then(Value::as_array)
            .ok_or(ApiError::InvalidRequest(format!(
                "{statement_path}.products must be an array"
            )))?;
        if products.is_empty() {
            return Err(ApiError::InvalidRequest(format!(
                "{statement_path}.products must contain at least one product"
            )));
        }

        let justification = optional_non_empty_json_string(
            statement_object.get("justification"),
            &format!("{statement_path}.justification"),
        )?;
        if let Some(value) = justification.as_deref() {
            validate_openvex_justification(value, &format!("{statement_path}.justification"))?;
        }
        let impact_statement = optional_non_empty_json_string(
            statement_object.get("impact_statement"),
            &format!("{statement_path}.impact_statement"),
        )?;
        let action_statement = optional_non_empty_json_string(
            statement_object.get("action_statement"),
            &format!("{statement_path}.action_statement"),
        )?;
        let statement_timestamp = parse_optional_rfc3339_timestamp(
            statement_object.get("timestamp"),
            &format!("{statement_path}.timestamp"),
        )?;
        validate_openvex_statement_requirements(
            &status,
            justification.as_deref(),
            impact_statement.as_deref(),
            action_statement.as_deref(),
            &statement_path,
        )?;

        let mut seen_product_ids = HashSet::new();

        for (product_index, product) in products.iter().enumerate() {
            let product_path = format!("{statement_path}.products[{product_index}]");
            let product_object = product.as_object().ok_or(ApiError::InvalidRequest(format!(
                "{product_path} must be an object"
            )))?;
            let product_id = required_non_empty_json_string(
                product_object.get("@id"),
                &format!("{product_path}.@id"),
            )?;
            if !seen_product_ids.insert(product_id.clone()) {
                return Err(ApiError::InvalidRequest(format!(
                    "{product_path}.@id must be unique within the statement"
                )));
            }
            normalized_statements.push(ValidatedOpenVexStatement {
                statement_index: index as i32,
                vulnerability_id: vulnerability_id.clone(),
                status: status.clone(),
                product_id,
                justification: justification.clone(),
                impact_statement: impact_statement.clone(),
                action_statement: action_statement.clone(),
                statement_timestamp,
                raw_statement: statement.clone(),
            });
        }
    }

    Ok(ValidatedOpenVexDocument {
        context,
        document_id,
        author,
        version,
        document_timestamp,
        statement_count: statements.len() as i32,
        statements: normalized_statements,
    })
}

fn validate_openvex_expiry_policy(policy: &OpenVexExpiryPolicyRequest) -> Result<(), ApiError> {
    match policy.mode {
        OpenVexExpiryMode::Never if policy.expires_at.is_none() => Ok(()),
        OpenVexExpiryMode::Never => Err(ApiError::InvalidRequest(
            "expiry_policy.expires_at must be omitted when mode is never".to_owned(),
        )),
        OpenVexExpiryMode::ExpiresAt if policy.expires_at.is_some() => Ok(()),
        OpenVexExpiryMode::ExpiresAt => Err(ApiError::InvalidRequest(
            "expiry_policy.expires_at is required when mode is expires-at".to_owned(),
        )),
    }
}

fn validate_openvex_status(status: &str, field: &str) -> Result<(), ApiError> {
    match status {
        "affected" | "fixed" | "not_affected" | "under_investigation" => Ok(()),
        _ => Err(ApiError::InvalidRequest(format!(
            "{field} must be one of affected, fixed, not_affected, under_investigation"
        ))),
    }
}

fn validate_openvex_justification(justification: &str, field: &str) -> Result<(), ApiError> {
    match justification {
        "component_not_present"
        | "vulnerable_code_not_present"
        | "vulnerable_code_not_in_execute_path"
        | "vulnerable_code_cannot_be_controlled_by_adversary"
        | "inline_mitigations_already_exist" => Ok(()),
        _ => Err(ApiError::InvalidRequest(format!(
            "{field} must be one of component_not_present, vulnerable_code_not_present, vulnerable_code_not_in_execute_path, vulnerable_code_cannot_be_controlled_by_adversary, inline_mitigations_already_exist"
        ))),
    }
}

fn validate_openvex_statement_requirements(
    status: &str,
    justification: Option<&str>,
    impact_statement: Option<&str>,
    action_statement: Option<&str>,
    statement_path: &str,
) -> Result<(), ApiError> {
    match status {
        "not_affected" if justification.is_none() && impact_statement.is_none() => {
            Err(ApiError::InvalidRequest(format!(
                "{statement_path} with status not_affected must include justification or impact_statement"
            )))
        }
        "affected" if action_statement.is_none() => Err(ApiError::InvalidRequest(format!(
            "{statement_path} with status affected must include action_statement"
        ))),
        _ => Ok(()),
    }
}

fn required_non_empty_json_string(value: Option<&Value>, field: &str) -> Result<String, ApiError> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(ApiError::InvalidRequest(format!(
            "{field} must be a non-empty string"
        )))
}

fn optional_non_empty_json_string(
    value: Option<&Value>,
    field: &str,
) -> Result<Option<String>, ApiError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(_) => required_non_empty_json_string(value, field).map(Some),
    }
}

fn parse_required_rfc3339_timestamp(
    value: Option<&Value>,
    field: &str,
) -> Result<DateTime<Utc>, ApiError> {
    let raw = required_non_empty_json_string(value, field)?;
    DateTime::parse_from_rfc3339(&raw)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| ApiError::InvalidRequest(format!("{field} must be an RFC 3339 timestamp")))
}

fn parse_optional_rfc3339_timestamp(
    value: Option<&Value>,
    field: &str,
) -> Result<Option<DateTime<Utc>>, ApiError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(_) => parse_required_rfc3339_timestamp(value, field).map(Some),
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validate_policy_simulation_request(request: &PolicySimulationRequest) -> Result<(), ApiError> {
    if !(1..=30).contains(&request.lookback_days) {
        return Err(ApiError::InvalidRequest(
            "policy simulation lookback_days must be between 1 and 30".to_owned(),
        ));
    }
    if !(1..=200).contains(&request.limit) {
        return Err(ApiError::InvalidRequest(
            "policy simulation limit must be between 1 and 200".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegiscudo_core::FeedState;
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use chrono::TimeZone;
    use serde::de::DeserializeOwned;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    const TEST_DATABASE_URL: &str = "postgres://aegiscudo:aegiscudo@localhost:15432/aegiscudo";

    struct InvestigationRouteFixture {
        tenant_id: Uuid,
        other_tenant_id: Uuid,
        admin_user_id: Uuid,
        developer_user_id: Uuid,
        admin_role_id: Uuid,
        other_admin_user_id: Uuid,
        other_admin_role_id: Uuid,
        policy_profile_id: Uuid,
        simulated_policy_profile_id: Uuid,
        other_policy_profile_id: Uuid,
        policy_version_id: Uuid,
        simulated_policy_version_id: Uuid,
        other_policy_version_id: Uuid,
        full_artifact_id: Uuid,
        degraded_artifact_id: Uuid,
        allow_artifact_id: Uuid,
        other_artifact_id: Uuid,
        full_job_id: Uuid,
        degraded_job_id: Uuid,
        allow_job_id: Uuid,
        other_job_id: Uuid,
        pending_override_id: Uuid,
        approved_override_id: Uuid,
        denied_override_id: Uuid,
        other_override_id: Uuid,
    }

    struct AuthRouteFixture {
        tenant_id: Uuid,
        platform_admin_user_id: Uuid,
        developer_user_id: Uuid,
        security_specialist_user_id: Uuid,
        ciso_auditor_user_id: Uuid,
        admin_role_id: Uuid,
        developer_role_id: Uuid,
        security_role_id: Uuid,
        auditor_role_id: Uuid,
    }

    impl AuthRouteFixture {
        async fn insert(pool: &PgPool) -> Self {
            let tenant_id = Uuid::now_v7();
            let platform_admin_user_id = Uuid::now_v7();
            let developer_user_id = Uuid::now_v7();
            let security_specialist_user_id = Uuid::now_v7();
            let ciso_auditor_user_id = Uuid::now_v7();
            let admin_role_id = Uuid::now_v7();
            let developer_role_id = Uuid::now_v7();
            let security_role_id = Uuid::now_v7();
            let auditor_role_id = Uuid::now_v7();

            sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
                .bind(tenant_id)
                .bind(format!("auth-tenant-{tenant_id}"))
                .execute(pool)
                .await
                .expect("insert auth tenant");

            sqlx::query(
                r#"
                INSERT INTO users (id, tenant_id, email, display_name)
                VALUES
                    ($1, $2, 'local-admin@aegiscudo.invalid', 'Local Admin'),
                    ($3, $4, 'dev@aegiscudo.invalid', 'Developer Persona'),
                    ($5, $6, 'security@aegiscudo.invalid', 'Security Specialist'),
                    ($7, $8, 'ciso@aegiscudo.invalid', 'CISO Auditor')
                "#,
            )
            .bind(platform_admin_user_id)
            .bind(tenant_id)
            .bind(developer_user_id)
            .bind(tenant_id)
            .bind(security_specialist_user_id)
            .bind(tenant_id)
            .bind(ciso_auditor_user_id)
            .bind(tenant_id)
            .execute(pool)
            .await
            .expect("insert auth users");

            sqlx::query(
                r#"
                INSERT INTO roles (id, tenant_id, name)
                VALUES
                    ($1, $2, 'admin'),
                    ($3, $4, 'developer'),
                    ($5, $6, 'security-analyst'),
                    ($7, $8, 'auditor')
                "#,
            )
            .bind(admin_role_id)
            .bind(tenant_id)
            .bind(developer_role_id)
            .bind(tenant_id)
            .bind(security_role_id)
            .bind(tenant_id)
            .bind(auditor_role_id)
            .bind(tenant_id)
            .execute(pool)
            .await
            .expect("insert auth roles");

            sqlx::query(
                r#"
                INSERT INTO user_roles (user_id, role_id)
                VALUES
                    ($1, $2),
                    ($3, $4),
                    ($5, $6),
                    ($7, $8)
                "#,
            )
            .bind(platform_admin_user_id)
            .bind(admin_role_id)
            .bind(developer_user_id)
            .bind(developer_role_id)
            .bind(security_specialist_user_id)
            .bind(security_role_id)
            .bind(ciso_auditor_user_id)
            .bind(auditor_role_id)
            .execute(pool)
            .await
            .expect("insert auth user roles");

            Self {
                tenant_id,
                platform_admin_user_id,
                developer_user_id,
                security_specialist_user_id,
                ciso_auditor_user_id,
                admin_role_id,
                developer_role_id,
                security_role_id,
                auditor_role_id,
            }
        }

        async fn cleanup(&self, pool: &PgPool) {
            let user_ids = [
                self.platform_admin_user_id,
                self.developer_user_id,
                self.security_specialist_user_id,
                self.ciso_auditor_user_id,
            ];
            let role_ids = [
                self.admin_role_id,
                self.developer_role_id,
                self.security_role_id,
                self.auditor_role_id,
            ];

            sqlx::query("DELETE FROM user_roles WHERE user_id = ANY($1)")
                .bind(&user_ids[..])
                .execute(pool)
                .await
                .expect("delete auth user roles");
            sqlx::query("DELETE FROM roles WHERE id = ANY($1)")
                .bind(&role_ids[..])
                .execute(pool)
                .await
                .expect("delete auth roles");
            sqlx::query("DELETE FROM users WHERE id = ANY($1)")
                .bind(&user_ids[..])
                .execute(pool)
                .await
                .expect("delete auth users");
            sqlx::query("DELETE FROM tenants WHERE id = $1")
                .bind(self.tenant_id)
                .execute(pool)
                .await
                .expect("delete auth tenant");
        }
    }

    impl InvestigationRouteFixture {
        async fn insert(pool: &PgPool) -> Self {
            let tenant_id = Uuid::now_v7();
            let other_tenant_id = Uuid::now_v7();
            let admin_user_id = Uuid::now_v7();
            let developer_user_id = Uuid::now_v7();
            let admin_role_id = Uuid::now_v7();
            let other_admin_user_id = Uuid::now_v7();
            let other_admin_role_id = Uuid::now_v7();
            let policy_profile_id = Uuid::now_v7();
            let simulated_policy_profile_id = Uuid::now_v7();
            let other_policy_profile_id = Uuid::now_v7();
            let policy_version_id = Uuid::now_v7();
            let simulated_policy_version_id = Uuid::now_v7();
            let other_policy_version_id = Uuid::now_v7();
            let full_artifact_id = Uuid::now_v7();
            let degraded_artifact_id = Uuid::now_v7();
            let allow_artifact_id = Uuid::now_v7();
            let other_artifact_id = Uuid::now_v7();
            let full_job_id = Uuid::now_v7();
            let degraded_job_id = Uuid::now_v7();
            let allow_job_id = Uuid::now_v7();
            let other_job_id = Uuid::now_v7();
            let pending_override_id = Uuid::now_v7();
            let approved_override_id = Uuid::now_v7();
            let denied_override_id = Uuid::now_v7();
            let other_override_id = Uuid::now_v7();

            sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2), ($3, $4)")
                .bind(tenant_id)
                .bind(format!("integration-tenant-{tenant_id}"))
                .bind(other_tenant_id)
                .bind(format!("integration-tenant-{other_tenant_id}"))
                .execute(pool)
                .await
                .expect("insert tenants");

            sqlx::query(
                r#"
                INSERT INTO users (id, tenant_id, email, display_name)
                VALUES
                    ($1, $2, $3, $4),
                    ($5, $6, $7, $8),
                    ($9, $10, $11, $12)
                "#,
            )
            .bind(admin_user_id)
            .bind(tenant_id)
            .bind(format!("admin-{admin_user_id}@example.invalid"))
            .bind("Fixture Admin")
            .bind(developer_user_id)
            .bind(tenant_id)
            .bind(format!("developer-{developer_user_id}@example.invalid"))
            .bind("Fixture Developer")
            .bind(other_admin_user_id)
            .bind(other_tenant_id)
            .bind(format!("admin-{other_admin_user_id}@example.invalid"))
            .bind("Other Fixture Admin")
            .execute(pool)
            .await
            .expect("insert users");

            sqlx::query(
                r#"
                INSERT INTO roles (id, tenant_id, name)
                VALUES ($1, $2, 'admin'), ($3, $4, 'admin')
                "#,
            )
            .bind(admin_role_id)
            .bind(tenant_id)
            .bind(other_admin_role_id)
            .bind(other_tenant_id)
            .execute(pool)
            .await
            .expect("insert roles");

            sqlx::query(
                r#"
                INSERT INTO user_roles (user_id, role_id)
                VALUES ($1, $2), ($3, $4)
                "#,
            )
            .bind(admin_user_id)
            .bind(admin_role_id)
            .bind(other_admin_user_id)
            .bind(other_admin_role_id)
            .execute(pool)
            .await
            .expect("insert user roles");

            sqlx::query(
                r#"
                INSERT INTO policy_profiles (id, tenant_id, name, mode)
                VALUES
                    ($1, $2, $3, 'enforce'),
                    ($4, $5, $6, 'shadow'),
                    ($7, $8, $9, 'enforce')
                "#,
            )
            .bind(policy_profile_id)
            .bind(tenant_id)
            .bind(format!("integration-profile-{policy_profile_id}"))
            .bind(simulated_policy_profile_id)
            .bind(tenant_id)
            .bind(format!("simulation-profile-{simulated_policy_profile_id}"))
            .bind(other_policy_profile_id)
            .bind(other_tenant_id)
            .bind(format!("integration-profile-{other_policy_profile_id}"))
            .execute(pool)
            .await
            .expect("insert policy profiles");

            sqlx::query(
                r#"
                INSERT INTO policy_versions (
                    id, tenant_id, policy_profile_id, version, immutable_rule_hash, document, effective_at
                )
                VALUES
                    ($1, $2, $3, 'v1', $4, $5, $6),
                    ($7, $8, $9, 'v2', $10, $11, $12),
                    ($13, $14, $15, 'v1', $16, $17, $18)
                "#,
            )
            .bind(policy_version_id)
            .bind(tenant_id)
            .bind(policy_profile_id)
            .bind(repeat_hex('a'))
            .bind(json!({ "version": "v1", "mode": "enforce" }))
            .bind(ts(2026, 5, 5, 10, 0, 0))
            .bind(simulated_policy_version_id)
            .bind(tenant_id)
            .bind(simulated_policy_profile_id)
            .bind(repeat_hex('c'))
            .bind(json!({ "version": "v2", "mode": "shadow" }))
            .bind(ts(2026, 5, 6, 10, 0, 0))
            .bind(other_policy_version_id)
            .bind(other_tenant_id)
            .bind(other_policy_profile_id)
            .bind(repeat_hex('b'))
            .bind(json!({ "version": "v1", "mode": "enforce" }))
            .bind(ts(2026, 5, 5, 10, 0, 0))
            .execute(pool)
            .await
            .expect("insert policy versions");

            sqlx::query(
                r#"
                INSERT INTO artifacts (
                    id, tenant_id, ecosystem, namespace, package_name, package_version, sha256, size_bytes, storage_uri, created_at
                )
                VALUES
                    ($1, $2, 'npm', NULL, 'fresh-postinstall', '0.1.0', $3, 1234, 's3://fixture/full', $4),
                    ($5, $6, 'pypi', NULL, 'requestz', '99.0.0', $7, 4321, 's3://fixture/degraded', $8),
                    ($9, $10, 'npm', NULL, 'left-pad', '1.3.0', $11, 512, 's3://fixture/allow', $12),
                    ($13, $14, 'npm', NULL, 'other-tenant', '9.9.9', $15, 256, 's3://fixture/other', $16)
                "#,
            )
            .bind(full_artifact_id)
            .bind(tenant_id)
            .bind(repeat_hex('1'))
            .bind(ts(2026, 5, 5, 10, 5, 0))
            .bind(degraded_artifact_id)
            .bind(tenant_id)
            .bind(repeat_hex('2'))
            .bind(ts(2026, 5, 5, 10, 6, 0))
            .bind(allow_artifact_id)
            .bind(tenant_id)
            .bind(repeat_hex('3'))
            .bind(ts(2026, 5, 5, 10, 7, 0))
            .bind(other_artifact_id)
            .bind(other_tenant_id)
            .bind(repeat_hex('4'))
            .bind(ts(2026, 5, 5, 10, 8, 0))
            .execute(pool)
            .await
            .expect("insert artifacts");

            sqlx::query(
                r#"
                INSERT INTO analysis_jobs (
                    id, tenant_id, artifact_id, policy_version_id, state, retry_count, trace_id,
                    ecosystem, namespace, package_name, package_version, artifact_sha256,
                    created_at, updated_at
                )
                VALUES
                    ($1, $2, $3, $4, 'completed', 0, 'trace-quarantine-full', 'npm', NULL, 'fresh-postinstall', '0.1.0', $5, $6, $6),
                    ($7, $8, $9, $10, 'completed', 0, 'trace-hitl-empty', 'pypi', NULL, 'requestz', '99.0.0', $11, $12, $12),
                    ($13, $14, $15, $16, 'completed', 0, 'trace-allow-hidden', 'npm', NULL, 'left-pad', '1.3.0', $17, $18, $18),
                    ($19, $20, $21, $22, 'completed', 0, 'trace-other-tenant', 'npm', NULL, 'other-tenant', '9.9.9', $23, $24, $24)
                "#,
            )
            .bind(full_job_id)
            .bind(tenant_id)
            .bind(full_artifact_id)
            .bind(policy_version_id)
            .bind(repeat_hex('1'))
            .bind(ts(2026, 5, 5, 10, 15, 0))
            .bind(degraded_job_id)
            .bind(tenant_id)
            .bind(degraded_artifact_id)
            .bind(policy_version_id)
            .bind(repeat_hex('2'))
            .bind(ts(2026, 5, 5, 10, 30, 0))
            .bind(allow_job_id)
            .bind(tenant_id)
            .bind(allow_artifact_id)
            .bind(policy_version_id)
            .bind(repeat_hex('3'))
            .bind(ts(2026, 5, 5, 10, 20, 0))
            .bind(other_job_id)
            .bind(other_tenant_id)
            .bind(other_artifact_id)
            .bind(other_policy_version_id)
            .bind(repeat_hex('4'))
            .bind(ts(2026, 5, 5, 10, 40, 0))
            .execute(pool)
            .await
            .expect("insert analysis jobs");

            sqlx::query(
                r#"
                INSERT INTO analysis_summaries (
                    analysis_job_id, artifact_id, recommended_action, confidence, requires_hitl, summary, created_at
                )
                VALUES
                    ($1, $2, 'QUARANTINE_PENDING_ANALYSIS', 'medium', true, $3, $4),
                    ($5, $6, 'REQUIRE_HITL_APPROVAL', 'high', true, $7, $8),
                    ($9, $10, 'ALLOW', 'low', false, $11, $12),
                    ($13, $14, 'BLOCK_POLICY_VIOLATION', 'high', false, $15, $16)
                "#,
            )
            .bind(full_job_id)
            .bind(full_artifact_id)
            .bind(json!({
                "evidence": {
                    "static_indicator_count": 2,
                    "sandbox_event_count": 2,
                    "malware_match_count": 0
                },
                "limitations": ["sandbox telemetry still requires human review"],
                "ai_observed_behavior": ["Lifecycle script was detected during static inspection."],
                "ai_inference": ["Package remains quarantined pending analyst review."]
            }))
            .bind(ts(2026, 5, 5, 10, 15, 0))
            .bind(degraded_job_id)
            .bind(degraded_artifact_id)
            .bind(json!({
                "evidence": {
                    "static_indicator_count": 0,
                    "sandbox_event_count": 0,
                    "malware_match_count": 0
                },
                "limitations": ["Sandbox worker unavailable for this artifact."],
                "ai_observed_behavior": [],
                "ai_inference": []
            }))
            .bind(ts(2026, 5, 5, 10, 30, 0))
            .bind(allow_job_id)
            .bind(allow_artifact_id)
            .bind(json!({
                "evidence": {
                    "static_indicator_count": 0,
                    "sandbox_event_count": 0,
                    "malware_match_count": 0
                },
                "limitations": [],
                "ai_observed_behavior": [],
                "ai_inference": []
            }))
            .bind(ts(2026, 5, 5, 10, 20, 0))
            .bind(other_job_id)
            .bind(other_artifact_id)
            .bind(json!({
                "evidence": {
                    "static_indicator_count": 1,
                    "sandbox_event_count": 1,
                    "malware_match_count": 0
                },
                "limitations": [],
                "ai_observed_behavior": ["cross-tenant record"],
                "ai_inference": ["must not leak" ]
            }))
            .bind(ts(2026, 5, 5, 10, 40, 0))
            .execute(pool)
            .await
            .expect("insert analysis summaries");

            sqlx::query(
                r#"
                INSERT INTO overrides (
                    id, tenant_id, scope, reason, requested_by, approved_by, status, expires_at, created_at
                )
                VALUES
                    ($1, $2, $3, $4, $5, NULL, 'pending', $6, $7),
                    ($8, $9, $10, $11, $12, $13, 'approved', $14, $15),
                    ($16, $17, $18, $19, $20, $21, 'denied', $22, $23),
                    ($24, $25, $26, $27, $28, NULL, 'pending', $29, $30)
                "#,
            )
            .bind(pending_override_id)
            .bind(tenant_id)
            .bind(json!({
                "ecosystem": "npm",
                "name": "fresh-postinstall",
                "version": "0.1.0",
                "kind": "metadata",
                "effect": "allow"
            }))
            .bind("Temporary analyst review bypass")
            .bind(admin_user_id)
            .bind(ts(2026, 12, 6, 10, 0, 0))
            .bind(ts(2026, 5, 5, 10, 20, 0))
            .bind(approved_override_id)
            .bind(tenant_id)
            .bind(json!({
                "ecosystem": "pypi",
                "name": "requestz",
                "version": "99.0.0",
                "kind": "artifact",
                "effect": "emergency-bypass",
                "digest": repeat_hex('2')
            }))
            .bind("Emergency unblock for incident triage")
            .bind(admin_user_id)
            .bind(admin_user_id)
            .bind(ts(2026, 12, 7, 10, 0, 0))
            .bind(ts(2026, 5, 5, 10, 18, 0))
            .bind(denied_override_id)
            .bind(tenant_id)
            .bind(json!({
                "ecosystem": "npm",
                "name": "left-pad",
                "version": "1.3.0",
                "kind": "metadata",
                "effect": "allow"
            }))
            .bind("Request lacked incident justification")
            .bind(admin_user_id)
            .bind(admin_user_id)
            .bind(ts(2026, 12, 8, 10, 0, 0))
            .bind(ts(2026, 5, 5, 10, 16, 0))
            .bind(other_override_id)
            .bind(other_tenant_id)
            .bind(json!({
                "ecosystem": "npm",
                "name": "other-tenant",
                "version": "9.9.9",
                "kind": "metadata",
                "effect": "allow"
            }))
            .bind("Cross-tenant row must stay hidden")
            .bind(other_admin_user_id)
            .bind(ts(2026, 12, 6, 10, 0, 0))
            .bind(ts(2026, 5, 5, 10, 14, 0))
            .execute(pool)
            .await
            .expect("insert overrides");

            sqlx::query(
                r#"
                INSERT INTO static_analysis_reports (
                    analysis_job_id, artifact_id, report, policy_version_id, created_at
                )
                VALUES ($1, $2, $3, $4, $5)
                "#,
            )
            .bind(full_job_id)
            .bind(full_artifact_id)
            .bind(json!({
                "indicators": [
                    {
                        "indicator_type": "lifecycle-script",
                        "summary": "postinstall script invokes remote bootstrap"
                    }
                ]
            }))
            .bind(policy_version_id)
            .bind(ts(2026, 5, 5, 10, 11, 0))
            .execute(pool)
            .await
            .expect("insert static analysis report");

            sqlx::query(
                r#"
                INSERT INTO sandbox_runs (
                    analysis_job_id, artifact_id, profile, state, telemetry, started_at, completed_at
                )
                VALUES ($1, $2, 'npm-install', 'completed', $3, $4, $5)
                "#,
            )
            .bind(full_job_id)
            .bind(full_artifact_id)
            .bind(json!({
                "phases": [
                    {
                        "name": "runtime",
                        "events": [
                            {
                                "type": "outbound-network-attempt",
                                "severity": "high",
                                "summary": "connection attempt to suspicious host"
                            },
                            {
                                "type": "canary-secret-access",
                                "severity": "critical",
                                "summary": "sandbox canary credential was touched"
                            }
                        ]
                    }
                ]
            }))
            .bind(ts(2026, 5, 5, 10, 12, 0))
            .bind(ts(2026, 5, 5, 10, 13, 0))
            .execute(pool)
            .await
            .expect("insert sandbox run");

            sqlx::query(
                r#"
                INSERT INTO ai_explanations (
                    analysis_job_id, provider_config_id, langfuse_trace_id, prompt_template_version,
                    redaction_complete, schema_valid, explanation, created_at
                )
                VALUES ($1, NULL, 'langfuse-trace-fixture', 'investigation-v1', true, true, $2, $3)
                "#,
            )
            .bind(full_job_id)
            .bind(json!({
                "observed_behavior": ["Outbound network activity was observed in the runtime sandbox."],
                "inference": ["The package should remain quarantined pending manual review."],
                "limitations": ["LLM output is advisory only."]
            }))
            .bind(ts(2026, 5, 5, 10, 14, 0))
            .execute(pool)
            .await
            .expect("insert ai explanation");

            let resource = format!("analysis-job/{full_job_id}");
            sqlx::query(
                r#"
                INSERT INTO audit_events (
                    id, tenant_id, actor, action, resource, trace_id, metadata, occurred_at
                )
                VALUES
                    ($1, $2, 'system/test-fixture', 'analysis.summary.completed', $3, 'trace-quarantine-full', $4, $5),
                    ($6, $7, 'system/test-fixture', 'analysis.evidence.persisted', 'artifact-evidence', 'trace-quarantine-full', $8, $9)
                "#,
            )
            .bind(Uuid::now_v7())
            .bind(tenant_id)
            .bind(&resource)
            .bind(json!({ "recommended_action": "QUARANTINE_PENDING_ANALYSIS" }))
            .bind(ts(2026, 5, 5, 10, 15, 30))
            .bind(Uuid::now_v7())
            .bind(tenant_id)
            .bind(json!({ "stage": "evidence-linked" }))
            .bind(ts(2026, 5, 5, 10, 15, 45))
            .execute(pool)
            .await
            .expect("insert audit events");

            Self {
                tenant_id,
                other_tenant_id,
                admin_user_id,
                developer_user_id,
                admin_role_id,
                other_admin_user_id,
                other_admin_role_id,
                policy_profile_id,
                simulated_policy_profile_id,
                other_policy_profile_id,
                policy_version_id,
                simulated_policy_version_id,
                other_policy_version_id,
                full_artifact_id,
                degraded_artifact_id,
                allow_artifact_id,
                other_artifact_id,
                full_job_id,
                degraded_job_id,
                allow_job_id,
                other_job_id,
                pending_override_id,
                approved_override_id,
                denied_override_id,
                other_override_id,
            }
        }

        async fn cleanup(&self, pool: &PgPool) {
            let tenant_ids = [self.tenant_id, self.other_tenant_id];
            let job_ids = [
                self.full_job_id,
                self.degraded_job_id,
                self.allow_job_id,
                self.other_job_id,
            ];
            let user_ids = [
                self.admin_user_id,
                self.developer_user_id,
                self.other_admin_user_id,
            ];
            let role_ids = [self.admin_role_id, self.other_admin_role_id];
            let override_ids = [
                self.pending_override_id,
                self.approved_override_id,
                self.denied_override_id,
                self.other_override_id,
            ];
            let artifact_ids = [
                self.full_artifact_id,
                self.degraded_artifact_id,
                self.allow_artifact_id,
                self.other_artifact_id,
            ];
            let policy_version_ids = [
                self.policy_version_id,
                self.simulated_policy_version_id,
                self.other_policy_version_id,
            ];
            let policy_profile_ids = [
                self.policy_profile_id,
                self.simulated_policy_profile_id,
                self.other_policy_profile_id,
            ];

            sqlx::query("DELETE FROM policy_decisions WHERE tenant_id = ANY($1)")
                .bind(&tenant_ids[..])
                .execute(pool)
                .await
                .expect("delete policy decisions");
            sqlx::query("DELETE FROM package_requests WHERE tenant_id = ANY($1)")
                .bind(&tenant_ids[..])
                .execute(pool)
                .await
                .expect("delete package requests");
            sqlx::query("DELETE FROM feed_snapshots WHERE tenant_id = ANY($1)")
                .bind(&tenant_ids[..])
                .execute(pool)
                .await
                .expect("delete feed snapshots");

            sqlx::query("DELETE FROM audit_events WHERE tenant_id = ANY($1)")
                .bind(&tenant_ids[..])
                .execute(pool)
                .await
                .expect("delete audit events");
            sqlx::query("DELETE FROM llm_usage_events WHERE tenant_id = ANY($1)")
                .bind(&tenant_ids[..])
                .execute(pool)
                .await
                .expect("delete llm usage events");
            sqlx::query("DELETE FROM registry_configs WHERE tenant_id = ANY($1)")
                .bind(&tenant_ids[..])
                .execute(pool)
                .await
                .expect("delete registry configs");
            sqlx::query("DELETE FROM overrides WHERE id = ANY($1)")
                .bind(&override_ids[..])
                .execute(pool)
                .await
                .expect("delete overrides");
            sqlx::query("DELETE FROM ai_explanations WHERE analysis_job_id = ANY($1)")
                .bind(&job_ids[..])
                .execute(pool)
                .await
                .expect("delete ai explanations");
            sqlx::query("DELETE FROM ai_provider_configs WHERE tenant_id = ANY($1)")
                .bind(&tenant_ids[..])
                .execute(pool)
                .await
                .expect("delete ai provider configs");
            sqlx::query("DELETE FROM sandbox_runs WHERE analysis_job_id = ANY($1)")
                .bind(&job_ids[..])
                .execute(pool)
                .await
                .expect("delete sandbox runs");
            sqlx::query("DELETE FROM static_analysis_reports WHERE analysis_job_id = ANY($1)")
                .bind(&job_ids[..])
                .execute(pool)
                .await
                .expect("delete static reports");
            sqlx::query("DELETE FROM analysis_summaries WHERE analysis_job_id = ANY($1)")
                .bind(&job_ids[..])
                .execute(pool)
                .await
                .expect("delete analysis summaries");
            sqlx::query("DELETE FROM analysis_jobs WHERE id = ANY($1)")
                .bind(&job_ids[..])
                .execute(pool)
                .await
                .expect("delete analysis jobs");
            sqlx::query("DELETE FROM artifacts WHERE id = ANY($1)")
                .bind(&artifact_ids[..])
                .execute(pool)
                .await
                .expect("delete artifacts");
            sqlx::query("DELETE FROM policy_versions WHERE id = ANY($1)")
                .bind(&policy_version_ids[..])
                .execute(pool)
                .await
                .expect("delete policy versions");
            sqlx::query("DELETE FROM user_roles WHERE user_id = ANY($1)")
                .bind(&user_ids[..])
                .execute(pool)
                .await
                .expect("delete user roles");
            sqlx::query("DELETE FROM roles WHERE id = ANY($1)")
                .bind(&role_ids[..])
                .execute(pool)
                .await
                .expect("delete roles");
            sqlx::query("DELETE FROM users WHERE id = ANY($1)")
                .bind(&user_ids[..])
                .execute(pool)
                .await
                .expect("delete users");
            sqlx::query("DELETE FROM policy_profiles WHERE id = ANY($1)")
                .bind(&policy_profile_ids[..])
                .execute(pool)
                .await
                .expect("delete policy profiles");
            sqlx::query("DELETE FROM tenants WHERE id = ANY($1)")
                .bind(&tenant_ids[..])
                .execute(pool)
                .await
                .expect("delete tenants");
        }
    }

    #[tokio::test]
    async fn healthz_route_returns_runtime_version() {
        let pool = PgPoolOptions::new()
            .connect_lazy(&test_database_url())
            .expect("create lazy test db pool");

        let response = app_with_auth_mode(pool, AuthMode::MockOidc, Uuid::nil())
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .expect("healthz request"),
            )
            .await
            .expect("healthz response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_value_body(response).await;
        let expected_version = aegiscudo_telemetry::app_version();

        assert_eq!(body.get("status").and_then(Value::as_str), Some("ok"));
        assert_eq!(
            body.get("service").and_then(Value::as_str),
            Some(SERVICE_NAME)
        );
        assert_eq!(
            body.get("version").and_then(Value::as_str),
            Some(expected_version.as_str())
        );
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn evaluate_decision_route_proxies_to_triage_counter() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_requests = captured.clone();
        let decision_client = DecisionClient::new_test(move |request| {
            captured_requests
                .lock()
                .expect("capture request")
                .push(request.clone());
            Ok(DecisionResponse {
                decision: PolicyDecision::AllowWithWarning,
                tenant_id: request.tenant_id,
                policy_profile_id: request.policy_profile_id,
                policy_snapshot_id: Uuid::now_v7(),
                mode: PolicyMode::Enforce,
                feed_state: FeedState::Fresh,
                feed_snapshot_age_seconds: 30,
                trace_id: request.request.trace_id.clone(),
                rationale: vec!["fixture decision".to_owned()],
                fallback_coordinate: None,
                create_analysis_job: false,
            })
        });

        let request_body = DecisionRequest {
            tenant_id: Uuid::now_v7(),
            registry_config_id: Uuid::now_v7(),
            policy_profile_id: Uuid::now_v7(),
            request: NormalizedPackageRequest {
                kind: PackageRequestKind::Metadata,
                tenant_id: Uuid::now_v7(),
                registry_config_id: Uuid::now_v7(),
                policy_profile_id: Uuid::now_v7(),
                coordinate: PackageCoordinate::new(
                    PackageEcosystem::Npm,
                    "left-pad",
                    Some("1.3.0"),
                    None::<String>,
                ),
                trace_id: "decision-trace-1".to_owned(),
                requested_digest: None,
                source_url: None,
                explicit_version_or_integrity: false,
            },
        };

        let response = app_with_clients(pool, None, decision_client)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/decisions/evaluate")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&request_body).expect("serialize request"),
                    ))
                    .expect("decision request"),
            )
            .await
            .expect("decision response");

        assert_eq!(response.status(), StatusCode::OK);
        let body: DecisionResponse = read_json_body(response).await;
        assert_eq!(body.decision, PolicyDecision::AllowWithWarning);
        assert_eq!(body.trace_id, "decision-trace-1");

        let captured = captured.lock().expect("captured requests");
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0], request_body);
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn submit_cli_scan_route_resolves_registry_context_and_returns_decisions() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;
        let registry_config_id = Uuid::now_v7();
        let mount_path = format!("/proxy/npm-fixture-{registry_config_id}");
        sqlx::query(
            r#"
            INSERT INTO registry_configs (
                id, tenant_id, name, description, adapter, upstream_url, mount_path,
                auth_type, mode, policy_profile_id, cache_ttl_seconds, verify_upstream_tls, enabled
            )
            VALUES (
                $1, $2, 'fixture npm registry', 'fixture registry for CLI scans', 'npm',
                'https://registry.example.invalid', $3, 'none', 'enforce',
                $4, 300, TRUE, TRUE
            )
            "#,
        )
        .bind(registry_config_id)
        .bind(fixture.tenant_id)
        .bind(&mount_path)
        .bind(fixture.policy_profile_id)
        .execute(&pool)
        .await
        .expect("insert registry config");

        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_requests = captured.clone();
        let decision_client = DecisionClient::new_test(move |request| {
            captured_requests
                .lock()
                .expect("capture request")
                .push(request.clone());
            Ok(DecisionResponse {
                decision: PolicyDecision::AllowWithWarning,
                tenant_id: request.tenant_id,
                policy_profile_id: request.policy_profile_id,
                policy_snapshot_id: Uuid::now_v7(),
                mode: PolicyMode::Enforce,
                feed_state: FeedState::Fresh,
                feed_snapshot_age_seconds: 12,
                trace_id: request.request.trace_id.clone(),
                rationale: vec!["fixture cli scan decision".to_owned()],
                fallback_coordinate: None,
                create_analysis_job: false,
            })
        });

        let result = async {
            let response = app_with_clients(pool.clone(), None, decision_client)
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/cli/scans")
                        .header("content-type", "application/json")
                        .header(TRACE_HEADER, "cli-trace")
                        .body(Body::from(
                            serde_json::to_vec(&CliScanRequest {
                                tenant_id: Some(fixture.tenant_id),
                                packages: vec![CliScanPackageRequest {
                                    coordinate: PackageCoordinate::new(
                                        PackageEcosystem::Npm,
                                        "fresh-postinstall",
                                        Some("0.1.0"),
                                        None::<String>,
                                    ),
                                    artifact_sha256: None,
                                }],
                            })
                            .expect("serialize cli scan request"),
                        ))
                        .expect("cli scan request"),
                )
                .await
                .expect("cli scan response");

            assert_eq!(response.status(), StatusCode::ACCEPTED);
            let body: CliScanResponse = read_json_body(response).await;
            assert_eq!(body.tenant_id, fixture.tenant_id);
            assert_eq!(body.registry_config_id, registry_config_id);
            assert_eq!(body.policy_profile_id, fixture.policy_profile_id);
            assert_eq!(body.findings.len(), 1);
            assert_eq!(body.findings[0].decision, PolicyDecision::AllowWithWarning);
            assert!(body.findings[0].decision_timestamp.is_some());
            assert_eq!(body.findings[0].trace_id, "cli-trace-1");

            let captured = captured.lock().expect("captured requests");
            assert_eq!(captured.len(), 1);
            assert_eq!(captured[0].tenant_id, fixture.tenant_id);
            assert_eq!(captured[0].registry_config_id, registry_config_id);
            assert_eq!(captured[0].policy_profile_id, fixture.policy_profile_id);
            assert_eq!(captured[0].request.trace_id, "cli-trace-1");
            assert_eq!(
                captured[0].request.coordinate,
                PackageCoordinate::new(
                    PackageEcosystem::Npm,
                    "fresh-postinstall",
                    Some("0.1.0"),
                    None::<String>,
                )
            );
            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("cli scan assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn github_actions_enrichment_route_resolves_policy_context_and_returns_decisions() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;

        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_requests = captured.clone();
        let decision_client = DecisionClient::new_query_test(move |request| {
            captured_requests
                .lock()
                .expect("capture request")
                .push(request.clone());
            Ok(DecisionResponse {
                decision: PolicyDecision::BlockKnownMalicious,
                tenant_id: request.tenant_id,
                policy_profile_id: request.policy_profile_id,
                policy_snapshot_id: Uuid::now_v7(),
                mode: PolicyMode::Enforce,
                feed_state: FeedState::Fresh,
                feed_snapshot_age_seconds: 7,
                trace_id: request.request.trace_id.clone(),
                rationale: vec!["fixture github action decision".to_owned()],
                fallback_coordinate: None,
                create_analysis_job: false,
            })
        });

        let result = async {
            let response = app_with_clients(pool.clone(), None, decision_client)
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/cli/github-actions/enrich")
                        .header("content-type", "application/json")
                        .header(TRACE_HEADER, "cli-trace")
                        .body(Body::from(
                            serde_json::to_vec(&CliGithubActionsEnrichmentRequest {
                                tenant_id: Some(fixture.tenant_id),
                                policy_profile_id: Some(fixture.policy_profile_id),
                                packages: vec![CliGithubActionsEnrichmentPackageRequest {
                                    coordinate: PackageCoordinate::new(
                                        PackageEcosystem::GithubActions,
                                        "checkout",
                                        Some("f".repeat(40)),
                                        Some("actions"),
                                    ),
                                }],
                            })
                            .expect("serialize github actions enrichment request"),
                        ))
                        .expect("github actions enrichment request"),
                )
                .await
                .expect("github actions enrichment response");

            assert_eq!(response.status(), StatusCode::OK);
            let body: CliGithubActionsEnrichmentResponse = read_json_body(response).await;
            assert_eq!(body.tenant_id, fixture.tenant_id);
            assert_eq!(body.policy_profile_id, fixture.policy_profile_id);
            assert_eq!(body.findings.len(), 1);
            assert_eq!(
                body.findings[0].decision,
                PolicyDecision::BlockKnownMalicious
            );
            assert!(body.findings[0].decision_timestamp.is_some());
            assert_eq!(body.findings[0].trace_id, "cli-trace-1");

            let captured = captured.lock().expect("captured requests");
            assert_eq!(captured.len(), 1);
            assert_eq!(captured[0].tenant_id, fixture.tenant_id);
            assert_eq!(captured[0].policy_profile_id, fixture.policy_profile_id);
            assert_eq!(captured[0].request.trace_id, "cli-trace-1");
            assert_eq!(
                captured[0].request.coordinate,
                PackageCoordinate::new(
                    PackageEcosystem::GithubActions,
                    "checkout",
                    Some("f".repeat(40)),
                    Some("actions"),
                )
            );
            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("github actions enrichment assertions");
    }

    #[tokio::test]
    async fn github_actions_enrichment_route_rejects_missing_policy_profile() {
        let pool = PgPoolOptions::new()
            .connect_lazy(&test_database_url())
            .expect("create lazy test db pool");

        let response = app_with_clients(
            pool,
            None,
            DecisionClient::new_query_test(|_| {
                panic!("decision client query should not be called")
            }),
        )
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/cli/github-actions/enrich")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&CliGithubActionsEnrichmentRequest {
                        tenant_id: None,
                        policy_profile_id: None,
                        packages: vec![CliGithubActionsEnrichmentPackageRequest {
                            coordinate: PackageCoordinate::new(
                                PackageEcosystem::GithubActions,
                                "checkout",
                                Some("f".repeat(40)),
                                Some("actions"),
                            ),
                        }],
                    })
                    .expect("serialize request"),
                ))
                .expect("build request"),
        )
        .await
        .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: ErrorBody = read_json_body(response).await;
        assert!(body.message.contains("policy_profile_id"));
    }

    #[tokio::test]
    async fn github_actions_enrichment_route_rejects_non_githubactions_packages() {
        let pool = PgPoolOptions::new()
            .connect_lazy(&test_database_url())
            .expect("create lazy test db pool");

        let response = app_with_clients(
            pool,
            None,
            DecisionClient::new_query_test(|_| {
                panic!("decision client query should not be called")
            }),
        )
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/cli/github-actions/enrich")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&CliGithubActionsEnrichmentRequest {
                        tenant_id: None,
                        policy_profile_id: Some(Uuid::now_v7()),
                        packages: vec![CliGithubActionsEnrichmentPackageRequest {
                            coordinate: PackageCoordinate::new(
                                PackageEcosystem::Npm,
                                "left-pad",
                                Some("1.3.0"),
                                None::<String>,
                            ),
                        }],
                    })
                    .expect("serialize request"),
                ))
                .expect("build request"),
        )
        .await
        .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: ErrorBody = read_json_body(response).await;
        assert!(body.message.contains("githubactions"));
    }

    #[tokio::test]
    async fn github_actions_enrichment_route_rejects_malformed_coordinates() {
        let pool = PgPoolOptions::new()
            .connect_lazy(&test_database_url())
            .expect("create lazy test db pool");

        let response = app_with_clients(
            pool,
            None,
            DecisionClient::new_query_test(|_| {
                panic!("decision client query should not be called")
            }),
        )
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/cli/github-actions/enrich")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&CliGithubActionsEnrichmentRequest {
                        tenant_id: None,
                        policy_profile_id: Some(Uuid::now_v7()),
                        packages: vec![CliGithubActionsEnrichmentPackageRequest {
                            coordinate: PackageCoordinate::new(
                                PackageEcosystem::GithubActions,
                                "checkout/plugin",
                                Some("release candidate"),
                                Some("actions org"),
                            ),
                        }],
                    })
                    .expect("serialize request"),
                ))
                .expect("build request"),
        )
        .await
        .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: ErrorBody = read_json_body(response).await;
        assert!(body.message.contains("owner/repo@ref"));
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn submit_cli_scan_route_rejects_mixed_ecosystems() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");

        let response = app_with_clients(
            pool,
            None,
            DecisionClient::new_test(|_| panic!("decision client should not be called")),
        )
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/cli/scans")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&CliScanRequest {
                        tenant_id: None,
                        packages: vec![
                            CliScanPackageRequest {
                                coordinate: PackageCoordinate::new(
                                    PackageEcosystem::Npm,
                                    "left-pad",
                                    Some("1.3.0"),
                                    None::<String>,
                                ),
                                artifact_sha256: None,
                            },
                            CliScanPackageRequest {
                                coordinate: PackageCoordinate::new(
                                    PackageEcosystem::Pypi,
                                    "requests",
                                    Some("2.32.0"),
                                    None::<String>,
                                ),
                                artifact_sha256: None,
                            },
                        ],
                    })
                    .expect("serialize cli scan request"),
                ))
                .expect("cli scan request"),
        )
        .await
        .expect("cli scan response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: ErrorBody = read_json_body(response).await;
        assert!(body.message.contains("same ecosystem"));
    }

    #[tokio::test]
    async fn cli_risk_rejects_empty_coordinate_name() {
        // Validation fires before any DB access, so a lazy pool is sufficient.
        let pool = PgPoolOptions::new()
            .connect_lazy(&test_database_url())
            .expect("create lazy test db pool");

        let response = app_with_auth_mode(pool, AuthMode::MockOidc, Uuid::nil())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/cli/risk")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&CliRiskRequest {
                            tenant_id: None,
                            coordinate: PackageCoordinate::new(
                                PackageEcosystem::Npm,
                                "",
                                Some("1.0.0"),
                                None::<String>,
                            ),
                        })
                        .expect("serialize request"),
                    ))
                    .expect("build request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: ErrorBody = read_json_body(response).await;
        assert!(body.message.contains("name"));
    }

    #[tokio::test]
    async fn cli_risk_rejects_missing_coordinate_version() {
        // Validation fires before any DB access, so a lazy pool is sufficient.
        let pool = PgPoolOptions::new()
            .connect_lazy(&test_database_url())
            .expect("create lazy test db pool");

        let response = app_with_auth_mode(pool, AuthMode::MockOidc, Uuid::nil())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/cli/risk")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&CliRiskRequest {
                            tenant_id: None,
                            coordinate: PackageCoordinate::new(
                                PackageEcosystem::Cargo,
                                "serde",
                                None::<String>,
                                None::<String>,
                            ),
                        })
                        .expect("serialize request"),
                    ))
                    .expect("build request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: ErrorBody = read_json_body(response).await;
        assert!(body.message.contains("version"));
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn explain_cli_package_route_returns_latest_summary_and_ai_explanation() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;

        let result = async {
            let response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/cli/explain")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&CliExplainRequest {
                                tenant_id: Some(fixture.tenant_id),
                                coordinate: PackageCoordinate::new(
                                    PackageEcosystem::Npm,
                                    "fresh-postinstall",
                                    Some("0.1.0"),
                                    None::<String>,
                                ),
                            })
                            .expect("serialize explain request"),
                        ))
                        .expect("cli explain request"),
                )
                .await
                .expect("cli explain response");

            assert_eq!(response.status(), StatusCode::OK);
            let body: CliExplainResponse = read_json_body(response).await;
            assert_eq!(body.tenant_id, fixture.tenant_id);
            assert_eq!(body.analysis_job_id, fixture.full_job_id);
            assert_eq!(body.artifact_id, fixture.full_artifact_id);
            assert_eq!(body.trace_id, "trace-quarantine-full");
            assert_eq!(
                body.coordinate,
                PackageCoordinate::new(
                    PackageEcosystem::Npm,
                    "fresh-postinstall",
                    Some("0.1.0"),
                    None::<String>,
                )
            );
            assert_eq!(body.recommended_action, "QUARANTINE_PENDING_ANALYSIS");
            assert!(body.ai_explanation.is_some());
            assert_eq!(body.summary["evidence"]["static_indicator_count"], 2);
            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("cli explain assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn overrides_route_returns_tenant_scoped_pending_and_resolved_items() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;

        let result = async {
            let response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/tenants/{}/overrides", fixture.tenant_id))
                        .body(Body::empty())
                        .expect("overrides request"),
                )
                .await
                .expect("overrides response");

            assert_eq!(response.status(), StatusCode::OK);
            let items: Vec<OverrideQueueItemResponse> = read_json_body(response).await;
            assert_eq!(items.len(), 3);

            assert_eq!(items[0].id, fixture.pending_override_id);
            assert_eq!(items[0].status, "pending");
            assert_eq!(
                items[0].requested_by_display.as_deref(),
                Some("Fixture Admin")
            );

            assert_eq!(items[1].id, fixture.approved_override_id);
            assert_eq!(items[1].status, "approved");
            assert_eq!(
                items[1].approved_by_display.as_deref(),
                Some("Fixture Admin")
            );

            assert_eq!(items[2].id, fixture.denied_override_id);
            assert_eq!(items[2].status, "denied");
            assert!(
                items
                    .iter()
                    .all(|item| item.id != fixture.other_override_id)
            );
            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("override assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn overrides_route_normalizes_expired_overrides() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;

        let result = async {
            sqlx::query(
                "UPDATE overrides SET expires_at = NOW() - INTERVAL '1 day' WHERE id = $1 AND tenant_id = $2",
            )
            .bind(fixture.approved_override_id)
            .bind(fixture.tenant_id)
            .execute(&pool)
            .await
            .expect("expire approved override");

            let response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/tenants/{}/overrides", fixture.tenant_id))
                        .body(Body::empty())
                        .expect("overrides request"),
                )
                .await
                .expect("overrides response");

            assert_eq!(response.status(), StatusCode::OK);
            let items: Vec<OverrideQueueItemResponse> = read_json_body(response).await;
            let expired_item = items
                .iter()
                .find(|item| item.id == fixture.approved_override_id)
                .expect("expired override present");

            assert_eq!(expired_item.status, "expired");
            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("expired override assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn approve_override_route_updates_pending_override_and_enforces_tenant_scope() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;

        let result = async {
            let response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!(
                            "/v1/tenants/{}/overrides/{}/approve",
                            fixture.tenant_id, fixture.pending_override_id
                        ))
                        .header("content-type", "application/json")
                        .body(Body::from(
                            json!({
                                "actor_id": fixture.admin_user_id,
                                "reason": "Approved after validating runtime investigation context"
                            })
                            .to_string(),
                        ))
                        .expect("approve request"),
                )
                .await
                .expect("approve response");

            assert_eq!(response.status(), StatusCode::OK);
            let approved: OverrideResponse = read_json_body(response).await;
            assert_eq!(approved.id, fixture.pending_override_id);
            assert_eq!(approved.status, "approved");
            assert_eq!(approved.approved_by, Some(fixture.admin_user_id));
            assert!(
                approved
                    .reason
                    .contains("approval: Approved after validating runtime investigation context")
            );

            let persisted_status: String = sqlx::query_scalar(
                "SELECT status::text FROM overrides WHERE id = $1 AND tenant_id = $2",
            )
            .bind(fixture.pending_override_id)
            .bind(fixture.tenant_id)
            .fetch_one(&pool)
            .await?;
            assert_eq!(persisted_status, "approved");

            let cross_tenant_response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!(
                            "/v1/tenants/{}/overrides/{}/approve",
                            fixture.other_tenant_id, fixture.pending_override_id
                        ))
                        .header("content-type", "application/json")
                        .body(Body::from(
                            json!({
                                "actor_id": fixture.other_admin_user_id,
                                "reason": "Cross-tenant approval must not succeed"
                            })
                            .to_string(),
                        ))
                        .expect("cross-tenant approve request"),
                )
                .await
                .expect("cross-tenant approve response");

            assert_eq!(cross_tenant_response.status(), StatusCode::NOT_FOUND);
            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("approve override assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn deny_override_route_updates_pending_override() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;

        let result = async {
            let response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!(
                            "/v1/tenants/{}/overrides/{}/deny",
                            fixture.tenant_id, fixture.pending_override_id
                        ))
                        .header("content-type", "application/json")
                        .body(Body::from(
                            json!({
                                "actor_id": fixture.admin_user_id,
                                "reason": "Denied because supporting incident evidence is incomplete"
                            })
                            .to_string(),
                        ))
                        .expect("deny request"),
                )
                .await
                .expect("deny response");

            assert_eq!(response.status(), StatusCode::OK);
            let denied: OverrideResponse = read_json_body(response).await;
            assert_eq!(denied.id, fixture.pending_override_id);
            assert_eq!(denied.status, "denied");
            assert_eq!(denied.approved_by, Some(fixture.admin_user_id));
            assert!(denied.reason.contains("denial: Denied because supporting incident evidence is incomplete"));

            let persisted_status: String = sqlx::query_scalar(
                "SELECT status::text FROM overrides WHERE id = $1 AND tenant_id = $2",
            )
            .bind(fixture.pending_override_id)
            .bind(fixture.tenant_id)
            .fetch_one(&pool)
            .await?;
            assert_eq!(persisted_status, "denied");
            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("deny override assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn request_timeline_route_returns_bucketed_counts_for_the_tenant() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;

        let result = async {
            let response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "/v1/tenants/{}/analysis/request-timeline",
                            fixture.tenant_id
                        ))
                        .body(Body::empty())
                        .expect("timeline request"),
                )
                .await
                .expect("timeline response");

            assert_eq!(response.status(), StatusCode::OK);

            let items: Vec<RequestTimelineBucketResponse> = read_json_body(response).await;
            assert_eq!(items.len(), 8);
            assert!(items.iter().take(7).all(|bucket| {
                bucket.allow == 0 && bucket.warn == 0 && bucket.quarantine == 0 && bucket.block == 0
            }));

            let latest = items.last().expect("latest timeline bucket");
            assert_eq!(latest.bucket_start, ts(2026, 5, 5, 10, 0, 0));
            assert_eq!(latest.allow, 1);
            assert_eq!(latest.warn, 1);
            assert_eq!(latest.quarantine, 1);
            assert_eq!(latest.block, 0);
            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("timeline assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn policy_profiles_route_returns_latest_profiles_for_the_tenant() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;

        let result = async {
            let response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/tenants/{}/policy-profiles", fixture.tenant_id))
                        .body(Body::empty())
                        .expect("policy profiles request"),
                )
                .await
                .expect("policy profiles response");

            assert_eq!(response.status(), StatusCode::OK);
            let items: Vec<PolicyProfileSummaryResponse> = read_json_body(response).await;
            assert_eq!(items.len(), 2);
            assert_eq!(items[0].id, fixture.policy_profile_id);
            assert_eq!(items[0].latest_version, "v1");
            assert_eq!(items[1].id, fixture.simulated_policy_profile_id);
            assert_eq!(items[1].latest_version, "v2");
            assert_eq!(items[1].mode, PolicyMode::Shadow);
            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("policy profile assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn admin_read_routes_require_control_plane_role() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;

        let result = async {
            for path in [
                format!("/v1/tenants/{}/registry-configs", fixture.tenant_id),
                format!("/v1/tenants/{}/credentials", fixture.tenant_id),
                format!("/v1/tenants/{}/audit-events", fixture.tenant_id),
                format!("/v1/tenants/{}/ai-providers", fixture.tenant_id),
            ] {
                let admin_response = app(pool.clone())
                    .oneshot(
                        Request::builder()
                            .uri(&path)
                            .header(ACTOR_HEADER, fixture.admin_user_id.to_string())
                            .body(Body::empty())
                            .expect("admin read request"),
                    )
                    .await
                    .expect("admin read response");
                assert_eq!(admin_response.status(), StatusCode::OK);

                let developer_response = app(pool.clone())
                    .oneshot(
                        Request::builder()
                            .uri(&path)
                            .header(ACTOR_HEADER, fixture.developer_user_id.to_string())
                            .body(Body::empty())
                            .expect("developer read request"),
                    )
                    .await
                    .expect("developer read response");
                assert_eq!(developer_response.status(), StatusCode::FORBIDDEN);
            }

            let missing_actor_response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "/v1/tenants/{}/registry-configs",
                            fixture.tenant_id
                        ))
                        .body(Body::empty())
                        .expect("missing actor request"),
                )
                .await
                .expect("missing actor response");
            assert_eq!(missing_actor_response.status(), StatusCode::UNAUTHORIZED);

            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("admin read route role assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn llm_usage_route_requires_admin_or_platform_admin_role() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = AuthRouteFixture::insert(&pool).await;

        let result = async {
            let path = format!("/v1/tenants/{}/llm-usage", fixture.tenant_id);

            let admin_response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri(&path)
                        .header(ACTOR_HEADER, fixture.platform_admin_user_id.to_string())
                        .body(Body::empty())
                        .expect("platform admin llm usage request"),
                )
                .await
                .expect("platform admin llm usage response");
            assert_eq!(admin_response.status(), StatusCode::OK);

            for denied_actor in [
                fixture.developer_user_id,
                fixture.security_specialist_user_id,
                fixture.ciso_auditor_user_id,
            ] {
                let denied_response = app(pool.clone())
                    .oneshot(
                        Request::builder()
                            .uri(&path)
                            .header(ACTOR_HEADER, denied_actor.to_string())
                            .body(Body::empty())
                            .expect("denied llm usage request"),
                    )
                    .await
                    .expect("denied llm usage response");
                assert_eq!(denied_response.status(), StatusCode::FORBIDDEN);
            }

            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("llm usage role assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn admin_mutation_routes_require_control_plane_role() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;
        let credential_id = Uuid::now_v7();
        let registry_name = format!("rbac-fixture-{}", Uuid::now_v7());
        let mount_path = format!("/proxy/{registry_name}");

        sqlx::query(
            r#"
            INSERT INTO integration_credentials (
                id, tenant_id, name, credential_type, source, configured
            )
            VALUES ($1, $2, 'rbac-test-credential', 'bearer', 'database-runtime-override', TRUE)
            "#,
        )
        .bind(credential_id)
        .bind(fixture.tenant_id)
        .execute(&pool)
        .await
        .expect("insert credential for RBAC mutation test");

        let create_request = CreateRegistryConfigRequest {
            name: registry_name.clone(),
            description: "RBAC create guard".to_owned(),
            adapter: RegistryAdapterDto::Npm,
            upstream_url: "https://registry.example.invalid".to_owned(),
            mount_path: mount_path.clone(),
            auth_type: CredentialAuthTypeDto::None,
            credential_ref: None,
            mode: PolicyMode::Enforce,
            policy_profile_id: fixture.policy_profile_id,
            cache_ttl_seconds: 300,
            verify_upstream_tls: true,
            enabled: true,
        };

        let result = async {
            let create_uri = format!("/v1/tenants/{}/registry-configs", fixture.tenant_id);
            let delete_uri = format!("/v1/tenants/{}/credentials/{}", fixture.tenant_id, credential_id);

            let missing_actor_create = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(&create_uri)
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&create_request).expect("serialize create request"),
                        ))
                        .expect("missing actor create request"),
                )
                .await
                .expect("missing actor create response");
            assert_eq!(missing_actor_create.status(), StatusCode::UNAUTHORIZED);

            let developer_create = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(&create_uri)
                        .header(ACTOR_HEADER, fixture.developer_user_id.to_string())
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&create_request).expect("serialize create request"),
                        ))
                        .expect("developer create request"),
                )
                .await
                .expect("developer create response");
            assert_eq!(developer_create.status(), StatusCode::FORBIDDEN);

            let created_count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM registry_configs WHERE tenant_id = $1 AND name = $2 AND deleted_at IS NULL",
            )
            .bind(fixture.tenant_id)
            .bind(&registry_name)
            .fetch_one(&pool)
            .await
            .expect("count registry configs after rejected create");
            assert_eq!(created_count, 0);

            let admin_create = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(&create_uri)
                        .header(ACTOR_HEADER, fixture.admin_user_id.to_string())
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&create_request).expect("serialize create request"),
                        ))
                        .expect("admin create request"),
                )
                .await
                .expect("admin create response");
            assert_eq!(admin_create.status(), StatusCode::OK);

            let missing_actor_delete = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .method("DELETE")
                        .uri(&delete_uri)
                        .body(Body::empty())
                        .expect("missing actor delete request"),
                )
                .await
                .expect("missing actor delete response");
            assert_eq!(missing_actor_delete.status(), StatusCode::UNAUTHORIZED);

            let developer_delete = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .method("DELETE")
                        .uri(&delete_uri)
                        .header(ACTOR_HEADER, fixture.developer_user_id.to_string())
                        .body(Body::empty())
                        .expect("developer delete request"),
                )
                .await
                .expect("developer delete response");
            assert_eq!(developer_delete.status(), StatusCode::FORBIDDEN);

            let credential_count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM integration_credentials WHERE tenant_id = $1 AND id = $2",
            )
            .bind(fixture.tenant_id)
            .bind(credential_id)
            .fetch_one(&pool)
            .await
            .expect("count credentials after rejected delete");
            assert_eq!(credential_count, 1);

            let admin_delete = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .method("DELETE")
                        .uri(&delete_uri)
                        .header(ACTOR_HEADER, fixture.admin_user_id.to_string())
                        .body(Body::empty())
                        .expect("admin delete request"),
                )
                .await
                .expect("admin delete response");
            assert_eq!(admin_delete.status(), StatusCode::NO_CONTENT);

            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("admin mutation RBAC assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn auth_session_route_defaults_to_platform_admin_identity_in_mock_mode() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = AuthRouteFixture::insert(&pool).await;

        let result = async {
            let response = app_with_auth_mode(pool.clone(), AuthMode::MockOidc, fixture.tenant_id)
                .oneshot(
                    Request::builder()
                        .uri("/v1/auth/session")
                        .body(Body::empty())
                        .expect("auth session request"),
                )
                .await
                .expect("auth session response");

            assert_eq!(response.status(), StatusCode::OK);
            let session: AuthSessionResponse = read_json_body(response).await;
            assert!(session.authenticated);
            assert_eq!(session.auth_mode, AuthMode::MockOidc);
            assert!(session.mock_identity_supported);

            let subject = session.subject.expect("subject present");
            assert_eq!(subject.user_id, fixture.platform_admin_user_id);
            assert_eq!(subject.display_name, "Local Admin");
            assert_eq!(subject.email, "local-admin@aegiscudo.invalid");
            assert_eq!(subject.mock_identity_id.as_deref(), Some("platform-admin"));
            assert_eq!(subject.roles, vec!["admin".to_owned()]);

            let invalid_actor_response =
                app_with_auth_mode(pool.clone(), AuthMode::MockOidc, fixture.tenant_id)
                    .oneshot(
                        Request::builder()
                            .uri("/v1/auth/session")
                            .header(ACTOR_HEADER, "not-a-uuid")
                            .body(Body::empty())
                            .expect("invalid auth session request"),
                    )
                    .await
                    .expect("invalid auth session response");

            assert_eq!(invalid_actor_response.status(), StatusCode::UNAUTHORIZED);

            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("auth session assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn mock_identity_routes_list_select_and_reject_unknown_identities() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = AuthRouteFixture::insert(&pool).await;

        let result = async {
            let list_response =
                app_with_auth_mode(pool.clone(), AuthMode::MockOidc, fixture.tenant_id)
                    .oneshot(
                        Request::builder()
                            .uri("/v1/auth/mock-identities")
                            .body(Body::empty())
                            .expect("mock identities request"),
                    )
                    .await
                    .expect("mock identities response");

            assert_eq!(list_response.status(), StatusCode::OK);
            let identities: MockIdentityListResponse = read_json_body(list_response).await;
            assert_eq!(identities.identities.len(), 4);
            assert_eq!(
                identities
                    .identities
                    .iter()
                    .map(|subject| subject.mock_identity_id.as_deref().unwrap_or_default())
                    .collect::<Vec<_>>(),
                vec![
                    "developer",
                    "security-specialist",
                    "platform-admin",
                    "ciso-auditor"
                ]
            );

            let select_response =
                app_with_auth_mode(pool.clone(), AuthMode::MockOidc, fixture.tenant_id)
                    .oneshot(
                        Request::builder()
                            .method("PUT")
                            .uri("/v1/auth/session/mock")
                            .header("content-type", "application/json")
                            .body(Body::from(
                                serde_json::to_vec(&SetMockAuthSessionRequest {
                                    identity_id: "developer".to_owned(),
                                })
                                .expect("serialize mock selection"),
                            ))
                            .expect("mock selection request"),
                    )
                    .await
                    .expect("mock selection response");

            assert_eq!(select_response.status(), StatusCode::OK);
            let selected_session: AuthSessionResponse = read_json_body(select_response).await;
            let selected_subject = selected_session.subject.expect("selected subject");
            assert_eq!(selected_subject.user_id, fixture.developer_user_id);
            assert_eq!(selected_subject.display_name, "Developer Persona");
            assert_eq!(
                selected_subject.mock_identity_id.as_deref(),
                Some("developer")
            );
            assert_eq!(selected_subject.roles, vec!["developer".to_owned()]);

            let unknown_response =
                app_with_auth_mode(pool.clone(), AuthMode::MockOidc, fixture.tenant_id)
                    .oneshot(
                        Request::builder()
                            .method("PUT")
                            .uri("/v1/auth/session/mock")
                            .header("content-type", "application/json")
                            .body(Body::from(
                                serde_json::to_vec(&SetMockAuthSessionRequest {
                                    identity_id: "not-a-persona".to_owned(),
                                })
                                .expect("serialize unknown selection"),
                            ))
                            .expect("unknown mock selection request"),
                    )
                    .await
                    .expect("unknown mock selection response");

            assert_eq!(unknown_response.status(), StatusCode::NOT_FOUND);
            let unknown_error = read_value_body(unknown_response).await;
            assert_eq!(
                unknown_error.get("message").and_then(Value::as_str),
                Some("requested resource was not found")
            );

            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("mock identity assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn mock_identity_routes_conflict_when_auth_mode_is_not_mock() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = AuthRouteFixture::insert(&pool).await;

        let result = async {
            let list_response = app_with_auth_mode(pool.clone(), AuthMode::Oidc, fixture.tenant_id)
                .oneshot(
                    Request::builder()
                        .uri("/v1/auth/mock-identities")
                        .body(Body::empty())
                        .expect("mock identity list request"),
                )
                .await
                .expect("mock identity list response");

            assert_eq!(list_response.status(), StatusCode::CONFLICT);
            let list_error = read_value_body(list_response).await;
            assert_eq!(
                list_error.get("message").and_then(Value::as_str),
                Some("mock identities are unavailable when auth mode is oidc")
            );

            let select_response =
                app_with_auth_mode(pool.clone(), AuthMode::Saml, fixture.tenant_id)
                    .oneshot(
                        Request::builder()
                            .method("PUT")
                            .uri("/v1/auth/session/mock")
                            .header("content-type", "application/json")
                            .body(Body::from(
                                serde_json::to_vec(&SetMockAuthSessionRequest {
                                    identity_id: "platform-admin".to_owned(),
                                })
                                .expect("serialize saml selection"),
                            ))
                            .expect("mock identity select request"),
                    )
                    .await
                    .expect("mock identity select response");

            assert_eq!(select_response.status(), StatusCode::CONFLICT);
            let select_error = read_value_body(select_response).await;
            assert_eq!(
                select_error.get("message").and_then(Value::as_str),
                Some("mock identities are unavailable when auth mode is saml")
            );

            let session_response =
                app_with_auth_mode(pool.clone(), AuthMode::Oidc, fixture.tenant_id)
                    .oneshot(
                        Request::builder()
                            .uri("/v1/auth/session")
                            .body(Body::empty())
                            .expect("enterprise session request"),
                    )
                    .await
                    .expect("enterprise session response");

            assert_eq!(session_response.status(), StatusCode::OK);
            let session: AuthSessionResponse = read_json_body(session_response).await;
            assert!(!session.authenticated);
            assert_eq!(session.auth_mode, AuthMode::Oidc);
            assert!(!session.mock_identity_supported);
            assert!(session.subject.is_none());

            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("auth mode conflict assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn audit_events_route_enriches_actor_display_and_roles() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;
        let audit_event_id = Uuid::now_v7();

        sqlx::query(
            r#"
            INSERT INTO audit_events (
                id, tenant_id, actor, action, resource, trace_id, metadata, occurred_at
            )
            VALUES ($1, $2, $3, 'registry-config.updated', 'registry-config/rbac-audit', 'trace-audit-actor', $4, $5)
            "#,
        )
        .bind(audit_event_id)
        .bind(fixture.tenant_id)
        .bind(actor_label(fixture.admin_user_id))
        .bind(json!({ "source": "contract-test" }))
        .bind(ts(2026, 5, 10, 18, 0, 0))
        .execute(&pool)
        .await
        .expect("insert actor-backed audit event");

        let result = async {
            let response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "/v1/tenants/{}/audit-events?actor={}",
                            fixture.tenant_id,
                            actor_label(fixture.admin_user_id)
                        ))
                        .header(ACTOR_HEADER, fixture.admin_user_id.to_string())
                        .body(Body::empty())
                        .expect("audit events request"),
                )
                .await
                .expect("audit events response");

            assert_eq!(response.status(), StatusCode::OK);
            let events: Vec<AuditEventResponse> = read_json_body(response).await;
            let event = events
                .iter()
                .find(|event| event.id == audit_event_id)
                .expect("expected inserted audit event");
            assert_eq!(event.actor, actor_label(fixture.admin_user_id));
            assert_eq!(event.actor_display, "Fixture Admin");
            assert_eq!(event.actor_roles, vec!["admin".to_owned()]);

            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("audit event enrichment assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn audit_events_csv_export_returns_filtered_csv() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;

        let result = async {
            let response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "/v1/tenants/{}/audit-events/export.csv?action=analysis.summary.completed&limit=10",
                            fixture.tenant_id
                        ))
                        .header(ACTOR_HEADER, fixture.admin_user_id.to_string())
                        .body(Body::empty())
                        .expect("audit csv export request"),
                )
                .await
                .expect("audit csv export response");

            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok()),
                Some("text/csv; charset=utf-8")
            );
            assert!(response
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .contains("audit-events-"));

            let body = String::from_utf8(
                to_bytes(response.into_body(), usize::MAX)
                    .await
                    .expect("read csv body")
                    .to_vec(),
            )
            .expect("decode csv body");
            assert!(body.starts_with(
                "occurred_at,action,actor,actor_display,actor_roles,resource,trace_id,metadata"
            ));
            assert!(body.contains("analysis.summary.completed"));
            assert!(!body.contains("analysis.evidence.persisted"));
            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("audit csv export assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn llm_usage_route_returns_aggregates_and_failing_traces() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;

        let result = async {
            let provider_config_id = Uuid::now_v7();
            let full_explanation_id = Uuid::now_v7();
            let degraded_explanation_id = Uuid::now_v7();

            sqlx::query(
                r#"
                INSERT INTO ai_provider_configs (
                    id, tenant_id, display_name, provider_type, base_url,
                    model_id, credential_ref, is_local, active
                )
                VALUES (
                    $1, $2, 'OpenRouter Primary', 'openrouter',
                    'https://openrouter.ai/api/v1', 'openai/o4-mini', NULL, false, true
                )
                "#,
            )
            .bind(provider_config_id)
            .bind(fixture.tenant_id)
            .execute(&pool)
            .await
            .expect("insert ai provider config");

            sqlx::query(
                r#"
                INSERT INTO ai_explanations (
                    id, analysis_job_id, provider_config_id, langfuse_trace_id,
                    prompt_template_version, redaction_complete, schema_valid, explanation, created_at
                )
                VALUES
                    ($1, $2, $3, 'langfuse-trace-full', 'analysis-preview-v1', true, true, $4, $5),
                    ($6, $7, $8, 'langfuse-trace-failed', 'analysis-preview-v1', false, false, $9, $10)
                "#,
            )
            .bind(full_explanation_id)
            .bind(fixture.full_job_id)
            .bind(provider_config_id)
            .bind(json!({
                "provider": "OpenRouter Primary",
                "model": "openai/o4-mini",
                "prompt_template_version": "analysis-preview-v1",
                "observed_behavior": ["sandbox observed outbound traffic"],
                "inference": ["maintain quarantine"],
                "limitations": ["AI output is advisory only."],
                "advisory_only": true,
                "evidence_hash": { "algorithm": "sha256", "hex": repeat_hex('a') },
                "output_hash": { "algorithm": "sha256", "hex": repeat_hex('b') },
                "langfuse_trace_id": "langfuse-trace-full"
            }))
            .bind(ts(2026, 5, 5, 10, 14, 30))
            .bind(degraded_explanation_id)
            .bind(fixture.degraded_job_id)
            .bind(provider_config_id)
            .bind(json!({
                "provider": "OpenRouter Primary",
                "model": "openai/o4-mini",
                "prompt_template_version": "analysis-preview-v1",
                "observed_behavior": ["redaction failed before final explanation"],
                "inference": ["manual review required"],
                "limitations": ["AI output is advisory only."],
                "advisory_only": true,
                "evidence_hash": { "algorithm": "sha256", "hex": repeat_hex('c') },
                "output_hash": { "algorithm": "sha256", "hex": repeat_hex('d') },
                "langfuse_trace_id": "langfuse-trace-failed"
            }))
            .bind(ts(2026, 5, 6, 10, 0, 0))
            .execute(&pool)
            .await
            .expect("insert llm usage explanations");

            sqlx::query(
                r#"
                INSERT INTO llm_usage_events (
                    tenant_id, analysis_job_id, artifact_id, ai_explanation_id, provider_config_id,
                    trace_id, provider_display_name, provider_type, model_id, langfuse_trace_id,
                    prompt_template_version, prompt_tokens, completion_tokens, total_tokens,
                    estimated_cost, latency_ms, schema_valid, redaction_complete,
                    evidence_hash, output_hash, created_at
                )
                VALUES
                    ($1, $2, $3, $4, $5, 'trace-quarantine-full', 'OpenRouter Primary', 'openrouter', 'openai/o4-mini', 'langfuse-trace-full', 'analysis-preview-v1', 194, 38, 232, 0.00042, 812.5, true, true, $6, $7, $8),
                    ($9, $10, $11, $12, $13, 'trace-hitl-empty', 'OpenRouter Primary', 'openrouter', 'openai/o4-mini', 'langfuse-trace-failed', 'analysis-preview-v1', 120, 18, 138, 0.00024, 1250.0, false, false, $14, $15, $16)
                "#,
            )
            .bind(fixture.tenant_id)
            .bind(fixture.full_job_id)
            .bind(fixture.full_artifact_id)
            .bind(full_explanation_id)
            .bind(provider_config_id)
            .bind(repeat_hex('a'))
            .bind(repeat_hex('b'))
            .bind(ts(2026, 5, 5, 10, 15, 0))
            .bind(fixture.tenant_id)
            .bind(fixture.degraded_job_id)
            .bind(fixture.degraded_artifact_id)
            .bind(degraded_explanation_id)
            .bind(provider_config_id)
            .bind(repeat_hex('c'))
            .bind(repeat_hex('d'))
            .bind(ts(2026, 5, 6, 10, 0, 30))
            .execute(&pool)
            .await
            .expect("insert llm usage events");

            let response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/tenants/{}/llm-usage", fixture.tenant_id))
                        .header(ACTOR_HEADER, fixture.admin_user_id.to_string())
                        .body(Body::empty())
                        .expect("llm usage request"),
                )
                .await
                .expect("llm usage response");

            assert_eq!(response.status(), StatusCode::OK);
            let usage: LlmUsageResponse = read_json_body(response).await;
            assert_eq!(usage.tenant_id, fixture.tenant_id);
            assert_eq!(usage.summary.total_calls, 2);
            assert_eq!(usage.summary.prompt_tokens, 314);
            assert_eq!(usage.summary.completion_tokens, 56);
            assert_eq!(usage.summary.total_tokens, 370);
            assert_eq!(usage.summary.schema_validation_passes, 1);
            assert_eq!(usage.summary.schema_validation_failures, 1);
            assert_eq!(usage.summary.redaction_failures, 1);
            assert_eq!(usage.calls_by_day.len(), 2);
            assert_eq!(usage.provider_models.len(), 1);
            assert_eq!(usage.provider_models[0].total_calls, 2);
            assert_eq!(usage.provider_models[0].model_id, "openai/o4-mini");
            assert_eq!(usage.analysis_jobs.len(), 2);
            assert_eq!(usage.analysis_jobs[0].trace_id, "trace-hitl-empty");
            assert_eq!(usage.failing_traces.len(), 1);
            assert_eq!(usage.failing_traces[0].trace_id, "trace-hitl-empty");
            assert_eq!(usage.failing_traces[0].langfuse_trace_id.as_deref(), Some("langfuse-trace-failed"));
            assert_eq!(usage.prompt_template_versions.len(), 1);
            assert_eq!(usage.prompt_template_versions[0].prompt_template_version, "analysis-preview-v1");
            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("llm usage assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn policy_simulator_route_replays_recent_requests_against_a_target_profile() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;
        let registry_config_id = Uuid::now_v7();
        let package_request_one_id = Uuid::now_v7();
        let package_request_two_id = Uuid::now_v7();
        let simulated_policy_profile_id = fixture.simulated_policy_profile_id;
        let simulated_policy_version_id = fixture.simulated_policy_version_id;

        sqlx::query(
            r#"
            INSERT INTO registry_configs (
                id, tenant_id, name, description, adapter, upstream_url, mount_path,
                auth_type, mode, policy_profile_id, cache_ttl_seconds, verify_upstream_tls, enabled
            )
            VALUES (
                $1, $2, 'policy simulator registry', 'fixture replay registry', 'npm',
                'https://registry.example.invalid', '/proxy/policy-sim', 'none', 'enforce',
                $3, 300, TRUE, TRUE
            )
            "#,
        )
        .bind(registry_config_id)
        .bind(fixture.tenant_id)
        .bind(fixture.policy_profile_id)
        .execute(&pool)
        .await
        .expect("insert simulator registry config");

        sqlx::query(
            r#"
            INSERT INTO package_requests (
                id, tenant_id, registry_config_id, client_type, ecosystem, namespace,
                package_name, package_version, trace_id, requested_at
            )
            VALUES
                ($1, $2, $3, 'metadata', 'npm', NULL, 'left-pad', '1.3.0', 'trace-policy-one', $4),
                ($5, $6, $7, 'metadata', 'npm', NULL, 'fresh-postinstall', '0.1.0', 'trace-policy-two', $8)
            "#,
        )
        .bind(package_request_one_id)
        .bind(fixture.tenant_id)
        .bind(registry_config_id)
        .bind(ts(2026, 5, 8, 9, 0, 0))
        .bind(package_request_two_id)
        .bind(fixture.tenant_id)
        .bind(registry_config_id)
        .bind(ts(2026, 5, 8, 9, 5, 0))
        .execute(&pool)
        .await
        .expect("insert simulator package requests");

        sqlx::query(
            r#"
            INSERT INTO policy_decisions (
                tenant_id, package_request_id, artifact_id, policy_version_id, decision,
                feed_state, feed_snapshot_age_seconds, rationale, trace_id, decided_at
            )
            VALUES
                ($1, $2, NULL, $3, 'ALLOW', 'fresh', 12, $4, 'trace-policy-one', $5),
                ($6, $7, NULL, $8, 'BLOCK_POLICY_VIOLATION', 'fresh', 9, $9, 'trace-policy-two', $10)
            "#,
        )
        .bind(fixture.tenant_id)
        .bind(package_request_one_id)
        .bind(fixture.policy_version_id)
        .bind(json!({
            "rationale": ["no blocking policy signal matched"],
            "coordinate": {
                "ecosystem": "npm",
                "name": "left-pad",
                "version": "1.3.0"
            },
            "requested_digest": Value::Null,
            "evidence_references": []
        }))
        .bind(ts(2026, 5, 8, 9, 0, 30))
        .bind(fixture.tenant_id)
        .bind(package_request_two_id)
        .bind(fixture.policy_version_id)
        .bind(json!({
            "rationale": ["static analysis score exceeded the configured policy threshold"],
            "coordinate": {
                "ecosystem": "npm",
                "name": "fresh-postinstall",
                "version": "0.1.0"
            },
            "requested_digest": Value::Null,
            "evidence_references": []
        }))
        .bind(ts(2026, 5, 8, 9, 5, 30))
        .execute(&pool)
        .await
        .expect("insert simulator policy decisions");

        let decision_client = DecisionClient::new_test(move |request| {
            let (decision, rationale) = match request.request.coordinate.name.as_str() {
                "left-pad" => (
                    PolicyDecision::AllowWithWarning,
                    vec!["install or lifecycle script requires review".to_owned()],
                ),
                _ => (
                    PolicyDecision::BlockPolicyViolation,
                    vec![
                        "static analysis score exceeded the configured policy threshold".to_owned(),
                    ],
                ),
            };
            Ok(DecisionResponse {
                decision,
                tenant_id: request.tenant_id,
                policy_profile_id: request.policy_profile_id,
                policy_snapshot_id: simulated_policy_version_id,
                mode: PolicyMode::Shadow,
                feed_state: FeedState::Fresh,
                feed_snapshot_age_seconds: 6,
                trace_id: request.request.trace_id.clone(),
                rationale,
                fallback_coordinate: None,
                create_analysis_job: false,
            })
        });

        let result = async {
            let response = app_with_clients(pool.clone(), None, decision_client)
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!(
                            "/v1/tenants/{}/policy-simulator/replay",
                            fixture.tenant_id
                        ))
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&PolicySimulationRequest {
                                policy_profile_id: simulated_policy_profile_id,
                                lookback_days: 30,
                                ecosystem: Some(PackageEcosystem::Npm),
                                limit: 10,
                            })
                            .expect("serialize policy simulation request"),
                        ))
                        .expect("policy simulation request"),
                )
                .await
                .expect("policy simulation response");

            assert_eq!(response.status(), StatusCode::OK);
            let body: PolicySimulationResponse = read_json_body(response).await;
            assert_eq!(body.target_policy_profile_id, simulated_policy_profile_id);
            assert_eq!(body.target_latest_version_id, simulated_policy_version_id);
            assert_eq!(body.target_policy_mode, PolicyMode::Shadow);
            assert_eq!(body.replayed_request_count, 2);
            assert_eq!(body.changed_request_count, 1);
            assert_eq!(body.baseline_counts.allow, 1);
            assert_eq!(body.baseline_counts.block_policy_violation, 1);
            assert_eq!(body.simulated_counts.allow_with_warning, 1);
            assert_eq!(body.simulated_counts.block_policy_violation, 1);
            assert_eq!(body.items.len(), 2);

            assert_eq!(body.items[0].coordinate.name, "left-pad");
            assert!(body.items[0].changed);
            assert_eq!(body.items[0].baseline_decision, PolicyDecision::Allow);
            assert_eq!(
                body.items[0].simulated_decision,
                PolicyDecision::AllowWithWarning
            );

            assert_eq!(body.items[1].coordinate.name, "fresh-postinstall");
            assert!(!body.items[1].changed);
            assert_eq!(
                body.items[1].baseline_decision,
                PolicyDecision::BlockPolicyViolation
            );
            assert_eq!(
                body.items[1].simulated_decision,
                PolicyDecision::BlockPolicyViolation
            );
            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("policy simulation assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn quarantine_queue_route_returns_only_reviewable_items_for_the_tenant() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;

        let result = async {
            let response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "/v1/tenants/{}/analysis/quarantine-queue",
                            fixture.tenant_id
                        ))
                        .body(Body::empty())
                        .expect("queue request"),
                )
                .await
                .expect("queue response");

            assert_eq!(response.status(), StatusCode::OK);

            let items: Vec<QuarantineQueueItemResponse> = read_json_body(response).await;
            assert_eq!(items.len(), 2);

            assert_eq!(items[0].analysis_job_id, fixture.degraded_job_id);
            assert_eq!(items[0].trace_id, "trace-hitl-empty");
            assert_eq!(items[0].recommended_action, "REQUIRE_HITL_APPROVAL");
            assert!(items[0].requires_hitl);
            assert_eq!(
                items[0].evidence_counts,
                EvidenceCountsResponse {
                    static_reports: 0,
                    sandbox_runs: 0,
                    ai_explanations: 0,
                    audit_events: 0,
                }
            );

            assert_eq!(items[1].analysis_job_id, fixture.full_job_id);
            assert_eq!(items[1].trace_id, "trace-quarantine-full");
            assert_eq!(items[1].coordinate.name, "fresh-postinstall");
            assert_eq!(items[1].recommended_action, "QUARANTINE_PENDING_ANALYSIS");
            assert_eq!(
                items[1].evidence_counts,
                EvidenceCountsResponse {
                    static_reports: 1,
                    sandbox_runs: 1,
                    ai_explanations: 1,
                    audit_events: 2,
                }
            );
            assert!(
                items
                    .iter()
                    .all(|item| item.artifact_id != fixture.allow_artifact_id)
            );
            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("queue assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn tenant_sbom_list_route_requires_actor_and_omits_storage_metadata() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;
        let sbom_id = Uuid::now_v7();

        let result = async {
            let app = app_with_auth_mode_and_sbom_client(
                pool.clone(),
                AuthMode::Oidc,
                fixture.tenant_id,
                SbomServiceClient::new_test(
                    move |tenant_id, limit| {
                        assert_eq!(tenant_id, fixture.tenant_id);
                        assert_eq!(limit, Some(5));
                        Ok(vec![SbomServiceDocumentSummary {
                            id: sbom_id,
                            analysis_job_id: Some(fixture.full_job_id),
                            tenant_id: Some(fixture.tenant_id),
                            format: "cyclonedx-1.7-json".to_owned(),
                            source: "Cargo.lock".to_owned(),
                            component_count: 42,
                            storage_size_bytes: 4096,
                            created_at: ts(2026, 5, 13, 18, 0, 0),
                            ntia_validation: SbomServiceNtiaValidation {
                                valid: false,
                                issues: vec!["missing metadata.component.name".to_owned()],
                            },
                        }])
                    },
                    |_, _| panic!("sbom download should not be called in list test"),
                ),
            );

            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/tenants/{}/sboms?limit=5", fixture.tenant_id))
                        .header(ACTOR_HEADER, fixture.admin_user_id.to_string())
                        .body(Body::empty())
                        .expect("sbom list request"),
                )
                .await
                .expect("sbom list response");

            assert_eq!(response.status(), StatusCode::OK);
            let body = read_value_body(response).await;
            let documents = body.as_array().expect("list response array");
            assert_eq!(documents.len(), 1);
            let expected_id = sbom_id.to_string();
            assert_eq!(
                documents[0].get("id").and_then(Value::as_str),
                Some(expected_id.as_str())
            );
            assert_eq!(
                documents[0].get("source").and_then(Value::as_str),
                Some("Cargo.lock")
            );
            assert_eq!(documents[0].get("storage_uri"), None);
            assert_eq!(documents[0].get("storage_sha256"), None);

            let missing_actor = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/tenants/{}/sboms", fixture.tenant_id))
                        .body(Body::empty())
                        .expect("missing actor request"),
                )
                .await
                .expect("missing actor response");

            assert_eq!(missing_actor.status(), StatusCode::UNAUTHORIZED);

            let other_tenant_actor = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/tenants/{}/sboms?limit=5", fixture.tenant_id))
                        .header(ACTOR_HEADER, fixture.other_admin_user_id.to_string())
                        .body(Body::empty())
                        .expect("cross-tenant actor request"),
                )
                .await
                .expect("cross-tenant actor response");

            assert_eq!(other_tenant_actor.status(), StatusCode::FORBIDDEN);

            let invalid_limit = app
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/tenants/{}/sboms?limit=75", fixture.tenant_id))
                        .header(ACTOR_HEADER, fixture.admin_user_id.to_string())
                        .body(Body::empty())
                        .expect("invalid limit request"),
                )
                .await
                .expect("invalid limit response");

            assert_eq!(invalid_limit.status(), StatusCode::BAD_REQUEST);
            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("tenant sbom list assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn tenant_sbom_download_route_requires_actor_and_preserves_headers() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;
        let sbom_id = Uuid::now_v7();

        let result = async {
            let app = app_with_auth_mode_and_sbom_client(
                pool.clone(),
                AuthMode::Oidc,
                fixture.tenant_id,
                SbomServiceClient::new_test(
                    |_, _| panic!("sbom list should not be called in download test"),
                    move |tenant_id, requested_sbom_id| {
                        assert_eq!(tenant_id, fixture.tenant_id);
                        assert_eq!(requested_sbom_id, sbom_id);
                        let mut headers = HeaderMap::new();
                        headers.insert(
                            header::CONTENT_TYPE,
                            HeaderValue::from_static("application/json"),
                        );
                        headers.insert(
                            header::CONTENT_DISPOSITION,
                            HeaderValue::from_static("attachment; filename=\"cargo-lock.json\""),
                        );
                        headers.insert(
                            header::CACHE_CONTROL,
                            HeaderValue::from_static("private, max-age=60"),
                        );
                        headers.insert(header::ETAG, HeaderValue::from_static("\"sbom-1\""));
                        Ok(SbomServiceDownload {
                            body: Body::from("{\"bomFormat\":\"CycloneDX\"}"),
                            headers,
                        })
                    },
                ),
            );

            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/tenants/{}/sboms/{sbom_id}", fixture.tenant_id))
                        .header(ACTOR_HEADER, fixture.admin_user_id.to_string())
                        .body(Body::empty())
                        .expect("sbom download request"),
                )
                .await
                .expect("sbom download response");

            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response
                    .headers()
                    .get(header::CONTENT_DISPOSITION)
                    .and_then(|value| value.to_str().ok()),
                Some("attachment; filename=\"cargo-lock.json\"")
            );
            assert_eq!(
                response
                    .headers()
                    .get(header::CACHE_CONTROL)
                    .and_then(|value| value.to_str().ok()),
                Some("private, max-age=60")
            );
            assert_eq!(
                response
                    .headers()
                    .get(header::ETAG)
                    .and_then(|value| value.to_str().ok()),
                Some("\"sbom-1\"")
            );
            let body = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("read sbom download body");
            assert_eq!(body.as_ref(), b"{\"bomFormat\":\"CycloneDX\"}");

            let missing_actor = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/tenants/{}/sboms/{sbom_id}", fixture.tenant_id))
                        .body(Body::empty())
                        .expect("missing actor download request"),
                )
                .await
                .expect("missing actor download response");

            assert_eq!(missing_actor.status(), StatusCode::UNAUTHORIZED);

            let other_tenant_actor = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/tenants/{}/sboms/{sbom_id}", fixture.tenant_id))
                        .header(ACTOR_HEADER, fixture.other_admin_user_id.to_string())
                        .body(Body::empty())
                        .expect("cross-tenant actor download request"),
                )
                .await
                .expect("cross-tenant actor download response");

            assert_eq!(other_tenant_actor.status(), StatusCode::FORBIDDEN);
            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("tenant sbom download assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn artifact_evidence_route_returns_joined_evidence_and_enforces_tenant_scope() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;

        let result = async {
            let response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "/v1/tenants/{}/artifacts/{}/evidence",
                            fixture.tenant_id, fixture.full_artifact_id
                        ))
                        .body(Body::empty())
                        .expect("evidence request"),
                )
                .await
                .expect("evidence response");

            assert_eq!(response.status(), StatusCode::OK);
            let evidence: ArtifactEvidenceResponse = read_json_body(response).await;
            assert_eq!(evidence.analysis_job_id, fixture.full_job_id);
            assert_eq!(evidence.trace_id, "trace-quarantine-full");
            assert_eq!(evidence.coordinate.name, "fresh-postinstall");
            assert_eq!(evidence.static_reports.len(), 1);
            assert_eq!(evidence.sandbox_runs.len(), 1);
            assert!(evidence.ai_explanation.is_some());
            assert_eq!(evidence.audit_events.len(), 2);
            assert_eq!(
                evidence.audit_events[0].action,
                "analysis.summary.completed"
            );
            assert_eq!(evidence.audit_events[1].trace_id, "trace-quarantine-full");

            let degraded_response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "/v1/tenants/{}/artifacts/{}/evidence",
                            fixture.tenant_id, fixture.degraded_artifact_id
                        ))
                        .body(Body::empty())
                        .expect("degraded evidence request"),
                )
                .await
                .expect("degraded evidence response");

            assert_eq!(degraded_response.status(), StatusCode::OK);
            let degraded: ArtifactEvidenceResponse = read_json_body(degraded_response).await;
            assert_eq!(degraded.analysis_job_id, fixture.degraded_job_id);
            assert!(degraded.static_reports.is_empty());
            assert!(degraded.sandbox_runs.is_empty());
            assert!(degraded.ai_explanation.is_none());
            assert!(degraded.audit_events.is_empty());

            let cross_tenant_response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "/v1/tenants/{}/artifacts/{}/evidence",
                            fixture.other_tenant_id, fixture.full_artifact_id
                        ))
                        .body(Body::empty())
                        .expect("cross-tenant evidence request"),
                )
                .await
                .expect("cross-tenant evidence response");

            assert_eq!(cross_tenant_response.status(), StatusCode::NOT_FOUND);
            let cross_tenant_error = read_value_body(cross_tenant_response).await;
            assert_eq!(
                cross_tenant_error.get("message").and_then(Value::as_str),
                Some("requested resource was not found")
            );

            let unknown_response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "/v1/tenants/{}/artifacts/{}/evidence",
                            fixture.tenant_id,
                            Uuid::now_v7()
                        ))
                        .body(Body::empty())
                        .expect("unknown evidence request"),
                )
                .await
                .expect("unknown evidence response");

            assert_eq!(unknown_response.status(), StatusCode::NOT_FOUND);
            let unknown_error = read_value_body(unknown_response).await;
            assert_eq!(
                unknown_error.get("message").and_then(Value::as_str),
                Some("requested resource was not found")
            );
            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("evidence assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn dedicated_report_routes_return_tenant_scoped_static_and_sandbox_payloads() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;

        let result = async {
            let static_response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "/v1/tenants/{}/artifacts/{}/static-analysis-reports",
                            fixture.tenant_id, fixture.full_artifact_id
                        ))
                        .body(Body::empty())
                        .expect("static report request"),
                )
                .await
                .expect("static report response");

            assert_eq!(static_response.status(), StatusCode::OK);
            let static_reports: ArtifactStaticAnalysisReportsResponse =
                read_json_body(static_response).await;
            assert_eq!(static_reports.analysis_job_id, fixture.full_job_id);
            assert_eq!(static_reports.reports.len(), 1);

            let sandbox_response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "/v1/tenants/{}/artifacts/{}/sandbox-execution-reports",
                            fixture.tenant_id, fixture.full_artifact_id
                        ))
                        .body(Body::empty())
                        .expect("sandbox report request"),
                )
                .await
                .expect("sandbox report response");

            assert_eq!(sandbox_response.status(), StatusCode::OK);
            let sandbox_reports: ArtifactSandboxExecutionReportsResponse =
                read_json_body(sandbox_response).await;
            assert_eq!(sandbox_reports.analysis_job_id, fixture.full_job_id);
            assert_eq!(sandbox_reports.runs.len(), 1);

            let cross_tenant_response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "/v1/tenants/{}/artifacts/{}/static-analysis-reports",
                            fixture.other_tenant_id, fixture.full_artifact_id
                        ))
                        .body(Body::empty())
                        .expect("cross tenant static report request"),
                )
                .await
                .expect("cross tenant static report response");

            assert_eq!(cross_tenant_response.status(), StatusCode::NOT_FOUND);
            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("dedicated report route assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn dashboard_metrics_route_returns_tenant_kpis() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;

        sqlx::query(
            r#"
            INSERT INTO feed_snapshots (
                tenant_id, feed_name, state, normalized_record_count, snapshot_digest, last_success_at, created_at
            )
            VALUES
                ($1, 'osv', 'fresh', 42, $2, $3, $3),
                ($1, 'known-malicious', 'fresh', 7, $4, $5, $5)
            "#,
        )
        .bind(fixture.tenant_id)
        .bind(repeat_hex('d'))
        .bind(Utc::now() - chrono::Duration::minutes(35))
        .bind(repeat_hex('e'))
        .bind(Utc::now() - chrono::Duration::hours(2))
        .execute(&pool)
        .await
        .expect("insert feed snapshots");

        let result = async {
            let response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "/v1/tenants/{}/analysis/dashboard-metrics",
                            fixture.tenant_id
                        ))
                        .body(Body::empty())
                        .expect("dashboard metrics request"),
                )
                .await
                .expect("dashboard metrics response");

            assert_eq!(response.status(), StatusCode::OK);

            let metrics: DashboardMetricsResponse = read_json_body(response).await;
            assert_eq!(metrics.blocked_packages, 0);
            assert_eq!(metrics.quarantine_queue_depth, 2);
            assert_eq!(metrics.active_overrides, 2);
            assert_eq!(metrics.feed_freshness, DashboardFeedFreshness::Fresh);
            assert!(metrics.feed_snapshot_age_seconds.is_some());
            assert!(metrics.feed_snapshot_age_seconds.unwrap() <= 7_200);
            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("dashboard metrics assertions");
    }

    #[test]
    fn validate_openvex_request_rejects_invalid_context() {
        let mut request = sample_openvex_import_request();
        request.document["@context"] = Value::String("https://example.invalid/openvex".to_owned());

        let error = validate_openvex_request(&request).unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid request: document.@context must be https://openvex.dev/ns/v0.2.0"
        );
    }

    #[test]
    fn validate_openvex_request_rejects_missing_products() {
        let mut request = sample_openvex_import_request();
        request.document["statements"][0]["products"] = json!([]);

        let error = validate_openvex_request(&request).unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid request: document.statements[0].products must contain at least one product"
        );
    }

    #[test]
    fn validate_openvex_request_rejects_duplicate_product_ids() {
        let mut request = sample_openvex_import_request();
        request.document["statements"][0]["products"] = json!([
            { "@id": "pkg:npm/left-pad@1.3.0" },
            { "@id": "pkg:npm/left-pad@1.3.0" }
        ]);

        let error = validate_openvex_request(&request).unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid request: document.statements[0].products[1].@id must be unique within the statement"
        );
    }

    #[test]
    fn validate_openvex_request_requires_not_affected_justification_or_impact_statement() {
        let mut request = sample_openvex_import_request();
        request.document["statements"][0]["justification"] = Value::Null;

        let error = validate_openvex_request(&request).unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid request: document.statements[0] with status not_affected must include justification or impact_statement"
        );
    }

    #[test]
    fn validate_openvex_request_rejects_unknown_justification() {
        let mut request = sample_openvex_import_request();
        request.document["statements"][0]["justification"] =
            Value::String("custom_reason".to_owned());

        let error = validate_openvex_request(&request).unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid request: document.statements[0].justification must be one of component_not_present, vulnerable_code_not_present, vulnerable_code_not_in_execute_path, vulnerable_code_cannot_be_controlled_by_adversary, inline_mitigations_already_exist"
        );
    }

    #[test]
    fn validate_openvex_request_requires_action_statement_for_affected_status() {
        let mut request = sample_openvex_import_request();
        request.document["statements"][0]["status"] = Value::String("affected".to_owned());
        request.document["statements"][0]["justification"] = Value::Null;

        let error = validate_openvex_request(&request).unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid request: document.statements[0] with status affected must include action_statement"
        );
    }

    #[test]
    fn validate_openvex_request_rejects_expires_at_policy_without_timestamp() {
        let request = CreateOpenVexDocumentRequest {
            source: "fixture-openvex.json".to_owned(),
            document: sample_openvex_document(),
            expiry_policy: OpenVexExpiryPolicyRequest {
                mode: OpenVexExpiryMode::ExpiresAt,
                expires_at: None,
            },
        };

        let error = validate_openvex_request(&request).unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid request: expiry_policy.expires_at is required when mode is expires-at"
        );
    }

    #[test]
    fn validate_openvex_request_allows_already_expired_policy() {
        let mut request = sample_openvex_import_request();
        request.expiry_policy.expires_at = Some(ts(2024, 1, 1, 0, 0, 0));

        let validated =
            validate_openvex_request(&request).expect("expired request should still validate");

        assert_eq!(
            validated.document_id,
            "https://fixtures.aegiscudo.invalid/openvex/acme-2026-001"
        );
        assert_eq!(validated.statement_count, 2);
    }

    #[test]
    fn validate_openvex_request_allows_statement_history_for_same_vulnerability_and_product() {
        let mut request = sample_openvex_import_request();
        request.document["version"] = json!(2);
        request.document["statements"] = json!([
            {
                "vulnerability": { "name": "CVE-2026-0001" },
                "products": [
                    { "@id": "pkg:npm/left-pad@1.3.0" }
                ],
                "status": "under_investigation",
                "timestamp": "2026-05-11T23:59:59Z"
            },
            {
                "vulnerability": { "name": "CVE-2026-0001" },
                "products": [
                    { "@id": "pkg:npm/left-pad@1.3.0" }
                ],
                "status": "fixed",
                "action_statement": "Patched in upstream release 1.3.0"
            }
        ]);

        let validated =
            validate_openvex_request(&request).expect("statement history should validate");

        assert_eq!(validated.statement_count, 2);
        assert_eq!(validated.statements.len(), 2);
        assert_eq!(validated.statements[0].status, "under_investigation");
        assert_eq!(validated.statements[1].status, "fixed");
        assert_eq!(
            validated.statements[0].product_id,
            validated.statements[1].product_id
        );
        assert_eq!(
            validated.statements[0].vulnerability_id,
            validated.statements[1].vulnerability_id
        );
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn openvex_document_routes_require_override_manager() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;

        let result = async {
            let request = sample_openvex_import_request();
            let uri = format!("/v1/tenants/{}/openvex-documents", fixture.tenant_id);

            let missing_actor = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(&uri)
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&request).expect("serialize openvex request"),
                        ))
                        .expect("missing actor openvex request"),
                )
                .await
                .expect("missing actor openvex response");
            assert_eq!(missing_actor.status(), StatusCode::UNAUTHORIZED);

            let developer = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(&uri)
                        .header(ACTOR_HEADER, fixture.developer_user_id.to_string())
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&request).expect("serialize openvex request"),
                        ))
                        .expect("developer openvex request"),
                )
                .await
                .expect("developer openvex response");
            assert_eq!(developer.status(), StatusCode::FORBIDDEN);

            let admin = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(&uri)
                        .header(ACTOR_HEADER, fixture.admin_user_id.to_string())
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&request).expect("serialize openvex request"),
                        ))
                        .expect("admin openvex request"),
                )
                .await
                .expect("admin openvex response");
            assert_eq!(admin.status(), StatusCode::OK);

            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("openvex route authorization assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn create_openvex_document_persists_document_statements_and_audit_event() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;

        let result = async {
            let response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/v1/tenants/{}/openvex-documents", fixture.tenant_id))
                        .header(ACTOR_HEADER, fixture.admin_user_id.to_string())
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&sample_openvex_import_request())
                                .expect("serialize openvex request"),
                        ))
                        .expect("create openvex request"),
                )
                .await
                .expect("create openvex response");
            assert_eq!(response.status(), StatusCode::OK);

            let created: OpenVexDocumentResponse = read_json_body(response).await;
            assert_eq!(created.summary.tenant_id, fixture.tenant_id);
            assert_eq!(created.summary.source, "fixture-openvex.json");
            assert_eq!(created.summary.statement_count, 2);
            assert_eq!(created.summary.expiry_policy.mode, OpenVexExpiryMode::ExpiresAt);

            let stored_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM openvex_documents WHERE tenant_id = $1 AND id = $2",
            )
            .bind(fixture.tenant_id)
            .bind(created.summary.id)
            .fetch_one(&pool)
            .await?;
            assert_eq!(stored_count, 1);

            let statement_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM openvex_statements WHERE tenant_id = $1 AND openvex_document_id = $2",
            )
            .bind(fixture.tenant_id)
            .bind(created.summary.id)
            .fetch_one(&pool)
            .await?;
            assert_eq!(statement_count, 2);

            let audit_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM audit_events WHERE tenant_id = $1 AND action = 'openvex.document.imported' AND resource = $2",
            )
            .bind(fixture.tenant_id)
            .bind(format!("openvex-document/{}", created.summary.id))
            .fetch_one(&pool)
            .await?;
            assert_eq!(audit_count, 1);

            let listed = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/tenants/{}/openvex-documents", fixture.tenant_id))
                        .header(ACTOR_HEADER, fixture.admin_user_id.to_string())
                        .body(Body::empty())
                        .expect("list openvex request"),
                )
                .await
                .expect("list openvex response");
            assert_eq!(listed.status(), StatusCode::OK);
            let listed_documents: Vec<OpenVexDocumentSummaryResponse> = read_json_body(listed).await;
            assert_eq!(listed_documents.len(), 1);
            assert_eq!(listed_documents[0].id, created.summary.id);

            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("openvex persistence assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn get_openvex_document_is_tenant_scoped() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;

        let result = async {
            let create_response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!(
                            "/v1/tenants/{}/openvex-documents",
                            fixture.tenant_id
                        ))
                        .header(ACTOR_HEADER, fixture.admin_user_id.to_string())
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&sample_openvex_import_request())
                                .expect("serialize openvex request"),
                        ))
                        .expect("create openvex request"),
                )
                .await
                .expect("create openvex response");
            assert_eq!(create_response.status(), StatusCode::OK);
            let created: OpenVexDocumentResponse = read_json_body(create_response).await;

            let own_response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "/v1/tenants/{}/openvex-documents/{}",
                            fixture.tenant_id, created.summary.id
                        ))
                        .header(ACTOR_HEADER, fixture.admin_user_id.to_string())
                        .body(Body::empty())
                        .expect("own openvex get request"),
                )
                .await
                .expect("own openvex get response");
            assert_eq!(own_response.status(), StatusCode::OK);

            let cross_tenant_response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "/v1/tenants/{}/openvex-documents/{}",
                            fixture.other_tenant_id, created.summary.id
                        ))
                        .header(ACTOR_HEADER, fixture.other_admin_user_id.to_string())
                        .body(Body::empty())
                        .expect("cross-tenant openvex get request"),
                )
                .await
                .expect("cross-tenant openvex get response");
            assert_eq!(cross_tenant_response.status(), StatusCode::NOT_FOUND);

            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("openvex tenant scoping assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn list_openvex_documents_is_tenant_scoped() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;

        let result = async {
            let create_response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!(
                            "/v1/tenants/{}/openvex-documents",
                            fixture.tenant_id
                        ))
                        .header(ACTOR_HEADER, fixture.admin_user_id.to_string())
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&sample_openvex_import_request())
                                .expect("serialize openvex request"),
                        ))
                        .expect("create openvex request"),
                )
                .await
                .expect("create openvex response");
            assert_eq!(create_response.status(), StatusCode::OK);

            let own_response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "/v1/tenants/{}/openvex-documents",
                            fixture.tenant_id
                        ))
                        .header(ACTOR_HEADER, fixture.admin_user_id.to_string())
                        .body(Body::empty())
                        .expect("own openvex list request"),
                )
                .await
                .expect("own openvex list response");
            assert_eq!(own_response.status(), StatusCode::OK);
            let own_documents: Vec<OpenVexDocumentSummaryResponse> =
                read_json_body(own_response).await;
            assert_eq!(own_documents.len(), 1);

            let cross_tenant_response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "/v1/tenants/{}/openvex-documents",
                            fixture.other_tenant_id
                        ))
                        .header(ACTOR_HEADER, fixture.other_admin_user_id.to_string())
                        .body(Body::empty())
                        .expect("cross-tenant openvex list request"),
                )
                .await
                .expect("cross-tenant openvex list response");
            assert_eq!(cross_tenant_response.status(), StatusCode::OK);
            let cross_tenant_documents: Vec<OpenVexDocumentSummaryResponse> =
                read_json_body(cross_tenant_response).await;
            assert!(cross_tenant_documents.is_empty());

            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("openvex list tenant scoping assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn create_openvex_document_rejects_malformed_document() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;

        let result = async {
            let mut request = sample_openvex_import_request();
            request.document["@context"] =
                Value::String("https://example.invalid/openvex".to_owned());

            let response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!(
                            "/v1/tenants/{}/openvex-documents",
                            fixture.tenant_id
                        ))
                        .header(ACTOR_HEADER, fixture.admin_user_id.to_string())
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&request)
                                .expect("serialize malformed openvex request"),
                        ))
                        .expect("malformed openvex request"),
                )
                .await
                .expect("malformed openvex response");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);

            let body: ErrorBody = read_json_body(response).await;
            assert!(
                body.message
                    .contains("document.@context must be https://openvex.dev/ns/v0.2.0")
            );

            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("openvex malformed route assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn create_openvex_document_preserves_expired_policy() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;

        let result = async {
            let mut request = sample_openvex_import_request();
            let expired_at = ts(2024, 1, 1, 0, 0, 0);
            request.expiry_policy.expires_at = Some(expired_at);

            let response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!(
                            "/v1/tenants/{}/openvex-documents",
                            fixture.tenant_id
                        ))
                        .header(ACTOR_HEADER, fixture.admin_user_id.to_string())
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&request)
                                .expect("serialize expired openvex request"),
                        ))
                        .expect("expired openvex request"),
                )
                .await
                .expect("expired openvex response");
            assert_eq!(response.status(), StatusCode::OK);

            let created: OpenVexDocumentResponse = read_json_body(response).await;
            assert_eq!(
                created.summary.expiry_policy.mode,
                OpenVexExpiryMode::ExpiresAt
            );
            assert_eq!(created.summary.expiry_policy.expires_at, Some(expired_at));

            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("openvex expired policy assertions");
    }

    fn sample_openvex_import_request() -> CreateOpenVexDocumentRequest {
        CreateOpenVexDocumentRequest {
            source: "fixture-openvex.json".to_owned(),
            document: sample_openvex_document(),
            expiry_policy: OpenVexExpiryPolicyRequest {
                mode: OpenVexExpiryMode::ExpiresAt,
                expires_at: Some(ts(2026, 5, 31, 12, 0, 0)),
            },
        }
    }

    fn sample_openvex_document() -> Value {
        json!({
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://fixtures.aegiscudo.invalid/openvex/acme-2026-001",
            "author": "Aegiscudo Fixture Suite",
            "timestamp": "2026-05-12T08:00:00Z",
            "version": 1,
            "statements": [
                {
                    "vulnerability": { "name": "CVE-2026-0001" },
                    "products": [
                        { "@id": "pkg:npm/left-pad@1.3.0" }
                    ],
                    "status": "not_affected",
                    "justification": "component_not_present"
                },
                {
                    "vulnerability": { "name": "CVE-2026-0002" },
                    "products": [
                        { "@id": "pkg:pypi/requests@2.31.0" }
                    ],
                    "status": "fixed",
                    "action_statement": "Patched in upstream release 2.31.0",
                    "timestamp": "2026-05-12T08:05:00Z"
                }
            ]
        })
    }

    async fn read_json_body<T>(response: Response) -> T
    where
        T: DeserializeOwned,
    {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        serde_json::from_slice(&bytes).expect("decode json body")
    }

    async fn read_value_body(response: Response) -> Value {
        read_json_body::<Value>(response).await
    }

    fn test_database_url() -> String {
        std::env::var("DATABASE_URL").unwrap_or_else(|_| TEST_DATABASE_URL.to_owned())
    }

    fn app_with_auth_mode(pool: PgPool, auth_mode: AuthMode, local_auth_tenant_id: Uuid) -> Router {
        app_with_auth_mode_and_sbom_client(
            pool,
            auth_mode,
            local_auth_tenant_id,
            SbomServiceClient::new_test(
                |_, _| panic!("sbom client list should not be called in this test"),
                |_, _| panic!("sbom client download should not be called in this test"),
            ),
        )
    }

    fn app_with_auth_mode_and_sbom_client(
        pool: PgPool,
        auth_mode: AuthMode,
        local_auth_tenant_id: Uuid,
        sbom_client: SbomServiceClient,
    ) -> Router {
        app_with_clients_and_auth_config(
            pool,
            None,
            DecisionClient::new_test(|_| panic!("decision client should not be called")),
            sbom_client,
            auth_mode,
            local_auth_tenant_id,
        )
    }

    fn repeat_hex(character: char) -> String {
        std::iter::repeat_n(character, 64).collect()
    }

    fn ts(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
            .single()
            .expect("valid timestamp")
    }

    #[test]
    fn override_scope_allows_only_policy_keys() {
        validate_override_scope(&json!({
            "ecosystem": "npm",
            "name": "left-pad",
            "version": "1.3.0",
            "kind": "artifact",
            "effect": "allow"
        }))
        .expect("valid scope");

        assert!(matches!(
            validate_override_scope(&json!({ "name": "left-pad", "token": "nope" })),
            Err(ApiError::InvalidRequest(_))
        ));
    }

    #[test]
    fn emergency_bypass_is_only_supported_override_effect() {
        validate_override_scope(&json!({ "effect": "emergency-bypass" })).expect("valid effect");
        assert!(matches!(
            validate_override_scope(&json!({ "effect": "forever-allow" })),
            Err(ApiError::InvalidRequest(_))
        ));
    }

    #[test]
    fn registry_validation_rejects_non_phase_1a_adapter() {
        let request = CreateRegistryConfigRequest {
            name: "cargo".to_owned(),
            description: String::new(),
            adapter: RegistryAdapterDto::Cargo,
            upstream_url: "https://example.invalid".to_owned(),
            mount_path: "/proxy/cargo".to_owned(),
            auth_type: CredentialAuthTypeDto::None,
            credential_ref: None,
            mode: PolicyMode::Enforce,
            policy_profile_id: Uuid::now_v7(),
            cache_ttl_seconds: 300,
            verify_upstream_tls: true,
            enabled: true,
        };

        assert!(matches!(
            validate_registry_create_request(&request),
            Err(ApiError::InvalidRequest(_))
        ));
    }

    #[test]
    fn registry_validation_rejects_insecure_authenticated_upstream() {
        let request = CreateRegistryConfigRequest {
            name: "private-npm".to_owned(),
            description: String::new(),
            adapter: RegistryAdapterDto::Npm,
            upstream_url: "http://registry.example.invalid".to_owned(),
            mount_path: "/proxy/private-npm".to_owned(),
            auth_type: CredentialAuthTypeDto::Bearer,
            credential_ref: Some(Uuid::now_v7()),
            mode: PolicyMode::Enforce,
            policy_profile_id: Uuid::now_v7(),
            cache_ttl_seconds: 300,
            verify_upstream_tls: true,
            enabled: true,
        };

        assert!(matches!(
            validate_registry_create_request(&request),
            Err(ApiError::InvalidRequest(_))
        ));
    }

    #[test]
    fn registry_validation_requires_canonical_proxy_mount() {
        assert!(validate_mount_path("/proxy/npm-fixtures").is_ok());
        assert!(matches!(
            validate_mount_path("/npm-fixtures"),
            Err(ApiError::InvalidRequest(_))
        ));
        assert!(matches!(
            validate_mount_path("/proxy/npm-fixtures/"),
            Err(ApiError::InvalidRequest(_))
        ));
    }

    #[test]
    fn only_control_plane_roles_can_manage_overrides_and_registry() {
        assert!(role_can_manage_control_plane("admin"));
        assert!(role_can_manage_control_plane("security-specialist"));
        assert!(!role_can_manage_control_plane("developer"));
    }

    #[test]
    fn only_admin_roles_can_view_llm_usage() {
        assert!(role_can_view_llm_usage("admin"));
        assert!(role_can_view_llm_usage("platform-admin"));
        assert!(!role_can_view_llm_usage("security-specialist"));
        assert!(!role_can_view_llm_usage("auditor"));
    }

    // --- Override field validation unit tests (P14) -------------------------

    #[test]
    fn validate_override_reason_rejects_short_reason() {
        assert!(matches!(
            validate_override_reason("tiny"),
            Err(ApiError::InvalidRequest(_))
        ));
        validate_override_reason("at least eight chars ok").expect("long enough reason");
    }

    #[test]
    fn validate_override_expiry_rejects_past_timestamp() {
        let past = Utc::now() - chrono::Duration::seconds(60);
        assert!(matches!(
            validate_override_expiry(past),
            Err(ApiError::InvalidRequest(_))
        ));
        let future = Utc::now() + chrono::Duration::hours(24);
        validate_override_expiry(future).expect("future expiry accepted");
    }

    #[test]
    fn validate_override_scope_rejects_non_object() {
        assert!(matches!(
            validate_override_scope(&json!("not-an-object")),
            Err(ApiError::InvalidRequest(_))
        ));
    }

    #[test]
    fn validate_override_scope_rejects_unsupported_effect() {
        assert!(matches!(
            validate_override_scope(&json!({ "effect": "always-allow" })),
            Err(ApiError::InvalidRequest(_))
        ));
    }

    #[test]
    fn validate_override_scope_rejects_unsupported_kind() {
        assert!(matches!(
            validate_override_scope(&json!({ "kind": "source-tarball" })),
            Err(ApiError::InvalidRequest(_))
        ));
    }

    #[tokio::test]
    async fn create_override_missing_required_fields_returns_422() {
        // JSON deserialization failure (missing required fields) must return 422
        // before any database interaction occurs.
        let pool = PgPoolOptions::new()
            .connect_lazy(&test_database_url())
            .expect("create lazy test db pool");
        let tenant_id = Uuid::now_v7();

        // Missing `scope` field
        let response = app_with_auth_mode(pool.clone(), AuthMode::MockOidc, tenant_id)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/tenants/{tenant_id}/overrides"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "reason": "missing scope field", "expires_at": "2099-01-01T00:00:00Z" })
                            .to_string(),
                    ))
                    .expect("override request"),
            )
            .await
            .expect("override response");
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        // Missing `reason` field
        let response = app_with_auth_mode(pool.clone(), AuthMode::MockOidc, tenant_id)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/tenants/{tenant_id}/overrides"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "scope": {}, "expires_at": "2099-01-01T00:00:00Z" }).to_string(),
                    ))
                    .expect("override request"),
            )
            .await
            .expect("override response");
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        // Missing `expires_at` field
        let response = app_with_auth_mode(pool, AuthMode::MockOidc, tenant_id)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/tenants/{tenant_id}/overrides"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "scope": {}, "reason": "some reason here" }).to_string(),
                    ))
                    .expect("override request"),
            )
            .await
            .expect("override response");
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn create_override_produces_audit_event() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;

        let result = async {
            let expires_at = "2099-06-01T10:00:00Z";
            let response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/v1/tenants/{}/overrides", fixture.tenant_id))
                        .header("content-type", "application/json")
                        .body(Body::from(
                            json!({
                                "scope": {
                                    "ecosystem": "npm",
                                    "name": "audit-test-pkg",
                                    "version": "1.0.0",
                                    "kind": "metadata",
                                    "effect": "allow"
                                },
                                "reason": "Audit event contract test — temporary allow",
                                "requested_by": fixture.admin_user_id,
                                "expires_at": expires_at
                            })
                            .to_string(),
                        ))
                        .expect("create override request"),
                )
                .await
                .expect("create override response");
            assert_eq!(response.status(), StatusCode::OK);
            let created: OverrideResponse = read_json_body(response).await;
            assert_eq!(created.status, "pending");

            // Verify that an override.request.created audit event was persisted.
            let audit_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM audit_events WHERE tenant_id = $1 AND action = 'override.request.created' AND resource = $2",
            )
            .bind(fixture.tenant_id)
            .bind(format!("override/{}", created.id))
            .fetch_one(&pool)
            .await?;
            assert_eq!(audit_count, 1, "override.request.created audit event must be persisted");

            // Clean up the created override.
            sqlx::query("DELETE FROM overrides WHERE id = $1")
                .bind(created.id)
                .execute(&pool)
                .await?;

            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("create override audit event assertions");
    }

    #[tokio::test]
    #[ignore = "requires migrated postgres contract database"]
    async fn approve_override_produces_audit_event() {
        let pool = connect(&test_database_url())
            .await
            .expect("connect test db");
        let fixture = InvestigationRouteFixture::insert(&pool).await;

        let result = async {
            let response = app(pool.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!(
                            "/v1/tenants/{}/overrides/{}/approve",
                            fixture.tenant_id, fixture.pending_override_id
                        ))
                        .header("content-type", "application/json")
                        .body(Body::from(
                            json!({
                                "actor_id": fixture.admin_user_id,
                                "reason": "Approved after full incident review"
                            })
                            .to_string(),
                        ))
                        .expect("approve override request"),
                )
                .await
                .expect("approve override response");
            assert_eq!(response.status(), StatusCode::OK);

            // Verify that an override.request.approved audit event was persisted.
            let audit_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM audit_events WHERE tenant_id = $1 AND action = 'override.request.approved'",
            )
            .bind(fixture.tenant_id)
            .fetch_one(&pool)
            .await?;
            assert!(audit_count >= 1, "override.request.approved audit event must be persisted");

            Ok::<(), anyhow::Error>(())
        }
        .await;

        fixture.cleanup(&pool).await;
        result.expect("approve override audit event assertions");
    }
}
