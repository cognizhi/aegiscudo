pub mod audit;
pub mod metrics;
pub mod rate_limit;
pub mod registry_config;
pub mod triage_client;

use std::{
    collections::HashMap,
    net::SocketAddr,
    ops::Range,
    sync::Arc,
    time::{Duration, Instant},
};

use aegiscudo_core::{
    ArtifactDigest, AuditEvent, Metadata, PackageCoordinate, PackageEcosystem, PolicyDecision,
    PolicyMode, validate_audit_metadata,
};
use aegiscudo_protocol::{
    AdvisoryHeaderPayload, DecisionRequest, DecisionResponse, NormalizedPackageRequest,
    PackageRequestKind, canonicalize_pypi_name, normalize_npm_name,
};
use aegiscudo_telemetry::health;
use audit::PostgresAuditEventRepository;
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, Path, State},
    http::{
        HeaderMap, HeaderValue, Method, StatusCode, Uri,
        header::{
            ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ETAG, HOST,
            HeaderName, LAST_MODIFIED, LOCATION, RETRY_AFTER, USER_AGENT,
        },
    },
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use base64::{
    Engine as _,
    engine::general_purpose::{
        STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD,
    },
};
use metrics::ProxyMetrics;
use rate_limit::{ProxyRateLimitConfig, ProxyRateLimiters, RateLimitRejection};
use registry_config::{
    CredentialAuthType, PostgresRegistryConfigRepository, RegistryAdapter, RegistryConfigStore,
    ResolvedRegistryConfig,
};
use ring::hmac;
use serde::Serialize;
use serde_json::json;
use sha1::Sha1 as Sha1Hasher;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use triage_client::{TriageClient, TriageClientError};
use uuid::Uuid;

pub const SERVICE_NAME: &str = "mosquito-net";
const ADVISORY_HEADER: &str = "x-aegiscudo-advisory";
const TRACE_HEADER: &str = "x-aegiscudo-trace-id";
const DEFAULT_MAX_ARTIFACT_BYTES: u64 = 100 * 1024 * 1024;
const CARGO_DL_PROXY_PREFIX: &str = "__cargo_dl__";
const CARGO_API_PROXY_PREFIX: &str = "__cargo_api__";
const MAX_CARGO_DOWNLOAD_REDIRECTS: usize = 4;

#[derive(Debug, Serialize)]
struct ProxyDispatchResponse {
    registry_config_id: String,
    mount_path: String,
    adapter: RegistryAdapter,
    upstream_path: String,
    normalized_name: Option<String>,
    triage_decision: Option<DecisionResponse>,
    enforced: bool,
    triage_unavailable: bool,
    message: &'static str,
}

#[derive(Debug, Serialize)]
struct ProxyErrorResponse {
    trace_id: String,
    decision: PolicyDecision,
    message: &'static str,
}

pub struct AppState {
    registry_configs: RegistryConfigStore,
    registry_repository: Option<PostgresRegistryConfigRepository>,
    triage_client: TriageClient,
    cargo_download_mac_key: Vec<u8>,
    verified_upstream_client: reqwest::Client,
    insecure_upstream_client: reqwest::Client,
    caches: ProxyCaches,
    max_artifact_bytes: u64,
    metrics: ProxyMetrics,
    rate_limiters: ProxyRateLimiters,
    audit_repository: Option<PostgresAuditEventRepository>,
}

impl AppState {
    pub fn new(
        registry_configs: RegistryConfigStore,
        registry_repository: Option<PostgresRegistryConfigRepository>,
        triage_client: TriageClient,
        rate_limit_config: ProxyRateLimitConfig,
        audit_repository: Option<PostgresAuditEventRepository>,
        max_artifact_bytes: u64,
    ) -> Self {
        Self::new_with_cargo_download_mac_key(
            registry_configs,
            registry_repository,
            triage_client,
            rate_limit_config,
            audit_repository,
            max_artifact_bytes,
            Uuid::new_v4().into_bytes().to_vec(),
        )
    }

    fn new_with_cargo_download_mac_key(
        registry_configs: RegistryConfigStore,
        registry_repository: Option<PostgresRegistryConfigRepository>,
        triage_client: TriageClient,
        rate_limit_config: ProxyRateLimitConfig,
        audit_repository: Option<PostgresAuditEventRepository>,
        max_artifact_bytes: u64,
        cargo_download_mac_key: Vec<u8>,
    ) -> Self {
        assert!(
            !cargo_download_mac_key.is_empty(),
            "Mosquito Net cargo download MAC key must not be empty"
        );
        Self {
            registry_configs,
            registry_repository,
            triage_client,
            cargo_download_mac_key,
            verified_upstream_client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Mosquito Net upstream client must initialize"),
            insecure_upstream_client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(30))
                .danger_accept_invalid_certs(true)
                .build()
                .expect("Mosquito Net upstream client must initialize"),
            caches: ProxyCaches::default(),
            max_artifact_bytes,
            metrics: ProxyMetrics::new().expect("Mosquito Net metrics must initialize"),
            rate_limiters: ProxyRateLimiters::new(rate_limit_config),
            audit_repository,
        }
    }
}

fn upstream_client<'a>(
    state: &'a AppState,
    resolved: &ResolvedRegistryConfig,
) -> &'a reqwest::Client {
    if resolved.config.verify_upstream_tls {
        &state.verified_upstream_client
    } else {
        &state.insecure_upstream_client
    }
}

#[derive(Default)]
struct ProxyCaches {
    decisions: RwLock<HashMap<String, CachedDecision>>,
    metadata: RwLock<HashMap<String, CachedUpstreamResponse>>,
    artifact_by_digest: RwLock<HashMap<String, CachedUpstreamResponse>>,
    artifact_digest_by_path: RwLock<HashMap<String, String>>,
}

#[derive(Clone)]
struct CachedDecision {
    response: DecisionResponse,
    expires_at: Instant,
}

#[derive(Clone)]
struct CachedUpstreamResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
    expires_at: Instant,
}

fn cache_deadline(cache_ttl_seconds: i32) -> Option<Instant> {
    if cache_ttl_seconds <= 0 {
        None
    } else {
        Some(Instant::now() + Duration::from_secs(cache_ttl_seconds as u64))
    }
}

fn cache_key_for_decision(request: &DecisionRequest) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}",
        request.tenant_id,
        request.registry_config_id,
        package_request_kind_label(&request.request.kind),
        request.request.coordinate.purl(),
        request
            .request
            .requested_digest
            .as_ref()
            .map(|digest| digest.hex.as_str())
            .unwrap_or("none"),
        request.request.explicit_version_or_integrity
    )
}

fn cache_key_for_upstream(resolved: &ResolvedRegistryConfig, query: Option<&str>) -> String {
    match query.filter(|value| !value.is_empty()) {
        Some(query) => format!(
            "{}:{}?{}",
            resolved.config.id, resolved.upstream_path, query
        ),
        None => format!("{}:{}", resolved.config.id, resolved.upstream_path),
    }
}

fn package_request_kind_label(kind: &PackageRequestKind) -> &'static str {
    match kind {
        PackageRequestKind::Metadata => "metadata",
        PackageRequestKind::Artifact => "artifact",
    }
}

async fn cached_decision(state: &AppState, cache_key: &str) -> Option<DecisionResponse> {
    let now = Instant::now();
    let cached = state.caches.decisions.read().await.get(cache_key).cloned();
    cached
        .filter(|entry| entry.expires_at > now)
        .map(|entry| entry.response)
}

async fn cache_decision(
    state: &AppState,
    resolved: &ResolvedRegistryConfig,
    cache_key: &str,
    decision: &DecisionResponse,
) {
    let Some(expires_at) = cache_deadline(resolved.config.cache_ttl_seconds) else {
        return;
    };
    state.caches.decisions.write().await.insert(
        cache_key.to_owned(),
        CachedDecision {
            response: decision.clone(),
            expires_at,
        },
    );
    state.metrics.observe_cache(
        resolved.config.tenant_id,
        resolved.config.id,
        resolved.config.adapter,
        "decision",
        "store",
    );
}

async fn cached_metadata_response(
    state: &AppState,
    cache_key: &str,
) -> Option<CachedUpstreamResponse> {
    let now = Instant::now();
    state
        .caches
        .metadata
        .read()
        .await
        .get(cache_key)
        .cloned()
        .filter(|entry| entry.expires_at > now)
}

async fn cache_metadata_response(
    state: &AppState,
    resolved: &ResolvedRegistryConfig,
    cache_key: &str,
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
) {
    if !status.is_success() {
        return;
    }
    let Some(expires_at) = cache_deadline(resolved.config.cache_ttl_seconds) else {
        return;
    };
    state.caches.metadata.write().await.insert(
        cache_key.to_owned(),
        CachedUpstreamResponse {
            status,
            headers,
            body,
            expires_at,
        },
    );
    state.metrics.observe_cache(
        resolved.config.tenant_id,
        resolved.config.id,
        resolved.config.adapter,
        "metadata",
        "store",
    );
}

async fn cached_artifact_response(
    state: &AppState,
    digest_hex: &str,
) -> Option<CachedUpstreamResponse> {
    let now = Instant::now();
    state
        .caches
        .artifact_by_digest
        .read()
        .await
        .get(digest_hex)
        .cloned()
        .filter(|entry| entry.expires_at > now)
}

async fn cache_artifact_response(
    state: &AppState,
    resolved: &ResolvedRegistryConfig,
    cache_key: &str,
    digest_hex: &str,
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
) {
    if !status.is_success() {
        return;
    }
    let Some(expires_at) = cache_deadline(resolved.config.cache_ttl_seconds) else {
        return;
    };
    state
        .caches
        .artifact_digest_by_path
        .write()
        .await
        .insert(cache_key.to_owned(), digest_hex.to_owned());
    state.caches.artifact_by_digest.write().await.insert(
        digest_hex.to_owned(),
        CachedUpstreamResponse {
            status,
            headers,
            body,
            expires_at,
        },
    );
    state.metrics.observe_cache(
        resolved.config.tenant_id,
        resolved.config.id,
        resolved.config.adapter,
        "artifact",
        "store",
    );
}

pub fn app(registry_configs: RegistryConfigStore) -> Router {
    let triage_client = TriageClient::new("http://127.0.0.1:8081", Duration::from_millis(750), 1)
        .expect("default Triage Counter URL is valid");
    app_with_runtime_config(
        registry_configs,
        triage_client,
        ProxyRateLimitConfig::default(),
    )
}

pub fn app_with_triage_client(
    registry_configs: RegistryConfigStore,
    triage_client: TriageClient,
) -> Router {
    app_with_runtime_config(
        registry_configs,
        triage_client,
        ProxyRateLimitConfig::default(),
    )
}

pub fn app_with_runtime_config(
    registry_configs: RegistryConfigStore,
    triage_client: TriageClient,
    rate_limit_config: ProxyRateLimitConfig,
) -> Router {
    app_with_runtime_config_and_cargo_download_mac_key(
        registry_configs,
        triage_client,
        rate_limit_config,
        Uuid::new_v4().into_bytes().to_vec(),
    )
}

pub fn app_with_runtime_config_and_cargo_download_mac_key(
    registry_configs: RegistryConfigStore,
    triage_client: TriageClient,
    rate_limit_config: ProxyRateLimitConfig,
    cargo_download_mac_key: Vec<u8>,
) -> Router {
    app_with_runtime_dependencies_and_cargo_download_mac_key(
        registry_configs,
        triage_client,
        rate_limit_config,
        None,
        DEFAULT_MAX_ARTIFACT_BYTES,
        cargo_download_mac_key,
    )
}

pub fn app_with_runtime_dependencies(
    registry_configs: RegistryConfigStore,
    triage_client: TriageClient,
    rate_limit_config: ProxyRateLimitConfig,
    audit_repository: Option<PostgresAuditEventRepository>,
) -> Router {
    app_with_runtime_dependencies_and_cargo_download_mac_key(
        registry_configs,
        triage_client,
        rate_limit_config,
        audit_repository,
        DEFAULT_MAX_ARTIFACT_BYTES,
        Uuid::new_v4().into_bytes().to_vec(),
    )
}

pub fn app_with_runtime_dependencies_and_cargo_download_mac_key(
    registry_configs: RegistryConfigStore,
    triage_client: TriageClient,
    rate_limit_config: ProxyRateLimitConfig,
    audit_repository: Option<PostgresAuditEventRepository>,
    max_artifact_bytes: u64,
    cargo_download_mac_key: Vec<u8>,
) -> Router {
    app_with_runtime_dependencies_and_reload_and_cargo_download_mac_key(
        registry_configs,
        None,
        triage_client,
        rate_limit_config,
        audit_repository,
        max_artifact_bytes,
        cargo_download_mac_key,
    )
}

pub fn app_with_runtime_dependencies_and_reload(
    registry_configs: RegistryConfigStore,
    registry_repository: Option<PostgresRegistryConfigRepository>,
    triage_client: TriageClient,
    rate_limit_config: ProxyRateLimitConfig,
    audit_repository: Option<PostgresAuditEventRepository>,
    max_artifact_bytes: u64,
) -> Router {
    app_with_runtime_dependencies_and_reload_and_cargo_download_mac_key(
        registry_configs,
        registry_repository,
        triage_client,
        rate_limit_config,
        audit_repository,
        max_artifact_bytes,
        Uuid::new_v4().into_bytes().to_vec(),
    )
}

pub fn app_with_runtime_dependencies_and_reload_and_cargo_download_mac_key(
    registry_configs: RegistryConfigStore,
    registry_repository: Option<PostgresRegistryConfigRepository>,
    triage_client: TriageClient,
    rate_limit_config: ProxyRateLimitConfig,
    audit_repository: Option<PostgresAuditEventRepository>,
    max_artifact_bytes: u64,
    cargo_download_mac_key: Vec<u8>,
) -> Router {
    let state = Arc::new(AppState::new_with_cargo_download_mac_key(
        registry_configs,
        registry_repository,
        triage_client,
        rate_limit_config,
        audit_repository,
        max_artifact_bytes,
        cargo_download_mac_key,
    ));
    Router::new()
        .route("/healthz", get(|| async { Json(health(SERVICE_NAME)) }))
        .route("/readyz", get(|| async { Json(health(SERVICE_NAME)) }))
        .route("/metrics", get(metrics))
        .route(
            "/admin/registry-configs/reload",
            post(reload_registry_configs),
        )
        .route(
            "/proxy/{*proxy_path}",
            get(proxy_get)
                .head(proxy_head)
                .post(proxy_write)
                .put(proxy_write)
                .delete(proxy_write),
        )
        .with_state(state)
}

async fn reload_registry_configs(State(state): State<Arc<AppState>>) -> Response {
    let Some(repository) = &state.registry_repository else {
        return status_response(StatusCode::SERVICE_UNAVAILABLE, None);
    };
    match repository.load_enabled_configs().await {
        Ok(configs) => match state.registry_configs.replace_configs(configs) {
            Ok(()) => Json(json!({ "registry_config_count": state.registry_configs.len() }))
                .into_response(),
            Err(error) => {
                tracing::error!(error = %error, "reloaded registry configuration set is invalid");
                status_response(StatusCode::INTERNAL_SERVER_ERROR, None)
            }
        },
        Err(error) => {
            tracing::error!(error = %error, "failed to reload registry configurations");
            status_response(StatusCode::SERVICE_UNAVAILABLE, None)
        }
    }
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
            tracing::error!(error = %error, "failed to render mosquito-net metrics");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn proxy_get(
    State(state): State<Arc<AppState>>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Path(proxy_path): Path<String>,
) -> Response {
    let request_started = Instant::now();
    let trace_id = new_proxy_trace_id();
    let Some(resolved) = state.registry_configs.resolve(&proxy_path) else {
        state.metrics.observe_request(
            None,
            "proxy",
            None,
            StatusCode::NOT_FOUND,
            request_started.elapsed(),
        );
        return status_response(StatusCode::NOT_FOUND, Some(trace_id));
    };
    emit_proxy_audit_event(
        state.as_ref(),
        inbound_request_audit_event(&resolved, &trace_id),
    )
    .await;
    if let Err(rejection) = state
        .rate_limiters
        .check_tenant(resolved.config.tenant_id)
        .await
    {
        return rate_limited_response(
            state.as_ref(),
            &resolved,
            &trace_id,
            request_started,
            "tenant-api",
            "tenant-rate-limit-exceeded",
            "tenant API rate limit exceeded",
            rejection,
        )
        .await;
    }
    if let Err(rejection) = state.rate_limiters.check_client(client_addr.ip()).await {
        return rate_limited_response(
            state.as_ref(),
            &resolved,
            &trace_id,
            request_started,
            "client-package",
            "client-rate-limit-exceeded",
            "client package request rate limit exceeded",
            rejection,
        )
        .await;
    }
    if !resolved.config.adapter.is_proxy_supported() {
        emit_proxy_audit_event(
            state.as_ref(),
            final_request_audit_event(
                &resolved,
                &trace_id,
                StatusCode::NOT_IMPLEMENTED,
                "adapter-not-implemented",
                None,
                false,
            ),
        )
        .await;
        state.metrics.observe_request(
            Some(resolved.config.tenant_id),
            "proxy",
            Some(resolved.config.adapter),
            StatusCode::NOT_IMPLEMENTED,
            request_started.elapsed(),
        );
        return status_response(StatusCode::NOT_IMPLEMENTED, Some(trace_id));
    }
    let request_query = uri.query().map(str::to_owned);
    let proxy_base = proxy_base_url(&headers);
    if resolved.config.adapter == RegistryAdapter::Cargo
        && cargo_registry_config_path(&resolved.upstream_path)
    {
        return cargo_registry_config_response(
            state.as_ref(),
            resolved,
            trace_id,
            request_started,
            proxy_base,
        )
        .await;
    }
    if resolved.config.adapter == RegistryAdapter::Cargo
        && cargo_proxy_api_path(&resolved.upstream_path)
    {
        if !cargo_registry_api_request_supported(&Method::GET, &resolved.upstream_path) {
            return unsupported_cargo_api_response(
                state.as_ref(),
                resolved,
                trace_id,
                request_started,
            )
            .await;
        }
        return cargo_registry_api_response(
            state.as_ref(),
            resolved,
            trace_id,
            request_started,
            proxy_base,
            Method::GET,
            headers,
            Vec::new(),
            request_query.clone(),
        )
        .await;
    }
    let source_url = if resolved.config.adapter == RegistryAdapter::GenericHttp {
        upstream_request_url_with_query(
            &resolved.config.upstream_url,
            &resolved.upstream_path,
            request_query.as_deref(),
        )
        .ok()
        .map(|url| url.to_string())
    } else {
        adapter_upstream_request_url(
            &state.cargo_download_mac_key,
            resolved.config.id,
            resolved.config.adapter,
            &resolved.config.upstream_url,
            &resolved.config.cargo_allowed_download_origins,
            &resolved.upstream_path,
        )
        .ok()
        .map(|url| url.to_string())
    };
    let mut decision_request = match decision_request_for_adapter(
        resolved.config.tenant_id,
        resolved.config.id,
        resolved.config.policy_profile_id,
        resolved.config.adapter,
        trace_id.clone(),
        source_url,
        &resolved.upstream_path,
    ) {
        Ok(request) => request,
        Err(status) => {
            emit_proxy_audit_event(
                state.as_ref(),
                final_request_audit_event(
                    &resolved,
                    &trace_id,
                    status,
                    "request-normalization-failed",
                    None,
                    false,
                ),
            )
            .await;
            state.metrics.observe_request(
                Some(resolved.config.tenant_id),
                "proxy",
                Some(resolved.config.adapter),
                status,
                request_started.elapsed(),
            );
            return status_response(status, Some(trace_id));
        }
    };
    let prefetched_artifact =
        if matches!(decision_request.request.kind, PackageRequestKind::Artifact) {
            match fetch_upstream_artifact(state.as_ref(), &resolved, request_query.as_deref()).await
            {
                Ok(prefetched) => {
                    if resolved.config.adapter == RegistryAdapter::Cargo
                        && !prefetched.status.is_success()
                    {
                        emit_proxy_audit_event(
                            state.as_ref(),
                            final_request_audit_event(
                                &resolved,
                                &trace_id,
                                prefetched.status,
                                "upstream-artifact-miss",
                                None,
                                false,
                            ),
                        )
                        .await;
                        state.metrics.observe_request(
                            Some(resolved.config.tenant_id),
                            "proxy",
                            Some(resolved.config.adapter),
                            prefetched.status,
                            request_started.elapsed(),
                        );
                        return match build_passthrough_upstream_response(
                            prefetched.status,
                            prefetched.headers,
                            prefetched.body,
                            &trace_id,
                            &resolved.config.mount_path,
                            &proxy_base,
                        ) {
                            Ok(response) => response,
                            Err(error) => {
                                tracing::warn!(
                                    tenant_id = %resolved.config.tenant_id,
                                    registry_config_id = %resolved.config.id,
                                    %trace_id,
                                    error = %error,
                                    "failed to build passthrough Cargo artifact response"
                                );
                                let body = ProxyErrorResponse {
                                    trace_id: trace_id.clone(),
                                    decision: PolicyDecision::QuarantinePendingAnalysis,
                                    message: "Failed to build Cargo artifact response",
                                }
                                .into_response_body();
                                json_response(
                                    error.status_code(),
                                    body,
                                    None,
                                    Some(trace_id.clone()),
                                    None,
                                )
                            }
                        };
                    }
                    decision_request.request.requested_digest = prefetched.digest.clone();
                    Some(prefetched)
                }
                Err(error) => {
                    let status = error.status_code();
                    tracing::warn!(
                        tenant_id = %resolved.config.tenant_id,
                        registry_config_id = %resolved.config.id,
                        %trace_id,
                        error = %error,
                        "artifact prefetch failed before Triage decision"
                    );
                    emit_proxy_audit_event(
                        state.as_ref(),
                        final_request_audit_event(
                            &resolved,
                            &trace_id,
                            status,
                            "artifact-prefetch-failed",
                            None,
                            false,
                        ),
                    )
                    .await;
                    state.metrics.observe_request(
                        Some(resolved.config.tenant_id),
                        "proxy",
                        Some(resolved.config.adapter),
                        status,
                        request_started.elapsed(),
                    );
                    return status_response(status, Some(trace_id));
                }
            }
        } else {
            None
        };
    let decision_cache_key = cache_key_for_decision(&decision_request);
    if let Some(mut cached) = cached_decision(state.as_ref(), &decision_cache_key).await {
        cached.trace_id = decision_request.request.trace_id.clone();
        state.metrics.observe_cache(
            resolved.config.tenant_id,
            resolved.config.id,
            resolved.config.adapter,
            "decision",
            "hit",
        );
        return decision_response(
            state.as_ref(),
            resolved,
            cached,
            request_started,
            Instant::now(),
            proxy_base,
            prefetched_artifact,
        )
        .await;
    }
    state.metrics.observe_cache(
        resolved.config.tenant_id,
        resolved.config.id,
        resolved.config.adapter,
        "decision",
        "miss",
    );
    let triage_started = Instant::now();
    match state.triage_client.evaluate(&decision_request).await {
        Ok(decision) => {
            cache_decision(state.as_ref(), &resolved, &decision_cache_key, &decision).await;
            decision_response(
                state.as_ref(),
                resolved,
                decision,
                request_started,
                triage_started,
                proxy_base,
                prefetched_artifact,
            )
            .await
        }
        Err(error) if error.is_outage() => {
            triage_outage_response(
                state.as_ref(),
                resolved,
                trace_id,
                error,
                request_started,
                triage_started,
            )
            .await
        }
        Err(error) => {
            triage_hard_error_response(
                state.as_ref(),
                resolved,
                trace_id,
                error,
                request_started,
                triage_started,
            )
            .await
        }
    }
}

async fn proxy_write(
    method: Method,
    State(state): State<Arc<AppState>>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    uri: Uri,
    headers: HeaderMap,
    Path(proxy_path): Path<String>,
    body: Bytes,
) -> Response {
    let request_started = Instant::now();
    let trace_id = new_proxy_trace_id();
    let Some(resolved) = state.registry_configs.resolve(&proxy_path) else {
        state.metrics.observe_request(
            None,
            "proxy",
            None,
            StatusCode::NOT_FOUND,
            request_started.elapsed(),
        );
        return status_response(StatusCode::NOT_FOUND, Some(trace_id));
    };
    emit_proxy_audit_event(
        state.as_ref(),
        inbound_request_audit_event(&resolved, &trace_id),
    )
    .await;
    if let Err(rejection) = state
        .rate_limiters
        .check_tenant(resolved.config.tenant_id)
        .await
    {
        return rate_limited_response(
            state.as_ref(),
            &resolved,
            &trace_id,
            request_started,
            "tenant-api",
            "tenant-rate-limit-exceeded",
            "tenant API rate limit exceeded",
            rejection,
        )
        .await;
    }
    if let Err(rejection) = state.rate_limiters.check_client(client_addr.ip()).await {
        return rate_limited_response(
            state.as_ref(),
            &resolved,
            &trace_id,
            request_started,
            "client-package",
            "client-rate-limit-exceeded",
            "client package request rate limit exceeded",
            rejection,
        )
        .await;
    }
    if !resolved.config.adapter.is_proxy_supported() {
        emit_proxy_audit_event(
            state.as_ref(),
            final_request_audit_event(
                &resolved,
                &trace_id,
                StatusCode::NOT_IMPLEMENTED,
                "adapter-not-implemented",
                None,
                false,
            ),
        )
        .await;
        state.metrics.observe_request(
            Some(resolved.config.tenant_id),
            "proxy",
            Some(resolved.config.adapter),
            StatusCode::NOT_IMPLEMENTED,
            request_started.elapsed(),
        );
        return status_response(StatusCode::NOT_IMPLEMENTED, Some(trace_id));
    }
    if resolved.config.adapter == RegistryAdapter::Cargo
        && cargo_proxy_api_path(&resolved.upstream_path)
    {
        if !cargo_registry_api_request_supported(&method, &resolved.upstream_path) {
            return unsupported_cargo_api_response(
                state.as_ref(),
                resolved,
                trace_id,
                request_started,
            )
            .await;
        }
        let proxy_base = proxy_base_url(&headers);
        return cargo_registry_api_response(
            state.as_ref(),
            resolved,
            trace_id,
            request_started,
            proxy_base,
            method,
            headers,
            body.to_vec(),
            uri.query().map(str::to_owned),
        )
        .await;
    }

    emit_proxy_audit_event(
        state.as_ref(),
        final_request_audit_event(
            &resolved,
            &trace_id,
            StatusCode::METHOD_NOT_ALLOWED,
            "proxy-method-not-supported",
            None,
            false,
        ),
    )
    .await;
    state.metrics.observe_request(
        Some(resolved.config.tenant_id),
        "proxy",
        Some(resolved.config.adapter),
        StatusCode::METHOD_NOT_ALLOWED,
        request_started.elapsed(),
    );
    status_response(StatusCode::METHOD_NOT_ALLOWED, Some(trace_id))
}

async fn rate_limited_response(
    state: &AppState,
    resolved: &ResolvedRegistryConfig,
    trace_id: &str,
    request_started: Instant,
    limiter: &'static str,
    outcome: &'static str,
    message: &'static str,
    rejection: RateLimitRejection,
) -> Response {
    emit_proxy_audit_event(
        state,
        final_request_audit_event(
            resolved,
            trace_id,
            StatusCode::TOO_MANY_REQUESTS,
            outcome,
            None,
            false,
        ),
    )
    .await;
    state.metrics.observe_request(
        Some(resolved.config.tenant_id),
        "proxy",
        Some(resolved.config.adapter),
        StatusCode::TOO_MANY_REQUESTS,
        request_started.elapsed(),
    );
    state.metrics.observe_rate_limit(
        resolved.config.tenant_id,
        resolved.config.id,
        resolved.config.adapter,
        limiter,
        outcome,
    );
    let body = json!({
        "trace_id": trace_id,
        "message": message,
        "retry_after_seconds": rejection.retry_after_seconds,
    });
    json_response(
        StatusCode::TOO_MANY_REQUESTS,
        body,
        None,
        Some(trace_id.to_owned()),
        Some(rejection.retry_after_seconds),
    )
}

async fn decision_response(
    state: &AppState,
    resolved: ResolvedRegistryConfig,
    decision: DecisionResponse,
    request_started: Instant,
    triage_started: Instant,
    proxy_base_url: String,
    prefetched_artifact: Option<PrefetchedArtifact>,
) -> Response {
    if decision.mode != resolved.config.mode {
        return triage_hard_error_response(
            state,
            resolved,
            decision.trace_id.clone(),
            TriageClientError::ResponseContextMismatch,
            request_started,
            triage_started,
        )
        .await;
    }
    let triage_elapsed = triage_started.elapsed();
    let enforced = resolved.config.mode == PolicyMode::Enforce && decision.decision.is_blocking();
    let advisory = advisory_payload(
        decision.decision.clone(),
        decision.trace_id.clone(),
        advisory_message(&decision),
    );
    let status = if enforced {
        StatusCode::FORBIDDEN
    } else {
        StatusCode::OK
    };
    emit_proxy_audit_event(
        state,
        final_request_audit_event(
            &resolved,
            &decision.trace_id,
            status,
            "triage-decision-applied",
            Some(decision.decision.clone()),
            false,
        ),
    )
    .await;
    state.metrics.observe_triage(
        resolved.config.tenant_id,
        resolved.config.id,
        resolved.config.adapter,
        "success",
        triage_elapsed,
    );
    state.metrics.observe_decision(
        resolved.config.tenant_id,
        resolved.config.id,
        resolved.config.adapter,
        &decision.decision,
        triage_elapsed,
    );
    if enforced {
        let body = ProxyErrorResponse {
            trace_id: decision.trace_id.clone(),
            decision: decision.decision.clone(),
            message: "Triage Counter returned an enforcing block decision",
        }
        .into_response_body();
        state.metrics.observe_request(
            Some(resolved.config.tenant_id),
            "proxy",
            Some(resolved.config.adapter),
            status,
            request_started.elapsed(),
        );
        return json_response(status, body, Some(advisory), Some(decision.trace_id), None);
    }

    match proxy_upstream_get(
        state,
        &resolved,
        &decision,
        advisory,
        proxy_base_url,
        prefetched_artifact,
    )
    .await
    {
        Ok(response) => {
            emit_proxy_audit_event(
                state,
                final_request_audit_event(
                    &resolved,
                    &decision.trace_id,
                    response.status(),
                    "upstream-proxy-completed",
                    Some(decision.decision.clone()),
                    false,
                ),
            )
            .await;
            state.metrics.observe_request(
                Some(resolved.config.tenant_id),
                "proxy",
                Some(resolved.config.adapter),
                response.status(),
                request_started.elapsed(),
            );
            response
        }
        Err(error) => {
            tracing::warn!(
                tenant_id = %resolved.config.tenant_id,
                registry_config_id = %resolved.config.id,
                trace_id = %decision.trace_id,
                error = %error,
                "upstream registry request failed"
            );
            emit_proxy_audit_event(
                state,
                final_request_audit_event(
                    &resolved,
                    &decision.trace_id,
                    StatusCode::BAD_GATEWAY,
                    "upstream-proxy-failed",
                    Some(decision.decision.clone()),
                    false,
                ),
            )
            .await;
            let body = ProxyErrorResponse {
                trace_id: decision.trace_id.clone(),
                decision: PolicyDecision::QuarantinePendingAnalysis,
                message: "upstream registry request failed",
            }
            .into_response_body();
            state.metrics.observe_request(
                Some(resolved.config.tenant_id),
                "proxy",
                Some(resolved.config.adapter),
                StatusCode::BAD_GATEWAY,
                request_started.elapsed(),
            );
            json_response(
                StatusCode::BAD_GATEWAY,
                body,
                None,
                Some(decision.trace_id),
                None,
            )
        }
    }
}

async fn cargo_registry_config_response(
    state: &AppState,
    resolved: ResolvedRegistryConfig,
    trace_id: String,
    request_started: Instant,
    proxy_base_url: String,
) -> Response {
    match proxy_cargo_registry_config(state, &resolved, &trace_id, &proxy_base_url).await {
        Ok(response) => {
            emit_proxy_audit_event(
                state,
                final_request_audit_event(
                    &resolved,
                    &trace_id,
                    response.status(),
                    "upstream-proxy-completed",
                    None,
                    false,
                ),
            )
            .await;
            state.metrics.observe_request(
                Some(resolved.config.tenant_id),
                "proxy",
                Some(resolved.config.adapter),
                response.status(),
                request_started.elapsed(),
            );
            response
        }
        Err(error) => {
            tracing::warn!(
                tenant_id = %resolved.config.tenant_id,
                registry_config_id = %resolved.config.id,
                %trace_id,
                error = %error,
                "upstream registry request failed"
            );
            emit_proxy_audit_event(
                state,
                final_request_audit_event(
                    &resolved,
                    &trace_id,
                    StatusCode::BAD_GATEWAY,
                    "upstream-proxy-failed",
                    None,
                    false,
                ),
            )
            .await;
            let body = ProxyErrorResponse {
                trace_id: trace_id.clone(),
                decision: PolicyDecision::QuarantinePendingAnalysis,
                message: "upstream registry request failed",
            }
            .into_response_body();
            state.metrics.observe_request(
                Some(resolved.config.tenant_id),
                "proxy",
                Some(resolved.config.adapter),
                StatusCode::BAD_GATEWAY,
                request_started.elapsed(),
            );
            json_response(StatusCode::BAD_GATEWAY, body, None, Some(trace_id), None)
        }
    }
}

async fn cargo_registry_api_response(
    state: &AppState,
    resolved: ResolvedRegistryConfig,
    trace_id: String,
    request_started: Instant,
    proxy_base_url: String,
    method: Method,
    request_headers: HeaderMap,
    request_body: Vec<u8>,
    query: Option<String>,
) -> Response {
    match proxy_cargo_registry_api(
        state,
        &resolved,
        &trace_id,
        &proxy_base_url,
        method,
        request_headers,
        request_body,
        query.as_deref(),
    )
    .await
    {
        Ok(response) => {
            emit_proxy_audit_event(
                state,
                final_request_audit_event(
                    &resolved,
                    &trace_id,
                    response.status(),
                    "upstream-proxy-completed",
                    None,
                    false,
                ),
            )
            .await;
            state.metrics.observe_request(
                Some(resolved.config.tenant_id),
                "proxy",
                Some(resolved.config.adapter),
                response.status(),
                request_started.elapsed(),
            );
            response
        }
        Err(error) => {
            let status = error.status_code();
            tracing::warn!(
                tenant_id = %resolved.config.tenant_id,
                registry_config_id = %resolved.config.id,
                %trace_id,
                error = %error,
                "upstream registry request failed"
            );
            emit_proxy_audit_event(
                state,
                final_request_audit_event(
                    &resolved,
                    &trace_id,
                    status,
                    "upstream-proxy-failed",
                    None,
                    false,
                ),
            )
            .await;
            state.metrics.observe_request(
                Some(resolved.config.tenant_id),
                "proxy",
                Some(resolved.config.adapter),
                status,
                request_started.elapsed(),
            );
            status_response(status, Some(trace_id))
        }
    }
}

async fn unsupported_cargo_api_response(
    state: &AppState,
    resolved: ResolvedRegistryConfig,
    trace_id: String,
    request_started: Instant,
) -> Response {
    emit_proxy_audit_event(
        state,
        final_request_audit_event(
            &resolved,
            &trace_id,
            StatusCode::NOT_FOUND,
            "unsupported-cargo-api-path",
            None,
            false,
        ),
    )
    .await;
    state.metrics.observe_request(
        Some(resolved.config.tenant_id),
        "proxy",
        Some(resolved.config.adapter),
        StatusCode::NOT_FOUND,
        request_started.elapsed(),
    );
    status_response(StatusCode::NOT_FOUND, Some(trace_id))
}

async fn proxy_head(
    State(state): State<Arc<AppState>>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
    Path(proxy_path): Path<String>,
) -> Response {
    let request_started = Instant::now();
    let trace_id = new_proxy_trace_id();
    let Some(resolved) = state.registry_configs.resolve(&proxy_path) else {
        state.metrics.observe_request(
            None,
            "proxy",
            None,
            StatusCode::NOT_FOUND,
            request_started.elapsed(),
        );
        return status_response(StatusCode::NOT_FOUND, Some(trace_id));
    };
    emit_proxy_audit_event(
        state.as_ref(),
        inbound_request_audit_event(&resolved, &trace_id),
    )
    .await;
    if let Err(rejection) = state
        .rate_limiters
        .check_tenant(resolved.config.tenant_id)
        .await
    {
        return rate_limited_response(
            state.as_ref(),
            &resolved,
            &trace_id,
            request_started,
            "tenant-api",
            "tenant-rate-limit-exceeded",
            "tenant API rate limit exceeded",
            rejection,
        )
        .await;
    }
    if let Err(rejection) = state.rate_limiters.check_client(client_addr.ip()).await {
        return rate_limited_response(
            state.as_ref(),
            &resolved,
            &trace_id,
            request_started,
            "client-package",
            "client-rate-limit-exceeded",
            "client package request rate limit exceeded",
            rejection,
        )
        .await;
    }
    if resolved.config.adapter != RegistryAdapter::GenericHttp {
        emit_proxy_audit_event(
            state.as_ref(),
            final_request_audit_event(
                &resolved,
                &trace_id,
                StatusCode::NOT_IMPLEMENTED,
                "adapter-not-implemented",
                None,
                false,
            ),
        )
        .await;
        state.metrics.observe_request(
            Some(resolved.config.tenant_id),
            "proxy",
            Some(resolved.config.adapter),
            StatusCode::NOT_IMPLEMENTED,
            request_started.elapsed(),
        );
        return status_response(StatusCode::NOT_IMPLEMENTED, Some(trace_id));
    }
    let proxy_base = proxy_base_url(&headers);
    let upstream_url = match upstream_request_url_with_query(
        &resolved.config.upstream_url,
        &resolved.upstream_path,
        uri.query(),
    ) {
        Ok(url) => url,
        Err(error) => {
            tracing::warn!(
                tenant_id = %resolved.config.tenant_id,
                registry_config_id = %resolved.config.id,
                %trace_id,
                error = %error,
                "failed to build upstream HEAD request url"
            );
            emit_proxy_audit_event(
                state.as_ref(),
                final_request_audit_event(
                    &resolved,
                    &trace_id,
                    StatusCode::BAD_GATEWAY,
                    "upstream-proxy-failed",
                    None,
                    false,
                ),
            )
            .await;
            state.metrics.observe_request(
                Some(resolved.config.tenant_id),
                "proxy",
                Some(resolved.config.adapter),
                StatusCode::BAD_GATEWAY,
                request_started.elapsed(),
            );
            return status_response(StatusCode::BAD_GATEWAY, Some(trace_id));
        }
    };
    let mut request_builder = upstream_client(&state, &resolved).head(upstream_url);
    request_builder = match inject_upstream_credentials(request_builder, &resolved) {
        Ok(builder) => builder,
        Err(error) => {
            tracing::warn!(
                tenant_id = %resolved.config.tenant_id,
                registry_config_id = %resolved.config.id,
                %trace_id,
                error = %error,
                "failed to inject upstream credentials for HEAD request"
            );
            emit_proxy_audit_event(
                state.as_ref(),
                final_request_audit_event(
                    &resolved,
                    &trace_id,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "upstream-proxy-failed",
                    None,
                    false,
                ),
            )
            .await;
            state.metrics.observe_request(
                Some(resolved.config.tenant_id),
                "proxy",
                Some(resolved.config.adapter),
                StatusCode::SERVICE_UNAVAILABLE,
                request_started.elapsed(),
            );
            return status_response(StatusCode::SERVICE_UNAVAILABLE, Some(trace_id));
        }
    };
    let upstream_response = match request_builder.send().await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(
                tenant_id = %resolved.config.tenant_id,
                registry_config_id = %resolved.config.id,
                %trace_id,
                error = %error,
                "upstream HEAD request failed"
            );
            emit_proxy_audit_event(
                state.as_ref(),
                final_request_audit_event(
                    &resolved,
                    &trace_id,
                    StatusCode::BAD_GATEWAY,
                    "upstream-proxy-failed",
                    None,
                    false,
                ),
            )
            .await;
            state.metrics.observe_request(
                Some(resolved.config.tenant_id),
                "proxy",
                Some(resolved.config.adapter),
                StatusCode::BAD_GATEWAY,
                request_started.elapsed(),
            );
            return status_response(StatusCode::BAD_GATEWAY, Some(trace_id));
        }
    };
    let status = upstream_response.status();
    let upstream_headers = upstream_response.headers().clone();
    let mut response = Response::builder().status(status);
    if let Some(response_headers) = response.headers_mut() {
        copy_safe_upstream_headers(&upstream_headers, response_headers);
        if let Some(content_length) = upstream_headers.get(CONTENT_LENGTH) {
            response_headers.insert(CONTENT_LENGTH, content_length.clone());
        }
        if let Some(location) = upstream_headers
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
        {
            let rewritten =
                rewrite_registry_url(&resolved.config.mount_path, &proxy_base, location);
            if let Ok(header_value) = HeaderValue::from_str(&rewritten) {
                response_headers.insert(LOCATION, header_value);
            }
        }
        if let Ok(header_value) = HeaderValue::from_str(&trace_id) {
            response_headers.insert(HeaderName::from_static(TRACE_HEADER), header_value);
        }
    }
    let response = response.body(Body::empty()).unwrap_or_else(|_| {
        status_response(StatusCode::INTERNAL_SERVER_ERROR, Some(trace_id.clone()))
    });
    emit_proxy_audit_event(
        state.as_ref(),
        final_request_audit_event(
            &resolved,
            &trace_id,
            response.status(),
            "upstream-proxy-completed",
            None,
            false,
        ),
    )
    .await;
    state.metrics.observe_request(
        Some(resolved.config.tenant_id),
        "proxy",
        Some(resolved.config.adapter),
        response.status(),
        request_started.elapsed(),
    );
    response
}

struct PrefetchedArtifact {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
    digest: Option<ArtifactDigest>,
}

async fn fetch_cargo_expected_digest(
    state: &AppState,
    resolved: &ResolvedRegistryConfig,
    coordinate: &PackageCoordinate,
) -> Result<ArtifactDigest, UpstreamProxyError> {
    let version = coordinate
        .version
        .as_deref()
        .ok_or(UpstreamProxyError::InvalidCargoRegistryConfig)?;
    let sparse_path = cargo_sparse_index_path(&coordinate.name);
    let cache_key = format!("{}:{}", resolved.config.id, sparse_path);
    let body = if let Some(cached) = cached_metadata_response(state, &cache_key).await {
        if !cached.status.is_success() {
            return Err(UpstreamProxyError::InvalidCargoArtifactDigest);
        }
        cached.body
    } else {
        let upstream_url = upstream_request_url(&resolved.config.upstream_url, &sparse_path)?;
        let mut request_builder = upstream_client(state, resolved).get(upstream_url);
        request_builder = inject_upstream_credentials(request_builder, resolved)?;
        let upstream_response = request_builder
            .send()
            .await
            .map_err(UpstreamProxyError::Request)?;
        let status = upstream_response.status();
        let headers = upstream_response.headers().clone();
        let body = upstream_response
            .bytes()
            .await
            .map_err(UpstreamProxyError::Body)?
            .to_vec();
        cache_metadata_response(state, resolved, &cache_key, status, headers, body.clone()).await;
        if !status.is_success() {
            return Err(UpstreamProxyError::InvalidCargoArtifactDigest);
        }
        body
    };
    cargo_sparse_expected_digest_for_version(&body, &coordinate.name, version)
}

async fn fetch_upstream_artifact(
    state: &AppState,
    resolved: &ResolvedRegistryConfig,
    query: Option<&str>,
) -> Result<PrefetchedArtifact, UpstreamProxyError> {
    let cache_key = cache_key_for_upstream(resolved, query);
    let upstream_url = if resolved.config.adapter == RegistryAdapter::GenericHttp {
        upstream_request_url_with_query(
            &resolved.config.upstream_url,
            &resolved.upstream_path,
            query,
        )?
    } else {
        adapter_upstream_request_url(
            &state.cargo_download_mac_key,
            resolved.config.id,
            resolved.config.adapter,
            &resolved.config.upstream_url,
            &resolved.config.cargo_allowed_download_origins,
            &resolved.upstream_path,
        )?
    };
    let cargo_expected_digest = if resolved.config.adapter == RegistryAdapter::Cargo {
        let (_, coordinate, _) = cargo_request_context(&resolved.upstream_path)
            .map_err(|_| UpstreamProxyError::InvalidCargoRegistryConfig)?;
        Some(fetch_cargo_expected_digest(state, resolved, &coordinate).await?)
    } else {
        None
    };
    if let Some(digest_hex) = state
        .caches
        .artifact_digest_by_path
        .read()
        .await
        .get(&cache_key)
        .cloned()
        && cargo_expected_digest
            .as_ref()
            .map(|expected| expected.hex == digest_hex)
            .unwrap_or(true)
        && let Some(cached) = cached_artifact_response(state, &digest_hex).await
    {
        state.metrics.observe_cache(
            resolved.config.tenant_id,
            resolved.config.id,
            resolved.config.adapter,
            "artifact",
            "hit",
        );
        return Ok(PrefetchedArtifact {
            status: cached.status,
            headers: cached.headers,
            body: cached.body,
            digest: Some(match cargo_expected_digest {
                Some(expected) => expected,
                None => ArtifactDigest::sha256(digest_hex).map_err(UpstreamProxyError::Digest)?,
            }),
        });
    }
    state.metrics.observe_cache(
        resolved.config.tenant_id,
        resolved.config.id,
        resolved.config.adapter,
        "artifact",
        "miss",
    );
    let upstream_started = Instant::now();
    let upstream_response = if resolved.config.adapter == RegistryAdapter::Cargo {
        fetch_cargo_download_response(state, resolved, upstream_url).await?
    } else {
        let mut request_builder = upstream_client(state, resolved).get(upstream_url);
        request_builder = inject_upstream_credentials(request_builder, resolved)?;
        request_builder
            .send()
            .await
            .map_err(UpstreamProxyError::Request)?
    };
    let status = upstream_response.status();
    let headers = upstream_response.headers().clone();
    enforce_artifact_size_limit(state.max_artifact_bytes, &headers, None)?;
    let body = upstream_response
        .bytes()
        .await
        .map_err(UpstreamProxyError::Body)?
        .to_vec();
    enforce_artifact_size_limit(state.max_artifact_bytes, &headers, Some(body.len() as u64))?;
    state.metrics.observe_upstream(
        resolved.config.tenant_id,
        resolved.config.id,
        resolved.config.adapter,
        "artifact",
        status,
        upstream_started.elapsed(),
    );
    if resolved.config.adapter == RegistryAdapter::Cargo && !status.is_success() {
        return Ok(PrefetchedArtifact {
            status,
            headers,
            body,
            digest: None,
        });
    }
    let digest = sha256_digest(&body).map_err(UpstreamProxyError::Digest)?;
    let digest = if let Some(expected_digest) = cargo_expected_digest {
        if digest.hex != expected_digest.hex {
            return Err(UpstreamProxyError::InvalidCargoArtifactDigest);
        }
        expected_digest
    } else {
        digest
    };
    // Maven sidecar checksum verification: fail closed on mismatch, pass through if absent.
    if resolved.config.adapter == RegistryAdapter::Maven {
        if let Ok((PackageRequestKind::Artifact, _, _)) =
            maven_request_context(&resolved.upstream_path)
        {
            verify_maven_checksum(state, resolved, &body).await?;
        }
    }
    let mut storage_headers = headers.clone();
    if resolved.config.adapter == RegistryAdapter::GenericHttp {
        redact_sensitive_upstream_headers(&mut storage_headers);
    }
    cache_artifact_response(
        state,
        resolved,
        &cache_key,
        &digest.hex,
        status,
        storage_headers,
        body.clone(),
    )
    .await;
    Ok(PrefetchedArtifact {
        status,
        headers,
        body,
        digest: Some(digest),
    })
}

async fn fetch_cargo_download_response(
    state: &AppState,
    resolved: &ResolvedRegistryConfig,
    initial_url: url::Url,
) -> Result<reqwest::Response, UpstreamProxyError> {
    let mut current_url = initial_url;
    for _ in 0..=MAX_CARGO_DOWNLOAD_REDIRECTS {
        let mut request_builder = upstream_client(state, resolved).get(current_url.clone());
        if cargo_download_uses_primary_origin(&resolved.config.upstream_url, &current_url)? {
            request_builder = inject_upstream_credentials(request_builder, resolved)?;
        }
        let response = request_builder
            .send()
            .await
            .map_err(UpstreamProxyError::Request)?;
        if !response.status().is_redirection() {
            return Ok(response);
        }

        let location = response
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(UpstreamProxyError::UnsupportedCargoDownloadRedirect)?;
        let next_url = current_url
            .join(location)
            .map_err(|_| UpstreamProxyError::UnsupportedCargoDownloadRedirect)?;
        if !cargo_download_origin_allowed(
            &resolved.config.upstream_url,
            &resolved.config.cargo_allowed_download_origins,
            &next_url,
        )? {
            return Err(UpstreamProxyError::UnsupportedCargoDownloadRedirect);
        }
        current_url = next_url;
    }

    Err(UpstreamProxyError::UnsupportedCargoDownloadRedirect)
}

fn sha256_digest(bytes: &[u8]) -> Result<ArtifactDigest, aegiscudo_core::DigestError> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    ArtifactDigest::sha256(hex::encode(hasher.finalize()))
}

fn maven_sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn maven_sha1_hex(bytes: &[u8]) -> String {
    let mut h = Sha1Hasher::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Verify a Maven artifact's integrity against its upstream sidecar checksum file.
///
/// Tries `.sha256` first (stronger), then `.sha1` (widely deployed). If a sidecar is present
/// and its hash does not match the fetched artifact bytes, returns
/// [`UpstreamProxyError::MavenChecksumMismatch`] so the proxy fails closed. If no sidecar is
/// available the function returns `Ok(())` — absence of a sidecar is not treated as an error.
async fn verify_maven_checksum(
    state: &AppState,
    resolved: &ResolvedRegistryConfig,
    artifact_body: &[u8],
) -> Result<(), UpstreamProxyError> {
    let candidates: &[(&str, fn(&[u8]) -> String)] =
        &[(".sha256", maven_sha256_hex), (".sha1", maven_sha1_hex)];
    for (suffix, compute) in candidates {
        let sidecar_path = format!("{}{}", resolved.upstream_path, suffix);
        let sidecar_url = upstream_request_url(&resolved.config.upstream_url, &sidecar_path)?;
        let mut rb = upstream_client(state, resolved).get(sidecar_url);
        rb = inject_upstream_credentials(rb, resolved)?;
        let resp = match rb.send().await {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };
        let sidecar_bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(_) => continue,
        };
        // Maven sidecar format: "<hash>" or "<hash>  <filename>" (GNU coreutils style)
        let sidecar_text = String::from_utf8_lossy(&sidecar_bytes);
        let expected = sidecar_text
            .trim()
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_lowercase();
        if expected.is_empty() {
            continue;
        }
        // Skip malformed sidecars: a valid SHA-1 is 40 hex chars, SHA-256 is 64 hex chars.
        let expected_len = if *suffix == ".sha256" { 64 } else { 40 };
        if expected.len() != expected_len || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let actual = compute(artifact_body);
        if actual != expected {
            return Err(UpstreamProxyError::MavenChecksumMismatch);
        }
        // Verified — stop after the first successful comparison.
        return Ok(());
    }
    // No sidecar available; pass through without verification.
    Ok(())
}

async fn proxy_upstream_get(
    state: &AppState,
    resolved: &ResolvedRegistryConfig,
    decision: &DecisionResponse,
    advisory: AdvisoryHeaderPayload,
    proxy_base_url: String,
    prefetched_artifact: Option<PrefetchedArtifact>,
) -> Result<Response, UpstreamProxyError> {
    let (status, upstream_headers, body) = if let Some(prefetched) = prefetched_artifact {
        (prefetched.status, prefetched.headers, prefetched.body)
    } else {
        let cache_key = cache_key_for_upstream(resolved, None);
        if let Some(cached) = cached_metadata_response(state, &cache_key).await {
            state.metrics.observe_cache(
                resolved.config.tenant_id,
                resolved.config.id,
                resolved.config.adapter,
                "metadata",
                "hit",
            );
            let body = if resolved.config.adapter == RegistryAdapter::Cargo
                && !cached.status.is_success()
            {
                cached.body
            } else {
                prepare_metadata_body(
                    state,
                    resolved,
                    decision,
                    resolved.config.adapter,
                    &resolved.config.mount_path,
                    &proxy_base_url,
                    &cached.headers,
                    cached.body,
                )
                .await?
            };
            return build_upstream_response(
                cached.status,
                cached.headers,
                body,
                advisory,
                decision,
                &resolved.config.mount_path,
                &proxy_base_url,
            );
        }
        state.metrics.observe_cache(
            resolved.config.tenant_id,
            resolved.config.id,
            resolved.config.adapter,
            "metadata",
            "miss",
        );
        let upstream_path = upstream_path_for_decision(resolved, decision);
        let upstream_url = adapter_upstream_request_url(
            &state.cargo_download_mac_key,
            resolved.config.id,
            resolved.config.adapter,
            &resolved.config.upstream_url,
            &resolved.config.cargo_allowed_download_origins,
            &upstream_path,
        )?;
        let upstream_started = Instant::now();
        let mut request_builder = upstream_client(state, resolved).get(upstream_url);
        request_builder = inject_upstream_credentials(request_builder, resolved)?;
        let upstream_response = request_builder
            .send()
            .await
            .map_err(UpstreamProxyError::Request)?;
        let status = upstream_response.status();
        let upstream_headers = upstream_response.headers().clone();
        let bytes = upstream_response
            .bytes()
            .await
            .map_err(UpstreamProxyError::Body)?;
        state.metrics.observe_upstream(
            resolved.config.tenant_id,
            resolved.config.id,
            resolved.config.adapter,
            "metadata",
            status,
            upstream_started.elapsed(),
        );
        let body = if resolved.config.adapter == RegistryAdapter::Cargo && !status.is_success() {
            bytes.to_vec()
        } else {
            prepare_metadata_body(
                state,
                resolved,
                decision,
                resolved.config.adapter,
                &resolved.config.mount_path,
                &proxy_base_url,
                &upstream_headers,
                bytes.to_vec(),
            )
            .await?
        };
        cache_metadata_response(
            state,
            resolved,
            &cache_key,
            status,
            upstream_headers.clone(),
            bytes.to_vec(),
        )
        .await;
        (status, upstream_headers, body)
    };
    build_upstream_response(
        status,
        upstream_headers,
        body,
        advisory,
        decision,
        &resolved.config.mount_path,
        &proxy_base_url,
    )
}

fn inject_upstream_credentials(
    request_builder: reqwest::RequestBuilder,
    resolved: &ResolvedRegistryConfig,
) -> Result<reqwest::RequestBuilder, UpstreamProxyError> {
    match resolved.config.auth_type {
        CredentialAuthType::None => Ok(request_builder),
        CredentialAuthType::Bearer => {
            let credential = upstream_credential_value(resolved)?;
            Ok(request_builder.bearer_auth(credential))
        }
        CredentialAuthType::Basic => {
            let credential = upstream_credential_value(resolved)?;
            let header_value = format!("Basic {}", BASE64_STANDARD.encode(credential.as_bytes()));
            Ok(request_builder.header("authorization", header_value))
        }
        CredentialAuthType::Mtls => Err(UpstreamProxyError::UnsupportedAuthType),
    }
}

fn upstream_credential_value(
    resolved: &ResolvedRegistryConfig,
) -> Result<String, UpstreamProxyError> {
    let env_var = resolved
        .config
        .credential_env_var
        .as_deref()
        .ok_or(UpstreamProxyError::MissingCredentialReference)?;
    std::env::var(env_var).map_err(|_| UpstreamProxyError::MissingCredentialReference)
}

fn build_upstream_response(
    status: StatusCode,
    upstream_headers: HeaderMap,
    body: Vec<u8>,
    advisory: AdvisoryHeaderPayload,
    decision: &DecisionResponse,
    mount_path: &str,
    proxy_base_url: &str,
) -> Result<Response, UpstreamProxyError> {
    let mut response = Response::builder().status(status);
    if let Some(headers) = response.headers_mut() {
        copy_safe_upstream_headers(&upstream_headers, headers);
        if let Some(location) = upstream_headers
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
        {
            let rewritten = rewrite_registry_url(mount_path, proxy_base_url, location);
            if let Ok(header_value) = HeaderValue::from_str(&rewritten) {
                headers.insert(LOCATION, header_value);
            }
        }
        if let Ok(value) = advisory.to_header_value()
            && let Ok(header_value) = HeaderValue::from_str(&value)
        {
            headers.insert(HeaderName::from_static(ADVISORY_HEADER), header_value);
        }
        if let Ok(header_value) = HeaderValue::from_str(&decision.trace_id) {
            headers.insert(HeaderName::from_static(TRACE_HEADER), header_value);
        }
    }
    response
        .body(Body::from(body))
        .map_err(UpstreamProxyError::ResponseBuild)
}

fn build_passthrough_upstream_response(
    status: StatusCode,
    upstream_headers: HeaderMap,
    body: Vec<u8>,
    trace_id: &str,
    mount_path: &str,
    proxy_base_url: &str,
) -> Result<Response, UpstreamProxyError> {
    let mut response = Response::builder().status(status);
    if let Some(headers) = response.headers_mut() {
        copy_safe_upstream_headers(&upstream_headers, headers);
        if let Some(location) = upstream_headers
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
        {
            let rewritten = rewrite_registry_url(mount_path, proxy_base_url, location);
            if let Ok(header_value) = HeaderValue::from_str(&rewritten) {
                headers.insert(LOCATION, header_value);
            }
        }
        if let Ok(header_value) = HeaderValue::from_str(trace_id) {
            headers.insert(HeaderName::from_static(TRACE_HEADER), header_value);
        }
    }
    response
        .body(Body::from(body))
        .map_err(UpstreamProxyError::ResponseBuild)
}

fn upstream_path_for_decision(
    resolved: &ResolvedRegistryConfig,
    decision: &DecisionResponse,
) -> String {
    if resolved.config.adapter == RegistryAdapter::Npm
        && decision.decision == PolicyDecision::FallbackToApprovedCandidate
        && let Some(candidate) = &decision.fallback_coordinate
        && npm_fallback_may_rewrite_metadata(&resolved.upstream_path)
    {
        return match &candidate.namespace {
            Some(namespace) if !namespace.is_empty() => format!("@{namespace}/{}", candidate.name),
            _ => candidate.name.clone(),
        };
    }
    resolved.upstream_path.clone()
}

fn npm_fallback_may_rewrite_metadata(upstream_path: &str) -> bool {
    npm_request_context(upstream_path)
        .map(|(kind, _, explicit_version_or_integrity)| {
            kind == PackageRequestKind::Metadata && !explicit_version_or_integrity
        })
        .unwrap_or(false)
}

fn upstream_request_url(
    base_url: &str,
    upstream_path: &str,
) -> Result<url::Url, UpstreamProxyError> {
    let mut base = url::Url::parse(base_url).map_err(|_| UpstreamProxyError::InvalidUpstreamUrl)?;
    if !base.path().ends_with('/') {
        base.set_path(&format!("{}/", base.path().trim_end_matches('/')));
    }
    base.join(upstream_path.trim_start_matches('/'))
        .map_err(|_| UpstreamProxyError::InvalidUpstreamUrl)
}

fn upstream_request_url_with_query(
    base_url: &str,
    upstream_path: &str,
    query: Option<&str>,
) -> Result<url::Url, UpstreamProxyError> {
    let mut url = upstream_request_url(base_url, upstream_path)?;
    url.set_query(query.filter(|value| !value.is_empty()));
    Ok(url)
}

fn adapter_upstream_request_url(
    cargo_download_mac_key: &[u8],
    config_id: Uuid,
    adapter: RegistryAdapter,
    base_url: &str,
    cargo_allowed_download_origins: &[String],
    upstream_path: &str,
) -> Result<url::Url, UpstreamProxyError> {
    if adapter == RegistryAdapter::Cargo
        && let Some((encoded_base, signature, suffix)) =
            cargo_proxy_download_components(upstream_path)
    {
        let original_base = decode_cargo_proxy_base(encoded_base)?;
        if signature
            != cargo_download_base_signature(cargo_download_mac_key, config_id, &original_base)
        {
            return Err(UpstreamProxyError::InvalidCargoRegistryConfig);
        }
        let mut url =
            resolve_cargo_download_base(base_url, cargo_allowed_download_origins, &original_base)?;
        let joined_path = format!("{}/{}", url.path().trim_end_matches('/'), suffix);
        url.set_path(&joined_path);
        return Ok(url);
    }

    upstream_request_url(base_url, upstream_path)
}

fn cargo_proxy_download_components(upstream_path: &str) -> Option<(&str, &str, &str)> {
    cargo_proxy_route_components(CARGO_DL_PROXY_PREFIX, upstream_path)
}

fn cargo_proxy_api_components(upstream_path: &str) -> Option<(&str, &str, &str)> {
    cargo_proxy_route_components(CARGO_API_PROXY_PREFIX, upstream_path)
}

fn cargo_proxy_route_components<'a>(
    prefix: &str,
    upstream_path: &'a str,
) -> Option<(&'a str, &'a str, &'a str)> {
    let prefix = format!("{prefix}/");
    let rest = upstream_path.strip_prefix(&prefix)?;
    let (encoded_base, rest) = rest.split_once('/')?;
    let (signature, suffix) = rest.split_once('/')?;
    (!suffix.is_empty()).then_some((encoded_base, signature, suffix))
}

fn cargo_proxy_api_path(upstream_path: &str) -> bool {
    cargo_proxy_api_components(upstream_path).is_some()
}

fn cargo_registry_api_request_supported(method: &Method, upstream_path: &str) -> bool {
    let Some((_, _, suffix)) = cargo_proxy_api_components(upstream_path) else {
        return false;
    };
    cargo_registry_api_suffix_supported(method, suffix)
}

fn cargo_registry_api_suffix_supported(method: &Method, suffix: &str) -> bool {
    let segments: Vec<_> = suffix
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    match (method.as_str(), segments.as_slice()) {
        ("GET", ["api", "v1", "crates"]) => true,
        ("POST" | "PUT", ["api", "v1", "crates", "new"]) => true,
        ("DELETE", ["api", "v1", "crates", crate_name, version, "yank"])
            if canonicalize_cargo_name(crate_name).is_some()
                && looks_like_cargo_version(version) =>
        {
            true
        }
        ("PUT", ["api", "v1", "crates", crate_name, version, "unyank"])
            if canonicalize_cargo_name(crate_name).is_some()
                && looks_like_cargo_version(version) =>
        {
            true
        }
        ("GET" | "PUT" | "DELETE", ["api", "v1", "crates", crate_name, "owners"])
            if canonicalize_cargo_name(crate_name).is_some() =>
        {
            true
        }
        _ => false,
    }
}

fn cargo_rewritten_download_base(
    cargo_download_mac_key: &[u8],
    config_id: Uuid,
    mount_path: &str,
    proxy_base_url: &str,
    upstream_base_url: &str,
    cargo_allowed_download_origins: &[String],
    original: &str,
) -> Result<String, UpstreamProxyError> {
    resolve_cargo_download_base(upstream_base_url, cargo_allowed_download_origins, original)?;

    let mount = normalized_mount_path(mount_path);
    let encoded = BASE64_URL_SAFE_NO_PAD.encode(original.as_bytes());
    let signature = cargo_download_base_signature(cargo_download_mac_key, config_id, original);
    Ok(format!(
        "{proxy_base_url}{mount}{CARGO_DL_PROXY_PREFIX}/{encoded}/{signature}"
    ))
}

fn cargo_rewritten_api_base(
    cargo_download_mac_key: &[u8],
    config_id: Uuid,
    mount_path: &str,
    proxy_base_url: &str,
    upstream_base_url: &str,
    original: &str,
) -> Result<String, UpstreamProxyError> {
    resolve_registry_local_cargo_base(upstream_base_url, original)?;

    let mount = normalized_mount_path(mount_path);
    let encoded = BASE64_URL_SAFE_NO_PAD.encode(original.as_bytes());
    let signature = cargo_api_base_signature(cargo_download_mac_key, config_id, original);
    Ok(format!(
        "{proxy_base_url}{mount}{CARGO_API_PROXY_PREFIX}/{encoded}/{signature}"
    ))
}

fn cargo_download_base_signature(
    cargo_download_mac_key: &[u8],
    config_id: Uuid,
    original: &str,
) -> String {
    cargo_proxy_base_signature(
        cargo_download_mac_key,
        "cargo-dl-base:",
        config_id,
        original,
    )
}

fn cargo_api_base_signature(
    cargo_download_mac_key: &[u8],
    config_id: Uuid,
    original: &str,
) -> String {
    cargo_proxy_base_signature(
        cargo_download_mac_key,
        "cargo-api-base:",
        config_id,
        original,
    )
}

fn cargo_proxy_base_signature(
    cargo_download_mac_key: &[u8],
    domain: &str,
    config_id: Uuid,
    original: &str,
) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, cargo_download_mac_key);
    let mut message =
        Vec::with_capacity(domain.len() + config_id.as_bytes().len() + 1 + original.len());
    message.extend_from_slice(domain.as_bytes());
    message.extend_from_slice(config_id.as_bytes());
    message.extend_from_slice(b":");
    message.extend_from_slice(original.as_bytes());
    hex::encode(hmac::sign(&key, &message).as_ref())
}

fn decode_cargo_proxy_base(encoded_base: &str) -> Result<String, UpstreamProxyError> {
    let original_base = BASE64_URL_SAFE_NO_PAD
        .decode(encoded_base)
        .map_err(|_| UpstreamProxyError::InvalidCargoRegistryConfig)?;
    String::from_utf8(original_base).map_err(|_| UpstreamProxyError::InvalidCargoRegistryConfig)
}

fn resolve_registry_local_cargo_base(
    upstream_base_url: &str,
    original: &str,
) -> Result<url::Url, UpstreamProxyError> {
    let upstream_base = validated_cargo_upstream_base(upstream_base_url)?;
    let resolved = if let Ok(parsed) = url::Url::parse(original) {
        parsed
    } else {
        upstream_base
            .join(original)
            .map_err(|_| UpstreamProxyError::InvalidCargoRegistryConfig)?
    };
    validate_cargo_download_url(&resolved)?;
    if !same_origin_url(&resolved, &upstream_base) {
        return Err(UpstreamProxyError::InvalidCargoRegistryConfig);
    }
    Ok(resolved)
}

fn resolve_cargo_download_base(
    upstream_base_url: &str,
    cargo_allowed_download_origins: &[String],
    original: &str,
) -> Result<url::Url, UpstreamProxyError> {
    let upstream_base = validated_cargo_upstream_base(upstream_base_url)?;
    let resolved = if let Ok(parsed) = url::Url::parse(original) {
        parsed
    } else {
        upstream_base
            .join(original)
            .map_err(|_| UpstreamProxyError::InvalidCargoRegistryConfig)?
    };
    validate_cargo_download_url(&resolved)?;
    if !cargo_download_origin_allowed(upstream_base_url, cargo_allowed_download_origins, &resolved)?
    {
        return Err(UpstreamProxyError::InvalidCargoRegistryConfig);
    }
    Ok(resolved)
}

fn validated_cargo_upstream_base(upstream_base_url: &str) -> Result<url::Url, UpstreamProxyError> {
    let mut upstream_base = url::Url::parse(upstream_base_url)
        .map_err(|_| UpstreamProxyError::InvalidCargoRegistryConfig)?;
    if !upstream_base.path().ends_with('/') {
        upstream_base.set_path(&format!("{}/", upstream_base.path().trim_end_matches('/')));
    }
    Ok(upstream_base)
}

fn validate_cargo_download_url(url: &url::Url) -> Result<(), UpstreamProxyError> {
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(UpstreamProxyError::InvalidCargoRegistryConfig);
    }
    Ok(())
}

fn cargo_download_origin_allowed(
    upstream_base_url: &str,
    cargo_allowed_download_origins: &[String],
    url: &url::Url,
) -> Result<bool, UpstreamProxyError> {
    let upstream_base = validated_cargo_upstream_base(upstream_base_url)?;
    if same_origin_url(url, &upstream_base) {
        return Ok(true);
    }
    let origin = canonical_cargo_origin(url)?;
    Ok(cargo_allowed_download_origins
        .iter()
        .any(|allowed| allowed == &origin))
}

fn cargo_download_uses_primary_origin(
    upstream_base_url: &str,
    url: &url::Url,
) -> Result<bool, UpstreamProxyError> {
    let upstream_base = validated_cargo_upstream_base(upstream_base_url)?;
    Ok(same_origin_url(url, &upstream_base))
}

fn canonical_cargo_origin(url: &url::Url) -> Result<String, UpstreamProxyError> {
    validate_cargo_download_url(url)?;
    let host = url
        .host_str()
        .ok_or(UpstreamProxyError::InvalidCargoRegistryConfig)?;
    let mut origin = format!("{}://{}", url.scheme(), host);
    if let Some(port) = url.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    Ok(origin)
}

fn same_origin_url(left: &url::Url, right: &url::Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn cargo_api_proxy_mount_path(mount_path: &str, upstream_path: &str) -> Option<String> {
    let (encoded_base, signature, _) = cargo_proxy_api_components(upstream_path)?;
    Some(format!(
        "{}/{CARGO_API_PROXY_PREFIX}/{encoded_base}/{signature}",
        mount_path.trim_end_matches('/')
    ))
}

async fn proxy_cargo_registry_api(
    state: &AppState,
    resolved: &ResolvedRegistryConfig,
    trace_id: &str,
    proxy_base_url: &str,
    method: Method,
    request_headers: HeaderMap,
    request_body: Vec<u8>,
    query: Option<&str>,
) -> Result<Response, UpstreamProxyError> {
    enforce_artifact_size_limit(
        state.max_artifact_bytes,
        &request_headers,
        Some(request_body.len() as u64),
    )?;
    let proxy_mount_path =
        cargo_api_proxy_mount_path(&resolved.config.mount_path, &resolved.upstream_path)
            .ok_or(UpstreamProxyError::InvalidCargoRegistryConfig)?;
    let upstream_url = cargo_api_request_url(
        &state.cargo_download_mac_key,
        resolved.config.id,
        &resolved.config.upstream_url,
        &resolved.upstream_path,
        query,
    )?;
    let upstream_started = Instant::now();
    let mut forwarded_headers = HeaderMap::new();
    copy_cargo_api_request_headers(&request_headers, &mut forwarded_headers);

    let mut request_builder = upstream_client(state, resolved)
        .request(method, upstream_url)
        .headers(forwarded_headers);
    if !request_body.is_empty() {
        request_builder = request_builder.body(request_body);
    }

    let upstream_response = request_builder
        .send()
        .await
        .map_err(UpstreamProxyError::Request)?;
    let status = upstream_response.status();
    let upstream_headers = upstream_response.headers().clone();
    let body = upstream_response
        .bytes()
        .await
        .map_err(UpstreamProxyError::Body)?
        .to_vec();
    state.metrics.observe_upstream(
        resolved.config.tenant_id,
        resolved.config.id,
        resolved.config.adapter,
        "api",
        status,
        upstream_started.elapsed(),
    );
    build_passthrough_upstream_response(
        status,
        upstream_headers,
        body,
        trace_id,
        &proxy_mount_path,
        proxy_base_url,
    )
}

fn cargo_api_request_url(
    cargo_download_mac_key: &[u8],
    config_id: Uuid,
    upstream_base_url: &str,
    upstream_path: &str,
    query: Option<&str>,
) -> Result<url::Url, UpstreamProxyError> {
    let Some((encoded_base, signature, suffix)) = cargo_proxy_api_components(upstream_path) else {
        return Err(UpstreamProxyError::InvalidCargoRegistryConfig);
    };
    let original_base = decode_cargo_proxy_base(encoded_base)?;
    if signature != cargo_api_base_signature(cargo_download_mac_key, config_id, &original_base) {
        return Err(UpstreamProxyError::InvalidCargoRegistryConfig);
    }
    let mut url = resolve_registry_local_cargo_base(upstream_base_url, &original_base)?;
    url.set_path(&join_registry_path_with_suffix(url.path(), suffix));
    let merged_query = match (
        url.query().filter(|value| !value.is_empty()),
        query.filter(|value| !value.is_empty()),
    ) {
        (Some(base_query), Some(request_query)) => Some(format!("{base_query}&{request_query}")),
        (Some(base_query), None) => Some(base_query.to_owned()),
        (None, Some(request_query)) => Some(request_query.to_owned()),
        (None, None) => None,
    };
    url.set_query(merged_query.as_deref());
    Ok(url)
}

fn join_registry_path_with_suffix(base_path: &str, suffix: &str) -> String {
    let base_segments: Vec<_> = base_path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let suffix_segments: Vec<_> = suffix
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();

    let max_overlap = (0..=base_segments.len().min(suffix_segments.len()))
        .rev()
        .find(|overlap| {
            base_segments[base_segments.len().saturating_sub(*overlap)..]
                == suffix_segments[..*overlap]
        })
        .unwrap_or(0);

    let mut joined_segments = base_segments;
    joined_segments.extend_from_slice(&suffix_segments[max_overlap..]);
    if joined_segments.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", joined_segments.join("/"))
    }
}

async fn prepare_metadata_body(
    state: &AppState,
    resolved: &ResolvedRegistryConfig,
    parent_decision: &DecisionResponse,
    adapter: RegistryAdapter,
    mount_path: &str,
    proxy_base_url: &str,
    headers: &HeaderMap,
    body: Vec<u8>,
) -> Result<Vec<u8>, UpstreamProxyError> {
    let filtered =
        maybe_filter_metadata_body(state, resolved, parent_decision, headers, body).await?;
    let filtered = maybe_apply_npm_fallback_metadata(resolved, parent_decision, headers, filtered);
    Ok(maybe_rewrite_metadata_body(
        adapter,
        mount_path,
        proxy_base_url,
        headers,
        filtered,
    ))
}

async fn proxy_cargo_registry_config(
    state: &AppState,
    resolved: &ResolvedRegistryConfig,
    trace_id: &str,
    proxy_base_url: &str,
) -> Result<Response, UpstreamProxyError> {
    let upstream_url = adapter_upstream_request_url(
        &state.cargo_download_mac_key,
        resolved.config.id,
        resolved.config.adapter,
        &resolved.config.upstream_url,
        &resolved.config.cargo_allowed_download_origins,
        &resolved.upstream_path,
    )?;
    let upstream_started = Instant::now();
    let mut request_builder = upstream_client(state, resolved).get(upstream_url);
    request_builder = inject_upstream_credentials(request_builder, resolved)?;
    let upstream_response = request_builder
        .send()
        .await
        .map_err(UpstreamProxyError::Request)?;
    let status = upstream_response.status();
    let upstream_headers = upstream_response.headers().clone();
    let body = upstream_response
        .bytes()
        .await
        .map_err(UpstreamProxyError::Body)?
        .to_vec();
    state.metrics.observe_upstream(
        resolved.config.tenant_id,
        resolved.config.id,
        resolved.config.adapter,
        "metadata",
        status,
        upstream_started.elapsed(),
    );
    if !status.is_success() {
        return build_passthrough_upstream_response(
            status,
            upstream_headers,
            body,
            trace_id,
            &resolved.config.mount_path,
            proxy_base_url,
        );
    }
    let rewritten = rewrite_cargo_registry_config(
        &state.cargo_download_mac_key,
        resolved.config.id,
        &resolved.config.mount_path,
        proxy_base_url,
        &resolved.config.upstream_url,
        &resolved.config.cargo_allowed_download_origins,
        body,
    )?;
    build_passthrough_upstream_response(
        status,
        upstream_headers,
        rewritten,
        trace_id,
        &resolved.config.mount_path,
        proxy_base_url,
    )
}

async fn maybe_filter_metadata_body(
    state: &AppState,
    resolved: &ResolvedRegistryConfig,
    parent_decision: &DecisionResponse,
    headers: &HeaderMap,
    body: Vec<u8>,
) -> Result<Vec<u8>, UpstreamProxyError> {
    if resolved.config.adapter == RegistryAdapter::Cargo
        && !cargo_registry_config_path(&resolved.upstream_path)
    {
        return filter_cargo_sparse_candidates(state, resolved, parent_decision, body).await;
    }

    let Some(content_type) = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(body);
    };
    match resolved.config.adapter {
        RegistryAdapter::Pypi if content_type.contains("html") => {
            filter_pypi_simple_candidates(state, resolved, parent_decision, body).await
        }
        RegistryAdapter::Pypi if content_type.contains("json") => {
            filter_pypi_json_candidates(state, resolved, parent_decision, body).await
        }
        _ => Ok(body),
    }
}

fn maybe_apply_npm_fallback_metadata(
    resolved: &ResolvedRegistryConfig,
    parent_decision: &DecisionResponse,
    headers: &HeaderMap,
    body: Vec<u8>,
) -> Vec<u8> {
    let Some(content_type) = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return body;
    };

    if resolved.config.adapter != RegistryAdapter::Npm || !content_type.contains("json") {
        return body;
    }

    if parent_decision.decision != PolicyDecision::FallbackToApprovedCandidate {
        return body;
    }

    let Some(candidate) = parent_decision.fallback_coordinate.as_ref() else {
        return body;
    };

    let Ok((kind, requested, explicit_version_or_integrity)) =
        npm_request_context(&resolved.upstream_path)
    else {
        return body;
    };

    if kind != PackageRequestKind::Metadata
        || explicit_version_or_integrity
        || candidate.namespace != requested.namespace
        || candidate.name != requested.name
    {
        return body;
    }

    let Some(candidate_version) = candidate.version.as_deref() else {
        return body;
    };

    filter_npm_packument_to_version(body, candidate_version)
}

fn maybe_rewrite_metadata_body(
    adapter: RegistryAdapter,
    mount_path: &str,
    proxy_base_url: &str,
    headers: &HeaderMap,
    body: Vec<u8>,
) -> Vec<u8> {
    let Some(content_type) = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return body;
    };
    match adapter {
        RegistryAdapter::Npm if content_type.contains("json") => {
            rewrite_npm_metadata_urls(mount_path, proxy_base_url, body)
        }
        RegistryAdapter::Pypi if content_type.contains("html") => {
            rewrite_pypi_simple_links(mount_path, proxy_base_url, body)
        }
        RegistryAdapter::Pypi if content_type.contains("json") => {
            rewrite_pypi_json_links(mount_path, proxy_base_url, body)
        }
        _ => body,
    }
}

fn rewrite_cargo_registry_config(
    cargo_download_mac_key: &[u8],
    config_id: Uuid,
    mount_path: &str,
    proxy_base_url: &str,
    upstream_base_url: &str,
    cargo_allowed_download_origins: &[String],
    body: Vec<u8>,
) -> Result<Vec<u8>, UpstreamProxyError> {
    let mut payload =
        serde_json::from_slice::<serde_json::Value>(&body).map_err(UpstreamProxyError::Json)?;
    let Some(object) = payload.as_object_mut() else {
        return Err(UpstreamProxyError::InvalidCargoRegistryConfig);
    };
    if let Some(value) = object.get_mut("dl")
        && let Some(url) = value.as_str()
    {
        if url.contains('{') || url.contains('}') {
            return Err(UpstreamProxyError::InvalidCargoRegistryConfig);
        }
        *value = json!(cargo_rewritten_download_base(
            cargo_download_mac_key,
            config_id,
            mount_path,
            proxy_base_url,
            upstream_base_url,
            cargo_allowed_download_origins,
            url,
        )?);
    } else {
        return Err(UpstreamProxyError::InvalidCargoRegistryConfig);
    }
    if let Some(value) = object.get_mut("api") {
        let Some(url) = value.as_str() else {
            return Err(UpstreamProxyError::InvalidCargoRegistryConfig);
        };
        if url.contains('{') || url.contains('}') {
            return Err(UpstreamProxyError::InvalidCargoRegistryConfig);
        }
        *value = json!(cargo_rewritten_api_base(
            cargo_download_mac_key,
            config_id,
            mount_path,
            proxy_base_url,
            upstream_base_url,
            url,
        )?);
    }
    serde_json::to_vec(&payload).map_err(UpstreamProxyError::Json)
}

async fn filter_cargo_sparse_candidates(
    state: &AppState,
    resolved: &ResolvedRegistryConfig,
    parent_decision: &DecisionResponse,
    body: Vec<u8>,
) -> Result<Vec<u8>, UpstreamProxyError> {
    let text =
        String::from_utf8(body).map_err(|_| UpstreamProxyError::InvalidCargoSparseMetadata)?;
    let Ok((PackageRequestKind::Metadata, requested_coordinate, _)) =
        cargo_request_context(&resolved.upstream_path)
    else {
        return Err(UpstreamProxyError::InvalidCargoSparseMetadata);
    };

    let mut kept = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let entry = serde_json::from_str::<serde_json::Value>(line)
            .map_err(|_| UpstreamProxyError::InvalidCargoSparseMetadata)?;
        if cargo_sparse_candidate_allowed(
            state,
            resolved,
            parent_decision,
            &requested_coordinate.name,
            &entry,
        )
        .await?
        {
            kept.push(line);
        }
    }

    let mut filtered = kept.join("\n");
    if text.ends_with('\n') && !filtered.is_empty() {
        filtered.push('\n');
    }
    Ok(filtered.into_bytes())
}

async fn cargo_sparse_candidate_allowed(
    state: &AppState,
    resolved: &ResolvedRegistryConfig,
    parent_decision: &DecisionResponse,
    requested_name: &str,
    entry: &serde_json::Value,
) -> Result<bool, UpstreamProxyError> {
    let (package_name, version, digest) = cargo_sparse_entry(entry)?;
    if package_name != requested_name {
        return Err(UpstreamProxyError::InvalidCargoSparseMetadata);
    }
    candidate_allowed_for_coordinate(
        state,
        resolved,
        parent_decision,
        PackageCoordinate::new(
            PackageEcosystem::Cargo,
            package_name.clone(),
            Some(version.to_owned()),
            None::<String>,
        ),
        format!("{package_name}@{version}"),
        Some(digest),
        None,
    )
    .await
}

fn cargo_sparse_entry(
    entry: &serde_json::Value,
) -> Result<(String, String, ArtifactDigest), UpstreamProxyError> {
    let Some(version) = entry.get("vers").and_then(|value| value.as_str()) else {
        return Err(UpstreamProxyError::InvalidCargoSparseMetadata);
    };
    if !looks_like_cargo_version(version) {
        return Err(UpstreamProxyError::InvalidCargoSparseMetadata);
    }
    let raw_name = entry
        .get("name")
        .and_then(|value| value.as_str())
        .ok_or(UpstreamProxyError::InvalidCargoSparseMetadata)?;
    if raw_name.trim() != raw_name {
        return Err(UpstreamProxyError::InvalidCargoSparseMetadata);
    }
    let package_name =
        canonicalize_cargo_name(raw_name).ok_or(UpstreamProxyError::InvalidCargoSparseMetadata)?;
    let checksum = entry
        .get("cksum")
        .and_then(|value| value.as_str())
        .ok_or(UpstreamProxyError::InvalidCargoSparseMetadata)?;
    let digest = ArtifactDigest::sha256(checksum)
        .map_err(|_| UpstreamProxyError::InvalidCargoSparseMetadata)?;
    Ok((package_name, version.to_owned(), digest))
}

fn cargo_sparse_expected_digest_for_version(
    body: &[u8],
    requested_name: &str,
    requested_version: &str,
) -> Result<ArtifactDigest, UpstreamProxyError> {
    let text =
        std::str::from_utf8(body).map_err(|_| UpstreamProxyError::InvalidCargoSparseMetadata)?;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let entry = serde_json::from_str::<serde_json::Value>(line)
            .map_err(|_| UpstreamProxyError::InvalidCargoSparseMetadata)?;
        let (package_name, version, digest) = cargo_sparse_entry(&entry)?;
        if package_name != requested_name {
            return Err(UpstreamProxyError::InvalidCargoSparseMetadata);
        }
        if version == requested_version {
            return Ok(digest);
        }
    }
    Err(UpstreamProxyError::InvalidCargoSparseMetadata)
}

async fn filter_pypi_simple_candidates(
    state: &AppState,
    resolved: &ResolvedRegistryConfig,
    parent_decision: &DecisionResponse,
    body: Vec<u8>,
) -> Result<Vec<u8>, UpstreamProxyError> {
    let text = match String::from_utf8(body) {
        Ok(text) => text,
        Err(error) => return Ok(error.into_bytes()),
    };
    let mut output = String::with_capacity(text.len());
    let lower = text.to_ascii_lowercase();
    let mut cursor = 0;
    while let Some(anchor_offset) = lower[cursor..].find("<a") {
        let anchor_start = cursor + anchor_offset;
        output.push_str(&text[cursor..anchor_start]);
        let Some(anchor_end_offset) = lower[anchor_start..].find("</a>") else {
            output.push_str(&text[anchor_start..]);
            return Ok(output.into_bytes());
        };
        let anchor_end = anchor_start + anchor_end_offset + "</a>".len();
        let anchor = &text[anchor_start..anchor_end];
        let keep = if let Some(href) = extract_href(anchor) {
            candidate_allowed_for_url(state, resolved, parent_decision, &href).await?
        } else {
            true
        };
        if keep {
            output.push_str(anchor);
        }
        cursor = anchor_end;
    }
    output.push_str(&text[cursor..]);
    Ok(output.into_bytes())
}

async fn filter_pypi_json_candidates(
    state: &AppState,
    resolved: &ResolvedRegistryConfig,
    parent_decision: &DecisionResponse,
    body: Vec<u8>,
) -> Result<Vec<u8>, UpstreamProxyError> {
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return Ok(body);
    };
    if let Some(files) = value
        .get_mut("files")
        .and_then(|value| value.as_array_mut())
    {
        let mut kept = Vec::new();
        for file in std::mem::take(files) {
            if pypi_json_candidate_allowed(state, resolved, parent_decision, &file).await? {
                kept.push(file);
            }
        }
        *files = kept;
    }
    if let Some(files) = value.get_mut("urls").and_then(|value| value.as_array_mut()) {
        let mut kept = Vec::new();
        for file in std::mem::take(files) {
            if pypi_json_candidate_allowed(state, resolved, parent_decision, &file).await? {
                kept.push(file);
            }
        }
        *files = kept;
    }
    serde_json::to_vec(&value).map_err(UpstreamProxyError::Json)
}

async fn pypi_json_candidate_allowed(
    state: &AppState,
    resolved: &ResolvedRegistryConfig,
    parent_decision: &DecisionResponse,
    file: &serde_json::Value,
) -> Result<bool, UpstreamProxyError> {
    let Some(url) = file
        .get("url")
        .or_else(|| file.get("download_url"))
        .and_then(|value| value.as_str())
    else {
        return Ok(true);
    };
    let digest = file
        .get("hashes")
        .and_then(|hashes| hashes.get("sha256"))
        .and_then(|value| value.as_str())
        .and_then(|value| ArtifactDigest::sha256(value).ok())
        .or_else(|| digest_from_url_fragment(url));
    candidate_allowed_for_url_with_digest(state, resolved, parent_decision, url, digest).await
}

async fn candidate_allowed_for_url(
    state: &AppState,
    resolved: &ResolvedRegistryConfig,
    parent_decision: &DecisionResponse,
    url: &str,
) -> Result<bool, UpstreamProxyError> {
    candidate_allowed_for_url_with_digest(
        state,
        resolved,
        parent_decision,
        url,
        digest_from_url_fragment(url),
    )
    .await
}

async fn candidate_allowed_for_url_with_digest(
    state: &AppState,
    resolved: &ResolvedRegistryConfig,
    parent_decision: &DecisionResponse,
    url: &str,
    digest: Option<ArtifactDigest>,
) -> Result<bool, UpstreamProxyError> {
    let Some(file_name) = file_name_from_registry_url(url) else {
        return Ok(true);
    };
    let Some(coordinate) = pypi_coordinate_from_distribution_filename(&file_name) else {
        return Ok(true);
    };
    candidate_allowed_for_coordinate(
        state,
        resolved,
        parent_decision,
        coordinate,
        file_name,
        digest,
        Some(url.to_owned()),
    )
    .await
}

async fn candidate_allowed_for_coordinate(
    state: &AppState,
    resolved: &ResolvedRegistryConfig,
    parent_decision: &DecisionResponse,
    coordinate: PackageCoordinate,
    candidate_id: String,
    requested_digest: Option<ArtifactDigest>,
    source_url: Option<String>,
) -> Result<bool, UpstreamProxyError> {
    let decision_request = DecisionRequest {
        tenant_id: parent_decision.tenant_id,
        registry_config_id: resolved.config.id,
        policy_profile_id: parent_decision.policy_profile_id,
        request: NormalizedPackageRequest {
            kind: PackageRequestKind::Artifact,
            tenant_id: parent_decision.tenant_id,
            registry_config_id: resolved.config.id,
            policy_profile_id: parent_decision.policy_profile_id,
            coordinate,
            trace_id: format!("{}:candidate:{}", parent_decision.trace_id, candidate_id),
            requested_digest,
            source_url,
            explicit_version_or_integrity: true,
        },
    };
    let cache_key = cache_key_for_decision(&decision_request);
    let trace_id = decision_request.request.trace_id.clone();
    let decision = if let Some(decision) = cached_decision(state, &cache_key).await {
        state.metrics.observe_cache(
            resolved.config.tenant_id,
            resolved.config.id,
            resolved.config.adapter,
            "decision",
            "hit",
        );
        decision
    } else {
        state.metrics.observe_cache(
            resolved.config.tenant_id,
            resolved.config.id,
            resolved.config.adapter,
            "decision",
            "miss",
        );
        let triage_started = Instant::now();
        match state.triage_client.evaluate(&decision_request).await {
            Ok(decision) => {
                state.metrics.observe_triage(
                    resolved.config.tenant_id,
                    resolved.config.id,
                    resolved.config.adapter,
                    "candidate-success",
                    triage_started.elapsed(),
                );
                cache_decision(state, resolved, &cache_key, &decision).await;
                decision
            }
            Err(error) if error.is_outage() => {
                tracing::warn!(
                    tenant_id = %resolved.config.tenant_id,
                    registry_config_id = %resolved.config.id,
                    candidate = %candidate_id,
                    error = %error,
                    "candidate Triage outage occurred during metadata filtering"
                );
                state.metrics.observe_triage(
                    resolved.config.tenant_id,
                    resolved.config.id,
                    resolved.config.adapter,
                    "candidate-outage",
                    triage_started.elapsed(),
                );
                return Ok(resolved.config.mode != PolicyMode::Enforce);
            }
            Err(error) => {
                tracing::warn!(
                    tenant_id = %resolved.config.tenant_id,
                    registry_config_id = %resolved.config.id,
                    candidate = %candidate_id,
                    error = %error,
                    "candidate Triage evaluation failed during metadata filtering"
                );
                state.metrics.observe_triage(
                    resolved.config.tenant_id,
                    resolved.config.id,
                    resolved.config.adapter,
                    "candidate-hard-error",
                    triage_started.elapsed(),
                );
                return Err(UpstreamProxyError::CandidateTriage(error));
            }
        }
    };

    if decision.mode != resolved.config.mode {
        tracing::warn!(
            tenant_id = %resolved.config.tenant_id,
            registry_config_id = %resolved.config.id,
            candidate = %candidate_id,
            expected_mode = ?resolved.config.mode,
            actual_mode = ?decision.mode,
            %trace_id,
            "candidate Triage response mode mismatched the configured registry mode"
        );
        return Err(UpstreamProxyError::InvalidCandidateDecisionMode);
    }

    Ok(!(resolved.config.mode == PolicyMode::Enforce && decision.decision.is_blocking()))
}

fn extract_href(anchor: &str) -> Option<String> {
    extract_href_range(anchor).map(|(_, href)| href)
}

fn extract_href_range(anchor: &str) -> Option<(Range<usize>, String)> {
    let lower = anchor.to_ascii_lowercase();
    let href_start = lower.find("href")?;
    let after_href_start = href_start + "href".len();
    let after_href = &anchor[after_href_start..];
    let equals_offset = after_href.find('=')?;
    let value_search_start = after_href_start + equals_offset + 1;
    let after_equals = &anchor[value_search_start..];
    let value_start = after_equals
        .char_indices()
        .find_map(|(offset, character)| {
            (!character.is_whitespace()).then_some(value_search_start + offset)
        })?;
    let after_equals = &anchor[value_start..];
    let quote = after_equals.chars().next()?;
    if matches!(quote, '"' | '\'') {
        let rest_start = value_start + quote.len_utf8();
        let rest = &anchor[rest_start..];
        let end = rest.find(quote)?;
        let range = rest_start..rest_start + end;
        Some((range.clone(), anchor[range].to_owned()))
    } else {
        let end = after_equals
            .find(|character: char| character.is_whitespace() || character == '>')
            .unwrap_or(after_equals.len());
        let range = value_start..value_start + end;
        Some((range.clone(), anchor[range].to_owned()))
    }
}

fn file_name_from_registry_url(url: &str) -> Option<String> {
    let path = url::Url::parse(url)
        .ok()
        .map(|parsed| parsed.path().to_owned())
        .unwrap_or_else(|| url.split('#').next().unwrap_or(url).to_owned());
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn digest_from_url_fragment(url: &str) -> Option<ArtifactDigest> {
    let fragment = url.split('#').nth(1)?;
    fragment
        .split('&')
        .find_map(|part| part.strip_prefix("sha256="))
        .and_then(|digest| ArtifactDigest::sha256(digest).ok())
}

fn rewrite_npm_metadata_urls(mount_path: &str, proxy_base_url: &str, body: Vec<u8>) -> Vec<u8> {
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return body;
    };
    if let Some(versions) = value
        .get_mut("versions")
        .and_then(|value| value.as_object_mut())
    {
        for version in versions.values_mut() {
            let Some(tarball) = version
                .get_mut("dist")
                .and_then(|dist| dist.get_mut("tarball"))
                .and_then(|tarball| tarball.as_str())
                .map(str::to_owned)
            else {
                continue;
            };
            version["dist"]["tarball"] = serde_json::Value::String(rewrite_registry_url(
                mount_path,
                proxy_base_url,
                &tarball,
            ));
        }
    }
    serde_json::to_vec(&value).unwrap_or(body)
}

fn filter_npm_packument_to_version(body: Vec<u8>, version: &str) -> Vec<u8> {
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return body;
    };

    let Some(selected_version) = value
        .get("versions")
        .and_then(|versions| versions.get(version))
        .cloned()
    else {
        return body;
    };

    let mut filtered_versions = serde_json::Map::new();
    filtered_versions.insert(version.to_owned(), selected_version);
    value["versions"] = serde_json::Value::Object(filtered_versions);

    if let Some(dist_tags) = value
        .get_mut("dist-tags")
        .and_then(|tags| tags.as_object_mut())
    {
        dist_tags.insert(
            "latest".to_owned(),
            serde_json::Value::String(version.to_owned()),
        );
    }

    if let Some(times) = value.get_mut("time").and_then(|time| time.as_object_mut())
        && let Some(version_time) = times.get(version).cloned()
    {
        let created = times.get("created").cloned();
        let modified = times.get("modified").cloned();
        times.clear();
        if let Some(created) = created {
            times.insert("created".to_owned(), created);
        }
        if let Some(modified) = modified {
            times.insert("modified".to_owned(), modified);
        }
        times.insert(version.to_owned(), version_time);
    }

    serde_json::to_vec(&value).unwrap_or(body)
}

fn rewrite_pypi_json_links(mount_path: &str, proxy_base_url: &str, body: Vec<u8>) -> Vec<u8> {
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return body;
    };
    for field in ["files", "urls"] {
        if let Some(files) = value.get_mut(field).and_then(|value| value.as_array_mut()) {
            for file in files {
                for key in ["url", "download_url"] {
                    let Some(url) = file
                        .get_mut(key)
                        .and_then(|url| url.as_str())
                        .map(str::to_owned)
                    else {
                        continue;
                    };
                    file[key] = serde_json::Value::String(rewrite_registry_url(
                        mount_path,
                        proxy_base_url,
                        &url,
                    ));
                }
            }
        }
    }
    serde_json::to_vec(&value).unwrap_or(body)
}

fn rewrite_pypi_simple_links(mount_path: &str, proxy_base_url: &str, body: Vec<u8>) -> Vec<u8> {
    let text = match String::from_utf8(body) {
        Ok(text) => text,
        Err(error) => return error.into_bytes(),
    };
    let lower = text.to_ascii_lowercase();
    let mut output = String::with_capacity(text.len());
    let mut cursor = 0;
    while let Some(anchor_offset) = lower[cursor..].find("<a") {
        let anchor_start = cursor + anchor_offset;
        output.push_str(&text[cursor..anchor_start]);
        let Some(anchor_end_offset) = lower[anchor_start..].find("</a>") else {
            output.push_str(&text[anchor_start..]);
            return output.into_bytes();
        };
        let anchor_end = anchor_start + anchor_end_offset + "</a>".len();
        let anchor = &text[anchor_start..anchor_end];
        if let Some((range, href)) = extract_href_range(anchor) {
            output.push_str(&anchor[..range.start]);
            output.push_str(&rewrite_registry_url(mount_path, proxy_base_url, &href));
            output.push_str(&anchor[range.end..]);
        } else {
            output.push_str(anchor);
        }
        cursor = anchor_end;
    }
    output.push_str(&text[cursor..]);
    output.into_bytes()
}

fn rewrite_registry_url(mount_path: &str, proxy_base_url: &str, original: &str) -> String {
    let mount = normalized_mount_path(mount_path);
    if let Ok(parsed) = url::Url::parse(original) {
        let path = parsed.path().trim_start_matches('/');
        let mut rewritten = format!("{proxy_base_url}{mount}{path}");
        if let Some(query) = parsed.query() {
            rewritten.push('?');
            rewritten.push_str(query);
        }
        if let Some(fragment) = parsed.fragment() {
            rewritten.push('#');
            rewritten.push_str(fragment);
        }
        rewritten
    } else if original.starts_with('/') {
        format!(
            "{proxy_base_url}{mount}{}",
            original.trim_start_matches('/')
        )
    } else {
        let mut normalized = original;
        while let Some(stripped) = normalized.strip_prefix("../") {
            normalized = stripped;
        }
        while let Some(stripped) = normalized.strip_prefix("./") {
            normalized = stripped;
        }
        format!(
            "{proxy_base_url}{mount}{}",
            normalized.trim_start_matches('/')
        )
    }
}

fn normalized_mount_path(mount_path: &str) -> String {
    format!("{}/", mount_path.trim_end_matches('/'))
}

fn redact_sensitive_upstream_headers(headers: &mut HeaderMap) {
    for name in [
        "authorization",
        "cookie",
        "set-cookie",
        "www-authenticate",
        "proxy-authorization",
    ] {
        headers.remove(name);
    }
}

fn copy_cargo_api_request_headers(from: &HeaderMap, to: &mut HeaderMap) {
    for (name, value) in from {
        if name == ACCEPT
            || name == AUTHORIZATION
            || name == CONTENT_TYPE
            || name == USER_AGENT
            || name.as_str().starts_with("cargo-")
        {
            to.insert(name.clone(), value.clone());
        }
    }
}

fn copy_safe_upstream_headers(from: &HeaderMap, to: &mut HeaderMap) {
    for header in [CONTENT_TYPE, CACHE_CONTROL, ETAG, LAST_MODIFIED] {
        if let Some(value) = from.get(&header) {
            to.insert(header, value.clone());
        }
    }
}

fn proxy_base_url(headers: &HeaderMap) -> String {
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .filter(|value| matches!(*value, "http" | "https"))
        .unwrap_or("http");
    let host = headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("localhost");
    format!("{proto}://{host}")
}

#[derive(Debug, thiserror::Error)]
enum UpstreamProxyError {
    #[error("upstream registry URL is invalid")]
    InvalidUpstreamUrl,
    #[error("upstream registry request failed")]
    Request(#[source] reqwest::Error),
    #[error("upstream registry response body failed")]
    Body(#[source] reqwest::Error),
    #[error("upstream registry metadata JSON could not be filtered")]
    Json(#[source] serde_json::Error),
    #[error("artifact digest could not be computed")]
    Digest(#[source] aegiscudo_core::DigestError),
    #[error("candidate Triage evaluation failed")]
    CandidateTriage(#[source] TriageClientError),
    #[error("candidate Triage response mode did not match the configured registry mode")]
    InvalidCandidateDecisionMode,
    #[error("Cargo sparse metadata was malformed")]
    InvalidCargoSparseMetadata,
    #[error("Cargo sparse registry config was invalid")]
    InvalidCargoRegistryConfig,
    #[error("Cargo artifact digest did not match sparse metadata")]
    InvalidCargoArtifactDigest,
    #[error("Cargo download redirects are not supported")]
    UnsupportedCargoDownloadRedirect,
    #[error("Maven repository checksum did not match artifact")]
    MavenChecksumMismatch,
    #[error("artifact exceeds configured maximum size")]
    ArtifactTooLarge,
    #[error("configured upstream credential is not available")]
    MissingCredentialReference,
    #[error("configured upstream auth type is not supported by Mosquito Net")]
    UnsupportedAuthType,
    #[error("upstream response could not be built")]
    ResponseBuild(#[source] http::Error),
}

impl UpstreamProxyError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::ArtifactTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::InvalidUpstreamUrl
            | Self::Request(_)
            | Self::Body(_)
            | Self::Json(_)
            | Self::Digest(_)
            | Self::CandidateTriage(_)
            | Self::InvalidCandidateDecisionMode
            | Self::InvalidCargoSparseMetadata
            | Self::InvalidCargoRegistryConfig
            | Self::InvalidCargoArtifactDigest
            | Self::UnsupportedCargoDownloadRedirect
            | Self::MavenChecksumMismatch
            | Self::MissingCredentialReference
            | Self::UnsupportedAuthType
            | Self::ResponseBuild(_) => StatusCode::BAD_GATEWAY,
        }
    }
}

fn enforce_artifact_size_limit(
    max_artifact_bytes: u64,
    headers: &HeaderMap,
    actual_size: Option<u64>,
) -> Result<(), UpstreamProxyError> {
    if let Some(content_length) = headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        && content_length > max_artifact_bytes
    {
        return Err(UpstreamProxyError::ArtifactTooLarge);
    }
    if let Some(actual_size) = actual_size
        && actual_size > max_artifact_bytes
    {
        return Err(UpstreamProxyError::ArtifactTooLarge);
    }
    Ok(())
}

async fn triage_outage_response(
    state: &AppState,
    resolved: ResolvedRegistryConfig,
    trace_id: String,
    error: TriageClientError,
    request_started: Instant,
    triage_started: Instant,
) -> Response {
    let triage_elapsed = triage_started.elapsed();
    match resolved.config.mode {
        PolicyMode::Enforce => {
            tracing::warn!(
                tenant_id = %resolved.config.tenant_id,
                registry_config_id = %resolved.config.id,
                %trace_id,
                error = %error,
                "Triage Counter unavailable; enforce mode fails closed"
            );
            emit_proxy_audit_event(
                state,
                final_request_audit_event(
                    &resolved,
                    &trace_id,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "triage-outage-enforce-block",
                    Some(PolicyDecision::QuarantinePendingAnalysis),
                    true,
                ),
            )
            .await;
            state.metrics.observe_triage(
                resolved.config.tenant_id,
                resolved.config.id,
                resolved.config.adapter,
                "outage",
                triage_elapsed,
            );
            state.metrics.observe_decision(
                resolved.config.tenant_id,
                resolved.config.id,
                resolved.config.adapter,
                &PolicyDecision::QuarantinePendingAnalysis,
                triage_elapsed,
            );
            let advisory = advisory_payload(
                PolicyDecision::QuarantinePendingAnalysis,
                trace_id.clone(),
                "Triage Counter unavailable; enforce mode blocks unevaluated request",
            );
            let body = ProxyErrorResponse {
                trace_id: trace_id.clone(),
                decision: PolicyDecision::QuarantinePendingAnalysis,
                message: "Triage Counter is unavailable and enforce mode blocks unevaluated requests",
            }
            .into_response_body();
            state.metrics.observe_request(
                Some(resolved.config.tenant_id),
                "proxy",
                Some(resolved.config.adapter),
                StatusCode::SERVICE_UNAVAILABLE,
                request_started.elapsed(),
            );
            json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                body,
                Some(advisory),
                Some(trace_id),
                None,
            )
        }
        PolicyMode::Warn | PolicyMode::Shadow => {
            tracing::warn!(
                tenant_id = %resolved.config.tenant_id,
                registry_config_id = %resolved.config.id,
                mode = ?resolved.config.mode,
                %trace_id,
                error = %error,
                "Triage Counter unavailable; warn/shadow mode fails open with advisory"
            );
            emit_proxy_audit_event(
                state,
                final_request_audit_event(
                    &resolved,
                    &trace_id,
                    StatusCode::OK,
                    "triage-outage-warn-shadow-fail-open",
                    Some(PolicyDecision::AllowWithWarning),
                    true,
                ),
            )
            .await;
            state.metrics.observe_triage(
                resolved.config.tenant_id,
                resolved.config.id,
                resolved.config.adapter,
                "outage",
                triage_elapsed,
            );
            state.metrics.observe_decision(
                resolved.config.tenant_id,
                resolved.config.id,
                resolved.config.adapter,
                &PolicyDecision::AllowWithWarning,
                triage_elapsed,
            );
            let advisory = advisory_payload(
                PolicyDecision::AllowWithWarning,
                trace_id.clone(),
                "Triage Counter unavailable; warn/shadow mode allowed unevaluated request",
            );
            let body = ProxyDispatchResponse {
                registry_config_id: resolved.config.id.to_string(),
                mount_path: resolved.config.mount_path,
                adapter: resolved.config.adapter,
                upstream_path: resolved.upstream_path.clone(),
                normalized_name: normalize_for_adapter(resolved.config.adapter, &resolved.upstream_path),
                triage_decision: None,
                enforced: false,
                triage_unavailable: true,
                message: "adapter dispatch scaffold allowed request because warn/shadow mode fails open during Triage outage",
            }
            .into_response_body();
            state.metrics.observe_request(
                Some(resolved.config.tenant_id),
                "proxy",
                Some(resolved.config.adapter),
                StatusCode::OK,
                request_started.elapsed(),
            );
            json_response(StatusCode::OK, body, Some(advisory), Some(trace_id), None)
        }
    }
}

async fn triage_hard_error_response(
    state: &AppState,
    resolved: ResolvedRegistryConfig,
    trace_id: String,
    error: TriageClientError,
    request_started: Instant,
    triage_started: Instant,
) -> Response {
    let triage_elapsed = triage_started.elapsed();
    tracing::warn!(
        tenant_id = %resolved.config.tenant_id,
        registry_config_id = %resolved.config.id,
        mode = ?resolved.config.mode,
        %trace_id,
        error = %error,
        "Triage Counter response was invalid or inconsistent; request fails closed"
    );
    emit_proxy_audit_event(
        state,
        final_request_audit_event(
            &resolved,
            &trace_id,
            StatusCode::BAD_GATEWAY,
            "triage-hard-error",
            Some(PolicyDecision::QuarantinePendingAnalysis),
            false,
        ),
    )
    .await;
    state.metrics.observe_triage(
        resolved.config.tenant_id,
        resolved.config.id,
        resolved.config.adapter,
        "hard-error",
        triage_elapsed,
    );
    state.metrics.observe_decision(
        resolved.config.tenant_id,
        resolved.config.id,
        resolved.config.adapter,
        &PolicyDecision::QuarantinePendingAnalysis,
        triage_elapsed,
    );
    let advisory = advisory_payload(
        PolicyDecision::QuarantinePendingAnalysis,
        trace_id.clone(),
        "Triage Counter returned invalid policy context; request blocked",
    );
    let body = ProxyErrorResponse {
        trace_id: trace_id.clone(),
        decision: PolicyDecision::QuarantinePendingAnalysis,
        message: "Triage Counter returned invalid policy context and the request was blocked",
    }
    .into_response_body();
    state.metrics.observe_request(
        Some(resolved.config.tenant_id),
        "proxy",
        Some(resolved.config.adapter),
        StatusCode::BAD_GATEWAY,
        request_started.elapsed(),
    );
    json_response(
        StatusCode::BAD_GATEWAY,
        body,
        Some(advisory),
        Some(trace_id),
        None,
    )
}

fn decision_request_for_adapter(
    tenant_id: Uuid,
    registry_config_id: Uuid,
    policy_profile_id: Uuid,
    adapter: RegistryAdapter,
    trace_id: String,
    source_url: Option<String>,
    upstream_path: &str,
) -> Result<DecisionRequest, StatusCode> {
    let (kind, coordinate, explicit_version_or_integrity) = match adapter {
        RegistryAdapter::Npm => npm_request_context(upstream_path)?,
        RegistryAdapter::Pypi => pypi_request_context(upstream_path)?,
        RegistryAdapter::Cargo => cargo_request_context(upstream_path)?,
        RegistryAdapter::GenericHttp => {
            generic_http_request_context(upstream_path, source_url.as_deref())?
        }
        RegistryAdapter::Maven => maven_request_context(upstream_path)?,
        RegistryAdapter::DockerOci => return Err(StatusCode::NOT_IMPLEMENTED),
    };
    let request = NormalizedPackageRequest {
        kind,
        tenant_id,
        registry_config_id,
        policy_profile_id,
        coordinate,
        trace_id,
        requested_digest: None,
        source_url,
        explicit_version_or_integrity,
    };
    Ok(DecisionRequest {
        tenant_id,
        registry_config_id,
        policy_profile_id,
        request,
    })
}

fn generic_http_request_context(
    upstream_path: &str,
    source_url: Option<&str>,
) -> Result<(PackageRequestKind, PackageCoordinate, bool), StatusCode> {
    let decoded = decode_registry_path(upstream_path);
    let name = decoded.trim_matches('/').to_owned();
    if name.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let namespace = source_url
        .and_then(|url| url::Url::parse(url).ok())
        .and_then(|url| url.host_str().map(str::to_owned));
    let coordinate = PackageCoordinate::new(
        PackageEcosystem::GenericHttp,
        name,
        None::<String>,
        namespace,
    );
    Ok((PackageRequestKind::Artifact, coordinate, true))
}

fn npm_request_context(
    upstream_path: &str,
) -> Result<(PackageRequestKind, PackageCoordinate, bool), StatusCode> {
    let decoded = decode_registry_path(upstream_path);
    let package_path = npm_package_path(&decoded).ok_or(StatusCode::BAD_REQUEST)?;
    let mut coordinate = normalize_npm_name(&package_path).map_err(|_| StatusCode::BAD_REQUEST)?;
    let kind = if decoded.contains("/-/") {
        PackageRequestKind::Artifact
    } else {
        PackageRequestKind::Metadata
    };
    if matches!(kind, PackageRequestKind::Artifact)
        && let Some(version) = npm_tarball_version(&decoded, &coordinate.name)
    {
        coordinate.version = Some(version);
    }
    let explicit_version_or_integrity = matches!(kind, PackageRequestKind::Artifact)
        || npm_metadata_path_has_explicit_version(&decoded, &package_path);
    Ok((kind, coordinate, explicit_version_or_integrity))
}

fn pypi_request_context(
    upstream_path: &str,
) -> Result<(PackageRequestKind, PackageCoordinate, bool), StatusCode> {
    let decoded = decode_registry_path(upstream_path);
    let normalized = decoded.trim_matches('/');
    if let Some(project_name) = normalized
        .strip_prefix("simple/")
        .and_then(|path| path.split('/').find(|segment| !segment.is_empty()))
    {
        let canonical =
            canonicalize_pypi_name(project_name).map_err(|_| StatusCode::BAD_REQUEST)?;
        return Ok((
            PackageRequestKind::Metadata,
            PackageCoordinate::new(
                PackageEcosystem::Pypi,
                canonical,
                None::<String>,
                None::<String>,
            ),
            false,
        ));
    }
    let file_name = normalized
        .rsplit('/')
        .next()
        .filter(|segment| !segment.is_empty())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let coordinate =
        pypi_coordinate_from_distribution_filename(file_name).ok_or(StatusCode::BAD_REQUEST)?;
    Ok((PackageRequestKind::Artifact, coordinate, true))
}

fn cargo_request_context(
    upstream_path: &str,
) -> Result<(PackageRequestKind, PackageCoordinate, bool), StatusCode> {
    let decoded = decode_registry_path(upstream_path);
    let normalized = decoded.trim_matches('/');
    if let Some(coordinate) = cargo_download_coordinate(normalized) {
        return Ok((PackageRequestKind::Artifact, coordinate, true));
    }

    let crate_name = cargo_sparse_index_package_name(normalized).ok_or(StatusCode::BAD_REQUEST)?;
    Ok((
        PackageRequestKind::Metadata,
        PackageCoordinate::new(
            PackageEcosystem::Cargo,
            crate_name,
            None::<String>,
            None::<String>,
        ),
        false,
    ))
}

fn strip_maven_checksum_suffix(filename: &str) -> &str {
    for suffix in &[".md5", ".sha1", ".sha256", ".sha512", ".asc"] {
        if let Some(stripped) = filename.strip_suffix(suffix) {
            return stripped;
        }
    }
    filename
}

fn is_maven_checksum_or_signature_file(filename: &str) -> bool {
    [".md5", ".sha1", ".sha256", ".sha512", ".asc"]
        .iter()
        .any(|suffix| filename.ends_with(suffix))
}

fn is_maven_metadata_file(filename: &str) -> bool {
    strip_maven_checksum_suffix(filename) == "maven-metadata.xml"
}

fn maven_request_context(
    upstream_path: &str,
) -> Result<(PackageRequestKind, PackageCoordinate, bool), StatusCode> {
    let decoded = decode_registry_path(upstream_path);
    let normalized = decoded.trim_matches('/');
    let segments: Vec<&str> = normalized.split('/').filter(|s| !s.is_empty()).collect();
    if segments.len() < 3 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let filename = segments[segments.len() - 1];
    if is_maven_metadata_file(filename) {
        let (artifact_id, version, group_segments) =
            if segments.len() >= 4 && segments[segments.len() - 2].ends_with("SNAPSHOT") {
                (
                    segments[segments.len() - 3],
                    Some(segments[segments.len() - 2]),
                    &segments[..segments.len() - 3],
                )
            } else {
                (
                    segments[segments.len() - 2],
                    None,
                    &segments[..segments.len() - 2],
                )
            };
        let coordinate = PackageCoordinate::new(
            PackageEcosystem::Maven,
            artifact_id,
            version,
            Some(group_segments.join(".")),
        );
        return Ok((PackageRequestKind::Metadata, coordinate, version.is_some()));
    }
    if segments.len() >= 4 {
        let version = segments[segments.len() - 2];
        let artifact_id = segments[segments.len() - 3];
        let group_id = segments[..segments.len() - 3].join(".");
        let base_filename = strip_maven_checksum_suffix(filename);
        let ext = base_filename.rsplit('.').next().unwrap_or("");
        let kind = if is_maven_checksum_or_signature_file(filename) {
            PackageRequestKind::Metadata
        } else {
            match ext {
                "jar" | "aar" | "war" | "ear" => PackageRequestKind::Artifact,
                _ => PackageRequestKind::Metadata,
            }
        };
        let coordinate = PackageCoordinate::new(
            PackageEcosystem::Maven,
            artifact_id,
            Some(version),
            Some(group_id),
        );
        let explicit_version_or_integrity = true;
        Ok((kind, coordinate, explicit_version_or_integrity))
    } else {
        let artifact_id = segments[segments.len() - 2];
        let group_id = segments[..segments.len() - 2].join(".");
        let coordinate = PackageCoordinate::new(
            PackageEcosystem::Maven,
            artifact_id,
            None::<String>,
            Some(group_id),
        );
        Ok((PackageRequestKind::Metadata, coordinate, false))
    }
}

fn cargo_registry_config_path(upstream_path: &str) -> bool {
    decode_registry_path(upstream_path).trim_matches('/') == "config.json"
}

fn cargo_sparse_index_package_name(path: &str) -> Option<String> {
    let segments: Vec<_> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let canonical = match segments.last().copied() {
        Some(crate_name) => canonicalize_cargo_name(crate_name)?,
        None => return None,
    };

    match segments.as_slice() {
        ["1", crate_name] if canonical.len() == 1 && *crate_name == canonical => Some(canonical),
        ["2", crate_name] if canonical.len() == 2 && *crate_name == canonical => Some(canonical),
        ["3", prefix, crate_name]
            if canonical.len() == 3 && *crate_name == canonical && *prefix == &canonical[..1] =>
        {
            Some(canonical)
        }
        [prefix_a, prefix_b, crate_name]
            if canonical.len() >= 4
                && *crate_name == canonical
                && *prefix_a == &canonical[..2]
                && *prefix_b == &canonical[2..4] =>
        {
            Some(canonical)
        }
        _ => None,
    }
}

fn cargo_sparse_index_path(crate_name: &str) -> String {
    match crate_name.len() {
        1 => format!("1/{crate_name}"),
        2 => format!("2/{crate_name}"),
        3 => format!("3/{}/{crate_name}", &crate_name[..1]),
        _ => format!("{}/{}/{crate_name}", &crate_name[..2], &crate_name[2..4]),
    }
}

fn cargo_download_coordinate(path: &str) -> Option<PackageCoordinate> {
    let (_, _, suffix) = cargo_proxy_download_components(path)?;
    let segments: Vec<_> = suffix
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let [crate_name, version, "download"] = segments.as_slice() else {
        return None;
    };
    if !looks_like_cargo_version(version) {
        return None;
    }

    Some(PackageCoordinate::new(
        PackageEcosystem::Cargo,
        canonicalize_cargo_name(crate_name)?,
        Some(version.to_owned()),
        None::<String>,
    ))
}

fn canonicalize_cargo_name(name: &str) -> Option<String> {
    let normalized = name.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    normalized
        .chars()
        .all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '-' | '_')
        })
        .then_some(normalized)
}

fn looks_like_cargo_version(version: &str) -> bool {
    semver::Version::parse(version).is_ok()
}

fn decode_registry_path(upstream_path: &str) -> String {
    upstream_path
        .trim_matches('/')
        .replace("%40", "@")
        .replace("%2f", "/")
        .replace("%2F", "/")
}

fn npm_package_path(decoded_path: &str) -> Option<String> {
    let mut segments = decoded_path
        .split('/')
        .filter(|segment| !segment.is_empty());
    let first = segments.next()?;
    if first.starts_with('@') {
        let second = segments.next()?;
        Some(format!("{first}/{second}"))
    } else {
        Some(first.to_owned())
    }
}

fn npm_metadata_path_has_explicit_version(decoded_path: &str, package_path: &str) -> bool {
    decoded_path
        .strip_prefix(package_path)
        .and_then(|tail| tail.strip_prefix('/'))
        .is_some_and(|tail| !tail.is_empty() && !tail.starts_with("-/"))
}

fn npm_tarball_version(decoded_path: &str, package_name: &str) -> Option<String> {
    let filename = decoded_path.rsplit('/').next()?.strip_suffix(".tgz")?;
    filename
        .strip_prefix(&format!("{package_name}-"))
        .filter(|version| !version.is_empty())
        .map(str::to_owned)
}

fn pypi_coordinate_from_distribution_filename(file_name: &str) -> Option<PackageCoordinate> {
    let normalized_file = file_name.split('#').next().unwrap_or(file_name);
    let (name, version) = if let Some(stem) = normalized_file.strip_suffix(".whl") {
        let mut parts = stem.split('-');
        (parts.next()?, parts.next()?)
    } else if let Some(stem) = normalized_file.strip_suffix(".tar.gz") {
        stem.rsplit_once('-')?
    } else if let Some(stem) = normalized_file.strip_suffix(".zip") {
        stem.rsplit_once('-')?
    } else {
        return None;
    };
    let canonical = canonicalize_pypi_name(name).ok()?;
    Some(PackageCoordinate::new(
        PackageEcosystem::Pypi,
        canonical,
        Some(version.to_owned()),
        None::<String>,
    ))
}

fn normalize_for_adapter(adapter: RegistryAdapter, upstream_path: &str) -> Option<String> {
    match adapter {
        RegistryAdapter::Npm => npm_package_path(&decode_registry_path(upstream_path))
            .and_then(|path| normalize_npm_name(&path).ok())
            .map(|coordinate| coordinate.purl()),
        RegistryAdapter::Pypi => pypi_request_context(upstream_path)
            .ok()
            .map(|(_, coordinate, _)| coordinate.purl()),
        RegistryAdapter::Cargo => cargo_request_context(upstream_path)
            .ok()
            .map(|(_, coordinate, _)| coordinate.purl()),
        RegistryAdapter::Maven => maven_request_context(upstream_path)
            .ok()
            .map(|(_, coordinate, _)| coordinate.purl()),
        RegistryAdapter::DockerOci => None,
        RegistryAdapter::GenericHttp => None,
    }
}

fn advisory_payload(
    decision: PolicyDecision,
    trace_id: String,
    message: impl Into<String>,
) -> AdvisoryHeaderPayload {
    AdvisoryHeaderPayload {
        decision,
        trace_id,
        message: message.into(),
    }
}

fn advisory_message(decision: &DecisionResponse) -> &'static str {
    match decision.decision {
        PolicyDecision::Allow => "Triage Counter allowed request",
        PolicyDecision::AllowWithWarning => "Triage Counter allowed request with warning",
        PolicyDecision::FallbackToApprovedCandidate => {
            "Triage Counter selected an approved fallback candidate"
        }
        PolicyDecision::QuarantinePendingAnalysis => {
            "Triage Counter quarantined request pending analysis"
        }
        PolicyDecision::BlockKnownMalicious => "Triage Counter blocked known malicious package",
        PolicyDecision::BlockPolicyViolation => "Triage Counter blocked policy violation",
        PolicyDecision::RequireHitlApproval => "Triage Counter requires human approval",
    }
}

fn new_proxy_trace_id() -> String {
    format!("mn-{}", Uuid::now_v7())
}

fn inbound_request_audit_event(resolved: &ResolvedRegistryConfig, trace_id: &str) -> AuditEvent {
    let metadata = Metadata::from([
        ("adapter".to_owned(), json!(resolved.config.adapter)),
        ("mount_path".to_owned(), json!(resolved.config.mount_path)),
        ("mode".to_owned(), json!(resolved.config.mode)),
        (
            "policy_profile_id".to_owned(),
            json!(resolved.config.policy_profile_id),
        ),
        ("upstream_path".to_owned(), json!(resolved.upstream_path)),
    ]);
    build_audit_event(
        resolved.config.tenant_id,
        trace_id,
        "proxy.request.received",
        &format!("registry-config/{}", resolved.config.id),
        metadata,
    )
}

fn final_request_audit_event(
    resolved: &ResolvedRegistryConfig,
    trace_id: &str,
    status: StatusCode,
    outcome: &'static str,
    decision: Option<PolicyDecision>,
    triage_unavailable: bool,
) -> AuditEvent {
    let mut metadata = Metadata::from([
        ("adapter".to_owned(), json!(resolved.config.adapter)),
        ("mount_path".to_owned(), json!(resolved.config.mount_path)),
        ("mode".to_owned(), json!(resolved.config.mode)),
        ("outcome".to_owned(), json!(outcome)),
        ("status_code".to_owned(), json!(status.as_u16())),
        ("triage_unavailable".to_owned(), json!(triage_unavailable)),
        ("upstream_path".to_owned(), json!(resolved.upstream_path)),
    ]);
    if let Some(decision) = decision {
        metadata.insert(
            "decision".to_owned(),
            serde_json::to_value(decision).expect("policy decision must serialize"),
        );
    }
    build_audit_event(
        resolved.config.tenant_id,
        trace_id,
        "proxy.request.completed",
        &format!("registry-config/{}", resolved.config.id),
        metadata,
    )
}

fn build_audit_event(
    tenant_id: Uuid,
    trace_id: &str,
    action: &str,
    resource: &str,
    metadata: Metadata,
) -> AuditEvent {
    AuditEvent {
        id: Uuid::now_v7(),
        tenant_id,
        actor: SERVICE_NAME.to_owned(),
        action: action.to_owned(),
        resource: resource.to_owned(),
        trace_id: trace_id.to_owned(),
        occurred_at: chrono::Utc::now(),
        metadata,
    }
}

async fn emit_proxy_audit_event(state: &AppState, event: AuditEvent) {
    if let Err(error) = validate_audit_metadata(&event.metadata) {
        tracing::error!(trace_id = %event.trace_id, error = %error, "mosquito-net audit metadata validation failed");
        return;
    }
    match serde_json::to_string(&event) {
        Ok(serialized) => tracing::info!(
            tenant_id = %event.tenant_id,
            trace_id = %event.trace_id,
            action = %event.action,
            audit_event = %serialized,
            "mosquito-net audit event"
        ),
        Err(error) => {
            tracing::error!(trace_id = %event.trace_id, error = %error, "mosquito-net audit serialization failed")
        }
    }
    if let Some(repository) = &state.audit_repository
        && let Err(error) = repository.insert(&event).await
    {
        tracing::error!(
            tenant_id = %event.tenant_id,
            trace_id = %event.trace_id,
            action = %event.action,
            error = %error,
            "mosquito-net audit persistence failed"
        );
    }
}

fn status_response(status: StatusCode, trace_id: Option<String>) -> Response {
    with_common_headers(status.into_response(), trace_id, None)
}

fn json_response(
    status: StatusCode,
    body: serde_json::Value,
    advisory: Option<AdvisoryHeaderPayload>,
    trace_id: Option<String>,
    retry_after_seconds: Option<u64>,
) -> Response {
    let mut response = (status, Json(body)).into_response();
    if let Some(advisory) = advisory
        && let Ok(value) = advisory.to_header_value()
        && let Ok(header_value) = HeaderValue::from_str(&value)
    {
        response
            .headers_mut()
            .insert(HeaderName::from_static(ADVISORY_HEADER), header_value);
    }
    with_common_headers(response, trace_id, retry_after_seconds)
}

fn with_common_headers(
    mut response: Response,
    trace_id: Option<String>,
    retry_after_seconds: Option<u64>,
) -> Response {
    if let Some(trace_id) = trace_id
        && let Ok(header_value) = HeaderValue::from_str(&trace_id)
    {
        response
            .headers_mut()
            .insert(HeaderName::from_static(TRACE_HEADER), header_value);
    }
    if let Some(retry_after_seconds) = retry_after_seconds
        && let Ok(header_value) = HeaderValue::from_str(&retry_after_seconds.to_string())
    {
        response.headers_mut().insert(RETRY_AFTER, header_value);
    }
    response
}

trait IntoResponseBody {
    fn into_response_body(self) -> serde_json::Value;
}

impl<T> IntoResponseBody for T
where
    T: Serialize,
{
    fn into_response_body(self) -> serde_json::Value {
        serde_json::to_value(self).expect("proxy response DTO must serialize")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CARGO_DOWNLOAD_MAC_KEY: [u8; 16] = *b"cargo-dl-testkey";
    use axum::http::header::AUTHORIZATION;
    use axum::{
        extract::State as AxumState,
        routing::{any, post},
    };
    use registry_config::{CredentialAuthType, RegistryConfig};
    use sqlx::postgres::PgPoolOptions;
    use std::{
        fs,
        path::PathBuf,
        process::{Command, Output},
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::task::JoinHandle;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("repo root")
            .to_path_buf()
    }

    fn run_local_command(repo_root: &PathBuf, program: &str, args: &[&str]) -> Output {
        Command::new(program)
            .args(args)
            .current_dir(repo_root)
            .output()
            .unwrap_or_else(|error| panic!("failed to run {program}: {error}"))
    }

    fn assert_command_success(program: &str, args: &[&str], output: &Output) {
        assert!(
            output.status.success(),
            "{program} {} failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    fn recreate_live_local_proxy_stack(repo_root: &PathBuf) {
        if std::env::var("MOSQUITO_NET_CARGO_DOWNLOAD_MAC_KEY")
            .ok()
            .filter(|value| !value.is_empty())
            .is_none()
        {
            unsafe {
                std::env::set_var(
                    "MOSQUITO_NET_CARGO_DOWNLOAD_MAC_KEY",
                    "live-local-cargo-download-mac-key",
                );
            }
        }

        let restart_registry = run_local_command(
            repo_root,
            "docker",
            &[
                "compose",
                "-f",
                "infra/docker-compose.yml",
                "up",
                "-d",
                "--force-recreate",
                "postgres",
                "npm-fixture-registry",
                "pypi-fixture-registry",
                "cargo-fixture-registry",
                "maven-fixture-registry",
            ],
        );
        assert_command_success(
            "docker",
            &[
                "compose",
                "-f",
                "infra/docker-compose.yml",
                "up",
                "-d",
                "--force-recreate",
                "postgres",
                "npm-fixture-registry",
                "pypi-fixture-registry",
                "cargo-fixture-registry",
                "maven-fixture-registry",
            ],
            &restart_registry,
        );

        let migrate = run_local_command(repo_root, "sh", &["scripts/apply-migrations.sh"]);
        assert_command_success("sh", &["scripts/apply-migrations.sh"], &migrate);

        let reseed = run_local_command(repo_root, "sh", &["scripts/seed-local-control-plane.sh"]);
        assert_command_success("sh", &["scripts/seed-local-control-plane.sh"], &reseed);

        let restart_proxy_stack = run_local_command(
            repo_root,
            "docker",
            &[
                "compose",
                "-f",
                "infra/docker-compose.yml",
                "up",
                "-d",
                "--build",
                "--force-recreate",
                "triage-counter",
                "mosquito-net",
            ],
        );
        assert_command_success(
            "docker",
            &[
                "compose",
                "-f",
                "infra/docker-compose.yml",
                "up",
                "-d",
                "--build",
                "--force-recreate",
                "triage-counter",
                "mosquito-net",
            ],
            &restart_proxy_stack,
        );

        let _ = fetch_json("http://127.0.0.1:18001/readyz");
        let _ = fetch_json("http://127.0.0.1:18000/readyz");
    }

    fn create_temp_npm_dirs(prefix: &str) -> (PathBuf, PathBuf) {
        let project_dir =
            std::env::temp_dir().join(format!("{prefix}-project-{}", Uuid::now_v7().simple()));
        let cache_dir =
            std::env::temp_dir().join(format!("{prefix}-cache-{}", Uuid::now_v7().simple()));
        fs::create_dir_all(&project_dir).expect("create temp npm project");
        fs::create_dir_all(&cache_dir).expect("create temp npm cache");
        (project_dir, cache_dir)
    }

    fn create_temp_python_dirs(prefix: &str) -> (PathBuf, PathBuf) {
        let project_dir =
            std::env::temp_dir().join(format!("{prefix}-project-{}", Uuid::now_v7().simple()));
        let cache_dir =
            std::env::temp_dir().join(format!("{prefix}-cache-{}", Uuid::now_v7().simple()));
        fs::create_dir_all(&project_dir).expect("create temp python project");
        fs::create_dir_all(&cache_dir).expect("create temp python cache");
        (project_dir, cache_dir)
    }

    fn create_temp_cargo_dirs(prefix: &str) -> (PathBuf, PathBuf) {
        let project_dir =
            std::env::temp_dir().join(format!("{prefix}-project-{}", Uuid::now_v7().simple()));
        let cargo_home =
            std::env::temp_dir().join(format!("{prefix}-cargo-home-{}", Uuid::now_v7().simple()));
        fs::create_dir_all(&project_dir).expect("create temp cargo project");
        fs::create_dir_all(&cargo_home).expect("create temp cargo home");
        (project_dir, cargo_home)
    }

    fn create_temp_maven_dirs(prefix: &str) -> (PathBuf, PathBuf) {
        let work_dir =
            std::env::temp_dir().join(format!("{prefix}-work-{}", Uuid::now_v7().simple()));
        let maven_repo =
            std::env::temp_dir().join(format!("{prefix}-repo-{}", Uuid::now_v7().simple()));
        fs::create_dir_all(&work_dir).expect("create temp maven work dir");
        fs::create_dir_all(&maven_repo).expect("create temp maven repo dir");
        (work_dir, maven_repo)
    }

    fn cargo_cache_contains_crate(cargo_home: &PathBuf, crate_name: &str, version: &str) -> bool {
        let cache_root = cargo_home.join("registry/cache");
        let Ok(entries) = fs::read_dir(cache_root) else {
            return false;
        };
        let crate_file = format!("{crate_name}-{version}.crate");
        entries
            .flatten()
            .any(|entry| entry.path().join(&crate_file).is_file())
    }

    fn fetch_json(url: &str) -> serde_json::Value {
        for attempt in 0..20 {
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build tokio runtime")
                .block_on(async {
                    let response = reqwest::get(url).await?;
                    response.json().await
                });
            match result {
                Ok(payload) => return payload,
                Err(error) if attempt < 19 => {
                    let _ = error;
                    std::thread::sleep(Duration::from_millis(250));
                }
                Err(error) => panic!("request json endpoint: {error}"),
            }
        }
        unreachable!("json fetch attempts exhausted")
    }

    fn fetch_bytes(url: &str) -> (StatusCode, Vec<u8>) {
        for attempt in 0..20 {
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build tokio runtime")
                .block_on(async {
                    let response = reqwest::get(url).await?;
                    let status = response.status();
                    let body = response.bytes().await?;
                    Ok::<_, reqwest::Error>((status, body.to_vec()))
                });
            match result {
                Ok(payload) => return payload,
                Err(error) if attempt < 19 => {
                    let _ = error;
                    std::thread::sleep(Duration::from_millis(250));
                }
                Err(error) => panic!("request binary endpoint: {error}"),
            }
        }
        unreachable!("binary fetch attempts exhausted")
    }

    fn live_analysis_job_count(package_name: &str, package_version: &str) -> i64 {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime")
            .block_on(async {
                let pool = PgPoolOptions::new()
                    .max_connections(1)
                    .connect("postgres://aegiscudo:aegiscudo@127.0.0.1:15432/aegiscudo")
                    .await
                    .expect("connect live local postgres");
                let count = sqlx::query_scalar::<_, i64>(
                    r#"
                    SELECT COUNT(*)
                    FROM analysis_jobs
                    WHERE tenant_id = $1
                      AND package_name = $2
                      AND package_version = $3
                    "#,
                )
                .bind(
                    Uuid::parse_str("018f4a6f-55d0-7000-8000-000000000001")
                        .expect("seed tenant id"),
                )
                .bind(package_name)
                .bind(package_version)
                .fetch_one(&pool)
                .await
                .expect("count analysis jobs");
                pool.close().await;
                count
            })
    }

    fn insert_live_override(
        scope: serde_json::Value,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Uuid {
        let override_id = Uuid::now_v7();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime")
            .block_on(async {
                let pool = PgPoolOptions::new()
                    .max_connections(1)
                    .connect("postgres://aegiscudo:aegiscudo@127.0.0.1:15432/aegiscudo")
                    .await
                    .expect("connect live local postgres");
                sqlx::query(
                    r#"
                    INSERT INTO overrides (
                      id,
                      tenant_id,
                      scope,
                      reason,
                      requested_by,
                      approved_by,
                      status,
                      expires_at,
                      created_at
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, 'approved', $7, NOW())
                    "#,
                )
                .bind(override_id)
                .bind(
                    Uuid::parse_str("018f4a6f-55d0-7000-8000-000000000001")
                        .expect("seed tenant id"),
                )
                .bind(scope)
                .bind("Live override expiry resumption proof")
                .bind(
                    Uuid::parse_str("018f4a6f-55d0-7000-8000-000000000011")
                        .expect("seed approver id"),
                )
                .bind(
                    Uuid::parse_str("018f4a6f-55d0-7000-8000-000000000011")
                        .expect("seed approver id"),
                )
                .bind(expires_at)
                .execute(&pool)
                .await
                .expect("insert live override");
                pool.close().await;
            });
        override_id
    }

    fn update_live_override_expiry(override_id: Uuid, expires_at: chrono::DateTime<chrono::Utc>) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime")
            .block_on(async {
                let pool = PgPoolOptions::new()
                    .max_connections(1)
                    .connect("postgres://aegiscudo:aegiscudo@127.0.0.1:15432/aegiscudo")
                    .await
                    .expect("connect live local postgres");
                sqlx::query(
                    r#"
                    UPDATE overrides
                    SET expires_at = $1
                    WHERE tenant_id = $2 AND id = $3
                    "#,
                )
                .bind(expires_at)
                .bind(
                    Uuid::parse_str("018f4a6f-55d0-7000-8000-000000000001")
                        .expect("seed tenant id"),
                )
                .bind(override_id)
                .execute(&pool)
                .await
                .expect("expire live override");
                pool.close().await;
            });
    }

    fn delete_live_override(override_id: Uuid) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime")
            .block_on(async {
                let pool = PgPoolOptions::new()
                    .max_connections(1)
                    .connect("postgres://aegiscudo:aegiscudo@127.0.0.1:15432/aegiscudo")
                    .await
                    .expect("connect live local postgres");
                sqlx::query(
                    r#"
                    DELETE FROM overrides
                    WHERE tenant_id = $1 AND id = $2
                    "#,
                )
                .bind(
                    Uuid::parse_str("018f4a6f-55d0-7000-8000-000000000001")
                        .expect("seed tenant id"),
                )
                .bind(override_id)
                .execute(&pool)
                .await
                .expect("delete live override");
                pool.close().await;
            });
    }

    #[derive(Debug, Clone)]
    struct FakeTriageState {
        decision: PolicyDecision,
        artifact_decision: Option<PolicyDecision>,
        artifact_decision_version: Option<String>,
        artifact_mode: Option<PolicyMode>,
        artifact_status: Option<StatusCode>,
        mode: PolicyMode,
        status: Option<StatusCode>,
        fallback_coordinate: Option<PackageCoordinate>,
        create_analysis_job: bool,
        calls: Arc<AtomicUsize>,
        requested_digests: Arc<Mutex<Vec<Option<String>>>>,
    }

    fn config(mount_path: &str, mode: PolicyMode) -> RegistryConfig {
        config_with_upstream(mount_path, mode, "http://127.0.0.1:9")
    }

    fn config_with_upstream(
        mount_path: &str,
        mode: PolicyMode,
        upstream_url: &str,
    ) -> RegistryConfig {
        config_with_adapter_upstream(mount_path, mode, RegistryAdapter::Npm, upstream_url)
    }

    fn config_with_adapter_upstream(
        mount_path: &str,
        mode: PolicyMode,
        adapter: RegistryAdapter,
        upstream_url: &str,
    ) -> RegistryConfig {
        RegistryConfig {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            name: mount_path.trim_matches('/').to_owned(),
            adapter,
            upstream_url: upstream_url.to_owned(),
            cargo_allowed_download_origins: Vec::new(),
            mount_path: mount_path.to_owned(),
            auth_type: CredentialAuthType::None,
            credential_ref: None,
            credential_env_var: None,
            mode,
            policy_profile_id: Uuid::now_v7(),
            cache_ttl_seconds: 300,
            verify_upstream_tls: true,
        }
    }

    #[test]
    fn verify_upstream_tls_false_uses_insecure_client() {
        let mut config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            "https://registry.example.invalid/sparse/",
        );
        config.verify_upstream_tls = false;
        let store = RegistryConfigStore::new(vec![config.clone()]).expect("store");
        let triage_client = TriageClient::new("http://127.0.0.1:9", Duration::from_millis(500), 0)
            .expect("triage client");
        let state = AppState::new(
            store,
            None,
            triage_client,
            ProxyRateLimitConfig::default(),
            None,
            DEFAULT_MAX_ARTIFACT_BYTES,
        );
        let resolved = ResolvedRegistryConfig {
            config,
            upstream_path: "config.json".to_owned(),
        };

        assert!(std::ptr::eq(
            upstream_client(&state, &resolved),
            &state.insecure_upstream_client,
        ));
    }

    #[derive(Debug, Clone, Default)]
    struct FakeUpstreamState {
        paths: Arc<Mutex<Vec<String>>>,
    }

    async fn fake_upstream_handler(
        AxumState(state): AxumState<FakeUpstreamState>,
        Path(path): Path<String>,
    ) -> Response {
        state.paths.lock().expect("record paths").push(path.clone());
        if path.contains("/-/") {
            return (
                [(CONTENT_TYPE, "application/octet-stream")],
                format!("artifact bytes for {path}"),
            )
                .into_response();
        }
        let escaped_path = path.replace('"', "");
        (
            [(CONTENT_TYPE, "application/json")],
            format!(
                r#"{{"name":"{escaped_path}","versions":{{"1.0.0":{{"dist":{{"tarball":"http://upstream.example/{escaped_path}/-/pkg-1.0.0.tgz"}}}}}}}}"#
            ),
        )
            .into_response()
    }

    async fn spawn_fake_upstream() -> (String, Arc<Mutex<Vec<String>>>, JoinHandle<()>) {
        let state = FakeUpstreamState::default();
        let paths = Arc::clone(&state.paths);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake upstream");
        let address = listener.local_addr().expect("fake upstream address");
        let router = Router::new()
            .route("/{*path}", get(fake_upstream_handler))
            .with_state(state);
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("fake upstream serve");
        });
        (format!("http://{address}"), paths, handle)
    }

    async fn fake_pypi_upstream_handler(
        AxumState(state): AxumState<FakeUpstreamState>,
        Path(path): Path<String>,
    ) -> Response {
        state.paths.lock().expect("record paths").push(path);
        (
            [(CONTENT_TYPE, "text/html")],
            r#"<html><body><a href="/packages/ab/pkg-1.0.0.tar.gz#sha256=abc">pkg</a></body></html>"#,
        )
            .into_response()
    }

    async fn spawn_fake_pypi_upstream() -> (String, Arc<Mutex<Vec<String>>>, JoinHandle<()>) {
        let state = FakeUpstreamState::default();
        let paths = Arc::clone(&state.paths);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake PyPI upstream");
        let address = listener.local_addr().expect("fake PyPI upstream address");
        let router = Router::new()
            .route("/{*path}", get(fake_pypi_upstream_handler))
            .with_state(state);
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("fake PyPI upstream serve");
        });
        (format!("http://{address}"), paths, handle)
    }

    #[derive(Debug, Clone)]
    struct FakeBodyUpstreamState {
        paths: Arc<Mutex<Vec<String>>>,
        status: StatusCode,
        content_type: &'static str,
        body: &'static str,
    }

    async fn fake_body_upstream_handler(
        AxumState(state): AxumState<FakeBodyUpstreamState>,
        Path(path): Path<String>,
    ) -> Response {
        state.paths.lock().expect("record paths").push(path);
        (
            state.status,
            [(CONTENT_TYPE, state.content_type)],
            state.body,
        )
            .into_response()
    }

    async fn spawn_fake_body_upstream(
        content_type: &'static str,
        body: &'static str,
    ) -> (String, Arc<Mutex<Vec<String>>>, JoinHandle<()>) {
        spawn_fake_status_body_upstream(StatusCode::OK, content_type, body).await
    }

    async fn spawn_fake_status_body_upstream(
        status: StatusCode,
        content_type: &'static str,
        body: &'static str,
    ) -> (String, Arc<Mutex<Vec<String>>>, JoinHandle<()>) {
        let paths = Arc::new(Mutex::new(Vec::new()));
        let state = FakeBodyUpstreamState {
            paths: Arc::clone(&paths),
            status,
            content_type,
            body,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake body upstream");
        let address = listener.local_addr().expect("fake body upstream address");
        let router = Router::new()
            .route("/{*path}", get(fake_body_upstream_handler))
            .with_state(state);
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("fake body upstream serve");
        });
        (format!("http://{address}"), paths, handle)
    }

    async fn fake_cargo_upstream_handler(
        AxumState(state): AxumState<FakeUpstreamState>,
        Path(path): Path<String>,
    ) -> Response {
        state.paths.lock().expect("record paths").push(path.clone());
        if path == "config.json" {
            return (
                [(CONTENT_TYPE, "application/json")],
                r#"{"dl":"api/v1/crates","api":"/api/v1"}"#,
            )
                .into_response();
        }
        if path.ends_with("/download") {
            return (
                [(CONTENT_TYPE, "application/octet-stream")],
                fake_cargo_download_body(&path),
            )
                .into_response();
        }
        (
            [(CONTENT_TYPE, "application/vnd.rust.crate-index")],
            format!(
                "{{\"name\":\"serde\",\"vers\":\"1.0.0\",\"cksum\":\"{}\"}}\n{{\"name\":\"serde\",\"vers\":\"1.0.1\",\"cksum\":\"{}\"}}",
                fake_cargo_download_sha256("api/v1/crates/serde/1.0.0/download"),
                fake_cargo_download_sha256("api/v1/crates/serde/1.0.1/download"),
            ),
        )
            .into_response()
    }

    fn fake_cargo_download_body(path: &str) -> String {
        format!("crate bytes for {path}")
    }

    fn fake_cargo_download_sha256(path: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(fake_cargo_download_body(path).as_bytes());
        hex::encode(hasher.finalize())
    }

    async fn spawn_fake_cargo_upstream() -> (String, Arc<Mutex<Vec<String>>>, JoinHandle<()>) {
        let state = FakeUpstreamState::default();
        let paths = Arc::clone(&state.paths);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Cargo upstream");
        let address = listener.local_addr().expect("fake Cargo upstream address");
        let router = Router::new()
            .route("/{*path}", get(fake_cargo_upstream_handler))
            .with_state(state);
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("fake Cargo upstream serve");
        });
        (format!("http://{address}"), paths, handle)
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FakeCargoApiRequest {
        method: String,
        path: String,
        query: Option<String>,
        authorization: Option<String>,
        body: Vec<u8>,
    }

    #[derive(Debug, Clone)]
    struct FakeCargoApiUpstreamState {
        config_body: String,
        paths: Arc<Mutex<Vec<String>>>,
        requests: Arc<Mutex<Vec<FakeCargoApiRequest>>>,
    }

    async fn fake_cargo_api_upstream_handler(
        AxumState(state): AxumState<FakeCargoApiUpstreamState>,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        Path(path): Path<String>,
        body: Bytes,
    ) -> Response {
        state.paths.lock().expect("record paths").push(path.clone());
        if path == "config.json" {
            return ([(CONTENT_TYPE, "application/json")], state.config_body).into_response();
        }
        if path.starts_with("api/v1/") {
            state
                .requests
                .lock()
                .expect("record requests")
                .push(FakeCargoApiRequest {
                    method: method.as_str().to_owned(),
                    path,
                    query: uri.query().map(str::to_owned),
                    authorization: headers
                        .get(AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned),
                    body: body.to_vec(),
                });
            let mut response = Json(json!({ "ok": true })).into_response();
            response
                .headers_mut()
                .insert(LOCATION, HeaderValue::from_static("/api/v1/crates/result"));
            return response;
        }
        StatusCode::NOT_FOUND.into_response()
    }

    async fn spawn_fake_cargo_api_upstream() -> (
        String,
        Arc<Mutex<Vec<String>>>,
        Arc<Mutex<Vec<FakeCargoApiRequest>>>,
        JoinHandle<()>,
    ) {
        spawn_fake_cargo_api_upstream_with_config(r#"{"dl":"api/v1/crates","api":"."}"#).await
    }

    async fn spawn_fake_cargo_api_upstream_with_config(
        config_body: &str,
    ) -> (
        String,
        Arc<Mutex<Vec<String>>>,
        Arc<Mutex<Vec<FakeCargoApiRequest>>>,
        JoinHandle<()>,
    ) {
        let paths = Arc::new(Mutex::new(Vec::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let state = FakeCargoApiUpstreamState {
            config_body: config_body.to_owned(),
            paths: Arc::clone(&paths),
            requests: Arc::clone(&requests),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Cargo API upstream");
        let address = listener
            .local_addr()
            .expect("fake Cargo API upstream address");
        let router = Router::new()
            .route("/{*path}", any(fake_cargo_api_upstream_handler))
            .with_state(state);
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("fake Cargo API upstream serve");
        });
        (format!("http://{address}"), paths, requests, handle)
    }

    #[derive(Debug, Clone)]
    struct FakeBinaryCargoUpstreamState {
        paths: Arc<Mutex<Vec<String>>>,
        crate_bytes: Arc<Vec<u8>>,
        sparse_metadata: Arc<String>,
    }

    async fn fake_binary_cargo_upstream_handler(
        AxumState(state): AxumState<FakeBinaryCargoUpstreamState>,
        Path(path): Path<String>,
    ) -> Response {
        state.paths.lock().expect("record paths").push(path.clone());
        if path == "config.json" {
            return (
                [(CONTENT_TYPE, "application/json")],
                r#"{"dl":"api/v1/crates","api":"/api/v1"}"#,
            )
                .into_response();
        }
        if path.ends_with("/download") {
            return (
                StatusCode::OK,
                [(CONTENT_TYPE, "application/octet-stream")],
                (*state.crate_bytes).clone(),
            )
                .into_response();
        }
        (
            [(CONTENT_TYPE, "application/vnd.rust.crate-index")],
            state.sparse_metadata.as_str().to_owned(),
        )
            .into_response()
    }

    async fn spawn_fake_cargo_upstream_with_binary_crate_and_sparse_metadata(
        sparse_metadata: String,
    ) -> (String, Arc<Mutex<Vec<String>>>, String, JoinHandle<()>) {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use tar::Builder as TarBuilder;

        let mut archive_buf: Vec<u8> = Vec::new();
        {
            let enc = GzEncoder::new(&mut archive_buf, Compression::fast());
            let mut builder = TarBuilder::new(enc);

            let cargo_toml =
                b"[package]\nname = \"codeshot\"\nversion = \"2.0.0\"\nedition = \"2021\"\n";
            let mut header = tar::Header::new_gnu();
            header.set_size(cargo_toml.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    "codeshot-2.0.0/Cargo.toml",
                    cargo_toml.as_ref(),
                )
                .expect("append Cargo.toml");

            let lib_rs = b"pub fn hello() {}\n";
            let mut header2 = tar::Header::new_gnu();
            header2.set_size(lib_rs.len() as u64);
            header2.set_mode(0o644);
            header2.set_cksum();
            builder
                .append_data(&mut header2, "codeshot-2.0.0/src/lib.rs", lib_rs.as_ref())
                .expect("append src/lib.rs");

            builder
                .into_inner()
                .expect("encoder")
                .finish()
                .expect("gz finish");
        }

        let expected_sha256_hex = {
            let mut hasher = Sha256::new();
            hasher.update(&archive_buf);
            hex::encode(hasher.finalize())
        };

        let crate_bytes = Arc::new(archive_buf);
        let paths = Arc::new(Mutex::new(Vec::<String>::new()));
        let state = FakeBinaryCargoUpstreamState {
            paths: Arc::clone(&paths),
            crate_bytes: Arc::clone(&crate_bytes),
            sparse_metadata: Arc::new(sparse_metadata),
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake binary Cargo upstream");
        let address = listener
            .local_addr()
            .expect("fake binary Cargo upstream address");
        let router = Router::new()
            .route("/{*path}", get(fake_binary_cargo_upstream_handler))
            .with_state(state);
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("fake binary Cargo upstream serve");
        });
        (
            format!("http://{address}"),
            paths,
            expected_sha256_hex,
            handle,
        )
    }

    async fn spawn_fake_cargo_upstream_with_binary_crate_and_sparse_checksum(
        sparse_checksum: String,
    ) -> (String, Arc<Mutex<Vec<String>>>, String, JoinHandle<()>) {
        spawn_fake_cargo_upstream_with_binary_crate_and_sparse_metadata(format!(
            "{{\"name\":\"codeshot\",\"vers\":\"2.0.0\",\"cksum\":\"{sparse_checksum}\"}}"
        ))
        .await
    }

    async fn spawn_fake_cargo_upstream_with_binary_crate()
    -> (String, Arc<Mutex<Vec<String>>>, String, JoinHandle<()>) {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use tar::Builder as TarBuilder;

        let mut archive_buf: Vec<u8> = Vec::new();
        {
            let enc = GzEncoder::new(&mut archive_buf, Compression::fast());
            let mut builder = TarBuilder::new(enc);

            let cargo_toml =
                b"[package]\nname = \"codeshot\"\nversion = \"2.0.0\"\nedition = \"2021\"\n";
            let mut header = tar::Header::new_gnu();
            header.set_size(cargo_toml.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    "codeshot-2.0.0/Cargo.toml",
                    cargo_toml.as_ref(),
                )
                .expect("append Cargo.toml");

            let lib_rs = b"pub fn hello() {}\n";
            let mut header2 = tar::Header::new_gnu();
            header2.set_size(lib_rs.len() as u64);
            header2.set_mode(0o644);
            header2.set_cksum();
            builder
                .append_data(&mut header2, "codeshot-2.0.0/src/lib.rs", lib_rs.as_ref())
                .expect("append src/lib.rs");

            builder
                .into_inner()
                .expect("encoder")
                .finish()
                .expect("gz finish");
        }

        let expected_sha256_hex = {
            let mut hasher = Sha256::new();
            hasher.update(&archive_buf);
            hex::encode(hasher.finalize())
        };

        spawn_fake_cargo_upstream_with_binary_crate_and_sparse_checksum(expected_sha256_hex).await
    }

    async fn fake_cargo_redirect_upstream_handler(
        AxumState(state): AxumState<FakeUpstreamState>,
        Path(path): Path<String>,
    ) -> Response {
        state.paths.lock().expect("record paths").push(path.clone());
        if path == "config.json" {
            return (
                [(CONTENT_TYPE, "application/json")],
                r#"{"dl":"api/v1/crates","api":"/api/v1"}"#,
            )
                .into_response();
        }
        if path.ends_with("/download") {
            return (
                StatusCode::FOUND,
                [(
                    LOCATION,
                    "https://static.example.invalid/crates/serde/serde-1.0.0.crate",
                )],
            )
                .into_response();
        }
        (
            [(CONTENT_TYPE, "application/vnd.rust.crate-index")],
            r#"{"name":"serde","vers":"1.0.0","cksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        )
            .into_response()
    }

    async fn spawn_fake_cargo_redirect_upstream()
    -> (String, Arc<Mutex<Vec<String>>>, JoinHandle<()>) {
        let state = FakeUpstreamState::default();
        let paths = Arc::clone(&state.paths);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Cargo redirect upstream");
        let address = listener
            .local_addr()
            .expect("fake Cargo redirect upstream address");
        let router = Router::new()
            .route("/{*path}", get(fake_cargo_redirect_upstream_handler))
            .with_state(state);
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("fake Cargo redirect upstream serve");
        });
        (format!("http://{address}"), paths, handle)
    }

    #[derive(Debug, Clone)]
    struct FakeCargoConfigurableUpstreamState {
        config_body: String,
        sparse_metadata: String,
        redirect_location: Option<String>,
        paths: Arc<Mutex<Vec<String>>>,
    }

    async fn fake_cargo_configurable_upstream_handler(
        AxumState(state): AxumState<FakeCargoConfigurableUpstreamState>,
        Path(path): Path<String>,
    ) -> Response {
        state.paths.lock().expect("record paths").push(path.clone());
        if path == "config.json" {
            return ([(CONTENT_TYPE, "application/json")], state.config_body).into_response();
        }
        if path.ends_with("/download") {
            if let Some(location) = &state.redirect_location {
                return (StatusCode::FOUND, [(LOCATION, location.as_str())]).into_response();
            }
            return StatusCode::NOT_FOUND.into_response();
        }
        (
            [(CONTENT_TYPE, "application/vnd.rust.crate-index")],
            state.sparse_metadata,
        )
            .into_response()
    }

    async fn spawn_fake_cargo_configurable_upstream(
        config_body: String,
        sparse_metadata: String,
        redirect_location: Option<String>,
    ) -> (String, Arc<Mutex<Vec<String>>>, JoinHandle<()>) {
        let paths = Arc::new(Mutex::new(Vec::new()));
        let state = FakeCargoConfigurableUpstreamState {
            config_body,
            sparse_metadata,
            redirect_location,
            paths: Arc::clone(&paths),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake configurable Cargo upstream");
        let address = listener
            .local_addr()
            .expect("fake configurable Cargo upstream address");
        let router = Router::new()
            .route("/{*path}", get(fake_cargo_configurable_upstream_handler))
            .with_state(state);
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("fake configurable Cargo upstream serve");
        });
        (format!("http://{address}"), paths, handle)
    }

    #[derive(Debug, Clone)]
    struct FakeCargoDownloadStatusState {
        paths: Arc<Mutex<Vec<String>>>,
        download_status: StatusCode,
        download_body: &'static str,
    }

    async fn fake_cargo_download_status_upstream_handler(
        AxumState(state): AxumState<FakeCargoDownloadStatusState>,
        Path(path): Path<String>,
    ) -> Response {
        state.paths.lock().expect("record paths").push(path.clone());
        if path == "config.json" {
            return (
                [(CONTENT_TYPE, "application/json")],
                r#"{"dl":"api/v1/crates","api":"/api/v1"}"#,
            )
                .into_response();
        }
        if path.ends_with("/download") {
            return (
                state.download_status,
                [(CONTENT_TYPE, "text/plain")],
                state.download_body,
            )
                .into_response();
        }
        (
            [(CONTENT_TYPE, "application/vnd.rust.crate-index")],
            r#"{"name":"serde","vers":"1.0.0","cksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        )
            .into_response()
    }

    async fn spawn_fake_cargo_download_status_upstream(
        download_status: StatusCode,
        download_body: &'static str,
    ) -> (String, Arc<Mutex<Vec<String>>>, JoinHandle<()>) {
        let paths = Arc::new(Mutex::new(Vec::new()));
        let state = FakeCargoDownloadStatusState {
            paths: Arc::clone(&paths),
            download_status,
            download_body,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Cargo download status upstream");
        let address = listener
            .local_addr()
            .expect("fake Cargo download status upstream address");
        let router = Router::new()
            .route("/{*path}", get(fake_cargo_download_status_upstream_handler))
            .with_state(state);
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("fake Cargo download status upstream serve");
        });
        (format!("http://{address}"), paths, handle)
    }

    async fn fake_triage_handler(
        AxumState(state): AxumState<FakeTriageState>,
        Json(request): Json<DecisionRequest>,
    ) -> Response {
        state.calls.fetch_add(1, Ordering::SeqCst);
        state
            .requested_digests
            .lock()
            .expect("record requested digests")
            .push(
                request
                    .request
                    .requested_digest
                    .as_ref()
                    .map(|digest| digest.hex.clone()),
            );
        if let Some(status) = state.status {
            return status.into_response();
        }
        let artifact_behavior_applies =
            matches!(request.request.kind, PackageRequestKind::Artifact)
                && !state
                    .artifact_decision_version
                    .as_deref()
                    .is_some_and(|version| {
                        request.request.coordinate.version.as_deref() != Some(version)
                    });
        if artifact_behavior_applies && let Some(status) = state.artifact_status {
            return status.into_response();
        }
        let decision = if artifact_behavior_applies {
            state.artifact_decision.unwrap_or(state.decision)
        } else {
            state.decision
        };
        let mode = if artifact_behavior_applies {
            state.artifact_mode.unwrap_or(state.mode)
        } else {
            state.mode
        };
        Json(DecisionResponse {
            decision,
            tenant_id: request.tenant_id,
            policy_profile_id: request.policy_profile_id,
            policy_snapshot_id: Uuid::now_v7(),
            mode,
            feed_state: aegiscudo_core::FeedState::Fresh,
            feed_snapshot_age_seconds: 0,
            trace_id: request.request.trace_id,
            rationale: vec!["fake triage decision".to_owned()],
            fallback_coordinate: state.fallback_coordinate,
            create_analysis_job: state.create_analysis_job,
        })
        .into_response()
    }

    async fn spawn_fake_triage(
        decision: PolicyDecision,
        mode: PolicyMode,
        status: Option<StatusCode>,
    ) -> (String, Arc<AtomicUsize>, JoinHandle<()>) {
        let (url, calls, _digests, handle) =
            spawn_fake_triage_response(decision, mode, status, None, false).await;
        (url, calls, handle)
    }

    async fn spawn_fake_triage_with_artifact_decision(
        metadata_decision: PolicyDecision,
        artifact_decision: PolicyDecision,
        mode: PolicyMode,
    ) -> (String, Arc<AtomicUsize>, JoinHandle<()>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let requested_digests = Arc::new(Mutex::new(Vec::new()));
        let state = FakeTriageState {
            decision: metadata_decision,
            artifact_decision: Some(artifact_decision),
            artifact_decision_version: None,
            artifact_mode: None,
            artifact_status: None,
            mode,
            status: None,
            fallback_coordinate: None,
            create_analysis_job: false,
            calls: Arc::clone(&calls),
            requested_digests,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake triage");
        let address = listener.local_addr().expect("fake triage address");
        let router = Router::new()
            .route("/v1/decisions/evaluate", post(fake_triage_handler))
            .with_state(state);
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("fake triage serve");
        });
        (format!("http://{address}"), calls, handle)
    }

    async fn spawn_fake_triage_with_artifact_version_decision(
        metadata_decision: PolicyDecision,
        artifact_decision: PolicyDecision,
        artifact_version: &str,
        mode: PolicyMode,
    ) -> (String, Arc<AtomicUsize>, JoinHandle<()>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let requested_digests = Arc::new(Mutex::new(Vec::new()));
        let state = FakeTriageState {
            decision: metadata_decision,
            artifact_decision: Some(artifact_decision),
            artifact_decision_version: Some(artifact_version.to_owned()),
            artifact_mode: None,
            artifact_status: None,
            mode,
            status: None,
            fallback_coordinate: None,
            create_analysis_job: false,
            calls: Arc::clone(&calls),
            requested_digests,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake triage");
        let address = listener.local_addr().expect("fake triage address");
        let router = Router::new()
            .route("/v1/decisions/evaluate", post(fake_triage_handler))
            .with_state(state);
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("fake triage serve");
        });
        (format!("http://{address}"), calls, handle)
    }

    async fn spawn_fake_triage_with_artifact_version_mode(
        metadata_decision: PolicyDecision,
        metadata_mode: PolicyMode,
        artifact_decision: PolicyDecision,
        artifact_version: &str,
        artifact_mode: PolicyMode,
    ) -> (String, Arc<AtomicUsize>, JoinHandle<()>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let requested_digests = Arc::new(Mutex::new(Vec::new()));
        let state = FakeTriageState {
            decision: metadata_decision,
            artifact_decision: Some(artifact_decision),
            artifact_decision_version: Some(artifact_version.to_owned()),
            artifact_mode: Some(artifact_mode),
            artifact_status: None,
            mode: metadata_mode,
            status: None,
            fallback_coordinate: None,
            create_analysis_job: false,
            calls: Arc::clone(&calls),
            requested_digests,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake triage");
        let address = listener.local_addr().expect("fake triage address");
        let router = Router::new()
            .route("/v1/decisions/evaluate", post(fake_triage_handler))
            .with_state(state);
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("fake triage serve");
        });
        (format!("http://{address}"), calls, handle)
    }

    async fn spawn_fake_triage_with_artifact_version_status(
        metadata_decision: PolicyDecision,
        metadata_mode: PolicyMode,
        artifact_version: &str,
        artifact_status: StatusCode,
    ) -> (String, Arc<AtomicUsize>, JoinHandle<()>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let requested_digests = Arc::new(Mutex::new(Vec::new()));
        let state = FakeTriageState {
            decision: metadata_decision,
            artifact_decision: None,
            artifact_decision_version: Some(artifact_version.to_owned()),
            artifact_mode: None,
            artifact_status: Some(artifact_status),
            mode: metadata_mode,
            status: None,
            fallback_coordinate: None,
            create_analysis_job: false,
            calls: Arc::clone(&calls),
            requested_digests,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake triage");
        let address = listener.local_addr().expect("fake triage address");
        let router = Router::new()
            .route("/v1/decisions/evaluate", post(fake_triage_handler))
            .with_state(state);
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("fake triage serve");
        });
        (format!("http://{address}"), calls, handle)
    }

    async fn spawn_fake_triage_response(
        decision: PolicyDecision,
        mode: PolicyMode,
        status: Option<StatusCode>,
        fallback_coordinate: Option<PackageCoordinate>,
        create_analysis_job: bool,
    ) -> (
        String,
        Arc<AtomicUsize>,
        Arc<Mutex<Vec<Option<String>>>>,
        JoinHandle<()>,
    ) {
        let calls = Arc::new(AtomicUsize::new(0));
        let requested_digests = Arc::new(Mutex::new(Vec::new()));
        let state = FakeTriageState {
            decision,
            artifact_decision: None,
            artifact_decision_version: None,
            artifact_mode: None,
            artifact_status: None,
            mode,
            status,
            fallback_coordinate,
            create_analysis_job,
            calls: Arc::clone(&calls),
            requested_digests: Arc::clone(&requested_digests),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().expect("fake triage address");
        let router = Router::new()
            .route("/v1/decisions/evaluate", post(fake_triage_handler))
            .with_state(state);
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("fake triage serve");
        });
        (
            format!("http://{address}"),
            calls,
            requested_digests,
            handle,
        )
    }

    async fn spawn_mosquito(
        store: RegistryConfigStore,
        triage_url: &str,
        rate_limit_config: ProxyRateLimitConfig,
    ) -> (String, JoinHandle<()>) {
        spawn_mosquito_with_cargo_download_mac_key(
            store,
            triage_url,
            rate_limit_config,
            TEST_CARGO_DOWNLOAD_MAC_KEY.to_vec(),
        )
        .await
    }

    async fn spawn_mosquito_with_cargo_download_mac_key(
        store: RegistryConfigStore,
        triage_url: &str,
        rate_limit_config: ProxyRateLimitConfig,
        cargo_download_mac_key: Vec<u8>,
    ) -> (String, JoinHandle<()>) {
        let client =
            TriageClient::new(triage_url, Duration::from_millis(500), 0).expect("triage client");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mosquito");
        let address = listener.local_addr().expect("mosquito address");
        let router = app_with_runtime_config_and_cargo_download_mac_key(
            store,
            client,
            rate_limit_config,
            cargo_download_mac_key,
        );
        let handle = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("mosquito serve");
        });
        (format!("http://{address}"), handle)
    }

    #[tokio::test]
    async fn proxy_calls_triage_and_allows_non_blocking_decision() {
        let (triage_url, calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, upstream_paths, upstream_handle) = spawn_fake_upstream().await;
        let config = config_with_upstream("/proxy/npm-public", PolicyMode::Enforce, &upstream_url);
        let store = RegistryConfigStore::new(vec![config.clone()]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/npm-public/left-pad"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("json body");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(body["name"], "left-pad");
        assert_eq!(
            body["versions"]["1.0.0"]["dist"]["tarball"],
            format!("{base_url}/proxy/npm-public/left-pad/-/pkg-1.0.0.tgz")
        );
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &["left-pad".to_owned()]
        );

        let metrics = reqwest::get(format!("{base_url}/metrics"))
            .await
            .expect("metrics request")
            .text()
            .await
            .expect("metrics text");
        assert!(metrics.contains("aegiscudo_requests_total"));
        assert!(metrics.contains("aegiscudo_decisions_total"));
        assert!(metrics.contains("aegiscudo_mosquito_net_triage_latency_seconds"));
        assert!(metrics.contains(&format!("tenant_id=\"{}\"", config.tenant_id)));
        assert!(metrics.contains(&format!("registry_config_id=\"{}\"", config.id)));
        assert!(metrics.contains("decision_state=\"ALLOW\""));

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn repeated_metadata_request_uses_decision_and_metadata_caches() {
        let (triage_url, calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, upstream_paths, upstream_handle) = spawn_fake_upstream().await;
        let config = config_with_upstream("/proxy/npm-public", PolicyMode::Enforce, &upstream_url);
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let first = reqwest::get(format!("{base_url}/proxy/npm-public/left-pad"))
            .await
            .expect("first proxy request");
        let second = reqwest::get(format!("{base_url}/proxy/npm-public/left-pad"))
            .await
            .expect("second proxy request");

        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &["left-pad".to_owned()]
        );

        let metrics = reqwest::get(format!("{base_url}/metrics"))
            .await
            .expect("metrics request")
            .text()
            .await
            .expect("metrics text");
        assert!(metrics.contains("aegiscudo_cache_events_total"));
        assert!(metrics.contains("cache_type=\"decision\",outcome=\"hit\""));
        assert!(metrics.contains("cache_type=\"metadata\",outcome=\"hit\""));

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn enforce_mode_blocks_blocking_decision() {
        let (triage_url, _calls, triage_handle) = spawn_fake_triage(
            PolicyDecision::BlockKnownMalicious,
            PolicyMode::Enforce,
            None,
        )
        .await;
        let store =
            RegistryConfigStore::new(vec![config("/proxy/npm-public", PolicyMode::Enforce)])
                .expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/npm-public/left-pad"))
            .await
            .expect("proxy request");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.headers().contains_key(ADVISORY_HEADER));
        let body: serde_json::Value = response.json().await.expect("json body");
        assert_eq!(body["decision"], "BLOCK_KNOWN_MALICIOUS");

        mosquito_handle.abort();
        triage_handle.abort();
    }

    #[tokio::test]
    async fn warn_mode_keeps_blocking_decision_advisory() {
        let (triage_url, _calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::BlockKnownMalicious, PolicyMode::Warn, None).await;
        let (upstream_url, _upstream_paths, upstream_handle) = spawn_fake_upstream().await;
        let store = RegistryConfigStore::new(vec![config_with_upstream(
            "/proxy/npm-public",
            PolicyMode::Warn,
            &upstream_url,
        )])
        .expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/npm-public/left-pad"))
            .await
            .expect("proxy request");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key(ADVISORY_HEADER));
        let advisory: AdvisoryHeaderPayload = serde_json::from_str(
            response
                .headers()
                .get(ADVISORY_HEADER)
                .expect("advisory header")
                .to_str()
                .expect("advisory header text"),
        )
        .expect("advisory payload");
        let body: serde_json::Value = response.json().await.expect("json body");
        assert_eq!(advisory.decision, PolicyDecision::BlockKnownMalicious);
        assert_eq!(body["name"], "left-pad");

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn shadow_mode_keeps_blocking_decision_advisory() {
        let (triage_url, _calls, triage_handle) = spawn_fake_triage(
            PolicyDecision::BlockKnownMalicious,
            PolicyMode::Shadow,
            None,
        )
        .await;
        let (upstream_url, _upstream_paths, upstream_handle) = spawn_fake_upstream().await;
        let store = RegistryConfigStore::new(vec![config_with_upstream(
            "/proxy/npm-public",
            PolicyMode::Shadow,
            &upstream_url,
        )])
        .expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/npm-public/left-pad"))
            .await
            .expect("proxy request");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key(ADVISORY_HEADER));
        let advisory: AdvisoryHeaderPayload = serde_json::from_str(
            response
                .headers()
                .get(ADVISORY_HEADER)
                .expect("advisory header")
                .to_str()
                .expect("advisory header text"),
        )
        .expect("advisory payload");
        let body: serde_json::Value = response.json().await.expect("json body");
        assert_eq!(advisory.decision, PolicyDecision::BlockKnownMalicious);
        assert_eq!(body["name"], "left-pad");

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn enforce_mode_blocks_quarantine_decision() {
        let (triage_url, _calls, triage_handle) = spawn_fake_triage(
            PolicyDecision::QuarantinePendingAnalysis,
            PolicyMode::Enforce,
            None,
        )
        .await;
        let store =
            RegistryConfigStore::new(vec![config("/proxy/npm-public", PolicyMode::Enforce)])
                .expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/npm-public/left-pad"))
            .await
            .expect("proxy request");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.headers().contains_key(ADVISORY_HEADER));
        let body: serde_json::Value = response.json().await.expect("json body");
        assert_eq!(body["decision"], "QUARANTINE_PENDING_ANALYSIS");

        mosquito_handle.abort();
        triage_handle.abort();
    }

    #[tokio::test]
    async fn fallback_decision_returns_candidate_without_enforcement() {
        let fallback_coordinate = PackageCoordinate::new(
            PackageEcosystem::Npm,
            "left-pad-safe",
            Some("1.3.1"),
            None::<String>,
        );
        let (triage_url, _calls, _digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::FallbackToApprovedCandidate,
            PolicyMode::Enforce,
            None,
            Some(fallback_coordinate.clone()),
            false,
        )
        .await;
        let (upstream_url, upstream_paths, upstream_handle) = spawn_fake_upstream().await;
        let store = RegistryConfigStore::new(vec![config_with_upstream(
            "/proxy/npm-public",
            PolicyMode::Enforce,
            &upstream_url,
        )])
        .expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/npm-public/left-pad"))
            .await
            .expect("proxy request");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key(ADVISORY_HEADER));
        let body: serde_json::Value = response.json().await.expect("json body");
        assert_eq!(body["name"], "left-pad-safe");
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &["left-pad-safe".to_owned()]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[test]
    fn fallback_metadata_filters_same_package_to_candidate_version() {
        let resolved = ResolvedRegistryConfig {
            config: config("/proxy/npm-public", PolicyMode::Enforce),
            upstream_path: "left-pad".to_owned(),
        };
        let decision = DecisionResponse {
            decision: PolicyDecision::FallbackToApprovedCandidate,
            tenant_id: resolved.config.tenant_id,
            policy_profile_id: resolved.config.policy_profile_id,
            policy_snapshot_id: Uuid::now_v7(),
            mode: PolicyMode::Enforce,
            feed_state: aegiscudo_core::FeedState::Fresh,
            feed_snapshot_age_seconds: 0,
            trace_id: "trace-fallback".to_owned(),
            rationale: vec![
                "eligible resolver metadata flow can use approved fallback candidate".to_owned(),
            ],
            fallback_coordinate: Some(PackageCoordinate::new(
                PackageEcosystem::Npm,
                "left-pad",
                Some("1.0.0"),
                None::<String>,
            )),
            create_analysis_job: false,
        };
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let body = br#"{
            "name": "left-pad",
            "dist-tags": { "latest": "1.2.0" },
            "versions": {
                "1.0.0": { "name": "left-pad", "version": "1.0.0" },
                "1.2.0": { "name": "left-pad", "version": "1.2.0" }
            },
            "time": {
                "created": "2026-05-01T00:00:00.000Z",
                "modified": "2026-05-03T00:00:00.000Z",
                "1.0.0": "2026-05-01T00:00:00.000Z",
                "1.2.0": "2026-05-03T00:00:00.000Z"
            }
        }"#
        .to_vec();

        let filtered = maybe_apply_npm_fallback_metadata(&resolved, &decision, &headers, body);
        let filtered: serde_json::Value =
            serde_json::from_slice(&filtered).expect("filtered npm metadata json");

        assert_eq!(filtered["dist-tags"]["latest"], "1.0.0");
        assert_eq!(
            filtered["versions"]
                .as_object()
                .map(|versions| versions.len()),
            Some(1)
        );
        assert!(filtered["versions"].get("1.2.0").is_none());
        assert_eq!(filtered["versions"]["1.0.0"]["version"], "1.0.0");
        assert!(filtered["time"].get("1.2.0").is_none());
    }

    #[tokio::test]
    async fn fallback_decision_does_not_substitute_explicit_npm_version_route() {
        let fallback_coordinate = PackageCoordinate::new(
            PackageEcosystem::Npm,
            "left-pad-safe",
            Some("1.3.1"),
            None::<String>,
        );
        let (triage_url, _calls, _digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::FallbackToApprovedCandidate,
            PolicyMode::Enforce,
            None,
            Some(fallback_coordinate),
            false,
        )
        .await;
        let (upstream_url, upstream_paths, upstream_handle) = spawn_fake_upstream().await;
        let store = RegistryConfigStore::new(vec![config_with_upstream(
            "/proxy/npm-public",
            PolicyMode::Enforce,
            &upstream_url,
        )])
        .expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/npm-public/left-pad/1.0.0"))
            .await
            .expect("proxy request");
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = response.json().await.expect("json body");
        assert_eq!(body["name"], "left-pad/1.0.0");
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &["left-pad/1.0.0".to_owned()]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn fallback_decision_does_not_substitute_npm_tarball_route() {
        let fallback_coordinate = PackageCoordinate::new(
            PackageEcosystem::Npm,
            "left-pad-safe",
            Some("1.3.1"),
            None::<String>,
        );
        let (triage_url, _calls, _digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::FallbackToApprovedCandidate,
            PolicyMode::Enforce,
            None,
            Some(fallback_coordinate),
            false,
        )
        .await;
        let (upstream_url, upstream_paths, upstream_handle) = spawn_fake_upstream().await;
        let store = RegistryConfigStore::new(vec![config_with_upstream(
            "/proxy/npm-public",
            PolicyMode::Enforce,
            &upstream_url,
        )])
        .expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let artifact_path = "left-pad/-/left-pad-1.0.0.tgz";
        let response = reqwest::get(format!("{base_url}/proxy/npm-public/{artifact_path}"))
            .await
            .expect("proxy request");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.text().await.expect("artifact body");
        assert_eq!(body, format!("artifact bytes for {artifact_path}"));
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &[artifact_path.to_owned()]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn pypi_simple_proxy_rewrites_file_links_under_mount() {
        let (triage_url, calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, upstream_paths, upstream_handle) = spawn_fake_pypi_upstream().await;
        let config = config_with_adapter_upstream(
            "/proxy/pypi-public",
            PolicyMode::Enforce,
            RegistryAdapter::Pypi,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/pypi-public/simple/Requests/"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body = response.text().await.expect("html body");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(body.contains(&format!(
            "href=\"{base_url}/proxy/pypi-public/packages/ab/pkg-1.0.0.tar.gz#sha256=abc\""
        )));
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &["simple/Requests".to_owned()]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn pypi_simple_proxy_filters_blocked_file_links() {
        let (triage_url, calls, triage_handle) = spawn_fake_triage_with_artifact_decision(
            PolicyDecision::Allow,
            PolicyDecision::BlockKnownMalicious,
            PolicyMode::Enforce,
        )
        .await;
        let (upstream_url, _upstream_paths, upstream_handle) = spawn_fake_body_upstream(
            "text/html",
            r#"<html><body><a href="/packages/ab/pkg-1.0.0.tar.gz#sha256=abc">pkg</a></body></html>"#,
        )
        .await;
        let config = config_with_adapter_upstream(
            "/proxy/pypi-public",
            PolicyMode::Enforce,
            RegistryAdapter::Pypi,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/pypi-public/simple/pkg/"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body = response.text().await.expect("html body");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(!body.contains("pkg-1.0.0.tar.gz"));

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn pypi_json_proxy_rewrites_relative_file_links_under_mount() {
        let (triage_url, calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, _upstream_paths, upstream_handle) = spawn_fake_body_upstream(
            "application/vnd.pypi.simple.v1+json",
            r#"{
              "meta": { "api-version": "1.3" },
              "name": "pkg",
              "files": [{
                "filename": "pkg-1.0.0.tar.gz",
                "url": "../../packages/ab/pkg-1.0.0.tar.gz#sha256=abc"
              }]
            }"#,
        )
        .await;
        let config = config_with_adapter_upstream(
            "/proxy/pypi-public",
            PolicyMode::Enforce,
            RegistryAdapter::Pypi,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/pypi-public/simple/pkg/"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("json body");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            body["files"][0]["url"],
            format!("{base_url}/proxy/pypi-public/packages/ab/pkg-1.0.0.tar.gz#sha256=abc")
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn pypi_json_proxy_filters_blocked_file_links() {
        let (triage_url, calls, triage_handle) = spawn_fake_triage_with_artifact_decision(
            PolicyDecision::Allow,
            PolicyDecision::BlockKnownMalicious,
            PolicyMode::Enforce,
        )
        .await;
        let (upstream_url, _upstream_paths, upstream_handle) = spawn_fake_body_upstream(
            "application/vnd.pypi.simple.v1+json",
            r#"{
              "meta": { "api-version": "1.3" },
              "name": "pkg",
              "files": [{
                "filename": "pkg-1.0.0.tar.gz",
                "url": "../../packages/ab/pkg-1.0.0.tar.gz#sha256=abc"
              }]
            }"#,
        )
        .await;
        let config = config_with_adapter_upstream(
            "/proxy/pypi-public",
            PolicyMode::Enforce,
            RegistryAdapter::Pypi,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/pypi-public/simple/pkg/"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("json body");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(body["files"].as_array().expect("files array").len(), 0);
        assert_eq!(body["meta"]["api-version"], "1.3");

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[test]
    fn bearer_credentials_are_injected_from_configured_env_var() {
        let env_name = format!("AEGISCUDO_TEST_CREDENTIAL_{}", Uuid::now_v7().simple());
        unsafe {
            std::env::set_var(&env_name, "redacted-test-token");
        }
        let mut config = config("/proxy/npm-private", PolicyMode::Enforce);
        config.auth_type = CredentialAuthType::Bearer;
        config.credential_ref = Some(Uuid::now_v7());
        config.credential_env_var = Some(env_name.clone());
        let resolved = ResolvedRegistryConfig {
            config,
            upstream_path: "left-pad".to_owned(),
        };
        let request = inject_upstream_credentials(
            reqwest::Client::new().get("https://registry.example.invalid/left-pad"),
            &resolved,
        )
        .expect("credential injection")
        .build()
        .expect("request build");
        let authorization = request
            .headers()
            .get(AUTHORIZATION)
            .expect("authorization header")
            .to_str()
            .expect("header value");
        assert!(authorization.starts_with("Bearer "));
        assert_eq!(
            authorization.len(),
            "Bearer ".len() + "redacted-test-token".len()
        );
        unsafe {
            std::env::remove_var(env_name);
        }
    }

    #[tokio::test]
    async fn artifact_proxy_prefetches_digest_before_triage_and_serves_body() {
        let (triage_url, calls, requested_digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::AllowWithWarning,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let (upstream_url, upstream_paths, upstream_handle) = spawn_fake_upstream().await;
        let store = RegistryConfigStore::new(vec![config_with_upstream(
            "/proxy/npm-public",
            PolicyMode::Enforce,
            &upstream_url,
        )])
        .expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let artifact_path = "left-pad/-/left-pad-1.3.0.tgz";
        let response = reqwest::get(format!("{base_url}/proxy/npm-public/{artifact_path}"))
            .await
            .expect("artifact proxy request");
        let status = response.status();
        let body = response.text().await.expect("artifact body");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(body, format!("artifact bytes for {artifact_path}"));
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &[artifact_path.to_owned()]
        );
        let expected_digest = sha256_digest(body.as_bytes()).expect("digest").hex;
        assert_eq!(
            requested_digests.lock().expect("digests").as_slice(),
            &[Some(expected_digest)]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn response_mode_mismatch_fails_closed() {
        let (triage_url, _calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::BlockKnownMalicious, PolicyMode::Warn, None).await;
        let store =
            RegistryConfigStore::new(vec![config("/proxy/npm-public", PolicyMode::Enforce)])
                .expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/npm-public/left-pad"))
            .await
            .expect("proxy request");
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(response.headers().contains_key(ADVISORY_HEADER));
        let body: serde_json::Value = response.json().await.expect("json body");
        assert_eq!(body["decision"], "QUARANTINE_PENDING_ANALYSIS");

        mosquito_handle.abort();
        triage_handle.abort();
    }

    #[tokio::test]
    async fn non_retryable_triage_error_does_not_fail_open_in_warn_mode() {
        let (triage_url, _calls, triage_handle) = spawn_fake_triage(
            PolicyDecision::Allow,
            PolicyMode::Warn,
            Some(StatusCode::BAD_REQUEST),
        )
        .await;
        let store = RegistryConfigStore::new(vec![config("/proxy/npm-public", PolicyMode::Warn)])
            .expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/npm-public/left-pad"))
            .await
            .expect("proxy request");
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(response.headers().contains_key(ADVISORY_HEADER));
        let body: serde_json::Value = response.json().await.expect("json body");
        assert_eq!(body["decision"], "QUARANTINE_PENDING_ANALYSIS");

        mosquito_handle.abort();
        triage_handle.abort();
    }

    #[tokio::test]
    async fn enforce_mode_fails_closed_when_triage_is_unavailable() {
        let (triage_url, _calls, triage_handle) = spawn_fake_triage(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            Some(StatusCode::SERVICE_UNAVAILABLE),
        )
        .await;
        let store =
            RegistryConfigStore::new(vec![config("/proxy/npm-public", PolicyMode::Enforce)])
                .expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/npm-public/left-pad"))
            .await
            .expect("proxy request");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.headers().contains_key(ADVISORY_HEADER));
        let body: serde_json::Value = response.json().await.expect("json body");
        assert_eq!(body["decision"], "QUARANTINE_PENDING_ANALYSIS");

        mosquito_handle.abort();
        triage_handle.abort();
    }

    #[tokio::test]
    async fn warn_mode_fails_open_with_advisory_when_triage_is_unavailable() {
        let (triage_url, _calls, triage_handle) = spawn_fake_triage(
            PolicyDecision::Allow,
            PolicyMode::Warn,
            Some(StatusCode::SERVICE_UNAVAILABLE),
        )
        .await;
        let store = RegistryConfigStore::new(vec![config("/proxy/npm-public", PolicyMode::Warn)])
            .expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/npm-public/left-pad"))
            .await
            .expect("proxy request");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key(ADVISORY_HEADER));
        let body: serde_json::Value = response.json().await.expect("json body");
        assert_eq!(body["triage_unavailable"], true);
        assert_eq!(body["triage_decision"], serde_json::Value::Null);

        mosquito_handle.abort();
        triage_handle.abort();
    }

    #[tokio::test]
    async fn tenant_rate_limit_rejects_second_request_with_retry_after() {
        let (triage_url, _calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, _upstream_paths, upstream_handle) = spawn_fake_upstream().await;
        let store = RegistryConfigStore::new(vec![config_with_upstream(
            "/proxy/npm-public",
            PolicyMode::Enforce,
            &upstream_url,
        )])
        .expect("store");
        let rate_limits = ProxyRateLimitConfig {
            tenant_api: rate_limit::RateLimitConfig::new(Duration::from_secs(60), 1),
            client_package: rate_limit::RateLimitConfig::new(Duration::from_secs(60), 10),
        };
        let (base_url, mosquito_handle) = spawn_mosquito(store, &triage_url, rate_limits).await;

        let first = reqwest::get(format!("{base_url}/proxy/npm-public/left-pad"))
            .await
            .expect("first proxy request");
        assert_eq!(first.status(), StatusCode::OK);

        let second = reqwest::get(format!("{base_url}/proxy/npm-public/left-pad"))
            .await
            .expect("second proxy request");
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            second
                .headers()
                .get(RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("60")
        );
        let body: serde_json::Value = second.json().await.expect("rate-limit body");
        assert_eq!(body["message"], "tenant API rate limit exceeded");

        let metrics = reqwest::get(format!("{base_url}/metrics"))
            .await
            .expect("metrics request")
            .text()
            .await
            .expect("metrics text");
        assert!(metrics.contains("aegiscudo_rate_limit_events_total"));
        assert!(metrics.contains("limiter=\"tenant-api\",outcome=\"tenant-rate-limit-exceeded\""));

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn client_rate_limit_rejects_second_request_when_tenant_limit_has_headroom() {
        let (triage_url, _calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, _upstream_paths, upstream_handle) = spawn_fake_upstream().await;
        let store = RegistryConfigStore::new(vec![config_with_upstream(
            "/proxy/npm-public",
            PolicyMode::Enforce,
            &upstream_url,
        )])
        .expect("store");
        let rate_limits = ProxyRateLimitConfig {
            tenant_api: rate_limit::RateLimitConfig::new(Duration::from_secs(60), 10),
            client_package: rate_limit::RateLimitConfig::new(Duration::from_secs(60), 1),
        };
        let (base_url, mosquito_handle) = spawn_mosquito(store, &triage_url, rate_limits).await;

        let first = reqwest::get(format!("{base_url}/proxy/npm-public/left-pad"))
            .await
            .expect("first proxy request");
        assert_eq!(first.status(), StatusCode::OK);

        let second = reqwest::get(format!("{base_url}/proxy/npm-public/left-pad"))
            .await
            .expect("second proxy request");
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        let body: serde_json::Value = second.json().await.expect("rate-limit body");
        assert_eq!(
            body["message"],
            "client package request rate limit exceeded"
        );

        let metrics = reqwest::get(format!("{base_url}/metrics"))
            .await
            .expect("metrics request")
            .text()
            .await
            .expect("metrics text");
        assert!(metrics.contains("aegiscudo_rate_limit_events_total"));
        assert!(
            metrics.contains("limiter=\"client-package\",outcome=\"client-rate-limit-exceeded\"")
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[test]
    fn npm_artifact_path_extracts_version() {
        let (kind, coordinate, explicit) = npm_request_context("left-pad/-/left-pad-1.3.0.tgz")
            .expect("npm tarball path should normalize");

        assert_eq!(kind, PackageRequestKind::Artifact);
        assert_eq!(coordinate.purl(), "pkg:npm/left-pad@1.3.0");
        assert!(explicit);
    }

    #[test]
    fn pypi_artifact_path_extracts_coordinate_from_wheel() {
        let (kind, coordinate, explicit) =
            pypi_request_context("packages/ab/cd/Requests-2.32.0-py3-none-any.whl")
                .expect("PyPI wheel path should normalize");

        assert_eq!(kind, PackageRequestKind::Artifact);
        assert_eq!(coordinate.purl(), "pkg:pypi/requests@2.32.0");
        assert!(explicit);
    }

    #[test]
    fn cargo_sparse_path_extracts_coordinate() {
        let (kind, coordinate, explicit) =
            cargo_request_context("se/rd/serde").expect("Cargo sparse path should normalize");

        assert_eq!(kind, PackageRequestKind::Metadata);
        assert_eq!(coordinate.purl(), "pkg:cargo/serde");
        assert!(!explicit);
    }

    #[test]
    fn cargo_download_path_extracts_coordinate() {
        let config_id = Uuid::nil();
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(b"api/v1/crates");
        let signature =
            cargo_download_base_signature(&TEST_CARGO_DOWNLOAD_MAC_KEY, config_id, "api/v1/crates");
        let (kind, coordinate, explicit) = cargo_request_context(&format!(
            "{CARGO_DL_PROXY_PREFIX}/{encoded}/{signature}/serde/1.0.0/download"
        ))
        .expect("Cargo download path should normalize");

        assert_eq!(kind, PackageRequestKind::Artifact);
        assert_eq!(coordinate.purl(), "pkg:cargo/serde@1.0.0");
        assert!(explicit);
    }

    #[test]
    fn cargo_download_path_extracts_coordinate_without_crates_prefix() {
        let config_id = Uuid::nil();
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(b"dl");
        let signature =
            cargo_download_base_signature(&TEST_CARGO_DOWNLOAD_MAC_KEY, config_id, "dl");
        let (kind, coordinate, explicit) = cargo_request_context(&format!(
            "{CARGO_DL_PROXY_PREFIX}/{encoded}/{signature}/serde/1.0.0/download"
        ))
        .expect("Cargo download path without crates prefix should normalize");

        assert_eq!(kind, PackageRequestKind::Artifact);
        assert_eq!(coordinate.purl(), "pkg:cargo/serde@1.0.0");
        assert!(explicit);
    }

    #[test]
    fn cargo_download_path_without_encoded_base_is_rejected() {
        assert_eq!(
            cargo_request_context("serde/1.0.0/download"),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn cargo_sparse_path_named_download_stays_metadata() {
        let (kind, coordinate, explicit) =
            cargo_request_context("do/wn/download").expect("download crate path should normalize");

        assert_eq!(kind, PackageRequestKind::Metadata);
        assert_eq!(coordinate.purl(), "pkg:cargo/download");
        assert!(!explicit);
    }

    #[test]
    fn cargo_sparse_path_rejects_non_index_three_segment_route() {
        assert_eq!(
            cargo_request_context("api/v1/crates"),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn cargo_sparse_path_rejects_invalid_three_segment_layout() {
        assert_eq!(
            cargo_request_context("foo/bar/baz"),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn cargo_download_path_rejects_extra_prefix_segments() {
        assert_eq!(
            cargo_request_context("api/v1/crates/extra/serde/1.0.0/download"),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn cargo_download_path_rejects_dot_segment_suffix_after_encoded_base() {
        let config_id = Uuid::nil();
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(b"api/v1/crates");
        let signature =
            cargo_download_base_signature(&TEST_CARGO_DOWNLOAD_MAC_KEY, config_id, "api/v1/crates");
        assert_eq!(
            cargo_request_context(&format!(
                "{CARGO_DL_PROXY_PREFIX}/{encoded}/{signature}/../serde/1.0.0/download"
            )),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn cargo_download_path_rejects_invalid_semver_suffix() {
        let config_id = Uuid::nil();
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(b"api/v1/crates");
        let signature =
            cargo_download_base_signature(&TEST_CARGO_DOWNLOAD_MAC_KEY, config_id, "api/v1/crates");
        assert_eq!(
            cargo_request_context(&format!(
                "{CARGO_DL_PROXY_PREFIX}/{encoded}/{signature}/serde/01.2.3/download"
            )),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn cargo_registry_config_rewrite_preserves_absolute_query_and_fragment() {
        let config_id = Uuid::nil();
        let rewritten = rewrite_cargo_registry_config(
            &TEST_CARGO_DOWNLOAD_MAC_KEY,
            config_id,
            "/proxy/cargo-public",
            "http://mosquito.local",
            "https://registry.example.invalid/sparse/",
            &[],
            br#"{"dl":"https://registry.example.invalid/dl?token=abc#frag"}"#.to_vec(),
        )
        .expect("rewritten config");
        let body: serde_json::Value = serde_json::from_slice(&rewritten).expect("rewritten json");
        let prefix = format!("http://mosquito.local/proxy/cargo-public/{CARGO_DL_PROXY_PREFIX}/");
        let encoded = body["dl"]
            .as_str()
            .expect("rewritten download url")
            .strip_prefix(&prefix)
            .expect("encoded cargo proxy prefix");
        let upstream = adapter_upstream_request_url(
            &TEST_CARGO_DOWNLOAD_MAC_KEY,
            config_id,
            RegistryAdapter::Cargo,
            "https://registry.example.invalid/sparse/",
            &[],
            &format!("{CARGO_DL_PROXY_PREFIX}/{encoded}/serde/1.0.0/download"),
        )
        .expect("upstream url");

        assert_eq!(body["dl"], format!("{prefix}{encoded}"));
        assert_eq!(
            upstream.as_str(),
            "https://registry.example.invalid/dl/serde/1.0.0/download?token=abc#frag"
        );
    }

    #[test]
    fn cargo_download_proxy_path_restores_rooted_download_base() {
        let config_id = Uuid::nil();
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(b"/api/v1/crates");
        let signature = cargo_download_base_signature(
            &TEST_CARGO_DOWNLOAD_MAC_KEY,
            config_id,
            "/api/v1/crates",
        );
        let upstream = adapter_upstream_request_url(
            &TEST_CARGO_DOWNLOAD_MAC_KEY,
            config_id,
            RegistryAdapter::Cargo,
            "https://registry.example.invalid/sparse/index/",
            &[],
            &format!("{CARGO_DL_PROXY_PREFIX}/{encoded}/{signature}/serde/1.0.0/download"),
        )
        .expect("upstream url");

        assert_eq!(
            upstream.as_str(),
            "https://registry.example.invalid/api/v1/crates/serde/1.0.0/download"
        );
    }

    #[test]
    fn cargo_download_proxy_path_restores_parent_relative_download_base() {
        let config_id = Uuid::nil();
        let rewritten = rewrite_cargo_registry_config(
            &TEST_CARGO_DOWNLOAD_MAC_KEY,
            config_id,
            "/proxy/cargo-public",
            "http://mosquito.local",
            "https://registry.example.invalid/sparse/",
            &[],
            br#"{"dl":"../api/v1/crates"}"#.to_vec(),
        )
        .expect("rewritten config");
        let body: serde_json::Value = serde_json::from_slice(&rewritten).expect("rewritten json");
        let prefix = format!("http://mosquito.local/proxy/cargo-public/{CARGO_DL_PROXY_PREFIX}/");
        let encoded = body["dl"]
            .as_str()
            .expect("rewritten download url")
            .strip_prefix(&prefix)
            .expect("encoded cargo proxy prefix");
        let upstream = adapter_upstream_request_url(
            &TEST_CARGO_DOWNLOAD_MAC_KEY,
            config_id,
            RegistryAdapter::Cargo,
            "https://registry.example.invalid/sparse/",
            &[],
            &format!("{CARGO_DL_PROXY_PREFIX}/{encoded}/serde/1.0.0/download"),
        )
        .expect("upstream url");

        assert_eq!(
            upstream.as_str(),
            "https://registry.example.invalid/api/v1/crates/serde/1.0.0/download"
        );
    }

    #[tokio::test]
    async fn cargo_registry_config_cross_origin_absolute_download_base_fails_closed() {
        let (triage_url, _calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, _upstream_paths, upstream_handle) = spawn_fake_body_upstream(
            "application/json",
            r#"{"dl":"https://elsewhere.example.invalid/api/v1/crates"}"#,
        )
        .await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/cargo-public/config.json"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("json body");

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["decision"], "QUARANTINE_PENDING_ANALYSIS");

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_registry_config_cross_origin_absolute_download_base_is_allowed_when_origin_is_listed()
     {
        let download_body = "cross-origin crate bytes";
        let sparse_checksum = hex::encode(Sha256::digest(download_body.as_bytes()));
        let (download_origin, download_paths, download_handle) =
            spawn_fake_body_upstream("application/octet-stream", download_body).await;
        let (triage_url, calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, upstream_paths, upstream_handle) =
            spawn_fake_cargo_configurable_upstream(
                format!(r#"{{"dl":"{download_origin}/crates","api":"/api/v1"}}"#),
                format!(r#"{{"name":"serde","vers":"1.0.0","cksum":"{sparse_checksum}"}}"#),
                None,
            )
            .await;
        let mut config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        config.cargo_allowed_download_origins = vec![download_origin.clone()];
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let config_response = reqwest::get(format!("{base_url}/proxy/cargo-public/config.json"))
            .await
            .expect("config request");
        let config_body: serde_json::Value = config_response.json().await.expect("config body");
        let download_base = config_body["dl"].as_str().expect("download base");
        let response = reqwest::get(format!("{download_base}/serde/1.0.0/download"))
            .await
            .expect("download request");
        let status = response.status();
        let body = response.text().await.expect("artifact body");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, download_body);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &["config.json".to_owned(), "se/rd/serde".to_owned()]
        );
        assert_eq!(
            download_paths.lock().expect("paths").as_slice(),
            &["crates/serde/1.0.0/download".to_owned()]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
        download_handle.abort();
    }

    #[tokio::test]
    async fn cargo_registry_config_rewrites_download_base_under_mount() {
        let (triage_url, calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, upstream_paths, upstream_handle) = spawn_fake_cargo_upstream().await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/cargo-public/config.json"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("config body");
        let dl = body["dl"].as_str().expect("download base");
        let api = body["api"].as_str().expect("api base");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(dl.starts_with(&format!(
            "{base_url}/proxy/cargo-public/{CARGO_DL_PROXY_PREFIX}/"
        )));
        assert!(api.starts_with(&format!(
            "{base_url}/proxy/cargo-public/{CARGO_API_PROXY_PREFIX}/"
        )));
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &["config.json".to_owned()]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_registry_config_rewrites_download_base_without_json_content_type() {
        let (triage_url, calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, upstream_paths, upstream_handle) =
            spawn_fake_body_upstream("text/plain", r#"{"dl":"api/v1/crates","api":"."}"#).await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/cargo-public/config.json"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("config body");
        let dl = body["dl"].as_str().expect("download base");
        let api = body["api"].as_str().expect("api base");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(dl.starts_with(&format!(
            "{base_url}/proxy/cargo-public/{CARGO_DL_PROXY_PREFIX}/"
        )));
        assert!(api.starts_with(&format!(
            "{base_url}/proxy/cargo-public/{CARGO_API_PROXY_PREFIX}/"
        )));
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &["config.json".to_owned()]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_registry_config_invalid_payload_fails_closed() {
        let (triage_url, _calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, _upstream_paths, upstream_handle) =
            spawn_fake_body_upstream("text/plain", "not-json").await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/cargo-public/config.json"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("json body");

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["decision"], "QUARANTINE_PENDING_ANALYSIS");

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_registry_config_rejects_absolute_api_origin_outside_registry_host() {
        let (triage_url, _calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, _upstream_paths, upstream_handle) = spawn_fake_body_upstream(
            "application/json",
            r#"{"dl":"api/v1/crates","api":"https://elsewhere.example.invalid"}"#,
        )
        .await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/cargo-public/config.json"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("json body");

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["decision"], "QUARANTINE_PENDING_ANALYSIS");

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_registry_api_get_preserves_query_string_and_rewrites_location() {
        let (triage_url, calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, upstream_paths, requests, upstream_handle) =
            spawn_fake_cargo_api_upstream().await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let config_response = reqwest::get(format!("{base_url}/proxy/cargo-public/config.json"))
            .await
            .expect("config request");
        let config_body: serde_json::Value = config_response.json().await.expect("config body");
        let api_base = config_body["api"].as_str().expect("api base");

        let response = reqwest::get(format!("{api_base}/api/v1/crates?q=serde&per_page=5"))
            .await
            .expect("proxy request");
        let status = response.status();
        let location = response
            .headers()
            .get(LOCATION)
            .expect("location header")
            .to_str()
            .expect("location value")
            .to_owned();
        let body: serde_json::Value = response.json().await.expect("json body");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(location, format!("{api_base}/api/v1/crates/result"));
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &["config.json".to_owned(), "api/v1/crates".to_owned()]
        );
        assert_eq!(
            requests.lock().expect("requests").as_slice(),
            &[FakeCargoApiRequest {
                method: "GET".to_owned(),
                path: "api/v1/crates".to_owned(),
                query: Some("q=serde&per_page=5".to_owned()),
                authorization: None,
                body: Vec::new(),
            }]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_registry_api_preserves_query_from_upstream_api_base() {
        let (triage_url, calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, upstream_paths, requests, upstream_handle) =
            spawn_fake_cargo_api_upstream_with_config(
                r#"{"dl":"api/v1/crates","api":"./?token=base-token"}"#,
            )
            .await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let config_response = reqwest::get(format!("{base_url}/proxy/cargo-public/config.json"))
            .await
            .expect("config request");
        let config_body: serde_json::Value = config_response.json().await.expect("config body");
        let api_base = config_body["api"].as_str().expect("api base");

        let response = reqwest::get(format!("{api_base}/api/v1/crates?q=serde&per_page=5"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("json body");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &["config.json".to_owned(), "api/v1/crates".to_owned()]
        );
        assert_eq!(
            requests.lock().expect("requests").as_slice(),
            &[FakeCargoApiRequest {
                method: "GET".to_owned(),
                path: "api/v1/crates".to_owned(),
                query: Some("token=base-token&q=serde&per_page=5".to_owned()),
                authorization: None,
                body: Vec::new(),
            }]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_registry_api_pathful_base_does_not_duplicate_api_prefix() {
        let (triage_url, calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, upstream_paths, requests, upstream_handle) =
            spawn_fake_cargo_api_upstream_with_config(r#"{"dl":"api/v1/crates","api":"/api/v1"}"#)
                .await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let config_response = reqwest::get(format!("{base_url}/proxy/cargo-public/config.json"))
            .await
            .expect("config request");
        let config_body: serde_json::Value = config_response.json().await.expect("config body");
        let api_base = config_body["api"].as_str().expect("api base");

        let response = reqwest::get(format!("{api_base}/api/v1/crates?q=serde&per_page=5"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("json body");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &["config.json".to_owned(), "api/v1/crates".to_owned()]
        );
        assert_eq!(
            requests.lock().expect("requests").as_slice(),
            &[FakeCargoApiRequest {
                method: "GET".to_owned(),
                path: "api/v1/crates".to_owned(),
                query: Some("q=serde&per_page=5".to_owned()),
                authorization: None,
                body: Vec::new(),
            }]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_registry_api_write_forwards_body_and_client_authorization() {
        let (triage_url, calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, _upstream_paths, requests, upstream_handle) =
            spawn_fake_cargo_api_upstream().await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let config_response = reqwest::get(format!("{base_url}/proxy/cargo-public/config.json"))
            .await
            .expect("config request");
        let config_body: serde_json::Value = config_response.json().await.expect("config body");
        let api_base = config_body["api"].as_str().expect("api base");

        let publish_body = b"publish-body".to_vec();
        let response = reqwest::Client::new()
            .put(format!("{api_base}/api/v1/crates/new"))
            .header(AUTHORIZATION, "Bearer cargo-client-token")
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(publish_body.clone())
            .send()
            .await
            .expect("proxy request");
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("json body");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            requests.lock().expect("requests").as_slice(),
            &[FakeCargoApiRequest {
                method: "PUT".to_owned(),
                path: "api/v1/crates/new".to_owned(),
                query: None,
                authorization: Some("Bearer cargo-client-token".to_owned()),
                body: publish_body,
            }]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_registry_api_out_of_scope_suffix_fails_closed() {
        let (triage_url, calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, upstream_paths, requests, upstream_handle) =
            spawn_fake_cargo_api_upstream().await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let config_response = reqwest::get(format!("{base_url}/proxy/cargo-public/config.json"))
            .await
            .expect("config request");
        let config_body: serde_json::Value = config_response.json().await.expect("config body");
        let api_base = config_body["api"].as_str().expect("api base");

        let response = reqwest::get(format!("{api_base}/internal/admin"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body = response.text().await.expect("body");

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &["config.json".to_owned()]
        );
        assert!(requests.lock().expect("requests").is_empty());

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_registry_config_not_found_preserves_upstream_status() {
        let (triage_url, calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, upstream_paths, upstream_handle) =
            spawn_fake_status_body_upstream(StatusCode::NOT_FOUND, "text/plain", "missing config")
                .await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/cargo-public/config.json"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body = response.text().await.expect("body");

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, "missing config");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &["config.json".to_owned()]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_registry_config_markerized_download_template_fails_closed() {
        let (triage_url, _calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, _upstream_paths, upstream_handle) = spawn_fake_body_upstream(
            "application/json",
            r#"{"dl":"https://registry.example.invalid/api/{crate}/{version}/download"}"#,
        )
        .await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/cargo-public/config.json"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("json body");

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["decision"], "QUARANTINE_PENDING_ANALYSIS");

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_sparse_proxy_forwards_metadata_requests() {
        let (triage_url, calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, upstream_paths, upstream_handle) = spawn_fake_cargo_upstream().await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/cargo-public/se/rd/serde"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body = response.text().await.expect("metadata body");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert!(body.contains("\"name\":\"serde\""));
        assert!(body.contains("\"vers\":\"1.0.0\""));
        assert!(body.contains("\"vers\":\"1.0.1\""));
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &["se/rd/serde".to_owned()]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_sparse_proxy_filters_blocked_candidates() {
        let (triage_url, calls, triage_handle) = spawn_fake_triage_with_artifact_version_decision(
            PolicyDecision::Allow,
            PolicyDecision::BlockKnownMalicious,
            "1.0.1",
            PolicyMode::Enforce,
        )
        .await;
        let (upstream_url, _upstream_paths, upstream_handle) = spawn_fake_cargo_upstream().await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/cargo-public/se/rd/serde"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body = response.text().await.expect("metadata body");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert!(body.contains("\"vers\":\"1.0.0\""));
        assert!(!body.contains("\"vers\":\"1.0.1\""));

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_sparse_proxy_filters_blocked_candidates_without_json_content_type() {
        let (triage_url, calls, triage_handle) = spawn_fake_triage_with_artifact_version_decision(
            PolicyDecision::Allow,
            PolicyDecision::BlockKnownMalicious,
            "1.0.1",
            PolicyMode::Enforce,
        )
        .await;
        let (upstream_url, _upstream_paths, upstream_handle) = spawn_fake_body_upstream(
            "text/plain",
            "{\"name\":\"serde\",\"vers\":\"1.0.0\",\"cksum\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}\n{\"name\":\"serde\",\"vers\":\"1.0.1\",\"cksum\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}",
        )
        .await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/cargo-public/se/rd/serde"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body = response.text().await.expect("metadata body");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert!(body.contains("\"vers\":\"1.0.0\""));
        assert!(!body.contains("\"vers\":\"1.0.1\""));

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_sparse_not_found_preserves_upstream_status() {
        let (triage_url, calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, _upstream_paths, upstream_handle) =
            spawn_fake_status_body_upstream(StatusCode::NOT_FOUND, "text/plain", "crate not found")
                .await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/cargo-public/se/rd/serde"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body = response.text().await.expect("text body");

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, "crate not found");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_sparse_invalid_metadata_fails_closed() {
        let (triage_url, _calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, _upstream_paths, upstream_handle) = spawn_fake_body_upstream(
            "application/vnd.rust.crate-index",
            "{\"name\":\"serde\",\"vers\":\"1.0.0\",\"cksum\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}\nnot-json",
        )
        .await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/cargo-public/se/rd/serde"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("json body");

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["decision"], "QUARANTINE_PENDING_ANALYSIS");

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_sparse_missing_version_field_fails_closed() {
        let (triage_url, _calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, _upstream_paths, upstream_handle) = spawn_fake_body_upstream(
            "application/vnd.rust.crate-index",
            "{\"name\":\"serde\",\"cksum\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        )
        .await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/cargo-public/se/rd/serde"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("json body");

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["decision"], "QUARANTINE_PENDING_ANALYSIS");

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_sparse_invalid_present_version_field_fails_closed() {
        let (triage_url, _calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, _upstream_paths, upstream_handle) = spawn_fake_body_upstream(
            "application/vnd.rust.crate-index",
            "{\"name\":\"serde\",\"vers\":\"01.2.3\",\"cksum\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        )
        .await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/cargo-public/se/rd/serde"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("json body");

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["decision"], "QUARANTINE_PENDING_ANALYSIS");

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_sparse_missing_name_field_fails_closed() {
        let (triage_url, _calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, _upstream_paths, upstream_handle) = spawn_fake_body_upstream(
            "application/vnd.rust.crate-index",
            "{\"vers\":\"1.0.0\",\"cksum\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        )
        .await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/cargo-public/se/rd/serde"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("json body");

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["decision"], "QUARANTINE_PENDING_ANALYSIS");

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_sparse_mismatched_name_field_fails_closed() {
        let (triage_url, _calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, _upstream_paths, upstream_handle) = spawn_fake_body_upstream(
            "application/vnd.rust.crate-index",
            "{\"name\":\"tokio\",\"vers\":\"1.0.0\",\"cksum\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        )
        .await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/cargo-public/se/rd/serde"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("json body");

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["decision"], "QUARANTINE_PENDING_ANALYSIS");

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_sparse_invalid_present_name_field_fails_closed() {
        let (triage_url, _calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, _upstream_paths, upstream_handle) = spawn_fake_body_upstream(
            "application/vnd.rust.crate-index",
            "{\"name\":\" SeRdE \",\"vers\":\"1.0.0\",\"cksum\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        )
        .await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/cargo-public/se/rd/serde"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("json body");

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["decision"], "QUARANTINE_PENDING_ANALYSIS");

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_sparse_mixed_case_name_field_is_allowed() {
        let (triage_url, _calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, _upstream_paths, upstream_handle) = spawn_fake_body_upstream(
            "application/vnd.rust.crate-index",
            "{\"name\":\"SeRdE\",\"vers\":\"1.0.0\",\"cksum\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        )
        .await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/cargo-public/se/rd/serde"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body = response.text().await.expect("body");

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"name\":\"SeRdE\""));

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_sparse_missing_checksum_field_fails_closed() {
        let (triage_url, _calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, _upstream_paths, upstream_handle) = spawn_fake_body_upstream(
            "application/vnd.rust.crate-index",
            "{\"name\":\"serde\",\"vers\":\"1.0.0\"}",
        )
        .await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/cargo-public/se/rd/serde"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("json body");

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["decision"], "QUARANTINE_PENDING_ANALYSIS");

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_sparse_invalid_checksum_field_fails_closed() {
        let (triage_url, _calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, _upstream_paths, upstream_handle) = spawn_fake_body_upstream(
            "application/vnd.rust.crate-index",
            "{\"name\":\"serde\",\"vers\":\"1.0.0\",\"cksum\":\"not-a-digest\"}",
        )
        .await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/cargo-public/se/rd/serde"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("json body");

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["decision"], "QUARANTINE_PENDING_ANALYSIS");

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_sparse_candidate_mode_mismatch_fails_closed() {
        let (triage_url, _calls, triage_handle) = spawn_fake_triage_with_artifact_version_mode(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            PolicyDecision::BlockKnownMalicious,
            "1.0.1",
            PolicyMode::Warn,
        )
        .await;
        let (upstream_url, _upstream_paths, upstream_handle) = spawn_fake_cargo_upstream().await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/cargo-public/se/rd/serde"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("json body");

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["decision"], "QUARANTINE_PENDING_ANALYSIS");

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_sparse_candidate_hard_error_fails_closed() {
        let (triage_url, _calls, triage_handle) = spawn_fake_triage_with_artifact_version_status(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            "1.0.1",
            StatusCode::BAD_REQUEST,
        )
        .await;
        let (upstream_url, _upstream_paths, upstream_handle) = spawn_fake_cargo_upstream().await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/cargo-public/se/rd/serde"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("json body");

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["decision"], "QUARANTINE_PENDING_ANALYSIS");

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_download_proxy_prefetches_and_forwards_crate_bytes() {
        let (triage_url, calls, requested_digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let (upstream_url, upstream_paths, upstream_handle) = spawn_fake_cargo_upstream().await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let config_response = reqwest::get(format!("{base_url}/proxy/cargo-public/config.json"))
            .await
            .expect("config request");
        let config_body: serde_json::Value = config_response.json().await.expect("config body");
        let download_base = config_body["dl"].as_str().expect("download base");
        let response = reqwest::get(format!("{download_base}/serde/1.0.0/download"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body = response.text().await.expect("artifact body");
        let artifact_path = "api/v1/crates/serde/1.0.0/download";

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, format!("crate bytes for {artifact_path}"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &[
                "config.json".to_owned(),
                "se/rd/serde".to_owned(),
                artifact_path.to_owned(),
            ]
        );
        assert_eq!(requested_digests.lock().expect("digests").len(), 1);
        assert!(requested_digests.lock().expect("digests")[0].is_some());

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_download_proxy_forwards_binary_crate_with_correct_digest() {
        let (triage_url, _calls, requested_digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let (upstream_url, _upstream_paths, expected_sha256_hex, upstream_handle) =
            spawn_fake_cargo_upstream_with_binary_crate().await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let config_response = reqwest::get(format!("{base_url}/proxy/cargo-public/config.json"))
            .await
            .expect("config request");
        let config_body: serde_json::Value = config_response.json().await.expect("config body");
        let download_base = config_body["dl"].as_str().expect("download base");
        let response = reqwest::get(format!("{download_base}/codeshot/2.0.0/download"))
            .await
            .expect("proxy request");

        assert_eq!(response.status(), StatusCode::OK);

        let digests = requested_digests.lock().expect("digests");
        assert_eq!(
            digests.len(),
            1,
            "expected exactly 1 triage call: {digests:?}"
        );
        assert_eq!(
            digests[0],
            Some(expected_sha256_hex),
            "digest sent to triage must match SHA-256 of the served binary crate bytes"
        );
        drop(digests);

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_download_proxy_fails_closed_on_sparse_checksum_mismatch() {
        let (triage_url, calls, _requested_digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let (upstream_url, upstream_paths, _expected_sha256_hex, upstream_handle) =
            spawn_fake_cargo_upstream_with_binary_crate_and_sparse_checksum(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            )
            .await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let config_response = reqwest::get(format!("{base_url}/proxy/cargo-public/config.json"))
            .await
            .expect("config request");
        let config_body: serde_json::Value = config_response.json().await.expect("config body");
        let download_base = config_body["dl"].as_str().expect("download base");
        let response = reqwest::get(format!("{download_base}/codeshot/2.0.0/download"))
            .await
            .expect("proxy request");

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &[
                "config.json".to_owned(),
                "co/de/codeshot".to_owned(),
                "api/v1/crates/codeshot/2.0.0/download".to_owned(),
            ]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_download_proxy_fails_closed_when_sparse_version_is_missing() {
        let (triage_url, calls, _requested_digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let (upstream_url, upstream_paths, _expected_sha256_hex, upstream_handle) =
            spawn_fake_cargo_upstream_with_binary_crate_and_sparse_metadata(
                "{\"name\":\"codeshot\",\"vers\":\"2.0.1\",\"cksum\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}".to_owned(),
            )
            .await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let config_response = reqwest::get(format!("{base_url}/proxy/cargo-public/config.json"))
            .await
            .expect("config request");
        let config_body: serde_json::Value = config_response.json().await.expect("config body");
        let download_base = config_body["dl"].as_str().expect("download base");
        let response = reqwest::get(format!("{download_base}/codeshot/2.0.0/download"))
            .await
            .expect("proxy request");

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &["config.json".to_owned(), "co/de/codeshot".to_owned()]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_download_route_remains_valid_after_restart_with_same_mac_key() {
        let (triage_url, calls, requested_digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let (upstream_url, upstream_paths, upstream_handle) = spawn_fake_cargo_upstream().await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let cargo_download_mac_key = TEST_CARGO_DOWNLOAD_MAC_KEY.to_vec();
        let artifact_path = "api/v1/crates/serde/1.0.0/download";

        let (first_base_url, first_mosquito_handle) = spawn_mosquito_with_cargo_download_mac_key(
            store.clone(),
            &triage_url,
            ProxyRateLimitConfig::default(),
            cargo_download_mac_key.clone(),
        )
        .await;
        let first_config_response =
            reqwest::get(format!("{first_base_url}/proxy/cargo-public/config.json"))
                .await
                .expect("first config request");
        let first_config_body: serde_json::Value = first_config_response
            .json()
            .await
            .expect("first config body");
        let first_download_base = first_config_body["dl"]
            .as_str()
            .expect("first download base");
        let first_download_url = url::Url::parse(first_download_base).expect("first download url");

        first_mosquito_handle.abort();

        let (second_base_url, second_mosquito_handle) = spawn_mosquito_with_cargo_download_mac_key(
            store,
            &triage_url,
            ProxyRateLimitConfig::default(),
            cargo_download_mac_key,
        )
        .await;
        let second_config_response =
            reqwest::get(format!("{second_base_url}/proxy/cargo-public/config.json"))
                .await
                .expect("second config request");
        let second_config_body: serde_json::Value = second_config_response
            .json()
            .await
            .expect("second config body");
        let second_download_base = second_config_body["dl"]
            .as_str()
            .expect("second download base");
        let second_download_url =
            url::Url::parse(second_download_base).expect("second download url");

        assert_eq!(first_download_url.path(), second_download_url.path());

        let response = reqwest::get(format!(
            "{second_base_url}{}/serde/1.0.0/download",
            first_download_url.path()
        ))
        .await
        .expect("download request after restart");
        let status = response.status();
        let body = response.text().await.expect("artifact body");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, format!("crate bytes for {artifact_path}"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &[
                "config.json".to_owned(),
                "config.json".to_owned(),
                "se/rd/serde".to_owned(),
                artifact_path.to_owned(),
            ]
        );
        assert_eq!(requested_digests.lock().expect("digests").len(), 1);
        assert!(requested_digests.lock().expect("digests")[0].is_some());

        second_mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_download_route_is_rejected_after_restart_with_different_mac_key() {
        let (triage_url, calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, upstream_paths, upstream_handle) = spawn_fake_cargo_upstream().await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");

        let (first_base_url, first_mosquito_handle) = spawn_mosquito_with_cargo_download_mac_key(
            store.clone(),
            &triage_url,
            ProxyRateLimitConfig::default(),
            TEST_CARGO_DOWNLOAD_MAC_KEY.to_vec(),
        )
        .await;
        let first_config_response =
            reqwest::get(format!("{first_base_url}/proxy/cargo-public/config.json"))
                .await
                .expect("first config request");
        let first_config_body: serde_json::Value = first_config_response
            .json()
            .await
            .expect("first config body");
        let first_download_base = first_config_body["dl"]
            .as_str()
            .expect("first download base");
        let first_download_url = url::Url::parse(first_download_base).expect("first download url");

        first_mosquito_handle.abort();

        let (second_base_url, second_mosquito_handle) = spawn_mosquito_with_cargo_download_mac_key(
            store,
            &triage_url,
            ProxyRateLimitConfig::default(),
            b"rotated-cargo-download-key".to_vec(),
        )
        .await;
        let second_config_response =
            reqwest::get(format!("{second_base_url}/proxy/cargo-public/config.json"))
                .await
                .expect("second config request");
        let second_config_body: serde_json::Value = second_config_response
            .json()
            .await
            .expect("second config body");
        let second_download_base = second_config_body["dl"]
            .as_str()
            .expect("second download base");
        let second_download_url =
            url::Url::parse(second_download_base).expect("second download url");

        assert_ne!(first_download_url.path(), second_download_url.path());

        let response = reqwest::get(format!(
            "{second_base_url}{}/serde/1.0.0/download",
            first_download_url.path()
        ))
        .await
        .expect("download request after key rotation");
        let status = response.status();
        let body = response.text().await.expect("body");

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &["config.json".to_owned(), "config.json".to_owned()]
        );

        second_mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_download_redirect_fails_closed() {
        let (triage_url, calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, upstream_paths, upstream_handle) =
            spawn_fake_cargo_redirect_upstream().await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let config_response = reqwest::get(format!("{base_url}/proxy/cargo-public/config.json"))
            .await
            .expect("config request");
        let config_body: serde_json::Value = config_response.json().await.expect("config body");
        let download_base = config_body["dl"].as_str().expect("download base");
        let response = reqwest::get(format!("{download_base}/serde/1.0.0/download"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body = response.text().await.expect("body");
        let artifact_path = "api/v1/crates/serde/1.0.0/download";

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &[
                "config.json".to_owned(),
                "se/rd/serde".to_owned(),
                artifact_path.to_owned(),
            ]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_download_redirect_to_allowlisted_origin_is_followed() {
        let download_body = "redirected crate bytes";
        let sparse_checksum = hex::encode(Sha256::digest(download_body.as_bytes()));
        let (download_origin, download_paths, download_handle) =
            spawn_fake_body_upstream("application/octet-stream", download_body).await;
        let redirect_location = format!("{download_origin}/crates/serde/1.0.0/download");
        let (triage_url, calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, upstream_paths, upstream_handle) =
            spawn_fake_cargo_configurable_upstream(
                r#"{"dl":"api/v1/crates","api":"/api/v1"}"#.to_owned(),
                format!(r#"{{"name":"serde","vers":"1.0.0","cksum":"{sparse_checksum}"}}"#),
                Some(redirect_location),
            )
            .await;
        let mut config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        config.cargo_allowed_download_origins = vec![download_origin.clone()];
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let config_response = reqwest::get(format!("{base_url}/proxy/cargo-public/config.json"))
            .await
            .expect("config request");
        let config_body: serde_json::Value = config_response.json().await.expect("config body");
        let download_base = config_body["dl"].as_str().expect("download base");
        let response = reqwest::get(format!("{download_base}/serde/1.0.0/download"))
            .await
            .expect("download request");
        let status = response.status();
        let body = response.text().await.expect("artifact body");
        let artifact_path = "api/v1/crates/serde/1.0.0/download";

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, download_body);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &[
                "config.json".to_owned(),
                "se/rd/serde".to_owned(),
                artifact_path.to_owned(),
            ]
        );
        assert_eq!(
            download_paths.lock().expect("paths").as_slice(),
            &["crates/serde/1.0.0/download".to_owned()]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
        download_handle.abort();
    }

    #[tokio::test]
    async fn cargo_download_not_found_preserves_upstream_status() {
        let (triage_url, calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, upstream_paths, upstream_handle) =
            spawn_fake_cargo_download_status_upstream(StatusCode::NOT_FOUND, "missing crate").await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let config_response = reqwest::get(format!("{base_url}/proxy/cargo-public/config.json"))
            .await
            .expect("config request");
        let config_body: serde_json::Value = config_response.json().await.expect("config body");
        let download_base = config_body["dl"].as_str().expect("download base");
        let response = reqwest::get(format!("{download_base}/serde/1.0.0/download"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body = response.text().await.expect("body");
        let artifact_path = "api/v1/crates/serde/1.0.0/download";

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, "missing crate");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &[
                "config.json".to_owned(),
                "se/rd/serde".to_owned(),
                artifact_path.to_owned(),
            ]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_download_server_error_preserves_upstream_status() {
        let (triage_url, calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, upstream_paths, upstream_handle) =
            spawn_fake_cargo_download_status_upstream(
                StatusCode::BAD_GATEWAY,
                "upstream download failed",
            )
            .await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let config_response = reqwest::get(format!("{base_url}/proxy/cargo-public/config.json"))
            .await
            .expect("config request");
        let config_body: serde_json::Value = config_response.json().await.expect("config body");
        let download_base = config_body["dl"].as_str().expect("download base");
        let response = reqwest::get(format!("{download_base}/serde/1.0.0/download"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body = response.text().await.expect("body");
        let artifact_path = "api/v1/crates/serde/1.0.0/download";

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body, "upstream download failed");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &[
                "config.json".to_owned(),
                "se/rd/serde".to_owned(),
                artifact_path.to_owned(),
            ]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_download_proxy_path_with_cross_origin_encoded_base_fails_closed() {
        let (triage_url, calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, upstream_paths, upstream_handle) = spawn_fake_cargo_upstream().await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let encoded = BASE64_URL_SAFE_NO_PAD.encode(b"https://evil.example.invalid/dl");
        let signature = "forged";
        let artifact_path =
            format!("{CARGO_DL_PROXY_PREFIX}/{encoded}/{signature}/serde/1.0.0/download");
        let response = reqwest::get(format!("{base_url}/proxy/cargo-public/{artifact_path}"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body = response.text().await.expect("body");

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(upstream_paths.lock().expect("paths").is_empty());

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_download_proxy_path_with_same_origin_forged_base_fails_closed() {
        let (triage_url, calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, upstream_paths, upstream_handle) = spawn_fake_cargo_upstream().await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let forged_base = format!("{upstream_url}/private/crates");
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(forged_base.as_bytes());
        let artifact_path =
            format!("{CARGO_DL_PROXY_PREFIX}/{encoded}/forged/serde/1.0.0/download");
        let response = reqwest::get(format!("{base_url}/proxy/cargo-public/{artifact_path}"))
            .await
            .expect("proxy request");
        let status = response.status();
        let body = response.text().await.expect("body");

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(upstream_paths.lock().expect("paths").is_empty());

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn cargo_api_proxy_path_with_same_origin_forged_base_fails_closed() {
        let (triage_url, calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::Allow, PolicyMode::Enforce, None).await;
        let (upstream_url, upstream_paths, _requests, upstream_handle) =
            spawn_fake_cargo_api_upstream().await;
        let config = config_with_adapter_upstream(
            "/proxy/cargo-public",
            PolicyMode::Enforce,
            RegistryAdapter::Cargo,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let forged_base = format!("{upstream_url}/private/api");
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(forged_base.as_bytes());
        let response = reqwest::Client::new()
            .put(format!(
                "{base_url}/proxy/cargo-public/{CARGO_API_PROXY_PREFIX}/{encoded}/forged/api/v1/crates/new"
            ))
            .body("publish-body")
            .send()
            .await
            .expect("proxy request");
        let status = response.status();
        let body = response.text().await.expect("body");

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(upstream_paths.lock().expect("paths").is_empty());

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[test]
    fn cargo_api_request_headers_only_forward_allowlisted_values() {
        let mut source = HeaderMap::new();
        source.insert(ACCEPT, HeaderValue::from_static("application/json"));
        source.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer cargo-client-token"),
        );
        source.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        source.insert(USER_AGENT, HeaderValue::from_static("cargo/1.89.0"));
        source.insert(
            HeaderName::from_static("cargo-protocol"),
            HeaderValue::from_static("version=1"),
        );
        source.insert(
            HeaderName::from_static("cookie"),
            HeaderValue::from_static("secret"),
        );
        source.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("127.0.0.1"),
        );

        let mut forwarded = HeaderMap::new();
        copy_cargo_api_request_headers(&source, &mut forwarded);

        assert_eq!(forwarded.len(), 5);
        assert_eq!(
            forwarded.get(ACCEPT),
            Some(&HeaderValue::from_static("application/json"))
        );
        assert_eq!(
            forwarded.get(AUTHORIZATION),
            Some(&HeaderValue::from_static("Bearer cargo-client-token"))
        );
        assert_eq!(
            forwarded.get(CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/octet-stream"))
        );
        assert_eq!(
            forwarded.get(USER_AGENT),
            Some(&HeaderValue::from_static("cargo/1.89.0"))
        );
        assert_eq!(
            forwarded.get(HeaderName::from_static("cargo-protocol")),
            Some(&HeaderValue::from_static("version=1"))
        );
        assert!(!forwarded.contains_key("cookie"));
        assert!(!forwarded.contains_key("x-forwarded-for"));
    }

    #[test]
    fn pypi_simple_html_links_rewrite_under_mount() {
        let rewritten = rewrite_pypi_simple_links(
            "/proxy/pypi-public",
            "http://mosquito.local",
            br#"<a href="/packages/ab/pkg-1.0.0.tar.gz#sha256=abc">pkg</a>"#.to_vec(),
        );

        assert_eq!(
            String::from_utf8(rewritten).expect("utf8"),
            r#"<a href="http://mosquito.local/proxy/pypi-public/packages/ab/pkg-1.0.0.tar.gz#sha256=abc">pkg</a>"#
        );
    }

    #[test]
    fn audit_event_helpers_produce_safe_request_metadata() {
        let resolved = ResolvedRegistryConfig {
            config: config("/proxy/npm-public", PolicyMode::Warn),
            upstream_path: "left-pad".to_owned(),
        };
        let inbound = inbound_request_audit_event(&resolved, "trace-audit");
        let completed = final_request_audit_event(
            &resolved,
            "trace-audit",
            StatusCode::OK,
            "triage-decision-applied",
            Some(PolicyDecision::Allow),
            false,
        );

        assert!(validate_audit_metadata(&inbound.metadata).is_ok());
        assert!(validate_audit_metadata(&completed.metadata).is_ok());
        assert_eq!(inbound.action, "proxy.request.received");
        assert_eq!(completed.action, "proxy.request.completed");
        assert_eq!(completed.metadata.get("decision"), Some(&json!("ALLOW")));
    }

    #[tokio::test]
    async fn generic_http_proxy_allows_artifact_capture() {
        let (triage_url, calls, requested_digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let (upstream_url, upstream_paths, upstream_handle) =
            spawn_fake_body_upstream("application/octet-stream", "binary artifact bytes").await;
        let config = config_with_adapter_upstream(
            "/proxy/generic-artifacts",
            PolicyMode::Enforce,
            RegistryAdapter::GenericHttp,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!(
            "{base_url}/proxy/generic-artifacts/some/artifact.tar.gz"
        ))
        .await
        .expect("proxy request");
        let status = response.status();
        let body = response.text().await.expect("artifact body");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "binary artifact bytes");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &["some/artifact.tar.gz".to_owned()]
        );
        // digest should be captured and sent to triage
        assert_eq!(requested_digests.lock().expect("digests").len(), 1);
        assert!(requested_digests.lock().expect("digests")[0].is_some());

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn generic_http_proxy_get_forwards_cache_validators() {
        let (triage_url, _calls, _requested_digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let upstream_paths = Arc::new(Mutex::new(Vec::new()));
        let recorded_paths = Arc::clone(&upstream_paths);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_addr = listener.local_addr().expect("upstream addr");
        let upstream_router = Router::new().route(
            "/{*path}",
            get(move |Path(path): Path<String>| {
                let recorded_paths = Arc::clone(&recorded_paths);
                async move {
                    recorded_paths.lock().expect("paths").push(path);
                    (
                        StatusCode::OK,
                        [
                            (CONTENT_TYPE, "application/octet-stream"),
                            (CACHE_CONTROL, "public, max-age=60"),
                            (ETAG, "\"artifact-etag\""),
                            (LAST_MODIFIED, "Wed, 21 Oct 2015 07:28:00 GMT"),
                        ],
                        "binary artifact bytes",
                    )
                }
            }),
        );
        let upstream_handle = tokio::spawn(async move {
            axum::serve(listener, upstream_router)
                .await
                .expect("upstream serve");
        });
        let upstream_url = format!("http://{upstream_addr}");

        let config = config_with_adapter_upstream(
            "/proxy/generic-artifacts",
            PolicyMode::Enforce,
            RegistryAdapter::GenericHttp,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!(
            "{base_url}/proxy/generic-artifacts/cacheable.tar.gz"
        ))
        .await
        .expect("proxy request");
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.text().await.expect("artifact body");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "binary artifact bytes");
        assert_eq!(
            headers
                .get(CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("public, max-age=60")
        );
        assert_eq!(
            headers.get(ETAG).and_then(|value| value.to_str().ok()),
            Some("\"artifact-etag\"")
        );
        assert_eq!(
            headers
                .get(LAST_MODIFIED)
                .and_then(|value| value.to_str().ok()),
            Some("Wed, 21 Oct 2015 07:28:00 GMT")
        );
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &["cacheable.tar.gz".to_owned()]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn generic_http_proxy_get_distinguishes_query_selected_artifacts() {
        let (triage_url, calls, requested_digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let upstream_requests = Arc::new(Mutex::new(Vec::new()));
        let recorded_requests = Arc::clone(&upstream_requests);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_addr = listener.local_addr().expect("upstream addr");
        let upstream_router = Router::new().route(
            "/{*path}",
            get(move |uri: Uri, Path(path): Path<String>| {
                let recorded_requests = Arc::clone(&recorded_requests);
                async move {
                    let query = uri.query().map(str::to_owned);
                    recorded_requests
                        .lock()
                        .expect("requests")
                        .push((path.clone(), query.clone()));
                    let body = match query.as_deref() {
                        Some("sig=one") => "artifact-one",
                        Some("sig=two") => "artifact-two",
                        _ => "artifact-default",
                    };
                    (
                        StatusCode::OK,
                        [(CONTENT_TYPE, "application/octet-stream")],
                        body,
                    )
                }
            }),
        );
        let upstream_handle = tokio::spawn(async move {
            axum::serve(listener, upstream_router)
                .await
                .expect("upstream serve");
        });
        let upstream_url = format!("http://{upstream_addr}");

        let config = config_with_adapter_upstream(
            "/proxy/generic-artifacts",
            PolicyMode::Enforce,
            RegistryAdapter::GenericHttp,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let first = reqwest::get(format!(
            "{base_url}/proxy/generic-artifacts/package.tar.gz?sig=one"
        ))
        .await
        .expect("first proxy request");
        assert_eq!(first.status(), StatusCode::OK);
        let first_body = first.text().await.expect("first body");

        let second = reqwest::get(format!(
            "{base_url}/proxy/generic-artifacts/package.tar.gz?sig=two"
        ))
        .await
        .expect("second proxy request");
        assert_eq!(second.status(), StatusCode::OK);
        let second_body = second.text().await.expect("second body");

        assert_eq!(first_body, "artifact-one");
        assert_eq!(second_body, "artifact-two");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let requested_digests = requested_digests.lock().expect("requested digests");
        assert_eq!(requested_digests.len(), 2);
        assert_ne!(requested_digests[0], requested_digests[1]);
        drop(requested_digests);
        assert_eq!(
            upstream_requests.lock().expect("requests").as_slice(),
            &[
                ("package.tar.gz".to_owned(), Some("sig=one".to_owned())),
                ("package.tar.gz".to_owned(), Some("sig=two".to_owned())),
            ]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn generic_http_proxy_blocks_artifact_in_enforce_mode() {
        let (triage_url, _calls, _requested_digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::BlockKnownMalicious,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let (upstream_url, _upstream_paths, upstream_handle) =
            spawn_fake_body_upstream("application/octet-stream", "blocked bytes").await;
        let config = config_with_adapter_upstream(
            "/proxy/generic-artifacts",
            PolicyMode::Enforce,
            RegistryAdapter::GenericHttp,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!(
            "{base_url}/proxy/generic-artifacts/malicious.tar.gz"
        ))
        .await
        .expect("proxy request");
        let status = response.status();
        let body: serde_json::Value = response.json().await.expect("json body");

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["decision"], "BLOCK_KNOWN_MALICIOUS");

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn generic_http_proxy_head_probe_returns_status_and_headers_without_body() {
        let (triage_url, _calls, _requested_digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let (upstream_url, upstream_paths, upstream_handle) =
            spawn_fake_body_upstream("application/octet-stream", "should not appear").await;
        let config = config_with_adapter_upstream(
            "/proxy/generic-artifacts",
            PolicyMode::Enforce,
            RegistryAdapter::GenericHttp,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client");
        let response = client
            .head(format!(
                "{base_url}/proxy/generic-artifacts/probe/artifact.tar.gz"
            ))
            .send()
            .await
            .expect("head request");
        let status = response.status();
        let body = response.bytes().await.expect("head body");

        assert_eq!(status, StatusCode::OK);
        assert!(body.is_empty(), "HEAD response must have no body");
        // triage should NOT be called for HEAD probes
        assert_eq!(_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &["probe/artifact.tar.gz".to_owned()]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn generic_http_proxy_head_probe_forwards_upstream_not_found() {
        let (triage_url, _calls, _requested_digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let (upstream_url, _upstream_paths, upstream_handle) =
            spawn_fake_status_body_upstream(StatusCode::NOT_FOUND, "application/octet-stream", "")
                .await;
        let config = config_with_adapter_upstream(
            "/proxy/generic-artifacts",
            PolicyMode::Enforce,
            RegistryAdapter::GenericHttp,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let client = reqwest::Client::new();
        let response = client
            .head(format!("{base_url}/proxy/generic-artifacts/missing.tar.gz"))
            .send()
            .await
            .expect("head request");
        let status = response.status();
        let body = response.bytes().await.expect("head body");

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_empty(), "HEAD response must have no body");
        assert_eq!(_calls.load(Ordering::SeqCst), 0);

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn generic_http_proxy_head_probe_rewrites_redirect_location() {
        let (triage_url, calls, _requested_digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_addr = listener.local_addr().expect("upstream addr");
        let upstream_router = Router::new().route(
            "/{*path}",
            get(
                |_method: Method, _uri: Uri, Path(_path): Path<String>| async move {
                    (
                        StatusCode::FOUND,
                        [(LOCATION, "/next/location.crate")],
                        "redirect body",
                    )
                },
            )
            .head(
                |_method: Method, _uri: Uri, Path(_path): Path<String>| async move {
                    (
                        StatusCode::FOUND,
                        [(LOCATION, "/next/location.crate")],
                        "redirect body",
                    )
                },
            ),
        );
        let upstream_handle = tokio::spawn(async move {
            axum::serve(listener, upstream_router)
                .await
                .expect("upstream serve");
        });
        let upstream_url = format!("http://{upstream_addr}");

        let config = config_with_adapter_upstream(
            "/proxy/generic-artifacts",
            PolicyMode::Enforce,
            RegistryAdapter::GenericHttp,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client");
        let response = client
            .head(format!(
                "{base_url}/proxy/generic-artifacts/probe/artifact.tar.gz"
            ))
            .send()
            .await
            .expect("head request");

        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let expected_location = format!("{base_url}/proxy/generic-artifacts/next/location.crate");
        assert_eq!(
            response
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some(expected_location.as_str())
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn generic_http_proxy_head_probe_respects_rate_limits() {
        let (triage_url, calls, _requested_digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let (upstream_url, upstream_paths, upstream_handle) =
            spawn_fake_body_upstream("application/octet-stream", "head probe body").await;
        let config = config_with_adapter_upstream(
            "/proxy/generic-artifacts",
            PolicyMode::Enforce,
            RegistryAdapter::GenericHttp,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let rate_limits = ProxyRateLimitConfig {
            tenant_api: rate_limit::RateLimitConfig::new(Duration::from_secs(60), 1),
            client_package: rate_limit::RateLimitConfig::new(Duration::from_secs(60), 10),
        };
        let (base_url, mosquito_handle) = spawn_mosquito(store, &triage_url, rate_limits).await;

        let client = reqwest::Client::new();
        let first = client
            .head(format!(
                "{base_url}/proxy/generic-artifacts/probe/artifact.tar.gz"
            ))
            .send()
            .await
            .expect("first head request");
        assert_eq!(first.status(), StatusCode::OK);

        let second = client
            .head(format!(
                "{base_url}/proxy/generic-artifacts/probe/artifact.tar.gz"
            ))
            .send()
            .await
            .expect("second head request");
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        let headers = second.headers().clone();
        let body = second.bytes().await.expect("rate-limit body");
        assert!(body.is_empty(), "HEAD response must have no body");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            headers
                .get(RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("60")
        );
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &["probe/artifact.tar.gz".to_owned()]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn generic_http_proxy_head_probe_preserves_query_string() {
        let (triage_url, calls, _requested_digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let upstream_requests = Arc::new(Mutex::new(Vec::new()));
        let get_requests = Arc::clone(&upstream_requests);
        let head_requests = Arc::clone(&upstream_requests);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_addr = listener.local_addr().expect("upstream addr");
        let upstream_router = Router::new().route(
            "/{*path}",
            get(move |method: Method, uri: Uri, Path(path): Path<String>| {
                let recorded_requests = Arc::clone(&get_requests);
                async move {
                    recorded_requests.lock().expect("requests").push((
                        method.as_str().to_owned(),
                        path,
                        uri.query().map(str::to_owned),
                    ));
                    (
                        StatusCode::OK,
                        [(CONTENT_TYPE, "application/octet-stream")],
                        "head",
                    )
                }
            })
            .head(move |method: Method, uri: Uri, Path(path): Path<String>| {
                let recorded_requests = Arc::clone(&head_requests);
                async move {
                    recorded_requests.lock().expect("requests").push((
                        method.as_str().to_owned(),
                        path,
                        uri.query().map(str::to_owned),
                    ));
                    (
                        StatusCode::OK,
                        [(CONTENT_TYPE, "application/octet-stream")],
                        "head",
                    )
                }
            }),
        );
        let upstream_handle = tokio::spawn(async move {
            axum::serve(listener, upstream_router)
                .await
                .expect("upstream serve");
        });
        let upstream_url = format!("http://{upstream_addr}");

        let config = config_with_adapter_upstream(
            "/proxy/generic-artifacts",
            PolicyMode::Enforce,
            RegistryAdapter::GenericHttp,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let client = reqwest::Client::new();
        let response = client
            .head(format!(
                "{base_url}/proxy/generic-artifacts/probe/artifact.tar.gz?sig=head"
            ))
            .send()
            .await
            .expect("head request");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            upstream_requests.lock().expect("requests").as_slice(),
            &[(
                "HEAD".to_owned(),
                "probe/artifact.tar.gz".to_owned(),
                Some("sig=head".to_owned()),
            )]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn generic_http_proxy_head_on_non_generic_adapter_returns_not_implemented() {
        let (triage_url, _calls, _requested_digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let store =
            RegistryConfigStore::new(vec![config("/proxy/npm-public", PolicyMode::Enforce)])
                .expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let client = reqwest::Client::new();
        let response = client
            .head(format!("{base_url}/proxy/npm-public/some-package"))
            .send()
            .await
            .expect("head request");

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);

        mosquito_handle.abort();
        triage_handle.abort();
    }

    #[tokio::test]
    async fn generic_http_proxy_sensitive_headers_are_redacted_in_storage() {
        let (triage_url, _calls, _requested_digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        // Use a custom upstream that returns a set-cookie header
        let upstream_state = FakeBodyUpstreamState {
            paths: Arc::new(Mutex::new(Vec::new())),
            status: StatusCode::OK,
            content_type: "application/octet-stream",
            body: "artifact bytes",
        };
        let upstream_paths = Arc::clone(&upstream_state.paths);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_addr = listener.local_addr().expect("upstream addr");
        let upstream_router = Router::new()
            .route(
                "/{*path}",
                get(
                    |AxumState(state): AxumState<FakeBodyUpstreamState>,
                     Path(path): Path<String>| async move {
                        state.paths.lock().expect("paths").push(path);
                        (
                            StatusCode::OK,
                            [
                                (CONTENT_TYPE, "application/octet-stream"),
                                (
                                    axum::http::header::SET_COOKIE,
                                    "session=secret123; HttpOnly",
                                ),
                            ],
                            "artifact bytes",
                        )
                            .into_response()
                    },
                ),
            )
            .with_state(upstream_state);
        let upstream_handle = tokio::spawn(async move {
            axum::serve(listener, upstream_router)
                .await
                .expect("upstream serve");
        });
        let upstream_url = format!("http://{upstream_addr}");

        let config = config_with_adapter_upstream(
            "/proxy/generic-artifacts",
            PolicyMode::Enforce,
            RegistryAdapter::GenericHttp,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/generic-artifacts/secure.tar.gz"))
            .await
            .expect("proxy request");
        let status = response.status();
        // The set-cookie header should NOT be forwarded to the client
        assert_eq!(status, StatusCode::OK);
        assert!(
            !response.headers().contains_key("set-cookie"),
            "set-cookie must not be forwarded to proxy client"
        );
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &["secure.tar.gz".to_owned()]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[test]
    #[ignore = "requires live local postgres, npm-fixture-registry, triage-counter, mosquito-net, and npm"]
    fn npm_install_works_against_live_local_proxy() {
        let repo_root = repo_root();
        recreate_live_local_proxy_stack(&repo_root);
        let (project_dir, cache_dir) = create_temp_npm_dirs("aegiscudo-live-npm-allow");

        let npm_init = Command::new("npm")
            .args(["init", "-y"])
            .current_dir(&project_dir)
            .output()
            .expect("run npm init");
        assert_command_success("npm", &["init", "-y"], &npm_init);

        let npm_install = Command::new("npm")
            .args([
                "install",
                "aegiscudo-benign-npm-fixture@1.0.0",
                "--registry",
                "http://127.0.0.1:18000/proxy/npm-fixtures/",
                "--cache",
                cache_dir.to_str().expect("cache dir utf8"),
                "--no-audit",
                "--no-fund",
            ])
            .current_dir(&project_dir)
            .output()
            .expect("run npm install");
        assert_command_success(
            "npm",
            &[
                "install",
                "aegiscudo-benign-npm-fixture@1.0.0",
                "--registry",
                "http://127.0.0.1:18000/proxy/npm-fixtures/",
                "--cache",
                cache_dir.to_str().expect("cache dir utf8"),
                "--no-audit",
                "--no-fund",
            ],
            &npm_install,
        );

        let installed_package = fs::read_to_string(
            project_dir.join("node_modules/aegiscudo-benign-npm-fixture/package.json"),
        )
        .expect("read installed package.json");
        let installed_package: serde_json::Value =
            serde_json::from_str(&installed_package).expect("installed package json");

        assert_eq!(installed_package["name"], "aegiscudo-benign-npm-fixture");
        assert_eq!(installed_package["version"], "1.0.0");

        let _ = fs::remove_dir_all(&project_dir);
        let _ = fs::remove_dir_all(&cache_dir);
    }

    #[test]
    #[ignore = "requires live local postgres, npm-fixture-registry, triage-counter, mosquito-net, and npm"]
    fn npm_latest_metadata_falls_back_to_prior_allowed_version_against_live_local_proxy() {
        let repo_root = repo_root();
        recreate_live_local_proxy_stack(&repo_root);

        let (seed_status, seed_body) = fetch_bytes(
            "http://127.0.0.1:18000/proxy/npm-fixtures/aegiscudo-benign-npm-fixture/-/aegiscudo-benign-npm-fixture-1.0.0.tgz",
        );
        assert_eq!(seed_status, StatusCode::OK);
        assert!(!seed_body.is_empty());

        let packument =
            fetch_json("http://127.0.0.1:18000/proxy/npm-fixtures/aegiscudo-benign-npm-fixture");
        assert_eq!(packument["dist-tags"]["latest"], "1.0.0");
        assert_eq!(
            packument["versions"]
                .as_object()
                .map(|versions| versions.len()),
            Some(1)
        );
        assert!(packument["versions"].get("1.2.0").is_none());

        let (project_dir, cache_dir) = create_temp_npm_dirs("aegiscudo-live-npm-fallback");
        let npm_init = Command::new("npm")
            .args(["init", "-y"])
            .current_dir(&project_dir)
            .output()
            .expect("run npm init for fallback project");
        assert_command_success("npm", &["init", "-y"], &npm_init);

        let npm_install = Command::new("npm")
            .args([
                "install",
                "aegiscudo-benign-npm-fixture",
                "--registry",
                "http://127.0.0.1:18000/proxy/npm-fixtures/",
                "--cache",
                cache_dir.to_str().expect("cache dir utf8"),
                "--no-audit",
                "--no-fund",
            ])
            .current_dir(&project_dir)
            .output()
            .expect("run fallback npm install");
        assert_command_success(
            "npm",
            &[
                "install",
                "aegiscudo-benign-npm-fixture",
                "--registry",
                "http://127.0.0.1:18000/proxy/npm-fixtures/",
                "--cache",
                cache_dir.to_str().expect("cache dir utf8"),
                "--no-audit",
                "--no-fund",
            ],
            &npm_install,
        );

        let installed_package = fs::read_to_string(
            project_dir.join("node_modules/aegiscudo-benign-npm-fixture/package.json"),
        )
        .expect("read installed fallback package.json");
        let installed_package: serde_json::Value =
            serde_json::from_str(&installed_package).expect("installed fallback package json");

        assert_eq!(installed_package["version"], "1.0.0");

        let _ = fs::remove_dir_all(&project_dir);
        let _ = fs::remove_dir_all(&cache_dir);
    }

    #[test]
    #[ignore = "requires live local postgres, npm-fixture-registry, triage-counter, mosquito-net, and npm"]
    fn npm_ci_lockfile_install_does_not_fallback_against_live_local_proxy() {
        let repo_root = repo_root();
        recreate_live_local_proxy_stack(&repo_root);

        let (seed_status, seed_body) = fetch_bytes(
            "http://127.0.0.1:18000/proxy/npm-fixtures/aegiscudo-benign-npm-fixture/-/aegiscudo-benign-npm-fixture-1.0.0.tgz",
        );
        assert_eq!(seed_status, StatusCode::OK);
        assert!(!seed_body.is_empty());

        let (project_dir, cache_dir) = create_temp_npm_dirs("aegiscudo-live-npm-lockfile");
        let npm_init = Command::new("npm")
            .args(["init", "-y"])
            .current_dir(&project_dir)
            .output()
            .expect("run npm init for lockfile project");
        assert_command_success("npm", &["init", "-y"], &npm_init);

        let package_lock_only = Command::new("npm")
            .args([
                "install",
                "aegiscudo-benign-npm-fixture@1.2.0",
                "--package-lock-only",
                "--ignore-scripts",
                "--registry",
                "http://127.0.0.1:18080/",
                "--cache",
                cache_dir.to_str().expect("cache dir utf8"),
                "--no-audit",
                "--no-fund",
            ])
            .current_dir(&project_dir)
            .output()
            .expect("generate npm lockfile");
        assert_command_success(
            "npm",
            &[
                "install",
                "aegiscudo-benign-npm-fixture@1.2.0",
                "--package-lock-only",
                "--ignore-scripts",
                "--registry",
                "http://127.0.0.1:18080/",
                "--cache",
                cache_dir.to_str().expect("cache dir utf8"),
                "--no-audit",
                "--no-fund",
            ],
            &package_lock_only,
        );

        let package_lock = fs::read_to_string(project_dir.join("package-lock.json"))
            .expect("read package-lock.json");
        let package_lock: serde_json::Value =
            serde_json::from_str(&package_lock).expect("parse package-lock.json");
        let locked_dependency =
            &package_lock["packages"]["node_modules/aegiscudo-benign-npm-fixture"];
        assert_eq!(locked_dependency["version"], "1.2.0");
        assert!(
            locked_dependency["integrity"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );

        let npm_ci = Command::new("npm")
            .args([
                "ci",
                "--ignore-scripts",
                "--registry",
                "http://127.0.0.1:18000/proxy/npm-fixtures/",
                "--cache",
                cache_dir.to_str().expect("cache dir utf8"),
                "--no-audit",
                "--no-fund",
            ])
            .current_dir(&project_dir)
            .output()
            .expect("run npm ci");
        assert_command_success(
            "npm",
            &[
                "ci",
                "--ignore-scripts",
                "--registry",
                "http://127.0.0.1:18000/proxy/npm-fixtures/",
                "--cache",
                cache_dir.to_str().expect("cache dir utf8"),
                "--no-audit",
                "--no-fund",
            ],
            &npm_ci,
        );

        let installed_package = fs::read_to_string(
            project_dir.join("node_modules/aegiscudo-benign-npm-fixture/package.json"),
        )
        .expect("read installed lockfile package.json");
        let installed_package: serde_json::Value =
            serde_json::from_str(&installed_package).expect("installed lockfile package json");

        assert_eq!(installed_package["version"], "1.2.0");

        let _ = fs::remove_dir_all(&project_dir);
        let _ = fs::remove_dir_all(&cache_dir);
    }

    #[test]
    #[ignore = "requires live local postgres, pypi-fixture-registry, triage-counter, mosquito-net, python3, and pip"]
    fn pypi_simple_index_filters_blocked_candidate_and_still_installs_against_live_local_proxy() {
        let repo_root = repo_root();
        recreate_live_local_proxy_stack(&repo_root);

        let (index_status, index_body) = fetch_bytes(
            "http://127.0.0.1:18000/proxy/pypi-fixtures/simple/aegiscudo-benign-pypi-fixture/",
        );
        assert_eq!(index_status, StatusCode::OK);
        let index_body = String::from_utf8(index_body).expect("simple index utf8");
        assert!(index_body.contains("aegiscudo_benign_pypi_fixture-1.0.0-py3-none-any.whl"));
        assert!(!index_body.contains("aegiscudo_benign_pypi_fixture-1.1.0-py3-none-any.whl"));

        let (project_dir, cache_dir) = create_temp_python_dirs("aegiscudo-live-pypi-filter");
        let venv_create = Command::new("python3")
            .args(["-m", "venv", ".venv"])
            .current_dir(&project_dir)
            .output()
            .expect("create python venv");
        assert_command_success("python3", &["-m", "venv", ".venv"], &venv_create);

        let venv_python = project_dir.join(".venv/bin/python");
        let pip_install = Command::new(&venv_python)
            .args([
                "-m",
                "pip",
                "install",
                "--no-deps",
                "--index-url",
                "http://127.0.0.1:18000/proxy/pypi-fixtures/simple",
                "--trusted-host",
                "127.0.0.1",
                "--cache-dir",
                cache_dir.to_str().expect("cache dir utf8"),
                "--disable-pip-version-check",
                "aegiscudo-benign-pypi-fixture",
            ])
            .current_dir(&project_dir)
            .output()
            .expect("run pip install through proxy");
        assert!(
            pip_install.status.success(),
            "python -m pip install --no-deps --index-url http://127.0.0.1:18000/proxy/pypi-fixtures/simple --trusted-host 127.0.0.1 --cache-dir {} --disable-pip-version-check aegiscudo-benign-pypi-fixture failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
            cache_dir.to_str().expect("cache dir utf8"),
            pip_install.status.code(),
            String::from_utf8_lossy(&pip_install.stdout),
            String::from_utf8_lossy(&pip_install.stderr),
        );

        let installed_version = Command::new(&venv_python)
            .args([
                "-c",
                "import importlib.metadata as metadata; print(metadata.version('aegiscudo-benign-pypi-fixture'))",
            ])
            .current_dir(&project_dir)
            .output()
            .expect("read installed PyPI package version");
        assert_command_success(
            ".venv/bin/python",
            &[
                "-c",
                "import importlib.metadata as metadata; print(metadata.version('aegiscudo-benign-pypi-fixture'))",
            ],
            &installed_version,
        );
        assert_eq!(
            String::from_utf8_lossy(&installed_version.stdout).trim(),
            "1.0.0"
        );

        let _ = fs::remove_dir_all(&project_dir);
        let _ = fs::remove_dir_all(&cache_dir);
    }

    #[test]
    #[ignore = "requires live local postgres, cargo-fixture-registry, triage-counter, mosquito-net, and cargo"]
    fn cargo_search_hits_live_local_proxy_api() {
        let repo_root = repo_root();
        recreate_live_local_proxy_stack(&repo_root);
        let (project_dir, cargo_home) = create_temp_cargo_dirs("aegiscudo-live-cargo-search");

        fs::create_dir_all(project_dir.join(".cargo")).expect("create cargo config dir");
        fs::write(
            project_dir.join(".cargo/config.toml"),
            r#"[registries.aegiscudo-fixtures]
index = "sparse+http://127.0.0.1:18000/proxy/cargo-fixtures/"
"#,
        )
        .expect("write cargo config");

        let cargo_search = Command::new("cargo")
            .args([
                "search",
                "aegiscudo-benign-cargo-fixture",
                "--registry",
                "aegiscudo-fixtures",
                "--limit",
                "1",
            ])
            .env("CARGO_HOME", &cargo_home)
            .current_dir(&project_dir)
            .output()
            .expect("run cargo search");
        assert_command_success(
            "cargo",
            &[
                "search",
                "aegiscudo-benign-cargo-fixture",
                "--registry",
                "aegiscudo-fixtures",
                "--limit",
                "1",
            ],
            &cargo_search,
        );

        let stdout = String::from_utf8_lossy(&cargo_search.stdout);
        assert!(stdout.contains("aegiscudo-benign-cargo-fixture = \"1.0.0\""));

        let _ = fs::remove_dir_all(&project_dir);
        let _ = fs::remove_dir_all(&cargo_home);
    }

    #[test]
    #[ignore = "requires live local postgres, cargo-fixture-registry, triage-counter, mosquito-net, and cargo"]
    fn cargo_fetch_downloads_allowed_fixture_against_live_local_proxy() {
        let repo_root = repo_root();
        recreate_live_local_proxy_stack(&repo_root);
        let (project_dir, cargo_home) = create_temp_cargo_dirs("aegiscudo-live-cargo-fetch");

        fs::create_dir_all(project_dir.join(".cargo")).expect("create cargo config dir");
        fs::create_dir_all(project_dir.join("src")).expect("create cargo src dir");
        fs::write(
            project_dir.join(".cargo/config.toml"),
            r#"[registries.aegiscudo-fixtures]
index = "sparse+http://127.0.0.1:18000/proxy/cargo-fixtures/"
"#,
        )
        .expect("write cargo config");
        fs::write(
            project_dir.join("Cargo.toml"),
            r#"[package]
name = "live-cargo-fixture-consumer"
version = "0.1.0"
edition = "2021"

[dependencies]
aegiscudo-benign-cargo-fixture = { version = "1.0.0", registry = "aegiscudo-fixtures" }
"#,
        )
        .expect("write Cargo.toml");
        fs::write(project_dir.join("src/main.rs"), "fn main() {}\n").expect("write src/main.rs");

        let manifest_path = project_dir.join("Cargo.toml");
        let manifest_path = manifest_path
            .to_str()
            .expect("manifest path utf8")
            .to_owned();
        let cargo_fetch_args = vec![
            "fetch".to_owned(),
            "--manifest-path".to_owned(),
            manifest_path.clone(),
        ];
        let cargo_fetch = Command::new("cargo")
            .args(&cargo_fetch_args)
            .env("CARGO_HOME", &cargo_home)
            .current_dir(&project_dir)
            .output()
            .expect("run cargo fetch");
        assert!(
            cargo_fetch.status.success(),
            "cargo {} failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
            cargo_fetch_args.join(" "),
            cargo_fetch.status.code(),
            String::from_utf8_lossy(&cargo_fetch.stdout),
            String::from_utf8_lossy(&cargo_fetch.stderr),
        );

        let cargo_lock =
            fs::read_to_string(project_dir.join("Cargo.lock")).expect("read Cargo.lock");
        assert!(cargo_lock.contains("name = \"aegiscudo-benign-cargo-fixture\""));
        assert!(cargo_lock.contains("version = \"1.0.0\""));
        assert!(cargo_cache_contains_crate(
            &cargo_home,
            "aegiscudo-benign-cargo-fixture",
            "1.0.0"
        ));

        let _ = fs::remove_dir_all(&project_dir);
        let _ = fs::remove_dir_all(&cargo_home);
    }

    #[test]
    #[ignore = "requires live local postgres, maven-fixture-registry, triage-counter, and mosquito-net"]
    fn maven_fetch_downloads_allowed_fixture_against_live_local_proxy() {
        let repo_root = repo_root();
        recreate_live_local_proxy_stack(&repo_root);

        let jar_url = "http://127.0.0.1:18000/proxy/maven-fixtures/com/aegiscudo/fixtures/aegiscudo-benign-maven-fixture/1.0.0/aegiscudo-benign-maven-fixture-1.0.0.jar";
        let (jar_status, jar_body) = fetch_bytes(jar_url);

        assert_eq!(jar_status, StatusCode::OK);
        assert_eq!(jar_body, b"aegiscudo benign maven fixture jar bytes");
    }

    #[test]
    #[ignore = "requires live local postgres, maven-fixture-registry, triage-counter, and mosquito-net"]
    fn maven_metadata_passthrough_against_live_local_proxy() {
        let repo_root = repo_root();
        recreate_live_local_proxy_stack(&repo_root);

        let pom_url = "http://127.0.0.1:18000/proxy/maven-fixtures/com/aegiscudo/fixtures/aegiscudo-benign-maven-fixture/1.0.0/aegiscudo-benign-maven-fixture-1.0.0.pom";
        let (pom_status, pom_body) = fetch_bytes(pom_url);
        assert_eq!(pom_status, StatusCode::OK);
        let pom_body = String::from_utf8(pom_body).expect("maven fixture pom utf8");
        assert!(pom_body.contains("<artifactId>aegiscudo-benign-maven-fixture</artifactId>"));
        assert!(pom_body.contains("<groupId>com.aegiscudo.fixtures</groupId>"));

        let metadata_url = "http://127.0.0.1:18000/proxy/maven-fixtures/com/aegiscudo/fixtures/aegiscudo-benign-maven-fixture/maven-metadata.xml";
        let (metadata_status, metadata_body) = fetch_bytes(metadata_url);
        assert_eq!(metadata_status, StatusCode::OK);
        let metadata_body = String::from_utf8(metadata_body).expect("maven metadata utf8");
        assert!(metadata_body.contains("<latest>1.0.0</latest>"));
        assert!(metadata_body.contains("<release>1.0.0</release>"));

        let metadata_checksum_url = "http://127.0.0.1:18000/proxy/maven-fixtures/com/aegiscudo/fixtures/aegiscudo-benign-maven-fixture/maven-metadata.xml.sha1";
        let (metadata_checksum_status, metadata_checksum_body) = fetch_bytes(metadata_checksum_url);
        assert_eq!(metadata_checksum_status, StatusCode::OK);
        let metadata_checksum_body =
            String::from_utf8(metadata_checksum_body).expect("maven metadata checksum utf8");
        assert_eq!(
            metadata_checksum_body.trim(),
            "cad000fc0169276e723a8eb6cbcbe977834a34bc"
        );

        let checksum_url = "http://127.0.0.1:18000/proxy/maven-fixtures/com/aegiscudo/fixtures/aegiscudo-benign-maven-fixture/1.0.0/aegiscudo-benign-maven-fixture-1.0.0.jar.sha1";
        let (checksum_status, checksum_body) = fetch_bytes(checksum_url);
        assert_eq!(checksum_status, StatusCode::OK);
        let checksum_body = String::from_utf8(checksum_body).expect("maven checksum utf8");
        assert_eq!(
            checksum_body.trim(),
            "06cf236ade9a0d5c99758694040ec6b2d1264ba8"
        );
    }

    #[test]
    #[ignore = "requires live local postgres, maven-fixture-registry, triage-counter, mosquito-net, and mvn"]
    fn maven_dependency_get_downloads_allowed_fixture_against_live_local_proxy() {
        let repo_root = repo_root();
        recreate_live_local_proxy_stack(&repo_root);
        let (work_dir, maven_repo) = create_temp_maven_dirs("aegiscudo-live-maven-get");

        let repo_arg = format!("-Dmaven.repo.local={}", maven_repo.display());
        let artifact_arg = "-Dartifact=com.aegiscudo.fixtures:aegiscudo-benign-maven-fixture:1.0.0";
        let remote_repos_arg =
            "-DremoteRepositories=fixture::default::http://127.0.0.1:18000/proxy/maven-fixtures";
        let maven_args = vec![
            "-q",
            repo_arg.as_str(),
            "dependency:get",
            "-Dtransitive=false",
            remote_repos_arg,
            artifact_arg,
        ];
        let maven_get = Command::new("mvn")
            .args(&maven_args)
            .current_dir(&work_dir)
            .output()
            .expect("run mvn dependency:get");
        assert_command_success("mvn", &maven_args, &maven_get);

        let jar_path = maven_repo.join(
            "com/aegiscudo/fixtures/aegiscudo-benign-maven-fixture/1.0.0/aegiscudo-benign-maven-fixture-1.0.0.jar",
        );
        assert!(
            jar_path.is_file(),
            "downloaded jar missing at {}",
            jar_path.display()
        );
        assert_eq!(
            fs::read(&jar_path).expect("read downloaded Maven fixture jar"),
            b"aegiscudo benign maven fixture jar bytes"
        );

        let _ = fs::remove_dir_all(&work_dir);
        let _ = fs::remove_dir_all(&maven_repo);
    }

    #[test]
    #[ignore = "requires live local postgres, npm-fixture-registry, triage-counter, and mosquito-net"]
    fn unknown_npm_artifact_request_creates_analysis_job_against_live_local_proxy() {
        let repo_root = repo_root();
        recreate_live_local_proxy_stack(&repo_root);

        let package_name = format!("aegiscudo-unknown-npm-fixture-{}", Uuid::now_v7().simple());
        let package_version = "0.0.1";
        assert_eq!(live_analysis_job_count(&package_name, package_version), 0);

        let tarball_url = format!(
            "http://127.0.0.1:18000/proxy/npm-fixtures/{package_name}/-/{package_name}-{package_version}.tgz"
        );
        let (tarball_status, tarball_body) = fetch_bytes(&tarball_url);
        assert_eq!(tarball_status, StatusCode::FORBIDDEN);

        let tarball_body: serde_json::Value =
            serde_json::from_slice(&tarball_body).expect("unknown artifact response json");
        assert_eq!(tarball_body["decision"], "QUARANTINE_PENDING_ANALYSIS");
        assert_eq!(live_analysis_job_count(&package_name, package_version), 1);
    }

    #[test]
    #[ignore = "requires live local postgres, npm-fixture-registry, triage-counter, and mosquito-net"]
    fn approved_override_expiry_resumes_policy_enforcement_against_live_local_proxy() {
        let repo_root = repo_root();
        recreate_live_local_proxy_stack(&repo_root);

        let override_id = insert_live_override(
            json!({
                "ecosystem": "npm",
                "name": "fresh-postinstall",
                "version": "0.1.0",
                "kind": "artifact",
                "effect": "allow"
            }),
            chrono::Utc::now() + chrono::Duration::hours(1),
        );

        let tarball_url = "http://127.0.0.1:18000/proxy/npm-fixtures/fresh-postinstall/-/fresh-postinstall-0.1.0.tgz";
        let (allowed_status, _allowed_body) = fetch_bytes(tarball_url);
        assert_eq!(allowed_status, StatusCode::OK);

        update_live_override_expiry(
            override_id,
            chrono::Utc::now() - chrono::Duration::minutes(1),
        );
        recreate_live_local_proxy_stack(&repo_root);

        let (blocked_status, blocked_body) = fetch_bytes(tarball_url);
        assert_eq!(blocked_status, StatusCode::FORBIDDEN);
        let blocked_body: serde_json::Value =
            serde_json::from_slice(&blocked_body).expect("expired override response json");
        assert_eq!(blocked_body["decision"], "BLOCK_POLICY_VIOLATION");

        delete_live_override(override_id);
    }

    #[test]
    #[ignore = "requires live local postgres, npm-fixture-registry, triage-counter, mosquito-net, and npm"]
    fn policy_blocked_npm_install_fails_against_live_local_proxy() {
        let repo_root = repo_root();
        recreate_live_local_proxy_stack(&repo_root);
        let (project_dir, cache_dir) = create_temp_npm_dirs("aegiscudo-live-npm-quarantine");

        let npm_init = Command::new("npm")
            .args(["init", "-y"])
            .current_dir(&project_dir)
            .output()
            .expect("run npm init");
        assert_command_success("npm", &["init", "-y"], &npm_init);

        let npm_install = Command::new("npm")
            .args([
                "install",
                "fresh-postinstall@0.1.0",
                "--registry",
                "http://127.0.0.1:18000/proxy/npm-fixtures/",
                "--cache",
                cache_dir.to_str().expect("cache dir utf8"),
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
            ])
            .current_dir(&project_dir)
            .output()
            .expect("run policy-blocked npm install");
        assert!(
            !npm_install.status.success(),
            "expected npm install to fail for policy-blocked package\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&npm_install.stdout),
            String::from_utf8_lossy(&npm_install.stderr),
        );

        let (tarball_status, tarball_body): (StatusCode, serde_json::Value) =
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build tokio runtime")
                .block_on(async {
                    let tarball_response = reqwest::get(
                        "http://127.0.0.1:18000/proxy/npm-fixtures/fresh-postinstall/-/fresh-postinstall-0.1.0.tgz",
                    )
                    .await
                    .expect("request policy-blocked tarball");
                    let tarball_status = tarball_response.status();
                    let tarball_body = tarball_response
                        .json()
                        .await
                        .expect("policy-blocked tarball json body");
                    (tarball_status, tarball_body)
                });
        assert_eq!(tarball_status, StatusCode::FORBIDDEN);
        assert_eq!(tarball_body["decision"], "BLOCK_POLICY_VIOLATION");
        assert!(!project_dir.join("node_modules/fresh-postinstall").exists());

        let _ = fs::remove_dir_all(&project_dir);
        let _ = fs::remove_dir_all(&cache_dir);
    }

    #[tokio::test]
    async fn maven_proxy_allows_jar_artifact() {
        let (triage_url, calls, requested_digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let (upstream_url, upstream_paths, upstream_handle) =
            spawn_fake_body_upstream("application/java-archive", "cafe-babe").await;
        let config = config_with_adapter_upstream(
            "/proxy/maven-central",
            PolicyMode::Enforce,
            RegistryAdapter::Maven,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!(
            "{base_url}/proxy/maven-central/com/example/foo/foo/1.0/foo-1.0.jar"
        ))
        .await
        .expect("proxy request");
        let status = response.status();
        let advisory_header = response.headers().contains_key(ADVISORY_HEADER);
        let body = response.bytes().await.expect("artifact body");

        assert_eq!(status, StatusCode::OK);
        assert!(advisory_header);
        assert_eq!(body.as_ref(), b"cafe-babe");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            upstream_paths.lock().expect("paths")[0],
            "com/example/foo/foo/1.0/foo-1.0.jar"
        );
        assert_eq!(requested_digests.lock().expect("digests").len(), 1);

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn maven_proxy_blocks_jar_in_enforce_mode() {
        let (triage_url, _calls, _requested_digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::BlockPolicyViolation,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let (upstream_url, _upstream_paths, upstream_handle) =
            spawn_fake_body_upstream("application/java-archive", "should not be returned").await;
        let config = config_with_adapter_upstream(
            "/proxy/maven-central",
            PolicyMode::Enforce,
            RegistryAdapter::Maven,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!(
            "{base_url}/proxy/maven-central/com/example/foo/foo/1.0/foo-1.0.jar"
        ))
        .await
        .expect("proxy request");
        let status = response.status();
        let advisory_present = response.headers().contains_key(ADVISORY_HEADER);
        let body: serde_json::Value = response.json().await.expect("json body");

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(advisory_present);
        assert_eq!(body["decision"], "BLOCK_POLICY_VIOLATION");

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn maven_proxy_forwards_pom_metadata_without_artifact_hold() {
        let (triage_url, calls, _requested_digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let (upstream_url, upstream_paths, upstream_handle) =
            spawn_fake_body_upstream("application/xml", "<project/>").await;
        let config = config_with_adapter_upstream(
            "/proxy/maven-central",
            PolicyMode::Enforce,
            RegistryAdapter::Maven,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!(
            "{base_url}/proxy/maven-central/com/example/foo/foo/1.0/foo-1.0.pom"
        ))
        .await
        .expect("proxy request");
        let status = response.status();
        let body = response.text().await.expect("pom body");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<project/>");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &["com/example/foo/foo/1.0/foo-1.0.pom".to_owned()]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn maven_proxy_forwards_maven_metadata_xml() {
        let (triage_url, calls, _requested_digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let (upstream_url, upstream_paths, upstream_handle) =
            spawn_fake_body_upstream("application/xml", "<metadata/>").await;
        let config = config_with_adapter_upstream(
            "/proxy/maven-central",
            PolicyMode::Enforce,
            RegistryAdapter::Maven,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!(
            "{base_url}/proxy/maven-central/com/example/foo/foo/maven-metadata.xml"
        ))
        .await
        .expect("proxy request");
        let status = response.status();
        let body = response.text().await.expect("metadata body");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<metadata/>");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &["com/example/foo/foo/maven-metadata.xml".to_owned()]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[test]
    fn maven_request_context_extracts_artifact_metadata_coordinate_for_multi_segment_group() {
        let (kind, coordinate, explicit_version_or_integrity) = maven_request_context(
            "com/aegiscudo/fixtures/aegiscudo-benign-maven-fixture/maven-metadata.xml",
        )
        .expect("artifact metadata request context");

        assert_eq!(kind, PackageRequestKind::Metadata);
        assert_eq!(
            coordinate,
            PackageCoordinate::new(
                PackageEcosystem::Maven,
                "aegiscudo-benign-maven-fixture",
                None::<String>,
                Some("com.aegiscudo.fixtures"),
            )
        );
        assert!(!explicit_version_or_integrity);
    }

    #[test]
    fn maven_request_context_extracts_artifact_metadata_checksum_coordinate_for_multi_segment_group()
     {
        let (kind, coordinate, explicit_version_or_integrity) = maven_request_context(
            "com/aegiscudo/fixtures/aegiscudo-benign-maven-fixture/maven-metadata.xml.sha1",
        )
        .expect("artifact metadata checksum request context");

        assert_eq!(kind, PackageRequestKind::Metadata);
        assert_eq!(
            coordinate,
            PackageCoordinate::new(
                PackageEcosystem::Maven,
                "aegiscudo-benign-maven-fixture",
                None::<String>,
                Some("com.aegiscudo.fixtures"),
            )
        );
        assert!(!explicit_version_or_integrity);
    }

    #[test]
    fn maven_request_context_extracts_snapshot_metadata_coordinate() {
        let (kind, coordinate, explicit_version_or_integrity) =
            maven_request_context("com/example/foo/foo/1.0-SNAPSHOT/maven-metadata.xml")
                .expect("snapshot metadata request context");

        assert_eq!(kind, PackageRequestKind::Metadata);
        assert_eq!(
            coordinate,
            PackageCoordinate::new(
                PackageEcosystem::Maven,
                "foo",
                Some("1.0-SNAPSHOT"),
                Some("com.example.foo"),
            )
        );
        assert!(explicit_version_or_integrity);
    }

    #[tokio::test]
    async fn maven_proxy_checksum_file_is_metadata() {
        let (triage_url, calls, requested_digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let (upstream_url, upstream_paths, upstream_handle) =
            spawn_fake_body_upstream("text/plain", "abc123").await;
        let config = config_with_adapter_upstream(
            "/proxy/maven-central",
            PolicyMode::Enforce,
            RegistryAdapter::Maven,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!(
            "{base_url}/proxy/maven-central/com/example/foo/foo/1.0/foo-1.0.jar.sha1"
        ))
        .await
        .expect("proxy request");
        let status = response.status();
        let body = response.text().await.expect("checksum body");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "abc123");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            requested_digests.lock().expect("digests").as_slice(),
            &[None]
        );
        assert_eq!(
            upstream_paths.lock().expect("paths").as_slice(),
            &["com/example/foo/foo/1.0/foo-1.0.jar.sha1".to_owned()]
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn maven_proxy_short_path_fails_closed() {
        let (triage_url, _calls, _requested_digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let (upstream_url, _upstream_paths, upstream_handle) =
            spawn_fake_body_upstream("application/octet-stream", "irrelevant").await;
        let config = config_with_adapter_upstream(
            "/proxy/maven-central",
            PolicyMode::Enforce,
            RegistryAdapter::Maven,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!("{base_url}/proxy/maven-central/com/foo"))
            .await
            .expect("proxy request");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn maven_proxy_aar_and_war_artifacts_route_through_triage() {
        for ext in &["aar", "war", "ear"] {
            let (triage_url, calls, _requested_digests, triage_handle) =
                spawn_fake_triage_response(
                    PolicyDecision::Allow,
                    PolicyMode::Enforce,
                    None,
                    None,
                    false,
                )
                .await;
            let (upstream_url, upstream_paths, upstream_handle) =
                spawn_fake_body_upstream("application/octet-stream", "artifact-bytes").await;
            let config = config_with_adapter_upstream(
                "/proxy/maven-central",
                PolicyMode::Enforce,
                RegistryAdapter::Maven,
                &upstream_url,
            );
            let store = RegistryConfigStore::new(vec![config]).expect("store");
            let (base_url, mosquito_handle) =
                spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

            let response = reqwest::get(format!(
                "{base_url}/proxy/maven-central/com/example/foo/foo/1.0/foo-1.0.{ext}"
            ))
            .await
            .expect("proxy request");
            let status = response.status();
            let _ = response.bytes().await;

            assert_eq!(status, StatusCode::OK, "ext={ext}");
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "ext={ext} must call triage"
            );
            assert_eq!(
                upstream_paths.lock().expect("paths")[0],
                format!("com/example/foo/foo/1.0/foo-1.0.{ext}"),
                "ext={ext}"
            );

            mosquito_handle.abort();
            triage_handle.abort();
            upstream_handle.abort();
        }
    }

    #[tokio::test]
    async fn maven_proxy_checksum_variants_are_metadata() {
        for suffix in &["sha256", "sha512", "asc"] {
            let (triage_url, calls, requested_digests, triage_handle) = spawn_fake_triage_response(
                PolicyDecision::Allow,
                PolicyMode::Enforce,
                None,
                None,
                false,
            )
            .await;
            let (upstream_url, upstream_paths, upstream_handle) =
                spawn_fake_body_upstream("text/plain", "checksum-value").await;
            let config = config_with_adapter_upstream(
                "/proxy/maven-central",
                PolicyMode::Enforce,
                RegistryAdapter::Maven,
                &upstream_url,
            );
            let store = RegistryConfigStore::new(vec![config]).expect("store");
            let (base_url, mosquito_handle) =
                spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

            let response = reqwest::get(format!(
                "{base_url}/proxy/maven-central/com/example/foo/foo/1.0/foo-1.0.jar.{suffix}"
            ))
            .await
            .expect("proxy request");
            let status = response.status();
            let body = response.text().await.expect("body");

            assert_eq!(status, StatusCode::OK, "suffix={suffix}");
            assert_eq!(body, "checksum-value", "suffix={suffix}");
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "checksum suffix={suffix} must still call triage for metadata"
            );
            assert_eq!(
                requested_digests.lock().expect("digests").as_slice(),
                &[None],
                "suffix={suffix}"
            );
            assert_eq!(
                upstream_paths.lock().expect("paths").as_slice(),
                &[format!("com/example/foo/foo/1.0/foo-1.0.jar.{suffix}")],
                "suffix={suffix}"
            );

            mosquito_handle.abort();
            triage_handle.abort();
            upstream_handle.abort();
        }
    }

    #[tokio::test]
    async fn maven_proxy_snapshot_jar_routes_through_triage() {
        let (triage_url, calls, requested_digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let (upstream_url, upstream_paths, upstream_handle) =
            spawn_fake_body_upstream("application/java-archive", "snapshot-bytes").await;
        let config = config_with_adapter_upstream(
            "/proxy/maven-central",
            PolicyMode::Enforce,
            RegistryAdapter::Maven,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!(
            "{base_url}/proxy/maven-central/com/example/foo/foo/1.0-SNAPSHOT/foo-1.0-SNAPSHOT.jar"
        ))
        .await
        .expect("proxy request");
        let status = response.status();
        let _ = response.bytes().await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "SNAPSHOT jar must call triage"
        );
        assert_eq!(
            upstream_paths.lock().expect("paths")[0],
            "com/example/foo/foo/1.0-SNAPSHOT/foo-1.0-SNAPSHOT.jar"
        );
        assert_eq!(requested_digests.lock().expect("digests").len(), 1);

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    // ── Maven checksum verification helpers ──────────────────────────────────

    #[derive(Debug, Clone)]
    struct FakeMavenUpstreamState {
        paths: Arc<Mutex<Vec<String>>>,
        responses: Arc<std::collections::HashMap<String, Vec<u8>>>,
    }

    async fn fake_maven_upstream_handler(
        AxumState(state): AxumState<FakeMavenUpstreamState>,
        Path(path): Path<String>,
    ) -> Response {
        state.paths.lock().expect("record paths").push(path.clone());
        match state.responses.get(&path) {
            Some(body) => (
                StatusCode::OK,
                [(CONTENT_TYPE, "application/octet-stream")],
                body.clone(),
            )
                .into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        }
    }

    async fn spawn_fake_maven_upstream(
        responses: std::collections::HashMap<String, Vec<u8>>,
    ) -> (String, Arc<Mutex<Vec<String>>>, JoinHandle<()>) {
        let paths = Arc::new(Mutex::new(Vec::new()));
        let state = FakeMavenUpstreamState {
            paths: Arc::clone(&paths),
            responses: Arc::new(responses),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake maven upstream");
        let address = listener.local_addr().expect("fake maven upstream address");
        let router = Router::new()
            .route("/{*path}", get(fake_maven_upstream_handler))
            .with_state(state);
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("fake maven upstream serve");
        });
        (format!("http://{address}"), paths, handle)
    }

    // ── Maven checksum verification tests ────────────────────────────────────

    #[tokio::test]
    async fn maven_jar_sha1_checksum_match_is_allowed() {
        let jar_bytes = b"fake-jar-bytes-for-checksum-test";
        let sha1 = maven_sha1_hex(jar_bytes);
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "com/example/foo/foo/1.0/foo-1.0.jar".to_owned(),
            jar_bytes.to_vec(),
        );
        responses.insert(
            "com/example/foo/foo/1.0/foo-1.0.jar.sha1".to_owned(),
            sha1.as_bytes().to_vec(),
        );

        let (triage_url, calls, _digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let (upstream_url, upstream_paths, upstream_handle) =
            spawn_fake_maven_upstream(responses).await;
        let config = config_with_adapter_upstream(
            "/proxy/maven-test",
            PolicyMode::Enforce,
            RegistryAdapter::Maven,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!(
            "{base_url}/proxy/maven-test/com/example/foo/foo/1.0/foo-1.0.jar"
        ))
        .await
        .expect("proxy request");
        let status = response.status();
        let body = response.bytes().await.expect("body");

        assert_eq!(status, StatusCode::OK, "matching sha1 must be allowed");
        assert_eq!(body.as_ref(), jar_bytes.as_slice());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "triage called once for jar"
        );
        let paths = upstream_paths.lock().expect("paths").clone();
        assert!(
            paths.contains(&"com/example/foo/foo/1.0/foo-1.0.jar".to_owned()),
            "jar fetched"
        );
        assert!(
            paths.contains(&"com/example/foo/foo/1.0/foo-1.0.jar.sha1".to_owned()),
            "sha1 sidecar fetched"
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn maven_jar_sha1_checksum_mismatch_fails_closed() {
        let jar_bytes = b"fake-jar-bytes-for-checksum-test";
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "com/example/foo/foo/1.0/foo-1.0.jar".to_owned(),
            jar_bytes.to_vec(),
        );
        // Intentionally wrong SHA-1 value
        responses.insert(
            "com/example/foo/foo/1.0/foo-1.0.jar.sha1".to_owned(),
            b"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_vec(),
        );

        let (triage_url, _calls, _digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let (upstream_url, _upstream_paths, upstream_handle) =
            spawn_fake_maven_upstream(responses).await;
        let config = config_with_adapter_upstream(
            "/proxy/maven-test",
            PolicyMode::Enforce,
            RegistryAdapter::Maven,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!(
            "{base_url}/proxy/maven-test/com/example/foo/foo/1.0/foo-1.0.jar"
        ))
        .await
        .expect("proxy request");

        assert_eq!(
            response.status(),
            StatusCode::BAD_GATEWAY,
            "sha1 checksum mismatch must fail closed"
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }

    #[tokio::test]
    async fn maven_jar_no_sidecar_passes_through() {
        let jar_bytes = b"fake-jar-bytes-no-sidecar";
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "com/example/foo/foo/1.0/foo-1.0.jar".to_owned(),
            jar_bytes.to_vec(),
        );
        // Neither .sha256 nor .sha1 sidecar present → both return 404

        let (triage_url, _calls, _digests, triage_handle) = spawn_fake_triage_response(
            PolicyDecision::Allow,
            PolicyMode::Enforce,
            None,
            None,
            false,
        )
        .await;
        let (upstream_url, upstream_paths, upstream_handle) =
            spawn_fake_maven_upstream(responses).await;
        let config = config_with_adapter_upstream(
            "/proxy/maven-test",
            PolicyMode::Enforce,
            RegistryAdapter::Maven,
            &upstream_url,
        );
        let store = RegistryConfigStore::new(vec![config]).expect("store");
        let (base_url, mosquito_handle) =
            spawn_mosquito(store, &triage_url, ProxyRateLimitConfig::default()).await;

        let response = reqwest::get(format!(
            "{base_url}/proxy/maven-test/com/example/foo/foo/1.0/foo-1.0.jar"
        ))
        .await
        .expect("proxy request");
        let status = response.status();
        let body = response.bytes().await.expect("body");

        assert_eq!(
            status,
            StatusCode::OK,
            "absent sidecar must pass through without verification"
        );
        assert_eq!(body.as_ref(), jar_bytes.as_slice());
        let paths = upstream_paths.lock().expect("paths").clone();
        assert!(
            paths.contains(&"com/example/foo/foo/1.0/foo-1.0.jar".to_owned()),
            "jar must be fetched"
        );

        mosquito_handle.abort();
        triage_handle.abort();
        upstream_handle.abort();
    }
}
