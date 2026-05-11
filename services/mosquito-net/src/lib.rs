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
    body::Body,
    extract::{ConnectInfo, Path, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{
            CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ETAG, HOST, HeaderName, LOCATION,
            RETRY_AFTER,
        },
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use metrics::ProxyMetrics;
use rate_limit::{ProxyRateLimitConfig, ProxyRateLimiters, RateLimitRejection};
use registry_config::{
    CredentialAuthType, PostgresRegistryConfigRepository, RegistryAdapter, RegistryConfigStore,
    ResolvedRegistryConfig,
};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use triage_client::{TriageClient, TriageClientError};
use uuid::Uuid;

pub const SERVICE_NAME: &str = "mosquito-net";
const ADVISORY_HEADER: &str = "x-aegiscudo-advisory";
const TRACE_HEADER: &str = "x-aegiscudo-trace-id";
const DEFAULT_MAX_ARTIFACT_BYTES: u64 = 100 * 1024 * 1024;

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
    upstream_client: reqwest::Client,
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
        Self {
            registry_configs,
            registry_repository,
            triage_client,
            upstream_client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(30))
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

fn cache_key_for_upstream(resolved: &ResolvedRegistryConfig) -> String {
    format!("{}:{}", resolved.config.id, resolved.upstream_path)
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
    app_with_runtime_dependencies(registry_configs, triage_client, rate_limit_config, None)
}

pub fn app_with_runtime_dependencies(
    registry_configs: RegistryConfigStore,
    triage_client: TriageClient,
    rate_limit_config: ProxyRateLimitConfig,
    audit_repository: Option<PostgresAuditEventRepository>,
) -> Router {
    app_with_runtime_dependencies_and_reload(
        registry_configs,
        None,
        triage_client,
        rate_limit_config,
        audit_repository,
        DEFAULT_MAX_ARTIFACT_BYTES,
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
    let state = Arc::new(AppState::new(
        registry_configs,
        registry_repository,
        triage_client,
        rate_limit_config,
        audit_repository,
        max_artifact_bytes,
    ));
    Router::new()
        .route("/healthz", get(|| async { Json(health(SERVICE_NAME)) }))
        .route("/readyz", get(|| async { Json(health(SERVICE_NAME)) }))
        .route("/metrics", get(metrics))
        .route(
            "/admin/registry-configs/reload",
            post(reload_registry_configs),
        )
        .route("/proxy/{*proxy_path}", get(proxy_get))
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
            "client-rate-limit-exceeded",
            "client package request rate limit exceeded",
            rejection,
        )
        .await;
    }
    if !resolved.config.adapter.is_mvp_supported() {
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
    let mut decision_request = match decision_request_for_adapter(
        resolved.config.tenant_id,
        resolved.config.id,
        resolved.config.policy_profile_id,
        resolved.config.adapter,
        trace_id.clone(),
        upstream_request_url(&resolved.config.upstream_url, &resolved.upstream_path)
            .ok()
            .map(|url| url.to_string()),
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
            match fetch_upstream_artifact(state.as_ref(), &resolved).await {
                Ok(prefetched) => {
                    decision_request.request.requested_digest = Some(prefetched.digest.clone());
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
            proxy_base_url(&headers),
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
                proxy_base_url(&headers),
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

async fn rate_limited_response(
    state: &AppState,
    resolved: &ResolvedRegistryConfig,
    trace_id: &str,
    request_started: Instant,
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

struct PrefetchedArtifact {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
    digest: ArtifactDigest,
}

async fn fetch_upstream_artifact(
    state: &AppState,
    resolved: &ResolvedRegistryConfig,
) -> Result<PrefetchedArtifact, UpstreamProxyError> {
    let cache_key = cache_key_for_upstream(resolved);
    if let Some(digest_hex) = state
        .caches
        .artifact_digest_by_path
        .read()
        .await
        .get(&cache_key)
        .cloned()
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
            digest: ArtifactDigest::sha256(digest_hex).map_err(UpstreamProxyError::Digest)?,
        });
    }
    state.metrics.observe_cache(
        resolved.config.tenant_id,
        resolved.config.id,
        resolved.config.adapter,
        "artifact",
        "miss",
    );
    let upstream_url =
        upstream_request_url(&resolved.config.upstream_url, &resolved.upstream_path)?;
    let upstream_started = Instant::now();
    let mut request_builder = state.upstream_client.get(upstream_url);
    request_builder = inject_upstream_credentials(request_builder, resolved)?;
    let upstream_response = request_builder
        .send()
        .await
        .map_err(UpstreamProxyError::Request)?;
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
    let digest = sha256_digest(&body).map_err(UpstreamProxyError::Digest)?;
    cache_artifact_response(
        state,
        resolved,
        &cache_key,
        &digest.hex,
        status,
        headers.clone(),
        body.clone(),
    )
    .await;
    Ok(PrefetchedArtifact {
        status,
        headers,
        body,
        digest,
    })
}

fn sha256_digest(bytes: &[u8]) -> Result<ArtifactDigest, aegiscudo_core::DigestError> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    ArtifactDigest::sha256(format!("{:x}", hasher.finalize()))
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
        let cache_key = cache_key_for_upstream(resolved);
        if let Some(cached) = cached_metadata_response(state, &cache_key).await {
            state.metrics.observe_cache(
                resolved.config.tenant_id,
                resolved.config.id,
                resolved.config.adapter,
                "metadata",
                "hit",
            );
            let body = prepare_metadata_body(
                state,
                resolved,
                decision,
                resolved.config.adapter,
                &resolved.config.mount_path,
                &proxy_base_url,
                &cached.headers,
                cached.body,
            )
            .await?;
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
        let upstream_url = upstream_request_url(&resolved.config.upstream_url, &upstream_path)?;
        let upstream_started = Instant::now();
        let mut request_builder = state.upstream_client.get(upstream_url);
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
        let body = prepare_metadata_body(
            state,
            resolved,
            decision,
            resolved.config.adapter,
            &resolved.config.mount_path,
            &proxy_base_url,
            &upstream_headers,
            bytes.to_vec(),
        )
        .await?;
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

async fn maybe_filter_metadata_body(
    state: &AppState,
    resolved: &ResolvedRegistryConfig,
    parent_decision: &DecisionResponse,
    headers: &HeaderMap,
    body: Vec<u8>,
) -> Result<Vec<u8>, UpstreamProxyError> {
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
            trace_id: format!("{}:candidate:{}", parent_decision.trace_id, file_name),
            requested_digest: digest,
            source_url: Some(url.to_owned()),
            explicit_version_or_integrity: true,
        },
    };
    let cache_key = cache_key_for_decision(&decision_request);
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
            Err(error) => {
                tracing::warn!(
                    tenant_id = %resolved.config.tenant_id,
                    registry_config_id = %resolved.config.id,
                    candidate = %file_name,
                    error = %error,
                    "candidate Triage evaluation failed during PyPI filtering"
                );
                state.metrics.observe_triage(
                    resolved.config.tenant_id,
                    resolved.config.id,
                    resolved.config.adapter,
                    "candidate-error",
                    triage_started.elapsed(),
                );
                return Ok(resolved.config.mode != PolicyMode::Enforce);
            }
        }
    };
    Ok(!(decision.mode == PolicyMode::Enforce && decision.decision.is_blocking()))
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

    if let Some(dist_tags) = value.get_mut("dist-tags").and_then(|tags| tags.as_object_mut()) {
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
        format!("{proxy_base_url}{mount}{path}")
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

fn copy_safe_upstream_headers(from: &HeaderMap, to: &mut HeaderMap) {
    for header in [CONTENT_TYPE, CACHE_CONTROL, ETAG] {
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
        RegistryAdapter::Cargo
        | RegistryAdapter::Maven
        | RegistryAdapter::DockerOci
        | RegistryAdapter::GenericHttp => return Err(StatusCode::NOT_IMPLEMENTED),
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
        RegistryAdapter::Cargo
        | RegistryAdapter::Maven
        | RegistryAdapter::DockerOci
        | RegistryAdapter::GenericHttp => None,
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
    use axum::http::header::AUTHORIZATION;
    use axum::{extract::State as AxumState, routing::post};
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
                "npm-fixture-registry",
                "pypi-fixture-registry",
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
                "npm-fixture-registry",
                "pypi-fixture-registry",
            ],
            &restart_registry,
        );

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
    }

    fn create_temp_npm_dirs(prefix: &str) -> (PathBuf, PathBuf) {
        let project_dir = std::env::temp_dir().join(format!(
            "{prefix}-project-{}",
            Uuid::now_v7().simple()
        ));
        let cache_dir = std::env::temp_dir().join(format!(
            "{prefix}-cache-{}",
            Uuid::now_v7().simple()
        ));
        fs::create_dir_all(&project_dir).expect("create temp npm project");
        fs::create_dir_all(&cache_dir).expect("create temp npm cache");
        (project_dir, cache_dir)
    }

    fn create_temp_python_dirs(prefix: &str) -> (PathBuf, PathBuf) {
        let project_dir = std::env::temp_dir().join(format!(
            "{prefix}-project-{}",
            Uuid::now_v7().simple()
        ));
        let cache_dir = std::env::temp_dir().join(format!(
            "{prefix}-cache-{}",
            Uuid::now_v7().simple()
        ));
        fs::create_dir_all(&project_dir).expect("create temp python project");
        fs::create_dir_all(&cache_dir).expect("create temp python cache");
        (project_dir, cache_dir)
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

    fn insert_live_override(scope: serde_json::Value, expires_at: chrono::DateTime<chrono::Utc>) -> Uuid {
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
        content_type: &'static str,
        body: &'static str,
    }

    async fn fake_body_upstream_handler(
        AxumState(state): AxumState<FakeBodyUpstreamState>,
        Path(path): Path<String>,
    ) -> Response {
        state.paths.lock().expect("record paths").push(path);
        ([(CONTENT_TYPE, state.content_type)], state.body).into_response()
    }

    async fn spawn_fake_body_upstream(
        content_type: &'static str,
        body: &'static str,
    ) -> (String, Arc<Mutex<Vec<String>>>, JoinHandle<()>) {
        let paths = Arc::new(Mutex::new(Vec::new()));
        let state = FakeBodyUpstreamState {
            paths: Arc::clone(&paths),
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
        let decision = if matches!(request.request.kind, PackageRequestKind::Artifact) {
            state.artifact_decision.unwrap_or(state.decision)
        } else {
            state.decision
        };
        Json(DecisionResponse {
            decision,
            tenant_id: request.tenant_id,
            policy_profile_id: request.policy_profile_id,
            policy_snapshot_id: Uuid::now_v7(),
            mode: state.mode,
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
            mode,
            status,
            fallback_coordinate,
            create_analysis_job,
            calls: Arc::clone(&calls),
            requested_digests: Arc::clone(&requested_digests),
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
        let client =
            TriageClient::new(triage_url, Duration::from_millis(500), 0).expect("triage client");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mosquito");
        let address = listener.local_addr().expect("mosquito address");
        let router = app_with_runtime_config(store, client, rate_limit_config);
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
        let (triage_url, _calls, triage_handle) =
            spawn_fake_triage(PolicyDecision::BlockKnownMalicious, PolicyMode::Shadow, None).await;
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
            rationale: vec!["eligible resolver metadata flow can use approved fallback candidate"
                .to_owned()],
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
        assert_eq!(filtered["versions"].as_object().map(|versions| versions.len()), Some(1));
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

        let packument = fetch_json(
            "http://127.0.0.1:18000/proxy/npm-fixtures/aegiscudo-benign-npm-fixture",
        );
        assert_eq!(packument["dist-tags"]["latest"], "1.0.0");
        assert_eq!(packument["versions"].as_object().map(|versions| versions.len()), Some(1));
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
        let locked_dependency = &package_lock["packages"]["node_modules/aegiscudo-benign-npm-fixture"];
        assert_eq!(locked_dependency["version"], "1.2.0");
        assert!(locked_dependency["integrity"].as_str().is_some_and(|value| !value.is_empty()));

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
        assert_eq!(String::from_utf8_lossy(&installed_version.stdout).trim(), "1.0.0");

        let _ = fs::remove_dir_all(&project_dir);
        let _ = fs::remove_dir_all(&cache_dir);
    }

    #[test]
    #[ignore = "requires live local postgres, npm-fixture-registry, triage-counter, and mosquito-net"]
    fn unknown_npm_artifact_request_creates_analysis_job_against_live_local_proxy() {
        let repo_root = repo_root();
        recreate_live_local_proxy_stack(&repo_root);

        let package_name = format!(
            "aegiscudo-unknown-npm-fixture-{}",
            Uuid::now_v7().simple()
        );
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

        let tarball_url =
            "http://127.0.0.1:18000/proxy/npm-fixtures/fresh-postinstall/-/fresh-postinstall-0.1.0.tgz";
        let (allowed_status, _allowed_body) = fetch_bytes(tarball_url);
        assert_eq!(allowed_status, StatusCode::OK);

        update_live_override_expiry(override_id, chrono::Utc::now() - chrono::Duration::minutes(1));
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
}
