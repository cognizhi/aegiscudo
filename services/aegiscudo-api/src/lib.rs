use std::time::Duration;

use aegiscudo_core::{AuditEvent, Metadata, PolicyMode, validate_audit_metadata};
use aegiscudo_telemetry::health;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, patch, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgPool, Row, postgres::PgPoolOptions, types::Json as SqlJson};
use thiserror::Error;
use uuid::Uuid;

pub const SERVICE_NAME: &str = "aegiscudo-api";
const ACTOR_HEADER: &str = "x-aegiscudo-actor-id";
const TRACE_HEADER: &str = "x-aegiscudo-trace-id";
const RELOAD_TIMEOUT: Duration = Duration::from_millis(750);

#[derive(Debug, Clone)]
pub struct AppState {
    pool: PgPool,
    reload_client: Option<ReloadClient>,
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
    let state = AppState {
        pool,
        reload_client,
    };
    Router::new()
        .route("/healthz", get(|| async { Json(health(SERVICE_NAME)) }))
        .route("/readyz", get(|| async { Json(health(SERVICE_NAME)) }))
        .route("/v1/tenants/{tenant_id}/overrides", post(create_override))
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

#[derive(Debug, Clone, Serialize)]
struct CredentialTestResponse {
    credential_id: Uuid,
    configured: bool,
    message: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ErrorBody {
    message: String,
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
    #[error("invalid request: {0}")]
    InvalidRequest(String),
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
            Self::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            Self::Database(_) | Self::Reload(_) => StatusCode::SERVICE_UNAVAILABLE,
        };
        let message = self.to_string();
        (status, Json(ErrorBody { message })).into_response()
    }
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
) -> Result<Json<Vec<RegistryConfigResponse>>, ApiError> {
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
) -> Result<Json<RegistryConfigResponse>, ApiError> {
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
) -> Result<Json<Vec<CredentialStatusResponse>>, ApiError> {
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
) -> Result<Json<CredentialTestResponse>, ApiError> {
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

fn role_can_manage_control_plane(role: &str) -> bool {
    matches!(
        role.trim().to_ascii_lowercase().as_str(),
        "admin" | "security-admin" | "security-specialist" | "platform-admin"
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

async fn audit(
    pool: &PgPool,
    tenant_id: Uuid,
    actor: String,
    action: &'static str,
    resource: &str,
    trace_id: String,
    metadata: Metadata,
) -> Result<(), ApiError> {
    validate_audit_metadata(&metadata).map_err(ApiError::InvalidRequest)?;
    let event = AuditEvent {
        id: Uuid::now_v7(),
        tenant_id,
        actor,
        action: action.to_owned(),
        resource: resource.to_owned(),
        trace_id,
        occurred_at: Utc::now(),
        metadata,
    };
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
    .execute(pool)
    .await?;
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

fn default_auth_type() -> CredentialAuthTypeDto {
    CredentialAuthTypeDto::None
}

fn default_credential_source() -> String {
    "environment".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
