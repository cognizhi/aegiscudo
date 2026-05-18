use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use aegiscudo_core::PackageEcosystem;
use aegiscudo_telemetry::health;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{
        StatusCode,
        header::{CONTENT_DISPOSITION, CONTENT_TYPE, HeaderValue},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sqlx::{
    PgPool, Row,
    postgres::{PgPoolOptions, PgRow},
};
use thiserror::Error;
use uuid::Uuid;

pub const SERVICE_NAME: &str = "sbom-service";
/// Hard upper bound on components per SBOM request. Prevents OOM via
/// unbounded allocations before any disk/DB work begins.
pub const MAX_COMPONENT_COUNT: usize = 50_000;
const DEFAULT_SBOM_LIST_LIMIT: i64 = 12;
const MAX_SBOM_LIST_LIMIT: u32 = 50;

#[derive(Debug, Clone)]
pub struct Config {
    pub sbom_store_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct AppState {
    pool: PgPool,
    config: Config,
}

#[derive(Debug, Clone)]
struct ResolvedGenerateComponents {
    tenant_id: Option<Uuid>,
    components: Vec<SbomComponentInput>,
}

pub async fn connect(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
}

pub fn app(pool: PgPool, config: Config) -> Router {
    let state = Arc::new(AppState { pool, config });
    Router::new()
        .route("/healthz", get(|| async { Json(health(SERVICE_NAME)) }))
        .route("/readyz", get(|| async { Json(health(SERVICE_NAME)) }))
        .route("/v1/sbom/generate", post(generate_sbom))
        .route("/v1/sbom/{id}", get(get_sbom))
        .route("/v1/sbom/{id}/metadata", get(get_sbom_metadata))
        .route("/v1/tenants/{tenant_id}/sboms", get(list_tenant_sboms))
        .route("/v1/tenants/{tenant_id}/sboms/{id}", get(get_tenant_sbom))
        .with_state(state)
}

// ── Request / response types ──────────────────────────────────────────────────

/// Input component passed to the SBOM generator.
#[derive(Debug, Clone, Deserialize)]
pub struct SbomComponentInput {
    /// Package URL (e.g. `pkg:npm/lodash@4.17.21`). Required.
    pub purl: String,
    /// Plain package name (e.g. `lodash`).
    pub name: String,
    /// Package ecosystem (`npm`, `pypi`, `cargo`, `maven`, ...).
    pub ecosystem: PackageEcosystem,
    /// Package version, may be `None` when inherited from parent POM.
    pub version: Option<String>,
    /// Namespace / scope / group-id (e.g. `@types`, `org.springframework`).
    pub namespace: Option<String>,
    /// Integrity string as produced by the CLI (e.g. `sha256:<hex>`).
    pub integrity: Option<String>,
    /// Aegiscudo policy decision for this component.
    pub decision: String,
    /// ISO-8601 decision timestamp.
    pub decision_timestamp: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GenerateSbomRequest {
    /// Human-readable source label (lockfile path, project name, etc.).
    pub source: String,
    /// SBOM format: `cyclonedx-1.7-json`, `cyclonedx-1.6-json`, or `spdx-2.3-json`.
    pub format: SbomFormatSpec,
    /// Components to include in the SBOM. May be empty when `analysis_job_id`
    /// is provided and stored Surgeon SBOM fragments should be loaded.
    pub components: Vec<SbomComponentInput>,
    /// Optional reference to the analysis job that produced these components.
    pub analysis_job_id: Option<Uuid>,
    /// Optional tenant owning this SBOM.
    pub tenant_id: Option<Uuid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SbomFormatSpec {
    #[serde(rename = "cyclonedx-1.7-json")]
    CycloneDx17,
    #[serde(rename = "cyclonedx-1.6-json")]
    CycloneDx16,
    #[serde(rename = "spdx-2.3-json")]
    Spdx23,
}

impl SbomFormatSpec {
    pub fn db_value(self) -> &'static str {
        match self {
            Self::CycloneDx17 => "cyclonedx-1.7-json",
            Self::CycloneDx16 => "cyclonedx-1.6-json",
            Self::Spdx23 => "spdx-2.3-json",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GenerateSbomResponse {
    pub id: Uuid,
    pub format: String,
    pub source: String,
    pub component_count: u32,
    pub storage_uri: String,
    pub storage_sha256: String,
    pub storage_size_bytes: u64,
    pub created_at: DateTime<Utc>,
    pub ntia_validation: NtiaValidationResult,
    /// Inline SBOM document.
    pub document: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct SbomMetadata {
    pub id: Uuid,
    pub analysis_job_id: Option<Uuid>,
    pub tenant_id: Option<Uuid>,
    pub format: String,
    pub source: String,
    pub component_count: i32,
    pub storage_uri: String,
    pub storage_sha256: String,
    pub storage_size_bytes: i64,
    pub created_at: DateTime<Utc>,
    pub ntia_validation: NtiaValidationResult,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NtiaValidationResult {
    pub valid: bool,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ListTenantSbomsQuery {
    limit: Option<u32>,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

async fn generate_sbom(
    State(state): State<Arc<AppState>>,
    Json(req): Json<GenerateSbomRequest>,
) -> Result<Json<GenerateSbomResponse>, ApiError> {
    validate_generate_request(&req)?;

    let resolved = resolve_generate_components(&state.pool, &req).await?;

    validate_component_inputs(&resolved.components)?;

    if resolved.components.len() > MAX_COMPONENT_COUNT {
        return Err(ApiError::TooManyComponents(resolved.components.len()));
    }

    let document = match req.format {
        SbomFormatSpec::CycloneDx17 => generate_cyclonedx(&req.source, "1.7", &resolved.components),
        SbomFormatSpec::CycloneDx16 => generate_cyclonedx(&req.source, "1.6", &resolved.components),
        SbomFormatSpec::Spdx23 => generate_spdx23(&req.source, &resolved.components),
    };

    let ntia_validation = validate_ntia_minimum_elements(req.format.db_value(), &document);

    let bytes = serde_json::to_vec_pretty(&document)?;
    let sha256 = hex_sha256(&bytes);
    let size_bytes = bytes.len() as u64;

    let id = Uuid::new_v4();
    let storage_uri =
        write_sbom_to_store(&state.config.sbom_store_dir, resolved.tenant_id, id, &bytes).await?;

    let component_count = resolved.components.len() as i32;
    let now: DateTime<Utc> = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO sbom_documents (
          id, analysis_job_id, tenant_id, source, format,
          storage_uri, storage_sha256, storage_size_bytes, component_count, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#,
    )
    .bind(id)
    .bind(req.analysis_job_id)
    .bind(resolved.tenant_id)
    .bind(&req.source)
    .bind(req.format.db_value())
    .bind(&storage_uri)
    .bind(&sha256)
    .bind(size_bytes as i64)
    .bind(component_count)
    .bind(now)
    .execute(&state.pool)
    .await?;

    Ok(Json(GenerateSbomResponse {
        id,
        format: req.format.db_value().to_owned(),
        source: req.source,
        component_count: component_count as u32,
        storage_uri,
        storage_sha256: sha256,
        storage_size_bytes: size_bytes,
        created_at: now,
        ntia_validation,
        document,
    }))
}

async fn get_sbom(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let row = sqlx::query(
        r#"
        SELECT storage_uri FROM sbom_documents WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;

    let storage_uri: String = row.try_get("storage_uri")?;
    let bytes = load_stored_sbom_bytes(&storage_uri).await?;

    Ok((
        StatusCode::OK,
        [("content-type", "application/json")],
        bytes,
    )
        .into_response())
}

async fn get_sbom_metadata(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<SbomMetadata>, ApiError> {
    let row = sqlx::query(
        r#"
        SELECT id, analysis_job_id, tenant_id, source, format,
               component_count, storage_uri, storage_sha256,
               storage_size_bytes, created_at
        FROM sbom_documents WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;

    Ok(Json(sbom_metadata_from_row(&row).await?))
}

async fn list_tenant_sboms(
    State(state): State<Arc<AppState>>,
    Path(tenant_id): Path<Uuid>,
    Query(query): Query<ListTenantSbomsQuery>,
) -> Result<Json<Vec<SbomMetadata>>, ApiError> {
    let limit = resolve_sbom_list_limit(query.limit)?;
    let rows = sqlx::query(
        r#"
        SELECT id, analysis_job_id, tenant_id, source, format,
               component_count, storage_uri, storage_sha256,
               storage_size_bytes, created_at
        FROM sbom_documents
        WHERE tenant_id = $1
        ORDER BY created_at DESC
        LIMIT $2
        "#,
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    let mut documents = Vec::with_capacity(rows.len());
    for row in rows {
        documents.push(sbom_metadata_from_row(&row).await?);
    }

    Ok(Json(documents))
}

async fn get_tenant_sbom(
    State(state): State<Arc<AppState>>,
    Path((tenant_id, id)): Path<(Uuid, Uuid)>,
) -> Result<Response, ApiError> {
    let row = sqlx::query(
        r#"
        SELECT source, format, storage_uri
        FROM sbom_documents
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;

    let source: String = row.try_get("source")?;
    let format: String = row.try_get("format")?;
    let storage_uri: String = row.try_get("storage_uri")?;
    let bytes = load_stored_sbom_bytes(&storage_uri).await?;
    let filename = sbom_download_filename(&source, &format, id);

    let mut response = Response::new(bytes.into());
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response.headers_mut().insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
            .map_err(|_| ApiError::Storage("content disposition failed".to_owned()))?,
    );

    Ok(response)
}

async fn sbom_metadata_from_row(row: &PgRow) -> Result<SbomMetadata, ApiError> {
    let id: Uuid = row.try_get("id")?;
    let format: String = row.try_get("format")?;
    let storage_uri: String = row.try_get("storage_uri")?;
    let ntia_validation = ntia_validation_for_summary(id, &format, &storage_uri).await;

    Ok(SbomMetadata {
        id,
        analysis_job_id: row.try_get("analysis_job_id")?,
        tenant_id: row.try_get("tenant_id")?,
        format,
        source: row.try_get("source")?,
        component_count: row.try_get("component_count")?,
        storage_uri,
        storage_sha256: row.try_get("storage_sha256")?,
        storage_size_bytes: row.try_get("storage_size_bytes")?,
        created_at: row.try_get("created_at")?,
        ntia_validation,
    })
}

async fn ntia_validation_for_summary(
    id: Uuid,
    format: &str,
    storage_uri: &str,
) -> NtiaValidationResult {
    match load_stored_sbom_validation(format, storage_uri).await {
        Ok(validation) => validation,
        Err(error) => {
            tracing::warn!(
                sbom_id = %id,
                storage_uri = %storage_uri,
                error = %error,
                "failed to load stored SBOM for summary validation"
            );
            NtiaValidationResult {
                valid: false,
                issues: vec![
                    "stored SBOM document could not be loaded for NTIA validation".to_owned(),
                ],
            }
        }
    }
}

async fn resolve_generate_components(
    pool: &PgPool,
    req: &GenerateSbomRequest,
) -> Result<ResolvedGenerateComponents, ApiError> {
    if !req.components.is_empty() {
        return Ok(ResolvedGenerateComponents {
            tenant_id: req.tenant_id,
            components: req.components.clone(),
        });
    }

    let analysis_job_id = req.analysis_job_id.ok_or_else(|| {
        ApiError::InvalidRequest(
            "analysis_job_id is required when components are omitted".to_owned(),
        )
    })?;

    load_analysis_job_components(pool, analysis_job_id, req.tenant_id).await
}

fn validate_generate_request(req: &GenerateSbomRequest) -> Result<(), ApiError> {
    if req.source.trim().is_empty() {
        return Err(ApiError::InvalidRequest(
            "source must not be empty".to_owned(),
        ));
    }

    if req.components.is_empty() && req.analysis_job_id.is_none() {
        return Err(ApiError::InvalidRequest(
            "components must not be empty when analysis_job_id is absent".to_owned(),
        ));
    }

    validate_component_inputs(&req.components)
}

fn validate_component_inputs(components: &[SbomComponentInput]) -> Result<(), ApiError> {
    for (index, component) in components.iter().enumerate() {
        if component.purl.trim().is_empty() {
            return Err(ApiError::InvalidRequest(format!(
                "components[{index}].purl must not be empty"
            )));
        }
        if component.name.trim().is_empty() {
            return Err(ApiError::InvalidRequest(format!(
                "components[{index}].name must not be empty"
            )));
        }
        let parsed_purl = parse_component_purl(&component.purl).map_err(|error| {
            ApiError::InvalidRequest(format!("components[{index}].purl {error}"))
        })?;
        if parsed_purl.ecosystem != component.ecosystem {
            return Err(ApiError::InvalidRequest(format!(
                "components[{index}].ecosystem must match purl ecosystem {}",
                parsed_purl.ecosystem
            )));
        }
        if parsed_purl.name != component.name {
            return Err(ApiError::InvalidRequest(format!(
                "components[{index}].name must match purl name {}",
                parsed_purl.name
            )));
        }
        if component.decision.trim().is_empty() {
            return Err(ApiError::InvalidRequest(format!(
                "components[{index}].decision must not be empty"
            )));
        }
        if component
            .version
            .as_deref()
            .is_some_and(|version| version.trim().is_empty())
        {
            return Err(ApiError::InvalidRequest(format!(
                "components[{index}].version must not be blank when provided"
            )));
        }
        if let Some(namespace) = component.namespace.as_deref() {
            if namespace.trim().is_empty() {
                return Err(ApiError::InvalidRequest(format!(
                    "components[{index}].namespace must not be blank when provided"
                )));
            }
            match parsed_purl.namespace.as_deref() {
                Some(purl_namespace) if namespace == purl_namespace => {}
                Some(purl_namespace) => {
                    return Err(ApiError::InvalidRequest(format!(
                        "components[{index}].namespace must match purl namespace {purl_namespace}"
                    )));
                }
                None => {
                    return Err(ApiError::InvalidRequest(format!(
                        "components[{index}].namespace must not be set when purl has no namespace"
                    )));
                }
            }
        }
        if let Some(version) = component.version.as_deref()
            && let Some(purl_version) = parsed_purl.version.as_deref()
            && version != purl_version
        {
            return Err(ApiError::InvalidRequest(format!(
                "components[{index}].version must match purl version {purl_version}"
            )));
        }
        if component
            .decision_timestamp
            .as_deref()
            .is_some_and(|timestamp| timestamp.trim().is_empty())
        {
            return Err(ApiError::InvalidRequest(format!(
                "components[{index}].decision_timestamp must not be blank when provided"
            )));
        }
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct StoredSbomFragment {
    components: Vec<StoredSbomFragmentComponent>,
}

#[derive(Debug, Deserialize)]
struct StoredSbomFragmentComponent {
    purl: String,
    name: String,
    ecosystem: PackageEcosystem,
    version: Option<String>,
    namespace: Option<String>,
    integrity: Option<String>,
}

async fn load_analysis_job_components(
    pool: &PgPool,
    analysis_job_id: Uuid,
    tenant_id: Option<Uuid>,
) -> Result<ResolvedGenerateComponents, ApiError> {
    let rows = if let Some(tenant_id) = tenant_id {
        sqlx::query(
            r#"
            SELECT
              fragments.tenant_id,
              fragments.fragment,
              policy_decision.decision AS decision,
              policy_decision.decided_at
            FROM analysis_sbom_fragments AS fragments
            LEFT JOIN LATERAL (
              SELECT
                policy_decisions.decision::text AS decision,
                policy_decisions.decided_at
              FROM policy_decisions
              WHERE policy_decisions.artifact_id = fragments.artifact_id
                AND policy_decisions.tenant_id = fragments.tenant_id
              ORDER BY policy_decisions.decided_at DESC
              LIMIT 1
            ) AS policy_decision ON TRUE
            WHERE fragments.analysis_job_id = $1
              AND fragments.tenant_id = $2
            ORDER BY fragments.created_at ASC, fragments.id ASC
            "#,
        )
        .bind(analysis_job_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query(
            r#"
            SELECT
              fragments.tenant_id,
              fragments.fragment,
              policy_decision.decision AS decision,
              policy_decision.decided_at
            FROM analysis_sbom_fragments AS fragments
            LEFT JOIN LATERAL (
              SELECT
                policy_decisions.decision::text AS decision,
                policy_decisions.decided_at
              FROM policy_decisions
              WHERE policy_decisions.artifact_id = fragments.artifact_id
                AND policy_decisions.tenant_id = fragments.tenant_id
              ORDER BY policy_decisions.decided_at DESC
              LIMIT 1
            ) AS policy_decision ON TRUE
            WHERE fragments.analysis_job_id = $1
            ORDER BY fragments.created_at ASC, fragments.id ASC
            "#,
        )
        .bind(analysis_job_id)
        .fetch_all(pool)
        .await?
    };

    if rows.is_empty() {
        return Err(ApiError::NotFound);
    }

    let resolved_tenant_id = rows.first().and_then(|row| row.try_get("tenant_id").ok());
    let mut components = Vec::new();
    for row in &rows {
        let fragment: Value = row.try_get("fragment")?;
        let decision = row.try_get::<Option<String>, _>("decision")?;
        let decided_at = row.try_get::<Option<DateTime<Utc>>, _>("decided_at")?;
        components.extend(stored_fragment_components(
            &fragment,
            decision.as_deref(),
            decided_at,
        )?);
    }

    Ok(ResolvedGenerateComponents {
        tenant_id: tenant_id.or(resolved_tenant_id),
        components,
    })
}

fn stored_fragment_components(
    fragment: &Value,
    decision: Option<&str>,
    decided_at: Option<DateTime<Utc>>,
) -> Result<Vec<SbomComponentInput>, ApiError> {
    let fragment: StoredSbomFragment =
        serde_json::from_value(fragment.clone()).map_err(|error| {
            ApiError::InvalidRequest(format!("stored SBOM fragment is invalid: {error}"))
        })?;

    Ok(fragment
        .components
        .into_iter()
        .map(|component| SbomComponentInput {
            purl: component.purl,
            name: component.name,
            ecosystem: component.ecosystem,
            version: component.version,
            namespace: component.namespace,
            integrity: component.integrity,
            decision: decision.unwrap_or("unknown").to_owned(),
            decision_timestamp: decided_at
                .map(|value| value.to_rfc3339_opts(SecondsFormat::Secs, true)),
        })
        .collect())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedPurl {
    ecosystem: PackageEcosystem,
    namespace: Option<String>,
    name: String,
    version: Option<String>,
}

fn parse_component_purl(purl: &str) -> Result<ParsedPurl, String> {
    let raw = purl
        .trim()
        .strip_prefix("pkg:")
        .ok_or_else(|| "must start with pkg:".to_owned())?;
    let (package_type, remainder) = raw
        .split_once('/')
        .ok_or_else(|| "must include a package type and package path".to_owned())?;
    let ecosystem = PackageEcosystem::from_str(package_type)
        .map_err(|_| format!("contains unsupported package type {package_type}"))?;
    let remainder = remainder
        .split_once('#')
        .map_or(remainder, |(main, _)| main);
    let remainder = remainder
        .split_once('?')
        .map_or(remainder, |(main, _)| main);
    let (path_part, version) = match remainder.rsplit_once('@') {
        Some((path, version)) => {
            if version.trim().is_empty() {
                return Err("must not include an empty version".to_owned());
            }
            (path, Some(version.to_owned()))
        }
        None => (remainder, None),
    };

    let mut path_segments: Vec<&str> = path_part
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    if path_segments.is_empty() {
        return Err("must include a package name".to_owned());
    }

    let name = path_segments
        .pop()
        .expect("path_segments is not empty")
        .to_owned();
    let namespace = (!path_segments.is_empty()).then(|| path_segments.join("/"));

    Ok(ParsedPurl {
        ecosystem,
        namespace,
        name,
        version,
    })
}

fn resolved_component_namespace(component: &SbomComponentInput) -> Option<String> {
    component.namespace.clone().or_else(|| {
        parse_component_purl(&component.purl)
            .ok()
            .and_then(|parsed| parsed.namespace)
    })
}

fn resolved_component_version(component: &SbomComponentInput) -> Option<String> {
    component.version.clone().or_else(|| {
        parse_component_purl(&component.purl)
            .ok()
            .and_then(|parsed| parsed.version)
    })
}

fn resolve_sbom_list_limit(requested_limit: Option<u32>) -> Result<i64, ApiError> {
    match requested_limit {
        None => Ok(DEFAULT_SBOM_LIST_LIMIT),
        Some(0) => Err(ApiError::InvalidRequest(
            "limit must be greater than zero".to_owned(),
        )),
        Some(limit) => Ok(i64::from(limit.min(MAX_SBOM_LIST_LIMIT))),
    }
}

fn sbom_download_filename(source: &str, format: &str, id: Uuid) -> String {
    let source_component = sanitize_filename_component(source);
    let format_component = sanitize_filename_component(format);
    format!("{source_component}-{format_component}-{id}.json")
}

fn sanitize_filename_component(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());
    let mut last_was_dash = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            sanitized.push(ch.to_ascii_lowercase());
            last_was_dash = false;
            continue;
        }
        if !last_was_dash {
            sanitized.push('-');
            last_was_dash = true;
        }
    }

    let trimmed = sanitized.trim_matches('-');
    if trimmed.is_empty() {
        "sbom".to_owned()
    } else {
        trimmed.to_owned()
    }
}

async fn load_stored_sbom_validation(
    format: &str,
    storage_uri: &str,
) -> Result<NtiaValidationResult, ApiError> {
    let bytes = load_stored_sbom_bytes(storage_uri).await?;
    let document: Value = serde_json::from_slice(&bytes)?;
    Ok(validate_ntia_minimum_elements(format, &document))
}

async fn load_stored_sbom_bytes(storage_uri: &str) -> Result<Vec<u8>, ApiError> {
    let path = uri_to_path(storage_uri)?;
    tokio::fs::read(&path).await.map_err(|error| {
        tracing::error!(error = %error, "failed to read SBOM from store");
        ApiError::Storage("read failed".to_owned())
    })
}

fn validate_ntia_minimum_elements(format: &str, document: &Value) -> NtiaValidationResult {
    let issues = match format {
        "cyclonedx-1.7-json" | "cyclonedx-1.6-json" => validate_cyclonedx_ntia(document),
        "spdx-2.3-json" => validate_spdx_ntia(document),
        other => vec![format!(
            "unsupported SBOM format for NTIA validation: {other}"
        )],
    };

    NtiaValidationResult {
        valid: issues.is_empty(),
        issues,
    }
}

// ── SBOM generation ───────────────────────────────────────────────────────────

/// Generate a CycloneDX BOM JSON document at the given spec version (1.6 or 1.7).
pub fn generate_cyclonedx(
    source: &str,
    spec_version: &str,
    components: &[SbomComponentInput],
) -> Value {
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let serial_number = format!("urn:uuid:{}", Uuid::new_v4());
    let root_ref = format!("aegiscudo:sbom:{source}");
    let root_ecosystem = common_ecosystem(components);

    let cdx_components: Vec<Value> = components
        .iter()
        .map(|c| cyclonedx_component(c, spec_version))
        .collect();

    let depends_on: Vec<Value> = components
        .iter()
        .map(|c| Value::String(c.purl.clone()))
        .collect();

    let mut dependencies: Vec<Value> = vec![json!({
        "ref": root_ref,
        "dependsOn": depends_on
    })];
    for c in components {
        dependencies.push(json!({ "ref": c.purl, "dependsOn": [] }));
    }

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{
                "vendor": "Aegiscudo",
                "name": "sbom-service",
                "version": env!("CARGO_PKG_VERSION")
            }],
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": source,
                "supplier": { "name": "NOASSERTION" },
                "properties": root_properties(source, &now, root_ecosystem.as_ref())
            }
        },
        "components": cdx_components,
        "dependencies": dependencies
    })
}

fn cyclonedx_component(c: &SbomComponentInput, _spec_version: &str) -> Value {
    let namespace = resolved_component_namespace(c);
    let version = resolved_component_version(c);
    let mut obj = Map::new();
    obj.insert("type".to_owned(), json!("library"));
    obj.insert("bom-ref".to_owned(), json!(c.purl));
    obj.insert("purl".to_owned(), json!(c.purl));
    obj.insert("name".to_owned(), json!(c.name));
    obj.insert("supplier".to_owned(), json!({ "name": "NOASSERTION" }));
    if let Some(ns) = namespace.as_deref() {
        obj.insert("group".to_owned(), json!(ns));
    }
    if let Some(ver) = version.as_deref() {
        obj.insert("version".to_owned(), json!(ver));
    }
    if let Some(hash) = integrity_to_cyclonedx_hash(&c.integrity) {
        obj.insert("hashes".to_owned(), json!([hash]));
    }
    obj.insert("properties".to_owned(), json!(component_properties(c)));
    Value::Object(obj)
}

fn integrity_to_cyclonedx_hash(integrity: &Option<String>) -> Option<Value> {
    let s = integrity.as_deref()?;
    let (alg, hex) = s.split_once(':')?;
    let cdx_alg = match alg {
        "sha256" | "sha-256" => "SHA-256",
        "sha512" | "sha-512" => "SHA-512",
        _ => return None,
    };
    Some(json!({ "alg": cdx_alg, "content": hex }))
}

/// Generate an SPDX 2.3 JSON document.
pub fn generate_spdx23(source: &str, components: &[SbomComponentInput]) -> Value {
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let doc_namespace = format!(
        "https://aegiscudo.io/sbom/{}/{}",
        urlenc(source),
        Uuid::new_v4()
    );
    let root_id = "SPDXRef-Root";

    let mut packages: Vec<Value> = vec![json!({
        "SPDXID": root_id,
        "name": source,
        "versionInfo": "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": false,
        "supplier": "NOASSERTION",
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "APPLICATION",
        "comment": format!("Generated from {source}")
    })];
    let mut relationships: Vec<Value> = vec![json!({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": root_id
    })];

    for (i, c) in components.iter().enumerate() {
        let version = resolved_component_version(c);
        let spdx_id = format!("SPDXRef-Package-{}", i + 1);
        let mut pkg = Map::new();
        pkg.insert("SPDXID".to_owned(), json!(spdx_id));
        pkg.insert("name".to_owned(), json!(c.name));
        pkg.insert(
            "versionInfo".to_owned(),
            json!(version.as_deref().unwrap_or("NOASSERTION")),
        );
        pkg.insert("downloadLocation".to_owned(), json!("NOASSERTION"));
        pkg.insert("filesAnalyzed".to_owned(), json!(false));
        pkg.insert("supplier".to_owned(), json!("NOASSERTION"));
        pkg.insert("licenseConcluded".to_owned(), json!("NOASSERTION"));
        pkg.insert("licenseDeclared".to_owned(), json!("NOASSERTION"));
        pkg.insert("copyrightText".to_owned(), json!("NOASSERTION"));
        pkg.insert("primaryPackagePurpose".to_owned(), json!("LIBRARY"));
        pkg.insert("comment".to_owned(), json!(component_comment(c)));

        let ext_ref = json!({
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": c.purl
        });
        pkg.insert("externalRefs".to_owned(), json!([ext_ref]));

        if let Some(hash) = integrity_to_spdx_checksum(&c.integrity) {
            pkg.insert("checksums".to_owned(), json!([hash]));
        }

        packages.push(Value::Object(pkg));
        relationships.push(json!({
            "spdxElementId": root_id,
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": spdx_id
        }));
    }

    json!({
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "creationInfo": {
            "created": now,
            "creators": [
                format!("Tool: Aegiscudo sbom-service-{}", env!("CARGO_PKG_VERSION"))
            ],
            "licenseListVersion": "3.22"
        },
        "name": source,
        "dataLicense": "CC0-1.0",
        "documentNamespace": doc_namespace,
        "packages": packages,
        "relationships": relationships
    })
}

fn integrity_to_spdx_checksum(integrity: &Option<String>) -> Option<Value> {
    let s = integrity.as_deref()?;
    let (alg, hex) = s.split_once(':')?;
    let spdx_alg = match alg {
        "sha256" | "sha-256" => "SHA256",
        "sha512" | "sha-512" => "SHA512",
        _ => return None,
    };
    Some(json!({ "algorithm": spdx_alg, "checksumValue": hex }))
}

fn root_properties(
    source: &str,
    generated_at: &str,
    ecosystem: Option<&PackageEcosystem>,
) -> Vec<Value> {
    let mut properties = vec![
        json!({ "name": "aegiscudo:source", "value": source }),
        json!({ "name": "aegiscudo:generated_at", "value": generated_at }),
    ];

    if let Some(ecosystem) = ecosystem {
        properties.push(json!({
            "name": "aegiscudo:ecosystem",
            "value": ecosystem.to_string(),
        }));
    }

    properties
}

fn component_properties(component: &SbomComponentInput) -> Vec<Value> {
    let mut properties = vec![json!({
        "name": "aegiscudo:ecosystem",
        "value": component.ecosystem.to_string(),
    })];

    properties.push(json!({
        "name": "aegiscudo:decision",
        "value": component.decision,
    }));

    if let Some(decision_timestamp) = component.decision_timestamp.as_deref() {
        properties.push(json!({
            "name": "aegiscudo:decision_timestamp",
            "value": decision_timestamp,
        }));
    } else {
        properties.push(json!({
            "name": "aegiscudo:decision_timestamp_status",
            "value": "unavailable",
        }));
    }

    if let Some(integrity) = component.integrity.as_deref() {
        properties.push(json!({
            "name": "aegiscudo:integrity",
            "value": integrity,
        }));
    }

    properties
}

fn component_comment(component: &SbomComponentInput) -> String {
    let mut parts = vec![format!("ecosystem={}", component.ecosystem)];
    parts.push(format!("Aegiscudo decision={}", component.decision));

    if let Some(decision_timestamp) = component.decision_timestamp.as_deref() {
        parts.push(format!("decision_timestamp={decision_timestamp}"));
    } else {
        parts.push("decision_timestamp=unavailable".to_owned());
    }

    if let Some(integrity) = component.integrity.as_deref() {
        parts.push(format!("integrity={integrity}"));
    }

    parts.join("; ")
}

fn common_ecosystem(components: &[SbomComponentInput]) -> Option<PackageEcosystem> {
    let first = components.first()?.ecosystem.clone();
    components
        .iter()
        .all(|component| component.ecosystem == first)
        .then_some(first)
}

/// Percent-encodes a string for use in a URI path segment following RFC 3986.
/// Operates on UTF-8 bytes so multi-byte characters are encoded correctly
/// (e.g. 'é' → "%C3%A9", not "%E9").
fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ── Storage helpers ───────────────────────────────────────────────────────────

async fn write_sbom_to_store(
    store_dir: &std::path::Path,
    tenant_id: Option<Uuid>,
    id: Uuid,
    bytes: &[u8],
) -> Result<String, ApiError> {
    let dir = match tenant_id {
        Some(tid) => store_dir.join(tid.to_string()),
        None => store_dir.join("untenanted"),
    };
    tokio::fs::create_dir_all(&dir).await.map_err(|e| {
        tracing::error!(error = %e, "failed to create SBOM store directory");
        ApiError::Storage("create_dir_all failed".to_owned())
    })?;
    let file_path = dir.join(format!("{id}.json"));
    tokio::fs::write(&file_path, bytes).await.map_err(|e| {
        tracing::error!(error = %e, "failed to write SBOM to store");
        ApiError::Storage("write failed".to_owned())
    })?;
    file_storage_uri(&file_path)
}

fn file_storage_uri(path: &std::path::Path) -> Result<String, ApiError> {
    let canonical = std::fs::canonicalize(path).map_err(|e| {
        tracing::error!(error = %e, "failed to canonicalize SBOM storage path");
        ApiError::Storage("canonicalize failed".to_owned())
    })?;
    Ok(format!("file://{}", canonical.display()))
}

fn uri_to_path(uri: &str) -> Result<std::path::PathBuf, ApiError> {
    let path = uri.strip_prefix("file://").ok_or_else(|| {
        tracing::error!("SBOM storage URI has unsupported scheme");
        ApiError::Storage("unsupported URI scheme".to_owned())
    })?;
    Ok(std::path::PathBuf::from(path))
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn validate_cyclonedx_ntia(document: &Value) -> Vec<String> {
    let mut issues = Vec::new();
    require_non_empty_string(
        document.pointer("/metadata/timestamp"),
        "metadata.timestamp",
        &mut issues,
    );
    if document
        .pointer("/metadata/tools")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty)
    {
        issues.push("missing metadata.tools author metadata".to_owned());
    }
    require_non_empty_string(
        document.pointer("/metadata/component/name"),
        "metadata.component.name",
        &mut issues,
    );
    require_non_empty_string(
        document.pointer("/metadata/component/supplier/name"),
        "metadata.component.supplier.name",
        &mut issues,
    );

    let Some(components) = document.get("components").and_then(Value::as_array) else {
        issues.push("missing components array".to_owned());
        return issues;
    };
    for (index, component) in components.iter().enumerate() {
        require_non_empty_string(
            component.get("name"),
            &format!("components[{index}].name"),
            &mut issues,
        );
        require_non_empty_string(
            component.get("version"),
            &format!("components[{index}].version"),
            &mut issues,
        );
        require_non_empty_string(
            component.get("purl"),
            &format!("components[{index}].purl"),
            &mut issues,
        );
        require_non_empty_string(
            component.pointer("/supplier/name"),
            &format!("components[{index}].supplier.name"),
            &mut issues,
        );
        if !has_named_property(component.get("properties"), "aegiscudo:ecosystem") {
            issues.push(format!(
                "components[{index}] is missing aegiscudo:ecosystem property"
            ));
        }
    }

    if document
        .get("dependencies")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty)
    {
        issues.push("missing dependency relationships".to_owned());
    }

    issues
}

fn validate_spdx_ntia(document: &Value) -> Vec<String> {
    let mut issues = Vec::new();
    require_non_empty_string(
        document.pointer("/creationInfo/created"),
        "creationInfo.created",
        &mut issues,
    );
    if document
        .pointer("/creationInfo/creators")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty)
    {
        issues.push("missing creationInfo.creators author metadata".to_owned());
    }

    let Some(packages) = document.get("packages").and_then(Value::as_array) else {
        issues.push("missing packages array".to_owned());
        return issues;
    };
    if packages.is_empty() {
        issues.push("packages array is empty".to_owned());
        return issues;
    }

    for (index, package) in packages.iter().enumerate() {
        require_non_empty_string(
            package.get("name"),
            &format!("packages[{index}].name"),
            &mut issues,
        );
        require_non_empty_string(
            package.get("supplier"),
            &format!("packages[{index}].supplier"),
            &mut issues,
        );
        require_non_empty_string(
            package.get("versionInfo"),
            &format!("packages[{index}].versionInfo"),
            &mut issues,
        );
        if index > 0 && !has_spdx_purl_external_ref(package) {
            issues.push(format!(
                "packages[{index}] is missing PACKAGE-MANAGER purl external reference"
            ));
        }
    }

    let Some(relationships) = document.get("relationships").and_then(Value::as_array) else {
        issues.push("missing relationships array".to_owned());
        return issues;
    };
    if !relationships.iter().any(|relationship| {
        relationship.get("spdxElementId") == Some(&Value::String("SPDXRef-DOCUMENT".to_owned()))
            && relationship.get("relationshipType") == Some(&Value::String("DESCRIBES".to_owned()))
            && relationship.get("relatedSpdxElement")
                == Some(&Value::String("SPDXRef-Root".to_owned()))
    }) {
        issues.push("missing document DESCRIBES root relationship".to_owned());
    }

    issues
}

fn require_non_empty_string(value: Option<&Value>, field: &str, issues: &mut Vec<String>) {
    match value.and_then(Value::as_str) {
        Some(text) if !text.trim().is_empty() => {}
        _ => issues.push(format!("missing {field}")),
    }
}

fn has_named_property(properties: Option<&Value>, expected_name: &str) -> bool {
    properties
        .and_then(Value::as_array)
        .is_some_and(|properties| {
            properties.iter().any(|property| {
                property.get("name") == Some(&Value::String(expected_name.to_owned()))
            })
        })
}

fn has_spdx_purl_external_ref(package: &Value) -> bool {
    package
        .get("externalRefs")
        .and_then(Value::as_array)
        .is_some_and(|external_refs| {
            external_refs.iter().any(|external_ref| {
                external_ref.get("referenceCategory")
                    == Some(&Value::String("PACKAGE-MANAGER".to_owned()))
                    && external_ref.get("referenceType") == Some(&Value::String("purl".to_owned()))
            })
        })
}

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("not found")]
    NotFound,
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("request contains {0} components; maximum allowed is 50000")]
    TooManyComponents(usize),
    #[error("SBOM JSON handling failed")]
    Json(#[from] serde_json::Error),
    /// The contained string is an internal diagnostic only; it is NOT
    /// forwarded to callers — only the fixed display text is.
    #[error("object storage error")]
    Storage(String),
    #[error("database error")]
    Database(#[from] sqlx::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::InvalidRequest(_) | Self::TooManyComponents(_) => {
                StatusCode::UNPROCESSABLE_ENTITY
            }
            Self::Json(_) | Self::Storage(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Database(_) => StatusCode::SERVICE_UNAVAILABLE,
        };
        (status, self.to_string()).into_response()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_components() -> Vec<SbomComponentInput> {
        vec![
            SbomComponentInput {
                purl: "pkg:npm/lodash@4.17.21".to_owned(),
                name: "lodash".to_owned(),
                ecosystem: PackageEcosystem::Npm,
                version: Some("4.17.21".to_owned()),
                namespace: None,
                integrity: Some(
                    "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd"
                        .to_owned(),
                ),
                decision: "allow".to_owned(),
                decision_timestamp: Some("2026-05-13T12:00:00Z".to_owned()),
            },
            SbomComponentInput {
                purl: "pkg:npm/express@4.18.2".to_owned(),
                name: "express".to_owned(),
                ecosystem: PackageEcosystem::Npm,
                version: Some("4.18.2".to_owned()),
                namespace: None,
                integrity: None,
                decision: "allow_with_warning".to_owned(),
                decision_timestamp: None,
            },
        ]
    }

    #[test]
    fn cyclonedx_17_has_required_fields() {
        let doc = generate_cyclonedx("test-project", "1.7", &sample_components());

        assert_eq!(doc["bomFormat"], "CycloneDX");
        assert_eq!(doc["specVersion"], "1.7");
        assert!(
            doc["serialNumber"]
                .as_str()
                .unwrap()
                .starts_with("urn:uuid:")
        );
        assert_eq!(doc["version"], 1);
    }

    #[test]
    fn cyclonedx_16_has_correct_spec_version() {
        let doc = generate_cyclonedx("test-project", "1.6", &sample_components());

        assert_eq!(doc["specVersion"], "1.6");
        assert_eq!(doc["bomFormat"], "CycloneDX");
    }

    #[test]
    fn cyclonedx_components_include_purl_and_decision() {
        let doc = generate_cyclonedx("test-project", "1.7", &sample_components());

        let components = doc["components"].as_array().unwrap();
        assert_eq!(components.len(), 2);

        let lodash = &components[0];
        assert_eq!(lodash["purl"], "pkg:npm/lodash@4.17.21");
        assert_eq!(lodash["name"], "lodash");
        assert_eq!(lodash["version"], "4.17.21");

        let props = lodash["properties"].as_array().unwrap();
        let ecosystem_prop = props
            .iter()
            .find(|p| p["name"] == "aegiscudo:ecosystem")
            .unwrap();
        assert_eq!(ecosystem_prop["value"], "npm");
        let decision_prop = props
            .iter()
            .find(|p| p["name"] == "aegiscudo:decision")
            .unwrap();
        assert_eq!(decision_prop["value"], "allow");
    }

    #[test]
    fn cyclonedx_component_with_sha256_integrity_emits_hash() {
        let doc = generate_cyclonedx("test-project", "1.7", &sample_components());
        let components = doc["components"].as_array().unwrap();
        let lodash = &components[0];

        let hashes = lodash["hashes"].as_array().unwrap();
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["alg"], "SHA-256");
    }

    #[test]
    fn cyclonedx_component_without_integrity_has_no_hashes() {
        let doc = generate_cyclonedx("test-project", "1.7", &sample_components());
        let components = doc["components"].as_array().unwrap();
        let express = &components[1];

        assert!(
            express.get("hashes").is_none() || express["hashes"].as_array().unwrap().is_empty()
        );
    }

    #[test]
    fn cyclonedx_dependencies_reference_all_components() {
        let doc = generate_cyclonedx("test-project", "1.7", &sample_components());
        let deps = doc["dependencies"].as_array().unwrap();

        // Root entry + one entry per component
        assert_eq!(deps.len(), 3);
        let root_dep = &deps[0];
        let depends_on = root_dep["dependsOn"].as_array().unwrap();
        assert_eq!(depends_on.len(), 2);
    }

    #[test]
    fn cyclonedx_empty_components_produces_valid_bom() {
        let doc = generate_cyclonedx("empty-project", "1.7", &[]);

        assert_eq!(doc["bomFormat"], "CycloneDX");
        assert!(doc["components"].as_array().unwrap().is_empty());
        assert_eq!(doc["dependencies"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn spdx23_has_required_fields() {
        let doc = generate_spdx23("test-project", &sample_components());

        assert_eq!(doc["spdxVersion"], "SPDX-2.3");
        assert_eq!(doc["dataLicense"], "CC0-1.0");
        assert!(
            doc["documentNamespace"]
                .as_str()
                .unwrap()
                .starts_with("https://aegiscudo.io/sbom/")
        );
    }

    #[test]
    fn spdx23_packages_include_purl_external_ref() {
        let doc = generate_spdx23("test-project", &sample_components());

        let packages = doc["packages"].as_array().unwrap();
        // root (SPDXRef-DOCUMENT) + 2 components
        assert_eq!(packages.len(), 3);

        // First real package (index 1, index 0 is root)
        let pkg = &packages[1];
        let ext_refs = pkg["externalRefs"].as_array().unwrap();
        assert_eq!(ext_refs[0]["referenceType"], "purl");
        assert_eq!(ext_refs[0]["referenceLocator"], "pkg:npm/lodash@4.17.21");
    }

    #[test]
    fn spdx23_relationships_describe_all_components() {
        let doc = generate_spdx23("test-project", &sample_components());

        let rels = doc["relationships"].as_array().unwrap();
        assert_eq!(rels.len(), 3);
        assert_eq!(rels[0]["spdxElementId"], "SPDXRef-DOCUMENT");
        assert_eq!(rels[0]["relationshipType"], "DESCRIBES");
        assert_eq!(rels[0]["relatedSpdxElement"], "SPDXRef-Root");
        assert!(
            rels[1..]
                .iter()
                .all(|r| r["spdxElementId"] == "SPDXRef-Root")
        );
        assert!(
            rels[1..]
                .iter()
                .all(|r| r["relationshipType"] == "DEPENDS_ON")
        );
    }

    #[test]
    fn spdx23_package_with_sha256_integrity_emits_checksum() {
        let doc = generate_spdx23("test-project", &sample_components());
        let packages = doc["packages"].as_array().unwrap();
        let lodash_pkg = &packages[1];

        let checksums = lodash_pkg["checksums"].as_array().unwrap();
        assert_eq!(checksums[0]["algorithm"], "SHA256");
    }

    #[test]
    fn spdx23_empty_components_produces_valid_document() {
        let doc = generate_spdx23("empty-project", &[]);

        assert_eq!(doc["spdxVersion"], "SPDX-2.3");
        assert_eq!(doc["packages"].as_array().unwrap().len(), 1); // just root
        assert_eq!(doc["relationships"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn cyclonedx_namespace_emitted_as_group() {
        let components = vec![SbomComponentInput {
            purl: "pkg:maven/org.springframework/spring-core@6.1.0".to_owned(),
            name: "spring-core".to_owned(),
            ecosystem: PackageEcosystem::Maven,
            version: Some("6.1.0".to_owned()),
            namespace: Some("org.springframework".to_owned()),
            integrity: None,
            decision: "allow".to_owned(),
            decision_timestamp: None,
        }];
        let doc = generate_cyclonedx("pom-project", "1.7", &components);

        let cdx_components = doc["components"].as_array().unwrap();
        assert_eq!(cdx_components[0]["group"], "org.springframework");
    }

    #[test]
    fn sbom_format_spec_db_values_are_correct() {
        assert_eq!(SbomFormatSpec::CycloneDx17.db_value(), "cyclonedx-1.7-json");
        assert_eq!(SbomFormatSpec::CycloneDx16.db_value(), "cyclonedx-1.6-json");
        assert_eq!(SbomFormatSpec::Spdx23.db_value(), "spdx-2.3-json");
    }

    #[test]
    fn hex_sha256_produces_64_char_hex() {
        let digest = hex_sha256(b"hello");
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn uri_to_path_strips_file_scheme() {
        let path = uri_to_path("file:///var/lib/aegiscudo/sboms/test.json").unwrap();
        assert_eq!(path.to_str().unwrap(), "/var/lib/aegiscudo/sboms/test.json");
    }

    #[test]
    fn uri_to_path_rejects_non_file_scheme() {
        let err = uri_to_path("s3://my-bucket/key").unwrap_err();
        // Storage errors surface a generic message; internals are only logged.
        assert!(matches!(err, ApiError::Storage(_)));
    }

    #[test]
    fn resolve_sbom_list_limit_defaults_and_clamps() {
        assert_eq!(
            resolve_sbom_list_limit(None).unwrap(),
            DEFAULT_SBOM_LIST_LIMIT
        );
        assert_eq!(resolve_sbom_list_limit(Some(3)).unwrap(), 3);
        assert_eq!(
            resolve_sbom_list_limit(Some(MAX_SBOM_LIST_LIMIT + 25)).unwrap(),
            i64::from(MAX_SBOM_LIST_LIMIT)
        );
    }

    #[test]
    fn resolve_sbom_list_limit_rejects_zero() {
        let err = resolve_sbom_list_limit(Some(0)).unwrap_err();
        assert!(matches!(err, ApiError::InvalidRequest(_)));
        assert!(err.to_string().contains("greater than zero"));
    }

    #[test]
    fn sbom_download_filename_sanitizes_source_and_format() {
        let filename =
            sbom_download_filename("Cargo lock / workspace", "cyclonedx-1.7-json", Uuid::nil());

        assert_eq!(
            filename,
            "cargo-lock-workspace-cyclonedx-1-7-json-00000000-0000-0000-0000-000000000000.json"
        );
    }

    #[tokio::test]
    async fn ntia_validation_for_summary_degrades_storage_failures() {
        let validation = ntia_validation_for_summary(
            Uuid::nil(),
            "cyclonedx-1.7-json",
            "file:///definitely-missing-aegiscudo-sbom.json",
        )
        .await;

        assert!(!validation.valid);
        assert_eq!(
            validation.issues,
            vec!["stored SBOM document could not be loaded for NTIA validation".to_owned()]
        );
    }

    #[test]
    fn too_many_components_error_is_descriptive() {
        let err = ApiError::TooManyComponents(100_000);
        let msg = err.to_string();
        assert!(msg.contains("100000"), "should include actual count");
        assert!(
            msg.contains(&MAX_COMPONENT_COUNT.to_string()),
            "should include the limit"
        );
    }

    #[test]
    fn urlenc_encodes_slash_and_space() {
        assert_eq!(urlenc("foo bar/baz"), "foo%20bar%2Fbaz");
    }

    #[test]
    fn urlenc_encodes_utf8_bytes_not_codepoints() {
        // 'é' is U+00E9 but its UTF-8 bytes are 0xC3 0xA9.
        // Encoding codepoints directly would wrongly produce %E9.
        assert_eq!(urlenc("caf\u{00E9}"), "caf%C3%A9");
    }

    #[test]
    fn urlenc_encodes_percent_itself() {
        assert_eq!(urlenc("100%"), "100%25");
    }

    #[test]
    fn max_component_count_constant_is_expected_value() {
        assert_eq!(MAX_COMPONENT_COUNT, 50_000);
    }

    #[test]
    fn spdx23_component_comment_includes_ecosystem_and_decision() {
        let doc = generate_spdx23("test-project", &sample_components());
        let packages = doc["packages"].as_array().unwrap();

        assert!(
            packages[1]["comment"]
                .as_str()
                .unwrap()
                .contains("ecosystem=npm")
        );
        assert!(
            packages[1]["comment"]
                .as_str()
                .unwrap()
                .contains("Aegiscudo decision=allow")
        );
    }

    #[test]
    fn ntia_validation_accepts_complete_cyclonedx_document() {
        let doc = generate_cyclonedx("test-project", "1.7", &sample_components());
        let validation = validate_ntia_minimum_elements("cyclonedx-1.7-json", &doc);

        assert!(validation.valid, "issues: {:?}", validation.issues);
        assert!(validation.issues.is_empty());
    }

    #[test]
    fn ntia_validation_accepts_complete_spdx_document() {
        let doc = generate_spdx23("test-project", &sample_components());
        let validation = validate_ntia_minimum_elements("spdx-2.3-json", &doc);

        assert!(validation.valid, "issues: {:?}", validation.issues);
        assert!(validation.issues.is_empty());
    }

    #[test]
    fn ntia_validation_flags_missing_cyclonedx_component_version() {
        let mut components = sample_components();
        components[0].version = None;
        components[0].purl = "pkg:npm/lodash".to_owned();
        let doc = generate_cyclonedx("test-project", "1.7", &components);
        let validation = validate_ntia_minimum_elements("cyclonedx-1.7-json", &doc);

        assert!(!validation.valid);
        assert!(
            validation
                .issues
                .iter()
                .any(|issue| issue.contains("components[0].version"))
        );
    }

    #[test]
    fn validate_generate_request_rejects_blank_source() {
        let request = GenerateSbomRequest {
            source: "   ".to_owned(),
            format: SbomFormatSpec::CycloneDx17,
            components: sample_components(),
            analysis_job_id: None,
            tenant_id: None,
        };

        let error = validate_generate_request(&request).unwrap_err();
        assert!(matches!(error, ApiError::InvalidRequest(_)));
        assert!(error.to_string().contains("source must not be empty"));
    }

    #[test]
    fn validate_generate_request_rejects_blank_component_purl() {
        let mut components = sample_components();
        components[0].purl = " ".to_owned();
        let request = GenerateSbomRequest {
            source: "test-project".to_owned(),
            format: SbomFormatSpec::CycloneDx17,
            components,
            analysis_job_id: None,
            tenant_id: None,
        };

        let error = validate_generate_request(&request).unwrap_err();
        assert!(matches!(error, ApiError::InvalidRequest(_)));
        assert!(error.to_string().contains("components[0].purl"));
    }

    #[test]
    fn validate_generate_request_rejects_component_ecosystem_mismatch() {
        let mut components = sample_components();
        components[0].ecosystem = PackageEcosystem::Cargo;
        let request = GenerateSbomRequest {
            source: "test-project".to_owned(),
            format: SbomFormatSpec::CycloneDx17,
            components,
            analysis_job_id: None,
            tenant_id: None,
        };

        let error = validate_generate_request(&request).unwrap_err();
        assert!(matches!(error, ApiError::InvalidRequest(_)));
        assert!(error.to_string().contains("components[0].ecosystem"));
    }

    #[test]
    fn generate_cyclonedx_uses_purl_version_when_explicit_version_is_missing() {
        let mut components = sample_components();
        components[0].version = None;

        let doc = generate_cyclonedx("test-project", "1.7", &components);
        let generated_components = doc["components"].as_array().unwrap();

        assert_eq!(generated_components[0]["version"], "4.17.21");
    }
}

#[test]
fn validate_generate_request_allows_analysis_job_without_inline_components() {
    let request = GenerateSbomRequest {
        source: "analysis-job".to_owned(),
        format: SbomFormatSpec::CycloneDx17,
        components: Vec::new(),
        analysis_job_id: Some(Uuid::new_v4()),
        tenant_id: None,
    };

    assert!(validate_generate_request(&request).is_ok());
}

#[test]
fn validate_generate_request_rejects_empty_components_without_analysis_job() {
    let request = GenerateSbomRequest {
        source: "analysis-job".to_owned(),
        format: SbomFormatSpec::CycloneDx17,
        components: Vec::new(),
        analysis_job_id: None,
        tenant_id: None,
    };

    let error = validate_generate_request(&request).unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid request: components must not be empty when analysis_job_id is absent"
    );
}

#[test]
fn stored_fragment_components_applies_decision_context() {
    let fragment = json!({
        "components": [{
            "purl": "pkg:cargo/serde@1.0.217",
            "name": "serde",
            "ecosystem": "cargo",
            "version": "1.0.217",
            "namespace": null,
            "integrity": "sha256:abc123"
        }],
        "dependency_edges": []
    });

    let decided_at = DateTime::parse_from_rfc3339("2026-05-14T12:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let components =
        stored_fragment_components(&fragment, Some("ALLOW_WITH_WARNING"), Some(decided_at))
            .unwrap();

    assert_eq!(components.len(), 1);
    assert_eq!(components[0].decision, "ALLOW_WITH_WARNING");
    assert_eq!(
        components[0].decision_timestamp.as_deref(),
        Some("2026-05-14T12:00:00Z")
    );
}

#[test]
fn stored_fragment_components_defaults_decision_to_unknown() {
    let fragment = json!({
        "components": [{
            "purl": "pkg:npm/babel/core@7.29.0",
            "name": "core",
            "ecosystem": "npm",
            "version": "7.29.0",
            "namespace": "babel",
            "integrity": null
        }],
        "dependency_edges": []
    });

    let components = stored_fragment_components(&fragment, None, None).unwrap();

    assert_eq!(components.len(), 1);
    assert_eq!(components[0].decision, "unknown");
    assert_eq!(components[0].namespace.as_deref(), Some("babel"));
    assert!(components[0].decision_timestamp.is_none());
}
