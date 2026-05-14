use std::fs;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::Duration;

use aegiscudo_core::{
    AnalysisJob, ArtifactDigest, JobState, PackageCoordinate, PackageEcosystem, Severity,
    StaticEvidence, StaticIndicator,
};
use anyhow::{Context, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use jsonschema::JSONSchema;
use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use tempfile::tempdir;
use tokio::task;
use url::Url;
use uuid::Uuid;

use crate::{ArtifactFileManifestEntry, ScanLimits, scan_artifact_package};

const MAX_INLINE_STATIC_REPORT_BYTES: usize = 64 * 1024;
const STATIC_REPORT_EMBEDDING_DIMENSIONS: usize = 1536;
const STATIC_REPORT_EMBEDDING_MAX_TOKENS: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExternalizedStaticReport {
    storage_uri: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct WorkerConfig {
    pub database_url: String,
    pub artifact_store_dir: PathBuf,
    pub max_retries: u16,
    pub scan_limits: ScanLimits,
    /// Maximum wall-clock seconds allowed for the unpack-and-scan phase.
    /// Defaults to 300 seconds (5 minutes). Jobs that exceed this limit are
    /// marked as failures with a `scan-timeout` audit event.
    pub scan_timeout_secs: u64,
}

#[derive(Debug, Clone)]
struct ClaimedJob {
    job: AnalysisJob,
    upstream_url: String,
    auth_type: RegistryAuthType,
    credential_env_var: Option<String>,
    verify_upstream_tls: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistryAuthType {
    None,
    Basic,
    Bearer,
    Mtls,
}

pub async fn process_next_analysis_job(
    config: &WorkerConfig,
) -> anyhow::Result<Option<AnalysisJob>> {
    let pool = PgPool::connect(&config.database_url)
        .await
        .context("connecting surgeon worker to PostgreSQL")?;
    process_next_analysis_job_with_pool(&pool, config).await
}

async fn process_next_analysis_job_with_pool(
    pool: &PgPool,
    config: &WorkerConfig,
) -> anyhow::Result<Option<AnalysisJob>> {
    let Some(claimed) = claim_next_job(pool).await? else {
        return Ok(None);
    };

    emit_job_audit_event(
        pool,
        &claimed.job,
        "analysis.job.fetching",
        json!({
            "state": "fetching",
            "source_host": Url::parse(&claimed.job.source_url)
                .ok()
                .and_then(|url| url.host_str().map(str::to_owned)),
        }),
    )
    .await?;

    let result = process_claimed_job(pool, config, &claimed).await;
    match result {
        Ok(()) => Ok(Some(claimed.job)),
        Err(error) => {
            mark_job_failure(pool, claimed.job.id, config.max_retries)
                .await
                .context("recording analysis job failure")?;
            let next_retry_count = claimed.job.retry_count.saturating_add(1);
            emit_job_audit_event(
                pool,
                &claimed.job,
                if next_retry_count >= config.max_retries {
                    "analysis.job.failed"
                } else {
                    "analysis.job.requeued"
                },
                json!({
                    "state": if next_retry_count >= config.max_retries { "failed" } else { "queued" },
                    "retry_count": next_retry_count,
                }),
            )
            .await?;
            Err(error)
        }
    }
}

async fn claim_next_job(pool: &PgPool) -> anyhow::Result<Option<ClaimedJob>> {
    let row = sqlx::query(
        r#"
        WITH candidate AS (
          SELECT id
          FROM analysis_jobs
          WHERE state = 'queued'::analysis_job_state
            AND registry_config_id IS NOT NULL
            AND source_url IS NOT NULL
                        AND (
                            retry_count = 0
                            OR updated_at <= now()
                                - make_interval(
                                        secs => LEAST(
                                            300,
                                            CAST(power(2::numeric, GREATEST(retry_count - 1, 0)) AS integer)
                                        )
                                    )
                        )
          ORDER BY created_at ASC
          FOR UPDATE SKIP LOCKED
          LIMIT 1
        )
        UPDATE analysis_jobs AS jobs
        SET state = 'fetching'::analysis_job_state,
            updated_at = now()
        FROM candidate
        WHERE jobs.id = candidate.id
        RETURNING jobs.id,
                  jobs.tenant_id,
                  jobs.registry_config_id,
                  jobs.policy_version_id,
                  jobs.ecosystem::text AS ecosystem,
                  jobs.namespace,
                  jobs.package_name,
                  jobs.package_version,
                  jobs.artifact_sha256,
                  jobs.source_url,
                  jobs.retry_count,
                  jobs.trace_id,
                  jobs.created_at,
                  jobs.updated_at
        "#,
    )
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    let tenant_id: Uuid = row.try_get("tenant_id")?;
    let registry_config_id: Uuid = row.try_get("registry_config_id")?;
    let source_url: String = row.try_get("source_url")?;
    let ecosystem = PackageEcosystem::from_str(row.try_get::<String, _>("ecosystem")?.as_str())
        .map_err(|error| anyhow!(error.to_string()))?;
    let coordinate = PackageCoordinate::new(
        ecosystem,
        row.try_get::<String, _>("package_name")?,
        row.try_get::<Option<String>, _>("package_version")?,
        row.try_get::<Option<String>, _>("namespace")?,
    );
    let artifact_digest = ArtifactDigest::sha256(row.try_get::<String, _>("artifact_sha256")?)?;

    let registry_row = sqlx::query(
        r#"
        SELECT
          registry_configs.upstream_url,
          registry_configs.auth_type::text AS auth_type,
          registry_configs.verify_upstream_tls,
          credential.name AS credential_env_var
        FROM registry_configs
        LEFT JOIN integration_credentials credential
          ON credential.tenant_id = registry_configs.tenant_id
         AND credential.id = registry_configs.credential_ref
        WHERE registry_configs.tenant_id = $1
          AND registry_configs.id = $2
          AND registry_configs.enabled = true
          AND registry_configs.deleted_at IS NULL
        "#,
    )
    .bind(tenant_id)
    .bind(registry_config_id)
    .fetch_one(pool)
    .await?;

    let job = AnalysisJob {
        id: row.try_get("id")?,
        tenant_id,
        registry_config_id,
        coordinate,
        artifact_digest,
        source_url: source_url.clone(),
        policy_snapshot_id: row.try_get("policy_version_id")?,
        state: JobState::Fetching,
        retry_count: row.try_get::<i32, _>("retry_count")? as u16,
        trace_id: row.try_get("trace_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    };

    Ok(Some(ClaimedJob {
        job,
        upstream_url: registry_row.try_get("upstream_url")?,
        auth_type: registry_auth_type_from_db(registry_row.try_get("auth_type")?)?,
        credential_env_var: registry_row.try_get("credential_env_var")?,
        verify_upstream_tls: registry_row.try_get("verify_upstream_tls")?,
    }))
}

async fn process_claimed_job(
    pool: &PgPool,
    config: &WorkerConfig,
    claimed: &ClaimedJob,
) -> anyhow::Result<()> {
    validate_source_url(&claimed.upstream_url, &claimed.job.source_url)?;
    let (artifact_bytes, file_name) = fetch_artifact_bytes(claimed).await?;

    let fetched_digest = hex::encode(Sha256::digest(&artifact_bytes));
    if fetched_digest != claimed.job.artifact_digest.hex {
        anyhow::bail!("artifact digest mismatch during analysis fetch");
    }

    let storage_path = artifact_storage_path(
        &config.artifact_store_dir,
        claimed.job.tenant_id,
        &claimed.job.artifact_digest.hex,
        &file_name,
    );
    if let Some(parent) = storage_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&storage_path, &artifact_bytes)?;
    let storage_uri = file_storage_uri(&storage_path)?;

    update_job_state(pool, claimed.job.id, JobState::StaticRunning).await?;

    let unpack_dir = tempdir().context("creating temporary unpack directory")?;
    let scan_input_path = unpack_dir.path().join(&file_name);
    fs::write(&scan_input_path, &artifact_bytes)?;

    // Run the synchronous scan in a blocking thread pool so the async executor
    // is not blocked, and enforce a wall-clock timeout.
    let scan_limits = config.scan_limits;
    let scan_input_path_clone = scan_input_path.clone();
    let unpack_dir_path = unpack_dir.path().to_path_buf();
    let scan_future = task::spawn_blocking(move || {
        scan_artifact_package(&scan_input_path_clone, &unpack_dir_path, scan_limits)
    });
    let scan_result =
        tokio::time::timeout(Duration::from_secs(config.scan_timeout_secs), scan_future).await;

    let (report, manifest) = match scan_result {
        Ok(Ok(Ok(result))) => result,
        Ok(Ok(Err(err))) => {
            return Err(err.context(format!(
                "scanning artifact for analysis job {}",
                claimed.job.id
            )));
        }
        Ok(Err(join_err)) => {
            return Err(anyhow!(join_err).context(format!(
                "scan thread panicked for analysis job {}",
                claimed.job.id
            )));
        }
        Err(_elapsed) => {
            emit_job_audit_event(
                pool,
                &claimed.job,
                "analysis.job.scan_timeout",
                json!({
                    "state": "failed",
                    "reason": "scan-timeout",
                    "timeout_secs": config.scan_timeout_secs,
                }),
            )
            .await?;
            return Err(anyhow!(
                "scan timed out after {} seconds for analysis job {}",
                config.scan_timeout_secs,
                claimed.job.id
            ));
        }
    };
    let indicator_count = report.indicators.len();
    let manifest_entries = manifest.len();

    update_job_state(pool, claimed.job.id, JobState::Finalizing).await?;
    persist_static_report(
        pool,
        claimed,
        &config.artifact_store_dir,
        storage_uri,
        artifact_bytes.len() as u64,
        report,
        manifest,
    )
    .await?;
    update_job_state(pool, claimed.job.id, JobState::SandboxPending).await?;
    emit_job_audit_event(
        pool,
        &claimed.job,
        "analysis.job.sandbox_pending",
        json!({
            "state": "sandbox-pending",
            "indicator_count": indicator_count,
            "manifest_entries": manifest_entries,
        }),
    )
    .await?;
    Ok(())
}

async fn fetch_artifact_bytes(claimed: &ClaimedJob) -> anyhow::Result<(Vec<u8>, String)> {
    let source = Url::parse(&claimed.job.source_url)
        .with_context(|| format!("parsing analysis source URL {}", claimed.job.source_url))?;
    let file_name = source
        .path_segments()
        .and_then(|segments| segments.filter(|segment| !segment.is_empty()).next_back())
        .unwrap_or("artifact.bin")
        .to_owned();

    let mut request = reqwest::Client::builder()
        .danger_accept_invalid_certs(!claimed.verify_upstream_tls)
        .build()?
        .get(source.clone());
    if let Some(value) = upstream_authorization_value(claimed)? {
        request = request.header(AUTHORIZATION, value);
    }
    let response = request
        .send()
        .await
        .with_context(|| format!("fetching {} for analysis", source))?;
    let response = response
        .error_for_status()
        .with_context(|| format!("analysis fetch failed for {}", source))?;
    let bytes = response.bytes().await?.to_vec();
    Ok((bytes, file_name))
}

fn upstream_authorization_value(claimed: &ClaimedJob) -> anyhow::Result<Option<HeaderValue>> {
    let Some(env_var) = &claimed.credential_env_var else {
        return Ok(None);
    };
    let value = std::env::var(env_var)
        .with_context(|| format!("missing configured credential environment variable {env_var}"))?;
    match claimed.auth_type {
        RegistryAuthType::None => Ok(None),
        RegistryAuthType::Basic => {
            let encoded = BASE64_STANDARD.encode(value);
            Ok(Some(HeaderValue::from_str(&format!("Basic {encoded}"))?))
        }
        RegistryAuthType::Bearer => Ok(Some(HeaderValue::from_str(&format!("Bearer {value}"))?)),
        RegistryAuthType::Mtls => Err(anyhow!(
            "mTLS upstream fetch is not yet supported by Surgeon"
        )),
    }
}

async fn persist_static_report(
    pool: &PgPool,
    claimed: &ClaimedJob,
    artifact_store_dir: &Path,
    storage_uri: String,
    size_bytes: u64,
    report: StaticEvidence,
    manifest: Vec<ArtifactFileManifestEntry>,
) -> anyhow::Result<()> {
    let mut transaction = pool.begin().await?;
    let report_json = validated_static_report_json(&report)?;
    let embedding_literal = static_report_embedding_literal(&report);
    let sbom_fragment = package_sbom_fragment_json(
        &claimed.job.coordinate,
        &claimed.job.artifact_digest,
    );
    let externalized_report =
        maybe_externalize_static_report(artifact_store_dir, claimed.job.tenant_id, &report_json)?;

    let artifact_row = sqlx::query(
        r#"
        INSERT INTO artifacts (
          tenant_id,
          ecosystem,
          namespace,
          package_name,
          package_version,
          sha256,
          size_bytes,
          storage_uri
        )
        VALUES ($1, $2::package_ecosystem, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (tenant_id, sha256)
        DO UPDATE SET
          ecosystem = EXCLUDED.ecosystem,
          namespace = EXCLUDED.namespace,
          package_name = EXCLUDED.package_name,
          package_version = EXCLUDED.package_version,
          size_bytes = EXCLUDED.size_bytes,
          storage_uri = EXCLUDED.storage_uri
        RETURNING id
        "#,
    )
    .bind(claimed.job.tenant_id)
    .bind(claimed.job.coordinate.ecosystem.to_string())
    .bind(claimed.job.coordinate.namespace.clone())
    .bind(claimed.job.coordinate.name.clone())
    .bind(claimed.job.coordinate.version.clone())
    .bind(&claimed.job.artifact_digest.hex)
    .bind(i64::try_from(size_bytes).context("artifact too large to persist")?)
    .bind(&storage_uri)
    .fetch_one(&mut *transaction)
    .await?;
    let artifact_id: Uuid = artifact_row.try_get("id")?;

    sqlx::query("DELETE FROM artifact_files WHERE artifact_id = $1")
        .bind(artifact_id)
        .execute(&mut *transaction)
        .await?;

    for entry in manifest {
        sqlx::query(
            r#"
            INSERT INTO artifact_files (artifact_id, path, sha256, size_bytes)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(artifact_id)
        .bind(entry.path)
        .bind(entry.sha256)
        .bind(i64::try_from(entry.size_bytes).context("artifact file too large to persist")?)
        .execute(&mut *transaction)
        .await?;
    }

    sqlx::query(
        r#"
        INSERT INTO static_analysis_reports (
          analysis_job_id,
          artifact_id,
          policy_version_id,
                    embedding,
          report,
          report_storage_uri,
          report_storage_sha256,
          report_storage_size_bytes
        )
                VALUES ($1, $2, $3, $4::vector, $5, $6, $7, $8)
        "#,
    )
    .bind(claimed.job.id)
    .bind(artifact_id)
    .bind(claimed.job.policy_snapshot_id)
        .bind(embedding_literal.as_deref())
    .bind(sqlx::types::Json(report_json))
    .bind(
        externalized_report
            .as_ref()
            .map(|report| report.storage_uri.as_str()),
    )
    .bind(
        externalized_report
            .as_ref()
            .map(|report| report.sha256.as_str()),
    )
    .bind(
        externalized_report
            .as_ref()
            .map(|report| i64::try_from(report.size_bytes))
            .transpose()
            .context("static report too large to persist")?,
    )
    .execute(&mut *transaction)
    .await?;

        sqlx::query(
                r#"
                INSERT INTO analysis_sbom_fragments (
                    analysis_job_id,
                    artifact_id,
                    tenant_id,
                    source,
                    fragment
                )
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (analysis_job_id, artifact_id)
                DO UPDATE SET
                    tenant_id = EXCLUDED.tenant_id,
                    source = EXCLUDED.source,
                    fragment = EXCLUDED.fragment
                "#,
        )
        .bind(claimed.job.id)
        .bind(artifact_id)
        .bind(claimed.job.tenant_id)
        .bind(claimed.job.coordinate.purl())
        .bind(sqlx::types::Json(sbom_fragment))
        .execute(&mut *transaction)
        .await?;

    sqlx::query(
        r#"
        UPDATE analysis_jobs
        SET artifact_id = $2,
            updated_at = now()
        WHERE id = $1
        "#,
    )
    .bind(claimed.job.id)
    .bind(artifact_id)
    .execute(&mut *transaction)
    .await?;

    transaction.commit().await?;
    Ok(())
}

async fn update_job_state(pool: &PgPool, job_id: Uuid, state: JobState) -> anyhow::Result<()> {
    let state_value = match state {
        JobState::Queued => "queued",
        JobState::Fetching => "fetching",
        JobState::StaticRunning => "static-running",
        JobState::SandboxPending => "sandbox-pending",
        JobState::SandboxRunning => "sandbox-running",
        JobState::AiPending => "ai-pending",
        JobState::Finalizing => "finalizing",
        JobState::Completed => "completed",
        JobState::Failed => "failed",
        JobState::Cancelled => "cancelled",
    };
    sqlx::query(
        r#"
        UPDATE analysis_jobs
        SET state = $2::analysis_job_state,
            updated_at = now()
        WHERE id = $1
        "#,
    )
    .bind(job_id)
    .bind(state_value)
    .execute(pool)
    .await?;
    Ok(())
}

async fn mark_job_failure(pool: &PgPool, job_id: Uuid, max_retries: u16) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        UPDATE analysis_jobs
        SET retry_count = retry_count + 1,
            state = CASE
              WHEN retry_count + 1 >= $2 THEN 'failed'::analysis_job_state
              ELSE 'queued'::analysis_job_state
            END,
            updated_at = now()
        WHERE id = $1
        "#,
    )
    .bind(job_id)
    .bind(i32::from(max_retries))
    .execute(pool)
    .await?;
    Ok(())
}

fn validate_source_url(upstream_url: &str, source_url: &str) -> anyhow::Result<()> {
    let upstream = Url::parse(upstream_url)?;
    let source = Url::parse(source_url)?;
    if upstream.scheme() != source.scheme()
        || upstream.host_str() != source.host_str()
        || upstream.port_or_known_default() != source.port_or_known_default()
    {
        anyhow::bail!("analysis source URL escapes the configured upstream origin");
    }
    let upstream_path = upstream.path().trim_end_matches('/');
    if !upstream_path.is_empty()
        && upstream_path != "/"
        && !(source.path() == upstream_path
            || source.path().starts_with(&format!("{upstream_path}/")))
    {
        anyhow::bail!("analysis source URL escapes the configured upstream path prefix");
    }
    Ok(())
}

fn artifact_storage_path(
    artifact_store_dir: &Path,
    tenant_id: Uuid,
    digest: &str,
    file_name: &str,
) -> PathBuf {
    let extension = Path::new(file_name)
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| format!(".{value}"))
        .unwrap_or_default();
    artifact_store_dir
        .join(tenant_id.to_string())
        .join(format!("{digest}{extension}"))
}

fn file_storage_uri(path: &Path) -> anyhow::Result<String> {
    Url::from_file_path(path)
        .map(|url| url.to_string())
        .map_err(|_| anyhow!("failed to convert artifact path to storage URI"))
}

fn static_report_storage_path(artifact_store_dir: &Path, tenant_id: Uuid, digest: &str) -> PathBuf {
    artifact_store_dir
        .join(tenant_id.to_string())
        .join("static-reports")
        .join(format!("{digest}.json"))
}

fn registry_auth_type_from_db(value: String) -> anyhow::Result<RegistryAuthType> {
    match value.as_str() {
        "none" => Ok(RegistryAuthType::None),
        "basic" => Ok(RegistryAuthType::Basic),
        "bearer" => Ok(RegistryAuthType::Bearer),
        "mtls" => Ok(RegistryAuthType::Mtls),
        _ => Err(anyhow!("unsupported registry auth type {value}")),
    }
}

fn validated_static_report_json(report: &StaticEvidence) -> anyhow::Result<Value> {
    let report_json = serde_json::to_value(report).context("serializing static evidence report")?;
    static_evidence_schema()
        .validate(&report_json)
        .map_err(|errors| {
            let messages = errors.map(|error| error.to_string()).collect::<Vec<_>>();
            anyhow!(
                "static evidence report does not satisfy evidence.schema.json: {}",
                messages.join("; ")
            )
        })?;
    Ok(report_json)
}

fn package_sbom_fragment_json(
    coordinate: &PackageCoordinate,
    artifact_digest: &ArtifactDigest,
) -> Value {
    json!({
        "source": "surgeon-static-analysis",
        "components": [{
            "purl": coordinate.purl(),
            "name": coordinate.name,
            "ecosystem": coordinate.ecosystem.to_string(),
            "version": coordinate.version,
            "namespace": coordinate.namespace,
            "integrity": format!("sha256:{}", artifact_digest.hex),
        }],
        "dependency_edges": [],
    })
}

fn static_report_embedding_literal(report: &StaticEvidence) -> Option<String> {
    let mut embedding = vec![0_f32; STATIC_REPORT_EMBEDDING_DIMENSIONS];
    let mut token_count = 0_usize;

    for indicator in &report.indicators {
        for token in static_indicator_embedding_tokens(indicator) {
            let digest = Sha256::digest(token.as_bytes());
            let dimension =
                usize::from(u16::from_be_bytes([digest[0], digest[1]]))
                    % STATIC_REPORT_EMBEDDING_DIMENSIONS;
            let sign = if digest[2] & 1 == 0 { 1_f32 } else { -1_f32 };
            embedding[dimension] += sign;
            token_count += 1;

            if token_count >= STATIC_REPORT_EMBEDDING_MAX_TOKENS {
                break;
            }
        }

        if token_count >= STATIC_REPORT_EMBEDDING_MAX_TOKENS {
            break;
        }
    }

    if token_count == 0 {
        return None;
    }

    let magnitude = embedding.iter().map(|value| value * value).sum::<f32>().sqrt();
    if magnitude <= f32::EPSILON {
        return None;
    }

    for value in &mut embedding {
        *value /= magnitude;
    }

    Some(vector_literal(&embedding))
}

fn static_indicator_embedding_tokens(indicator: &StaticIndicator) -> Vec<String> {
    let mut tokens = Vec::new();
    append_embedding_tokens(&mut tokens, &indicator.indicator_type);
    append_embedding_tokens(&mut tokens, severity_token(&indicator.severity));
    append_embedding_tokens(&mut tokens, &indicator.file_path);
    append_embedding_tokens(&mut tokens, &indicator.summary);
    append_embedding_tokens(&mut tokens, &indicator.summary);

    if let Some(details) = &indicator.details {
        if let Some(destination) = details.destination.as_deref() {
            append_embedding_tokens(&mut tokens, destination);
        }
        if let Some(destination_raw) = details.destination_raw.as_deref() {
            append_embedding_tokens(&mut tokens, destination_raw);
        }
        if let Some(payload_hint) = details.payload_hint.as_deref() {
            append_embedding_tokens(&mut tokens, payload_hint);
        }
    }

    tokens
}

fn append_embedding_tokens(tokens: &mut Vec<String>, text: &str) {
    for raw_token in text.split(|character: char| !character.is_ascii_alphanumeric()) {
        let normalized = raw_token.trim().to_ascii_lowercase();
        if normalized.len() >= 2 {
            tokens.push(normalized);
        }
    }
}

fn severity_token(severity: &Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn vector_literal(values: &[f32]) -> String {
    let mut literal = String::with_capacity(values.len() * 10);
    literal.push('[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            literal.push(',');
        }
        write!(&mut literal, "{value:.6}").expect("writing vector literal to String");
    }
    literal.push(']');
    literal
}

fn maybe_externalize_static_report(
    artifact_store_dir: &Path,
    tenant_id: Uuid,
    report_json: &Value,
) -> anyhow::Result<Option<ExternalizedStaticReport>> {
    let report_bytes =
        serde_json::to_vec(report_json).context("serializing static evidence bytes")?;
    if report_bytes.len() <= MAX_INLINE_STATIC_REPORT_BYTES {
        return Ok(None);
    }

    let digest = hex::encode(Sha256::digest(&report_bytes));
    let storage_path = static_report_storage_path(artifact_store_dir, tenant_id, &digest);
    if let Some(parent) = storage_path.parent() {
        fs::create_dir_all(parent).context("creating static report storage directory")?;
    }
    fs::write(&storage_path, &report_bytes).context("writing static report to object storage")?;

    Ok(Some(ExternalizedStaticReport {
        storage_uri: file_storage_uri(&storage_path)?,
        sha256: digest,
        size_bytes: report_bytes.len() as u64,
    }))
}

fn static_evidence_schema() -> &'static JSONSchema {
    static STATIC_EVIDENCE_SCHEMA: OnceLock<JSONSchema> = OnceLock::new();
    STATIC_EVIDENCE_SCHEMA.get_or_init(|| {
        let schema_json: Value =
            serde_json::from_str(include_str!("../../../schemas/evidence.schema.json"))
                .expect("evidence schema should parse");
        JSONSchema::compile(&schema_json).expect("evidence schema should compile")
    })
}

async fn emit_job_audit_event(
    pool: &PgPool,
    job: &AnalysisJob,
    action: &str,
    metadata: serde_json::Value,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO audit_events (tenant_id, actor, action, resource, trace_id, metadata)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(job.tenant_id)
    .bind("surgeon")
    .bind(action)
    .bind(format!("analysis-job/{}", job.id))
    .bind(&job.trace_id)
    .bind(sqlx::types::Json(metadata))
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use aegiscudo_core::{
        ArtifactDigest, PackageCoordinate, PackageEcosystem, Severity, StaticIndicator,
    };
    use serde_json::json;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn accepts_source_url_under_upstream_prefix() {
        validate_source_url(
            "https://files.pythonhosted.org/packages/",
            "https://files.pythonhosted.org/packages/aa/bb/pkg.whl",
        )
        .unwrap();
    }

    #[test]
    fn rejects_source_url_outside_upstream_prefix() {
        let error = validate_source_url(
            "https://registry.npmjs.org/",
            "https://evil.example.com/left-pad/-/left-pad-1.3.0.tgz",
        )
        .unwrap_err();
        assert!(error.to_string().contains("configured upstream origin"));
    }

    #[test]
    fn derives_digest_keyed_storage_path() {
        let path = artifact_storage_path(
            Path::new("/tmp/aegiscudo-artifacts-local"),
            Uuid::nil(),
            "aabb",
            "left-pad-1.3.0.tgz",
        );
        assert!(
            path.to_string_lossy()
                .ends_with("00000000-0000-0000-0000-000000000000/aabb.tgz")
        );
    }

    #[test]
    fn derives_static_report_storage_path() {
        let path = static_report_storage_path(
            Path::new("/tmp/aegiscudo-artifacts-local"),
            Uuid::nil(),
            "bbcc",
        );
        assert!(
            path.to_string_lossy()
                .ends_with("00000000-0000-0000-0000-000000000000/static-reports/bbcc.json")
        );
    }

    #[test]
    fn static_report_embedding_literal_is_deterministic() {
        let report = sample_static_report("child process execution detected");

        let first = static_report_embedding_literal(&report).unwrap();
        let second = static_report_embedding_literal(&report).unwrap();

        assert_eq!(first, second);
        assert_eq!(parse_vector_literal(&first).len(), STATIC_REPORT_EMBEDDING_DIMENSIONS);
    }

    #[test]
    fn static_report_embedding_literal_returns_none_without_indicator_tokens() {
        let report = StaticEvidence {
            artifact_digest: ArtifactDigest::sha256("a".repeat(64)).unwrap(),
            analyzer_version: "0.1.0".to_owned(),
            rule_set_version: "mvp-static-rules-2026-05".to_owned(),
            indicators: Vec::new(),
        };

        assert!(static_report_embedding_literal(&report).is_none());
    }

    #[test]
    fn static_report_embedding_literal_changes_for_distinct_indicator_text() {
        let first = sample_static_report("child process execution detected");
        let second = sample_static_report("curl download plus shell execution observed");

        assert_ne!(
            static_report_embedding_literal(&first),
            static_report_embedding_literal(&second)
        );
    }

    #[test]
    fn package_sbom_fragment_json_emits_root_component_fields() {
        let coordinate = PackageCoordinate::new(
            PackageEcosystem::Cargo,
            "serde",
            Some("1.0.217"),
            None::<String>,
        );
        let artifact_digest = ArtifactDigest::sha256("b".repeat(64)).unwrap();

        let fragment = package_sbom_fragment_json(&coordinate, &artifact_digest);

        assert_eq!(fragment["source"], "surgeon-static-analysis");
        assert_eq!(fragment["components"][0]["purl"], "pkg:cargo/serde@1.0.217");
        assert_eq!(fragment["components"][0]["name"], "serde");
        assert_eq!(fragment["components"][0]["ecosystem"], "cargo");
        assert_eq!(fragment["components"][0]["version"], "1.0.217");
        assert_eq!(
            fragment["components"][0]["integrity"],
            format!("sha256:{}", artifact_digest.hex)
        );
        assert_eq!(fragment["dependency_edges"], json!([]));
    }

    #[test]
    fn package_sbom_fragment_json_preserves_namespace_when_present() {
        let coordinate = PackageCoordinate::new(
            PackageEcosystem::Npm,
            "core",
            Some("7.29.0"),
            Some("babel"),
        );
        let artifact_digest = ArtifactDigest::sha256("c".repeat(64)).unwrap();

        let fragment = package_sbom_fragment_json(&coordinate, &artifact_digest);

        assert_eq!(fragment["components"][0]["purl"], "pkg:npm/babel/core@7.29.0");
        assert_eq!(fragment["components"][0]["namespace"], "babel");
    }

    #[test]
    fn validated_static_report_json_accepts_schema_valid_report() {
        let report = StaticEvidence {
            artifact_digest: ArtifactDigest::sha256("a".repeat(64)).unwrap(),
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
        };

        let json = validated_static_report_json(&report).unwrap();
        assert_eq!(
            json.get("analyzer_version").and_then(Value::as_str),
            Some("0.1.0")
        );
    }

    fn sample_static_report(summary: &str) -> StaticEvidence {
        StaticEvidence {
            artifact_digest: ArtifactDigest::sha256("a".repeat(64)).unwrap(),
            analyzer_version: "0.1.0".to_owned(),
            rule_set_version: "mvp-static-rules-2026-05".to_owned(),
            indicators: vec![StaticIndicator {
                indicator_type: "node-child-process".to_owned(),
                severity: Severity::High,
                file_path: "package/preinstall.js".to_owned(),
                start_line: 1,
                end_line: 1,
                redacted: true,
                summary: summary.to_owned(),
                details: None,
            }],
        }
    }

    fn parse_vector_literal(literal: &str) -> Vec<f32> {
        literal
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split(',')
            .filter(|value| !value.is_empty())
            .map(|value| value.parse::<f32>().unwrap())
            .collect()
    }

    #[test]
    fn static_evidence_schema_rejects_invalid_severity() {
        let invalid = json!({
            "artifact_digest": {"algorithm": "sha256", "hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            "analyzer_version": "0.1.0",
            "rule_set_version": "mvp-static-rules-2026-05",
            "indicators": [{
                "indicator_type": "node-child-process",
                "severity": "urgent",
                "file_path": "package/preinstall.js",
                "start_line": 1,
                "end_line": 1,
                "redacted": true,
                "summary": "child process execution detected"
            }]
        });

        assert!(!static_evidence_schema().is_valid(&invalid));
    }

    #[test]
    fn skips_external_storage_for_small_static_reports() {
        let temp_dir = tempfile::tempdir().unwrap();
        let report_json = json!({
            "artifact_digest": {"algorithm": "sha256", "hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            "analyzer_version": "0.1.0",
            "rule_set_version": "mvp-static-rules-2026-05",
            "indicators": []
        });

        let externalized =
            maybe_externalize_static_report(temp_dir.path(), Uuid::nil(), &report_json).unwrap();
        assert!(externalized.is_none());
    }

    #[test]
    fn stores_large_static_reports_in_object_storage() {
        let temp_dir = tempfile::tempdir().unwrap();
        let large_summary = "x".repeat(MAX_INLINE_STATIC_REPORT_BYTES + 32);
        let report_json = json!({
            "artifact_digest": {"algorithm": "sha256", "hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            "analyzer_version": "0.1.0",
            "rule_set_version": "mvp-static-rules-2026-05",
            "indicators": [{
                "indicator_type": "node-child-process",
                "severity": "high",
                "file_path": "package/preinstall.js",
                "start_line": 1,
                "end_line": 1,
                "redacted": true,
                "summary": large_summary
            }]
        });

        let externalized =
            maybe_externalize_static_report(temp_dir.path(), Uuid::nil(), &report_json)
                .unwrap()
                .unwrap();

        assert_eq!(
            externalized.size_bytes as usize,
            serde_json::to_vec(&report_json).unwrap().len()
        );
        assert!(
            externalized
                .storage_uri
                .ends_with(&format!("/static-reports/{}.json", externalized.sha256))
        );
    }
}
