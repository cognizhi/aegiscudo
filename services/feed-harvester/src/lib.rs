use std::{collections::BTreeSet, path::PathBuf, sync::Arc, time::Instant};

use aegiscudo_core::{ArtifactDigest, FeedState};
use aegiscudo_telemetry::health;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderValue, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, NaiveDate, Utc};
use prometheus::{Encoder, IntCounterVec, IntGaugeVec, Opts, Registry, TextEncoder};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row, postgres::PgPoolOptions, types::Json as SqlxJson};
use thiserror::Error;
use uuid::Uuid;

pub const SERVICE_NAME: &str = "feed-harvester";
const FEED_HTTP_TIMEOUT_SECS: u64 = 20;
const FEEDS: &[FeedSource] = &[
    FeedSource::Osv,
    FeedSource::Ghsa,
    FeedSource::OpenSsfMaliciousPackages,
    FeedSource::OpenSsfPackageAnalysis,
    FeedSource::CisaKev,
    FeedSource::FirstEpss,
    FeedSource::DepsDev,
    FeedSource::OpenSsfScorecard,
];
const IOC_INDICATOR_MAINTAINER_IDENTITY: &str = "maintainer-identity";
const IOC_INDICATOR_DOMAIN: &str = "domain";
const IOC_INDICATOR_IP: &str = "ip";
const IOC_INDICATOR_URL: &str = "url";
const IOC_INDICATOR_PACKAGE_NAME: &str = "package-name";
const IOC_INDICATOR_BEHAVIORAL_FINGERPRINT: &str = "behavioral-fingerprint";

#[derive(Debug, Clone)]
pub struct AppState {
    pool: PgPool,
    fixture_dir: PathBuf,
    metrics: FeedMetrics,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct LiveFeedSources {
    deps_dev_url: Option<String>,
    deps_dev_api_base_url: Option<String>,
    openssf_scorecard_url: Option<String>,
}

impl LiveFeedSources {
    fn from_env() -> Self {
        Self {
            deps_dev_url: std::env::var("FEED_HARVESTER_DEPS_DEV_URL").ok(),
            deps_dev_api_base_url: std::env::var("FEED_HARVESTER_DEPS_DEV_API_BASE_URL").ok(),
            openssf_scorecard_url: std::env::var("FEED_HARVESTER_OPENSSF_SCORECARD_URL").ok(),
        }
    }

    fn url_for(&self, feed: FeedSource) -> Option<&str> {
        match feed {
            FeedSource::DepsDev => self.deps_dev_url.as_deref(),
            FeedSource::OpenSsfScorecard => self.openssf_scorecard_url.as_deref(),
            _ => None,
        }
    }

    fn deps_dev_api_base_url(&self) -> &str {
        self.deps_dev_api_base_url
            .as_deref()
            .unwrap_or("https://api.deps.dev/v3")
    }
}

pub async fn connect(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
}

pub fn app(pool: PgPool, fixture_dir: PathBuf) -> Router {
    let state = Arc::new(AppState {
        pool,
        fixture_dir,
        metrics: FeedMetrics::new().expect("feed harvester metrics must initialize"),
    });
    Router::new()
        .route("/healthz", get(|| async { Json(health(SERVICE_NAME)) }))
        .route("/readyz", get(|| async { Json(health(SERVICE_NAME)) }))
        .route("/metrics", get(metrics))
        .route("/v1/feeds/refresh", post(refresh_feeds))
        .route("/v1/feeds/status", get(feed_status))
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
            tracing::error!(error = %error, "failed to render feed harvester metrics");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn refresh_feeds(
    State(state): State<Arc<AppState>>,
) -> Result<Json<RefreshFeedsResponse>, ApiError> {
    let started = Instant::now();
    let snapshots = refresh_fixture_feeds(&state.pool, &state.fixture_dir).await?;
    for snapshot in &snapshots {
        state.metrics.observe_snapshot(&snapshot);
    }
    state
        .metrics
        .observe_refresh("success", started.elapsed().as_millis() as i64);
    Ok(Json(RefreshFeedsResponse { snapshots }))
}

pub async fn refresh_fixture_feeds(
    pool: &PgPool,
    fixture_dir: &std::path::Path,
) -> Result<Vec<FeedSnapshotResponse>, ApiError> {
    let live_sources = LiveFeedSources::from_env();
    let http_client = build_http_client()?;
    let mut snapshots = Vec::new();
    for feed in FEEDS {
        snapshots.push(
            ingest_feed_fixture(pool, fixture_dir, &http_client, &live_sources, *feed).await?,
        );
    }
    Ok(snapshots)
}

async fn feed_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<FeedSnapshotResponse>>, ApiError> {
    let feed_names = FEEDS
        .iter()
        .map(|feed| feed.name().to_owned())
        .collect::<Vec<_>>();
    let rows = sqlx::query(
        r#"
        SELECT DISTINCT ON (feed_name)
          id, feed_name, state::text AS state, normalized_record_count,
          snapshot_digest, last_success_at, created_at
        FROM feed_snapshots
        WHERE feed_name = ANY($1)
        ORDER BY feed_name, created_at DESC
        "#,
    )
    .bind(feed_names)
    .fetch_all(&state.pool)
    .await?;
    rows.iter()
        .map(feed_snapshot_response_from_row)
        .collect::<Result<Vec<_>, _>>()
        .map(Json)
}

async fn ingest_feed_fixture(
    pool: &PgPool,
    fixture_dir: &std::path::Path,
    http_client: &Client,
    live_sources: &LiveFeedSources,
    feed: FeedSource,
) -> Result<FeedSnapshotResponse, ApiError> {
    let now = Utc::now();
    let (state, maybe_bytes) =
        load_feed_snapshot_bytes(fixture_dir, http_client, live_sources, feed).await?;
    let (record_count, digest, last_success_at) = match maybe_bytes.as_deref() {
        Some(bytes) => {
            let record_count = normalized_record_count(feed, &bytes)?;
            let digest = sha256_digest(&bytes)?;
            let last_success_at = matches!(state, FeedState::Fresh).then_some(now);
            (record_count, digest, last_success_at)
        }
        None => {
            let digest = sha256_digest(feed.name().as_bytes())?;
            (0, digest, None)
        }
    };

    let mut transaction = pool.begin().await?;

    let row = sqlx::query(
        r#"
        INSERT INTO feed_snapshots (
          tenant_id, feed_name, state, normalized_record_count, snapshot_digest, last_success_at
        )
        VALUES (NULL, $1, $2::feed_state, $3, $4, $5)
        RETURNING id, feed_name, state::text AS state, normalized_record_count,
                  snapshot_digest, last_success_at, created_at
        "#,
    )
    .bind(feed.name())
    .bind(feed_state_db_value(&state))
    .bind(record_count as i64)
    .bind(&digest.hex)
    .bind(last_success_at)
    .fetch_one(&mut *transaction)
    .await?;

    let snapshot_id: Uuid = row.try_get("id")?;
    if let Some(bytes) = maybe_bytes.as_deref() {
        persist_feed_records(&mut transaction, snapshot_id, feed, bytes).await?;
    }

    transaction.commit().await?;
    Ok(feed_snapshot_response_from_row(&row)?)
}

async fn persist_feed_records(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    snapshot_id: Uuid,
    feed: FeedSource,
    bytes: &[u8],
) -> Result<(), ApiError> {
    match feed {
        FeedSource::DepsDev => persist_deps_dev_records(transaction, snapshot_id, bytes).await,
        FeedSource::OpenSsfScorecard => {
            persist_scorecard_records(transaction, snapshot_id, bytes).await
        }
        FeedSource::OpenSsfMaliciousPackages | FeedSource::OpenSsfPackageAnalysis => {
            persist_cross_ecosystem_ioc_records(transaction, snapshot_id, feed, bytes).await
        }
        _ => Ok(()),
    }
}

async fn persist_cross_ecosystem_ioc_records(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    snapshot_id: Uuid,
    feed: FeedSource,
    bytes: &[u8],
) -> Result<(), ApiError> {
    let value = serde_json::from_slice::<Value>(bytes)?;
    for record in cross_ecosystem_ioc_records(feed, &value) {
        sqlx::query(
            r#"
            INSERT INTO cross_ecosystem_ioc_records (
              snapshot_id, ecosystem, namespace, package_name, package_version,
              indicator_type, indicator_value, details
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(snapshot_id)
        .bind(&record.ecosystem)
        .bind(&record.namespace)
        .bind(&record.package_name)
        .bind(&record.package_version)
        .bind(&record.indicator_type)
        .bind(&record.indicator_value)
        .bind(SqlxJson(&record.details))
        .execute(&mut **transaction)
        .await?;
    }

    Ok(())
}

async fn persist_deps_dev_records(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    snapshot_id: Uuid,
    bytes: &[u8],
) -> Result<(), ApiError> {
    let value = serde_json::from_slice::<Value>(bytes)?;
    for package in deps_dev_packages(&value) {
        let Some(package_record) = parse_deps_dev_package(package) else {
            tracing::warn!(snapshot_id = %snapshot_id, "skipping deps.dev package without usable identity");
            continue;
        };

        sqlx::query(
            r#"
            INSERT INTO deps_dev_packages (
              snapshot_id, purl, ecosystem, namespace, package_name,
              package_version, licenses, dependency_count, project_links, raw_document
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (snapshot_id, purl) DO NOTHING
            "#,
        )
        .bind(snapshot_id)
        .bind(&package_record.purl)
        .bind(&package_record.ecosystem)
        .bind(package_record.namespace.as_deref())
        .bind(&package_record.package_name)
        .bind(package_record.package_version.as_deref())
        .bind(SqlxJson(package_record.licenses))
        .bind(i32::try_from(package_record.dependency_count).map_err(|_| {
            ApiError::InvalidFeed(serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "deps.dev dependencyCount exceeds integer bounds",
            )))
        })?)
        .bind(SqlxJson(package_record.project_links))
        .bind(SqlxJson(package_record.raw_document))
        .execute(&mut **transaction)
        .await?;
    }

    for edge in deps_dev_dependency_edges(&value) {
        sqlx::query(
            r#"
            INSERT INTO deps_dev_dependency_edges (
              snapshot_id, package_purl, dependency_purl, relationship, details
            )
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (snapshot_id, package_purl, dependency_purl, relationship) DO NOTHING
            "#,
        )
        .bind(snapshot_id)
        .bind(&edge.package_purl)
        .bind(&edge.dependency_purl)
        .bind(&edge.relationship)
        .bind(SqlxJson(edge.details))
        .execute(&mut **transaction)
        .await?;
    }

    Ok(())
}

async fn persist_scorecard_records(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    snapshot_id: Uuid,
    bytes: &[u8],
) -> Result<(), ApiError> {
    let value = serde_json::from_slice::<Value>(bytes)?;
    for result in scorecard_results(&value) {
        let Some(scorecard_record) = parse_scorecard_result(result) else {
            tracing::warn!(snapshot_id = %snapshot_id, "skipping OpenSSF Scorecard result without repo name or score");
            continue;
        };

        let inserted = sqlx::query(
            r#"
            INSERT INTO openssf_scorecard_results (
              snapshot_id, observed_on, repo_name, repo_commit,
              scorecard_version, scorecard_commit, score, raw_document
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (snapshot_id, repo_name)
            DO UPDATE SET
              observed_on = EXCLUDED.observed_on,
              repo_commit = EXCLUDED.repo_commit,
              scorecard_version = EXCLUDED.scorecard_version,
              scorecard_commit = EXCLUDED.scorecard_commit,
              score = EXCLUDED.score,
              raw_document = EXCLUDED.raw_document
            RETURNING id
            "#,
        )
        .bind(snapshot_id)
        .bind(scorecard_record.observed_on)
        .bind(&scorecard_record.repo_name)
        .bind(scorecard_record.repo_commit.as_deref())
        .bind(scorecard_record.scorecard_version.as_deref())
        .bind(scorecard_record.scorecard_commit.as_deref())
        .bind(scorecard_record.score)
        .bind(SqlxJson(scorecard_record.raw_document))
        .fetch_one(&mut **transaction)
        .await?;

        let result_id: Uuid = inserted.try_get("id")?;

        sqlx::query(
            r#"
            DELETE FROM openssf_scorecard_checks
            WHERE result_id = $1
            "#,
        )
        .bind(result_id)
        .execute(&mut **transaction)
        .await?;

        for check in scorecard_record.checks {
            sqlx::query(
                r#"
                INSERT INTO openssf_scorecard_checks (
                  result_id, check_name, score, reason, details
                )
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (result_id, check_name)
                DO UPDATE SET
                  score = EXCLUDED.score,
                  reason = EXCLUDED.reason,
                  details = EXCLUDED.details
                "#,
            )
            .bind(result_id)
            .bind(&check.name)
            .bind(check.score)
            .bind(check.reason.as_deref())
            .bind(SqlxJson(check.details))
            .execute(&mut **transaction)
            .await?;
        }
    }

    Ok(())
}

fn build_http_client() -> Result<Client, ApiError> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(FEED_HTTP_TIMEOUT_SECS))
        .user_agent(format!(
            "aegiscudo-feed-harvester/{}",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
        .map_err(ApiError::Http)
}

async fn load_feed_snapshot_bytes(
    fixture_dir: &std::path::Path,
    http_client: &Client,
    live_sources: &LiveFeedSources,
    feed: FeedSource,
) -> Result<(FeedState, Option<Vec<u8>>), ApiError> {
    if let Some(url) = live_sources.url_for(feed) {
        let live_fetch = match feed {
            FeedSource::DepsDev => {
                fetch_live_deps_dev_bytes(http_client, url, live_sources.deps_dev_api_base_url())
                    .await
            }
            _ => fetch_live_feed_bytes(http_client, url).await,
        };
        match live_fetch {
            Ok(bytes) => match normalized_record_count(feed, &bytes) {
                Ok(_) => return Ok((FeedState::Fresh, Some(bytes))),
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        feed = feed.name(),
                        url,
                        "live feed payload validation failed; falling back to fixture snapshot"
                    );
                }
            },
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    feed = feed.name(),
                    url,
                    "live feed fetch failed; falling back to fixture snapshot"
                );
            }
        }

        return match read_fixture_bytes(fixture_dir, feed).await? {
            Some(bytes) => Ok((FeedState::Degraded, Some(bytes))),
            None => Ok((FeedState::Unavailable, None)),
        };
    }

    match read_fixture_bytes(fixture_dir, feed).await? {
        Some(bytes) => Ok((FeedState::Fresh, Some(bytes))),
        None => Ok((FeedState::Unavailable, None)),
    }
}

async fn fetch_live_feed_bytes(http_client: &Client, url: &str) -> Result<Vec<u8>, ApiError> {
    let response = http_client.get(url).send().await?.error_for_status()?;
    Ok(response.bytes().await?.to_vec())
}

async fn fetch_live_deps_dev_bytes(
    http_client: &Client,
    metadata_url: &str,
    deps_dev_api_base_url: &str,
) -> Result<Vec<u8>, ApiError> {
    let bytes = fetch_live_feed_bytes(http_client, metadata_url).await?;
    let value = serde_json::from_slice::<Value>(&bytes)?;
    let enriched = enrich_live_deps_dev_payload(http_client, value, deps_dev_api_base_url).await?;
    serde_json::to_vec(&enriched).map_err(ApiError::InvalidFeed)
}

async fn enrich_live_deps_dev_payload(
    http_client: &Client,
    value: Value,
    deps_dev_api_base_url: &str,
) -> Result<Value, ApiError> {
    if !should_enrich_deps_dev_payload(&value) {
        return Ok(value);
    }

    let package_values = deps_dev_packages(&value)
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    let mut merged_packages = Vec::new();
    let mut seen_packages = BTreeSet::new();
    extend_unique_deps_dev_packages(&mut merged_packages, &mut seen_packages, &value);

    let mut merged_edges = Vec::new();
    let mut seen_edges = BTreeSet::new();
    let mut graph_fetches = 0_u64;

    for package in &package_values {
        let Some(version_key) = deps_dev_version_key_from_value(package) else {
            continue;
        };
        graph_fetches += 1;

        let graph_url = deps_dev_dependencies_url(deps_dev_api_base_url, &version_key)?;
        let graph_bytes = fetch_live_feed_bytes(http_client, &graph_url).await?;
        let graph_value = serde_json::from_slice::<Value>(&graph_bytes)?;
        extend_unique_deps_dev_packages(&mut merged_packages, &mut seen_packages, &graph_value);

        for edge in deps_dev_dependency_edges(&graph_value) {
            if seen_edges.insert((
                edge.package_purl.clone(),
                edge.dependency_purl.clone(),
                edge.relationship.clone(),
            )) {
                merged_edges.push(explicit_deps_dev_edge_document(&edge));
            }
        }
    }

    if graph_fetches == 0 {
        return Ok(value);
    }

    match value {
        Value::Object(mut map) => {
            map.insert("packages".to_owned(), Value::Array(merged_packages));
            map.insert("edges".to_owned(), Value::Array(merged_edges));
            Ok(Value::Object(map))
        }
        _ => Ok(json!({
            "packages": merged_packages,
            "edges": merged_edges,
        })),
    }
}

async fn read_fixture_bytes(
    fixture_dir: &std::path::Path,
    feed: FeedSource,
) -> Result<Option<Vec<u8>>, ApiError> {
    let path = fixture_dir.join(feed.file_name());
    match tokio::fs::read(&path).await {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ApiError::Io(error)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedSource {
    Osv,
    Ghsa,
    OpenSsfMaliciousPackages,
    /// OpenSSF Package Analysis behavioral signals (pre-classification of packages).
    OpenSsfPackageAnalysis,
    CisaKev,
    FirstEpss,
    /// deps.dev package metadata: versions, licenses, dependency graphs.
    DepsDev,
    /// OpenSSF Scorecard scores for open-source projects.
    OpenSsfScorecard,
}

impl FeedSource {
    pub fn name(self) -> &'static str {
        match self {
            Self::Osv => "osv",
            Self::Ghsa => "ghsa",
            Self::OpenSsfMaliciousPackages => "openssf-malicious-packages",
            Self::OpenSsfPackageAnalysis => "openssf-package-analysis",
            Self::CisaKev => "cisa-kev",
            Self::FirstEpss => "first-epss",
            Self::DepsDev => "deps.dev",
            Self::OpenSsfScorecard => "openssf-scorecard",
        }
    }

    pub fn file_name(self) -> &'static str {
        match self {
            Self::Osv => "osv.json",
            Self::Ghsa => "ghsa.json",
            Self::OpenSsfMaliciousPackages => "openssf-malicious-packages.json",
            Self::OpenSsfPackageAnalysis => "openssf-package-analysis.json",
            Self::CisaKev => "cisa-kev.json",
            Self::FirstEpss => "first-epss.csv",
            Self::DepsDev => "deps-dev.json",
            Self::OpenSsfScorecard => "openssf-scorecard.json",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeedSnapshotResponse {
    pub id: Uuid,
    pub feed_name: String,
    pub state: FeedState,
    pub normalized_record_count: u64,
    pub snapshot_digest: ArtifactDigest,
    pub last_success_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefreshFeedsResponse {
    pub snapshots: Vec<FeedSnapshotResponse>,
}

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("feed fixture could not be read")]
    Io(#[from] std::io::Error),
    #[error("feed HTTP fetch failed")]
    Http(#[from] reqwest::Error),
    #[error("feed fixture content is invalid")]
    InvalidFeed(#[from] serde_json::Error),
    #[error("feed snapshot digest is invalid")]
    Digest(#[from] aegiscudo_core::DigestError),
    #[error("feed snapshot repository is unavailable")]
    Database(#[from] sqlx::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::InvalidFeed(_) | Self::Digest(_) => StatusCode::BAD_REQUEST,
            Self::Io(_) | Self::Http(_) | Self::Database(_) => StatusCode::SERVICE_UNAVAILABLE,
        };
        (status, self.to_string()).into_response()
    }
}

#[derive(Debug, Clone)]
struct FeedMetrics {
    registry: Registry,
    refresh_total: IntCounterVec,
    refresh_duration_ms: IntGaugeVec,
    last_success_timestamp: IntGaugeVec,
    record_count: IntGaugeVec,
}

impl FeedMetrics {
    fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();
        let refresh_total = IntCounterVec::new(
            Opts::new(
                "aegiscudo_feed_refresh_total",
                "Feed refresh attempts by feed harvester outcome",
            ),
            &["service", "outcome"],
        )?;
        let refresh_duration_ms = IntGaugeVec::new(
            Opts::new(
                "aegiscudo_feed_refresh_duration_ms",
                "Last feed refresh duration in milliseconds",
            ),
            &["service", "outcome"],
        )?;
        let last_success_timestamp = IntGaugeVec::new(
            Opts::new(
                "aegiscudo_feed_last_success_timestamp_seconds",
                "Last successful feed snapshot timestamp",
            ),
            &["service", "feed_name"],
        )?;
        let record_count = IntGaugeVec::new(
            Opts::new(
                "aegiscudo_feed_snapshot_record_count",
                "Normalized feed records in the latest snapshot",
            ),
            &["service", "feed_name", "state"],
        )?;
        registry.register(Box::new(refresh_total.clone()))?;
        registry.register(Box::new(refresh_duration_ms.clone()))?;
        registry.register(Box::new(last_success_timestamp.clone()))?;
        registry.register(Box::new(record_count.clone()))?;
        Ok(Self {
            registry,
            refresh_total,
            refresh_duration_ms,
            last_success_timestamp,
            record_count,
        })
    }

    fn observe_refresh(&self, outcome: &'static str, elapsed_ms: i64) {
        let labels = [SERVICE_NAME, outcome];
        self.refresh_total.with_label_values(&labels).inc();
        self.refresh_duration_ms
            .with_label_values(&labels)
            .set(elapsed_ms);
    }

    fn observe_snapshot(&self, snapshot: &FeedSnapshotResponse) {
        let feed_label = snapshot.feed_name.as_str();
        let state_label = feed_state_db_value(&snapshot.state);
        self.record_count
            .with_label_values(&[SERVICE_NAME, feed_label, state_label])
            .set(snapshot.normalized_record_count as i64);
        if let Some(last_success_at) = snapshot.last_success_at {
            self.last_success_timestamp
                .with_label_values(&[SERVICE_NAME, feed_label])
                .set(last_success_at.timestamp());
        }
    }

    fn render(&self) -> Result<String, prometheus::Error> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer).expect("Prometheus metrics must be UTF-8"))
    }

    fn content_type(&self) -> String {
        TextEncoder::new().format_type().to_owned()
    }
}

fn normalized_record_count(feed: FeedSource, bytes: &[u8]) -> Result<u64, ApiError> {
    match feed {
        FeedSource::FirstEpss => Ok(String::from_utf8_lossy(bytes)
            .lines()
            .filter(|line| {
                !line.trim().is_empty() && !line.starts_with('#') && !line.starts_with("cve,")
            })
            .count() as u64),
        FeedSource::CisaKev => {
            let value = serde_json::from_slice::<Value>(bytes)?;
            Ok(value
                .get("vulnerabilities")
                .and_then(Value::as_array)
                .map_or(0, |items| items.len() as u64))
        }
        FeedSource::DepsDev => {
            // deps.dev may arrive as package metadata, a node-indexed graph, or explicit edge data.
            let value = serde_json::from_slice::<Value>(bytes)?;
            let package_count = deps_dev_packages(&value).len() as u64;
            if package_count > 0 {
                return Ok(package_count);
            }

            Ok(deps_dev_dependency_edges(&value).len() as u64)
        }
        FeedSource::OpenSsfScorecard => {
            // Scorecard fixture: JSON object with a "results" array, or a plain array.
            let value = serde_json::from_slice::<Value>(bytes)?;
            Ok(match &value {
                Value::Array(items) => items.len() as u64,
                Value::Object(map) => map
                    .get("results")
                    .and_then(Value::as_array)
                    .map_or(0, |items| items.len() as u64),
                _ => 0,
            })
        }
        FeedSource::OpenSsfPackageAnalysis => {
            // Package analysis fixture: JSON object with a "results" or "packages" array.
            let value = serde_json::from_slice::<Value>(bytes)?;
            Ok(match &value {
                Value::Array(items) => items.len() as u64,
                Value::Object(map) => map
                    .get("results")
                    .or_else(|| map.get("packages"))
                    .and_then(Value::as_array)
                    .map_or(0, |items| items.len() as u64),
                _ => 0,
            })
        }
        FeedSource::Osv | FeedSource::Ghsa | FeedSource::OpenSsfMaliciousPackages => {
            let value = serde_json::from_slice::<Value>(bytes)?;
            Ok(match value {
                Value::Array(items) => items.len() as u64,
                Value::Object(map) => map
                    .get("vulns")
                    .or_else(|| map.get("advisories"))
                    .or_else(|| map.get("packages"))
                    .and_then(Value::as_array)
                    .map_or(map.len() as u64, |items| items.len() as u64),
                _ => 0,
            })
        }
    }
}

fn deps_dev_packages(value: &Value) -> Vec<&Value> {
    match value {
        Value::Array(items) => items.iter().collect(),
        Value::Object(map) => map
            .get("packages")
            .or_else(|| map.get("nodes"))
            .and_then(Value::as_array)
            .map_or_else(Vec::new, |items| items.iter().collect()),
        _ => Vec::new(),
    }
}

fn scorecard_results(value: &Value) -> Vec<&Value> {
    match value {
        Value::Array(items) => items.iter().collect(),
        Value::Object(map) => map
            .get("results")
            .and_then(Value::as_array)
            .map_or_else(Vec::new, |items| items.iter().collect()),
        _ => Vec::new(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedPurl {
    purl: String,
    ecosystem: String,
    namespace: Option<String>,
    name: String,
    version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DepsDevVersionKey {
    system: String,
    name: String,
    version: String,
}

#[derive(Debug, Clone)]
struct DepsDevPackageRecord {
    purl: String,
    ecosystem: String,
    namespace: Option<String>,
    package_name: String,
    package_version: Option<String>,
    licenses: Vec<String>,
    dependency_count: u64,
    project_links: Vec<Value>,
    raw_document: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DepsDevDependencyEdgeRecord {
    package_purl: String,
    dependency_purl: String,
    relationship: String,
    details: Value,
}

#[derive(Debug, Clone)]
struct ScorecardResultRecord {
    observed_on: Option<NaiveDate>,
    repo_name: String,
    repo_commit: Option<String>,
    scorecard_version: Option<String>,
    scorecard_commit: Option<String>,
    score: f64,
    checks: Vec<ScorecardCheckRecord>,
    raw_document: Value,
}

#[derive(Debug, Clone)]
struct ScorecardCheckRecord {
    name: String,
    score: f64,
    reason: Option<String>,
    details: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FeedPackageIdentity {
    ecosystem: String,
    namespace: Option<String>,
    name: String,
    version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CrossEcosystemIocRecord {
    ecosystem: String,
    namespace: Option<String>,
    package_name: String,
    package_version: Option<String>,
    indicator_type: String,
    indicator_value: String,
    details: Value,
}

fn parse_deps_dev_package(value: &Value) -> Option<DepsDevPackageRecord> {
    let parsed = package_identity_from_value(value)?;
    let dependency_count = value
        .get("dependencyCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let licenses = value
        .get("licenses")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let project_links = value
        .get("projectLinks")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    Some(DepsDevPackageRecord {
        purl: parsed.purl,
        ecosystem: parsed.ecosystem,
        namespace: parsed.namespace,
        package_name: parsed.name,
        package_version: parsed.version,
        licenses,
        dependency_count,
        project_links,
        raw_document: value.clone(),
    })
}

fn should_enrich_deps_dev_payload(value: &Value) -> bool {
    match value {
        Value::Array(_) => true,
        Value::Object(map) => {
            map.contains_key("packages")
                && !map.contains_key("nodes")
                && !map.contains_key("edges")
                && !map.contains_key("dependencyGraph")
        }
        _ => false,
    }
}

fn extend_unique_deps_dev_packages(
    target: &mut Vec<Value>,
    seen_purls: &mut BTreeSet<String>,
    value: &Value,
) {
    for package in deps_dev_packages(value) {
        let Some(parsed) = package_identity_from_value(package) else {
            continue;
        };
        if seen_purls.insert(parsed.purl) {
            target.push(package.clone());
        }
    }
}

fn explicit_deps_dev_edge_document(edge: &DepsDevDependencyEdgeRecord) -> Value {
    let mut object = serde_json::Map::new();
    object.insert(
        "fromPurl".to_owned(),
        Value::String(edge.package_purl.clone()),
    );
    object.insert(
        "toPurl".to_owned(),
        Value::String(edge.dependency_purl.clone()),
    );
    object.insert(
        "relationship".to_owned(),
        Value::String(edge.relationship.clone()),
    );

    if let Value::Object(details) = &edge.details {
        for (key, value) in details {
            if matches!(key.as_str(), "fromNode" | "toNode") {
                continue;
            }
            object.entry(key.clone()).or_insert_with(|| value.clone());
        }
    }

    Value::Object(object)
}

fn deps_dev_dependency_edges(value: &Value) -> Vec<DepsDevDependencyEdgeRecord> {
    let mut seen = BTreeSet::new();
    let mut edges = Vec::new();

    for package in deps_dev_packages(value) {
        let Some(from) = package_identity_from_value(package) else {
            continue;
        };
        let Some(dependencies) = package.get("dependencies").and_then(Value::as_array) else {
            continue;
        };
        for dependency in dependencies {
            let Some(to) = value_to_purl(dependency) else {
                continue;
            };
            let record = DepsDevDependencyEdgeRecord {
                package_purl: from.purl.clone(),
                dependency_purl: to,
                relationship: "depends-on".to_owned(),
                details: dependency.clone(),
            };
            if seen.insert((
                record.package_purl.clone(),
                record.dependency_purl.clone(),
                record.relationship.clone(),
            )) {
                edges.push(record);
            }
        }
    }

    for edge in top_level_deps_dev_edges(value) {
        if seen.insert((
            edge.package_purl.clone(),
            edge.dependency_purl.clone(),
            edge.relationship.clone(),
        )) {
            edges.push(edge);
        }
    }

    edges
}

fn top_level_deps_dev_edges(value: &Value) -> Vec<DepsDevDependencyEdgeRecord> {
    let mut edges = explicit_deps_dev_edges(value);
    edges.extend(node_indexed_deps_dev_edges(value));
    edges
}

fn explicit_deps_dev_edges(value: &Value) -> Vec<DepsDevDependencyEdgeRecord> {
    let edge_values = match value {
        Value::Object(map) => map
            .get("dependencyGraph")
            .and_then(|graph| graph.get("edges"))
            .or_else(|| map.get("edges"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        _ => Vec::new(),
    };

    edge_values
        .iter()
        .filter_map(|edge| {
            let from = edge
                .get("fromPurl")
                .or_else(|| edge.get("from"))
                .and_then(value_to_purl)?;
            let to = edge
                .get("toPurl")
                .or_else(|| edge.get("to"))
                .and_then(value_to_purl)?;
            let relationship = edge
                .get("relationship")
                .and_then(Value::as_str)
                .unwrap_or("depends-on")
                .to_owned();
            Some(DepsDevDependencyEdgeRecord {
                package_purl: from,
                dependency_purl: to,
                relationship,
                details: edge.clone(),
            })
        })
        .collect()
}

fn node_indexed_deps_dev_edges(value: &Value) -> Vec<DepsDevDependencyEdgeRecord> {
    let (nodes, edge_values) = match value {
        Value::Object(map) => {
            let graph = map.get("dependencyGraph");
            let nodes = map
                .get("nodes")
                .or_else(|| graph.and_then(|graph| graph.get("nodes")))
                .and_then(Value::as_array);
            let edges = map
                .get("edges")
                .or_else(|| graph.and_then(|graph| graph.get("edges")))
                .and_then(Value::as_array);
            match (nodes, edges) {
                (Some(nodes), Some(edges)) => (nodes, edges),
                _ => return Vec::new(),
            }
        }
        _ => return Vec::new(),
    };

    edge_values
        .iter()
        .filter_map(|edge| {
            let from_index = edge.get("fromNode").and_then(Value::as_u64)? as usize;
            let to_index = edge.get("toNode").and_then(Value::as_u64)? as usize;
            let from_node = nodes.get(from_index)?;
            let to_node = nodes.get(to_index)?;
            let from = value_to_purl(from_node)?;
            let to = value_to_purl(to_node)?;

            let mut details = edge.clone();
            if let Value::Object(object) = &mut details {
                if let Some(relation) = to_node.get("relation") {
                    object
                        .entry("relation".to_owned())
                        .or_insert_with(|| relation.clone());
                }
                if let Some(bundled) = to_node.get("bundled") {
                    object
                        .entry("bundled".to_owned())
                        .or_insert_with(|| bundled.clone());
                }
                if let Some(errors) = to_node.get("errors") {
                    object
                        .entry("nodeErrors".to_owned())
                        .or_insert_with(|| errors.clone());
                }
            }

            Some(DepsDevDependencyEdgeRecord {
                package_purl: from,
                dependency_purl: to,
                relationship: edge
                    .get("relationship")
                    .and_then(Value::as_str)
                    .unwrap_or("depends-on")
                    .to_owned(),
                details,
            })
        })
        .collect()
}

fn parse_scorecard_result(value: &Value) -> Option<ScorecardResultRecord> {
    let repo_name = value
        .get("repo")
        .and_then(|repo| repo.get("name"))
        .and_then(Value::as_str)?
        .to_owned();
    let score = value.get("score").and_then(Value::as_f64)?;

    let observed_on = value
        .get("date")
        .and_then(Value::as_str)
        .and_then(|date| NaiveDate::parse_from_str(date, "%Y-%m-%d").ok());
    let repo_commit = value
        .get("repo")
        .and_then(|repo| repo.get("commit"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let scorecard_version = value
        .get("scorecard")
        .and_then(|scorecard| scorecard.get("version"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let scorecard_commit = value
        .get("scorecard")
        .and_then(|scorecard| scorecard.get("commit"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let checks = value
        .get("checks")
        .and_then(Value::as_array)
        .map(|checks| {
            checks
                .iter()
                .filter_map(parse_scorecard_check)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Some(ScorecardResultRecord {
        observed_on,
        repo_name,
        repo_commit,
        scorecard_version,
        scorecard_commit,
        score,
        checks,
        raw_document: value.clone(),
    })
}

fn parse_scorecard_check(value: &Value) -> Option<ScorecardCheckRecord> {
    Some(ScorecardCheckRecord {
        name: value.get("name").and_then(Value::as_str)?.to_owned(),
        score: value.get("score").and_then(Value::as_f64)?,
        reason: value
            .get("reason")
            .and_then(Value::as_str)
            .map(str::to_owned),
        details: value.get("details").cloned().unwrap_or_else(|| json!([])),
    })
}

fn cross_ecosystem_ioc_records(feed: FeedSource, value: &Value) -> Vec<CrossEcosystemIocRecord> {
    let mut seen = BTreeSet::new();
    let mut records = Vec::new();

    match feed {
        FeedSource::OpenSsfMaliciousPackages => {
            for package in openssf_malicious_packages(value) {
                let Some(identity) = feed_package_identity(package) else {
                    continue;
                };
                let mut indicators = vec![(
                    IOC_INDICATOR_PACKAGE_NAME,
                    package_indicator_value(identity.namespace.as_deref(), &identity.name),
                )];
                indicators.extend(
                    indicator_values(
                        package,
                        &["maintainerIdentity", "maintainerIdentities", "maintainers"],
                    )
                    .into_iter()
                    .map(|value| (IOC_INDICATOR_MAINTAINER_IDENTITY, value)),
                );
                indicators.extend(
                    indicator_values(package, &["domains", "domain"])
                        .into_iter()
                        .map(|value| (IOC_INDICATOR_DOMAIN, value)),
                );
                indicators.extend(
                    indicator_values(package, &["ips", "ip"])
                        .into_iter()
                        .map(|value| (IOC_INDICATOR_IP, value)),
                );
                indicators.extend(
                    indicator_values(package, &["urls", "url"])
                        .into_iter()
                        .map(|value| (IOC_INDICATOR_URL, value)),
                );

                for (indicator_type, indicator_value) in indicators {
                    if seen.insert((
                        identity.ecosystem.clone(),
                        identity.namespace.clone(),
                        identity.name.clone(),
                        identity.version.clone(),
                        indicator_type.to_owned(),
                        indicator_value.clone(),
                    )) {
                        records.push(CrossEcosystemIocRecord {
                            ecosystem: identity.ecosystem.clone(),
                            namespace: identity.namespace.clone(),
                            package_name: identity.name.clone(),
                            package_version: identity.version.clone(),
                            indicator_type: indicator_type.to_owned(),
                            indicator_value,
                            details: package.clone(),
                        });
                    }
                }
            }
        }
        FeedSource::OpenSsfPackageAnalysis => {
            for result in openssf_package_analysis_results(value) {
                let Some(identity) = feed_package_identity(result) else {
                    continue;
                };
                let Some(fingerprint) = behavioral_fingerprint(result) else {
                    continue;
                };
                if seen.insert((
                    identity.ecosystem.clone(),
                    identity.namespace.clone(),
                    identity.name.clone(),
                    identity.version.clone(),
                    IOC_INDICATOR_BEHAVIORAL_FINGERPRINT.to_owned(),
                    fingerprint.clone(),
                )) {
                    records.push(CrossEcosystemIocRecord {
                        ecosystem: identity.ecosystem,
                        namespace: identity.namespace,
                        package_name: identity.name,
                        package_version: identity.version,
                        indicator_type: IOC_INDICATOR_BEHAVIORAL_FINGERPRINT.to_owned(),
                        indicator_value: fingerprint,
                        details: result.clone(),
                    });
                }
            }
        }
        _ => {}
    }

    records
}

fn openssf_malicious_packages(value: &Value) -> Vec<&Value> {
    match value {
        Value::Array(items) => items.iter().collect(),
        Value::Object(map) => map
            .get("packages")
            .and_then(Value::as_array)
            .map_or_else(Vec::new, |items| items.iter().collect()),
        _ => Vec::new(),
    }
}

fn openssf_package_analysis_results(value: &Value) -> Vec<&Value> {
    match value {
        Value::Array(items) => items.iter().collect(),
        Value::Object(map) => map
            .get("results")
            .or_else(|| map.get("packages"))
            .and_then(Value::as_array)
            .map_or_else(Vec::new, |items| items.iter().collect()),
        _ => Vec::new(),
    }
}

fn feed_package_identity(value: &Value) -> Option<FeedPackageIdentity> {
    let package = value
        .get("package")
        .filter(|value| value.is_object())
        .unwrap_or(value);
    let ecosystem = package
        .get("ecosystem")
        .and_then(Value::as_str)?
        .trim()
        .to_ascii_lowercase();
    let raw_name = package.get("name").and_then(Value::as_str)?.trim();
    let version = package
        .get("version")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);

    let explicit_namespace = package
        .get("namespace")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let (namespace, name) = match explicit_namespace {
        Some(namespace) => (Some(namespace), raw_name.to_owned()),
        None => split_package_name_for_ecosystem(&ecosystem, raw_name),
    };

    Some(FeedPackageIdentity {
        ecosystem,
        namespace,
        name,
        version,
    })
}

fn split_package_name_for_ecosystem(ecosystem: &str, raw_name: &str) -> (Option<String>, String) {
    if ecosystem == "npm" {
        if let Some(scoped) = raw_name.strip_prefix('@') {
            if let Some((namespace, name)) = scoped.split_once('/') {
                return (Some(namespace.to_owned()), name.to_owned());
            }
        }
    }

    (None, raw_name.to_owned())
}

fn package_indicator_value(namespace: Option<&str>, name: &str) -> String {
    match namespace {
        Some(namespace) => format!(
            "{}/{}",
            normalize_indicator_value(namespace),
            normalize_indicator_value(name)
        ),
        None => normalize_indicator_value(name),
    }
}

fn behavioral_fingerprint(value: &Value) -> Option<String> {
    let analysis = value.get("analysis")?;
    let behaviors = analysis.get("behaviors")?.as_array()?;
    let components = behaviors
        .iter()
        .filter_map(|behavior| {
            behavior
                .get("id")
                .and_then(Value::as_str)
                .or_else(|| behavior.get("description").and_then(Value::as_str))
                .map(normalize_indicator_value)
                .filter(|value| !value.is_empty())
        })
        .collect::<BTreeSet<_>>();
    if components.is_empty() {
        None
    } else {
        Some(components.into_iter().collect::<Vec<_>>().join("|"))
    }
}

fn indicator_values(value: &Value, field_names: &[&str]) -> Vec<String> {
    let mut values = BTreeSet::new();
    let object = match value {
        Value::Object(object) => object,
        _ => return Vec::new(),
    };

    for field_name in field_names {
        if let Some(field_value) = object.get(*field_name) {
            collect_stringish_values(&mut values, field_value);
        }
    }

    values.into_iter().collect()
}

fn collect_stringish_values(target: &mut BTreeSet<String>, value: &Value) {
    match value {
        Value::String(value) => {
            let normalized = normalize_indicator_value(value);
            if !normalized.is_empty() {
                target.insert(normalized);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_stringish_values(target, item);
            }
        }
        Value::Object(object) => {
            for key in [
                "value", "id", "name", "email", "url", "domain", "ip", "handle", "login",
            ] {
                if let Some(candidate) = object.get(key) {
                    collect_stringish_values(target, candidate);
                    break;
                }
            }
        }
        _ => {}
    }
}

fn normalize_indicator_value(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn package_identity_from_value(value: &Value) -> Option<ParsedPurl> {
    if let Some(purl) = value.get("purl").and_then(Value::as_str) {
        return parse_purl(purl);
    }

    if let Some(version_key) = value.get("versionKey") {
        return package_identity_from_version_key(version_key);
    }

    let ecosystem = value.get("ecosystem").and_then(Value::as_str)?;
    let name = value.get("name").and_then(Value::as_str)?;
    let namespace = value
        .get("namespace")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let version = value
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_owned);

    Some(ParsedPurl {
        purl: build_purl(ecosystem, namespace.as_deref(), name, version.as_deref()),
        ecosystem: ecosystem.to_owned(),
        namespace,
        name: name.to_owned(),
        version,
    })
}

fn package_identity_from_version_key(value: &Value) -> Option<ParsedPurl> {
    let system = value.get("system").and_then(Value::as_str)?;
    let ecosystem = deps_dev_system_to_purl_type(system)?;
    let raw_name = value.get("name").and_then(Value::as_str)?;
    let version = value
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let (namespace, name) = split_deps_dev_name_for_purl(system, raw_name);

    Some(ParsedPurl {
        purl: build_purl(ecosystem, namespace.as_deref(), &name, version.as_deref()),
        ecosystem: ecosystem.to_owned(),
        namespace,
        name,
        version,
    })
}

fn deps_dev_version_key_from_value(value: &Value) -> Option<DepsDevVersionKey> {
    if let Some(version_key) = value.get("versionKey") {
        return Some(DepsDevVersionKey {
            system: version_key
                .get("system")
                .and_then(Value::as_str)?
                .to_owned(),
            name: version_key.get("name").and_then(Value::as_str)?.to_owned(),
            version: version_key
                .get("version")
                .and_then(Value::as_str)?
                .to_owned(),
        });
    }

    let parsed = package_identity_from_value(value)?;
    let version = parsed.version?;
    let system = deps_dev_purl_type_to_system(&parsed.ecosystem)?.to_owned();
    let name = match parsed.namespace {
        Some(namespace) if !namespace.is_empty() && system.eq_ignore_ascii_case("MAVEN") => {
            format!("{namespace}:{}", parsed.name)
        }
        Some(namespace) if !namespace.is_empty() => format!("{namespace}/{}", parsed.name),
        _ => parsed.name,
    };

    Some(DepsDevVersionKey {
        system,
        name,
        version,
    })
}

fn deps_dev_system_to_purl_type(system: &str) -> Option<&'static str> {
    if system.eq_ignore_ascii_case("GO") {
        Some("golang")
    } else if system.eq_ignore_ascii_case("RUBYGEMS") {
        Some("gem")
    } else if system.eq_ignore_ascii_case("NPM") {
        Some("npm")
    } else if system.eq_ignore_ascii_case("CARGO") {
        Some("cargo")
    } else if system.eq_ignore_ascii_case("MAVEN") {
        Some("maven")
    } else if system.eq_ignore_ascii_case("PYPI") {
        Some("pypi")
    } else if system.eq_ignore_ascii_case("NUGET") {
        Some("nuget")
    } else {
        None
    }
}

fn deps_dev_purl_type_to_system(ecosystem: &str) -> Option<&'static str> {
    if ecosystem.eq_ignore_ascii_case("golang") {
        Some("GO")
    } else if ecosystem.eq_ignore_ascii_case("gem") {
        Some("RUBYGEMS")
    } else if ecosystem.eq_ignore_ascii_case("npm") {
        Some("NPM")
    } else if ecosystem.eq_ignore_ascii_case("cargo") {
        Some("CARGO")
    } else if ecosystem.eq_ignore_ascii_case("maven") {
        Some("MAVEN")
    } else if ecosystem.eq_ignore_ascii_case("pypi") {
        Some("PYPI")
    } else if ecosystem.eq_ignore_ascii_case("nuget") {
        Some("NUGET")
    } else {
        None
    }
}

fn deps_dev_dependencies_url(
    deps_dev_api_base_url: &str,
    version_key: &DepsDevVersionKey,
) -> Result<String, ApiError> {
    let mut url = reqwest::Url::parse(deps_dev_api_base_url).map_err(|error| {
        ApiError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid deps.dev API base URL: {error}"),
        ))
    })?;
    {
        let mut segments = url.path_segments_mut().map_err(|_| {
            ApiError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "deps.dev API base URL cannot be a base path",
            ))
        })?;
        segments.pop_if_empty();
        segments.extend([
            "systems",
            &version_key.system.to_ascii_lowercase(),
            "packages",
            &version_key.name,
            "versions",
            &version_key.version,
        ]);
    }
    Ok(format!("{url}:dependencies"))
}

fn split_deps_dev_name_for_purl(system: &str, raw_name: &str) -> (Option<String>, String) {
    if system.eq_ignore_ascii_case("MAVEN") {
        if let Some((namespace, name)) = raw_name.split_once(':') {
            return (Some(namespace.to_owned()), name.to_owned());
        }
    }

    if system.eq_ignore_ascii_case("NPM") || system.eq_ignore_ascii_case("GO") {
        if let Some((namespace, name)) = raw_name.rsplit_once('/') {
            return (Some(namespace.to_owned()), name.to_owned());
        }
    }

    (None, raw_name.to_owned())
}

fn value_to_purl(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => text.starts_with("pkg:").then(|| text.to_owned()),
        Value::Object(_) => package_identity_from_value(value).map(|parsed| parsed.purl),
        _ => None,
    }
}

fn parse_purl(purl: &str) -> Option<ParsedPurl> {
    let raw = purl.trim().strip_prefix("pkg:")?;
    let (ecosystem, remainder) = raw.split_once('/')?;
    let remainder = remainder
        .split_once('#')
        .map_or(remainder, |(main, _)| main);
    let remainder = remainder
        .split_once('?')
        .map_or(remainder, |(main, _)| main);
    let (path_part, version) = match remainder.rsplit_once('@') {
        Some((path, version)) if !version.trim().is_empty() => (path, Some(version.to_owned())),
        Some((path, _)) => (path, None),
        None => (remainder, None),
    };
    let mut segments: Vec<&str> = path_part
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let name = segments.pop()?.to_owned();
    let namespace = (!segments.is_empty()).then(|| segments.join("/"));

    Some(ParsedPurl {
        purl: purl.to_owned(),
        ecosystem: ecosystem.to_owned(),
        namespace,
        name,
        version,
    })
}

fn build_purl(
    ecosystem: &str,
    namespace: Option<&str>,
    name: &str,
    version: Option<&str>,
) -> String {
    let path = match namespace.filter(|namespace| !namespace.is_empty()) {
        Some(namespace) => format!("{namespace}/{name}"),
        None => name.to_owned(),
    };
    match version.filter(|version| !version.is_empty()) {
        Some(version) => format!("pkg:{ecosystem}/{path}@{version}"),
        None => format!("pkg:{ecosystem}/{path}"),
    }
}

fn sha256_digest(bytes: &[u8]) -> Result<ArtifactDigest, aegiscudo_core::DigestError> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    ArtifactDigest::sha256(hex::encode(hasher.finalize()))
}

fn feed_snapshot_response_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<FeedSnapshotResponse, ApiError> {
    Ok(FeedSnapshotResponse {
        id: row.try_get("id")?,
        feed_name: row.try_get("feed_name")?,
        state: feed_state_from_db(row.try_get::<String, _>("state")?)?,
        normalized_record_count: row.try_get::<i64, _>("normalized_record_count")? as u64,
        snapshot_digest: ArtifactDigest::sha256(row.try_get::<String, _>("snapshot_digest")?)?,
        last_success_at: row.try_get("last_success_at")?,
        created_at: row.try_get("created_at")?,
    })
}

fn feed_state_from_db(value: String) -> Result<FeedState, ApiError> {
    match value.as_str() {
        "fresh" => Ok(FeedState::Fresh),
        "stale" => Ok(FeedState::Stale),
        "degraded" => Ok(FeedState::Degraded),
        "unavailable" => Ok(FeedState::Unavailable),
        _ => Err(ApiError::InvalidFeed(serde_json::Error::io(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid feed state"),
        ))),
    }
}

fn feed_state_db_value(state: &FeedState) -> &'static str {
    match state {
        FeedState::Fresh => "fresh",
        FeedState::Stale => "stale",
        FeedState::Degraded => "degraded",
        FeedState::Unavailable => "unavailable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};
    use std::path::PathBuf;

    #[test]
    fn counts_osv_array_records() {
        let count = normalized_record_count(FeedSource::Osv, br#"[{"id":"OSV-1"},{"id":"OSV-2"}]"#)
            .expect("valid feed");

        assert_eq!(count, 2);
    }

    #[test]
    fn counts_cisa_kev_vulnerabilities() {
        let count = normalized_record_count(
            FeedSource::CisaKev,
            br#"{"vulnerabilities":[{"cveID":"CVE-1"}]}"#,
        )
        .expect("valid feed");

        assert_eq!(count, 1);
    }

    #[test]
    fn counts_epss_csv_rows_without_header() {
        let count = normalized_record_count(
            FeedSource::FirstEpss,
            b"cve,epss,percentile\nCVE-2026-0001,0.42,0.9\n",
        )
        .expect("valid feed");

        assert_eq!(count, 1);
    }

    #[test]
    fn computes_sha256_digest() {
        let digest = sha256_digest(b"feed").expect("digest");

        assert_eq!(digest.hex.len(), 64);
    }

    #[test]
    fn counts_deps_dev_packages_array() {
        let count = normalized_record_count(
            FeedSource::DepsDev,
            br#"[{"purl":"pkg:npm/lodash@4.17.21"},{"purl":"pkg:npm/express@4.18.2"}]"#,
        )
        .expect("valid feed");

        assert_eq!(count, 2);
    }

    #[test]
    fn counts_deps_dev_packages_object() {
        let count = normalized_record_count(
            FeedSource::DepsDev,
            br#"{"packages":[{"purl":"pkg:npm/lodash@4.17.21"}]}"#,
        )
        .expect("valid feed");

        assert_eq!(count, 1);
    }

    #[test]
    fn counts_deps_dev_node_index_graph_payload() {
        let count = normalized_record_count(
            FeedSource::DepsDev,
            br#"{
                "nodes": [
                    {"versionKey": {"system": "NPM", "name": "express", "version": "4.18.2"}},
                    {"versionKey": {"system": "NPM", "name": "accepts", "version": "1.3.8"}},
                    {"versionKey": {"system": "NPM", "name": "mime-types", "version": "2.1.34"}}
                ],
                "edges": [
                    {"fromNode": 0, "toNode": 1, "requirement": "~1.3.8"},
                    {"fromNode": 1, "toNode": 2, "requirement": "~2.1.34"}
                ]
            }"#,
        )
        .expect("valid feed");

        assert_eq!(count, 3);
    }

    #[test]
    fn counts_deps_dev_explicit_edges_without_packages() {
        let count = normalized_record_count(
            FeedSource::DepsDev,
            br#"{
                "dependencyGraph": {
                    "edges": [
                        {
                            "fromPurl": "pkg:npm/express@4.18.2",
                            "toPurl": "pkg:npm/accepts@1.3.8",
                            "relationship": "runtime"
                        }
                    ]
                }
            }"#,
        )
        .expect("valid feed");

        assert_eq!(count, 1);
    }

    #[test]
    fn counts_scorecard_results_array() {
        let count = normalized_record_count(
            FeedSource::OpenSsfScorecard,
            br#"[{"repo":{"name":"github.com/lodash/lodash"},"score":8.5}]"#,
        )
        .expect("valid feed");

        assert_eq!(count, 1);
    }

    #[test]
    fn counts_scorecard_results_object() {
        let count = normalized_record_count(
            FeedSource::OpenSsfScorecard,
            br#"{"results":[{"repo":{"name":"github.com/lodash/lodash"},"score":8.5}]}"#,
        )
        .expect("valid feed");

        assert_eq!(count, 1);
    }

    #[test]
    fn counts_package_analysis_results() {
        let count = normalized_record_count(
            FeedSource::OpenSsfPackageAnalysis,
            br#"{"results":[{"package":{"name":"malware-pkg","ecosystem":"npm"},"analysis":{"behaviors":[]}}]}"#,
        )
        .expect("valid feed");

        assert_eq!(count, 1);
    }

    #[test]
    fn all_feed_sources_have_distinct_names() {
        let names: Vec<_> = FEEDS.iter().map(|f| f.name()).collect();
        let unique: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(names.len(), unique.len(), "feed names must be unique");
    }

    #[test]
    fn all_feed_sources_have_distinct_file_names() {
        let file_names: Vec<_> = FEEDS.iter().map(|f| f.file_name()).collect();
        let unique: std::collections::HashSet<_> = file_names.iter().collect();
        assert_eq!(
            file_names.len(),
            unique.len(),
            "feed file names must be unique"
        );
    }

    #[test]
    fn parse_deps_dev_package_derives_identity_from_purl() {
        let value = serde_json::json!({
            "purl": "pkg:npm/lodash@4.17.21",
            "licenses": ["MIT"],
            "dependencyCount": 2,
            "projectLinks": [{"type": "SOURCE_REPO", "url": "https://github.com/lodash/lodash"}]
        });

        let record = parse_deps_dev_package(&value).expect("deps.dev package");

        assert_eq!(record.ecosystem, "npm");
        assert_eq!(record.package_name, "lodash");
        assert_eq!(record.package_version.as_deref(), Some("4.17.21"));
        assert_eq!(record.licenses, vec!["MIT"]);
    }

    #[test]
    fn parse_deps_dev_package_derives_identity_from_version_key() {
        let value = serde_json::json!({
            "versionKey": {"system": "NPM", "name": "express", "version": "4.18.2"},
            "relation": "SELF",
            "bundled": false,
            "errors": []
        });

        let record = parse_deps_dev_package(&value).expect("deps.dev package node");

        assert_eq!(record.purl, "pkg:npm/express@4.18.2");
        assert_eq!(record.ecosystem, "npm");
        assert_eq!(record.package_name, "express");
        assert_eq!(record.package_version.as_deref(), Some("4.18.2"));
    }

    #[test]
    fn deps_dev_dependency_edges_extracts_package_dependencies() {
        let value = serde_json::json!({
            "packages": [
                {
                    "purl": "pkg:npm/express@4.18.2",
                    "dependencies": [
                        "pkg:npm/body-parser@1.20.2",
                        {"ecosystem": "npm", "name": "debug", "version": "4.3.4"}
                    ]
                }
            ]
        });

        let edges = deps_dev_dependency_edges(&value);

        assert_eq!(edges.len(), 2);
        assert!(
            edges
                .iter()
                .any(|edge| edge.dependency_purl == "pkg:npm/body-parser@1.20.2")
        );
        assert!(
            edges
                .iter()
                .any(|edge| edge.dependency_purl == "pkg:npm/debug@4.3.4")
        );
    }

    #[test]
    fn deps_dev_dependency_edges_extracts_top_level_graph_edges() {
        let value = serde_json::json!({
            "packages": [],
            "dependencyGraph": {
                "edges": [
                    {
                        "fromPurl": "pkg:npm/express@4.18.2",
                        "toPurl": "pkg:npm/accepts@1.3.8",
                        "relationship": "runtime"
                    }
                ]
            }
        });

        let edges = deps_dev_dependency_edges(&value);

        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].relationship, "runtime");
    }

    #[test]
    fn deps_dev_dependency_edges_extracts_node_index_graph_edges() {
        let value = serde_json::json!({
            "nodes": [
                {
                    "versionKey": {"system": "NPM", "name": "express", "version": "4.18.2"},
                    "relation": "SELF",
                    "bundled": false,
                    "errors": []
                },
                {
                    "versionKey": {"system": "NPM", "name": "accepts", "version": "1.3.8"},
                    "relation": "DIRECT",
                    "bundled": false,
                    "errors": []
                },
                {
                    "versionKey": {"system": "NPM", "name": "mime-types", "version": "2.1.34"},
                    "relation": "INDIRECT",
                    "bundled": false,
                    "errors": []
                }
            ],
            "edges": [
                {"fromNode": 0, "toNode": 1, "requirement": "~1.3.8"},
                {"fromNode": 1, "toNode": 2, "requirement": "~2.1.34"}
            ]
        });

        let edges = deps_dev_dependency_edges(&value);

        assert_eq!(edges.len(), 2);
        assert!(edges.iter().any(|edge| {
            edge.package_purl == "pkg:npm/express@4.18.2"
                && edge.dependency_purl == "pkg:npm/accepts@1.3.8"
                && edge.details["relation"] == "DIRECT"
        }));
        assert!(edges.iter().any(|edge| {
            edge.package_purl == "pkg:npm/accepts@1.3.8"
                && edge.dependency_purl == "pkg:npm/mime-types@2.1.34"
                && edge.details["relation"] == "INDIRECT"
        }));
    }

    #[test]
    fn parse_scorecard_result_extracts_checks() {
        let value = serde_json::json!({
            "date": "2026-05-01",
            "repo": {"name": "github.com/example/repo", "commit": "abc123"},
            "scorecard": {"version": "v5.0.0", "commit": "def456"},
            "score": 8.7,
            "checks": [
                {"name": "Code-Review", "score": 10, "reason": "reviewed", "details": []}
            ]
        });

        let result = parse_scorecard_result(&value).expect("scorecard result");

        assert_eq!(result.repo_name, "github.com/example/repo");
        assert_eq!(result.checks.len(), 1);
        assert_eq!(result.checks[0].name, "Code-Review");
    }

    #[test]
    fn malicious_package_ioc_records_capture_supported_indicator_types() {
        let value = serde_json::json!({
            "packages": [
                {
                    "ecosystem": "npm",
                    "name": "@bad/actor",
                    "maintainers": ["evil@example.test"],
                    "domains": ["evil.example"],
                    "ips": ["203.0.113.10"],
                    "urls": ["https://evil.example/dropper"]
                }
            ]
        });

        let records = cross_ecosystem_ioc_records(FeedSource::OpenSsfMaliciousPackages, &value);

        assert!(records.iter().any(|record| {
            record.indicator_type == IOC_INDICATOR_PACKAGE_NAME
                && record.indicator_value == "bad/actor"
        }));
        assert!(records.iter().any(|record| {
            record.indicator_type == IOC_INDICATOR_MAINTAINER_IDENTITY
                && record.indicator_value == "evil@example.test"
        }));
        assert!(records.iter().any(|record| {
            record.indicator_type == IOC_INDICATOR_DOMAIN
                && record.indicator_value == "evil.example"
        }));
        assert!(records.iter().any(|record| {
            record.indicator_type == IOC_INDICATOR_IP && record.indicator_value == "203.0.113.10"
        }));
        assert!(records.iter().any(|record| {
            record.indicator_type == IOC_INDICATOR_URL
                && record.indicator_value == "https://evil.example/dropper"
        }));
    }

    #[test]
    fn package_analysis_ioc_records_capture_behavioral_fingerprint() {
        let value = serde_json::json!({
            "results": [
                {
                    "package": {
                        "ecosystem": "npm",
                        "name": "malware-sample",
                        "version": "1.0.0"
                    },
                    "analysis": {
                        "behaviors": [
                            {"id": "NETWORK_ACCESS"},
                            {"id": "EXEC_BINARY"}
                        ]
                    }
                }
            ]
        });

        let records = cross_ecosystem_ioc_records(FeedSource::OpenSsfPackageAnalysis, &value);

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].indicator_type,
            IOC_INDICATOR_BEHAVIORAL_FINGERPRINT
        );
        assert_eq!(records[0].indicator_value, "exec_binary|network_access");
        assert_eq!(records[0].package_name, "malware-sample");
    }

    #[test]
    fn package_identity_from_value_builds_purl_without_explicit_purl_field() {
        let value = serde_json::json!({
            "ecosystem": "pypi",
            "name": "requests",
            "version": "2.31.0"
        });

        let identity = package_identity_from_value(&value).expect("identity");

        assert_eq!(identity.purl, "pkg:pypi/requests@2.31.0");
    }

    #[test]
    fn live_feed_sources_only_target_supported_live_feeds() {
        let sources = LiveFeedSources {
            deps_dev_url: Some("https://example.test/deps-dev.json".to_owned()),
            deps_dev_api_base_url: Some("https://example.test/v3".to_owned()),
            openssf_scorecard_url: Some("https://example.test/scorecard.json".to_owned()),
        };

        assert_eq!(
            sources.url_for(FeedSource::DepsDev),
            Some("https://example.test/deps-dev.json")
        );
        assert_eq!(
            sources.url_for(FeedSource::OpenSsfScorecard),
            Some("https://example.test/scorecard.json")
        );
        assert_eq!(sources.deps_dev_api_base_url(), "https://example.test/v3");
        assert_eq!(sources.url_for(FeedSource::Osv), None);
    }

    #[test]
    fn deps_dev_feed_name_matches_policy_contract() {
        assert_eq!(FeedSource::DepsDev.name(), "deps.dev");
    }

    #[tokio::test]
    async fn load_feed_snapshot_bytes_prefers_live_deps_dev_response() {
        let http_client = build_http_client().expect("http client");
        let (url, handle) = spawn_json_server(
            r#"{"packages":[{"purl":"pkg:npm/lodash@4.17.21"}],"edges":[]}"#.to_owned(),
        )
        .await;
        let live_sources = LiveFeedSources {
            deps_dev_url: Some(url),
            deps_dev_api_base_url: Some("http://127.0.0.1:9/v3".to_owned()),
            openssf_scorecard_url: None,
        };

        let (state, bytes) = load_feed_snapshot_bytes(
            &test_fixture_dir(),
            &http_client,
            &live_sources,
            FeedSource::DepsDev,
        )
        .await
        .expect("load feed bytes");

        handle.abort();

        assert_eq!(state, FeedState::Fresh);
        let bytes = bytes.expect("live bytes should exist");
        assert_eq!(
            normalized_record_count(FeedSource::DepsDev, &bytes).unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn load_feed_snapshot_bytes_prefers_live_deps_dev_graph_response() {
        let http_client = build_http_client().expect("http client");
        let (url, handle) = spawn_json_server(
            r#"{
                "nodes": [
                    {"versionKey": {"system": "NPM", "name": "express", "version": "4.18.2"}},
                    {"versionKey": {"system": "NPM", "name": "accepts", "version": "1.3.8"}}
                ],
                "edges": [
                    {"fromNode": 0, "toNode": 1, "requirement": "~1.3.8"}
                ]
            }"#
            .to_owned(),
        )
        .await;
        let live_sources = LiveFeedSources {
            deps_dev_url: Some(url),
            deps_dev_api_base_url: Some("http://127.0.0.1:9/v3".to_owned()),
            openssf_scorecard_url: None,
        };

        let (state, bytes) = load_feed_snapshot_bytes(
            &test_fixture_dir(),
            &http_client,
            &live_sources,
            FeedSource::DepsDev,
        )
        .await
        .expect("load feed bytes");

        handle.abort();

        assert_eq!(state, FeedState::Fresh);
        let bytes = bytes.expect("live bytes should exist");
        assert_eq!(
            normalized_record_count(FeedSource::DepsDev, &bytes).unwrap(),
            2
        );
        let edges = deps_dev_dependency_edges(&serde_json::from_slice::<Value>(&bytes).unwrap());
        assert_eq!(edges.len(), 1);
    }

    #[tokio::test]
    async fn load_feed_snapshot_bytes_falls_back_to_fixture_when_live_fetch_fails() {
        let http_client = build_http_client().expect("http client");
        let live_sources = LiveFeedSources {
            deps_dev_url: None,
            deps_dev_api_base_url: None,
            openssf_scorecard_url: Some("http://127.0.0.1:9/scorecard.json".to_owned()),
        };

        let (state, bytes) = load_feed_snapshot_bytes(
            &test_fixture_dir(),
            &http_client,
            &live_sources,
            FeedSource::OpenSsfScorecard,
        )
        .await
        .expect("load fallback bytes");

        assert_eq!(state, FeedState::Degraded);
        let bytes = bytes.expect("fixture fallback bytes should exist");
        assert_eq!(
            normalized_record_count(FeedSource::OpenSsfScorecard, &bytes).unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn load_feed_snapshot_bytes_falls_back_to_fixture_when_live_payload_is_invalid() {
        let http_client = build_http_client().expect("http client");
        let (url, handle) = spawn_json_server("{not-json".to_owned()).await;
        let live_sources = LiveFeedSources {
            deps_dev_url: Some(url),
            deps_dev_api_base_url: Some("http://127.0.0.1:9/v3".to_owned()),
            openssf_scorecard_url: None,
        };

        let (state, bytes) = load_feed_snapshot_bytes(
            &test_fixture_dir(),
            &http_client,
            &live_sources,
            FeedSource::DepsDev,
        )
        .await
        .expect("load fallback bytes");

        handle.abort();

        assert_eq!(state, FeedState::Degraded);
        let bytes = bytes.expect("fixture fallback bytes should exist");
        assert!(
            normalized_record_count(FeedSource::DepsDev, &bytes).unwrap() > 0,
            "fixture fallback should remain usable"
        );
    }

    #[tokio::test]
    async fn load_feed_snapshot_bytes_marks_feed_unavailable_without_valid_live_or_fixture_data() {
        let http_client = build_http_client().expect("http client");
        let (url, handle) = spawn_json_server("{not-json".to_owned()).await;
        let live_sources = LiveFeedSources {
            deps_dev_url: None,
            deps_dev_api_base_url: None,
            openssf_scorecard_url: Some(url),
        };
        let missing_fixture_dir = std::env::temp_dir()
            .join("aegiscudo-feed-harvester-missing-fixtures")
            .join(Uuid::new_v4().to_string());

        let (state, bytes) = load_feed_snapshot_bytes(
            &missing_fixture_dir,
            &http_client,
            &live_sources,
            FeedSource::OpenSsfScorecard,
        )
        .await
        .expect("load feed bytes");

        handle.abort();

        assert_eq!(state, FeedState::Unavailable);
        assert!(
            bytes.is_none(),
            "missing fallback fixture should stay unavailable"
        );
    }

    #[tokio::test]
    async fn load_feed_snapshot_bytes_enriches_live_deps_dev_packages_with_graphs() {
        let http_client = build_http_client().expect("http client");
        let (metadata_url, api_base_url, handle) = spawn_deps_dev_enrichment_server(
            r#"{
                "packages": [
                    {
                        "purl": "pkg:npm/express@4.18.2",
                        "ecosystem": "npm",
                        "name": "express",
                        "version": "4.18.2",
                        "licenses": ["MIT"]
                    }
                ]
            }"#
            .to_owned(),
            vec![(
                "/v3/systems/npm/packages/express/versions/4.18.2:dependencies".to_owned(),
                r#"{
                    "nodes": [
                        {"versionKey": {"system": "NPM", "name": "express", "version": "4.18.2"}},
                        {"versionKey": {"system": "NPM", "name": "accepts", "version": "1.3.8"}}
                    ],
                    "edges": [
                        {"fromNode": 0, "toNode": 1, "requirement": "~1.3.8"}
                    ]
                }"#
                .to_owned(),
            )],
        )
        .await;
        let live_sources = LiveFeedSources {
            deps_dev_url: Some(metadata_url),
            deps_dev_api_base_url: Some(api_base_url),
            openssf_scorecard_url: None,
        };

        let (state, bytes) = load_feed_snapshot_bytes(
            &test_fixture_dir(),
            &http_client,
            &live_sources,
            FeedSource::DepsDev,
        )
        .await
        .expect("load deps.dev bytes");

        handle.abort();

        assert_eq!(state, FeedState::Fresh);
        let bytes = bytes.expect("live bytes should exist");
        let value = serde_json::from_slice::<Value>(&bytes).expect("merged deps.dev payload");
        assert_eq!(deps_dev_packages(&value).len(), 2);
        assert_eq!(deps_dev_dependency_edges(&value).len(), 1);
    }

    #[tokio::test]
    async fn load_feed_snapshot_bytes_falls_back_when_deps_dev_graph_enrichment_fails() {
        let http_client = build_http_client().expect("http client");
        let (metadata_url, api_base_url, handle) = spawn_deps_dev_enrichment_server(
            r#"{
                "packages": [
                    {
                        "purl": "pkg:npm/express@4.18.2",
                        "ecosystem": "npm",
                        "name": "express",
                        "version": "4.18.2"
                    }
                ]
            }"#
            .to_owned(),
            Vec::new(),
        )
        .await;
        let live_sources = LiveFeedSources {
            deps_dev_url: Some(metadata_url),
            deps_dev_api_base_url: Some(api_base_url),
            openssf_scorecard_url: None,
        };

        let (state, bytes) = load_feed_snapshot_bytes(
            &test_fixture_dir(),
            &http_client,
            &live_sources,
            FeedSource::DepsDev,
        )
        .await
        .expect("load fallback bytes");

        handle.abort();

        assert_eq!(state, FeedState::Degraded);
        let bytes = bytes.expect("fixture fallback bytes should exist");
        assert!(normalized_record_count(FeedSource::DepsDev, &bytes).unwrap() > 0);
    }

    fn test_fixture_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/feeds")
    }

    async fn spawn_json_server(body: String) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let address = listener.local_addr().expect("listener address");
        let app = Router::new().route(
            "/feed.json",
            get(move || {
                let body = body.clone();
                async move {
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        body,
                    )
                }
            }),
        );
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{address}/feed.json"), handle)
    }

    async fn spawn_deps_dev_enrichment_server(
        metadata_body: String,
        graph_routes: Vec<(String, String)>,
    ) -> (String, String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind deps.dev listener");
        let address = listener.local_addr().expect("listener address");
        let metadata_body = Arc::new(metadata_body);
        let graph_routes = Arc::new(graph_routes);
        let app = Router::new()
            .route(
                "/feed.json",
                get(move || {
                    let metadata_body = metadata_body.clone();
                    async move {
                        (
                            [(axum::http::header::CONTENT_TYPE, "application/json")],
                            (*metadata_body).clone(),
                        )
                    }
                }),
            )
            .route(
                "/v3/{*path}",
                get(
                    move |axum::extract::Path(path): axum::extract::Path<String>| {
                        let graph_routes = graph_routes.clone();
                        async move {
                            let route_path = format!("/v3/{path}");
                            if let Some((_, body)) = graph_routes
                                .iter()
                                .find(|(candidate_path, _)| candidate_path == &route_path)
                            {
                                (
                                    StatusCode::OK,
                                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                                    body.clone(),
                                )
                                    .into_response()
                            } else {
                                StatusCode::NOT_FOUND.into_response()
                            }
                        }
                    },
                ),
            );
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (
            format!("http://{address}/feed.json"),
            format!("http://{address}/v3"),
            handle,
        )
    }
}
