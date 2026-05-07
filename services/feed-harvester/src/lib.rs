use std::{path::PathBuf, sync::Arc, time::Instant};

use aegiscudo_core::{ArtifactDigest, FeedState};
use aegiscudo_telemetry::health;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderValue, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use prometheus::{Encoder, IntCounterVec, IntGaugeVec, Opts, Registry, TextEncoder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use thiserror::Error;
use uuid::Uuid;

pub const SERVICE_NAME: &str = "feed-harvester";
const FEEDS: &[FeedSource] = &[
    FeedSource::Osv,
    FeedSource::Ghsa,
    FeedSource::OpenSsfMaliciousPackages,
    FeedSource::CisaKev,
    FeedSource::FirstEpss,
];

#[derive(Debug, Clone)]
pub struct AppState {
    pool: PgPool,
    fixture_dir: PathBuf,
    metrics: FeedMetrics,
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
    let mut snapshots = Vec::new();
    for feed in FEEDS {
        snapshots.push(ingest_feed_fixture(pool, fixture_dir, *feed).await?);
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
    feed: FeedSource,
) -> Result<FeedSnapshotResponse, ApiError> {
    let path = fixture_dir.join(feed.file_name());
    let now = Utc::now();
    let (state, record_count, digest, last_success_at) = match tokio::fs::read(&path).await {
        Ok(bytes) => {
            let record_count = normalized_record_count(feed, &bytes)?;
            let digest = sha256_digest(&bytes)?;
            (FeedState::Fresh, record_count, digest, Some(now))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let digest = sha256_digest(feed.name().as_bytes())?;
            (FeedState::Unavailable, 0, digest, None)
        }
        Err(error) => return Err(ApiError::Io(error)),
    };

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
    .fetch_one(pool)
    .await?;
    Ok(feed_snapshot_response_from_row(&row)?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedSource {
    Osv,
    Ghsa,
    OpenSsfMaliciousPackages,
    CisaKev,
    FirstEpss,
}

impl FeedSource {
    pub fn name(self) -> &'static str {
        match self {
            Self::Osv => "osv",
            Self::Ghsa => "ghsa",
            Self::OpenSsfMaliciousPackages => "openssf-malicious-packages",
            Self::CisaKev => "cisa-kev",
            Self::FirstEpss => "first-epss",
        }
    }

    pub fn file_name(self) -> &'static str {
        match self {
            Self::Osv => "osv.json",
            Self::Ghsa => "ghsa.json",
            Self::OpenSsfMaliciousPackages => "openssf-malicious-packages.json",
            Self::CisaKev => "cisa-kev.json",
            Self::FirstEpss => "first-epss.csv",
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
            Self::Io(_) | Self::Database(_) => StatusCode::SERVICE_UNAVAILABLE,
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

fn sha256_digest(bytes: &[u8]) -> Result<ArtifactDigest, aegiscudo_core::DigestError> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    ArtifactDigest::sha256(format!("{:x}", hasher.finalize()))
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
}
