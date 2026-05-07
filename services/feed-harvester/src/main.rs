use std::{path::PathBuf, time::Duration};

use aegiscudo_telemetry::init_json_tracing;
use anyhow::Context;
use feed_harvester::{app, connect, refresh_fixture_feeds};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_json_tracing();
    let database_url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL is required for feed-harvester snapshots")?;
    let pool = connect(&database_url)
        .await
        .context("connecting feed-harvester database pool")?;
    let fixture_dir = std::env::var("FEED_FIXTURE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("testdata/feeds"));
    let bind_addr =
        std::env::var("FEED_HARVESTER_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8085".to_owned());
    let refresh_interval_secs = env_u64("FEED_HARVESTER_REFRESH_INTERVAL_SECS", 0);
    if refresh_interval_secs > 0 {
        let scheduled_pool = pool.clone();
        let scheduled_fixture_dir = fixture_dir.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(refresh_interval_secs));
            loop {
                interval.tick().await;
                match refresh_fixture_feeds(&scheduled_pool, &scheduled_fixture_dir).await {
                    Ok(snapshots) => tracing::info!(
                        snapshot_count = snapshots.len(),
                        refresh_interval_secs,
                        "scheduled feed fixture refresh completed"
                    ),
                    Err(error) => tracing::warn!(
                        error = %error,
                        refresh_interval_secs,
                        "scheduled feed fixture refresh failed"
                    ),
                }
            }
        });
    }
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("binding feed-harvester to {bind_addr}"))?;
    tracing::info!(%bind_addr, fixture_dir = %fixture_dir.display(), refresh_interval_secs, "feed-harvester listening");
    axum::serve(listener, app(pool, fixture_dir)).await?;
    Ok(())
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
