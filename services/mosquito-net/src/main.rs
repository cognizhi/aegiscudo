use aegiscudo_telemetry::init_json_tracing;
use anyhow::Context;
use mosquito_net::{
    audit::PostgresAuditEventRepository,
    rate_limit::{ProxyRateLimitConfig, RateLimitConfig},
    registry_config::PostgresRegistryConfigRepository,
    triage_client::TriageClient,
};
use std::net::SocketAddr;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_json_tracing();
    let database_url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL is required for mosquito-net registry configuration loading")?;
    let registry_repository = PostgresRegistryConfigRepository::connect(&database_url)
        .await
        .context("connecting mosquito-net registry config repository")?;
    let registry_configs = registry_repository
        .load_enabled()
        .await
        .context("loading enabled registry configurations")?;
    let bind_addr =
        std::env::var("MOSQUITO_NET_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());
    let triage_counter_url =
        std::env::var("TRIAGE_COUNTER_URL").unwrap_or_else(|_| "http://127.0.0.1:8081".to_owned());
    let triage_timeout_ms = env_u64("TRIAGE_COUNTER_TIMEOUT_MS", 750).clamp(100, 5_000);
    let triage_max_retries = env_u8("TRIAGE_COUNTER_MAX_RETRIES", 1).min(3);
    let triage_client = TriageClient::new(
        &triage_counter_url,
        Duration::from_millis(triage_timeout_ms),
        triage_max_retries,
    )
    .context("configuring mosquito-net Triage Counter client")?;
    let audit_repository = PostgresAuditEventRepository::connect(&database_url)
        .await
        .context("configuring mosquito-net audit repository")?;
    let rate_limit_config = ProxyRateLimitConfig {
        tenant_api: RateLimitConfig::new(
            Duration::from_secs(env_u64("MOSQUITO_NET_TENANT_RATE_LIMIT_WINDOW_SECS", 60)),
            env_usize("MOSQUITO_NET_TENANT_RATE_LIMIT_BURST", 240).max(1),
        ),
        client_package: RateLimitConfig::new(
            Duration::from_secs(env_u64("MOSQUITO_NET_CLIENT_RATE_LIMIT_WINDOW_SECS", 60)),
            env_usize("MOSQUITO_NET_CLIENT_RATE_LIMIT_BURST", 120).max(1),
        ),
    };
    let max_artifact_bytes = env_u64("MOSQUITO_NET_MAX_ARTIFACT_BYTES", 100 * 1024 * 1024).max(1);
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("binding mosquito-net to {bind_addr}"))?;
    tracing::info!(
        %bind_addr,
        registry_config_count = registry_configs.len(),
        triage_timeout_ms,
        triage_max_retries,
        tenant_rate_limit_window_secs = rate_limit_config.tenant_api.window.as_secs(),
        tenant_rate_limit_burst = rate_limit_config.tenant_api.burst,
        client_rate_limit_window_secs = rate_limit_config.client_package.window.as_secs(),
        client_rate_limit_burst = rate_limit_config.client_package.burst,
        max_artifact_bytes,
        "mosquito-net listening"
    );
    axum::serve(
        listener,
        mosquito_net::app_with_runtime_dependencies_and_reload(
            registry_configs,
            Some(registry_repository),
            triage_client,
            rate_limit_config,
            Some(audit_repository),
            max_artifact_bytes,
        )
        .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_u8(name: &str, default: u8) -> u8 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
