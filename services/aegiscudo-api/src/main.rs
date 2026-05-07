use aegiscudo_api::{ReloadClient, app_with_reload, connect};
use aegiscudo_telemetry::init_json_tracing;
use anyhow::Context;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_json_tracing();
    let database_url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL is required for aegiscudo-api control-plane persistence")?;
    let pool = connect(&database_url)
        .await
        .context("connecting aegiscudo-api database pool")?;
    let reload_client = std::env::var("MOSQUITO_NET_RELOAD_URL")
        .ok()
        .map(ReloadClient::new)
        .transpose()
        .context("configuring Mosquito Net reload client")?;
    let app = app_with_reload(pool, reload_client);
    let bind_addr =
        std::env::var("AEGISCUDO_API_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8082".to_owned());
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("binding aegiscudo-api to {bind_addr}"))?;
    tracing::info!(%bind_addr, "aegiscudo-api listening");
    axum::serve(listener, app).await?;
    Ok(())
}
