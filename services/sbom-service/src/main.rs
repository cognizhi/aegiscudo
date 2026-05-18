use aegiscudo_telemetry::init_json_tracing;
use anyhow::Context;
use sbom_service::{Config, app, connect};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_json_tracing();
    let database_url =
        std::env::var("DATABASE_URL").context("DATABASE_URL is required for sbom-service")?;
    let pool = connect(&database_url)
        .await
        .context("connecting sbom-service database pool")?;
    let sbom_store_dir =
        std::env::var("SBOM_STORE_DIR").unwrap_or_else(|_| "/var/lib/aegiscudo/sboms".to_owned());
    let config = Config {
        sbom_store_dir: sbom_store_dir.into(),
    };
    let application = app(pool, config);
    let bind_addr =
        std::env::var("SBOM_SERVICE_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8086".to_owned());
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("binding sbom-service to {bind_addr}"))?;
    tracing::info!(%bind_addr, "sbom-service listening");
    axum::serve(listener, application).await?;
    Ok(())
}
