use aegiscudo_telemetry::{health, init_json_tracing};
use anyhow::Context;
use axum::{Json, Router, routing::get};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_json_tracing();
    let app = Router::new()
        .route("/healthz", get(|| async { Json(health("aegiscudo-api")) }))
        .route("/readyz", get(|| async { Json(health("aegiscudo-api")) }));
    let bind_addr =
        std::env::var("AEGISCUDO_API_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8082".to_owned());
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("binding aegiscudo-api to {bind_addr}"))?;
    tracing::info!(%bind_addr, "aegiscudo-api listening");
    axum::serve(listener, app).await?;
    Ok(())
}
