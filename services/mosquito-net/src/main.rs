use aegiscudo_telemetry::init_json_tracing;
use anyhow::Context;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_json_tracing();
    let bind_addr =
        std::env::var("MOSQUITO_NET_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("binding mosquito-net to {bind_addr}"))?;
    tracing::info!(%bind_addr, "mosquito-net listening");
    axum::serve(listener, mosquito_net::app()).await?;
    Ok(())
}
