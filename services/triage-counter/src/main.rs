use aegiscudo_telemetry::init_json_tracing;
use anyhow::Context;
use triage_counter::repository::{PolicyRepository, PostgresPolicyRepository};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_json_tracing();
    let database_url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL is required for triage-counter policy loading")?;
    let policy_repository = PostgresPolicyRepository::connect(&database_url)
        .await
        .context("connecting triage-counter policy repository")?;
    let bind_addr =
        std::env::var("TRIAGE_COUNTER_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8081".to_owned());
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("binding triage-counter to {bind_addr}"))?;
    tracing::info!(%bind_addr, "triage-counter listening");
    axum::serve(
        listener,
        triage_counter::app(PolicyRepository::Postgres(policy_repository)),
    )
    .await?;
    Ok(())
}
