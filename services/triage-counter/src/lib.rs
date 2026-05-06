use aegiscudo_policy::{DecisionEngine, PolicyInput};
use aegiscudo_telemetry::health;
use axum::{
    Json, Router,
    routing::{get, post},
};

pub const SERVICE_NAME: &str = "triage-counter";

pub fn app() -> Router {
    Router::new()
        .route("/healthz", get(|| async { Json(health(SERVICE_NAME)) }))
        .route("/readyz", get(|| async { Json(health(SERVICE_NAME)) }))
        .route("/v1/decisions/evaluate", post(evaluate_decision))
}

async fn evaluate_decision(
    Json(input): Json<PolicyInput>,
) -> Json<aegiscudo_protocol::DecisionResponse> {
    Json(DecisionEngine.evaluate(input))
}
