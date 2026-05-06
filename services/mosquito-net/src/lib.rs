use aegiscudo_protocol::{canonicalize_pypi_name, normalize_npm_name};
use aegiscudo_telemetry::health;
use axum::{Json, Router, extract::Path, http::StatusCode, routing::get};
use serde::Serialize;

pub const SERVICE_NAME: &str = "mosquito-net";

#[derive(Debug, Serialize)]
struct ProxyPlaceholderResponse {
    mount_path: String,
    upstream_path: String,
    normalized_name: Option<String>,
    message: &'static str,
}

pub fn app() -> Router {
    Router::new()
        .route("/healthz", get(|| async { Json(health(SERVICE_NAME)) }))
        .route("/readyz", get(|| async { Json(health(SERVICE_NAME)) }))
        .route("/metrics", get(metrics))
        .route("/proxy/{mount}/{*upstream_path}", get(proxy_get))
}

async fn metrics() -> &'static str {
    "# HELP aegiscudo_mosquito_net_requests_total Total Mosquito Net requests\n# TYPE aegiscudo_mosquito_net_requests_total counter\n"
}

async fn proxy_get(
    Path((mount, upstream_path)): Path<(String, String)>,
) -> Result<Json<ProxyPlaceholderResponse>, StatusCode> {
    let normalized_name = match mount.as_str() {
        "npm-public" => normalize_npm_name(&upstream_path)
            .ok()
            .map(|coordinate| coordinate.purl()),
        "pypi-public" => canonicalize_pypi_name(upstream_path.trim_start_matches("simple/"))
            .ok()
            .map(|name| format!("pkg:pypi/{name}")),
        _ => None,
    };

    Ok(Json(ProxyPlaceholderResponse {
        mount_path: mount,
        upstream_path,
        normalized_name,
        message: "adapter dispatch scaffold is ready; upstream proxying is implemented in Phase 1A tasks",
    }))
}
