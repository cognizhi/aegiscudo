use std::collections::BTreeMap;
use std::sync::OnceLock;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

static INIT_RESULT: OnceLock<()> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricDefinition {
    pub name: &'static str,
    pub kind: &'static str,
    pub help: &'static str,
}

pub const DEFAULT_PROMETHEUS_METRICS: &[MetricDefinition] = &[
    MetricDefinition {
        name: "aegiscudo_requests_total",
        kind: "counter",
        help: "Request count by service, tenant, and route",
    },
    MetricDefinition {
        name: "aegiscudo_request_duration_seconds",
        kind: "histogram",
        help: "Request latency by service, tenant, and route",
    },
    MetricDefinition {
        name: "aegiscudo_decisions_total",
        kind: "counter",
        help: "Policy decisions by state, tenant, and registry",
    },
    MetricDefinition {
        name: "aegiscudo_decision_duration_seconds",
        kind: "histogram",
        help: "Decision latency by service, tenant, and registry",
    },
    MetricDefinition {
        name: "aegiscudo_analysis_jobs_total",
        kind: "counter",
        help: "Analysis jobs by state, tenant, and ecosystem",
    },
    MetricDefinition {
        name: "aegiscudo_analysis_duration_seconds",
        kind: "histogram",
        help: "Analysis duration by analyzer and result",
    },
    MetricDefinition {
        name: "aegiscudo_sandbox_runs_total",
        kind: "counter",
        help: "Sandbox runs by profile, phase, and result",
    },
    MetricDefinition {
        name: "aegiscudo_sandbox_duration_seconds",
        kind: "histogram",
        help: "Sandbox duration by profile and phase",
    },
    MetricDefinition {
        name: "aegiscudo_feed_records_total",
        kind: "gauge",
        help: "Normalized feed records by feed and state",
    },
    MetricDefinition {
        name: "aegiscudo_feed_snapshot_age_seconds",
        kind: "gauge",
        help: "Age of the latest usable feed snapshot",
    },
    MetricDefinition {
        name: "aegiscudo_llm_requests_total",
        kind: "counter",
        help: "LLM requests by provider, model, and result",
    },
    MetricDefinition {
        name: "aegiscudo_llm_request_duration_seconds",
        kind: "histogram",
        help: "LLM request latency by provider and model",
    },
    MetricDefinition {
        name: "aegiscudo_llm_tokens_total",
        kind: "counter",
        help: "LLM token usage by provider, model, tenant, and direction",
    },
];

const SENSITIVE_KEYS: &[&str] = &[
    "authorization",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
];

#[derive(Debug, Clone, Serialize)]
pub struct HealthStatus {
    pub status: &'static str,
    pub service: &'static str,
    pub checked_at: DateTime<Utc>,
}

pub fn init_json_tracing() {
    INIT_RESULT.get_or_init(|| {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    });
}

pub fn health(service: &'static str) -> HealthStatus {
    HealthStatus {
        status: "ok",
        service,
        checked_at: Utc::now(),
    }
}

pub fn new_trace_id() -> String {
    Uuid::now_v7().to_string()
}

pub fn default_prometheus_help_text() -> String {
    DEFAULT_PROMETHEUS_METRICS
        .iter()
        .map(|definition| {
            format!(
                "# HELP {} {}\n# TYPE {} {}\n",
                definition.name, definition.help, definition.name, definition.kind
            )
        })
        .collect()
}

pub fn redact_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, nested)| {
                    if is_sensitive_key(key) {
                        (key.clone(), Value::String("[REDACTED]".to_owned()))
                    } else {
                        (key.clone(), redact_value(nested))
                    }
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(redact_value).collect()),
        _ => value.clone(),
    }
}

pub fn redact_metadata(metadata: &BTreeMap<String, Value>) -> BTreeMap<String, Value> {
    metadata
        .iter()
        .map(|(key, value)| {
            if is_sensitive_key(key) {
                (key.clone(), Value::String("[REDACTED]".to_owned()))
            } else {
                (key.clone(), redact_value(value))
            }
        })
        .collect()
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace('-', "_");
    SENSITIVE_KEYS
        .iter()
        .any(|needle| normalized.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_nested_sensitive_values() {
        let value = json!({
            "safe": "visible",
            "nested": { "api-key": "secret-value" },
            "items": [{ "token": "abc" }]
        });
        let redacted = redact_value(&value);
        assert_eq!(redacted["safe"], "visible");
        assert_eq!(redacted["nested"]["api-key"], "[REDACTED]");
        assert_eq!(redacted["items"][0]["token"], "[REDACTED]");
    }

    #[test]
    fn default_metrics_cover_required_operation_classes() {
        let names: Vec<&str> = DEFAULT_PROMETHEUS_METRICS
            .iter()
            .map(|definition| definition.name)
            .collect();
        assert!(names.iter().any(|name| name.contains("requests")));
        assert!(names.iter().any(|name| name.contains("decisions")));
        assert!(names.iter().any(|name| name.contains("analysis")));
        assert!(names.iter().any(|name| name.contains("sandbox")));
        assert!(names.iter().any(|name| name.contains("feed")));
        assert!(names.iter().any(|name| name.contains("llm")));
        assert!(default_prometheus_help_text().contains("aegiscudo_llm_tokens_total"));
    }
}
