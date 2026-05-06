use std::collections::BTreeMap;
use std::sync::OnceLock;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

static INIT_RESULT: OnceLock<()> = OnceLock::new();

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
}
