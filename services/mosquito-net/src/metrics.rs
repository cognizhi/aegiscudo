use std::time::Duration;

use aegiscudo_core::PolicyDecision;
use http::StatusCode;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder,
};
use uuid::Uuid;

use crate::{SERVICE_NAME, registry_config::RegistryAdapter};

pub struct ProxyMetrics {
    registry: Registry,
    requests_total: IntCounterVec,
    request_duration_seconds: HistogramVec,
    decisions_total: IntCounterVec,
    decision_duration_seconds: HistogramVec,
    triage_latency_seconds: HistogramVec,
    upstream_latency_seconds: HistogramVec,
    cache_events_total: IntCounterVec,
}

impl ProxyMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();
        let requests_total = IntCounterVec::new(
            Opts::new(
                "aegiscudo_requests_total",
                "Request count by service, tenant, and route",
            ),
            &["service", "tenant_id", "route", "adapter", "status_code"],
        )?;
        let request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "aegiscudo_request_duration_seconds",
                "Request latency by service, tenant, and route",
            ),
            &["service", "tenant_id", "route", "adapter", "status_code"],
        )?;
        let decisions_total = IntCounterVec::new(
            Opts::new(
                "aegiscudo_decisions_total",
                "Policy decisions by state, tenant, and registry",
            ),
            &[
                "service",
                "tenant_id",
                "registry_config_id",
                "adapter",
                "decision_state",
            ],
        )?;
        let decision_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "aegiscudo_decision_duration_seconds",
                "Decision latency by service, tenant, and registry",
            ),
            &[
                "service",
                "tenant_id",
                "registry_config_id",
                "adapter",
                "decision_state",
            ],
        )?;
        let triage_latency_seconds = HistogramVec::new(
            HistogramOpts::new(
                "aegiscudo_mosquito_net_triage_latency_seconds",
                "Triage Counter client latency by tenant, registry, adapter, and outcome",
            ),
            &[
                "service",
                "tenant_id",
                "registry_config_id",
                "adapter",
                "outcome",
            ],
        )?;
        let upstream_latency_seconds = HistogramVec::new(
            HistogramOpts::new(
                "aegiscudo_mosquito_net_upstream_latency_seconds",
                "Upstream registry latency by tenant, registry, adapter, request kind, and status",
            ),
            &[
                "service",
                "tenant_id",
                "registry_config_id",
                "adapter",
                "request_kind",
                "status_code",
            ],
        )?;
        let cache_events_total = IntCounterVec::new(
            Opts::new(
                "aegiscudo_cache_events_total",
                "Cache events by cache type, tenant, registry, adapter, and outcome",
            ),
            &[
                "service",
                "tenant_id",
                "registry_config_id",
                "adapter",
                "cache_type",
                "outcome",
            ],
        )?;

        registry.register(Box::new(requests_total.clone()))?;
        registry.register(Box::new(request_duration_seconds.clone()))?;
        registry.register(Box::new(decisions_total.clone()))?;
        registry.register(Box::new(decision_duration_seconds.clone()))?;
        registry.register(Box::new(triage_latency_seconds.clone()))?;
        registry.register(Box::new(upstream_latency_seconds.clone()))?;
        registry.register(Box::new(cache_events_total.clone()))?;

        Ok(Self {
            registry,
            requests_total,
            request_duration_seconds,
            decisions_total,
            decision_duration_seconds,
            triage_latency_seconds,
            upstream_latency_seconds,
            cache_events_total,
        })
    }

    pub fn observe_request(
        &self,
        tenant_id: Option<Uuid>,
        route: &str,
        adapter: Option<RegistryAdapter>,
        status: StatusCode,
        elapsed: Duration,
    ) {
        let tenant_label = tenant_id
            .map(|tenant_id| tenant_id.to_string())
            .unwrap_or_else(|| "unknown".to_owned());
        let status_label = status.as_u16().to_string();
        let adapter_label = adapter.map(adapter_label).unwrap_or("unresolved");
        let labels = [
            SERVICE_NAME,
            tenant_label.as_str(),
            route,
            adapter_label,
            status_label.as_str(),
        ];
        self.requests_total.with_label_values(&labels).inc();
        self.request_duration_seconds
            .with_label_values(&labels)
            .observe(elapsed.as_secs_f64());
    }

    pub fn observe_decision(
        &self,
        tenant_id: Uuid,
        registry_config_id: Uuid,
        adapter: RegistryAdapter,
        decision: &PolicyDecision,
        elapsed: Duration,
    ) {
        let tenant_label = tenant_id.to_string();
        let registry_label = registry_config_id.to_string();
        let labels = [
            SERVICE_NAME,
            tenant_label.as_str(),
            registry_label.as_str(),
            adapter_label(adapter),
            decision_label(decision),
        ];
        self.decisions_total.with_label_values(&labels).inc();
        self.decision_duration_seconds
            .with_label_values(&labels)
            .observe(elapsed.as_secs_f64());
    }

    pub fn observe_triage(
        &self,
        tenant_id: Uuid,
        registry_config_id: Uuid,
        adapter: RegistryAdapter,
        outcome: &'static str,
        elapsed: Duration,
    ) {
        let tenant_label = tenant_id.to_string();
        let registry_label = registry_config_id.to_string();
        let labels = [
            SERVICE_NAME,
            tenant_label.as_str(),
            registry_label.as_str(),
            adapter_label(adapter),
            outcome,
        ];
        self.triage_latency_seconds
            .with_label_values(&labels)
            .observe(elapsed.as_secs_f64());
    }

    pub fn observe_cache(
        &self,
        tenant_id: Uuid,
        registry_config_id: Uuid,
        adapter: RegistryAdapter,
        cache_type: &'static str,
        outcome: &'static str,
    ) {
        let tenant_label = tenant_id.to_string();
        let registry_label = registry_config_id.to_string();
        let labels = [
            SERVICE_NAME,
            tenant_label.as_str(),
            registry_label.as_str(),
            adapter_label(adapter),
            cache_type,
            outcome,
        ];
        self.cache_events_total.with_label_values(&labels).inc();
    }

    pub fn observe_upstream(
        &self,
        tenant_id: Uuid,
        registry_config_id: Uuid,
        adapter: RegistryAdapter,
        request_kind: &'static str,
        status: StatusCode,
        elapsed: Duration,
    ) {
        let tenant_label = tenant_id.to_string();
        let registry_label = registry_config_id.to_string();
        let status_label = status.as_u16().to_string();
        let labels = [
            SERVICE_NAME,
            tenant_label.as_str(),
            registry_label.as_str(),
            adapter_label(adapter),
            request_kind,
            status_label.as_str(),
        ];
        self.upstream_latency_seconds
            .with_label_values(&labels)
            .observe(elapsed.as_secs_f64());
    }

    pub fn render(&self) -> Result<String, prometheus::Error> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer).expect("Prometheus metrics must be UTF-8"))
    }

    pub fn content_type(&self) -> String {
        TextEncoder::new().format_type().to_owned()
    }
}

fn adapter_label(adapter: RegistryAdapter) -> &'static str {
    match adapter {
        RegistryAdapter::Npm => "npm",
        RegistryAdapter::Pypi => "pypi",
        RegistryAdapter::Cargo => "cargo",
        RegistryAdapter::Maven => "maven",
        RegistryAdapter::DockerOci => "docker-oci",
        RegistryAdapter::GenericHttp => "generic-http",
    }
}

fn decision_label(decision: &PolicyDecision) -> &'static str {
    match decision {
        PolicyDecision::Allow => "ALLOW",
        PolicyDecision::AllowWithWarning => "ALLOW_WITH_WARNING",
        PolicyDecision::QuarantinePendingAnalysis => "QUARANTINE_PENDING_ANALYSIS",
        PolicyDecision::BlockKnownMalicious => "BLOCK_KNOWN_MALICIOUS",
        PolicyDecision::BlockPolicyViolation => "BLOCK_POLICY_VIOLATION",
        PolicyDecision::RequireHitlApproval => "REQUIRE_HITL_APPROVAL",
        PolicyDecision::FallbackToApprovedCandidate => "FALLBACK_TO_APPROVED_CANDIDATE",
    }
}
