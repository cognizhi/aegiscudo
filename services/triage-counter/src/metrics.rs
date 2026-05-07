use std::time::Duration;

use aegiscudo_core::{FeedState, PolicyDecision};
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder,
};
use uuid::Uuid;

use crate::SERVICE_NAME;

#[derive(Debug, Clone)]
pub struct DecisionMetrics {
    registry: Registry,
    decisions_total: IntCounterVec,
    decision_duration_seconds: HistogramVec,
    degraded_feed_decisions_total: IntCounterVec,
    cache_events_total: IntCounterVec,
}

impl DecisionMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();
        let decisions_total = IntCounterVec::new(
            Opts::new(
                "aegiscudo_decisions_total",
                "Policy decisions by state, tenant, and registry",
            ),
            &[
                "service",
                "tenant_id",
                "registry_config_id",
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
                "decision_state",
            ],
        )?;
        let degraded_feed_decisions_total = IntCounterVec::new(
            Opts::new(
                "aegiscudo_triage_counter_degraded_feed_decisions_total",
                "Decisions evaluated while feed state was stale, degraded, or unavailable",
            ),
            &[
                "service",
                "tenant_id",
                "registry_config_id",
                "feed_state",
                "decision_state",
            ],
        )?;
        let cache_events_total = IntCounterVec::new(
            Opts::new(
                "aegiscudo_triage_counter_cache_events_total",
                "Triage Counter decision cache events by tenant, registry, and outcome",
            ),
            &["service", "tenant_id", "registry_config_id", "outcome"],
        )?;

        registry.register(Box::new(decisions_total.clone()))?;
        registry.register(Box::new(decision_duration_seconds.clone()))?;
        registry.register(Box::new(degraded_feed_decisions_total.clone()))?;
        registry.register(Box::new(cache_events_total.clone()))?;

        Ok(Self {
            registry,
            decisions_total,
            decision_duration_seconds,
            degraded_feed_decisions_total,
            cache_events_total,
        })
    }

    pub fn observe_decision(
        &self,
        tenant_id: Uuid,
        registry_config_id: Uuid,
        decision: &PolicyDecision,
        feed_state: &FeedState,
        elapsed: Duration,
    ) {
        let tenant_label = tenant_id.to_string();
        let registry_label = registry_config_id.to_string();
        let decision_label = decision_label(decision);
        let labels = [
            SERVICE_NAME,
            tenant_label.as_str(),
            registry_label.as_str(),
            decision_label,
        ];

        self.decisions_total.with_label_values(&labels).inc();
        self.decision_duration_seconds
            .with_label_values(&labels)
            .observe(elapsed.as_secs_f64());

        if !matches!(feed_state, FeedState::Fresh) {
            let degraded_labels = [
                SERVICE_NAME,
                tenant_label.as_str(),
                registry_label.as_str(),
                feed_state_label(feed_state),
                decision_label,
            ];
            self.degraded_feed_decisions_total
                .with_label_values(&degraded_labels)
                .inc();
        }
    }

    pub fn render(&self) -> Result<String, prometheus::Error> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer).expect("Prometheus metrics must be UTF-8"))
    }

    pub fn observe_cache(&self, tenant_id: Uuid, registry_config_id: Uuid, outcome: &'static str) {
        let tenant_label = tenant_id.to_string();
        let registry_label = registry_config_id.to_string();
        let labels = [
            SERVICE_NAME,
            tenant_label.as_str(),
            registry_label.as_str(),
            outcome,
        ];
        self.cache_events_total.with_label_values(&labels).inc();
    }

    pub fn content_type(&self) -> String {
        TextEncoder::new().format_type().to_owned()
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

fn feed_state_label(feed_state: &FeedState) -> &'static str {
    match feed_state {
        FeedState::Fresh => "fresh",
        FeedState::Stale => "stale",
        FeedState::Degraded => "degraded",
        FeedState::Unavailable => "unavailable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_includes_decision_and_degraded_feed_metrics() {
        let metrics = DecisionMetrics::new().expect("metrics");
        let tenant_id = Uuid::now_v7();
        let registry_config_id = Uuid::now_v7();

        metrics.observe_decision(
            tenant_id,
            registry_config_id,
            &PolicyDecision::AllowWithWarning,
            &FeedState::Degraded,
            Duration::from_millis(42),
        );

        let rendered = metrics.render().expect("rendered metrics");
        assert!(rendered.contains("aegiscudo_decisions_total"));
        assert!(rendered.contains("aegiscudo_decision_duration_seconds"));
        assert!(rendered.contains("aegiscudo_triage_counter_degraded_feed_decisions_total"));
        assert!(rendered.contains("decision_state=\"ALLOW_WITH_WARNING\""));
        assert!(rendered.contains("feed_state=\"degraded\""));
        assert!(rendered.contains(&format!("tenant_id=\"{}\"", tenant_id)));
        assert!(rendered.contains(&format!("registry_config_id=\"{}\"", registry_config_id)));
    }
}
