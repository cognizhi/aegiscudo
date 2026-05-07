from aegiscudo_common.service import DEFAULT_PROMETHEUS_METRIC_NAMES, metrics_text


def test_default_metric_names_cover_required_operation_classes() -> None:
    assert any("requests" in name for name in DEFAULT_PROMETHEUS_METRIC_NAMES)
    assert any("decisions" in name for name in DEFAULT_PROMETHEUS_METRIC_NAMES)
    assert any("analysis" in name for name in DEFAULT_PROMETHEUS_METRIC_NAMES)
    assert any("sandbox" in name for name in DEFAULT_PROMETHEUS_METRIC_NAMES)
    assert any("feed" in name for name in DEFAULT_PROMETHEUS_METRIC_NAMES)
    assert any("llm" in name for name in DEFAULT_PROMETHEUS_METRIC_NAMES)


def test_metrics_text_includes_common_foundation_metric_names() -> None:
    metrics = metrics_text("ai-analyst")

    assert "aegiscudo_ai_analyst_up" in metrics
    assert "aegiscudo_decisions_total" in metrics
    assert "aegiscudo_sandbox_runs_total" in metrics
    assert "aegiscudo_llm_requests_total" in metrics
    assert "aegiscudo_llm_tokens_total" in metrics
