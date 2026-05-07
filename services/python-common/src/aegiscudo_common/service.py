from __future__ import annotations

from collections.abc import Awaitable, Callable
from uuid import uuid4

import structlog
from fastapi import FastAPI, Request, Response

DEFAULT_PROMETHEUS_METRICS: tuple[tuple[str, str, str], ...] = (
    ("aegiscudo_requests_total", "counter", "Request count by service, tenant, and route"),
    (
        "aegiscudo_request_duration_seconds",
        "histogram",
        "Request latency by service, tenant, and route",
    ),
    ("aegiscudo_decisions_total", "counter", "Policy decisions by state, tenant, and registry"),
    (
        "aegiscudo_decision_duration_seconds",
        "histogram",
        "Decision latency by service, tenant, and registry",
    ),
    (
        "aegiscudo_analysis_jobs_total",
        "counter",
        "Analysis jobs by state, tenant, and ecosystem",
    ),
    (
        "aegiscudo_analysis_duration_seconds",
        "histogram",
        "Analysis duration by analyzer and result",
    ),
    ("aegiscudo_sandbox_runs_total", "counter", "Sandbox runs by profile, phase, and result"),
    ("aegiscudo_sandbox_duration_seconds", "histogram", "Sandbox duration by profile and phase"),
    ("aegiscudo_feed_records_total", "gauge", "Normalized feed records by feed and state"),
    ("aegiscudo_feed_snapshot_age_seconds", "gauge", "Age of the latest usable feed snapshot"),
    ("aegiscudo_llm_requests_total", "counter", "LLM requests by provider, model, and result"),
    (
        "aegiscudo_llm_request_duration_seconds",
        "histogram",
        "LLM request latency by provider and model",
    ),
    (
        "aegiscudo_llm_tokens_total",
        "counter",
        "LLM token usage by provider, model, tenant, and direction",
    ),
)
DEFAULT_PROMETHEUS_METRIC_NAMES: tuple[str, ...] = tuple(
    name for name, _kind, _help in DEFAULT_PROMETHEUS_METRICS
)


def install_request_context(app: FastAPI) -> None:
    @app.middleware("http")
    async def request_context(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        trace_id = request.headers.get("x-trace-id") or str(uuid4())
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(trace_id=trace_id)
        try:
            response = await call_next(request)
            response.headers.setdefault("x-trace-id", trace_id)
            return response
        finally:
            structlog.contextvars.clear_contextvars()


def metrics_text(service_name: str) -> str:
    normalized_service = service_name.replace("-", "_")
    default_metric_help = "".join(
        f"# HELP {name} {help_text}\n# TYPE {name} {kind}\n"
        for name, kind, help_text in DEFAULT_PROMETHEUS_METRICS
    )
    return (
        f"# HELP aegiscudo_{normalized_service}_up Service health gauge\n"
        f"# TYPE aegiscudo_{normalized_service}_up gauge\n"
        f'aegiscudo_{normalized_service}_up{{service="{service_name}"}} 1\n'
        f"{default_metric_help}"
    )
