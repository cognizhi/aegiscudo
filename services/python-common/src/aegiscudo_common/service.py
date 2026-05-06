from __future__ import annotations

from collections.abc import Awaitable, Callable
from uuid import uuid4

import structlog
from fastapi import FastAPI, Request, Response


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
    return (
        f"# HELP aegiscudo_{normalized_service}_up Service health gauge\n"
        f"# TYPE aegiscudo_{normalized_service}_up gauge\n"
        f'aegiscudo_{normalized_service}_up{{service="{service_name}"}} 1\n'
    )