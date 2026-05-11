from __future__ import annotations

import os
from dataclasses import dataclass
from time import perf_counter
from typing import Any, Protocol


try:
    from langfuse import Langfuse
except ModuleNotFoundError:  # pragma: no cover - exercised only when dependency is absent.
    Langfuse = None


class TraceClient(Protocol):
    def record_generation(
        self,
        *,
        trace_name: str,
        session_id: str,
        provider: str,
        model: str,
        prompt_template_version: str,
        input_payload: dict[str, Any],
        output_payload: dict[str, Any],
        metadata: dict[str, Any],
    ) -> str | None: ...


@dataclass(frozen=True)
class LangfuseSettings:
    host: str
    public_key: str
    secret_key: str


class OptionalLangfuseTraceClient:
    def __init__(self, client: Any) -> None:
        self._client = client

    def record_generation(
        self,
        *,
        trace_name: str,
        session_id: str,
        provider: str,
        model: str,
        prompt_template_version: str,
        input_payload: dict[str, Any],
        output_payload: dict[str, Any],
        metadata: dict[str, Any],
    ) -> str | None:
        started = perf_counter()
        trace = self._client.trace(
            name=trace_name,
            session_id=session_id,
            metadata=metadata,
            input=input_payload,
        )
        generation = trace.generation(
            name="ai-analyst-generation",
            model=model,
            input=input_payload,
            model_parameters={"prompt_template_version": prompt_template_version, "provider": provider},
        )
        generation.end(output=output_payload)
        trace.end(
            output=output_payload,
            metadata={
                **metadata,
                "latency_ms": round((perf_counter() - started) * 1000, 2),
                "prompt_template_version": prompt_template_version,
                "provider": provider,
                "model": model,
            },
        )
        self._client.flush()
        return getattr(trace, "id", None)


def build_optional_trace_client(env: dict[str, str] | None = None) -> TraceClient | None:
    if Langfuse is None:
        return None
    values = os.environ if env is None else env
    settings = resolve_langfuse_settings(values)
    if settings is None:
        return None
    client = Langfuse(
        public_key=settings.public_key,
        secret_key=settings.secret_key,
        host=settings.host,
    )
    return OptionalLangfuseTraceClient(client)


def resolve_langfuse_settings(env: dict[str, str] | None = None) -> LangfuseSettings | None:
    values = os.environ if env is None else env
    host = values.get("LANGFUSE_HOST", "").strip()
    public_key = values.get("LANGFUSE_PUBLIC_KEY", "").strip()
    secret_key = values.get("LANGFUSE_SECRET_KEY", "").strip()
    if not host or not public_key or not secret_key:
        return None
    return LangfuseSettings(host=host, public_key=public_key, secret_key=secret_key)