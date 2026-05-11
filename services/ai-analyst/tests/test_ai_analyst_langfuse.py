from __future__ import annotations

from ai_analyst.langfuse_client import OptionalLangfuseTraceClient, resolve_langfuse_settings


class FakeGeneration:
    def __init__(self) -> None:
        self.output = None

    def end(self, *, output):  # noqa: ANN001
        self.output = output


class FakeTrace:
    def __init__(self) -> None:
        self.id = "trace-123"
        self.generation_calls = []
        self.ended = None

    def generation(self, **kwargs):  # noqa: ANN003
        self.generation_calls.append(kwargs)
        return FakeGeneration()

    def end(self, *, output, metadata):  # noqa: ANN001
        self.ended = {"output": output, "metadata": metadata}


class FakeLangfuse:
    def __init__(self) -> None:
        self.trace_calls = []
        self.trace_instance = FakeTrace()
        self.flushed = False

    def trace(self, **kwargs):  # noqa: ANN003
        self.trace_calls.append(kwargs)
        return self.trace_instance

    def flush(self) -> None:
        self.flushed = True


def test_resolve_langfuse_settings_requires_complete_configuration() -> None:
    assert resolve_langfuse_settings({}) is None
    assert resolve_langfuse_settings({"LANGFUSE_HOST": "http://localhost:13001"}) is None


def test_optional_trace_client_records_generation() -> None:
    fake_langfuse = FakeLangfuse()
    client = OptionalLangfuseTraceClient(fake_langfuse)

    trace_id = client.record_generation(
        trace_name="ai-analyst-job",
        session_id="job-1",
        provider="local-preview",
        model="deterministic-preview",
        prompt_template_version="analysis-preview-v1",
        input_payload={"static_indicators": []},
        output_payload={"summary": "ok"},
        metadata={"analysis_job_id": "job-1"},
    )

    assert trace_id == "trace-123"
    assert fake_langfuse.trace_calls[0]["name"] == "ai-analyst-job"
    assert fake_langfuse.trace_calls[0]["session_id"] == "job-1"
    assert fake_langfuse.trace_instance.generation_calls[0]["model"] == "deterministic-preview"
    assert fake_langfuse.trace_instance.ended is not None
    assert fake_langfuse.flushed is True