"""OpenTelemetry initialisation for the Autonomous Pentesting Agent.

Sets up:
- OTLP gRPC span exporter → otel-collector
- LangChain auto-instrumentation (spans for every LLM call and tool call)
- httpx auto-instrumentation (spans for every HTTP request to the target)

A root span ("agent.run") is started immediately so that all child spans
(httpx, LangChain) are nested under one trace.  Call end_root_span() when
the agent run finishes so the root span is closed and flushed.
"""
from __future__ import annotations

import os
from typing import Any

from opentelemetry import context as otel_context
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
    OTLPSpanExporter,
)
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

# Module-level references so main.py can close them at shutdown
_root_span: Any = None
_ctx_token: Any = None


def setup_telemetry(
    target_url: str = "",
    username: str = "",
) -> TracerProvider:
    """Initialise OpenTelemetry, start a root span, return the TracerProvider.

    A root "agent.run" span is created and attached to the current context so
    that every httpx and LangChain child span is nested under the same trace.
    Call end_root_span() once the agent finishes.
    """
    global _root_span, _ctx_token

    service_name = os.getenv("OTEL_SERVICE_NAME", "autonomous-pen-tester")
    otlp_endpoint = os.getenv(
        "OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317"
    )

    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)

    exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
    provider.add_span_processor(BatchSpanProcessor(exporter))

    trace.set_tracer_provider(provider)

    # Auto-instrument httpx (covers all HTTP calls to the target app)
    HTTPXClientInstrumentor().instrument()

    # Auto-instrument LangChain (covers LLM calls and tool calls).
    # Wrapped broadly: some instrumentation versions are incompatible with
    # certain langchain releases and raise TypeError at instrument() time.
    try:
        from opentelemetry.instrumentation.langchain import LangchainInstrumentor  # type: ignore
        LangchainInstrumentor().instrument()
    except Exception:  # noqa: BLE001
        pass  # graceful degradation — tracing still works for httpx spans

    # Start a root span so child spans (httpx, LangChain) share one trace_id
    tracer = trace.get_tracer(service_name)
    attrs: dict[str, str] = {}
    if target_url:
        attrs["agent.target"] = target_url
    if username:
        attrs["agent.username"] = username
    _root_span = tracer.start_span(
        "agent.run", attributes=attrs or None
    )
    ctx = trace.set_span_in_context(_root_span)
    _ctx_token = otel_context.attach(ctx)

    return provider


def end_root_span() -> None:
    """Close the root span and detach the context.  Call before force_flush."""
    global _root_span, _ctx_token
    if _ctx_token is not None:
        otel_context.detach(_ctx_token)
        _ctx_token = None
    if _root_span is not None:
        _root_span.end()
        _root_span = None


def get_current_trace_id() -> str:
    """Return the current OTel trace_id as a hex string, or empty string."""
    span = trace.get_current_span()
    ctx = span.get_span_context()
    if ctx and ctx.is_valid:
        return format(ctx.trace_id, "032x")
    return ""
