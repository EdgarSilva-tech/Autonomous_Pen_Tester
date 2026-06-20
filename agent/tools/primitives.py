"""Layer 1 HTTP primitives — generic, API-agnostic tools available to the LLM.

The underlying _do_http_* coroutines are imported by Layer 2 attack modules
so they can build specialised probes without going through LangChain tooling.
The @tool-decorated wrappers expose the same functionality to the LLM for
ad-hoc probing of endpoints that no named attack module covers.
"""
from __future__ import annotations

import contextvars
import os
from dataclasses import dataclass
from typing import Any

import httpx
from langchain_core.tools import tool
from opentelemetry import trace

from agent.logger import get_logger

log = get_logger(__name__)
_tracer = trace.get_tracer("agent.tools.primitives")

# ── Base URL ──────────────────────────────────────────────────────────────────

_base_url_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "pentest_base_url",
    default=os.getenv("TARGET_BASE_URL", "http://localhost:8000"),
)

REQUEST_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "10"))


def set_base_url(url: str) -> None:
    _base_url_var.set(url)


# ── Session store — persistent headers / cookies within a run ─────────────────
# Each asyncio Task inherits a copy of the context from its creator, so the
# session is automatically scoped to the agent run that started the graph.

_session_headers_var: contextvars.ContextVar[dict[str, str] | None] = (
    contextvars.ContextVar("session_headers", default=None)
)
_session_cookies_var: contextvars.ContextVar[dict[str, str] | None] = (
    contextvars.ContextVar("session_cookies", default=None)
)


def _get_session_headers() -> dict[str, str]:
    h = _session_headers_var.get()
    if h is None:
        h = {}
        _session_headers_var.set(h)
    return h


def _get_session_cookies() -> dict[str, str]:
    c = _session_cookies_var.get()
    if c is None:
        c = {}
        _session_cookies_var.set(c)
    return c


def reset_session() -> None:
    """Clear all persisted session headers and cookies. Call once per run."""
    _session_headers_var.set({})
    _session_cookies_var.set({})


# ── HttpResponse ──────────────────────────────────────────────────────────────

@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: Any          # parsed JSON (dict/list) or raw str
    elapsed_ms: int
    error: str | None = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "ok": self.ok,
            "headers": self.headers,
            "body": self.body,
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
        }


# ── Internal helpers ──────────────────────────────────────────────────────────

def _make_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=_base_url_var.get(),
        timeout=REQUEST_TIMEOUT,
        headers=dict(_get_session_headers()),
        cookies=dict(_get_session_cookies()),
    )


def _parse_response(resp: httpx.Response) -> HttpResponse:
    try:
        body: Any = resp.json()
    except Exception:
        body = resp.text
    try:
        elapsed_ms = int(resp.elapsed.total_seconds() * 1000)
    except Exception:
        elapsed_ms = 0
    return HttpResponse(
        status=resp.status_code,
        headers=dict(resp.headers),
        body=body,
        elapsed_ms=elapsed_ms,
    )


# ── Internal coroutines (imported by Layer 2 attack modules) ──────────────────

async def _do_http_get(
    url: str,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
    timeout: float | None = None,
) -> HttpResponse:
    with _tracer.start_as_current_span("http.get", attributes={"http.url": url}):
        async with _make_client() as client:
            kwargs: dict[str, Any] = {}
            if params:
                kwargs["params"] = params
            if headers:
                kwargs["headers"] = headers
            if timeout is not None:
                kwargs["timeout"] = timeout
            resp = await client.get(url, **kwargs)
    return _parse_response(resp)


async def _do_http_post(
    url: str,
    body: dict[str, Any] | str | None = None,
    headers: dict[str, str] | None = None,
    content_type: str = "application/json",
    timeout: float | None = None,
) -> HttpResponse:
    with _tracer.start_as_current_span("http.post", attributes={"http.url": url}):
        async with _make_client() as client:
            kwargs: dict[str, Any] = {}
            if body is not None:
                if content_type == "application/json" or isinstance(body, dict):
                    kwargs["json"] = body
                else:
                    data = body if isinstance(body, bytes) else str(body).encode()
                    kwargs["content"] = data
                    kwargs["headers"] = {"Content-Type": content_type, **(headers or {})}
                    headers = None
            if headers:
                kwargs["headers"] = {**kwargs.get("headers", {}), **headers}
            if timeout is not None:
                kwargs["timeout"] = timeout
            resp = await client.post(url, **kwargs)
    return _parse_response(resp)


async def _do_http_put(
    url: str,
    body: dict[str, Any] | str | None = None,
    headers: dict[str, str] | None = None,
    timeout: float | None = None,
) -> HttpResponse:
    with _tracer.start_as_current_span("http.put", attributes={"http.url": url}):
        async with _make_client() as client:
            kwargs: dict[str, Any] = {}
            if body is not None:
                kwargs["json"] = body
            if headers:
                kwargs["headers"] = headers
            if timeout is not None:
                kwargs["timeout"] = timeout
            resp = await client.put(url, **kwargs)
    return _parse_response(resp)


async def _do_http_delete(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: float | None = None,
) -> HttpResponse:
    with _tracer.start_as_current_span("http.delete", attributes={"http.url": url}):
        async with _make_client() as client:
            kwargs: dict[str, Any] = {}
            if headers:
                kwargs["headers"] = headers
            if timeout is not None:
                kwargs["timeout"] = timeout
            resp = await client.delete(url, **kwargs)
    return _parse_response(resp)


# ── @tool wrappers (Layer 1 — called by the LLM for ad-hoc probing) ──────────

@tool
async def http_get(
    url: str,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Send an HTTP GET request to the target.

    Use for retrieving resources, probing endpoints, and reading responses.
    Session headers set via set_session_header are merged automatically.
    Returns: {status, ok, headers, body, elapsed_ms, error}.
    """
    log.debug("primitive.http_get", url=url)
    return (await _do_http_get(url, headers=headers, params=params)).to_dict()


@tool
async def http_post(
    url: str,
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    content_type: str = "application/json",
) -> dict[str, Any]:
    """Send an HTTP POST request to the target.

    Use for form submission, login attempts, mutations, and injection probing.
    body is serialised as JSON by default; set content_type to override.
    Returns: {status, ok, headers, body, elapsed_ms, error}.
    """
    log.debug("primitive.http_post", url=url)
    return (await _do_http_post(url, body=body, headers=headers, content_type=content_type)).to_dict()


@tool
async def http_put(
    url: str,
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Send an HTTP PUT request to the target.

    Use for update operations and testing whether PUT is accepted on an endpoint.
    Returns: {status, ok, headers, body, elapsed_ms, error}.
    """
    log.debug("primitive.http_put", url=url)
    return (await _do_http_put(url, body=body, headers=headers)).to_dict()


@tool
async def http_delete(
    url: str,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Send an HTTP DELETE request to the target.

    Use for testing whether DELETE is accepted on endpoints that should forbid it.
    Returns: {status, ok, headers, body, elapsed_ms, error}.
    """
    log.debug("primitive.http_delete", url=url)
    return (await _do_http_delete(url, headers=headers)).to_dict()


@tool
def set_session_header(name: str, value: str) -> dict[str, str]:
    """Persist an HTTP request header for all subsequent calls in this run.

    Use once to set Authorization, Accept, or any other header rather than
    repeating it in every http_get / http_post call.
    Returns the full set of currently persisted session headers.
    """
    h = _get_session_headers()
    h[name] = value
    log.debug("primitive.set_session_header", name=name)
    return dict(h)


@tool
def clear_session_headers() -> dict[str, str]:
    """Remove all persisted session headers.

    Use when switching users or testing unauthenticated access after an
    authenticated session. Returns an empty dict.
    """
    # Clear in place so the mutation is visible outside the copied context
    # that LangChain uses when running @tool functions via context.run().
    _get_session_headers().clear()
    return {}


PRIMITIVE_TOOLS = [
    http_get,
    http_post,
    http_put,
    http_delete,
    set_session_header,
    clear_session_headers,
]
