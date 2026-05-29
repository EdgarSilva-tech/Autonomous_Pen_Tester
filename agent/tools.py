"""LangChain tools wrapping the target FastAPI authentication endpoints.

Each tool communicates with the target app via httpx (async) with configurable
timeouts. The base URL is read from the PENTEST_BASE_URL context variable so
that tests can override it without changing tool code.
"""
from __future__ import annotations

import contextvars
import os
from typing import Any

import httpx
from langchain_core.tools import tool
from opentelemetry import trace
from opentelemetry.trace import StatusCode

from agent.logger import get_logger

log = get_logger(__name__)
_tracer = trace.get_tracer("agent.tools")

# Context variable so the base URL is thread-safe and injectable in tests
_base_url_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "pentest_base_url",
    default=os.getenv("TARGET_BASE_URL", "http://localhost:8000"),
)

REQUEST_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "10"))
MAX_RETRIES = int(os.getenv("HTTP_MAX_RETRIES", "3"))


def set_base_url(url: str) -> None:
    _base_url_var.set(url)


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=_base_url_var.get(),
        timeout=REQUEST_TIMEOUT,
    )


def _result(step: str, response: httpx.Response) -> dict[str, Any]:
    try:
        body = response.json()
    except Exception:
        body = response.text
    return {
        "step": step,
        "http_status": response.status_code,
        "body": body,
        "ok": response.is_success,
    }


# ── Tools ─────────────────────────────────────────────────────────────────────

@tool
async def login_tool(username: str, password: str) -> dict[str, Any]:
    """POST /login — authenticate with username and password.
    Returns the session token on success or an error dict on failure.
    """
    log.info("tool.login", username=username)
    with _tracer.start_as_current_span(
        "pentest.login",
        attributes={"pentest.step": "login", "pentest.username": username},
    ) as span:
        async with _client() as client:
            response = await client.post(
                "/login", json={"username": username, "password": password}
            )
        result = _result("login", response)
        span.set_attribute("http.status_code", response.status_code)
        span.set_attribute("pentest.ok", result["ok"])
        log.info(
            "tool.login.result", http_status=response.status_code, ok=result["ok"]
        )
    return result


@tool
async def me_tool(token: str) -> dict[str, Any]:
    """GET /me — retrieve authenticated user info using a Bearer token.
    Returns user data on success, or 401 if the token is invalid/expired.
    A 401 is the CORRECT outcome when called to validate session invalidation
    after a password change or logout.
    """
    log.info("tool.me", token_prefix=token[:8] if token else "none")
    with _tracer.start_as_current_span(
        "pentest.validate_session",
        attributes={"pentest.step": "validate_session"},
    ) as span:
        async with _client() as client:
            response = await client.get(
                "/me", headers={"Authorization": f"Bearer {token}"}
            )
        result = _result("me", response)
        span.set_attribute("http.status_code", response.status_code)
        span.set_attribute("pentest.http_ok", result["ok"])
        # A 401 here is semantically correct for invalidation-validation steps.
        # Mark the span itself as OK so Tempo doesn't highlight it in red.
        span.set_status(StatusCode.OK)
        log.info(
            "tool.me.result", http_status=response.status_code, ok=result["ok"]
        )
    return result


@tool
async def change_password_tool(
    token: str, current_password: str, new_password: str
) -> dict[str, Any]:
    """POST /change-password — change the authenticated user's password.
    Requires a valid Bearer token and both the current and new passwords.
    """
    log.info("tool.change_password")
    with _tracer.start_as_current_span(
        "pentest.change_password",
        attributes={"pentest.step": "change_password"},
    ) as span:
        async with _client() as client:
            response = await client.post(
                "/change-password",
                json={
                    "current_password": current_password,
                    "new_password": new_password,
                },
                headers={"Authorization": f"Bearer {token}"},
            )
        result = _result("change_password", response)
        span.set_attribute("http.status_code", response.status_code)
        span.set_attribute("pentest.ok", result["ok"])
        log.info(
            "tool.change_password.result",
            http_status=response.status_code,
            ok=result["ok"],
        )
    return result


@tool
async def logout_tool(token: str) -> dict[str, Any]:
    """POST /logout — invalidate the current session token.
    After a successful logout, any subsequent /me call with this token should
    return 401. If it does not, that is an anomaly.
    """
    log.info("tool.logout")
    with _tracer.start_as_current_span(
        "pentest.logout",
        attributes={"pentest.step": "logout"},
    ) as span:
        async with _client() as client:
            response = await client.post(
                "/logout", headers={"Authorization": f"Bearer {token}"}
            )
        result = _result("logout", response)
        span.set_attribute("http.status_code", response.status_code)
        span.set_attribute("pentest.ok", result["ok"])
        log.info(
            "tool.logout.result", http_status=response.status_code, ok=result["ok"]
        )
    return result


# Exported pool of HTTP tools
HTTP_TOOLS = [login_tool, me_tool, change_password_tool, logout_tool]
