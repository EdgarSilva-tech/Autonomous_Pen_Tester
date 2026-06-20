"""Layer 2 — Authentication attack tools.

Thin wrappers over the Layer 1 HTTP primitives that preserve the original
tool signatures, OTel spans, structured logging, and result format so the
existing auth-flow tests and report assembly continue to work unchanged.
"""
from __future__ import annotations

from typing import Any

from langchain_core.tools import tool
from opentelemetry import trace
from opentelemetry.trace import StatusCode

from agent.logger import get_logger
from agent.tools.primitives import _do_http_get, _do_http_post

log = get_logger(__name__)
_tracer = trace.get_tracer("agent.tools.auth")


def _auth_result(step: str, resp) -> dict[str, Any]:
    """Build the result dict that the evaluator and report nodes expect."""
    return {
        "step": step,
        "http_status": resp.status,
        "body": resp.body,
        "ok": resp.ok,
    }


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
        resp = await _do_http_post("/login", body={"username": username, "password": password})
        result = _auth_result("login", resp)
        span.set_attribute("http.status_code", resp.status)
        span.set_attribute("pentest.ok", result["ok"])
        log.info("tool.login.result", http_status=resp.status, ok=result["ok"])
    return result


@tool
async def me_tool(token: str) -> dict[str, Any]:
    """GET /me — retrieve authenticated user info using a Bearer token.
    Returns user data on success, or 401 if the token is invalid/expired.
    A 401 is the CORRECT outcome when validating session invalidation after
    a password change or logout.
    """
    log.info("tool.me", token_prefix=token[:8] if token else "none")
    with _tracer.start_as_current_span(
        "pentest.validate_session",
        attributes={"pentest.step": "validate_session"},
    ) as span:
        resp = await _do_http_get("/me", headers={"Authorization": f"Bearer {token}"})
        result = _auth_result("me", resp)
        span.set_attribute("http.status_code", resp.status)
        span.set_attribute("pentest.http_ok", result["ok"])
        # A 401 here is semantically correct for invalidation-validation steps;
        # mark the span OK so Tempo doesn't highlight it as an error.
        span.set_status(StatusCode.OK)
        log.info("tool.me.result", http_status=resp.status, ok=result["ok"])
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
        resp = await _do_http_post(
            "/change-password",
            body={"current_password": current_password, "new_password": new_password},
            headers={"Authorization": f"Bearer {token}"},
        )
        result = _auth_result("change_password", resp)
        span.set_attribute("http.status_code", resp.status)
        span.set_attribute("pentest.ok", result["ok"])
        log.info("tool.change_password.result", http_status=resp.status, ok=result["ok"])
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
        resp = await _do_http_post("/logout", headers={"Authorization": f"Bearer {token}"})
        result = _auth_result("logout", resp)
        span.set_attribute("http.status_code", resp.status)
        span.set_attribute("pentest.ok", result["ok"])
        log.info("tool.logout.result", http_status=resp.status, ok=result["ok"])
    return result


AUTH_TOOLS = [login_tool, me_tool, change_password_tool, logout_tool]
