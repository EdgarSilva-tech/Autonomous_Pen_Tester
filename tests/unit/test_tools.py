"""Unit tests for the HTTP tool layer using respx to mock httpx."""
from __future__ import annotations

import json

import pytest
import respx
import httpx

from tests.conftest import BASE_URL, TOKEN, NEW_TOKEN, USERNAME, PASSWORD, NEW_PASSWORD


# ── login_tool ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_login_success(mock_router):
    mock_router.post("/login").mock(
        return_value=httpx.Response(200, json={"access_token": TOKEN})
    )
    from agent.tools import login_tool
    result = await login_tool.ainvoke({"username": USERNAME, "password": PASSWORD})

    assert result["ok"] is True
    assert result["http_status"] == 200
    assert result["body"]["access_token"] == TOKEN


@pytest.mark.asyncio
async def test_login_invalid_credentials(mock_router):
    mock_router.post("/login").mock(
        return_value=httpx.Response(401, json={"detail": "Invalid credentials"})
    )
    from agent.tools import login_tool
    result = await login_tool.ainvoke({"username": USERNAME, "password": "wrong"})

    assert result["ok"] is False
    assert result["http_status"] == 401


# ── me_tool ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_me_success(mock_router):
    mock_router.get("/me").mock(
        return_value=httpx.Response(200, json={"username": USERNAME})
    )
    from agent.tools import me_tool
    result = await me_tool.ainvoke({"token": TOKEN})

    assert result["ok"] is True
    assert result["body"]["username"] == USERNAME


@pytest.mark.asyncio
async def test_me_unauthorized(mock_router):
    mock_router.get("/me").mock(
        return_value=httpx.Response(401, json={"detail": "Not authenticated"})
    )
    from agent.tools import me_tool
    result = await me_tool.ainvoke({"token": "expired-token"})

    assert result["ok"] is False
    assert result["http_status"] == 401


# ── change_password_tool ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_change_password_success(mock_router):
    mock_router.post("/change-password").mock(
        return_value=httpx.Response(200, json={"message": "Password updated"})
    )
    from agent.tools import change_password_tool
    result = await change_password_tool.ainvoke(
        {"token": TOKEN, "current_password": PASSWORD, "new_password": NEW_PASSWORD}
    )

    assert result["ok"] is True
    assert result["http_status"] == 200


@pytest.mark.asyncio
async def test_change_password_without_current_password(mock_router):
    """Anomaly detection: server accepts change-password without current_password."""
    mock_router.post("/change-password").mock(
        return_value=httpx.Response(200, json={"message": "Password updated"})
    )
    from agent.tools import change_password_tool
    result = await change_password_tool.ainvoke(
        {"token": TOKEN, "current_password": "", "new_password": NEW_PASSWORD}
    )
    # The tool itself returns 200 — the LLM is responsible for flagging this as anomalous
    assert result["http_status"] == 200
    assert result["ok"] is True


# ── logout_tool ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_logout_success(mock_router):
    mock_router.post("/logout").mock(
        return_value=httpx.Response(200, json={"message": "Logged out"})
    )
    from agent.tools import logout_tool
    result = await logout_tool.ainvoke({"token": TOKEN})

    assert result["ok"] is True


@pytest.mark.asyncio
async def test_logout_then_me_returns_401(mock_router):
    """After logout the token should be invalid."""
    mock_router.post("/logout").mock(return_value=httpx.Response(200, json={}))
    mock_router.get("/me").mock(return_value=httpx.Response(401, json={"detail": "Not authenticated"}))

    from agent.tools import logout_tool, me_tool
    logout_result = await logout_tool.ainvoke({"token": TOKEN})
    me_result = await me_tool.ainvoke({"token": TOKEN})

    assert logout_result["ok"] is True
    assert me_result["http_status"] == 401


# ── Timeout handling ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_login_timeout(mock_router):
    mock_router.post("/login").mock(side_effect=httpx.TimeoutException("timeout"))
    from agent.tools import login_tool
    with pytest.raises(httpx.TimeoutException):
        await login_tool.ainvoke({"username": USERNAME, "password": PASSWORD})
