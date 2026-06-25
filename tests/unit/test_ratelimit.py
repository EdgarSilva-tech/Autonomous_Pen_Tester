"""Unit tests for rate-limit and IP-bypass checks."""
from __future__ import annotations

import pytest
import httpx

from agent.tools.attacks.ratelimit import ip_bypass_check, rate_limit_check


# ── rate_limit_check ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rate_limit_detects_429(mock_router):
    call_count = 0

    def respond(request):
        nonlocal call_count
        call_count += 1
        if call_count >= 5:
            return httpx.Response(
                429,
                json={"error": "Too many requests"},
                headers={"retry-after": "30"},
            )
        return httpx.Response(200, json={})

    mock_router.get("/api/search").mock(side_effect=respond)
    result = await rate_limit_check.ainvoke(
        {"path": "/api/search", "requests_count": 7}
    )
    assert result["rate_limited"] is True
    assert result["vulnerable"] is False
    assert result["limit_after"] == 5


@pytest.mark.asyncio
async def test_rate_limit_no_protection(mock_router):
    mock_router.get("/api/search").mock(
        return_value=httpx.Response(200, json={})
    )
    result = await rate_limit_check.ainvoke(
        {"path": "/api/search", "requests_count": 5}
    )
    assert result["rate_limited"] is False
    assert result["vulnerable"] is True
    assert result["severity"] == "medium"
    assert result["requests_sent"] == 5


@pytest.mark.asyncio
async def test_rate_limit_post_method(mock_router):
    mock_router.post("/api/login").mock(
        return_value=httpx.Response(401, json={})
    )
    result = await rate_limit_check.ainvoke(
        {"path": "/api/login", "method": "POST", "requests_count": 3}
    )
    assert result["method"] == "POST"
    assert result["requests_sent"] == 3


@pytest.mark.asyncio
async def test_rate_limit_returns_timing(mock_router):
    mock_router.get("/api/data").mock(
        return_value=httpx.Response(200, json={})
    )
    result = await rate_limit_check.ainvoke(
        {"path": "/api/data", "requests_count": 3}
    )
    assert len(result["timing_ms"]) == 3
    assert all(isinstance(t, float) for t in result["timing_ms"])


# ── ip_bypass_check ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ip_bypass_detects_effective_header(mock_router):
    """X-Forwarded-For: 127.0.0.1 changes the response from 429 to 200."""
    call_count = 0

    def respond(request):
        # If X-Forwarded-For is present, pretend bypass works
        if "x-forwarded-for" in request.headers:
            return httpx.Response(200, json={})
        return httpx.Response(429, json={"error": "Rate limited"})

    mock_router.get("/api/data").mock(side_effect=respond)
    result = await ip_bypass_check.ainvoke({"path": "/api/data"})
    assert result["vulnerable"] is True
    assert "X-Forwarded-For" in result["effective_headers"]


@pytest.mark.asyncio
async def test_ip_bypass_no_bypass(mock_router):
    """All requests return same status regardless of IP header."""
    mock_router.get("/api/data").mock(
        return_value=httpx.Response(200, json={})
    )
    result = await ip_bypass_check.ainvoke({"path": "/api/data"})
    assert result["vulnerable"] is False
    assert result["effective_headers"] == []


@pytest.mark.asyncio
async def test_ip_bypass_returns_all_header_results(mock_router):
    mock_router.get("/api/data").mock(
        return_value=httpx.Response(200, json={})
    )
    result = await ip_bypass_check.ainvoke({"path": "/api/data"})
    assert "X-Forwarded-For" in result["responses"]
    assert "X-Real-IP" in result["responses"]
    assert "CF-Connecting-IP" in result["responses"]
