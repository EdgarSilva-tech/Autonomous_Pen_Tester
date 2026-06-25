"""Unit tests for injection attack probes."""
from __future__ import annotations

import pytest
import httpx

from agent.tools.attacks.injection import (
    nosql_probe,
    sqli_probe,
    ssti_probe,
    xss_probe,
)


# ── sqli_probe ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_sqli_detects_sql_error_in_body(mock_router):
    mock_router.get("/api/users").mock(
        return_value=httpx.Response(
            500, text="You have an error in your SQL syntax"
        )
    )
    result = await sqli_probe.ainvoke(
        {"path": "/api/users", "parameter": "id"}
    )
    assert result["vulnerable"] is True
    assert result["severity"] == "high"
    assert len(result["payloads_triggered"]) > 0


@pytest.mark.asyncio
async def test_sqli_detects_on_500_even_without_error_string(mock_router):
    mock_router.get("/api/items").mock(
        return_value=httpx.Response(500, text="Internal Error")
    )
    result = await sqli_probe.ainvoke(
        {"path": "/api/items", "parameter": "q"}
    )
    assert result["vulnerable"] is True


@pytest.mark.asyncio
async def test_sqli_clean_200_not_vulnerable(mock_router):
    mock_router.get("/api/users").mock(
        return_value=httpx.Response(200, json={"users": []})
    )
    result = await sqli_probe.ainvoke(
        {"path": "/api/users", "parameter": "id"}
    )
    assert result["vulnerable"] is False
    assert result["severity"] == "info"


@pytest.mark.asyncio
async def test_sqli_post_method(mock_router):
    mock_router.post("/api/search").mock(
        return_value=httpx.Response(
            200, text="pg:: error in query"
        )
    )
    result = await sqli_probe.ainvoke(
        {"path": "/api/search", "parameter": "q", "method": "POST"}
    )
    assert result["vulnerable"] is True
    assert result["method"] == "POST"


# ── nosql_probe ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_nosql_detects_error_pattern(mock_router):
    mock_router.post("/api/login").mock(
        return_value=httpx.Response(
            500, text="CasterError: cannot cast value"
        )
    )
    result = await nosql_probe.ainvoke(
        {"path": "/api/login", "parameter": "username"}
    )
    assert result["vulnerable"] is True
    assert result["severity"] == "high"


@pytest.mark.asyncio
async def test_nosql_clean_response(mock_router):
    mock_router.post("/api/login").mock(
        return_value=httpx.Response(
            401, json={"error": "Invalid credentials"}
        )
    )
    result = await nosql_probe.ainvoke(
        {"path": "/api/login", "parameter": "username"}
    )
    assert result["vulnerable"] is False


# ── ssti_probe ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ssti_detects_evaluated_expression(mock_router):
    mock_router.get("/search").mock(
        return_value=httpx.Response(200, text="Result: 49")
    )
    result = await ssti_probe.ainvoke(
        {"path": "/search", "parameter": "q"}
    )
    assert result["vulnerable"] is True
    assert result["severity"] == "critical"
    assert result["reflected_value"] == "49"


@pytest.mark.asyncio
async def test_ssti_not_detected_when_not_reflected(mock_router):
    mock_router.get("/search").mock(
        return_value=httpx.Response(200, text="No results found")
    )
    result = await ssti_probe.ainvoke(
        {"path": "/search", "parameter": "q"}
    )
    assert result["vulnerable"] is False
    assert result["severity"] == "info"


# ── xss_probe ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_xss_detects_reflected_payload(mock_router):
    payload = "<script>alert(1)</script>"
    mock_router.get("/page").mock(
        return_value=httpx.Response(
            200,
            text=f"<html><body>{payload}</body></html>",
            headers={"content-type": "text/html"},
        )
    )
    result = await xss_probe.ainvoke(
        {"path": "/page", "parameter": "q"}
    )
    assert result["vulnerable"] is True
    assert result["severity"] == "medium"
    assert result["payload"] == payload


@pytest.mark.asyncio
async def test_xss_not_detected_when_escaped(mock_router):
    mock_router.get("/page").mock(
        return_value=httpx.Response(
            200,
            text="<html><body>&lt;script&gt;</body></html>",
            headers={"content-type": "text/html"},
        )
    )
    result = await xss_probe.ainvoke(
        {"path": "/page", "parameter": "q"}
    )
    assert result["vulnerable"] is False


@pytest.mark.asyncio
async def test_xss_post_method(mock_router):
    payload = "<script>alert(1)</script>"
    mock_router.post("/comment").mock(
        return_value=httpx.Response(
            200, text=f"Comment: {payload}"
        )
    )
    result = await xss_probe.ainvoke(
        {"path": "/comment", "parameter": "text", "method": "POST"}
    )
    assert result["vulnerable"] is True
