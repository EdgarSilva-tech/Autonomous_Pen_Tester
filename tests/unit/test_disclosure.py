"""Unit tests for information disclosure probes."""
from __future__ import annotations

import pytest
import httpx

from agent.tools.attacks.disclosure import (
    error_disclosure_probe,
    http_methods_check,
    path_traversal_probe,
    pii_scan,
)


# ── error_disclosure_probe ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_error_disclosure_detects_stack_trace(mock_router):
    mock_router.post("/api/data").mock(
        return_value=httpx.Response(
            500,
            text="Traceback (most recent call last):\n  File app.py",
        )
    )
    mock_router.get("/api/data").mock(
        return_value=httpx.Response(200, json={})
    )
    result = await error_disclosure_probe.ainvoke({"path": "/api/data"})
    assert result["vulnerable"] is True
    assert len(result["patterns_found"]) > 0


@pytest.mark.asyncio
async def test_error_disclosure_detects_internal_path(mock_router):
    mock_router.post("/api/data").mock(
        return_value=httpx.Response(
            500, text="Error at /home/deploy/app/server.py line 42"
        )
    )
    mock_router.get("/api/data").mock(
        return_value=httpx.Response(200, json={})
    )
    result = await error_disclosure_probe.ainvoke({"path": "/api/data"})
    assert result["vulnerable"] is True


@pytest.mark.asyncio
async def test_error_disclosure_clean_response(mock_router):
    mock_router.post("/api/data").mock(
        return_value=httpx.Response(
            400, json={"error": "Bad request"}
        )
    )
    mock_router.get("/api/data").mock(
        return_value=httpx.Response(200, json={})
    )
    result = await error_disclosure_probe.ainvoke({"path": "/api/data"})
    assert result["vulnerable"] is False


# ── pii_scan ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pii_scan_detects_email(mock_router):
    mock_router.get("/api/users").mock(
        return_value=httpx.Response(
            200,
            json={"email": "alice@example.com"},
        )
    )
    result = await pii_scan.ainvoke({"path": "/api/users"})
    assert result["pii_found"] is True
    assert "email" in result["types_found"]
    assert result["count"] >= 1


@pytest.mark.asyncio
async def test_pii_scan_detects_credit_card(mock_router):
    mock_router.get("/api/payment").mock(
        return_value=httpx.Response(
            200,
            json={"card": "4111 1111 1111 1111"},
        )
    )
    result = await pii_scan.ainvoke({"path": "/api/payment"})
    assert result["pii_found"] is True
    assert "credit_card" in result["types_found"]


@pytest.mark.asyncio
async def test_pii_scan_no_pii_in_clean_response(mock_router):
    mock_router.get("/api/status").mock(
        return_value=httpx.Response(200, json={"status": "ok"})
    )
    result = await pii_scan.ainvoke({"path": "/api/status"})
    assert result["pii_found"] is False
    assert result["types_found"] == []


# ── path_traversal_probe ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_traversal_detects_passwd_content(mock_router):
    mock_router.get("/api/file").mock(
        return_value=httpx.Response(
            200, text="root:x:0:0:root:/root:/bin/bash"
        )
    )
    result = await path_traversal_probe.ainvoke({"path": "/api/file"})
    assert result["vulnerable"] is True
    assert result["severity"] == "critical"
    assert "root:x:" in result["indicators"]


@pytest.mark.asyncio
async def test_traversal_clean_response(mock_router):
    mock_router.get("/api/file").mock(
        return_value=httpx.Response(200, json={"content": "safe data"})
    )
    result = await path_traversal_probe.ainvoke({"path": "/api/file"})
    assert result["vulnerable"] is False


# ── http_methods_check ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_http_methods_flags_trace(mock_router):
    from tests.conftest import BASE_URL

    # Mock TRACE returning 200
    mock_router.route(method="TRACE", url=f"{BASE_URL}/api").mock(
        return_value=httpx.Response(200, text="TRACE echo")
    )
    # All others return 405
    for m in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]:
        mock_router.route(method=m, url=f"{BASE_URL}/api").mock(
            return_value=httpx.Response(405)
        )
    result = await http_methods_check.ainvoke({"path": "/api"})
    assert result["trace_enabled"] is True
    assert result["vulnerable"] is True


@pytest.mark.asyncio
async def test_http_methods_only_expected_allowed(mock_router):
    from tests.conftest import BASE_URL

    for m in ["GET", "POST", "OPTIONS", "HEAD"]:
        mock_router.route(method=m, url=f"{BASE_URL}/api").mock(
            return_value=httpx.Response(200)
        )
    for m in ["PUT", "PATCH", "DELETE", "TRACE"]:
        mock_router.route(method=m, url=f"{BASE_URL}/api").mock(
            return_value=httpx.Response(405)
        )
    result = await http_methods_check.ainvoke({"path": "/api"})
    assert result["trace_enabled"] is False
    assert result["unexpected_allowed"] == []
    assert result["vulnerable"] is False
