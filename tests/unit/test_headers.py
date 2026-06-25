"""Unit tests for HTTP security header checks."""
from __future__ import annotations

import pytest
import httpx

from agent.tools.attacks.headers import (
    cors_check,
    csp_check,
    security_headers_check,
)


# ── cors_check ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cors_vulnerable_reflects_origin_with_credentials(mock_router):
    origin = "https://evil.example.com"
    mock_router.get("/api/data").mock(
        return_value=httpx.Response(
            200,
            json={},
            headers={
                "access-control-allow-origin": origin,
                "access-control-allow-credentials": "true",
            },
        )
    )
    result = await cors_check.ainvoke(
        {"path": "/api/data", "origin": origin}
    )
    assert result["vulnerable"] is True
    assert result["reflects_origin"] is True
    assert result["credentials_allowed"] is True
    assert result["severity"] == "high"


@pytest.mark.asyncio
async def test_cors_wildcard_without_credentials_not_vulnerable(mock_router):
    mock_router.get("/api/public").mock(
        return_value=httpx.Response(
            200,
            json={},
            headers={"access-control-allow-origin": "*"},
        )
    )
    result = await cors_check.ainvoke({"path": "/api/public"})
    assert result["wildcard_origin"] is True
    assert result["credentials_allowed"] is False
    assert result["vulnerable"] is False


@pytest.mark.asyncio
async def test_cors_no_cors_headers_not_vulnerable(mock_router):
    mock_router.get("/api/data").mock(
        return_value=httpx.Response(200, json={})
    )
    result = await cors_check.ainvoke({"path": "/api/data"})
    assert result["vulnerable"] is False
    assert result["reflects_origin"] is False


@pytest.mark.asyncio
async def test_cors_reflects_without_credentials_medium_severity(mock_router):
    origin = "https://evil.example.com"
    mock_router.get("/api/data").mock(
        return_value=httpx.Response(
            200,
            json={},
            headers={"access-control-allow-origin": origin},
        )
    )
    result = await cors_check.ainvoke(
        {"path": "/api/data", "origin": origin}
    )
    assert result["reflects_origin"] is True
    assert result["credentials_allowed"] is False
    assert result["vulnerable"] is False
    assert result["severity"] == "medium"


# ── security_headers_check ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_security_headers_flags_missing(mock_router):
    mock_router.get("/").mock(
        return_value=httpx.Response(200, json={})
    )
    result = await security_headers_check.ainvoke({"path": "/"})
    assert len(result["missing"]) > 0
    assert result["vulnerable"] is True


@pytest.mark.asyncio
async def test_security_headers_all_present(mock_router):
    mock_router.get("/").mock(
        return_value=httpx.Response(
            200,
            json={},
            headers={
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "strict-transport-security": "max-age=31536000",
                "referrer-policy": "no-referrer",
                "permissions-policy": "geolocation=()",
                "content-security-policy": "default-src 'self'",
            },
        )
    )
    result = await security_headers_check.ainvoke({"path": "/"})
    assert result["missing"] == []
    assert result["csp_present"] is True


@pytest.mark.asyncio
async def test_security_headers_misconfigured_xcto(mock_router):
    mock_router.get("/").mock(
        return_value=httpx.Response(
            200,
            json={},
            headers={"x-content-type-options": "wrong-value"},
        )
    )
    result = await security_headers_check.ainvoke({"path": "/"})
    assert any(
        "x-content-type-options" in m for m in result["misconfigured"]
    )


# ── csp_check ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_csp_flags_absent_policy(mock_router):
    mock_router.get("/").mock(
        return_value=httpx.Response(200, json={})
    )
    result = await csp_check.ainvoke({"path": "/"})
    assert result["present"] is False
    assert result["vulnerable"] is True
    assert result["severity"] == "high"
    assert any("absent" in i.lower() for i in result["issues"])


@pytest.mark.asyncio
async def test_csp_flags_unsafe_inline(mock_router):
    mock_router.get("/").mock(
        return_value=httpx.Response(
            200,
            json={},
            headers={
                "content-security-policy": (
                    "default-src 'self'; script-src 'unsafe-inline'"
                )
            },
        )
    )
    result = await csp_check.ainvoke({"path": "/"})
    assert result["vulnerable"] is True
    assert any("unsafe-inline" in i for i in result["issues"])


@pytest.mark.asyncio
async def test_csp_flags_unsafe_eval(mock_router):
    mock_router.get("/").mock(
        return_value=httpx.Response(
            200,
            json={},
            headers={
                "content-security-policy": (
                    "default-src 'self'; script-src 'unsafe-eval'"
                )
            },
        )
    )
    result = await csp_check.ainvoke({"path": "/"})
    assert any("unsafe-eval" in i for i in result["issues"])


@pytest.mark.asyncio
async def test_csp_sound_policy_no_issues(mock_router):
    mock_router.get("/").mock(
        return_value=httpx.Response(
            200,
            json={},
            headers={
                "content-security-policy": (
                    "default-src 'self'; "
                    "object-src 'none'; base-uri 'self'"
                )
            },
        )
    )
    result = await csp_check.ainvoke({"path": "/"})
    assert result["present"] is True
    assert result["vulnerable"] is False
    assert result["issues"] == []
