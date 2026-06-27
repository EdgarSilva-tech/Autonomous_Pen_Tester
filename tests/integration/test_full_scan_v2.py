"""Integration tests for Phase 5: Finding-based report generation.

Coverage:
  1. Attack tools (sqli, cors, security headers, error disclosure) correctly
     detect vulnerabilities in mocked responses.
  2. assemble_report() v2 mode builds Finding objects with correct fields.
  3. The Markdown report contains all expected sections.
  4. Target-app vulnerable endpoints respond as expected.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest
import respx
from httpx import ASGITransport
from langchain_core.messages import ToolMessage

from agent.report import assemble_report
from agent.tools.attacks.headers import cors_check, security_headers_check
from agent.tools.attacks.injection import sqli_probe
from agent.tools.attacks.disclosure import error_disclosure_probe

BASE = "http://test-target:8000"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_v2_state(tool_messages: list[ToolMessage]) -> dict:
    return {
        "messages": tool_messages,
        "test_plan": [{"module": "injection"}, {"module": "headers"}],
        "findings": [],
        "thread_id": "test-thread-v2",
        "past_context": [],
        "step_results": [],
        "anomalies": [],
        "error": None,
        "final_status": None,
    }


def _tool_msg(name: str, result: dict) -> ToolMessage:
    return ToolMessage(
        content=json.dumps(result),
        tool_call_id=f"tc_{name}",
        name=name,
    )


# ---------------------------------------------------------------------------
# Tool detection tests (respx-mocked responses)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sqli_probe_detects_injection(mock_router):
    """sqli_probe flags SQL error strings and produces a High Finding."""
    mock_router.get("/api/search").mock(
        return_value=httpx.Response(
            500,
            json={"detail": "sqlite_error: near \"'\": syntax error"},
        )
    )

    result = await sqli_probe.ainvoke(
        {"path": "/api/search", "parameter": "q", "method": "GET"}
    )

    assert result["vulnerable"] is True
    assert result["severity"] == "high"
    assert result["parameter"] == "q"

    report = assemble_report(
        _make_v2_state([_tool_msg("sqli_probe", result)]),
        elapsed_ms=50,
    )

    assert len(report.findings) == 1
    f = report.findings[0]
    assert f.severity == "High"
    assert f.cvss_score == 7.5
    assert "A03:2021" in f.category
    assert f.endpoint == "/api/search"
    assert f.parameter == "q"
    assert "Injection" in f.category


@pytest.mark.asyncio
async def test_cors_check_detects_misconfiguration(mock_router):
    """cors_check flags reflect-origin + credentials and produces a High Finding."""
    mock_router.get("/api/data").mock(
        return_value=httpx.Response(
            200,
            json={"data": "secret"},
            headers={
                "access-control-allow-origin": "https://evil.example.com",
                "access-control-allow-credentials": "true",
            },
        )
    )

    result = await cors_check.ainvoke(
        {"path": "/api/data", "origin": "https://evil.example.com"}
    )

    assert result["vulnerable"] is True
    assert result["reflects_origin"] is True
    assert result["credentials_allowed"] is True

    report = assemble_report(
        _make_v2_state([_tool_msg("cors_check", result)]),
        elapsed_ms=30,
    )

    assert len(report.findings) == 1
    f = report.findings[0]
    assert f.severity == "High"
    assert "A05:2021" in f.category
    assert f.evidence.payload == "https://evil.example.com"


@pytest.mark.asyncio
async def test_security_headers_check_detects_missing_headers(mock_router):
    """security_headers_check flags missing headers and produces a Medium Finding."""
    mock_router.get("/").mock(
        return_value=httpx.Response(200, json={"status": "ok"})
    )

    result = await security_headers_check.ainvoke({"path": "/"})

    assert result["vulnerable"] is True
    assert len(result["missing"]) >= 3

    report = assemble_report(
        _make_v2_state([_tool_msg("security_headers_check", result)]),
        elapsed_ms=20,
    )

    assert len(report.findings) == 1
    f = report.findings[0]
    assert f.severity == "Medium"
    assert "A05:2021" in f.category


@pytest.mark.asyncio
async def test_error_disclosure_probe_detects_traceback(mock_router):
    """error_disclosure_probe flags traceback patterns and produces a Medium Finding."""
    traceback_body = {
        "error": "Internal Server Error",
        "traceback": "Traceback (most recent call last):\n  File 'app.py', line 42",
    }
    mock_router.post("/api/debug").mock(
        return_value=httpx.Response(500, json=traceback_body)
    )
    mock_router.get("/api/debug").mock(
        return_value=httpx.Response(500, json=traceback_body)
    )

    result = await error_disclosure_probe.ainvoke({"path": "/api/debug"})

    assert result["vulnerable"] is True

    report = assemble_report(
        _make_v2_state([_tool_msg("error_disclosure_probe", result)]),
        elapsed_ms=40,
    )

    assert len(report.findings) == 1
    assert report.findings[0].severity == "Medium"


# ---------------------------------------------------------------------------
# Multi-finding report tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_report_markdown_contains_expected_sections(mock_router):
    """Full v2 report with multiple findings renders complete Markdown."""
    mock_router.get("/api/search").mock(
        return_value=httpx.Response(
            500,
            json={"detail": "sqlite_error: near \"'\": syntax error"},
        )
    )
    mock_router.get("/").mock(
        return_value=httpx.Response(200, json={"status": "ok"})
    )

    sqli = await sqli_probe.ainvoke(
        {"path": "/api/search", "parameter": "q", "method": "GET"}
    )
    headers = await security_headers_check.ainvoke({"path": "/"})

    state = _make_v2_state([
        _tool_msg("sqli_probe", sqli),
        _tool_msg("security_headers_check", headers),
    ])
    report = assemble_report(state, elapsed_ms=200)

    assert len(report.findings) == 2
    md = report.markdown_report

    assert "# Pentest Report" in md
    assert "## Executive Summary" in md
    assert "## Findings" in md
    assert "## Remediation Checklist" in md
    assert "| Severity | Count |" in md
    assert "- [ ] **[High]**" in md or "- [ ] **[Medium]**" in md


@pytest.mark.asyncio
async def test_non_vulnerable_tools_produce_no_findings(mock_router):
    """Tools returning vulnerable=False are excluded from findings."""
    mock_router.get("/safe").mock(
        return_value=httpx.Response(
            200,
            json={"ok": True},
            headers={
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "strict-transport-security": "max-age=31536000",
                "referrer-policy": "no-referrer",
                "permissions-policy": "geolocation=()",
                "content-security-policy": "default-src 'self'; object-src 'none'",
            },
        )
    )

    result = await security_headers_check.ainvoke({"path": "/safe"})
    assert result["vulnerable"] is False

    report = assemble_report(
        _make_v2_state([_tool_msg("security_headers_check", result)]),
        elapsed_ms=10,
    )
    assert len(report.findings) == 0
    assert "## Findings" not in report.markdown_report
    assert "No security findings identified" in report.markdown_report


# ---------------------------------------------------------------------------
# Target-app endpoint tests (in-process ASGI)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def _add_target_to_path():
    root = Path(__file__).parents[2]
    target_path = str(root / "target-app" / "target-app")
    if target_path not in sys.path:
        sys.path.insert(0, target_path)


@pytest.fixture
async def target_client(_add_target_to_path):
    """Async httpx client backed by the target-app ASGI transport."""
    from app.main import app as target_app, state, _seed_users  # noqa: PLC0415
    state.users.clear()
    state.sessions.clear()
    _seed_users()
    transport = ASGITransport(app=target_app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        yield client


@pytest.mark.asyncio
async def test_target_app_sqli_endpoint(target_client):
    """Target-app /api/search returns SQL error on injection payload."""
    resp = await target_client.get("/api/search", params={"q": "' OR 1=1 --"})
    assert resp.status_code == 500
    body = resp.text.lower()
    assert "sqlite_error" in body


@pytest.mark.asyncio
async def test_target_app_sqli_safe_query(target_client):
    """Target-app /api/search returns results for a clean query."""
    resp = await target_client.get("/api/search", params={"q": "alice"})
    assert resp.status_code == 200
    data = resp.json()
    assert "alice" in data["results"]


@pytest.mark.asyncio
async def test_target_app_idor_endpoint(target_client):
    """Target-app /api/users/{user_id} returns data without authentication."""
    resp = await target_client.get("/api/users/alice")
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == "alice"


@pytest.mark.asyncio
async def test_target_app_idor_unknown_user(target_client):
    """Target-app /api/users/{user_id} returns 404 for unknown users."""
    resp = await target_client.get("/api/users/nobody")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_target_app_cors_reflects_origin(target_client):
    """Target-app reflects evil Origin with Allow-Credentials: true (CORS vuln)."""
    resp = await target_client.get(
        "/health",
        headers={"origin": "https://evil.example.com"},
    )
    assert resp.headers.get("access-control-allow-origin") == "https://evil.example.com"
    assert resp.headers.get("access-control-allow-credentials") == "true"


@pytest.mark.asyncio
async def test_target_app_error_disclosure(target_client):
    """Target-app /api/debug leaks traceback on SQL-like id param."""
    resp = await target_client.get("/api/debug", params={"id": "' OR 1=1 --"})
    assert resp.status_code == 500
    body = resp.text.lower()
    assert "traceback" in body


@pytest.mark.asyncio
async def test_target_app_missing_security_headers(target_client):
    """Target-app does not set security headers â€” headers checker will flag it."""
    resp = await target_client.get("/health")
    assert resp.status_code == 200
    for header in (
        "x-content-type-options",
        "x-frame-options",
        "strict-transport-security",
        "content-security-policy",
    ):
        assert header not in resp.headers