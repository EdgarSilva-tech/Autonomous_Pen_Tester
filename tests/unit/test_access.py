"""Unit tests for broken access control probes."""
from __future__ import annotations

import pytest
import httpx

from agent.tools.attacks.access import (
    bola_probe,
    idor_probe,
    privilege_escalation_check,
)

TOKEN = "test-access-token"


# ── idor_probe ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_idor_detects_unauthorized_access(mock_router):
    mock_router.get("/api/users/1").mock(
        return_value=httpx.Response(200, json={"id": 1, "name": "Alice"})
    )
    mock_router.get("/api/users/2").mock(
        return_value=httpx.Response(200, json={"id": 2, "name": "Bob"})
    )
    result = await idor_probe.ainvoke({
        "own_path": "/api/users/1",
        "other_path": "/api/users/2",
        "token": TOKEN,
    })
    assert result["vulnerable"] is True
    assert result["severity"] == "high"
    assert result["other_status"] == 200


@pytest.mark.asyncio
async def test_idor_returns_not_vulnerable_on_403(mock_router):
    mock_router.get("/api/users/1").mock(
        return_value=httpx.Response(200, json={"id": 1})
    )
    mock_router.get("/api/users/2").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    result = await idor_probe.ainvoke({
        "own_path": "/api/users/1",
        "other_path": "/api/users/2",
        "token": TOKEN,
    })
    assert result["vulnerable"] is False
    assert result["other_status"] == 403


@pytest.mark.asyncio
async def test_idor_returns_not_vulnerable_on_404(mock_router):
    mock_router.get("/api/orders/1").mock(
        return_value=httpx.Response(200, json={})
    )
    mock_router.get("/api/orders/99").mock(
        return_value=httpx.Response(404)
    )
    result = await idor_probe.ainvoke({
        "own_path": "/api/orders/1",
        "other_path": "/api/orders/99",
        "token": TOKEN,
    })
    assert result["vulnerable"] is False


@pytest.mark.asyncio
async def test_idor_not_vulnerable_on_401(mock_router):
    mock_router.get("/api/users/1").mock(
        return_value=httpx.Response(200, json={})
    )
    mock_router.get("/api/users/2").mock(
        return_value=httpx.Response(401)
    )
    result = await idor_probe.ainvoke({
        "own_path": "/api/users/1",
        "other_path": "/api/users/2",
        "token": TOKEN,
    })
    assert result["vulnerable"] is False


# ── bola_probe ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_bola_detects_multiple_accessible_ids(mock_router):
    for order_id in ["1", "2", "3"]:
        mock_router.get(f"/api/orders/{order_id}").mock(
            return_value=httpx.Response(200, json={"id": order_id})
        )
    result = await bola_probe.ainvoke({
        "path_template": "/api/orders/{id}",
        "ids": ["1", "2", "3"],
        "token": TOKEN,
    })
    assert result["vulnerable"] is True
    assert len(result["accessible_ids"]) > 1


@pytest.mark.asyncio
async def test_bola_not_vulnerable_when_only_own_accessible(mock_router):
    mock_router.get("/api/orders/1").mock(
        return_value=httpx.Response(200, json={"id": "1"})
    )
    mock_router.get("/api/orders/2").mock(
        return_value=httpx.Response(403)
    )
    mock_router.get("/api/orders/3").mock(
        return_value=httpx.Response(403)
    )
    result = await bola_probe.ainvoke({
        "path_template": "/api/orders/{id}",
        "ids": ["1", "2", "3"],
        "token": TOKEN,
    })
    assert result["vulnerable"] is False
    assert result["accessible_ids"] == ["1"]


# ── privilege_escalation_check ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_privilege_escalation_detects_access(mock_router):
    mock_router.get("/api/admin/users").mock(
        return_value=httpx.Response(
            200, json={"users": [{"id": 1}, {"id": 2}]}
        )
    )
    result = await privilege_escalation_check.ainvoke({
        "path": "/api/admin/users",
        "low_priv_token": TOKEN,
    })
    assert result["vulnerable"] is True
    assert result["severity"] == "critical"
    assert result["http_status"] == 200


@pytest.mark.asyncio
async def test_privilege_escalation_safe_on_403(mock_router):
    mock_router.get("/api/admin/users").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    result = await privilege_escalation_check.ainvoke({
        "path": "/api/admin/users",
        "low_priv_token": TOKEN,
    })
    assert result["vulnerable"] is False
    assert result["http_status"] == 403


@pytest.mark.asyncio
async def test_privilege_escalation_safe_on_401(mock_router):
    mock_router.get("/api/admin").mock(
        return_value=httpx.Response(401)
    )
    result = await privilege_escalation_check.ainvoke({
        "path": "/api/admin",
        "low_priv_token": TOKEN,
    })
    assert result["vulnerable"] is False
