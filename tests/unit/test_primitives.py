"""Unit tests for the Layer 1 HTTP primitives using respx to mock httpx."""
from __future__ import annotations

import pytest
import httpx

from agent.tools.primitives import (
    _do_http_get,
    _do_http_post,
    clear_session_headers,
    http_delete,
    http_get,
    http_post,
    http_put,
    reset_session,
    set_session_header,
)


# ── http_get ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_http_get_success(mock_router):
    mock_router.get("/api/items").mock(
        return_value=httpx.Response(200, json={"items": [1, 2, 3]})
    )
    result = await http_get.ainvoke({"url": "/api/items"})
    assert result["status"] == 200
    assert result["ok"] is True
    assert result["body"] == {"items": [1, 2, 3]}


@pytest.mark.asyncio
async def test_http_get_not_found(mock_router):
    mock_router.get("/api/missing").mock(
        return_value=httpx.Response(404, json={"detail": "Not found"})
    )
    result = await http_get.ainvoke({"url": "/api/missing"})
    assert result["status"] == 404
    assert result["ok"] is False


@pytest.mark.asyncio
async def test_http_get_with_extra_headers(mock_router):
    mock_router.get("/api/secure").mock(
        return_value=httpx.Response(200, json={"data": "secret"})
    )
    result = await http_get.ainvoke(
        {
            "url": "/api/secure",
            "headers": {"Authorization": "Bearer tok"},
        }
    )
    assert result["ok"] is True
    sent = mock_router.calls.last.request
    assert sent.headers.get("authorization") == "Bearer tok"


@pytest.mark.asyncio
async def test_http_get_with_params(mock_router):
    mock_router.get("/api/search").mock(
        return_value=httpx.Response(200, json={"results": []})
    )
    result = await http_get.ainvoke(
        {"url": "/api/search", "params": {"q": "test"}}
    )
    assert result["ok"] is True
    assert "q=test" in str(mock_router.calls.last.request.url)


@pytest.mark.asyncio
async def test_http_get_plain_text_body(mock_router):
    mock_router.get("/api/text").mock(
        return_value=httpx.Response(200, text="hello world")
    )
    result = await http_get.ainvoke({"url": "/api/text"})
    assert result["body"] == "hello world"


# ── http_post ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_http_post_json_body(mock_router):
    mock_router.post("/api/create").mock(
        return_value=httpx.Response(201, json={"id": 42})
    )
    result = await http_post.ainvoke(
        {"url": "/api/create", "body": {"name": "test"}}
    )
    assert result["status"] == 201
    assert result["ok"] is True
    assert result["body"]["id"] == 42


@pytest.mark.asyncio
async def test_http_post_no_body(mock_router):
    mock_router.post("/api/trigger").mock(
        return_value=httpx.Response(200, json={"triggered": True})
    )
    result = await http_post.ainvoke({"url": "/api/trigger"})
    assert result["ok"] is True


@pytest.mark.asyncio
async def test_http_post_server_error(mock_router):
    mock_router.post("/api/boom").mock(
        return_value=httpx.Response(500, text="Internal Server Error")
    )
    result = await http_post.ainvoke(
        {"url": "/api/boom", "body": {"x": 1}}
    )
    assert result["status"] == 500
    assert result["ok"] is False


# ── http_put ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_http_put_success(mock_router):
    mock_router.put("/api/items/1").mock(
        return_value=httpx.Response(200, json={"updated": True})
    )
    result = await http_put.ainvoke(
        {"url": "/api/items/1", "body": {"name": "updated"}}
    )
    assert result["status"] == 200
    assert result["ok"] is True


@pytest.mark.asyncio
async def test_http_put_method_not_allowed(mock_router):
    mock_router.put("/api/readonly").mock(
        return_value=httpx.Response(405, json={"detail": "Not allowed"})
    )
    result = await http_put.ainvoke({"url": "/api/readonly"})
    assert result["status"] == 405
    assert result["ok"] is False


# ── http_delete ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_http_delete_success(mock_router):
    mock_router.delete("/api/items/1").mock(
        return_value=httpx.Response(204, text="")
    )
    result = await http_delete.ainvoke({"url": "/api/items/1"})
    assert result["status"] == 204
    assert result["ok"] is True


@pytest.mark.asyncio
async def test_http_delete_forbidden(mock_router):
    mock_router.delete("/api/protected").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden"})
    )
    result = await http_delete.ainvoke({"url": "/api/protected"})
    assert result["status"] == 403
    assert result["ok"] is False


# ── session header store ──────────────────────────────────────────────────────

def test_set_session_header_returns_current_headers():
    reset_session()
    result = set_session_header.invoke(
        {"name": "X-Custom", "value": "hello"}
    )
    assert result["X-Custom"] == "hello"


def test_set_session_header_accumulates():
    reset_session()
    set_session_header.invoke({"name": "X-A", "value": "1"})
    result = set_session_header.invoke({"name": "X-B", "value": "2"})
    assert result["X-A"] == "1"
    assert result["X-B"] == "2"


def test_clear_session_headers():
    reset_session()
    set_session_header.invoke({"name": "X-A", "value": "1"})
    result = clear_session_headers.invoke({})
    assert result == {}


@pytest.mark.asyncio
async def test_session_header_sent_in_request(mock_router):
    """Headers set via set_session_header appear in subsequent requests."""
    reset_session()
    mock_router.get("/api/check").mock(
        return_value=httpx.Response(200, json={})
    )
    set_session_header.invoke(
        {"name": "X-Session-Key", "value": "abc123"}
    )
    await _do_http_get("/api/check")
    sent = mock_router.calls.last.request
    assert sent.headers.get("x-session-key") == "abc123"


@pytest.mark.asyncio
async def test_clear_headers_removes_from_requests(mock_router):
    """After clear_session_headers, the header is no longer sent."""
    reset_session()
    mock_router.get("/api/check").mock(
        return_value=httpx.Response(200, json={})
    )
    set_session_header.invoke({"name": "X-Gone", "value": "yes"})
    clear_session_headers.invoke({})
    await _do_http_get("/api/check")
    sent = mock_router.calls.last.request
    assert "x-gone" not in sent.headers


# ── Internal coroutines used by Layer 2 ──────────────────────────────────────

@pytest.mark.asyncio
async def test_do_http_post_with_headers(mock_router):
    """_do_http_post merges per-request headers with session headers."""
    reset_session()
    mock_router.post("/api/auth").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    resp = await _do_http_post(
        "/api/auth",
        body={"user": "alice"},
        headers={"Authorization": "Bearer xyz"},
    )
    assert resp.ok is True
    sent = mock_router.calls.last.request
    assert sent.headers.get("authorization") == "Bearer xyz"
