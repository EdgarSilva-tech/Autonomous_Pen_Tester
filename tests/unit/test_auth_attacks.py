"""Unit tests for v2 auth attack tools (jwt_analyze, brute_force_check,
session_fixation_check, token_entropy_check).

The original flow tools (login_tool, me_tool, etc.) are tested in
tests/unit/test_tools.py and remain unchanged.
"""
from __future__ import annotations

import base64
import json
import time

import httpx
import pytest

from agent.tools.attacks.auth import (
    brute_force_check,
    jwt_analyze,
    session_fixation_check,
    token_entropy_check,
)


# ── Helpers ───────────────────────────────────────────────────────────────


def _make_jwt(header: dict, payload: dict) -> str:
    def _enc(d: dict) -> str:
        raw = json.dumps(d).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{_enc(header)}.{_enc(payload)}.fakesig"


# ── jwt_analyze ───────────────────────────────────────────────────────────


def test_jwt_none_algorithm_flagged():
    token = _make_jwt(
        {"alg": "none", "typ": "JWT"},
        {"sub": "1", "exp": int(time.time()) + 3600},
    )
    result = jwt_analyze.invoke({"token": token})
    assert result["vulnerable"] is True
    assert any("none" in issue.lower() for issue in result["issues"])


def test_jwt_hs256_flagged():
    token = _make_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "1", "exp": int(time.time()) + 3600},
    )
    result = jwt_analyze.invoke({"token": token})
    assert any("hs256" in issue.lower() for issue in result["issues"])


def test_jwt_missing_exp_flagged():
    token = _make_jwt(
        {"alg": "RS256", "typ": "JWT"},
        {"sub": "user-1"},  # no exp
    )
    result = jwt_analyze.invoke({"token": token})
    assert result["vulnerable"] is True
    assert any("exp" in issue.lower() for issue in result["issues"])


def test_jwt_expired_token_flagged():
    token = _make_jwt(
        {"alg": "RS256", "typ": "JWT"},
        {"sub": "1", "exp": int(time.time()) - 100},
    )
    result = jwt_analyze.invoke({"token": token})
    assert result["expired"] is True
    assert any("expired" in issue.lower() for issue in result["issues"])


def test_jwt_sensitive_field_flagged():
    token = _make_jwt(
        {"alg": "RS256", "typ": "JWT"},
        {"sub": "1", "exp": int(time.time()) + 3600, "password": "x"},
    )
    result = jwt_analyze.invoke({"token": token})
    assert any("sensitive" in issue.lower() for issue in result["issues"])


def test_jwt_invalid_format():
    result = jwt_analyze.invoke({"token": "not.a.valid.jwt.token.extra"})
    assert result["vulnerable"] is True


def test_jwt_valid_rs256_no_issues():
    token = _make_jwt(
        {"alg": "RS256", "typ": "JWT"},
        {"sub": "user-1", "exp": int(time.time()) + 3600},
    )
    result = jwt_analyze.invoke({"token": token})
    assert result["algorithm"] == "RS256"
    # Only the symmetric-key warning is absent; no other issues
    assert not any("none" in i.lower() for i in result["issues"])


# ── brute_force_check ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_brute_force_detects_rate_limiting(mock_router):
    call_count = 0

    def respond(request):
        nonlocal call_count
        call_count += 1
        if call_count >= 4:
            return httpx.Response(
                429, json={"error": "Too many requests"}
            )
        return httpx.Response(
            401, json={"error": "Invalid credentials"}
        )

    mock_router.post("/login").mock(side_effect=respond)
    result = await brute_force_check.ainvoke(
        {"path": "/login", "username": "admin", "attempts": 5}
    )
    assert result["rate_limited"] is True
    assert result["vulnerable"] is False
    assert result["limit_after"] is not None


@pytest.mark.asyncio
async def test_brute_force_detects_no_protection(mock_router):
    mock_router.post("/login").mock(
        return_value=httpx.Response(
            401, json={"error": "Invalid credentials"}
        )
    )
    result = await brute_force_check.ainvoke(
        {"path": "/login", "username": "admin", "attempts": 5}
    )
    assert result["rate_limited"] is False
    assert result["vulnerable"] is True
    assert result["severity"] == "high"


@pytest.mark.asyncio
async def test_brute_force_detects_lockout_message(mock_router):
    mock_router.post("/login").mock(
        return_value=httpx.Response(
            401,
            json={"error": "Account locked due to too many attempts"},
        )
    )
    result = await brute_force_check.ainvoke(
        {"path": "/login", "username": "admin", "attempts": 5}
    )
    assert result["locked_out"] is True
    assert result["vulnerable"] is False


# ── session_fixation_check ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_session_fixation_not_vulnerable_when_no_pre_cookie(
    mock_router,
):
    mock_router.get("/login").mock(
        return_value=httpx.Response(200, json={})
    )
    mock_router.post("/login").mock(
        return_value=httpx.Response(
            200,
            json={"access_token": "new-token"},
        )
    )
    result = await session_fixation_check.ainvoke(
        {"path": "/login", "username": "user", "password": "pass"}
    )
    assert result["vulnerable"] is False
    assert result["session_changes"] is True


@pytest.mark.asyncio
async def test_session_fixation_detects_unchanged_session(mock_router):
    mock_router.get("/login").mock(
        return_value=httpx.Response(
            200,
            headers={"set-cookie": "sessionid=abc123; Path=/"},
        )
    )
    mock_router.post("/login").mock(
        return_value=httpx.Response(
            200,
            json={"ok": True},
            headers={"set-cookie": "sessionid=abc123; Path=/"},
        )
    )
    result = await session_fixation_check.ainvoke(
        {"path": "/login", "username": "user", "password": "pass"}
    )
    assert result["vulnerable"] is True
    assert result["session_changes"] is False


@pytest.mark.asyncio
async def test_session_fixation_safe_when_session_changes(mock_router):
    mock_router.get("/login").mock(
        return_value=httpx.Response(
            200,
            headers={"set-cookie": "sessionid=old; Path=/"},
        )
    )
    mock_router.post("/login").mock(
        return_value=httpx.Response(
            200,
            json={"ok": True},
            headers={"set-cookie": "sessionid=new; Path=/"},
        )
    )
    result = await session_fixation_check.ainvoke(
        {"path": "/login", "username": "user", "password": "pass"}
    )
    assert result["vulnerable"] is False
    assert result["session_changes"] is True


# ── token_entropy_check ───────────────────────────────────────────────────


def test_token_entropy_strong_token():
    import secrets
    token = secrets.token_urlsafe(32)  # ~256 bits
    result = token_entropy_check.invoke({"token": token})
    assert result["strength"] == "strong"
    assert result["total_bits"] > 128
    assert result["vulnerable"] is False


def test_token_entropy_weak_short_token():
    result = token_entropy_check.invoke({"token": "abc123"})
    assert result["vulnerable"] is True
    assert result["length"] == 6
    assert any("length" in i.lower() for i in result["issues"])


def test_token_entropy_low_diversity():
    result = token_entropy_check.invoke({"token": "aaaaaaaaaaaaaaaa"})
    assert result["vulnerable"] is True
    assert result["unique_chars"] == 1


def test_token_entropy_returns_numeric_bits():
    result = token_entropy_check.invoke({"token": "test-token-12345"})
    assert isinstance(result["total_bits"], float)
    assert isinstance(result["entropy_per_char"], float)
