"""Unit tests for agent/probe.py.

Tests are split into two groups:
  - Pure Python (no I/O) — SiteFingerprint serialisation and compare_fingerprints logic.
  - HTTP-mocked — probe_site() with respx intercepting httpx calls.
"""
from __future__ import annotations

import pytest
import httpx
import respx
from httpx import Response

from agent.probe import (
    EndpointProbe,
    OpenAPIFingerprint,
    SiteFingerprint,
    build_openapi_context,
    compare_fingerprints,
)

# ── Helpers ───────────────────────────────────────────────────────────────────

BASE_URL = "http://test-target:8000"

_OPENAPI_SCHEMA = {
    "info": {"title": "Test API", "version": "1.0.0"},
    "paths": {
        "/login": {
            "post": {
                "parameters": [],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "properties": {
                                    "username": {"type": "string"},
                                    "password": {"type": "string"},
                                }
                            }
                        }
                    }
                },
            }
        },
        "/me": {"get": {"parameters": []}},
    },
}


def _mock_openapi_unavailable(router: respx.MockRouter) -> None:
    router.get("/openapi.json").mock(return_value=Response(404))


def _mock_openapi_schema(router: respx.MockRouter) -> None:
    router.get("/openapi.json").mock(
        return_value=Response(200, json=_OPENAPI_SCHEMA)
    )


def _mock_probe_endpoints(router: respx.MockRouter) -> None:
    """Default unauthenticated probe responses for all four endpoints."""
    router.post("/login").mock(
        return_value=Response(401, json={"detail": "Unauthorized"})
    )
    router.get("/me").mock(
        return_value=Response(401, json={"detail": "Unauthorized"})
    )
    router.post("/change-password").mock(
        return_value=Response(401, json={"detail": "Unauthorized"})
    )
    router.post("/logout").mock(
        return_value=Response(401, json={"detail": "Unauthorized"})
    )
    router.get("/").mock(
        return_value=Response(200, json={"message": "API root"})
    )


def _make_fp(endpoints: dict | None = None, scrape=None) -> SiteFingerprint:
    eps = endpoints or {
        "POST /login": EndpointProbe(
            method="POST", path="/login", status=401,
            has_json_body=True, json_keys=["detail"],
        ),
        "GET /me": EndpointProbe(
            method="GET", path="/me", status=401,
            has_json_body=True, json_keys=["detail"],
        ),
    }
    return SiteFingerprint(
        target_url=BASE_URL,
        probed_at="2026-05-23T10:00:00+00:00",
        endpoints=eps,
        scrape=scrape,
    )


# ── Serialisation round-trip ──────────────────────────────────────────────────

def test_endpoint_probe_roundtrip():
    ep = EndpointProbe(
        method="POST", path="/login", status=401,
        has_json_body=True, json_keys=["detail"],
    )
    assert EndpointProbe.from_dict(ep.to_dict()) == ep


def test_site_fingerprint_roundtrip():
    fp = _make_fp()
    restored = SiteFingerprint.from_dict(fp.to_dict())
    assert restored.target_url == fp.target_url
    assert restored.probed_at == fp.probed_at
    assert set(restored.endpoints.keys()) == set(fp.endpoints.keys())
    ep_orig = fp.endpoints["POST /login"]
    ep_rest = restored.endpoints["POST /login"]
    assert ep_orig.status == ep_rest.status
    assert ep_orig.json_keys == ep_rest.json_keys


# ── compare_fingerprints — no drift ──────────────────────────────────────────

def test_compare_identical_fingerprints_returns_none():
    fp = _make_fp()
    assert compare_fingerprints(fp, fp) is None


def test_compare_first_run_returns_none():
    """No previous fingerprint = first run → no drift report."""
    fp = _make_fp()
    assert compare_fingerprints(None, fp) is None


# ── compare_fingerprints — API layer drift ────────────────────────────────────

def test_compare_status_change_detected():
    prev = _make_fp({
        "POST /login": EndpointProbe("POST", "/login", status=401,
                                     has_json_body=True, json_keys=["detail"]),
    })
    curr = _make_fp({
        "POST /login": EndpointProbe("POST", "/login", status=404,
                                     has_json_body=False, json_keys=[]),
    })
    drift = compare_fingerprints(prev, curr)
    assert drift is not None
    assert "401" in drift and "404" in drift
    assert "DRIFT DETECTED" in drift


def test_compare_missing_endpoint_detected():
    prev = _make_fp({
        "POST /login": EndpointProbe("POST", "/login", status=401),
        "GET /me":     EndpointProbe("GET", "/me", status=401),
    })
    curr = _make_fp({
        "POST /login": EndpointProbe("POST", "/login", status=401),
        # /me is gone
    })
    drift = compare_fingerprints(prev, curr)
    assert drift is not None
    assert "MISSING" in drift or "/me" in drift


def test_compare_new_endpoint_detected():
    prev = _make_fp({
        "POST /login": EndpointProbe("POST", "/login", status=401),
    })
    curr = _make_fp({
        "POST /login":       EndpointProbe("POST", "/login", status=401),
        "POST /auth/token":  EndpointProbe("POST", "/auth/token", status=422),
    })
    drift = compare_fingerprints(prev, curr)
    assert drift is not None
    assert "NEW" in drift or "/auth/token" in drift


def test_compare_json_keys_added():
    prev = _make_fp({
        "POST /login": EndpointProbe("POST", "/login", status=200,
                                     has_json_body=True,
                                     json_keys=["access_token"]),
    })
    curr = _make_fp({
        "POST /login": EndpointProbe("POST", "/login", status=200,
                                     has_json_body=True,
                                     json_keys=["access_token", "refresh_token"]),
    })
    drift = compare_fingerprints(prev, curr)
    assert drift is not None
    assert "refresh_token" in drift


def test_compare_json_keys_removed():
    prev = _make_fp({
        "POST /login": EndpointProbe("POST", "/login", status=200,
                                     has_json_body=True,
                                     json_keys=["access_token", "expires_in"]),
    })
    curr = _make_fp({
        "POST /login": EndpointProbe("POST", "/login", status=200,
                                     has_json_body=True,
                                     json_keys=["access_token"]),
    })
    drift = compare_fingerprints(prev, curr)
    assert drift is not None
    assert "expires_in" in drift


# ── probe_site — HTTP mocked ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_probe_site_records_status_codes():
    """probe_site should record status codes for all 4 probed endpoints."""
    from agent.probe import probe_site

    with respx.mock(base_url=BASE_URL, assert_all_called=False) as router:
        _mock_openapi_unavailable(router)
        _mock_probe_endpoints(router)

        fp = await probe_site(BASE_URL)

    assert fp.target_url == BASE_URL
    assert "POST /login" in fp.endpoints
    assert fp.endpoints["POST /login"].status == 401
    assert fp.endpoints["GET /me"].status == 401


@pytest.mark.asyncio
async def test_probe_site_handles_connection_error():
    """Unreachable endpoints should get status=None (not raise)."""
    from agent.probe import probe_site

    with respx.mock(base_url=BASE_URL, assert_all_called=False) as router:
        _mock_openapi_unavailable(router)
        router.post("/login").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        router.get("/me").mock(
            return_value=Response(401, json={"detail": "Unauthorized"})
        )
        router.post("/change-password").mock(
            return_value=Response(401, json={"detail": "Unauthorized"})
        )
        router.post("/logout").mock(
            return_value=Response(401, json={"detail": "Unauthorized"})
        )
        router.get("/").mock(
            return_value=Response(200, json={"message": "API root"})
        )

        fp = await probe_site(BASE_URL)

    # Should not raise — connection errors recorded as status=None
    assert fp.endpoints["POST /login"].status is None
    assert fp.endpoints["GET /me"].status == 401


@pytest.mark.asyncio
async def test_probe_site_captures_json_keys():
    """JSON response keys should be captured for drift comparison."""
    from agent.probe import probe_site

    with respx.mock(base_url=BASE_URL, assert_all_called=False) as router:
        _mock_openapi_unavailable(router)
        router.post("/login").mock(
            return_value=Response(200, json={"access_token": "tok", "token_type": "bearer"})
        )
        router.get("/me").mock(
            return_value=Response(200, json={"username": "testuser", "id": 1})
        )
        router.post("/change-password").mock(
            return_value=Response(401, json={"detail": "Unauthorized"})
        )
        router.post("/logout").mock(
            return_value=Response(401, json={"detail": "Unauthorized"})
        )
        router.get("/").mock(
            return_value=Response(200, json={"message": "API root"})
        )

        fp = await probe_site(BASE_URL)

    login_ep = fp.endpoints["POST /login"]
    assert login_ep.has_json_body is True
    assert "access_token" in login_ep.json_keys
    assert "token_type" in login_ep.json_keys


# ── OpenAPI fingerprint ───────────────────────────────────────────────────────

def test_openapi_fingerprint_roundtrip():
    oa = OpenAPIFingerprint(
        title="Test API",
        version="1.0.0",
        operations={"POST /login": ["password", "username"]},
        raw={"info": {"title": "Test API"}},
    )
    restored = OpenAPIFingerprint.from_dict(oa.to_dict())
    assert restored.title == oa.title
    assert restored.operations == oa.operations


def test_site_fingerprint_includes_openapi():
    oa = OpenAPIFingerprint(title="API", version="1.0.0")
    fp = SiteFingerprint(
        target_url=BASE_URL,
        probed_at="2026-05-23T10:00:00+00:00",
        openapi=oa,
    )
    restored = SiteFingerprint.from_dict(fp.to_dict())
    assert restored.openapi is not None
    assert restored.openapi.title == "API"


def test_build_openapi_context_formats_operations():
    oa = OpenAPIFingerprint(
        title="Auth API",
        version="2.0.0",
        operations={
            "POST /login": ["password", "username"],
            "GET /me": [],
        },
    )
    context = build_openapi_context(oa)
    assert "Auth API" in context
    assert "POST /login" in context
    assert "password" in context


def test_build_openapi_context_none_returns_fallback():
    assert "No OpenAPI schema available" in build_openapi_context(None)


def test_compare_openapi_version_change():
    prev = _make_fp()
    prev.openapi = OpenAPIFingerprint(
        title="API", version="1.0.0",
        operations={"POST /login": ["password", "username"]},
    )
    curr = _make_fp()
    curr.openapi = OpenAPIFingerprint(
        title="API", version="2.0.0",
        operations={"POST /login": ["password", "username"]},
    )
    drift = compare_fingerprints(prev, curr)
    assert drift is not None
    assert "version changed" in drift


def test_compare_openapi_new_operation():
    prev = _make_fp()
    prev.openapi = OpenAPIFingerprint(
        title="API", version="1.0.0",
        operations={"POST /login": ["password", "username"]},
    )
    curr = _make_fp()
    curr.openapi = OpenAPIFingerprint(
        title="API", version="1.0.0",
        operations={
            "POST /login": ["password", "username"],
            "POST /logout": [],
        },
    )
    drift = compare_fingerprints(prev, curr)
    assert drift is not None
    assert "NEW operation" in drift


def test_compare_openapi_param_change():
    prev = _make_fp()
    prev.openapi = OpenAPIFingerprint(
        title="API", version="1.0.0",
        operations={"POST /login": ["password", "username"]},
    )
    curr = _make_fp()
    curr.openapi = OpenAPIFingerprint(
        title="API", version="1.0.0",
        operations={"POST /login": ["password", "totp_code", "username"]},
    )
    drift = compare_fingerprints(prev, curr)
    assert drift is not None
    assert "totp_code" in drift


@pytest.mark.asyncio
async def test_fetch_openapi_parses_schema():
    from agent.probe import _fetch_openapi

    with respx.mock(base_url=BASE_URL, assert_all_called=False) as router:
        _mock_openapi_schema(router)
        oa = await _fetch_openapi(BASE_URL, timeout=5.0)

    assert oa is not None
    assert oa.title == "Test API"
    assert "POST /login" in oa.operations
    assert oa.operations["POST /login"] == ["password", "username"]


@pytest.mark.asyncio
async def test_probe_site_fetches_openapi():
    from agent.probe import probe_site

    with respx.mock(base_url=BASE_URL, assert_all_called=False) as router:
        _mock_openapi_schema(router)
        _mock_probe_endpoints(router)

        fp = await probe_site(BASE_URL)

    assert fp.openapi is not None
    assert fp.openapi.title == "Test API"
    assert "GET /me" in fp.openapi.operations
