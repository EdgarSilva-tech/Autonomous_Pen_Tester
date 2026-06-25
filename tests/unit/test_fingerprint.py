"""Unit tests for agent.recon.fingerprint using respx to mock httpx."""
from __future__ import annotations

import httpx
import pytest
import respx

from agent.recon.fingerprint import (
    ApiType,
    AuthMechanism,
    FingerprintResult,
    TechStack,
    _detect_auth_mechanisms,
    _detect_tech_stack,
    fingerprint_target,
)

TARGET = "http://test-target:9000"

_OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Test API", "version": "1.0"},
    "paths": {
        "/users": {"get": {"summary": "List users"}},
    },
}

_GRAPHQL_INTROSPECTION_RESPONSE = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": None,
            "types": [
                {
                    "name": "Query",
                    "kind": "OBJECT",
                    "fields": [
                        {"name": "users", "args": []},
                    ],
                }
            ],
        }
    }
}

_WSDL_XML = """<?xml version="1.0"?>
<definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
             xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
             name="TestService">
  <portType name="TestPort">
    <operation name="GetUser">
      <input message="tns:GetUserRequest"/>
    </operation>
  </portType>
  <binding name="TestBinding" type="tns:TestPort">
    <operation name="GetUser"/>
  </binding>
  <service name="TestService">
    <port name="TestPort" binding="tns:TestBinding">
      <soap:address location="http://test-target:9000/ws"/>
    </port>
  </service>
</definitions>"""


# ── REST_OPENAPI detection ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_detect_rest_openapi():
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{TARGET}/openapi.json").mock(
            return_value=httpx.Response(200, json=_OPENAPI_SPEC)
        )
        result = await fingerprint_target(TARGET, timeout=2.0)

    assert result.api_type == ApiType.REST_OPENAPI
    assert result.openapi_spec == _OPENAPI_SPEC
    assert result.base_url == TARGET


@pytest.mark.asyncio
async def test_rest_openapi_populates_endpoints():
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{TARGET}/openapi.json").mock(
            return_value=httpx.Response(200, json=_OPENAPI_SPEC)
        )
        result = await fingerprint_target(TARGET, timeout=2.0)

    assert len(result.endpoints) == 1
    ep = result.endpoints[0]
    assert ep.method == "GET"
    assert ep.path == "/users"
    assert ep.description == "List users"


# ── GRAPHQL detection ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_detect_graphql():
    with respx.mock(assert_all_called=False) as router:
        # All OpenAPI paths return 404
        for path in [
            "/openapi.json", "/swagger.json", "/api-docs",
            "/api-docs.json", "/swagger/v1/swagger.json",
            "/api/swagger.json", "/api/openapi.json",
            "/v1/openapi.json", "/api/v1/openapi.json",
            "/docs/openapi.json",
        ]:
            router.get(f"{TARGET}{path}").mock(
                return_value=httpx.Response(404)
            )
        router.post(f"{TARGET}/graphql").mock(
            return_value=httpx.Response(
                200, json=_GRAPHQL_INTROSPECTION_RESPONSE
            )
        )
        result = await fingerprint_target(TARGET, timeout=2.0)

    assert result.api_type == ApiType.GRAPHQL
    assert result.graphql_schema == _GRAPHQL_INTROSPECTION_RESPONSE


@pytest.mark.asyncio
async def test_graphql_with_errors_response():
    """A 400 with {"errors": [...]} still confirms GraphQL."""
    gql_error = {"errors": [{"message": "introspection disabled"}]}
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{TARGET}/graphql").mock(
            return_value=httpx.Response(400, json=gql_error)
        )
        result = await fingerprint_target(TARGET, timeout=2.0)

    assert result.api_type == ApiType.GRAPHQL


# ── SOAP detection ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_detect_soap():
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{TARGET}/?wsdl").mock(
            return_value=httpx.Response(
                200,
                text=_WSDL_XML,
                headers={"content-type": "text/xml"},
            )
        )
        result = await fingerprint_target(TARGET, timeout=2.0)

    assert result.api_type == ApiType.SOAP
    assert "GetUser" in result.wsdl_operations


# ── REST_SPECLESS fallback ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_detect_rest_specless_fallback():
    """When no spec or schema is found, fall back to REST_SPECLESS."""
    with respx.mock(assert_all_called=False) as router:
        # Mock a couple of fuzz paths as 200 so we get endpoints
        router.get(f"{TARGET}/health").mock(
            return_value=httpx.Response(200, json={"status": "ok"})
        )
        router.get(f"{TARGET}/api").mock(
            return_value=httpx.Response(200, json={})
        )
        result = await fingerprint_target(TARGET, timeout=2.0)

    assert result.api_type == ApiType.REST_SPECLESS
    assert result.openapi_spec is None
    assert result.graphql_schema is None
    paths = [e.path for e in result.endpoints]
    assert "/health" in paths
    assert "/api" in paths


# ── Tech stack detection ──────────────────────────────────────────────────────


def test_detect_fastapi_from_uvicorn_server():
    resp = httpx.Response(200, headers={"server": "uvicorn"})
    ts = _detect_tech_stack([resp])
    assert ts.server == "uvicorn"
    assert ts.framework == "FastAPI/Starlette"
    assert ts.language == "Python"


def test_detect_node_from_x_powered_by():
    resp = httpx.Response(
        200, headers={"x-powered-by": "Express"}
    )
    ts = _detect_tech_stack([resp])
    assert ts.framework == "Express"
    assert ts.language == "JavaScript/Node.js"


def test_detect_dotnet_from_x_powered_by():
    resp = httpx.Response(
        200, headers={"x-powered-by": "ASP.NET"}
    )
    ts = _detect_tech_stack([resp])
    assert ts.language == ".NET"


def test_detect_php_session_cookie_hint():
    resp = httpx.Response(
        200, headers={"set-cookie": "PHPSESSID=abc; Path=/"}
    )
    ts = _detect_tech_stack([resp])
    assert "PHP session cookie" in ts.hints


def test_detect_json_api_hint():
    resp = httpx.Response(
        200, headers={"content-type": "application/json"}
    )
    ts = _detect_tech_stack([resp])
    assert "JSON API" in ts.hints


def test_empty_responses_returns_empty_tech_stack():
    ts = _detect_tech_stack([])
    assert ts.server is None
    assert ts.framework is None
    assert ts.hints == []


# ── Auth mechanism detection ──────────────────────────────────────────────────


def test_detect_bearer_from_www_authenticate():
    resp = httpx.Response(
        401, headers={"www-authenticate": "Bearer realm=api"}
    )
    mechs = _detect_auth_mechanisms([resp], None)
    assert AuthMechanism.BEARER.value in mechs


def test_detect_basic_from_www_authenticate():
    resp = httpx.Response(
        401,
        headers={"www-authenticate": "Basic realm=protected"},
    )
    mechs = _detect_auth_mechanisms([resp], None)
    assert AuthMechanism.BASIC.value in mechs


def test_detect_cookie_from_set_cookie():
    resp = httpx.Response(
        200, headers={"set-cookie": "session=xyz; Path=/"}
    )
    mechs = _detect_auth_mechanisms([resp], None)
    assert AuthMechanism.COOKIE.value in mechs


def test_detect_bearer_from_openapi_security_scheme():
    spec = {
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                }
            }
        }
    }
    mechs = _detect_auth_mechanisms([], spec)
    assert AuthMechanism.BEARER.value in mechs


def test_detect_apikey_header_from_openapi():
    spec = {
        "components": {
            "securitySchemes": {
                "apiKey": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                }
            }
        }
    }
    mechs = _detect_auth_mechanisms([], spec)
    assert AuthMechanism.API_KEY_HEADER.value in mechs


def test_detect_oauth2_from_openapi():
    spec = {
        "components": {
            "securitySchemes": {
                "oauth2": {
                    "type": "oauth2",
                    "flows": {},
                }
            }
        }
    }
    mechs = _detect_auth_mechanisms([], spec)
    assert AuthMechanism.OAUTH2.value in mechs


def test_no_signals_returns_unknown():
    mechs = _detect_auth_mechanisms([], None)
    assert mechs == [AuthMechanism.UNKNOWN.value]


# ── FingerprintResult.to_dict ─────────────────────────────────────────────────


def test_fingerprint_result_to_dict():
    result = FingerprintResult(
        base_url="http://example.com",
        api_type=ApiType.REST_OPENAPI,
        tech_stack=TechStack(server="uvicorn", language="Python"),
        auth_mechanisms=["bearer"],
        endpoints=[],
        openapi_spec={"openapi": "3.0.0"},
    )
    d = result.to_dict()
    assert d["api_type"] == "rest_openapi"
    assert d["base_url"] == "http://example.com"
    assert d["tech_stack"]["server"] == "uvicorn"
    assert d["auth_mechanisms"] == ["bearer"]
    assert d["openapi_spec"] == {"openapi": "3.0.0"}
