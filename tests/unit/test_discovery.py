"""Unit tests for endpoint discovery and API-type adapters."""
from __future__ import annotations

import httpx
import pytest
import respx

from agent.recon.api_adapters.graphql import parse_graphql_schema
from agent.recon.api_adapters.grpc import discover_grpc
from agent.recon.api_adapters.rest import parse_openapi
from agent.recon.api_adapters.soap import (
    extract_operation_names,
    parse_wsdl,
)
from agent.recon.discovery import discover_endpoints
from agent.recon.fingerprint import ApiType

TARGET = "http://test-target:9000"

# ── REST / OpenAPI adapter ────────────────────────────────────────────────


def test_parse_openapi_returns_endpoints():
    spec = {
        "paths": {
            "/users": {
                "get": {
                    "summary": "List users",
                    "parameters": [
                        {"name": "limit", "in": "query"}
                    ],
                }
            }
        }
    }
    eps = parse_openapi(spec)
    assert len(eps) == 1
    ep = eps[0]
    assert ep.method == "GET"
    assert ep.path == "/users"
    assert "limit" in ep.params
    assert ep.description == "List users"


def test_parse_openapi_request_body_params():
    spec = {
        "paths": {
            "/items": {
                "post": {
                    "operationId": "createItem",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "properties": {
                                        "name": {},
                                        "price": {},
                                    }
                                }
                            }
                        }
                    },
                }
            }
        }
    }
    eps = parse_openapi(spec)
    assert len(eps) == 1
    assert set(eps[0].params) == {"name", "price"}
    assert eps[0].description == "createItem"


def test_parse_openapi_auth_required_from_security():
    spec = {
        "paths": {
            "/secure": {
                "get": {
                    "security": [{"bearerAuth": []}],
                }
            },
            "/public": {
                "get": {
                    "security": [],
                }
            },
            "/unknown": {
                "get": {},
            },
        }
    }
    eps = {e.path: e for e in parse_openapi(spec)}
    assert eps["/secure"].auth_required is True
    assert eps["/public"].auth_required is False
    assert eps["/unknown"].auth_required is None


def test_parse_openapi_empty_paths():
    assert parse_openapi({}) == []
    assert parse_openapi({"paths": {}}) == []


def test_parse_openapi_skips_non_http_keys():
    spec = {
        "paths": {
            "/items": {
                "get": {"summary": "ok"},
                "parameters": [],  # path-level, not an HTTP method
                "summary": "blah",
            }
        }
    }
    eps = parse_openapi(spec)
    assert all(e.method in {"GET"} for e in eps)


# ── GraphQL adapter ───────────────────────────────────────────────────────


def test_parse_graphql_extracts_queries():
    data = {
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
                            {
                                "name": "user",
                                "args": [{"name": "id"}],
                            },
                        ],
                    }
                ],
            }
        }
    }
    eps = parse_graphql_schema(data)
    descriptions = [e.description for e in eps]
    assert "query: users" in descriptions
    assert "query: user" in descriptions
    user_ep = next(
        e for e in eps if "user" in e.description and e.params
    )
    assert "id" in user_ep.params


def test_parse_graphql_extracts_mutations():
    data = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "types": [
                    {
                        "name": "Query",
                        "kind": "OBJECT",
                        "fields": [],
                    },
                    {
                        "name": "Mutation",
                        "kind": "OBJECT",
                        "fields": [
                            {
                                "name": "createUser",
                                "args": [{"name": "name"}],
                            }
                        ],
                    },
                ],
            }
        }
    }
    eps = parse_graphql_schema(data)
    descriptions = [e.description for e in eps]
    assert "mutation: createUser" in descriptions


def test_parse_graphql_limited_introspection():
    """Introspection disabled → single fallback endpoint."""
    data = {"errors": [{"message": "introspection disabled"}]}
    eps = parse_graphql_schema(data)
    assert len(eps) == 1
    assert (
        "limited" in eps[0].description
        or "GraphQL" in eps[0].description
    )


def test_parse_graphql_all_post():
    data = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": None,
                "types": [
                    {
                        "name": "Query",
                        "kind": "OBJECT",
                        "fields": [{"name": "ping", "args": []}],
                    }
                ],
            }
        }
    }
    eps = parse_graphql_schema(data)
    assert all(e.method == "POST" for e in eps)


# ── SOAP adapter ──────────────────────────────────────────────────────────

_WSDL_XML = """<?xml version="1.0"?>
<definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
             xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
             name="CalcService">
  <portType name="CalcPort">
    <operation name="Add">
      <input message="tns:AddRequest"/>
      <output message="tns:AddResponse"/>
    </operation>
    <operation name="Subtract">
      <input message="tns:SubtractRequest"/>
    </operation>
  </portType>
  <service name="CalcService">
    <port name="CalcPort" binding="tns:CalcBinding">
      <soap:address location="http://example.com/calculator"/>
    </port>
  </service>
</definitions>"""


def test_extract_operation_names():
    names = extract_operation_names(_WSDL_XML)
    assert "Add" in names
    assert "Subtract" in names


def test_extract_operation_names_deduplicates():
    names = extract_operation_names(_WSDL_XML)
    assert names.count("Add") == 1


def test_parse_wsdl_returns_endpoints():
    eps = parse_wsdl(_WSDL_XML)
    ops = [e.description for e in eps]
    assert any("Add" in d for d in ops)
    assert any("Subtract" in d for d in ops)


def test_parse_wsdl_uses_soap_address_path():
    eps = parse_wsdl(_WSDL_XML)
    assert all(e.path == "/calculator" for e in eps)


def test_parse_wsdl_all_post():
    eps = parse_wsdl(_WSDL_XML)
    assert all(e.method == "POST" for e in eps)


def test_parse_wsdl_invalid_xml():
    eps = parse_wsdl("<not valid xml<<<")
    assert isinstance(eps, list)


def test_extract_operation_names_invalid_xml():
    names = extract_operation_names("<broken")
    assert names == []


# ── gRPC adapter stub ─────────────────────────────────────────────────────


def test_discover_grpc_returns_empty():
    eps = discover_grpc("http://target:50051")
    assert eps == []


# ── discover_endpoints dispatch ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_discover_rest_openapi_dispatches_to_adapter():
    spec = {
        "paths": {"/ping": {"get": {"summary": "Ping"}}}
    }
    eps = await discover_endpoints(
        base_url=TARGET,
        api_type=ApiType.REST_OPENAPI,
        spec=spec,
    )
    assert len(eps) == 1
    assert eps[0].path == "/ping"


@pytest.mark.asyncio
async def test_discover_graphql_dispatches_to_adapter():
    data = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": None,
                "types": [
                    {
                        "name": "Query",
                        "kind": "OBJECT",
                        "fields": [{"name": "ping", "args": []}],
                    }
                ],
            }
        }
    }
    eps = await discover_endpoints(
        base_url=TARGET,
        api_type=ApiType.GRAPHQL,
        graphql_data=data,
    )
    assert len(eps) >= 1
    assert all(e.method == "POST" for e in eps)


@pytest.mark.asyncio
async def test_discover_soap_dispatches_to_adapter():
    eps = await discover_endpoints(
        base_url=TARGET,
        api_type=ApiType.SOAP,
        wsdl_xml=_WSDL_XML,
    )
    ops = [e.description for e in eps]
    assert any("Add" in d for d in ops)


@pytest.mark.asyncio
async def test_discover_grpc_dispatches_to_stub():
    eps = await discover_endpoints(
        base_url=TARGET,
        api_type=ApiType.GRPC,
    )
    assert eps == []


@pytest.mark.asyncio
async def test_discover_rest_specless_fuzzes_paths():
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{TARGET}/health").mock(
            return_value=httpx.Response(200, json={"status": "ok"})
        )
        router.get(f"{TARGET}/api/v1").mock(
            return_value=httpx.Response(200, json={})
        )
        eps = await discover_endpoints(
            base_url=TARGET,
            api_type=ApiType.REST_SPECLESS,
            timeout=2.0,
        )

    paths = [e.path for e in eps]
    assert "/health" in paths
    assert "/api/v1" in paths


@pytest.mark.asyncio
async def test_discover_specless_skips_404():
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{TARGET}/health").mock(
            return_value=httpx.Response(404)
        )
        router.get(f"{TARGET}/status").mock(
            return_value=httpx.Response(404)
        )
        eps = await discover_endpoints(
            base_url=TARGET,
            api_type=ApiType.REST_SPECLESS,
            timeout=2.0,
        )
    paths = [e.path for e in eps]
    assert "/health" not in paths
    assert "/status" not in paths


@pytest.mark.asyncio
async def test_discover_specless_marks_401_as_auth_required():
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{TARGET}/admin").mock(
            return_value=httpx.Response(401)
        )
        eps = await discover_endpoints(
            base_url=TARGET,
            api_type=ApiType.REST_SPECLESS,
            timeout=2.0,
        )

    admin_ep = next((e for e in eps if e.path == "/admin"), None)
    assert admin_ep is not None
    assert admin_ep.auth_required is True
