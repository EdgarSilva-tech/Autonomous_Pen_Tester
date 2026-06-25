"""API type detection and target fingerprinting.

Detection priority (first match wins):
1. OpenAPI spec found at well-known path  → REST_OPENAPI
2. GraphQL introspection responds         → GRAPHQL
3. WSDL document found at ?wsdl path     → SOAP
4. grpc-status / grpc Content-Type seen  → GRPC
5. Fallback                               → REST_SPECLESS
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx
from opentelemetry import trace

from agent.logger import get_logger

log = get_logger(__name__)
_tracer = trace.get_tracer("agent.recon.fingerprint")

_PROBE_TIMEOUT = 5.0

# ── API type ──────────────────────────────────────────────────────────────────


class ApiType(str, Enum):
    REST_OPENAPI = "rest_openapi"
    REST_SPECLESS = "rest_specless"
    GRAPHQL = "graphql"
    SOAP = "soap"
    GRPC = "grpc"


# ── Tech stack ────────────────────────────────────────────────────────────────


@dataclass
class TechStack:
    server: str | None = None
    framework: str | None = None
    language: str | None = None
    hints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "framework": self.framework,
            "language": self.language,
            "hints": self.hints,
        }


# ── Auth mechanisms ───────────────────────────────────────────────────────────


class AuthMechanism(str, Enum):
    BEARER = "bearer"
    BASIC = "basic"
    COOKIE = "cookie"
    API_KEY_HEADER = "api_key_header"
    API_KEY_QUERY = "api_key_query"
    OAUTH2 = "oauth2"
    UNKNOWN = "unknown"


# ── DiscoveredEndpoint ────────────────────────────────────────────────────────


@dataclass
class DiscoveredEndpoint:
    method: str
    path: str
    params: list[str] = field(default_factory=list)
    auth_required: bool | None = None
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "params": self.params,
            "auth_required": self.auth_required,
            "description": self.description,
        }


# ── FingerprintResult ─────────────────────────────────────────────────────────


@dataclass
class FingerprintResult:
    base_url: str
    api_type: ApiType
    tech_stack: TechStack
    auth_mechanisms: list[str]
    endpoints: list[DiscoveredEndpoint]
    openapi_spec: dict[str, Any] | None = None
    graphql_schema: dict[str, Any] | None = None
    wsdl_operations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_url": self.base_url,
            "api_type": self.api_type.value,
            "tech_stack": self.tech_stack.to_dict(),
            "auth_mechanisms": self.auth_mechanisms,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "openapi_spec": self.openapi_spec,
            "graphql_schema": self.graphql_schema,
            "wsdl_operations": self.wsdl_operations,
        }


# ── Well-known probe paths ─────────────────────────────────────────────────────

_OPENAPI_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/api-docs.json",
    "/swagger/v1/swagger.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/v1/openapi.json",
    "/api/v1/openapi.json",
    "/docs/openapi.json",
]

_GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/query",
    "/gql",
    "/v1/graphql",
    "/api/v1/graphql",
]

_WSDL_PATHS = [
    "/?wsdl",
    "/ws?wsdl",
    "/service?wsdl",
    "/soap?wsdl",
    "/services?wsdl",
    "/webservice?wsdl",
]

_GRAPHQL_INTROSPECTION = {
    "query": "{ __schema { queryType { name } } }"
}


# ── Internal probe helpers ─────────────────────────────────────────────────────


async def _probe_root(
    client: httpx.AsyncClient,
) -> list[httpx.Response]:
    """Probe root and /api for tech-stack header collection."""
    responses: list[httpx.Response] = []
    for path in ["/", "/api"]:
        try:
            responses.append(await client.get(path))
        except Exception:
            pass
    return responses


async def _try_openapi(
    client: httpx.AsyncClient,
) -> dict[str, Any] | None:
    """Try OpenAPI spec paths; return parsed schema on first hit."""
    for path in _OPENAPI_PATHS:
        try:
            resp = await client.get(path)
            if resp.is_success:
                schema = resp.json()
                if isinstance(schema, dict) and (
                    "openapi" in schema
                    or "swagger" in schema
                    or "paths" in schema
                ):
                    log.info("recon.openapi_found", path=path)
                    return schema
        except Exception:
            pass
    return None


async def _try_graphql(
    client: httpx.AsyncClient,
) -> dict[str, Any] | None:
    """Try GraphQL introspection; return response body on first hit."""
    for path in _GRAPHQL_PATHS:
        try:
            resp = await client.post(
                path, json=_GRAPHQL_INTROSPECTION
            )
            if resp.is_success or resp.status_code == 400:
                body = resp.json()
                if isinstance(body, dict) and (
                    "data" in body or "errors" in body
                ):
                    log.info("recon.graphql_found", path=path)
                    return body
        except Exception:
            pass
    return None


async def _try_wsdl(
    client: httpx.AsyncClient,
) -> str | None:
    """Try WSDL paths; return raw XML on first hit."""
    for path in _WSDL_PATHS:
        try:
            resp = await client.get(path)
            if resp.is_success:
                ct = resp.headers.get("content-type", "")
                text = resp.text
                if (
                    "xml" in ct
                    or "<definitions" in text
                    or "<wsdl:" in text
                    or "wsdl.xsd" in text
                ):
                    log.info("recon.wsdl_found", path=path)
                    return text
        except Exception:
            pass
    return None


def _detect_grpc(responses: list[httpx.Response]) -> bool:
    """Check collected responses for gRPC content-type or status header."""
    for resp in responses:
        ct = resp.headers.get("content-type", "")
        if ct.startswith("application/grpc"):
            return True
        if "grpc-status" in resp.headers:
            return True
    return False


# ── Tech stack detection ──────────────────────────────────────────────────────


def _detect_tech_stack(
    responses: list[httpx.Response],
) -> TechStack:
    """Infer tech stack from HTTP response headers."""
    ts = TechStack()
    hints: list[str] = []

    for resp in responses:
        h = resp.headers

        server = h.get("server", "")
        if server and ts.server is None:
            ts.server = server
            sl = server.lower()
            if "uvicorn" in sl or "starlette" in sl:
                ts.framework = "FastAPI/Starlette"
                ts.language = "Python"
            elif "gunicorn" in sl:
                ts.language = "Python"
            elif "node" in sl:
                ts.language = "JavaScript/Node.js"
            elif "nginx" in sl:
                hints.append("nginx")
            elif "apache" in sl:
                hints.append("Apache HTTP Server")
            elif "jetty" in sl or "tomcat" in sl:
                ts.language = "Java"
            elif "kestrel" in sl or "microsoft-httpapi" in sl:
                ts.language = ".NET"

        powered_by = h.get("x-powered-by", "")
        if powered_by and ts.framework is None:
            ts.framework = powered_by
            pl = powered_by.lower()
            if "express" in pl:
                ts.language = "JavaScript/Node.js"
            elif "php" in pl:
                ts.language = "PHP"
            elif "asp.net" in pl or "aspnet" in pl:
                ts.language = ".NET"
            elif "django" in pl:
                ts.framework = "Django"
                ts.language = "Python"
            elif "rails" in pl or "ruby" in pl:
                ts.language = "Ruby"

        set_cookie = h.get("set-cookie", "")
        if "PHPSESSID" in set_cookie:
            hints.append("PHP session cookie")
        if "JSESSIONID" in set_cookie:
            hints.append("Java session cookie")
        if "ASP.NET_SessionId" in set_cookie:
            hints.append(".NET session cookie")

        ct = h.get("content-type", "")
        if "application/json" in ct and "JSON API" not in hints:
            hints.append("JSON API")
        if ("application/xml" in ct or "text/xml" in ct) and (
            "XML API" not in hints
        ):
            hints.append("XML API")

    ts.hints = list(dict.fromkeys(hints))
    return ts


# ── Auth mechanism detection ──────────────────────────────────────────────────


def _detect_auth_mechanisms(
    responses: list[httpx.Response],
    openapi_spec: dict[str, Any] | None,
) -> list[str]:
    """Infer supported auth mechanisms from response headers and spec."""
    mechanisms: set[str] = set()

    for resp in responses:
        www_auth = resp.headers.get("www-authenticate", "").lower()
        if "bearer" in www_auth:
            mechanisms.add(AuthMechanism.BEARER.value)
        if "basic" in www_auth:
            mechanisms.add(AuthMechanism.BASIC.value)
        if resp.headers.get("set-cookie"):
            mechanisms.add(AuthMechanism.COOKIE.value)

    if openapi_spec:
        schemes = (
            openapi_spec
            .get("components", {})
            .get("securitySchemes", {})
        )
        for scheme in schemes.values():
            stype = scheme.get("type", "").lower()
            sscheme = scheme.get("scheme", "").lower()
            if stype == "http" and sscheme == "bearer":
                mechanisms.add(AuthMechanism.BEARER.value)
            elif stype == "http" and sscheme == "basic":
                mechanisms.add(AuthMechanism.BASIC.value)
            elif stype == "apikey":
                loc = scheme.get("in", "").lower()
                if loc == "header":
                    mechanisms.add(AuthMechanism.API_KEY_HEADER.value)
                else:
                    mechanisms.add(AuthMechanism.API_KEY_QUERY.value)
            elif stype in ("oauth2", "openidconnect"):
                mechanisms.add(AuthMechanism.OAUTH2.value)

    return (
        sorted(mechanisms) if mechanisms
        else [AuthMechanism.UNKNOWN.value]
    )


# ── Public entry point ────────────────────────────────────────────────────────


async def fingerprint_target(
    base_url: str,
    timeout: float = _PROBE_TIMEOUT,
) -> FingerprintResult:
    """Probe a target and return a complete FingerprintResult.

    All detection probes run in parallel. Individual failures are caught
    and treated as non-matches — the call always returns a result.
    """
    with _tracer.start_as_current_span(
        "recon.fingerprint",
        attributes={"recon.target": base_url},
    ):
        return await _fingerprint_inner(base_url, timeout)


async def _fingerprint_inner(
    base_url: str,
    timeout: float,
) -> FingerprintResult:
    async with httpx.AsyncClient(
        base_url=base_url,
        timeout=timeout,
        follow_redirects=True,
        limits=httpx.Limits(max_connections=10),
    ) as client:
        root_resp, openapi_spec, graphql_data, wsdl_xml = (
            await asyncio.gather(
                _probe_root(client),
                _try_openapi(client),
                _try_graphql(client),
                _try_wsdl(client),
                return_exceptions=True,
            )
        )

    root_responses: list[httpx.Response] = (
        root_resp if isinstance(root_resp, list) else []
    )
    openapi_spec = openapi_spec if isinstance(openapi_spec, dict) else None
    graphql_data = graphql_data if isinstance(graphql_data, dict) else None
    wsdl_xml = wsdl_xml if isinstance(wsdl_xml, str) else None

    if isinstance(openapi_spec, dict):
        api_type = ApiType.REST_OPENAPI
    elif isinstance(graphql_data, dict):
        api_type = ApiType.GRAPHQL
    elif isinstance(wsdl_xml, str):
        api_type = ApiType.SOAP
    elif _detect_grpc(root_responses):
        api_type = ApiType.GRPC
    else:
        api_type = ApiType.REST_SPECLESS

    tech_stack = _detect_tech_stack(root_responses)
    auth_mechanisms = _detect_auth_mechanisms(root_responses, openapi_spec)

    from agent.recon.discovery import discover_endpoints
    endpoints = await discover_endpoints(
        base_url=base_url,
        api_type=api_type,
        spec=openapi_spec,
        graphql_data=graphql_data,
        wsdl_xml=wsdl_xml,
        timeout=timeout,
    )

    wsdl_operations: list[str] = []
    if wsdl_xml:
        from agent.recon.api_adapters.soap import extract_operation_names
        wsdl_operations = extract_operation_names(wsdl_xml)

    log.info(
        "recon.fingerprint_complete",
        target=base_url,
        api_type=api_type.value,
        endpoint_count=len(endpoints),
        auth_mechanisms=auth_mechanisms,
        framework=tech_stack.framework,
    )

    return FingerprintResult(
        base_url=base_url,
        api_type=api_type,
        tech_stack=tech_stack,
        auth_mechanisms=auth_mechanisms,
        endpoints=endpoints,
        openapi_spec=openapi_spec,
        graphql_schema=graphql_data,
        wsdl_operations=wsdl_operations,
    )
