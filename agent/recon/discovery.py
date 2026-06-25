"""Endpoint discovery — delegates to the appropriate API adapter."""
from __future__ import annotations

import asyncio
from typing import Any

import httpx

from agent.logger import get_logger
from agent.recon.fingerprint import ApiType, DiscoveredEndpoint

log = get_logger(__name__)

# Common paths to probe for specless REST APIs (method, path)
_FUZZ_PATHS: list[tuple[str, str]] = [
    ("GET",  "/health"),
    ("GET",  "/status"),
    ("GET",  "/ping"),
    ("GET",  "/ready"),
    ("GET",  "/api"),
    ("GET",  "/api/v1"),
    ("GET",  "/api/v2"),
    ("GET",  "/v1"),
    ("GET",  "/v2"),
    ("POST", "/login"),
    ("POST", "/auth/login"),
    ("POST", "/api/login"),
    ("POST", "/auth"),
    ("POST", "/token"),
    ("POST", "/oauth/token"),
    ("GET",  "/users"),
    ("GET",  "/api/users"),
    ("GET",  "/api/v1/users"),
    ("GET",  "/me"),
    ("GET",  "/profile"),
    ("GET",  "/account"),
    ("GET",  "/products"),
    ("GET",  "/items"),
    ("GET",  "/resources"),
    ("GET",  "/admin"),
    ("GET",  "/docs"),
    ("GET",  "/swagger"),
    ("GET",  "/redoc"),
]


async def discover_endpoints(
    base_url: str,
    api_type: ApiType,
    spec: dict[str, Any] | None = None,
    graphql_data: dict[str, Any] | None = None,
    wsdl_xml: str | None = None,
    timeout: float = 5.0,
) -> list[DiscoveredEndpoint]:
    """Return discovered endpoints for the given API type."""

    if api_type == ApiType.REST_OPENAPI and spec:
        from agent.recon.api_adapters.rest import parse_openapi
        return parse_openapi(spec)

    if api_type == ApiType.GRAPHQL and graphql_data:
        from agent.recon.api_adapters.graphql import parse_graphql_schema
        return parse_graphql_schema(graphql_data)

    if api_type == ApiType.SOAP and wsdl_xml:
        from agent.recon.api_adapters.soap import parse_wsdl
        return parse_wsdl(wsdl_xml)

    if api_type == ApiType.GRPC:
        from agent.recon.api_adapters.grpc import discover_grpc
        return discover_grpc(base_url)

    return await _fuzz_paths(base_url, timeout)


async def _fuzz_paths(
    base_url: str,
    timeout: float,
) -> list[DiscoveredEndpoint]:
    """Probe common API paths; return those that respond with non-404."""
    found: list[DiscoveredEndpoint] = []

    async with httpx.AsyncClient(
        base_url=base_url,
        timeout=timeout,
        follow_redirects=True,
    ) as client:

        async def probe(
            method: str, path: str
        ) -> DiscoveredEndpoint | None:
            try:
                if method == "GET":
                    resp = await client.get(path)
                else:
                    resp = await client.post(path, json={})
                if resp.status_code != 404:
                    return DiscoveredEndpoint(
                        method=method,
                        path=path,
                        auth_required=resp.status_code in (401, 403),
                        description=(
                            f"Responded with HTTP {resp.status_code}"
                        ),
                    )
            except Exception:
                pass
            return None

        results = await asyncio.gather(
            *[probe(m, p) for m, p in _FUZZ_PATHS],
            return_exceptions=True,
        )

    for r in results:
        if isinstance(r, DiscoveredEndpoint):
            found.append(r)

    log.info(
        "recon.fuzz_complete",
        target=base_url,
        found=len(found),
        probed=len(_FUZZ_PATHS),
    )
    return found
