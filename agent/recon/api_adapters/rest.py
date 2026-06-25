"""REST/OpenAPI adapter — converts an OpenAPI 3.x/Swagger 2.x schema
to a list of DiscoveredEndpoint objects."""
from __future__ import annotations

from typing import Any

from agent.recon.fingerprint import DiscoveredEndpoint

_HTTP_METHODS = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
)


def parse_openapi(spec: dict[str, Any]) -> list[DiscoveredEndpoint]:
    """Extract all operations from an OpenAPI / Swagger schema."""
    endpoints: list[DiscoveredEndpoint] = []

    for path, path_item in spec.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.upper() not in _HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                continue

            params: list[str] = []
            for p in operation.get("parameters", []):
                if isinstance(p, dict):
                    name = p.get("name", "")
                    if name:
                        params.append(name)

            # Request body schema properties → params list
            for media in (
                operation.get("requestBody", {})
                .get("content", {})
                .values()
            ):
                props = media.get("schema", {}).get("properties", {})
                params.extend(k for k in props if k)

            security = operation.get("security")
            auth_required: bool | None = (
                len(security) > 0 if security is not None else None
            )

            endpoints.append(DiscoveredEndpoint(
                method=method.upper(),
                path=path,
                params=sorted(set(params)),
                auth_required=auth_required,
                description=(
                    operation.get("summary")
                    or operation.get("operationId")
                    or ""
                ),
            ))

    return endpoints
