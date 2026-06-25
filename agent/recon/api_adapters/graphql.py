"""GraphQL adapter — extracts queries and mutations from an introspection
response and converts them to DiscoveredEndpoint objects."""
from __future__ import annotations

from typing import Any

from agent.recon.fingerprint import DiscoveredEndpoint

_DEFAULT_PATH = "/graphql"


def parse_graphql_schema(
    schema_data: dict[str, Any],
    graphql_path: str = _DEFAULT_PATH,
) -> list[DiscoveredEndpoint]:
    """Convert a GraphQL introspection response to DiscoveredEndpoint list.

    All operations share the same HTTP path; the operation name and kind
    are encoded in the `description` field so the planner can distinguish
    query vs. mutation.
    """
    schema = (
        (schema_data.get("data") or {}).get("__schema") or {}
    )

    if not schema:
        # Endpoint confirmed but introspection returned no schema data
        # (introspection may be disabled; errors block still confirms GraphQL)
        return [DiscoveredEndpoint(
            method="POST",
            path=graphql_path,
            description="GraphQL endpoint (introspection limited)",
        )]

    types = {
        t["name"]: t
        for t in schema.get("types", [])
        if isinstance(t, dict) and t.get("name")
    }

    endpoints: list[DiscoveredEndpoint] = []

    def _extract(type_name: str | None, op_kind: str) -> None:
        if not type_name or type_name not in types:
            return
        for fld in (types[type_name].get("fields") or []):
            field_name = fld.get("name", "")
            args = [
                a.get("name", "")
                for a in (fld.get("args") or [])
                if a.get("name")
            ]
            endpoints.append(DiscoveredEndpoint(
                method="POST",
                path=graphql_path,
                params=args,
                description=f"{op_kind}: {field_name}",
            ))

    query_name = (schema.get("queryType") or {}).get("name")
    mutation_name = (schema.get("mutationType") or {}).get("name")

    _extract(query_name, "query")
    _extract(mutation_name, "mutation")

    if not endpoints:
        endpoints.append(DiscoveredEndpoint(
            method="POST",
            path=graphql_path,
            description="GraphQL endpoint",
        ))

    return endpoints
