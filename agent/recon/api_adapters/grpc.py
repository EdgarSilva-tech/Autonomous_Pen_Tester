"""gRPC adapter stub — detection only, no active probing in v2.

Full gRPC testing requires protobuf reflection over HTTP/2, which needs
a dedicated MCP server. Add an grpc-mcp entry to MCP_SERVERS to enable it.
"""
from __future__ import annotations

from agent.logger import get_logger
from agent.recon.fingerprint import DiscoveredEndpoint

log = get_logger(__name__)


def discover_grpc(base_url: str) -> list[DiscoveredEndpoint]:
    """Log gRPC detection and return an empty endpoint list."""
    log.warning(
        "recon.grpc_detected_not_tested",
        base_url=base_url,
        hint=(
            "Add a grpc-mcp server via MCP_SERVERS to enable gRPC scanning."
        ),
    )
    return []
