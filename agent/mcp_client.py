"""MCP Client — connects to external MCP servers and converts their tools
into LangChain BaseTool instances that can be added to the ReAct agent pool.

MCP servers are declared via the MCP_SERVERS environment variable as a
JSON object:

    MCP_SERVERS='{"security-scanner": {"url": "http://mcp-scanner:8080/mcp", "transport": "streamable_http"}}'

If the variable is absent or the servers are unreachable, get_mcp_tools()
returns an empty list so the agent still works with only the HTTP tools.
"""
from __future__ import annotations

import json
import os
from typing import Any

from agent.logger import get_logger

log = get_logger(__name__)


def _parse_server_config() -> dict[str, Any]:
    raw = os.getenv("MCP_SERVERS", "{}")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        log.warning("mcp_client.invalid_config", raw=raw)
        return {}


async def get_mcp_tools() -> list:
    """Return LangChain tools discovered from all configured MCP servers.

    Falls back to an empty list if langchain-mcp-adapters is not installed
    or if no MCP servers are configured / reachable.
    """
    server_config = _parse_server_config()
    if not server_config:
        log.info("mcp_client.no_servers_configured")
        return []

    try:
        from langchain_mcp_adapters.client import MultiServerMCPClient  # type: ignore
    except ImportError:
        log.warning("mcp_client.package_not_installed", package="langchain-mcp-adapters")
        return []

    try:
        async with MultiServerMCPClient(server_config) as client:
            tools = client.get_tools()
            log.info("mcp_client.tools_loaded", count=len(tools), servers=list(server_config))
            return tools
    except Exception as exc:
        log.warning("mcp_client.connection_failed", error=str(exc))
        return []
