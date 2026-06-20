"""Agent tool registry.

Exports ALL_TOOLS — the flat list of Layer 1 (primitives) + Layer 2 (attack
modules) tools that get bound to the LLM.  Layer 3 MCP tools are discovered
at runtime in graph.py via get_mcp_tools() and appended before LLM binding.

Backward-compat aliases keep existing imports in graph.py and tests working
without changes.
"""
from agent.tools.primitives import (
    PRIMITIVE_TOOLS,
    reset_session,
    set_base_url,
)
from agent.tools.attacks.auth import (
    AUTH_TOOLS,
    change_password_tool,
    login_tool,
    logout_tool,
    me_tool,
)

# Layer 1 + Layer 2 — always present regardless of MCP configuration
ALL_TOOLS = PRIMITIVE_TOOLS + AUTH_TOOLS

# graph.py imports this name
HTTP_TOOLS = ALL_TOOLS

__all__ = [
    "ALL_TOOLS",
    "HTTP_TOOLS",
    "set_base_url",
    "reset_session",
    # individual auth tools re-exported for tests that import from agent.tools
    "login_tool",
    "me_tool",
    "change_password_tool",
    "logout_tool",
]
