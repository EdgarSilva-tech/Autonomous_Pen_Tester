"""Planner node — maps fingerprint + scope to a prioritised test plan."""
from __future__ import annotations

import os
from typing import Any, Literal

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from agent.logger import get_logger
from agent.state import PentestState

log = get_logger(__name__)


# ── Output schema ────────────────────────────────────────────────────────────

class PlanItem(BaseModel):
    module: str = Field(
        description=(
            "Attack module: auth, injection, access, "
            "headers, disclosure, or ratelimit"
        )
    )
    tools: list[str] = Field(
        description="Tool function names to invoke for this module"
    )
    priority: Literal["critical", "high", "medium", "low"] = Field(
        description="Execution priority (critical runs first)"
    )
    paths: list[str] = Field(
        description="Target paths to test (max 5)"
    )
    reason: str = Field(
        description="One sentence explaining why this module applies"
    )
    config: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional per-module config (e.g. parameter names)",
    )


class _TestPlan(BaseModel):
    """Wrapper so with_structured_output can extract a list."""

    items: list[PlanItem]


# ── Planner prompt ───────────────────────────────────────────────────────────

_PLANNER_SYSTEM_PROMPT = """\
You are a security test planner. Given a reconnaissance fingerprint of a
web API, produce a prioritised test plan covering the most relevant checks.

## Available modules and their built-in tools

### auth
jwt_analyze, brute_force_check, session_fixation_check, token_entropy_check

### injection
sqli_probe, nosql_probe, ssti_probe, xss_probe

### access
idor_probe, bola_probe, privilege_escalation_check

### headers
cors_check, security_headers_check, csp_check

### disclosure
error_disclosure_probe, pii_scan, path_traversal_probe, http_methods_check

### ratelimit
rate_limit_check, ip_bypass_check

## Planning rules
1. Only include modules listed under "enabled modules" in the scope.
2. Prioritise: critical > high > medium > low.
3. For each module list: specific tool names and paths to test (max 5 paths).
4. If no endpoints discovered use common paths: /, /api, /login, /health.
5. Include a one-sentence reason per module.
6. MCP tools may be available at runtime for deeper analysis — this plan
   covers the built-in Layer 2 tools only; do not reference MCP tool names.
7. Respond ONLY with the structured JSON — no prose.
"""


# ── Helpers ──────────────────────────────────────────────────────────────────

def _format_endpoints(endpoints: list[dict[str, Any]]) -> str:
    if not endpoints:
        return "  (none discovered)"
    return "\n".join(
        f"  {e.get('method', '?')} {e.get('path', '?')}"
        for e in endpoints[:20]
    )


def _build_human_msg(
    fingerprint: dict[str, Any],
    scope: dict[str, Any],
) -> str:
    active: list[str] = scope.get("active_modules") or [
        "auth",
        "injection",
        "access",
        "headers",
        "disclosure",
        "ratelimit",
    ]
    excluded: list[str] = scope.get("excluded_paths") or []
    endpoints = fingerprint.get("endpoints", [])

    lines = [
        "## Target fingerprint",
        f"API type: {fingerprint.get('api_type', 'unknown')}",
        f"Auth mechanisms: {fingerprint.get('auth_mechanisms', [])}",
        f"Tech stack: {fingerprint.get('tech_stack', {})}",
        "Discovered endpoints:",
        _format_endpoints(endpoints),
        "",
        "## Scope constraints",
        f"Enabled modules: {active}",
        f"Excluded paths: {excluded or '(none)'}",
        "",
        "Produce the test plan now.",
    ]
    return "\n".join(lines)


def _build_llm() -> Any:
    llm = ChatOpenAI(
        model="gpt-4o-mini",
        openai_api_base=os.getenv(
            "LITELLM_BASE_URL", "http://localhost:4000"
        ),
        openai_api_key=os.getenv(
            "LITELLM_API_KEY", "sk-pentest-master"
        ),
        temperature=0,
        max_retries=0,
    )
    return llm.with_structured_output(_TestPlan)


# ── Node ─────────────────────────────────────────────────────────────────────

async def planner_node(state: PentestState) -> dict[str, Any]:
    """Generate a test plan from fingerprint + scope via the planner LLM."""
    fingerprint: dict[str, Any] = state.get("fingerprint") or {}
    scope: dict[str, Any] = state.get("scope") or {}

    log.info(
        "planner_node.start",
        api_type=fingerprint.get("api_type"),
        endpoints=len(fingerprint.get("endpoints", [])),
    )

    planner = _build_llm()
    result: _TestPlan = await planner.ainvoke([
        SystemMessage(content=_PLANNER_SYSTEM_PROMPT),
        HumanMessage(
            content=_build_human_msg(fingerprint, scope)
        ),
    ])

    items = [item.model_dump() for item in result.items]
    log.info(
        "planner_node.done",
        modules=[i["module"] for i in items],
        count=len(items),
    )
    return {"test_plan": items}
