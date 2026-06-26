"""Integration tests: planner node and graph wiring.

These tests verify the planner_node behaviour without a live LLM by
patching ChatOpenAI at import time.  They cover:
  - Basic plan generation from fingerprint
  - Empty-fingerprint handling
  - Scope constraints passed to the LLM prompt
  - No-MCP-server scenario (planner has no external tool deps)
  - evaluate_node module-coverage logic (v2 mode)
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent.nodes.planner import PlanItem, _TestPlan, planner_node


# ── Fixtures ─────────────────────────────────────────────────────────────────

MOCK_FP = {
    "api_type": "rest_openapi",
    "endpoints": [
        {"method": "GET", "path": "/"},
        {"method": "POST", "path": "/login"},
        {"method": "GET", "path": "/api/users"},
    ],
    "auth_mechanisms": ["bearer"],
    "tech_stack": {"framework": "fastapi"},
}


def _plan_with(*modules: str) -> _TestPlan:
    items = [
        PlanItem(
            module=m,
            tools=["security_headers_check"] if m == "headers"
            else ["sqli_probe"] if m == "injection"
            else ["brute_force_check"],
            priority="high",
            paths=["/"],
            reason=f"{m} is relevant for this target",
        )
        for m in modules
    ]
    return _TestPlan(items=items)


def _mock_llm(plan: _TestPlan):
    """Return a patched ChatOpenAI context manager."""
    mock_runnable = AsyncMock()
    mock_runnable.ainvoke.return_value = plan
    mock_instance = MagicMock()
    mock_instance.with_structured_output.return_value = mock_runnable
    return mock_instance


# ── planner_node tests ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_planner_node_generates_test_plan():
    """Planner returns correctly shaped test_plan list."""
    plan = _plan_with("headers", "auth")
    state = {
        "fingerprint": MOCK_FP,
        "scope": {},
        "test_plan": [],
        "messages": [],
    }
    with patch(
        "agent.nodes.planner.ChatOpenAI",
        return_value=_mock_llm(plan),
    ):
        result = await planner_node(state)

    items = result["test_plan"]
    assert len(items) == 2
    assert items[0]["module"] == "headers"
    assert items[0]["priority"] == "high"
    assert "security_headers_check" in items[0]["tools"]
    assert items[1]["module"] == "auth"


@pytest.mark.asyncio
async def test_planner_node_handles_empty_fingerprint():
    """Planner works when fingerprint has no endpoints."""
    plan = _plan_with("headers")
    state = {
        "fingerprint": {},
        "scope": {},
        "test_plan": [],
        "messages": [],
    }
    with patch(
        "agent.nodes.planner.ChatOpenAI",
        return_value=_mock_llm(plan),
    ):
        result = await planner_node(state)

    assert isinstance(result["test_plan"], list)
    assert len(result["test_plan"]) == 1


@pytest.mark.asyncio
async def test_planner_node_passes_scope_to_llm():
    """Scope constraints appear in the human message sent to the LLM."""
    plan = _plan_with("headers")
    state = {
        "fingerprint": MOCK_FP,
        "scope": {
            "active_modules": ["headers"],
            "excluded_paths": ["/admin"],
        },
        "test_plan": [],
        "messages": [],
    }

    captured: list = []

    async def capture(msgs):
        captured.extend(msgs)
        return plan

    mock_runnable = AsyncMock()
    mock_runnable.ainvoke.side_effect = capture
    mock_instance = MagicMock()
    mock_instance.with_structured_output.return_value = mock_runnable

    with patch(
        "agent.nodes.planner.ChatOpenAI",
        return_value=mock_instance,
    ):
        await planner_node(state)

    human_content = captured[1].content
    assert "headers" in human_content
    assert "/admin" in human_content


@pytest.mark.asyncio
async def test_planner_node_without_mcp_servers():
    """Planner works with no MCP servers — it has no external deps."""
    plan = _plan_with("injection", "headers")
    state = {
        "fingerprint": MOCK_FP,
        "scope": {},
        "test_plan": [],
        "messages": [],
    }
    with patch(
        "agent.nodes.planner.ChatOpenAI",
        return_value=_mock_llm(plan),
    ):
        result = await planner_node(state)

    assert result["test_plan"] is not None
    modules = [i["module"] for i in result["test_plan"]]
    assert "injection" in modules
    assert "headers" in modules


# ── evaluate_node v2 mode tests ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_evaluate_node_v2_marks_missing_modules():
    """evaluate_node v2 mode flags modules with no tool calls."""
    from langchain_core.messages import HumanMessage, ToolMessage
    from agent.nodes.evaluate import evaluate_node

    test_plan = [
        {"module": "headers"},
        {"module": "injection"},
    ]

    # Only a headers tool call — injection is missing
    tool_msg = ToolMessage(
        content='{"vulnerable": false}',
        tool_call_id="abc",
        name="security_headers_check",
    )

    from agent.state import EvaluationResult

    not_approved = EvaluationResult(
        approved=False,
        confidence=0.6,
        feedback="injection module not executed",
        missing_steps=["injection"],
    )

    state = {
        "messages": [
            HumanMessage(content="start"),
            tool_msg,
        ],
        "test_plan": test_plan,
        "eval_attempts": 0,
        "eval_result": None,
        "findings": [],
    }

    with patch(
        "agent.nodes.evaluate._build_eval_llm"
    ) as mock_build:
        mock_evaluator = AsyncMock()
        mock_evaluator.ainvoke.return_value = not_approved
        mock_build.return_value = mock_evaluator

        result = await evaluate_node(state)

    assert result["eval_result"]["approved"] is False
    assert "injection" in result["eval_result"]["missing_steps"]
    assert "messages" in result


@pytest.mark.asyncio
async def test_evaluate_node_v2_approves_full_coverage():
    """evaluate_node v2 approves when all planned modules ran."""
    from langchain_core.messages import HumanMessage, ToolMessage
    from agent.nodes.evaluate import evaluate_node
    from agent.state import EvaluationResult

    test_plan = [{"module": "headers"}, {"module": "ratelimit"}]

    messages = [
        HumanMessage(content="start"),
        ToolMessage(
            content='{}',
            tool_call_id="1",
            name="security_headers_check",
        ),
        ToolMessage(
            content='{}',
            tool_call_id="2",
            name="rate_limit_check",
        ),
    ]

    approved = EvaluationResult(
        approved=True,
        confidence=0.95,
        feedback="All modules covered",
    )

    state = {
        "messages": messages,
        "test_plan": test_plan,
        "eval_attempts": 0,
        "eval_result": None,
        "findings": [],
    }

    with patch(
        "agent.nodes.evaluate._build_eval_llm"
    ) as mock_build:
        mock_evaluator = AsyncMock()
        mock_evaluator.ainvoke.return_value = approved
        mock_build.return_value = mock_evaluator

        result = await evaluate_node(state)

    assert result["eval_result"]["approved"] is True
    assert "messages" not in result


@pytest.mark.asyncio
async def test_evaluate_node_force_approves_after_max_retries():
    """evaluate_node force-approves after MAX_EVAL_RETRIES."""
    from agent.nodes.evaluate import evaluate_node, MAX_EVAL_RETRIES

    state = {
        "messages": [],
        "test_plan": [{"module": "headers"}],
        "eval_attempts": MAX_EVAL_RETRIES,
        "eval_result": None,
        "findings": [],
    }

    result = await evaluate_node(state)

    assert result["eval_result"]["approved"] is True
    assert result["eval_attempts"] == MAX_EVAL_RETRIES + 1
