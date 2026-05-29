"""Unit tests for agent/nodes/evaluate.py.

Groups:
  - should_continue_after_eval() — pure routing logic, no I/O.
  - evaluate_node() — judge behaviour with mocked LLM structured output.
      - Happy path: LLM approves → state updated, no feedback injected.
      - Rejection path: LLM rejects → feedback HumanMessage appended.
      - Max retries: force-approval after MAX_EVAL_RETRIES exceeded.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from agent.nodes.evaluate import MAX_EVAL_RETRIES, should_continue_after_eval
from agent.state import EvaluationResult


# ── Helpers ───────────────────────────────────────────────────────────────────

def _base_state(**overrides) -> dict:
    state = {
        "messages": [
            SystemMessage(content="You are a pentesting agent."),
            AIMessage(content="All 8 steps completed successfully."),
        ],
        "eval_result": None,
        "eval_attempts": 0,
        "base_url": "http://test:8000",
        "username": "u",
        "current_password": "p",
        "new_password": "np",
        "thread_id": "t1",
        "session_token": None,
        "retry_count": 0,
        "step_results": [],
        "anomalies": [],
        "error": None,
        "final_status": None,
        "past_context": [],
        "drift_context": None,
        "summary_count": 0,
        "trace_id": "trace-xyz",
    }
    state.update(overrides)
    return state


def _approved_result(**kwargs) -> EvaluationResult:
    defaults = dict(
        approved=True,
        confidence=0.95,
        feedback="All 8 steps executed with evidence.",
        missing_steps=[],
        unsupported_anomalies=[],
        suggested_actions=[],
    )
    defaults.update(kwargs)
    return EvaluationResult(**defaults)


def _rejected_result(**kwargs) -> EvaluationResult:
    defaults = dict(
        approved=False,
        confidence=0.4,
        feedback="Missing validate_logout step.",
        missing_steps=["validate_logout"],
        unsupported_anomalies=[],
        suggested_actions=["Execute GET /me after POST /logout to confirm 401."],
    )
    defaults.update(kwargs)
    return EvaluationResult(**defaults)


def _mock_evaluator(return_value: EvaluationResult) -> MagicMock:
    """Mock the structured-output LLM returned by _build_eval_llm()."""
    evaluator = MagicMock()
    evaluator.ainvoke = AsyncMock(return_value=return_value)
    return evaluator


# ── should_continue_after_eval — routing ─────────────────────────────────────

def test_routing_approved_goes_to_report():
    state = _base_state(
        eval_result={"approved": True, "confidence": 0.9, "feedback": "ok",
                     "missing_steps": [], "unsupported_anomalies": [],
                     "suggested_actions": []},
        eval_attempts=1,
    )
    assert should_continue_after_eval(state) == "report_node"


def test_routing_rejected_goes_to_llm_when_retries_remain():
    state = _base_state(
        eval_result={"approved": False, "confidence": 0.3, "feedback": "bad",
                     "missing_steps": ["validate_logout"], "unsupported_anomalies": [],
                     "suggested_actions": []},
        eval_attempts=1,  # < MAX_EVAL_RETRIES (2)
    )
    assert should_continue_after_eval(state) == "llm_node"


def test_routing_rejected_at_max_retries_goes_to_report():
    state = _base_state(
        eval_result={"approved": False, "confidence": 0.3, "feedback": "bad",
                     "missing_steps": ["validate_logout"], "unsupported_anomalies": [],
                     "suggested_actions": []},
        eval_attempts=MAX_EVAL_RETRIES,
    )
    assert should_continue_after_eval(state) == "report_node"


def test_routing_no_eval_result_goes_to_report():
    state = _base_state(eval_result=None, eval_attempts=0)
    assert should_continue_after_eval(state) == "report_node"


# ── evaluate_node — approved path ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_evaluate_node_approved_updates_state():
    from agent.nodes.evaluate import evaluate_node

    approved = _approved_result()
    mock_evaluator = _mock_evaluator(approved)

    with patch("agent.nodes.evaluate._build_eval_llm", return_value=mock_evaluator):
        result = await evaluate_node(_base_state())

    assert result["eval_result"]["approved"] is True
    assert result["eval_result"]["confidence"] == 0.95
    assert result["eval_attempts"] == 1
    # No feedback message appended when approved
    assert "messages" not in result


@pytest.mark.asyncio
async def test_evaluate_node_approved_confidence_stored():
    from agent.nodes.evaluate import evaluate_node

    approved = _approved_result(confidence=0.87)
    mock_evaluator = _mock_evaluator(approved)

    with patch("agent.nodes.evaluate._build_eval_llm", return_value=mock_evaluator):
        result = await evaluate_node(_base_state())

    assert abs(result["eval_result"]["confidence"] - 0.87) < 0.001


# ── evaluate_node — rejection + feedback path ─────────────────────────────────

@pytest.mark.asyncio
async def test_evaluate_node_rejected_injects_feedback_message():
    from agent.nodes.evaluate import evaluate_node

    rejected = _rejected_result()
    mock_evaluator = _mock_evaluator(rejected)

    with patch("agent.nodes.evaluate._build_eval_llm", return_value=mock_evaluator):
        result = await evaluate_node(_base_state())

    assert result["eval_result"]["approved"] is False
    assert result["eval_attempts"] == 1
    # A HumanMessage with feedback must be appended
    assert "messages" in result
    assert len(result["messages"]) == 1
    msg = result["messages"][0]
    assert isinstance(msg, HumanMessage)
    assert "validate_logout" in msg.content
    assert "EVALUATION FEEDBACK" in msg.content


@pytest.mark.asyncio
async def test_evaluate_node_feedback_contains_suggested_actions():
    from agent.nodes.evaluate import evaluate_node

    rejected = _rejected_result(
        suggested_actions=["Re-run POST /logout", "Check /me returns 401"]
    )
    mock_evaluator = _mock_evaluator(rejected)

    with patch("agent.nodes.evaluate._build_eval_llm", return_value=mock_evaluator):
        result = await evaluate_node(_base_state())

    feedback = result["messages"][0].content
    assert "Re-run POST /logout" in feedback
    assert "Check /me returns 401" in feedback


@pytest.mark.asyncio
async def test_evaluate_node_rejected_unsupported_anomaly_in_feedback():
    from agent.nodes.evaluate import evaluate_node

    rejected = _rejected_result(
        unsupported_anomalies=["token_not_rotated"],
        missing_steps=[],
    )
    mock_evaluator = _mock_evaluator(rejected)

    with patch("agent.nodes.evaluate._build_eval_llm", return_value=mock_evaluator):
        result = await evaluate_node(_base_state())

    feedback = result["messages"][0].content
    assert "token_not_rotated" in feedback


# ── evaluate_node — max retries force-approve ─────────────────────────────────

@pytest.mark.asyncio
async def test_evaluate_node_force_approves_after_max_retries():
    """After MAX_EVAL_RETRIES, the node force-approves without calling the LLM."""
    from agent.nodes.evaluate import evaluate_node

    # eval_attempts already at MAX_EVAL_RETRIES → skip LLM call
    state = _base_state(
        eval_attempts=MAX_EVAL_RETRIES,
        eval_result={"approved": False, "confidence": 0.2, "feedback": "issues",
                     "missing_steps": ["validate_logout"], "unsupported_anomalies": [],
                     "suggested_actions": []},
    )

    mock_build = MagicMock()

    with patch("agent.nodes.evaluate._build_eval_llm", mock_build):
        result = await evaluate_node(state)

    mock_build.assert_not_called()

    # Force-approve with confidence 0.5
    assert result["eval_result"]["approved"] is True
    assert result["eval_result"]["confidence"] == 0.5
    assert "Forced approval" in result["eval_result"]["feedback"]
    assert result["eval_attempts"] == MAX_EVAL_RETRIES + 1


@pytest.mark.asyncio
async def test_evaluate_node_force_approve_does_not_inject_messages():
    """Force-approve path should not inject any feedback messages."""
    from agent.nodes.evaluate import evaluate_node

    state = _base_state(eval_attempts=MAX_EVAL_RETRIES)

    with patch("agent.nodes.evaluate._build_eval_llm") as mock_build:
        result = await evaluate_node(state)

    mock_build.assert_not_called()

    assert "messages" not in result


# ── evaluate_node — attempt counter ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_evaluate_node_increments_attempts_each_call():
    """eval_attempts must increment on each invocation."""
    from agent.nodes.evaluate import evaluate_node

    approved = _approved_result()
    mock_evaluator = _mock_evaluator(approved)

    with patch("agent.nodes.evaluate._build_eval_llm", return_value=mock_evaluator):
        # First call
        r1 = await evaluate_node(_base_state(eval_attempts=0))
        assert r1["eval_attempts"] == 1

        # Second call (simulating a retry)
        r2 = await evaluate_node(_base_state(eval_attempts=1))
        assert r2["eval_attempts"] == 2
