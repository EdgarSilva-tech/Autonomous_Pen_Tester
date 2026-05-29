"""Unit tests for agent/nodes/summarize.py.

Groups:
  - should_summarise() — pure conditional logic, no I/O.
  - summarize_node() — message compression with a mocked LLM.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from agent.nodes.summarize import RECENT_KEEP, SUMMARY_THRESHOLD, should_summarise


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_state(messages: list) -> dict:
    return {
        "messages": messages,
        "summary_count": 0,
        # Required PentestState fields (unused in these nodes)
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
        "eval_result": None,
        "eval_attempts": 0,
        "trace_id": "trace-abc",
    }


def _system() -> SystemMessage:
    return SystemMessage(content="You are a pentesting agent.")


def _human(text: str = "test") -> HumanMessage:
    return HumanMessage(content=text)


def _ai(text: str = "reasoning") -> AIMessage:
    return AIMessage(content=text)


def _tool(text: str = "result") -> ToolMessage:
    return ToolMessage(content=text, tool_call_id="call_1")


def _conversation(n_pairs: int) -> list:
    """System prompt + n_pairs of (AIMessage, ToolMessage)."""
    msgs = [_system()]
    for i in range(n_pairs):
        msgs.append(_ai(f"Thinking about step {i}"))
        msgs.append(_tool(f"Tool result {i}"))
    return msgs


# ── should_summarise — routing logic ─────────────────────────────────────────

def test_should_summarise_below_threshold_routes_to_llm():
    # 5 non-system messages (well below default threshold of 14)
    msgs = [_system()] + [_ai(), _tool()] * 2 + [_ai()]
    state = _make_state(msgs)
    assert should_summarise(state) == "llm_node"


def test_should_summarise_at_threshold_routes_to_llm():
    # Exactly at SUMMARY_THRESHOLD — should NOT trigger
    msgs = [_system()] + [_ai(), _tool()] * (SUMMARY_THRESHOLD // 2)
    state = _make_state(msgs)
    non_system = len(msgs) - 1  # one SystemMessage
    assert non_system == SUMMARY_THRESHOLD
    assert should_summarise(state) == "llm_node"


def test_should_summarise_above_threshold_routes_to_summarize():
    # One message over the threshold
    msgs = _conversation(n_pairs=(SUMMARY_THRESHOLD // 2) + 1)
    state = _make_state(msgs)
    assert should_summarise(state) == "summarize"


def test_should_summarise_no_messages_routes_to_llm():
    state = _make_state([])
    assert should_summarise(state) == "llm_node"


def test_should_summarise_only_system_message_routes_to_llm():
    state = _make_state([_system()])
    assert should_summarise(state) == "llm_node"


def test_should_summarise_multiple_system_messages_counted_correctly():
    """Summary messages ([HISTORY SUMMARY]) are SystemMessages — they should
    not count toward the non-system threshold."""
    summary_msg = SystemMessage(content="[HISTORY SUMMARY #1] login completed")
    # 4 real SystemMessages + 5 non-system messages = well below threshold
    msgs = [_system(), summary_msg] + [_ai(), _tool()] * 2 + [_ai()]
    state = _make_state(msgs)
    assert should_summarise(state) == "llm_node"


# ── summarize_node — message compression ─────────────────────────────────────

@pytest.mark.asyncio
async def test_summarize_node_below_threshold_is_noop():
    """When messages are below threshold, summarize_node returns {} (no-op)."""
    from agent.nodes.summarize import summarize_node

    msgs = [_system()] + [_ai(), _tool()] * 3
    state = _make_state(msgs)
    result = await summarize_node(state)
    assert result == {}


@pytest.mark.asyncio
async def test_summarize_node_compresses_messages():
    """Above threshold: summarize_node should replace middle messages with a summary."""
    from agent.nodes.summarize import summarize_node

    # Build a message list well above threshold
    msgs = _conversation(n_pairs=SUMMARY_THRESHOLD)
    original_count = len(msgs)
    state = _make_state(msgs)

    mock_llm = MagicMock()
    mock_llm.ainvoke = AsyncMock(
        return_value=AIMessage(content="Summary: login and validate_login completed.")
    )

    with patch("agent.nodes.summarize._build_summary_llm", return_value=mock_llm):
        result = await summarize_node(state)

    assert "messages" in result
    new_messages = result["messages"]

    # New list must be shorter than original
    assert len(new_messages) < original_count

    # System prompt must be first
    assert isinstance(new_messages[0], SystemMessage)

    # A summary SystemMessage must be present
    summary_msgs = [
        m for m in new_messages
        if isinstance(m, SystemMessage) and "HISTORY SUMMARY" in m.content
    ]
    assert len(summary_msgs) == 1

    # The last RECENT_KEEP messages must be preserved verbatim
    original_recent = msgs[-RECENT_KEEP:]
    new_recent = new_messages[-RECENT_KEEP:]
    for orig, new in zip(original_recent, new_recent):
        assert orig.content == new.content

    # summary_count must be incremented
    assert result["summary_count"] == 1


@pytest.mark.asyncio
async def test_summarize_node_increments_summary_count():
    """summary_count should increment on each call."""
    from agent.nodes.summarize import summarize_node

    msgs = _conversation(n_pairs=SUMMARY_THRESHOLD)
    state = _make_state(msgs)
    state["summary_count"] = 2  # simulate previous compressions

    mock_llm = MagicMock()
    mock_llm.ainvoke = AsyncMock(
        return_value=AIMessage(content="Second summary.")
    )

    with patch("agent.nodes.summarize._build_summary_llm", return_value=mock_llm):
        result = await summarize_node(state)

    assert result["summary_count"] == 3

    # Summary message should reflect correct compression number
    summary_msgs = [
        m for m in result["messages"]
        if isinstance(m, SystemMessage) and "HISTORY SUMMARY" in m.content
    ]
    assert "#3" in summary_msgs[0].content


@pytest.mark.asyncio
async def test_summarize_node_preserves_system_prompt():
    """The original system prompt (index 0) must always be first after compression."""
    from agent.nodes.summarize import summarize_node

    system_content = "You are a pentesting agent. [UNIQUE MARKER]"
    msgs = [SystemMessage(content=system_content)] + [_ai(), _tool()] * SUMMARY_THRESHOLD
    state = _make_state(msgs)

    mock_llm = MagicMock()
    mock_llm.ainvoke = AsyncMock(return_value=AIMessage(content="summary text"))

    with patch("agent.nodes.summarize._build_summary_llm", return_value=mock_llm):
        result = await summarize_node(state)

    assert result["messages"][0].content == system_content
