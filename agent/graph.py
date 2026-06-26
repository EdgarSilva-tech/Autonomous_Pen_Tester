"""LangGraph graph definition for the Autonomous Pentesting Agent.

Graph topology (Phase 4):

  START
    |
    v
  planner_node  (LLM: fingerprint + scope -> test_plan)
    |
    v
  llm_node  <──────────────────────────────────────────┐
    |                                                   |
    +-- tool_calls? --> tools_node                      |  (ReAct loop)
    |                       |                           |
    |             should_summarise?                     |
    |                  |       |                        |
    |             summarize  llm_node ──────────────────┘
    |             _node
    |
    +-- no tool_calls --> evaluate_node
                               |
                     should_continue_after_eval?
                          |              |
                      llm_node        report_node
                    (corrective          |
                       pass)           END

Nodes
-----
  planner_node    — calls LLM; reads fingerprint+scope -> writes test_plan
  llm_node        — calls the executor LLM; produces tool calls or final answer
  tools_node      — executes all tool calls in the latest AIMessage
  summarize_node  — compresses old message history to control context size
  evaluate_node   — independent judge: validates completeness and evidence
  report_node     — assembles and emits the final JSON report
"""
from __future__ import annotations

import os
import time
from typing import Any

from langchain_core.messages import AIMessage, SystemMessage
from langchain_core.tools import BaseTool
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode

from agent.logger import get_logger
from agent.mcp_client import get_mcp_tools
from agent.nodes.evaluate import evaluate_node, should_continue_after_eval
from agent.nodes.planner import planner_node
from agent.nodes.summarize import should_summarise, summarize_node
from agent.prompts import build_system_prompt
from agent.report import assemble_report, emit_report
from agent.state import PentestState
from agent.tools import HTTP_TOOLS, reset_session, set_base_url

log = get_logger(__name__)


# ── LLM factory ──────────────────────────────────────────────────────────────

def _build_llm(tools: list[BaseTool]) -> ChatOpenAI:
    """Return an LLM bound to tool schemas, routed via LiteLLM proxy."""
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
    return llm.bind_tools(tools)


# ── Checkpointer ─────────────────────────────────────────────────────────────

async def _get_checkpointer():
    db_uri = os.getenv("LANGGRAPH_DB_URI")
    if not db_uri:
        log.warning(
            "graph.checkpointer_disabled",
            reason="LANGGRAPH_DB_URI not set",
        )
        return None
    try:
        from psycopg_pool import AsyncConnectionPool  # type: ignore
        from langgraph.checkpoint.postgres.aio import (  # type: ignore
            AsyncPostgresSaver,
        )

        psycopg_uri = db_uri.replace(
            "postgresql+asyncpg://", "postgresql://"
        )
        pool = AsyncConnectionPool(
            conninfo=psycopg_uri,
            kwargs={"autocommit": True},
            open=False,
        )
        await pool.open()
        checkpointer = AsyncPostgresSaver(pool)
        await checkpointer.setup()
        log.info(
            "graph.checkpointer_ready",
            uri=db_uri.split("@")[-1],
        )
        return checkpointer
    except Exception as exc:
        log.warning("graph.checkpointer_failed", error=str(exc))
        return None


# ── Node: llm_node (executor) ────────────────────────────────────────────────

def _make_llm_node(llm_with_tools):
    """Return the llm_node function closed over the bound LLM."""

    async def llm_node(state: PentestState) -> dict[str, Any]:
        messages = state["messages"]

        if not messages or not isinstance(messages[0], SystemMessage):
            system_prompt = build_system_prompt(
                username=state.get("username", ""),
                current_password=state.get("current_password", ""),
                new_password=state.get("new_password", ""),
                past_context=state.get("past_context", []),
                drift_context=state.get("drift_context"),
                openapi_context=state.get("openapi_context"),
                fingerprint=state.get("fingerprint"),
                test_plan=state.get("test_plan"),
                scope=state.get("scope"),
            )
            messages = (
                [SystemMessage(content=system_prompt)] + list(messages)
            )

        log.debug("llm_node.invoke", message_count=len(messages))
        response: AIMessage = await llm_with_tools.ainvoke(messages)
        log.info(
            "llm_node.response",
            has_tool_calls=bool(
                getattr(response, "tool_calls", None)
            ),
            tool_names=[
                tc["name"] for tc in (response.tool_calls or [])
            ],
        )
        return {"messages": [response]}

    return llm_node


# ── Edge: after llm_node ─────────────────────────────────────────────────────

def route_after_llm(state: PentestState) -> str:
    """Route to tools_node on tool calls; else to evaluate_node."""
    last = state["messages"][-1]
    if isinstance(last, AIMessage) and getattr(
        last, "tool_calls", None
    ):
        return "tools_node"
    return "evaluate_node"


# ── Node: report_node ────────────────────────────────────────────────────────

_start_time: float = 0.0


async def report_node(state: PentestState) -> dict[str, Any]:
    elapsed_ms = int((time.monotonic() - _start_time) * 1000)
    report = assemble_report(state, elapsed_ms=elapsed_ms)

    if state.get("eval_result"):
        from agent.state import EvaluationResult
        report.evaluation = EvaluationResult(**state["eval_result"])

    emit_report(report)
    return {"final_status": report.status}


# ── Graph builder ─────────────────────────────────────────────────────────────

async def build_graph():
    """Assemble and compile the full LangGraph StateGraph."""
    global _start_time
    _start_time = time.monotonic()

    set_base_url(os.getenv("TARGET_BASE_URL", "http://localhost:8000"))
    reset_session()

    mcp_tools = await get_mcp_tools()
    all_tools: list[BaseTool] = HTTP_TOOLS + mcp_tools

    log.info(
        "graph.tools_registered",
        http=len(HTTP_TOOLS),
        mcp=len(mcp_tools),
        total=len(all_tools),
    )

    llm_with_tools = _build_llm(all_tools)
    checkpointer = await _get_checkpointer()

    graph = StateGraph(PentestState)

    # ── Register nodes ───────────────────────────────────────────────────────
    graph.add_node("planner_node",    planner_node)
    graph.add_node("llm_node",        _make_llm_node(llm_with_tools))
    graph.add_node("tools_node",      ToolNode(all_tools))
    graph.add_node("summarize_node",  summarize_node)
    graph.add_node("evaluate_node",   evaluate_node)
    graph.add_node("report_node",     report_node)

    # ── Edges ───────────────────────────────────────────────────────────────
    graph.add_edge(START, "planner_node")
    graph.add_edge("planner_node", "llm_node")

    graph.add_conditional_edges(
        "llm_node",
        route_after_llm,
        {
            "tools_node": "tools_node",
            "evaluate_node": "evaluate_node",
        },
    )

    graph.add_conditional_edges(
        "tools_node",
        should_summarise,
        {"summarize": "summarize_node", "llm_node": "llm_node"},
    )

    graph.add_edge("summarize_node", "llm_node")

    graph.add_conditional_edges(
        "evaluate_node",
        should_continue_after_eval,
        {"llm_node": "llm_node", "report_node": "report_node"},
    )

    graph.add_edge("report_node", END)

    return graph.compile(checkpointer=checkpointer)
