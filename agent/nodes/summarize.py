"""Summary node — compresses the message history when it grows too large.

Why this exists
---------------
The ReAct loop accumulates one AIMessage + N ToolMessages per iteration.
After 7 protocol steps (each with a validation call) the history easily
reaches 20+ messages. Together with the system prompt this can approach
the context window of smaller models and increase cost on every iteration.

Strategy
--------
When the number of non-system messages exceeds SUMMARY_THRESHOLD:
  1. Keep the SystemMessage (index 0) and the last RECENT_KEEP messages.
  2. Ask the LLM to produce a concise factual summary of everything in
     between: which steps were completed, what tokens were obtained,
     what errors or anomalies were observed.
  3. Replace the middle portion with a single SystemMessage marked as
     "[HISTORY SUMMARY]" so the LLM understands it is condensed context.

The original full history is NOT stored — this is intentional. The
checkpointer already persists the full state to PostgreSQL after every
node, so the complete audit trail is always recoverable.
"""
from __future__ import annotations

import os
from typing import Any

from langchain_core.messages import AnyMessage, HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

from agent.logger import get_logger
from agent.state import PentestState

log = get_logger(__name__)

# Trigger summarisation when non-system messages exceed this count
SUMMARY_THRESHOLD = int(os.getenv("SUMMARY_THRESHOLD", "14"))
# Number of recent messages to keep verbatim after summarisation
RECENT_KEEP = int(os.getenv("SUMMARY_RECENT_KEEP", "6"))

_SUMMARISE_PROMPT = """\
You are summarising the work completed so far in a security testing session.
Below is the message history. Produce a concise factual summary (≤200 words) covering:
- Which authentication steps have been completed and their outcomes
- Any session tokens obtained (mention them by their first 8 chars only)
- Any errors encountered and the decisions taken
- Any anomalies detected so far
- What step should come next

Be precise. Do not invent facts. Only summarise what is explicitly present in the messages.
"""


def _build_summary_llm() -> ChatOpenAI:
    return ChatOpenAI(
        model="gpt-4o-mini",
        openai_api_base=os.getenv("LITELLM_BASE_URL", "http://localhost:4000"),
        openai_api_key=os.getenv("LITELLM_API_KEY", "sk-pentest-master"),
        temperature=0,
        max_retries=0,
    )


def _messages_to_text(messages: list[AnyMessage]) -> str:
    parts: list[str] = []
    for m in messages:
        role = getattr(m, "type", "unknown")
        content = m.content if isinstance(m.content, str) else str(m.content)
        parts.append(f"[{role.upper()}]: {content[:800]}")
    return "\n\n".join(parts)


async def summarize_node(state: PentestState) -> dict[str, Any]:
    """Compress message history when it exceeds SUMMARY_THRESHOLD.

    Replaces the middle portion of the message list with a single summary
    message. Always keeps the original SystemMessage and the most recent
    RECENT_KEEP messages verbatim.
    """
    messages: list[AnyMessage] = state["messages"]

    # Separate system prompt (always index 0) from the rest
    system_msg = messages[0] if messages and isinstance(messages[0], SystemMessage) else None
    rest = messages[1:] if system_msg else messages

    if len(rest) <= SUMMARY_THRESHOLD:
        # Nothing to do — return state unchanged (this node is a no-op)
        log.debug(
            "summarize_node.skipped",
            message_count=len(rest),
            threshold=SUMMARY_THRESHOLD,
        )
        return {}

    to_summarise = rest[:-RECENT_KEEP]
    recent = rest[-RECENT_KEEP:]

    log.info(
        "summarize_node.compressing",
        total_messages=len(messages),
        summarising=len(to_summarise),
        keeping=len(recent),
        summary_count=state.get("summary_count", 0) + 1,
    )

    llm = _build_summary_llm()
    history_text = _messages_to_text(to_summarise)
    summary_response = await llm.ainvoke([
        SystemMessage(content=_SUMMARISE_PROMPT),
        HumanMessage(content=f"Message history to summarise:\n\n{history_text}"),
    ])
    summary_text = summary_response.content

    summary_msg = SystemMessage(
        content=f"[HISTORY SUMMARY — compression #{state.get('summary_count', 0) + 1}]\n{summary_text}"
    )

    # Rebuild: system_prompt + summary + recent messages
    new_messages: list[AnyMessage] = []
    if system_msg:
        new_messages.append(system_msg)
    new_messages.append(summary_msg)
    new_messages.extend(recent)

    log.info(
        "summarize_node.done",
        original_count=len(messages),
        new_count=len(new_messages),
        summary_preview=summary_text[:120],
    )

    return {
        # Overwrite the messages list entirely (not append via add_messages)
        "messages": new_messages,
        "summary_count": state.get("summary_count", 0) + 1,
    }


def should_summarise(state: PentestState) -> str:
    """Conditional edge: returns 'summarize' or 'llm_node'."""
    messages = state.get("messages", [])
    system_count = sum(1 for m in messages if isinstance(m, SystemMessage))
    non_system = len(messages) - system_count
    if non_system > SUMMARY_THRESHOLD:
        return "summarize"
    return "llm_node"
