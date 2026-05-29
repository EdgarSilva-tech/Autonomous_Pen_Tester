"""Evaluation node — validates the agent's conclusions before the report is emitted.

Why this exists
---------------
The ReAct agent may:
  - Skip a validation step (e.g. omit the POST-logout /me check)
  - Claim an anomaly without sufficient HTTP evidence
  - Mislabel a step status due to ambiguous tool output
  - Stop early when the protocol is not yet complete

The evaluation node acts as an independent judge: it re-reads the full
conversation and checks every claim against the evidence. If it finds
problems, it injects structured feedback as a HumanMessage and returns
control to the LLM node for a corrective pass — up to MAX_EVAL_RETRIES.

Design
------
  - Uses the same LLM (GPT-4o-mini via LiteLLM) with a different system
    prompt, so there is no additional model dependency.
  - Uses with_structured_output(EvaluationResult) for deterministic output.
  - The feedback injected back to the LLM is precise: it names the missing
    steps and unsupported anomalies so the LLM knows exactly what to fix.
  - After MAX_EVAL_RETRIES the node approves anyway to avoid infinite loops,
    recording the outstanding issues in the EvaluationResult for the report.
"""
from __future__ import annotations

import json
import os
from typing import Any

from langchain_core.messages import AnyMessage, HumanMessage, SystemMessage, ToolMessage

from agent.logger import get_logger
from agent.state import EvaluationResult, PentestState

log = get_logger(__name__)

MAX_EVAL_RETRIES = int(os.getenv("MAX_EVAL_RETRIES", "2"))

# Ordered exactly as the protocol executes them
_REQUIRED_STEPS = [
    "login",
    "validate_login",
    "change_password",
    "validate_session_invalidation",
    "re-authenticate",
    "validate_reauth",
    "logout",
    "validate_logout",
]

# Maps tool name → ordered list of protocol step names (by invocation index)
_TOOL_STEP_SEQUENCES: dict[str, list[str]] = {
    "login_tool": ["login", "re-authenticate"],
    "me_tool": [
        "validate_login",
        "validate_session_invalidation",
        "validate_reauth",
        "validate_logout",
    ],
    "change_password_tool": ["change_password"],
    "logout_tool": ["logout"],
}

# Expected HTTP status per step.  401 is the CORRECT outcome for validation
# steps that confirm session/token invalidation.
_EXPECTED_STATUS: dict[str, int] = {
    "login": 200,
    "validate_login": 200,
    "change_password": 200,
    "validate_session_invalidation": 401,
    "re-authenticate": 200,
    "validate_reauth": 200,
    "logout": 200,
    "validate_logout": 401,
}

_EVAL_SYSTEM_PROMPT = """\
You are an independent security test evaluator. Your job is to review a
completed authentication lifecycle test and decide whether all required steps
were executed correctly.

## Protocol steps and EXPECTED HTTP status (in execution order)

| # | Step name                      | Expected HTTP | Pass condition               |
|---|-------------------------------|---------------|------------------------------|
| 1 | login                         | 200           | token received               |
| 2 | validate_login                | 200           | correct username returned    |
| 3 | change_password               | 200           | password changed             |
| 4 | validate_session_invalidation | 401           | OLD token rejected (CORRECT) |
| 5 | re-authenticate               | 200           | new token received           |
| 6 | validate_reauth               | 200           | correct username returned    |
| 7 | logout                        | 200           | session removed              |
| 8 | validate_logout               | 401           | new token rejected (CORRECT) |

IMPORTANT: HTTP 401 for steps 4 and 8 is the CORRECT and EXPECTED result.
A step labelled "CORRECT" in the summary has passed, regardless of whether
the HTTP status is 200 or 401.  Only mark a step as missing if it shows
"WRONG" outcome or is entirely absent from the summary.

## What to check
1. **Completeness** — Are ALL 8 steps present and CORRECT in the summary?
2. **Anomaly evidence** — For each anomaly claimed, is there HTTP evidence?
3. **Consistency** — Does the observed HTTP status match the table above?

You will receive a structured summary of executed steps derived directly from
tool call evidence — treat it as the ground truth.

## Output
Return approved=true if all 8 required steps are present with CORRECT
outcomes. Otherwise set approved=false and list only steps that are absent
or show WRONG outcomes in missing_steps.
"""


def _build_eval_llm():
    from langchain_openai import ChatOpenAI  # local import to avoid circular
    llm = ChatOpenAI(
        model="gpt-4o-mini",
        openai_api_base=os.getenv("LITELLM_BASE_URL", "http://localhost:4000"),
        openai_api_key=os.getenv("LITELLM_API_KEY", "sk-pentest-master"),
        temperature=0,
        max_retries=0,
    )
    return llm.with_structured_output(EvaluationResult)


def _build_step_summary(messages: list[AnyMessage]) -> str:
    """Build a structured step summary from ToolMessages for the evaluator.

    Instead of asking the LLM to parse raw conversation text (which misses
    tool call arguments because AIMessage.content is empty for tool-call
    turns), we reconstruct the step sequence directly from the ToolMessages
    using the known invocation order for each tool.
    """
    counters: dict[str, int] = {k: 0 for k in _TOOL_STEP_SEQUENCES}
    lines = ["EXECUTED STEPS (derived from tool call evidence):"]

    for msg in messages:
        if not isinstance(msg, ToolMessage):
            continue
        tool_name = getattr(msg, "name", "")
        if tool_name not in _TOOL_STEP_SEQUENCES:
            continue

        try:
            raw = msg.content
            data: dict[str, Any] = json.loads(raw) if isinstance(raw, str) else (raw if isinstance(raw, dict) else {})
        except Exception:
            data = {}

        idx = counters[tool_name]
        step_names = _TOOL_STEP_SEQUENCES[tool_name]
        step_name = step_names[idx] if idx < len(step_names) else f"{tool_name}[{idx}]"
        counters[tool_name] += 1

        http_status = data.get("http_status")
        expected = _EXPECTED_STATUS.get(step_name, 200)
        correct = http_status == expected
        body = str(data.get("body", ""))[:300]
        outcome = "CORRECT" if correct else "WRONG"
        lines.append(
            f"  [{step_name}] HTTP {http_status} "
            f"({outcome}, expected {expected}) | {body}"
        )

    if len(lines) == 1:
        lines.append("  (no tool calls found — the agent did not execute any steps)")

    return "\n".join(lines)


def _feedback_message(result: EvaluationResult) -> HumanMessage:
    lines = [
        "EVALUATION FEEDBACK — please address the following before concluding:",
        f"Confidence: {result.confidence:.0%}",
    ]
    if result.missing_steps:
        lines.append(f"Missing/incomplete steps: {', '.join(result.missing_steps)}")
        lines.append("Please execute or re-validate these steps now.")
    if result.unsupported_anomalies:
        lines.append(
            f"Anomalies claimed without sufficient evidence: {', '.join(result.unsupported_anomalies)}"
        )
        lines.append(
            "Either provide the HTTP evidence or remove the anomaly from your conclusions."
        )
    if result.suggested_actions:
        lines.append("Suggested actions:")
        for action in result.suggested_actions:
            lines.append(f"  - {action}")
    lines.append(
        "\nAfter completing the above, summarise all steps and anomalies for the final report."
    )
    return HumanMessage(content="\n".join(lines))


async def evaluate_node(state: PentestState) -> dict[str, Any]:
    """Run the independent evaluator on the current conversation.

    Returns updated state with the EvaluationResult and, if not approved,
    a feedback HumanMessage appended to messages for the next LLM pass.
    """
    attempt = state.get("eval_attempts", 0) + 1
    messages: list[AnyMessage] = state["messages"]

    log.info("evaluate_node.start", attempt=attempt, max=MAX_EVAL_RETRIES)

    # Force-approve if we have exhausted retries to avoid infinite loops
    if attempt > MAX_EVAL_RETRIES:
        log.warning(
            "evaluate_node.max_retries_reached",
            attempt=attempt,
            max=MAX_EVAL_RETRIES,
        )
        forced = EvaluationResult(
            approved=True,
            confidence=0.5,
            feedback=(
                f"Forced approval after {MAX_EVAL_RETRIES} evaluation attempts. "
                "Outstanding issues may remain."
            ),
        )
        return {
            "eval_result": forced.model_dump(),
            "eval_attempts": attempt,
        }

    evaluator = _build_eval_llm()
    step_summary = _build_step_summary(messages)

    result: EvaluationResult = await evaluator.ainvoke([
        SystemMessage(content=_EVAL_SYSTEM_PROMPT),
        HumanMessage(
            content=(
                f"{step_summary}\n\n"
                "Based on the executed steps above, provide your structured evaluation now."
            )
        ),
    ])

    log.info(
        "evaluate_node.result",
        approved=result.approved,
        confidence=result.confidence,
        missing_steps=result.missing_steps,
        unsupported_anomalies=result.unsupported_anomalies,
        attempt=attempt,
    )

    updates: dict[str, Any] = {
        "eval_result": result.model_dump(),
        "eval_attempts": attempt,
    }

    # If not approved, append feedback so the LLM can correct itself
    if not result.approved:
        updates["messages"] = [_feedback_message(result)]

    return updates


def should_continue_after_eval(state: PentestState) -> str:
    """Conditional edge after evaluate_node.

    Returns 'llm_node' for a corrective pass, or 'report_node' to finalise.
    """
    result_dict = state.get("eval_result")
    attempt = state.get("eval_attempts", 0)

    if result_dict is None:
        return "report_node"

    approved = result_dict.get("approved", True)
    if approved or attempt >= MAX_EVAL_RETRIES:
        return "report_node"
    return "llm_node"
