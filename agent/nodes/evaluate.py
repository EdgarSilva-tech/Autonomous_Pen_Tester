"""Evaluation node — validates agent conclusions before report."""
from __future__ import annotations

import json
import os
from typing import Any

from langchain_core.messages import (
    AnyMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)

from agent.logger import get_logger
from agent.state import EvaluationResult, PentestState

log = get_logger(__name__)

MAX_EVAL_RETRIES = int(os.getenv("MAX_EVAL_RETRIES", "2"))


# v1 (legacy auth) ────────────────────────────────────────────────────────────

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


# v2 (module-based) ───────────────────────────────────────────────────────────

_TOOL_TO_MODULE: dict[str, str] = {
    "login_tool": "auth",
    "me_tool": "auth",
    "change_password_tool": "auth",
    "logout_tool": "auth",
    "jwt_analyze": "auth",
    "brute_force_check": "auth",
    "session_fixation_check": "auth",
    "token_entropy_check": "auth",
    "sqli_probe": "injection",
    "nosql_probe": "injection",
    "ssti_probe": "injection",
    "xss_probe": "injection",
    "idor_probe": "access",
    "bola_probe": "access",
    "privilege_escalation_check": "access",
    "cors_check": "headers",
    "security_headers_check": "headers",
    "csp_check": "headers",
    "error_disclosure_probe": "disclosure",
    "pii_scan": "disclosure",
    "path_traversal_probe": "disclosure",
    "http_methods_check": "disclosure",
    "rate_limit_check": "ratelimit",
    "ip_bypass_check": "ratelimit",
}


# Evaluator LLM ───────────────────────────────────────────────────────────────

_V1_EVAL_PROMPT = """\
You are an independent security test evaluator. Review a completed
authentication lifecycle test and decide whether all 8 required steps
were executed correctly.

## Required steps and expected HTTP status

1. login                          HTTP 200  (token received)
2. validate_login                 HTTP 200  (username returned)
3. change_password                HTTP 200  (password changed)
4. validate_session_invalidation  HTTP 401  (OLD token rejected)
5. re-authenticate                HTTP 200  (new token received)
6. validate_reauth                HTTP 200  (username returned)
7. logout                         HTTP 200  (session removed)
8. validate_logout                HTTP 401  (new token rejected)

HTTP 401 for steps 4 and 8 is the CORRECT and EXPECTED result.
A step labelled "CORRECT" has passed regardless of 200 or 401.
Only mark a step missing if it shows "WRONG" outcome or is absent.

Return approved=true if all 8 steps are present with CORRECT outcomes.
"""

_V2_EVAL_PROMPT = """\
You are an independent security test evaluator. Review a completed
web security scan and decide whether all planned modules were tested.

A module is "executed" if at least one of its tools was called.

Return approved=true when every planned module has been executed.
List unexecuted modules in missing_steps (one entry per module name).
Set confidence based on how thoroughly each module was covered.
"""


def _build_eval_llm() -> Any:
    from langchain_openai import ChatOpenAI
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
    return llm.with_structured_output(EvaluationResult)


# v1 helpers ──────────────────────────────────────────────────────────────────

def _build_step_summary(messages: list[AnyMessage]) -> str:
    """Reconstruct auth step sequence from ToolMessages."""
    counters: dict[str, int] = {
        k: 0 for k in _TOOL_STEP_SEQUENCES
    }
    lines = ["EXECUTED STEPS (from tool call evidence):"]

    for msg in messages:
        if not isinstance(msg, ToolMessage):
            continue
        tool_name = getattr(msg, "name", "")
        if tool_name not in _TOOL_STEP_SEQUENCES:
            continue

        try:
            raw = msg.content
            if isinstance(raw, str):
                data: dict[str, Any] = json.loads(raw)
            elif isinstance(raw, dict):
                data = raw
            else:
                data = {}
        except Exception:
            data = {}

        idx = counters[tool_name]
        step_names = _TOOL_STEP_SEQUENCES[tool_name]
        if idx < len(step_names):
            step_name = step_names[idx]
        else:
            step_name = f"{tool_name}[{idx}]"
        counters[tool_name] += 1

        http_status = data.get("http_status")
        expected = _EXPECTED_STATUS.get(step_name, 200)
        correct = http_status == expected
        body = str(data.get("body", ""))[:200]
        outcome = "CORRECT" if correct else "WRONG"
        lines.append(
            f"  [{step_name}] HTTP {http_status} "
            f"({outcome}, expected {expected}) | {body}"
        )

    if len(lines) == 1:
        lines.append(
            "  (no tool calls found — agent executed no steps)"
        )

    return "\n".join(lines)


# v2 helpers ──────────────────────────────────────────────────────────────────

def _build_module_summary(
    messages: list[AnyMessage],
    test_plan: list[dict[str, Any]],
) -> str:
    """Summarise which planned modules had tool calls."""
    planned = {item["module"] for item in test_plan}
    executed: set[str] = set()

    for msg in messages:
        if not isinstance(msg, ToolMessage):
            continue
        tool_name = getattr(msg, "name", "")
        module = _TOOL_TO_MODULE.get(tool_name)
        if module and module in planned:
            executed.add(module)

    lines = ["MODULE COVERAGE:"]
    for module in sorted(planned):
        status = "DONE" if module in executed else "MISSING"
        lines.append(f"  {module}: {status}")

    missing = sorted(planned - executed)
    if missing:
        lines.append(f"Unexecuted: {', '.join(missing)}")
    else:
        lines.append("All planned modules were executed.")

    return "\n".join(lines)


# Feedback message ────────────────────────────────────────────────────────────

def _feedback_message(result: EvaluationResult) -> HumanMessage:
    lines = [
        "EVALUATION FEEDBACK — address before concluding:",
        f"Confidence: {result.confidence:.0%}",
    ]
    if result.missing_steps:
        missing = ", ".join(result.missing_steps)
        lines.append(f"Missing/incomplete: {missing}")
        lines.append("Execute or re-validate these now.")
    if result.unsupported_anomalies:
        unsup = ", ".join(result.unsupported_anomalies)
        lines.append(f"Anomalies without evidence: {unsup}")
        lines.append(
            "Provide HTTP evidence or remove the anomaly."
        )
    if result.suggested_actions:
        lines.append("Suggested actions:")
        for action in result.suggested_actions:
            lines.append(f"  - {action}")
    lines.append(
        "\nAfter completing the above, summarise findings."
    )
    return HumanMessage(content="\n".join(lines))


# evaluate_node ───────────────────────────────────────────────────────────────

async def evaluate_node(state: PentestState) -> dict[str, Any]:
    """Run the independent evaluator on the current conversation."""
    attempt = state.get("eval_attempts", 0) + 1
    messages: list[AnyMessage] = state["messages"]
    test_plan: list[dict[str, Any]] = state.get("test_plan") or []

    log.info(
        "evaluate_node.start",
        attempt=attempt,
        max=MAX_EVAL_RETRIES,
        mode="v2" if test_plan else "v1",
    )

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
                f"Forced approval after {MAX_EVAL_RETRIES} "
                "attempts. Outstanding issues may remain."
            ),
        )
        return {
            "eval_result": forced.model_dump(),
            "eval_attempts": attempt,
        }

    evaluator = _build_eval_llm()

    if test_plan:
        sys_prompt = _V2_EVAL_PROMPT
        summary = _build_module_summary(messages, test_plan)
    else:
        sys_prompt = _V1_EVAL_PROMPT
        summary = _build_step_summary(messages)

    result: EvaluationResult = await evaluator.ainvoke([
        SystemMessage(content=sys_prompt),
        HumanMessage(
            content=(
                f"{summary}\n\n"
                "Based on the summary above, provide your evaluation."
            )
        ),
    ])

    log.info(
        "evaluate_node.result",
        approved=result.approved,
        confidence=result.confidence,
        missing=result.missing_steps,
        attempt=attempt,
    )

    updates: dict[str, Any] = {
        "eval_result": result.model_dump(),
        "eval_attempts": attempt,
    }

    if not result.approved:
        updates["messages"] = [_feedback_message(result)]

    return updates


# should_continue_after_eval ──────────────────────────────────────────────────

def should_continue_after_eval(state: PentestState) -> str:
    """Conditional edge: corrective LLM pass or finalise report."""
    result_dict = state.get("eval_result")
    attempt = state.get("eval_attempts", 0)

    if result_dict is None:
        return "report_node"

    approved = result_dict.get("approved", True)
    if approved or attempt >= MAX_EVAL_RETRIES:
        return "report_node"
    return "llm_node"
