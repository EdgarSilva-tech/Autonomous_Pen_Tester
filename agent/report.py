"""Report assembly and serialisation.

The report_node extracts structured data from the LangGraph message history,
builds a PentestReport, writes it to stdout (JSON lines) and optionally to
a file path.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from langchain_core.messages import AnyMessage, ToolMessage

from agent.logger import get_logger
from agent.state import Anomaly, PentestReport, PentestState, StepResult

log = get_logger(__name__)

# Maps tool name → ordered list of protocol step names (by invocation index).
# Kept in sync with evaluate.py's _TOOL_STEP_SEQUENCES.
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

# Expected HTTP status per step.  401 is CORRECT for invalidation checks.
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


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_steps_from_messages(messages: list[AnyMessage]) -> list[StepResult]:
    """Reconstruct step results from the ToolMessage history.

    step_results in the state are never written directly — tools return dicts
    to the LLM, not to the state.  This function reconstructs the step list by
    replaying the sequence of ToolMessages and assigning protocol step names
    based on the known invocation order for each tool.
    """
    counters: dict[str, int] = {k: 0 for k in _TOOL_STEP_SEQUENCES}
    results: list[StepResult] = []

    for msg in messages:
        if not isinstance(msg, ToolMessage):
            continue
        tool_name = getattr(msg, "name", "")
        if tool_name not in _TOOL_STEP_SEQUENCES:
            continue

        try:
            raw = msg.content
            data: dict[str, Any] = (
                json.loads(raw)
                if isinstance(raw, str)
                else (raw if isinstance(raw, dict) else {})
            )
        except Exception:
            data = {}

        idx = counters[tool_name]
        step_names = _TOOL_STEP_SEQUENCES[tool_name]
        step_name = (
            step_names[idx] if idx < len(step_names) else f"{tool_name}[{idx}]"
        )
        counters[tool_name] += 1

        http_status: int | None = data.get("http_status")
        body = data.get("body", "")

        # A step passes when its HTTP status matches the expected value.
        # For validation steps (validate_session_invalidation, validate_logout)
        # the expected status is 401 — that IS the correct outcome.
        expected = _EXPECTED_STATUS.get(step_name, 200)
        passed = http_status == expected
        error_msg: str | None = None if passed else str(body)[:400]

        results.append(
            StepResult(
                name=step_name,
                status="ok" if passed else "error",
                http_status=http_status,
                error_msg=error_msg,
                timestamp=_now_iso(),
            )
        )

    return results


def assemble_report(state: PentestState, elapsed_ms: int) -> PentestReport:
    """Build a PentestReport from the accumulated state."""
    # Prefer state-level step_results if already populated; otherwise
    # reconstruct from ToolMessage history (common case — tools update the
    # LLM, not the state directly).
    raw_steps = state.get("step_results", [])
    if raw_steps:
        step_results = [StepResult(**s) for s in raw_steps]
    else:
        step_results = _parse_steps_from_messages(state["messages"])

    anomalies = [Anomaly(**a) for a in state.get("anomalies", [])]

    # Infer overall status from step evidence if the LLM didn't set it
    final_status = state.get("final_status") or "failure"
    if not state.get("final_status"):
        if state.get("error"):
            final_status = "failure"
        elif any(s.status == "error" for s in step_results):
            final_status = "partial_failure"
        elif step_results:
            final_status = "success"
        else:
            final_status = "failure"

    return PentestReport(
        status=final_status,
        steps=step_results,
        anomalies=anomalies,
        elapsed_ms=elapsed_ms,
        thread_id=state.get("thread_id", ""),
        past_context=state.get("past_context", []),
    )


def emit_report(report: PentestReport) -> None:
    """Write the report to stdout and optionally to REPORT_OUTPUT_PATH."""
    payload = report.model_dump()
    line = json.dumps(payload, default=str)

    print(line, flush=True)

    output_path = os.getenv("REPORT_OUTPUT_PATH")
    if output_path:
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w") as fh:
                json.dump(payload, fh, indent=2, default=str)
            log.info("report.written", path=output_path)
        except OSError as exc:
            log.warning("report.write_failed", path=output_path, error=str(exc))

    log.info(
        "report.emitted",
        status=report.status,
        steps=len(report.steps),
        anomalies=len(report.anomalies),
        elapsed_ms=report.elapsed_ms,
    )
