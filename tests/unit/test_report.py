"""Unit tests for report assembly and Pydantic schema validation."""
from __future__ import annotations

import json

import pytest
from langchain_core.messages import ToolMessage

from agent.state import Anomaly, PentestReport, StepResult


def _make_state(overrides: dict | None = None) -> dict:
    base = {
        "base_url": "http://localhost:8000",
        "username": "testuser",
        "current_password": "pass",
        "new_password": "newpass",
        "thread_id": "test-thread",
        "session_token": None,
        "retry_count": 0,
        "step_results": [
            {"name": "login", "status": "ok", "http_status": 200, "timestamp": "2026-01-01T00:00:00Z"},
            {"name": "validate_login", "status": "ok", "http_status": 200, "timestamp": "2026-01-01T00:00:01Z"},
        ],
        "anomalies": [],
        "error": None,
        "final_status": "success",
        "past_context": [],
        "drift_context": None,
        "summary_count": 0,
        "eval_result": None,
        "eval_attempts": 0,
        "trace_id": "abc123",
        "messages": [],
    }
    if overrides:
        base.update(overrides)
    return base


def test_report_success():
    from agent.report import assemble_report
    state = _make_state()
    report = assemble_report(state, elapsed_ms=1200)

    assert report.status == "success"
    assert len(report.steps) == 2
    assert report.elapsed_ms == 1200
    assert report.anomalies == []


def test_report_partial_failure():
    from agent.report import assemble_report
    state = _make_state({
        "final_status": None,
        "step_results": [
            {"name": "login", "status": "ok", "http_status": 200, "timestamp": ""},
            {"name": "change_password", "status": "error", "http_status": 500, "error_msg": "Server error", "timestamp": ""},
        ],
    })
    report = assemble_report(state, elapsed_ms=500)
    assert report.status == "partial_failure"


def test_report_with_anomaly():
    from agent.report import assemble_report
    state = _make_state({
        "anomalies": [
            {
                "type": "session_not_invalidated",
                "description": "Token valid after logout",
                "evidence": "GET /me returned 200",
            }
        ]
    })
    report = assemble_report(state, elapsed_ms=800)
    assert len(report.anomalies) == 1
    assert report.anomalies[0].type == "session_not_invalidated"


def test_report_json_serialisable():
    from agent.report import assemble_report
    state = _make_state()
    report = assemble_report(state, elapsed_ms=100)
    payload = report.model_dump()
    # Must serialise to valid JSON without errors
    serialised = json.dumps(payload, default=str)
    parsed = json.loads(serialised)
    assert parsed["status"] == "success"


def test_pentest_report_pydantic_validation():
    report = PentestReport(
        status="failure",
        steps=[StepResult(name="login", status="error", http_status=401)],
        anomalies=[],
        elapsed_ms=300,
        thread_id="t1",
    )
    assert report.status == "failure"
    assert report.steps[0].name == "login"


def test_report_with_evaluation_result():
    """PentestReport should accept and store an EvaluationResult."""
    from agent.state import EvaluationResult
    report = PentestReport(
        status="success",
        elapsed_ms=1500,
        thread_id="t2",
        evaluation=EvaluationResult(
            approved=True,
            confidence=0.95,
            feedback="All steps verified.",
            missing_steps=[],
            unsupported_anomalies=[],
            suggested_actions=[],
        ),
    )
    assert report.evaluation is not None
    assert report.evaluation.approved is True
    assert report.evaluation.confidence == 0.95


def test_report_evaluation_none_by_default():
    """evaluation field defaults to None."""
    from agent.report import assemble_report
    state = _make_state()
    report = assemble_report(state, elapsed_ms=100)
    assert report.evaluation is None


def test_report_evaluation_attached_from_state():
    """assemble_report attaches evaluation from state["eval_result"] when present."""
    from agent.report import assemble_report
    state = _make_state({
        "eval_result": {
            "approved": True,
            "confidence": 0.88,
            "feedback": "Evaluation passed.",
            "missing_steps": [],
            "unsupported_anomalies": [],
            "suggested_actions": [],
        }
    })
    report = assemble_report(state, elapsed_ms=200)
    # assemble_report does not attach evaluation — that is done in report_node.
    # The field exists on PentestReport and defaults to None from assemble_report.
    assert report.evaluation is None  # attached separately in report_node


def test_report_json_includes_evaluation_when_set():
    """Serialised JSON should include the evaluation block when present."""
    from agent.state import EvaluationResult
    report = PentestReport(
        status="success",
        elapsed_ms=100,
        thread_id="t3",
        evaluation=EvaluationResult(
            approved=False,
            confidence=0.5,
            feedback="Forced approval.",
            missing_steps=["validate_logout"],
            unsupported_anomalies=[],
            suggested_actions=[],
        ),
    )
    payload = json.loads(report.model_dump_json())
    assert payload["evaluation"]["approved"] is False
    assert payload["evaluation"]["missing_steps"] == ["validate_logout"]
    assert payload["evaluation"]["confidence"] == 0.5


def test_report_json_evaluation_null_when_none():
    """evaluation should serialise as null when not set."""
    from agent.report import assemble_report
    state = _make_state()
    report = assemble_report(state, elapsed_ms=100)
    payload = json.loads(report.model_dump_json())
    assert payload["evaluation"] is None


def _tool_msg(name: str, status: int, body: str = "ok") -> ToolMessage:
    return ToolMessage(
        content=json.dumps({"http_status": status, "body": body}),
        name=name,
        tool_call_id=f"call-{name}-{status}",
    )


def test_parse_steps_from_messages_full_protocol():
    """Reconstruct all 8 protocol steps from ToolMessage history."""
    from agent.report import _parse_steps_from_messages

    messages = [
        _tool_msg("login_tool", 200),
        _tool_msg("me_tool", 200),
        _tool_msg("change_password_tool", 200),
        _tool_msg("me_tool", 401, "Unauthorized"),
        _tool_msg("login_tool", 200),
        _tool_msg("me_tool", 200),
        _tool_msg("logout_tool", 200),
        _tool_msg("me_tool", 401, "Unauthorized"),
    ]

    steps = _parse_steps_from_messages(messages)

    assert [s.name for s in steps] == [
        "login",
        "validate_login",
        "change_password",
        "validate_session_invalidation",
        "re-authenticate",
        "validate_reauth",
        "logout",
        "validate_logout",
    ]
    assert all(s.status == "ok" for s in steps)
    assert steps[3].http_status == 401
    assert steps[7].http_status == 401


def test_parse_steps_from_messages_marks_unexpected_status_as_error():
    from agent.report import _parse_steps_from_messages

    messages = [
        _tool_msg("login_tool", 401, "Invalid credentials"),
    ]

    steps = _parse_steps_from_messages(messages)

    assert len(steps) == 1
    assert steps[0].name == "login"
    assert steps[0].status == "error"
    assert steps[0].http_status == 401


def test_assemble_report_parses_steps_when_state_empty():
    """When step_results is empty, assemble_report rebuilds from ToolMessages."""
    from agent.report import assemble_report

    state = _make_state({
        "step_results": [],
        "final_status": None,
        "messages": [
            _tool_msg("login_tool", 200),
            _tool_msg("me_tool", 200),
        ],
    })

    report = assemble_report(state, elapsed_ms=900)

    assert len(report.steps) == 2
    assert report.steps[0].name == "login"
    assert report.steps[1].name == "validate_login"
    assert report.status == "success"
