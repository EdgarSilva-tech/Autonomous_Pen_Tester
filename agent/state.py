"""LangGraph state schema for the Autonomous Pentesting Agent."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any, Literal
from typing_extensions import TypedDict
from uuid import uuid4

from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field


# -- Per-step result ----------------------------------------------------------

class StepResult(BaseModel):
    name: str
    status: Literal["ok", "error", "skipped"]
    http_status: int | None = None
    error_msg: str | None = None
    timestamp: str = ""
    decision: str | None = None


# -- Anomaly record -----------------------------------------------------------

class Anomaly(BaseModel):
    type: str
    description: str
    evidence: str


# -- Security finding (v2 report) ---------------------------------------------

class FindingEvidence(BaseModel):
    payload: str = ""
    request: str = ""
    response_snippet: str = ""
    http_status: int | None = None


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    category: str
    severity: Literal["Critical", "High", "Medium", "Low", "Informational"]
    cvss_score: float = 0.0
    cvss_vector: str = ""
    endpoint: str = ""
    parameter: str = ""
    evidence: FindingEvidence = Field(default_factory=FindingEvidence)
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    confirmed: bool = True
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    module: str = ""
    tool: str = ""


# -- Evaluation result (produced by evaluate_node) ----------------------------

class EvaluationResult(BaseModel):
    """Structured output from the evaluation node."""
    approved: bool
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score 0.0-1.0")
    feedback: str = Field(description="Explanation of the evaluation decision")
    missing_steps: list[str] = Field(
        default_factory=list,
        description="Steps from the protocol that were not executed or not validated",
    )
    unsupported_anomalies: list[str] = Field(
        default_factory=list,
        description="Anomaly types claimed without sufficient evidence in the conversation",
    )
    suggested_actions: list[str] = Field(
        default_factory=list,
        description="Specific actions the agent should take before the report is finalised",
    )


# -- Final report -------------------------------------------------------------

class PentestReport(BaseModel):
    status: Literal["success", "partial_failure", "failure"]
    steps: list[StepResult] = Field(default_factory=list)
    anomalies: list[Anomaly] = Field(default_factory=list)
    elapsed_ms: int = 0
    thread_id: str = ""
    past_context: list[str] = Field(default_factory=list)
    evaluation: EvaluationResult | None = None
    findings: list[Finding] = Field(default_factory=list)
    markdown_report: str = ""


# -- LangGraph State ----------------------------------------------------------

class PentestState(TypedDict):
    # Conversation history managed by LangGraph via add_messages reducer
    messages: Annotated[list[AnyMessage], add_messages]

    # Run configuration (injected at startup)
    base_url: str
    username: str
    current_password: str
    new_password: str
    thread_id: str

    # Runtime state updated by tools
    session_token: str | None
    retry_count: int

    # Accumulated results (written by the LLM into structured output)
    step_results: list[dict[str, Any]]
    anomalies: list[dict[str, Any]]
    error: str | None
    final_status: Literal["success", "partial_failure", "failure"] | None

    # Long-term memory context injected before the run starts
    past_context: list[str]

    # Drift detection: None = first run or no drift
    drift_context: str | None

    # OpenAPI enrichment from /openapi.json
    openapi_context: str | None

    # Summary node: tracks how many times history was compressed
    summary_count: int

    # Evaluation node: structured result + retry counter
    eval_result: dict[str, Any] | None
    eval_attempts: int

    # Observability
    trace_id: str

    # -- v2 fields (populated progressively as phases are implemented) --------

    # Phase 2: populated by recon node
    fingerprint: dict[str, Any] | None

    # Phase 4: populated by planner node
    test_plan: list[dict[str, Any]]

    # Phase 3+: accumulated findings from attack modules
    findings: list[dict[str, Any]]

    # Phase 4: loaded from --scope-file at startup
    scope: dict[str, Any] | None