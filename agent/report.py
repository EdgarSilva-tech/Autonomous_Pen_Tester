"""Report assembly and serialisation.

The report_node extracts structured data from the LangGraph message history,
builds a PentestReport, writes it to stdout (JSON lines) and optionally to
a file path.

v1 mode: reconstructs protocol steps from auth tool ToolMessages.
v2 mode: extracts Finding objects from all attack-tool ToolMessages,
         computes CVSS scores, and renders a Markdown report.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from langchain_core.messages import AnyMessage, ToolMessage

from agent.logger import get_logger
from agent.state import (
    Anomaly,
    Finding,
    FindingEvidence,
    PentestReport,
    PentestState,
    StepResult,
)

log = get_logger(__name__)

# -- v1 auth step sequences ---------------------------------------------------

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

# -- v2 OWASP / CVSS reference tables ----------------------------------------

_TOOL_TO_OWASP: dict[str, str] = {
    "sqli_probe":                "A03:2021 - Injection",
    "nosql_probe":               "A03:2021 - Injection",
    "ssti_probe":                "A03:2021 - Injection",
    "xss_probe":                 "A03:2021 - Injection",
    "idor_probe":                "A01:2021 - Broken Access Control",
    "bola_probe":                "A01:2021 - Broken Access Control",
    "privilege_escalation_check":"A01:2021 - Broken Access Control",
    "path_traversal_probe":      "A01:2021 - Broken Access Control",
    "pii_scan":                  "A02:2021 - Cryptographic Failures",
    "rate_limit_check":          "A04:2021 - Insecure Design",
    "ip_bypass_check":           "A04:2021 - Insecure Design",
    "cors_check":                "A05:2021 - Security Misconfiguration",
    "security_headers_check":    "A05:2021 - Security Misconfiguration",
    "csp_check":                 "A05:2021 - Security Misconfiguration",
    "error_disclosure_probe":    "A05:2021 - Security Misconfiguration",
    "http_methods_check":        "A05:2021 - Security Misconfiguration",
    "jwt_analyze":               "A07:2021 - Identification and Authentication Failures",
    "brute_force_check":         "A07:2021 - Identification and Authentication Failures",
    "session_fixation_check":    "A07:2021 - Identification and Authentication Failures",
    "token_entropy_check":       "A07:2021 - Identification and Authentication Failures",
}

_OWASP_REFS: dict[str, str] = {
    "A01:2021 - Broken Access Control":
        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "A02:2021 - Cryptographic Failures":
        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    "A03:2021 - Injection":
        "https://owasp.org/Top10/A03_2021-Injection/",
    "A04:2021 - Insecure Design":
        "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    "A05:2021 - Security Misconfiguration":
        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    "A07:2021 - Identification and Authentication Failures":
        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
}

# Representative CVSS v3.1 base scores and vectors per severity tier.
_SEVERITY_CVSS: dict[str, tuple[float, str]] = {
    "Critical":      (9.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "High":          (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
    "Medium":        (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Low":           (2.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    "Informational": (0.0, ""),
}

_SEVERITY_NORM: dict[str, str] = {
    "critical":      "Critical",
    "high":          "High",
    "medium":        "Medium",
    "low":           "Low",
    "info":          "Informational",
    "informational": "Informational",
}

_TOOL_TO_MODULE: dict[str, str] = {
    "login_tool": "auth", "me_tool": "auth",
    "change_password_tool": "auth", "logout_tool": "auth",
    "jwt_analyze": "auth", "brute_force_check": "auth",
    "session_fixation_check": "auth", "token_entropy_check": "auth",
    "sqli_probe": "injection", "nosql_probe": "injection",
    "ssti_probe": "injection", "xss_probe": "injection",
    "idor_probe": "access", "bola_probe": "access",
    "privilege_escalation_check": "access",
    "cors_check": "headers", "security_headers_check": "headers",
    "csp_check": "headers",
    "error_disclosure_probe": "disclosure", "pii_scan": "disclosure",
    "path_traversal_probe": "disclosure", "http_methods_check": "disclosure",
    "rate_limit_check": "ratelimit", "ip_bypass_check": "ratelimit",
}


# -- Helpers ------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# -- v1 step reconstruction ---------------------------------------------------


def _parse_steps_from_messages(messages: list[AnyMessage]) -> list[StepResult]:
    """Reconstruct v1 step results from the ToolMessage history."""
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


# -- v2 finding extraction ----------------------------------------------------


def _extract_findings_v2(messages: list[AnyMessage]) -> list[Finding]:
    """Scan ToolMessages for vulnerable=True results and build Finding objects."""
    findings: list[Finding] = []

    for msg in messages:
        if not isinstance(msg, ToolMessage):
            continue
        tool_name = getattr(msg, "name", "")
        try:
            raw = msg.content
            data: dict[str, Any] = (
                json.loads(raw)
                if isinstance(raw, str)
                else (raw if isinstance(raw, dict) else {})
            )
        except Exception:
            continue

        if not data.get("vulnerable"):
            continue

        sev_raw = str(data.get("severity", "medium")).lower()
        severity = _SEVERITY_NORM.get(sev_raw, "Medium")

        category = _TOOL_TO_OWASP.get(tool_name, "A05:2021 - Security Misconfiguration")
        cvss_score, cvss_vector = _SEVERITY_CVSS.get(severity, (0.0, ""))

        endpoint = (
            data.get("path")
            or data.get("other_path")
            or data.get("path_template")
            or ""
        )

        first_triggered: dict[str, Any] = (data.get("payloads_triggered") or [{}])[0]
        payload = (
            data.get("payload")
            or data.get("payload_used")
            or first_triggered.get("payload")
            or data.get("origin_sent")
            or ""
        )
        response_snippet = str(
            data.get("evidence")
            or data.get("body_excerpt")
            or first_triggered.get("body_excerpt")
            or data.get("acao_value")
            or data.get("patterns_found")
            or ""
        )[:500]

        http_status: int | None = (
            data.get("http_status") or first_triggered.get("http_status")
        )

        findings.append(
            Finding(
                title=data.get("description", f"{tool_name} finding"),
                category=category,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                endpoint=str(endpoint),
                parameter=data.get("parameter", ""),
                evidence=FindingEvidence(
                    payload=str(payload),
                    response_snippet=response_snippet,
                    http_status=http_status,
                ),
                remediation=data.get("remediation", ""),
                references=[ref for ref in [_OWASP_REFS.get(category, "")] if ref],
                confirmed=True,
                tool=tool_name,
                module=_TOOL_TO_MODULE.get(tool_name, ""),
            )
        )

    return findings


# -- Markdown renderer --------------------------------------------------------


def _render_markdown(report: PentestReport) -> str:
    lines: list[str] = []

    lines.append("# Pentest Report\n")
    lines.append(f"**Status:** {report.status}  ")
    lines.append(f"**Thread:** {report.thread_id}  ")
    lines.append(f"**Duration:** {report.elapsed_ms} ms\n")

    lines.append("## Executive Summary\n")
    if not report.findings:
        lines.append("No security findings identified.\n")
    else:
        by_sev: dict[str, int] = {}
        for f in report.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

        lines.append(f"{len(report.findings)} finding(s) identified:\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ("Critical", "High", "Medium", "Low", "Informational"):
            if sev in by_sev:
                lines.append(f"| {sev} | {by_sev[sev]} |")
        lines.append("")

    if report.findings:
        lines.append("## Findings\n")
        for i, f in enumerate(report.findings, 1):
            lines.append(f"### {i}. {f.title}\n")
            lines.append(f"**Category:** {f.category}  ")
            lines.append(f"**Severity:** {f.severity}  ")
            if f.cvss_score > 0.0:
                lines.append(f"**CVSS:** {f.cvss_score:.1f}  `{f.cvss_vector}`  ")
            if f.endpoint:
                lines.append(f"**Endpoint:** `{f.endpoint}`  ")
            if f.parameter:
                lines.append(f"**Parameter:** `{f.parameter}`")
            lines.append("")
            if f.evidence.payload:
                lines.append(f"**Payload:**\n```\n{f.evidence.payload}\n```\n")
            if f.evidence.response_snippet:
                snippet = f.evidence.response_snippet[:200]
                lines.append(f"**Response:** `{snippet}`\n")
            if f.remediation:
                lines.append(f"**Remediation:** {f.remediation}\n")
            if f.references:
                lines.append("**References:**")
                for ref in f.references:
                    lines.append(f"- {ref}")
                lines.append("")
            lines.append("---\n")

        lines.append("## Remediation Checklist\n")
        for f in report.findings:
            lines.append(f"- [ ] **[{f.severity}]** {f.title}")

    return "\n".join(lines)


# -- Report assembly ----------------------------------------------------------


def assemble_report(state: PentestState, elapsed_ms: int) -> PentestReport:
    """Build a PentestReport from the accumulated state."""
    messages: list[AnyMessage] = state.get("messages", [])
    is_v2 = bool(state.get("test_plan"))

    if is_v2:
        findings = _extract_findings_v2(messages)
        step_results: list[StepResult] = []
        anomalies: list[Anomaly] = []
        final_status: str = state.get("final_status") or (
            "success" if findings else "failure"
        )
    else:
        raw_steps = state.get("step_results", [])
        step_results = (
            [StepResult(**s) for s in raw_steps]
            if raw_steps
            else _parse_steps_from_messages(messages)
        )
        anomalies = [Anomaly(**a) for a in state.get("anomalies", [])]
        findings = []

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

    report = PentestReport(
        status=final_status,
        steps=step_results,
        anomalies=anomalies,
        elapsed_ms=elapsed_ms,
        thread_id=state.get("thread_id", ""),
        past_context=state.get("past_context", []),
        findings=findings,
    )

    if is_v2:
        report.markdown_report = _render_markdown(report)

    return report


def emit_report(report: PentestReport) -> None:
    """Write the report to stdout and optionally to output files."""
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

    md_path = os.getenv("MARKDOWN_OUTPUT_PATH")
    if md_path and report.markdown_report:
        try:
            os.makedirs(os.path.dirname(md_path), exist_ok=True)
            with open(md_path, "w") as fh:
                fh.write(report.markdown_report)
            log.info("report.markdown_written", path=md_path)
        except OSError as exc:
            log.warning("report.markdown_write_failed", path=md_path, error=str(exc))

    log.info(
        "report.emitted",
        status=report.status,
        steps=len(report.steps),
        anomalies=len(report.anomalies),
        findings=len(report.findings),
        elapsed_ms=report.elapsed_ms,
    )