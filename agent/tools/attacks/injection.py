"""Layer 2 — Injection attack probes (SQLi, NoSQLi, SSTI, XSS).

Tools send purpose-built payloads to a single endpoint parameter and
inspect responses for tell-tale error patterns or content reflection.
"""
from __future__ import annotations

from typing import Any

from langchain_core.tools import tool
from opentelemetry import trace

from agent.logger import get_logger
from agent.tools.primitives import _do_http_get, _do_http_post

log = get_logger(__name__)
_tracer = trace.get_tracer("agent.tools.injection")

# ── Payload / pattern tables ──────────────────────────────────────────────

_SQLI_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR 1=1 --",
    "1; DROP TABLE users --",
]

_SQLI_ERROR_PATTERNS = [
    "sql syntax",
    "mysql_error",
    "unclosed quotation",
    "ora-",
    "pg::",
    "sqlite_error",
    "syntax error near",
    "microsoft sql",
    "you have an error in your sql",
    "odbc driver",
]

_NOSQL_OPS: list[tuple[str, Any]] = [
    ("$ne", None),
    ("$gt", ""),
    ("$regex", ".*"),
]

_NOSQL_ERROR_PATTERNS = [
    "castererror",
    "bsontype",
    "invalid query",
    "bad value for",
    "no such operator",
    "cannot read property",
]

_SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
]

_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "'<script>alert(1)</script>",
]


# ── Helpers ───────────────────────────────────────────────────────────────


def _body_text(resp) -> str:
    raw = resp.body if isinstance(resp.body, str) else str(resp.body)
    return raw.lower()


# ── Tools ─────────────────────────────────────────────────────────────────


@tool
async def sqli_probe(
    path: str,
    parameter: str,
    method: str = "GET",
) -> dict[str, Any]:
    """Probe an endpoint for SQL injection via error-based detection.

    Sends common SQL payloads in `parameter` and checks responses for
    database error strings. Only flags confirmed SQL error patterns.

    Args:
        path:      URL path to probe (e.g. "/api/users").
        parameter: Query / body parameter to inject into.
        method:    "GET" injects into query string; "POST" into JSON body.

    Returns: {check, path, vulnerable, severity, payloads_triggered,
    description, remediation}.
    """
    triggered: list[dict[str, Any]] = []

    with _tracer.start_as_current_span(
        "pentest.injection.sqli",
        attributes={"pentest.path": path, "pentest.param": parameter},
    ):
        for payload in _SQLI_PAYLOADS:
            try:
                if method.upper() == "GET":
                    resp = await _do_http_get(
                        path, params={parameter: payload}
                    )
                else:
                    resp = await _do_http_post(
                        path, body={parameter: payload}
                    )
                bt = _body_text(resp)
                errors = [p for p in _SQLI_ERROR_PATTERNS if p in bt]
                if errors or resp.status == 500:
                    triggered.append({
                        "payload": payload,
                        "http_status": resp.status,
                        "errors": errors,
                        "body_excerpt": bt[:200],
                    })
            except Exception as exc:
                log.debug("sqli_probe.error", error=str(exc))

    vulnerable = bool(triggered)
    log.info(
        "tool.sqli_probe",
        path=path,
        vulnerable=vulnerable,
        triggers=len(triggered),
    )
    return {
        "check": "sqli_probe",
        "path": path,
        "parameter": parameter,
        "method": method,
        "vulnerable": vulnerable,
        "severity": "high" if vulnerable else "info",
        "confidence": "high" if triggered else "low",
        "payloads_triggered": triggered,
        "description": (
            f"SQL injection detected via '{parameter}' on {path}"
            if vulnerable else
            f"No SQL injection found in '{parameter}' on {path}"
        ),
        "remediation": (
            "Use parameterised queries / prepared statements. "
            "Never concatenate user input into SQL strings."
        ),
    }


@tool
async def nosql_probe(
    path: str,
    parameter: str,
    method: str = "POST",
) -> dict[str, Any]:
    """Probe for NoSQL injection by sending MongoDB operator payloads.

    Sends payloads such as {\"$ne\": null} in the target parameter and
    checks for NoSQL error messages or unexpectedly successful responses
    (e.g. auth bypass returning 200 instead of 401).

    Args:
        path:      URL path to probe.
        parameter: Body / query parameter to inject operators into.
        method:    "POST" (JSON body) or "GET" (query string).

    Returns: {check, path, vulnerable, severity, triggered, description}.
    """
    triggered: list[dict[str, Any]] = []

    with _tracer.start_as_current_span(
        "pentest.injection.nosql",
        attributes={"pentest.path": path},
    ):
        for op, val in _NOSQL_OPS:
            payload = {parameter: {op: val}}
            try:
                if method.upper() == "GET":
                    resp = await _do_http_get(
                        path, params={parameter: f"{{{op}: {val}}}"}
                    )
                else:
                    resp = await _do_http_post(path, body=payload)
                bt = _body_text(resp)
                errors = [p for p in _NOSQL_ERROR_PATTERNS if p in bt]
                if errors or (resp.status == 200 and op == "$ne"):
                    triggered.append({
                        "operator": op,
                        "http_status": resp.status,
                        "errors": errors,
                        "body_excerpt": bt[:200],
                    })
            except Exception as exc:
                log.debug("nosql_probe.error", error=str(exc))

    vulnerable = bool(triggered)
    log.info("tool.nosql_probe", path=path, vulnerable=vulnerable)
    return {
        "check": "nosql_probe",
        "path": path,
        "parameter": parameter,
        "method": method,
        "vulnerable": vulnerable,
        "severity": "high" if vulnerable else "info",
        "triggered": triggered,
        "description": (
            f"NoSQL injection indicators found in '{parameter}' on {path}"
            if vulnerable else
            f"No NoSQL injection found in '{parameter}' on {path}"
        ),
        "remediation": (
            "Validate and sanitise all input before passing to query "
            "builders. Use schema validation (e.g. Mongoose schemas) "
            "to reject unexpected operator keys."
        ),
    }


@tool
async def ssti_probe(
    path: str,
    parameter: str,
    method: str = "GET",
) -> dict[str, Any]:
    """Probe for Server-Side Template Injection (SSTI).

    Sends arithmetic expressions as payloads (e.g. {{7*7}}) and checks
    whether the response contains the evaluated result ("49").
    Covers Jinja2, FreeMarker, Thymeleaf, and ERB template engines.

    Args:
        path:      URL path to probe.
        parameter: Input parameter to inject template expressions into.
        method:    "GET" or "POST".

    Returns: {check, path, vulnerable, payload_used, reflected_value}.
    """
    result_entry: dict[str, Any] = {}

    with _tracer.start_as_current_span(
        "pentest.injection.ssti",
        attributes={"pentest.path": path},
    ):
        for payload, expected in _SSTI_PAYLOADS:
            try:
                if method.upper() == "GET":
                    resp = await _do_http_get(
                        path, params={parameter: payload}
                    )
                else:
                    resp = await _do_http_post(
                        path, body={parameter: payload}
                    )
                bt = _body_text(resp)
                if expected in bt:
                    result_entry = {
                        "payload": payload,
                        "expected": expected,
                        "body_excerpt": bt[:300],
                    }
                    break
            except Exception as exc:
                log.debug("ssti_probe.error", error=str(exc))

    vulnerable = bool(result_entry)
    log.info("tool.ssti_probe", path=path, vulnerable=vulnerable)
    return {
        "check": "ssti_probe",
        "path": path,
        "parameter": parameter,
        "method": method,
        "vulnerable": vulnerable,
        "severity": "critical" if vulnerable else "info",
        "confidence": "high" if vulnerable else "low",
        "payload_used": result_entry.get("payload"),
        "reflected_value": result_entry.get("expected"),
        "body_excerpt": result_entry.get("body_excerpt"),
        "description": (
            f"SSTI confirmed via payload '{result_entry.get('payload')}'"
            if vulnerable else
            "No SSTI detected"
        ),
        "remediation": (
            "Never pass user-controlled strings to a template renderer. "
            "Sandbox the template engine and disable dangerous functions."
        ),
    }


@tool
async def xss_probe(
    path: str,
    parameter: str,
    method: str = "GET",
) -> dict[str, Any]:
    """Probe for reflected Cross-Site Scripting (XSS).

    Sends XSS payloads in `parameter` and checks whether the unescaped
    payload is reflected verbatim in the HTML response. Only meaningful
    for endpoints that return text/html — JSON APIs are immune.

    Args:
        path:      URL path to probe.
        parameter: Input parameter to inject XSS payloads into.
        method:    "GET" or "POST".

    Returns: {check, path, vulnerable, payload, content_type, description}.
    """
    finding: dict[str, Any] = {}

    with _tracer.start_as_current_span(
        "pentest.injection.xss",
        attributes={"pentest.path": path},
    ):
        for payload in _XSS_PAYLOADS:
            try:
                if method.upper() == "GET":
                    resp = await _do_http_get(
                        path, params={parameter: payload}
                    )
                else:
                    resp = await _do_http_post(
                        path, body={parameter: payload}
                    )
                body_raw = (
                    resp.body if isinstance(resp.body, str)
                    else str(resp.body)
                )
                ct = resp.headers.get("content-type", "")
                if payload in body_raw:
                    finding = {
                        "payload": payload,
                        "content_type": ct,
                        "body_excerpt": body_raw[:300],
                    }
                    break
            except Exception as exc:
                log.debug("xss_probe.error", error=str(exc))

    vulnerable = bool(finding)
    log.info("tool.xss_probe", path=path, vulnerable=vulnerable)
    return {
        "check": "xss_probe",
        "path": path,
        "parameter": parameter,
        "method": method,
        "vulnerable": vulnerable,
        "severity": "medium" if vulnerable else "info",
        "payload": finding.get("payload"),
        "content_type": finding.get("content_type"),
        "description": (
            "Reflected XSS: payload echoed unescaped in response"
            if vulnerable else
            "No XSS reflection detected"
        ),
        "remediation": (
            "HTML-encode all user-supplied output. "
            "Set Content-Security-Policy to block inline scripts."
        ),
    }


INJECTION_TOOLS = [sqli_probe, nosql_probe, ssti_probe, xss_probe]
