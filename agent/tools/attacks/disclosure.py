"""Layer 2 — Information disclosure probes (error messages, PII,
path traversal, HTTP methods).

These tools check whether the API leaks internal details that could
help an attacker understand the system or extract sensitive data.
"""
from __future__ import annotations

import re
from typing import Any

import httpx
from langchain_core.tools import tool
from opentelemetry import trace

from agent.logger import get_logger
from agent.tools.primitives import (
    _base_url_var,
    _do_http_get,
    _do_http_post,
)

log = get_logger(__name__)
_tracer = trace.get_tracer("agent.tools.disclosure")

# ── Pattern tables ────────────────────────────────────────────────────────

_ERROR_DISCLOSURE_PATTERNS: list[re.Pattern] = [
    re.compile(r"traceback \(most recent call last\)", re.I),
    re.compile(r"exception in thread", re.I),
    re.compile(r"at [a-z][a-z0-9.]+\.[a-z]+\(", re.I),  # Java stack
    re.compile(r"/home/\w+/"),
    re.compile(r"c:\\[\w\\]+\\", re.I),
    re.compile(r"(mysql|postgresql|sqlite)://", re.I),
    re.compile(r"password\s*=\s*['\"][^'\"]{3,}['\"]", re.I),
    re.compile(r"internal server error", re.I),
    re.compile(r"stack trace", re.I),
]

_MALFORMED_PAYLOADS = [
    ("body", '{"broken": '),           # malformed JSON
    ("body", "' OR 1=1 --"),           # SQL chars
    ("path_suffix", "/../../../etc"),  # traversal hint
]

_PII_PATTERNS: dict[str, re.Pattern] = {
    "email": re.compile(
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    ),
    "phone": re.compile(
        r'\b(\+?\d{1,3}[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b'
    ),
    "credit_card": re.compile(
        r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b'
    ),
    "ssn": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
}

_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//etc/passwd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
]

_TRAVERSAL_INDICATORS = [
    "root:x:",
    "[boot loader]",
    "127.0.0.1 localhost",
    "# copyright (c) microsoft",
]

_METHODS_TO_TEST = [
    "GET", "POST", "PUT", "PATCH",
    "DELETE", "OPTIONS", "HEAD", "TRACE",
]


# ── Tools ─────────────────────────────────────────────────────────────────


@tool
async def error_disclosure_probe(
    path: str,
    method: str = "GET",
) -> dict[str, Any]:
    """Probe for verbose error message disclosure.

    Sends malformed requests (broken JSON, SQL characters) and checks
    responses for stack traces, internal file paths, DB connection strings,
    or embedded passwords.

    Args:
        path:   URL path to probe.
        method: Preferred HTTP method ("GET" or "POST").

    Returns: {check, vulnerable, patterns_found, evidence, description}.
    """
    found_patterns: list[str] = []
    evidence_excerpt = ""

    with _tracer.start_as_current_span(
        "pentest.disclosure.error",
        attributes={"pentest.path": path},
    ):
        # Malformed JSON body
        try:
            resp = await _do_http_post(
                path,
                body=None,
                headers={"Content-Type": "application/json"},
                content_type="application/json",
            )
            body_text = (
                resp.body if isinstance(resp.body, str)
                else str(resp.body)
            )
            matched = [
                p.pattern for p in _ERROR_DISCLOSURE_PATTERNS
                if p.search(body_text)
            ]
            if matched:
                found_patterns.extend(matched)
                evidence_excerpt = body_text[:300]
        except Exception as exc:
            log.debug("error_disclosure.post_error", error=str(exc))

        # SQL char injection
        try:
            resp = await _do_http_get(
                path, params={"id": "' OR 1=1 --"}
            )
            body_text = (
                resp.body if isinstance(resp.body, str)
                else str(resp.body)
            )
            matched = [
                p.pattern for p in _ERROR_DISCLOSURE_PATTERNS
                if p.search(body_text)
            ]
            if matched:
                found_patterns.extend(matched)
                if not evidence_excerpt:
                    evidence_excerpt = body_text[:300]
        except Exception as exc:
            log.debug("error_disclosure.get_error", error=str(exc))

    found_patterns = list(dict.fromkeys(found_patterns))
    vulnerable = bool(found_patterns)
    log.info(
        "tool.error_disclosure_probe",
        path=path,
        vulnerable=vulnerable,
        patterns=len(found_patterns),
    )
    return {
        "check": "error_disclosure_probe",
        "path": path,
        "vulnerable": vulnerable,
        "severity": "medium" if vulnerable else "info",
        "patterns_found": found_patterns,
        "evidence": evidence_excerpt,
        "description": (
            f"Verbose errors expose internal details: "
            + ", ".join(found_patterns[:3])
            if vulnerable else
            "No sensitive information detected in error responses"
        ),
        "remediation": (
            "Return generic error messages to clients. "
            "Log detailed errors server-side only. "
            "Disable debug mode in production."
        ),
    }


@tool
async def pii_scan(path: str) -> dict[str, Any]:
    """Scan an endpoint's response body for PII patterns.

    Checks for email addresses, phone numbers, credit-card numbers,
    and US Social Security Numbers in the response body.

    Args:
        path: URL path to inspect.

    Returns: {check, vulnerable, pii_found, types_found, count, description}.
    """
    with _tracer.start_as_current_span(
        "pentest.disclosure.pii",
        attributes={"pentest.path": path},
    ):
        resp = await _do_http_get(path)

    body_text = (
        resp.body if isinstance(resp.body, str) else str(resp.body)
    )
    types_found: list[str] = []
    total = 0

    for pii_type, pattern in _PII_PATTERNS.items():
        matches = pattern.findall(body_text)
        if matches:
            types_found.append(pii_type)
            total += len(matches)

    vulnerable = bool(types_found)
    log.info(
        "tool.pii_scan",
        path=path,
        vulnerable=vulnerable,
        types=types_found,
        count=total,
    )
    return {
        "check": "pii_scan",
        "path": path,
        "vulnerable": vulnerable,
        "severity": "high" if vulnerable else "info",
        "pii_found": vulnerable,
        "types_found": types_found,
        "count": total,
        "http_status": resp.status,
        "description": (
            f"PII detected: {', '.join(types_found)} ({total} matches)"
            if vulnerable else
            "No PII patterns found in response"
        ),
        "remediation": (
            "Mask or redact PII in API responses. "
            "Apply field-level access controls. "
            "Log data access and alert on bulk exports."
        ),
    }


@tool
async def path_traversal_probe(
    path: str,
    parameter: str = "file",
) -> dict[str, Any]:
    """Probe for path / directory traversal vulnerabilities.

    Sends URL-encoded and double-encoded traversal sequences in `parameter`
    and checks responses for OS file system content (e.g. /etc/passwd).

    Args:
        path:      URL path to probe.
        parameter: Query parameter expected to contain a file/path value.

    Returns: {check, vulnerable, payload_used, evidence, description}.
    """
    finding: dict[str, Any] = {}

    with _tracer.start_as_current_span(
        "pentest.disclosure.traversal",
        attributes={"pentest.path": path},
    ):
        for payload in _TRAVERSAL_PAYLOADS:
            try:
                resp = await _do_http_get(
                    path, params={parameter: payload}
                )
                body_text = (
                    resp.body if isinstance(resp.body, str)
                    else str(resp.body)
                ).lower()
                indicators = [
                    i for i in _TRAVERSAL_INDICATORS if i in body_text
                ]
                if indicators:
                    finding = {
                        "payload": payload,
                        "http_status": resp.status,
                        "indicators": indicators,
                        "body_excerpt": body_text[:300],
                    }
                    break
            except Exception as exc:
                log.debug("traversal_probe.error", error=str(exc))

    vulnerable = bool(finding)
    log.info(
        "tool.path_traversal_probe",
        path=path,
        vulnerable=vulnerable,
    )
    return {
        "check": "path_traversal_probe",
        "path": path,
        "parameter": parameter,
        "vulnerable": vulnerable,
        "severity": "critical" if vulnerable else "info",
        "payload_used": finding.get("payload"),
        "indicators": finding.get("indicators", []),
        "evidence": finding.get("body_excerpt", ""),
        "description": (
            f"Path traversal: file content exposed via "
            f"payload '{finding.get('payload')}'"
            if vulnerable else
            "No path traversal indicators found"
        ),
        "remediation": (
            "Sanitise file path inputs. Use an allow-list of permitted "
            "files/directories. Resolve paths and verify they are "
            "within the expected root before opening."
        ),
    }


@tool
async def http_methods_check(path: str) -> dict[str, Any]:
    """Check which HTTP methods are accepted on an endpoint.

    Tests GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD, and TRACE.
    TRACE being enabled is a Cross-Site Tracing (XST) vulnerability.
    Any method returning a non-405 response is reported as allowed.

    Args:
        path: URL path to test.

    Returns: {check, vulnerable, allowed, unexpected_allowed,
    trace_enabled, all_results, description}.
    """
    base_url = _base_url_var.get()
    results: dict[str, int] = {}

    with _tracer.start_as_current_span(
        "pentest.disclosure.methods",
        attributes={"pentest.path": path},
    ):
        async with httpx.AsyncClient(
            base_url=base_url, timeout=5.0
        ) as client:
            for method in _METHODS_TO_TEST:
                try:
                    resp = await client.request(method, path)
                    results[method] = resp.status_code
                except Exception:
                    results[method] = 0

    allowed = [
        m for m, s in results.items()
        if s not in (0, 405, 501)
    ]
    trace_enabled = results.get("TRACE", 0) not in (0, 405, 501)
    expected = {"GET", "POST", "OPTIONS", "HEAD"}
    unexpected = [m for m in allowed if m not in expected]

    vulnerable = trace_enabled or len(unexpected) > 0
    severity = "medium" if trace_enabled else ("low" if unexpected else "info")

    log.info(
        "tool.http_methods_check",
        path=path,
        allowed=allowed,
        trace_enabled=trace_enabled,
        vulnerable=vulnerable,
    )
    return {
        "check": "http_methods_check",
        "path": path,
        "vulnerable": vulnerable,
        "severity": severity,
        "allowed": allowed,
        "unexpected_allowed": unexpected,
        "trace_enabled": trace_enabled,
        "all_results": results,
        "description": (
            "TRACE enabled (XST risk); "
            if trace_enabled else ""
        ) + (
            f"Unexpected methods: {', '.join(unexpected)}"
            if unexpected else
            "Only expected HTTP methods allowed"
        ),
        "remediation": (
            "Disable TRACE and any methods not explicitly required. "
            "Use an allow-list in your server/framework configuration."
        ),
    }


DISCLOSURE_TOOLS = [
    error_disclosure_probe,
    pii_scan,
    path_traversal_probe,
    http_methods_check,
]
