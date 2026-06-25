"""Layer 2 — HTTP security header checks (CORS, security headers, CSP).

These tools make a single GET request and inspect the response headers
for misconfigurations that could enable client-side attacks.
"""
from __future__ import annotations

from typing import Any

from langchain_core.tools import tool
from opentelemetry import trace

from agent.logger import get_logger
from agent.tools.primitives import _do_http_get

log = get_logger(__name__)
_tracer = trace.get_tracer("agent.tools.headers")

# ── Security header requirements ──────────────────────────────────────────

_REQUIRED_HEADERS: dict[str, str | None] = {
    "x-content-type-options": "nosniff",
    "x-frame-options": None,           # any value accepted
    "strict-transport-security": None,
    "referrer-policy": None,
    "permissions-policy": None,
}

# CSP directives that weaken the policy
_UNSAFE_CSP = [
    "unsafe-inline",
    "unsafe-eval",
    "unsafe-hashes",
]


@tool
async def cors_check(
    path: str,
    origin: str = "https://evil.example.com",
) -> dict[str, Any]:
    """Check for overly permissive CORS configuration.

    Sends a request with a fake `Origin` header and inspects whether the
    server reflects that origin or returns a wildcard in
    Access-Control-Allow-Origin. Dangerous when combined with
    Access-Control-Allow-Credentials: true.

    Args:
        path:   URL path to test, e.g. "/api/users".
        origin: The attacker-controlled origin to send.

    Returns: {check, vulnerable, reflects_origin, wildcard, credentials,
    acao_value, description, remediation}.
    """
    with _tracer.start_as_current_span(
        "pentest.headers.cors",
        attributes={"pentest.path": path, "pentest.origin": origin},
    ):
        resp = await _do_http_get(
            path, headers={"Origin": origin}
        )

    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get(
        "access-control-allow-credentials", ""
    ).lower()

    reflects_origin = acao == origin
    wildcard = acao == "*"
    credentials_allowed = acac == "true"

    vulnerable = (reflects_origin or wildcard) and credentials_allowed
    severity = "high" if vulnerable else ("medium" if reflects_origin else "info")

    log.info(
        "tool.cors_check",
        path=path,
        acao=acao,
        credentials=credentials_allowed,
        vulnerable=vulnerable,
    )
    return {
        "check": "cors_check",
        "path": path,
        "origin_sent": origin,
        "vulnerable": vulnerable,
        "severity": severity,
        "reflects_origin": reflects_origin,
        "wildcard_origin": wildcard,
        "credentials_allowed": credentials_allowed,
        "acao_value": acao,
        "description": (
            "Dangerous CORS: origin reflected with credentials allowed"
            if vulnerable else (
                "CORS reflects origin but without credentials"
                if reflects_origin else
                "CORS appears correctly configured"
            )
        ),
        "remediation": (
            "Set Access-Control-Allow-Origin to a specific allow-list. "
            "Never combine a wildcard origin with "
            "Access-Control-Allow-Credentials: true."
        ),
    }


@tool
async def security_headers_check(path: str) -> dict[str, Any]:
    """Check which HTTP security headers are present or missing.

    Inspects the response for: X-Content-Type-Options, X-Frame-Options,
    Strict-Transport-Security, Referrer-Policy, and Permissions-Policy.
    Also flags Content-Security-Policy separately (use csp_check for
    detailed CSP analysis).

    Args:
        path: URL path to inspect, e.g. "/".

    Returns: {check, missing, present, misconfigured, score, description}.
    """
    with _tracer.start_as_current_span(
        "pentest.headers.security",
        attributes={"pentest.path": path},
    ):
        resp = await _do_http_get(path)

    h = {k.lower(): v for k, v in resp.headers.items()}
    missing: list[str] = []
    present: dict[str, str] = {}
    misconfigured: list[str] = []

    for header, required_value in _REQUIRED_HEADERS.items():
        if header not in h:
            missing.append(header)
        else:
            present[header] = h[header]
            if required_value and h[header].lower() != required_value:
                misconfigured.append(
                    f"{header}: expected '{required_value}', "
                    f"got '{h[header]}'"
                )

    # X-Content-Type-Options check
    if "x-content-type-options" in present:
        if present["x-content-type-options"].lower() != "nosniff":
            misconfigured.append(
                "x-content-type-options must be 'nosniff'"
            )

    csp_present = "content-security-policy" in h
    score = max(
        0,
        len(_REQUIRED_HEADERS) - len(missing) - len(misconfigured)
        + (1 if csp_present else 0),
    )
    total = len(_REQUIRED_HEADERS) + 1

    vulnerable = len(missing) > 2 or len(misconfigured) > 0
    log.info(
        "tool.security_headers_check",
        path=path,
        missing=len(missing),
        score=f"{score}/{total}",
    )
    return {
        "check": "security_headers_check",
        "path": path,
        "vulnerable": vulnerable,
        "severity": "medium" if missing else "info",
        "present": present,
        "missing": missing,
        "misconfigured": misconfigured,
        "csp_present": csp_present,
        "score": f"{score}/{total}",
        "description": (
            f"{len(missing)} required security header(s) missing: "
            + ", ".join(missing)
            if missing else
            "All checked security headers present"
        ),
        "remediation": (
            "Add missing headers via server config or middleware. "
            "Refer to OWASP Secure Headers Project for values."
        ),
    }


@tool
async def csp_check(path: str) -> dict[str, Any]:
    """Analyse the Content-Security-Policy header for weaknesses.

    Checks for: absent CSP, unsafe-inline, unsafe-eval, wildcard (*) in
    script-src / default-src, and missing object-src / base-uri
    restrictions.

    Args:
        path: URL path to inspect.

    Returns: {check, vulnerable, present, policy, issues, description}.
    """
    with _tracer.start_as_current_span(
        "pentest.headers.csp",
        attributes={"pentest.path": path},
    ):
        resp = await _do_http_get(path)

    policy = resp.headers.get("content-security-policy", "")
    present = bool(policy)
    issues: list[str] = []

    if not present:
        issues.append("Content-Security-Policy header is absent")
    else:
        policy_lower = policy.lower()
        for keyword in _UNSAFE_CSP:
            if keyword in policy_lower:
                issues.append(f"CSP contains '{keyword}'")
        if "'*'" in policy or "* " in policy or policy.endswith("*"):
            issues.append("CSP contains wildcard (*) source")
        if "object-src" not in policy_lower:
            issues.append("object-src directive missing (allows plugins)")
        if "base-uri" not in policy_lower:
            issues.append("base-uri directive missing (allows base hijacking)")

    vulnerable = bool(issues)
    severity = "high" if not present else ("medium" if issues else "info")

    log.info(
        "tool.csp_check",
        path=path,
        present=present,
        issues=len(issues),
        vulnerable=vulnerable,
    )
    return {
        "check": "csp_check",
        "path": path,
        "vulnerable": vulnerable,
        "severity": severity,
        "present": present,
        "policy": policy,
        "issues": issues,
        "description": (
            "; ".join(issues) if issues else "CSP is present and well-formed"
        ),
        "remediation": (
            "Define a strict CSP. Start with "
            "default-src 'self' and add only required sources. "
            "Avoid unsafe-inline by using nonces or hashes."
        ),
    }


HEADER_TOOLS = [cors_check, security_headers_check, csp_check]
