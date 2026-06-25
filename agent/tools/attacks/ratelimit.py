"""Layer 2 — Rate-limiting and IP-bypass checks.

Tests whether the API enforces request rate limits and whether those
limits can be circumvented using IP-spoofing headers.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from langchain_core.tools import tool
from opentelemetry import trace

from agent.logger import get_logger
from agent.tools.primitives import _do_http_get, _do_http_post

log = get_logger(__name__)
_tracer = trace.get_tracer("agent.tools.ratelimit")

_IP_BYPASS_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Originating-IP",
    "CF-Connecting-IP",
    "True-Client-IP",
    "X-Client-IP",
]

_FAKE_IP = "127.0.0.1"


async def _single_request(
    path: str, method: str
) -> tuple[int, float]:
    """Return (status_code, elapsed_ms) for one request."""
    t0 = time.monotonic()
    try:
        if method.upper() == "GET":
            resp = await _do_http_get(path)
        else:
            resp = await _do_http_post(path, body={})
        elapsed = (time.monotonic() - t0) * 1000
        return resp.status, elapsed
    except Exception:
        elapsed = (time.monotonic() - t0) * 1000
        return 0, elapsed


@tool
async def rate_limit_check(
    path: str,
    method: str = "GET",
    requests_count: int = 20,
) -> dict[str, Any]:
    """Check whether the endpoint enforces rate limiting.

    Sends `requests_count` requests in rapid succession and checks whether
    any return HTTP 429. Also records per-request timing to detect
    server-side throttling even without an explicit 429.

    Args:
        path:           URL path to probe, e.g. "/api/users".
        method:         HTTP method to use ("GET" or "POST").
        requests_count: Number of requests to send (default 20).

    Returns: {check, vulnerable, rate_limited, limit_after,
    retry_after, timing_ms, description}.
    """
    statuses: list[int] = []
    timings: list[float] = []
    retry_after: str | None = None

    with _tracer.start_as_current_span(
        "pentest.ratelimit.check",
        attributes={"pentest.path": path, "pentest.count": requests_count},
    ):
        for i in range(requests_count):
            status, elapsed = await _single_request(path, method)
            statuses.append(status)
            timings.append(round(elapsed, 1))

            if status == 429:
                # Capture the first 429 occurrence
                if method.upper() == "GET":
                    try:
                        resp = await _do_http_get(path)
                        retry_after = resp.headers.get("retry-after")
                    except Exception:
                        pass
                break

            # Small delay to not hammer the target too hard
            await asyncio.sleep(0.05)

    rate_limited = 429 in statuses
    limit_after = (
        statuses.index(429) + 1 if rate_limited else None
    )
    vulnerable = not rate_limited

    log.info(
        "tool.rate_limit_check",
        path=path,
        requests_sent=len(statuses),
        rate_limited=rate_limited,
        limit_after=limit_after,
    )
    return {
        "check": "rate_limit_check",
        "path": path,
        "method": method,
        "requests_sent": len(statuses),
        "vulnerable": vulnerable,
        "severity": "medium" if vulnerable else "info",
        "rate_limited": rate_limited,
        "limit_after": limit_after,
        "retry_after": retry_after,
        "timing_ms": timings,
        "description": (
            f"Rate limit enforced after {limit_after} requests"
            if rate_limited else
            f"No rate limiting detected after {len(statuses)} requests"
        ),
        "remediation": (
            "Implement rate limiting per IP and per authenticated user. "
            "Return HTTP 429 with Retry-After when limits are hit."
        ),
    }


@tool
async def ip_bypass_check(
    path: str,
    method: str = "GET",
) -> dict[str, Any]:
    """Check whether IP-spoofing headers bypass rate limiting or access control.

    Sends one baseline request, then repeats with each common IP-spoofing
    header set to 127.0.0.1. A different status code or response body
    suggests the server trusts the header for access decisions.

    Args:
        path:   URL path to test.
        method: HTTP method to use.

    Returns: {check, vulnerable, baseline_status, effective_headers,
    responses, description}.
    """
    baseline_status = 0
    header_results: dict[str, int] = {}

    with _tracer.start_as_current_span(
        "pentest.ratelimit.bypass",
        attributes={"pentest.path": path},
    ):
        baseline_status, _ = await _single_request(path, method)

        for header in _IP_BYPASS_HEADERS:
            try:
                if method.upper() == "GET":
                    resp = await _do_http_get(
                        path, headers={header: _FAKE_IP}
                    )
                else:
                    resp = await _do_http_post(
                        path, body={}, headers={header: _FAKE_IP}
                    )
                header_results[header] = resp.status
            except Exception:
                header_results[header] = 0

    effective_headers = [
        h for h, s in header_results.items()
        if s != baseline_status and s not in (0,)
    ]
    vulnerable = bool(effective_headers)

    log.info(
        "tool.ip_bypass_check",
        path=path,
        baseline_status=baseline_status,
        effective=effective_headers,
        vulnerable=vulnerable,
    )
    return {
        "check": "ip_bypass_check",
        "path": path,
        "method": method,
        "vulnerable": vulnerable,
        "severity": "medium" if vulnerable else "info",
        "baseline_status": baseline_status,
        "effective_headers": effective_headers,
        "responses": header_results,
        "description": (
            f"IP bypass possible via header(s): "
            + ", ".join(effective_headers)
            if vulnerable else
            "No IP spoofing bypass detected"
        ),
        "remediation": (
            "Do not trust X-Forwarded-For or similar headers for "
            "security decisions unless the upstream proxy is controlled "
            "by you. Validate the real client IP at the network layer."
        ),
    }


RATELIMIT_TOOLS = [rate_limit_check, ip_bypass_check]
