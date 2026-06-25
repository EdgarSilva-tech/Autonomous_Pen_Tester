"""Layer 2 — Broken access control probes (IDOR, BOLA, privilege
escalation).

These tools test whether the API enforces object-level and function-level
authorization correctly.
"""
from __future__ import annotations

from typing import Any

from langchain_core.tools import tool
from opentelemetry import trace

from agent.logger import get_logger
from agent.tools.primitives import (
    _do_http_delete,
    _do_http_get,
    _do_http_post,
    _do_http_put,
)

log = get_logger(__name__)
_tracer = trace.get_tracer("agent.tools.access")


async def _request(
    method: str,
    path: str,
    token: str | None,
) -> Any:
    """Send a request with optional Bearer token; return HttpResponse."""
    headers = (
        {"Authorization": f"Bearer {token}"} if token else None
    )
    method = method.upper()
    if method == "GET":
        return await _do_http_get(path, headers=headers)
    if method == "POST":
        return await _do_http_post(path, headers=headers)
    if method == "PUT":
        return await _do_http_put(path, headers=headers)
    if method == "DELETE":
        return await _do_http_delete(path, headers=headers)
    return await _do_http_get(path, headers=headers)


@tool
async def idor_probe(
    own_path: str,
    other_path: str,
    token: str,
    method: str = "GET",
) -> dict[str, Any]:
    """Test for Insecure Direct Object Reference (IDOR).

    Accesses a resource belonging to another user using the current
    user's `token`. If `other_path` returns 200, the endpoint is likely
    vulnerable — authorization is not enforced at the object level.

    Args:
        own_path:   Path to current user's resource, e.g. /api/users/1.
        other_path: Path to another user's resource, e.g. /api/users/2.
        token:      Bearer token of the current (low-privilege) user.
        method:     HTTP method to use.

    Returns: {check, vulnerable, own_status, other_status, description}.
    """
    with _tracer.start_as_current_span(
        "pentest.access.idor",
        attributes={
            "pentest.own_path": own_path,
            "pentest.other_path": other_path,
        },
    ):
        own_resp = await _request(method, own_path, token)
        other_resp = await _request(method, other_path, token)

    vulnerable = other_resp.status not in (401, 403, 404)
    log.info(
        "tool.idor_probe",
        own_status=own_resp.status,
        other_status=other_resp.status,
        vulnerable=vulnerable,
    )
    return {
        "check": "idor_probe",
        "own_path": own_path,
        "other_path": other_path,
        "method": method,
        "vulnerable": vulnerable,
        "severity": "high" if vulnerable else "info",
        "own_status": own_resp.status,
        "other_status": other_resp.status,
        "other_body": other_resp.body,
        "description": (
            f"IDOR: {other_path} returned {other_resp.status} "
            "with another user's token"
            if vulnerable else
            f"Access to {other_path} correctly denied "
            f"({other_resp.status})"
        ),
        "remediation": (
            "Validate object ownership on every request. "
            "Check that the authenticated user owns the requested "
            "resource before returning data."
        ),
    }


@tool
async def bola_probe(
    path_template: str,
    ids: list[str],
    token: str,
) -> dict[str, Any]:
    """Test multiple object IDs for Broken Object Level Authorization.

    Sends a GET request for each ID in `ids` using the same `token`.
    IDs that return 200 with data are potential unauthorized accesses.

    Args:
        path_template: URL with {id} placeholder, e.g. /api/orders/{id}.
        ids:           List of IDs to test (strings).
        token:         Bearer token to use for all requests.

    Returns: {check, vulnerable, accessible_ids, responses, description}.
    """
    headers = {"Authorization": f"Bearer {token}"}
    responses: dict[str, dict[str, Any]] = {}

    with _tracer.start_as_current_span(
        "pentest.access.bola",
        attributes={"pentest.template": path_template},
    ):
        for obj_id in ids:
            path = path_template.format(id=obj_id)
            try:
                resp = await _do_http_get(path, headers=headers)
                responses[obj_id] = {
                    "status": resp.status,
                    "has_body": bool(resp.body),
                }
            except Exception as exc:
                responses[obj_id] = {"error": str(exc)}

    accessible = [
        oid for oid, r in responses.items()
        if r.get("status", 999) not in (401, 403, 404)
    ]
    vulnerable = len(accessible) > 1

    log.info(
        "tool.bola_probe",
        template=path_template,
        ids_tested=len(ids),
        accessible=len(accessible),
        vulnerable=vulnerable,
    )
    return {
        "check": "bola_probe",
        "path_template": path_template,
        "ids_tested": ids,
        "vulnerable": vulnerable,
        "severity": "high" if vulnerable else "info",
        "accessible_ids": accessible,
        "responses": responses,
        "description": (
            f"BOLA: {len(accessible)} of {len(ids)} IDs accessible "
            "with the same token"
            if vulnerable else
            "Object-level authorization appears correct"
        ),
        "remediation": (
            "Enforce ownership checks per-object. Never rely on "
            "obscure IDs alone — always verify the authenticated "
            "user owns the requested resource."
        ),
    }


@tool
async def privilege_escalation_check(
    path: str,
    low_priv_token: str,
    method: str = "GET",
) -> dict[str, Any]:
    """Check whether a low-privilege token can access an elevated endpoint.

    Sends a request to an admin / privileged `path` using `low_priv_token`.
    A 200 response indicates broken function-level authorization (BFLA).

    Args:
        path:           Privileged endpoint to test, e.g. /api/admin/users.
        low_priv_token: Bearer token of a regular (non-admin) user.
        method:         HTTP method to use.

    Returns: {check, vulnerable, http_status, body, description}.
    """
    with _tracer.start_as_current_span(
        "pentest.access.privilege",
        attributes={"pentest.path": path},
    ):
        resp = await _request(method, path, low_priv_token)

    vulnerable = resp.status not in (401, 403, 404)
    log.info(
        "tool.privilege_escalation_check",
        path=path,
        status=resp.status,
        vulnerable=vulnerable,
    )
    return {
        "check": "privilege_escalation_check",
        "path": path,
        "method": method,
        "vulnerable": vulnerable,
        "severity": "critical" if vulnerable else "info",
        "http_status": resp.status,
        "body": resp.body,
        "description": (
            f"Privilege escalation: {path} returned {resp.status} "
            "for a low-privilege token"
            if vulnerable else
            f"Access to {path} correctly denied ({resp.status})"
        ),
        "remediation": (
            "Implement function-level authorization checks. "
            "Deny by default — only grant access when an explicit "
            "role/permission permits it."
        ),
    }


ACCESS_TOOLS = [idor_probe, bola_probe, privilege_escalation_check]
