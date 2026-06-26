"""System prompts for the Autonomous Pentesting Agent."""
from __future__ import annotations

import json


# ── Legacy auth-lifecycle prompt (v1) ────────────────────────────────────────

_LEGACY_AUTH_PROMPT = """\
You are an autonomous security testing agent. Perform a complete
authentication lifecycle test and produce a structured audit report.

## API Contract

### POST /login
- Request:  {{"username": "...", "password": "..."}}
- Success:  HTTP 200 -> {{"token": "<bearer>", "expires_in": 300}}
            Field is "token", NOT "access_token".
- Failure:  HTTP 401 -> {{"detail": "Invalid credentials"}}
- Lockout:  HTTP 429 after 3 consecutive failures.

### GET /me
- Header:  Authorization: Bearer <token>
- Success: HTTP 200 -> {{"username": "..."}}
- Expired: HTTP 401 -> {{"detail": "Token expired"}} re-auth required.

### POST /change-password
- Request: {{"current_password": "...", "new_password": "..."}}
- Success: HTTP 200. ALL sessions immediately invalidated.

### POST /logout
- Header:  Authorization: Bearer <token>
- Success: HTTP 200. Session removed.

## Steps (execute in order)

1. login — POST /login with {username} / {current_password}.
2. validate_login — GET /me; confirm authentication.
3. change_password — POST /change-password; supply {current_password}
   and {new_password}.
4. validate_session_invalidation — GET /me with OLD token; expect 401.
5. re-authenticate — POST /login with {username} / {new_password}.
6. validate_reauth — GET /me with new token; expect 200.
7. logout — POST /logout with new token.
8. validate_logout — GET /me with new token; expect 401.
9. report — Stop tools. Produce the final JSON report.

## Anomaly Types
weak_password_policy, session_not_invalidated, logout_session_leak,
token_not_rotated, rate_limiting_absent, structural_change.

## Discovered Endpoints
{openapi_context}

## Drift Context
{drift_context}

## Past Runs
{past_context}
"""


# ── General executor prompt (v2) ─────────────────────────────────────────────

_EXECUTOR_PROMPT = """\
You are an autonomous web security testing agent. Reconnaissance has
been completed and a test plan has been generated. Execute each item
in the plan using the available tools, then produce a security report.

## Target
- API type:        {api_type}
- Auth mechanisms: {auth_mechanisms}
- Tech stack:      {tech_stack}

## Discovered Endpoints
{endpoints}

## Test Plan (execute: critical -> high -> medium -> low)
{test_plan}

## Credentials (for auth-related tests)
- Username: {username}
- Password: {current_password}

## Scope
{scope_summary}

## Past Run Context
{past_context}

## Drift Context
{drift_context}

## Execution Instructions
1. Execute each plan item in priority order.
2. For each item call the listed tools on the listed paths.
3. Supply required parameters (path, parameter, token) from the
   endpoint list and credentials above.
4. For access-control tools (idor_probe, bola_probe,
   privilege_escalation_check) obtain a token via login_tool first.
5. After all plan items are done, STOP and produce a final JSON report:
   - overall_risk: critical | high | medium | low | clean
   - findings: list of check, path, vulnerable, severity, description,
     remediation dicts
   - modules_tested: list of module names executed
   - elapsed_ms: estimated total time

## Error Handling
- If a tool raises an error, skip it and move on.
- Do not repeat identical tool calls more than twice.
- If no endpoints discovered, probe: /, /api, /login, /health.

## MCP Tools
Additional tools may be available at runtime from MCP servers
(e.g. nmap-mcp, nuclei-mcp, sqlmap-mcp). Use them when relevant;
they complement the built-in tools.
"""


# ── Constants ─────────────────────────────────────────────────────────────────

_NO_PLAN = (
    "(No test plan — run all modules on the discovered endpoints)"
)
_NO_ENDPOINTS = (
    "(None discovered — probe /, /api, /login, /health)"
)
_NO_CONTEXT = "No previous runs recorded for this target."
_NO_DRIFT = (
    "No drift detected — behaviour matches the last recorded run."
)


# ── Formatters ────────────────────────────────────────────────────────────────

def _fmt_test_plan(items: list[dict]) -> str:
    if not items:
        return _NO_PLAN
    lines: list[str] = []
    for i, item in enumerate(items, 1):
        tools_str = ", ".join(item.get("tools", []))
        paths_str = ", ".join(item.get("paths", []))
        pri = item.get("priority", "?").upper()
        mod = item.get("module", "?")
        reason = item.get("reason", "")
        lines.append(f"{i}. [{pri}] {mod} — {reason}")
        lines.append(f"   Tools: {tools_str}")
        lines.append(f"   Paths: {paths_str}")
    return "\n".join(lines)


def _fmt_endpoints(endpoints: list[dict]) -> str:
    if not endpoints:
        return _NO_ENDPOINTS
    return "\n".join(
        f"  {e.get('method','?')} {e.get('path','?')}"
        for e in endpoints[:30]
    )


def _fmt_past(past: list[str]) -> str:
    if not past:
        return _NO_CONTEXT
    return "\n".join(
        f"[Run {i + 1}]: {s}" for i, s in enumerate(past)
    )


# ── Public API ────────────────────────────────────────────────────────────────

def build_executor_prompt(
    fingerprint: dict,
    test_plan: list[dict],
    scope: dict,
    username: str = "",
    current_password: str = "",
    past_context: list[str] | None = None,
    drift_context: str | None = None,
) -> str:
    """Build the general executor system prompt for v2 runs."""
    fp = fingerprint or {}
    tech = fp.get("tech_stack") or {}
    tech_str = (
        json.dumps(tech, separators=(",", ":"))
        if tech else "(unknown)"
    )
    active = scope.get("active_modules") or "all modules"
    excl = scope.get("excluded_paths") or "(none)"
    return _EXECUTOR_PROMPT.format(
        api_type=fp.get("api_type", "unknown"),
        auth_mechanisms=fp.get("auth_mechanisms", []),
        tech_stack=tech_str,
        endpoints=_fmt_endpoints(fp.get("endpoints", [])),
        test_plan=_fmt_test_plan(test_plan or []),
        username=username or "(not provided)",
        current_password=current_password or "(not provided)",
        scope_summary=(
            f"Active modules: {active} | "
            f"Excluded paths: {excl}"
        ),
        past_context=_fmt_past(past_context or []),
        drift_context=drift_context or _NO_DRIFT,
    )


def build_system_prompt(
    username: str,
    current_password: str,
    new_password: str,
    past_context: list[str],
    drift_context: str | None = None,
    openapi_context: str | None = None,
    *,
    fingerprint: dict | None = None,
    test_plan: list[dict] | None = None,
    scope: dict | None = None,
) -> str:
    """Return the executor system prompt.

    Uses the v2 general executor prompt when fingerprint + test_plan are
    available (Phase 4+); falls back to the v1 auth-lifecycle prompt for
    backward compatibility.
    """
    if fingerprint and test_plan is not None:
        return build_executor_prompt(
            fingerprint=fingerprint,
            test_plan=test_plan,
            scope=scope or {},
            username=username,
            current_password=current_password,
            past_context=past_context,
            drift_context=drift_context,
        )

    openapi_block = (
        openapi_context
        or "No OpenAPI schema — rely on the API contract above."
    )
    return _LEGACY_AUTH_PROMPT.format(
        username=username,
        current_password=current_password,
        new_password=new_password,
        past_context=_fmt_past(past_context),
        drift_context=drift_context or _NO_DRIFT,
        openapi_context=openapi_block,
    )
