"""Layer 2 — Authentication tools.

Includes:
  * Flow tools (login, me, change_password, logout) — thin wrappers that
    preserve original signatures, OTel spans, and result format.
  * Attack tools (jwt_analyze, brute_force_check, session_fixation_check,
    token_entropy_check) — security checks for auth weaknesses.
"""
from __future__ import annotations

import asyncio
import base64
import json
import math
from collections import Counter
from typing import Any

from langchain_core.tools import tool
from opentelemetry import trace
from opentelemetry.trace import StatusCode

from agent.logger import get_logger
from agent.tools.primitives import _do_http_get, _do_http_post

log = get_logger(__name__)
_tracer = trace.get_tracer("agent.tools.auth")

_WRONG_PASSWORDS = [f"__invalid_{i}__" for i in range(10)]

_LOCK_PATTERNS = ["locked", "too many attempts", "account disabled"]


# ── Shared helper ─────────────────────────────────────────────────────────


def _auth_result(step: str, resp) -> dict[str, Any]:
    """Build the result dict that the evaluator and report nodes expect."""
    return {
        "step": step,
        "http_status": resp.status,
        "body": resp.body,
        "ok": resp.ok,
    }


# ── Flow tools (v1 auth lifecycle) ────────────────────────────────────────


@tool
async def login_tool(username: str, password: str) -> dict[str, Any]:
    """POST /login — authenticate with username and password.
    Returns the session token on success or an error dict on failure.
    """
    log.info("tool.login", username=username)
    with _tracer.start_as_current_span(
        "pentest.login",
        attributes={
            "pentest.step": "login",
            "pentest.username": username,
        },
    ) as span:
        resp = await _do_http_post(
            "/login",
            body={"username": username, "password": password},
        )
        result = _auth_result("login", resp)
        span.set_attribute("http.status_code", resp.status)
        span.set_attribute("pentest.ok", result["ok"])
        log.info(
            "tool.login.result",
            http_status=resp.status,
            ok=result["ok"],
        )
    return result


@tool
async def me_tool(token: str) -> dict[str, Any]:
    """GET /me — retrieve authenticated user info using a Bearer token.
    Returns user data on success, or 401 if the token is invalid/expired.
    A 401 is the CORRECT outcome when validating session invalidation after
    a password change or logout.
    """
    log.info("tool.me", token_prefix=token[:8] if token else "none")
    with _tracer.start_as_current_span(
        "pentest.validate_session",
        attributes={"pentest.step": "validate_session"},
    ) as span:
        resp = await _do_http_get(
            "/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        result = _auth_result("me", resp)
        span.set_attribute("http.status_code", resp.status)
        span.set_attribute("pentest.http_ok", result["ok"])
        # A 401 here is semantically correct for invalidation checks;
        # mark span OK so Tempo doesn't flag it as an error.
        span.set_status(StatusCode.OK)
        log.info(
            "tool.me.result",
            http_status=resp.status,
            ok=result["ok"],
        )
    return result


@tool
async def change_password_tool(
    token: str, current_password: str, new_password: str
) -> dict[str, Any]:
    """POST /change-password — change the authenticated user's password.
    Requires a valid Bearer token and both the current and new passwords.
    """
    log.info("tool.change_password")
    with _tracer.start_as_current_span(
        "pentest.change_password",
        attributes={"pentest.step": "change_password"},
    ) as span:
        resp = await _do_http_post(
            "/change-password",
            body={
                "current_password": current_password,
                "new_password": new_password,
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        result = _auth_result("change_password", resp)
        span.set_attribute("http.status_code", resp.status)
        span.set_attribute("pentest.ok", result["ok"])
        log.info(
            "tool.change_password.result",
            http_status=resp.status,
            ok=result["ok"],
        )
    return result


@tool
async def logout_tool(token: str) -> dict[str, Any]:
    """POST /logout — invalidate the current session token.
    After a successful logout, any subsequent /me call with this token
    should return 401. If it does not, that is an anomaly.
    """
    log.info("tool.logout")
    with _tracer.start_as_current_span(
        "pentest.logout",
        attributes={"pentest.step": "logout"},
    ) as span:
        resp = await _do_http_post(
            "/logout",
            headers={"Authorization": f"Bearer {token}"},
        )
        result = _auth_result("logout", resp)
        span.set_attribute("http.status_code", resp.status)
        span.set_attribute("pentest.ok", result["ok"])
        log.info(
            "tool.logout.result",
            http_status=resp.status,
            ok=result["ok"],
        )
    return result


# ── Attack tools (v2 auth security checks) ───────────────────────────────


def _decode_jwt_part(part: str) -> dict[str, Any]:
    """Decode one base64url segment of a JWT."""
    try:
        padded = part + "=" * (4 - len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(
        (c / n) * math.log2(c / n) for c in Counter(s).values()
    )


@tool
def jwt_analyze(token: str) -> dict[str, Any]:
    """Decode and analyse a JWT for security weaknesses (no HTTP calls).

    Checks for: 'none' or weak algorithm, missing / expired 'exp' claim,
    and sensitive field names in the payload (password, secret, key).

    Args:
        token: Raw JWT string (header.payload.signature).

    Returns: {check, header, payload, algorithm, expired, issues,
    description}.
    """
    import time as _time

    parts = token.split(".")
    issues: list[str] = []
    header: dict[str, Any] = {}
    payload: dict[str, Any] = {}

    if len(parts) != 3:
        issues.append("Token does not have three dot-separated parts")
    else:
        header = _decode_jwt_part(parts[0])
        payload = _decode_jwt_part(parts[1])

        alg = header.get("alg", "").lower()
        if alg == "none":
            issues.append("Algorithm 'none': signature not verified")
        elif alg in ("hs256", "hs384", "hs512"):
            issues.append(
                f"Symmetric algorithm {alg.upper()}: "
                "key may be guessable if weak"
            )

        exp = payload.get("exp")
        if exp is None:
            issues.append("Missing 'exp' claim: token never expires")
        elif exp < _time.time():
            issues.append(
                f"Token expired at {exp} (current time {int(_time.time())})"
            )

        sensitive = [
            k for k in payload
            if any(s in k.lower() for s in ("password", "secret", "key"))
        ]
        if sensitive:
            issues.append(
                f"Sensitive field(s) in payload: {sensitive}"
            )

    algorithm = header.get("alg", "unknown")
    vulnerable = bool(issues)
    log.info("tool.jwt_analyze", algorithm=algorithm, issues=len(issues))
    return {
        "check": "jwt_analyze",
        "header": header,
        "payload": {k: v for k, v in payload.items() if k != "exp"},
        "algorithm": algorithm,
        "expired": (
            payload.get("exp", 0) < _time.time()
            if payload.get("exp") else None
        ),
        "vulnerable": vulnerable,
        "severity": "high" if vulnerable else "info",
        "issues": issues,
        "description": (
            "; ".join(issues) if issues else "JWT structure appears sound"
        ),
        "remediation": (
            "Use RS256/ES256. Always set exp. "
            "Never put secrets in JWT payload."
        ),
    }


@tool
async def brute_force_check(
    path: str,
    username: str,
    attempts: int = 5,
) -> dict[str, Any]:
    """Test whether the login endpoint enforces rate limiting or lockout.

    Sends `attempts` login requests with deliberately wrong passwords and
    checks whether the server responds with HTTP 429 or an account-lock
    message. Sequential requests with a 50 ms gap are used to avoid
    triggering legitimate infrastructure limits on the scan itself.

    Args:
        path:     Login endpoint path, e.g. "/login".
        username: Username to attempt logins with.
        attempts: Number of failed attempts to send (default 5).

    Returns: {check, vulnerable, rate_limited, locked_out, limit_after,
    responses, description}.
    """
    statuses: list[int] = []
    bodies: list[Any] = []
    passwords = _WRONG_PASSWORDS[: max(attempts, len(_WRONG_PASSWORDS))]

    with _tracer.start_as_current_span(
        "pentest.auth.brute_force",
        attributes={"pentest.path": path, "pentest.username": username},
    ):
        for pw in passwords[:attempts]:
            try:
                resp = await _do_http_post(
                    path,
                    body={"username": username, "password": pw},
                )
                statuses.append(resp.status)
                bodies.append(resp.body)
            except Exception as exc:
                log.debug("brute_force.error", error=str(exc))
                statuses.append(0)
                bodies.append(None)
            await asyncio.sleep(0.05)

    rate_limited = 429 in statuses
    limit_after = (
        statuses.index(429) + 1 if rate_limited else None
    )
    locked_out = any(
        isinstance(b, dict)
        and any(p in str(b).lower() for p in _LOCK_PATTERNS)
        for b in bodies
    )
    vulnerable = not rate_limited and not locked_out

    log.info(
        "tool.brute_force_check",
        path=path,
        rate_limited=rate_limited,
        locked_out=locked_out,
        vulnerable=vulnerable,
    )
    return {
        "check": "brute_force_check",
        "path": path,
        "username": username,
        "attempts_sent": len(statuses),
        "vulnerable": vulnerable,
        "severity": "high" if vulnerable else "info",
        "rate_limited": rate_limited,
        "locked_out": locked_out,
        "limit_after": limit_after,
        "statuses": statuses,
        "description": (
            f"No brute-force protection after {len(statuses)} attempts"
            if vulnerable else (
                f"Rate-limited after {limit_after} attempts"
                if rate_limited else
                "Account lockout triggered"
            )
        ),
        "remediation": (
            "Enforce account lockout or exponential back-off. "
            "Return HTTP 429 with Retry-After for repeated failures."
        ),
    }


@tool
async def session_fixation_check(
    path: str,
    username: str,
    password: str,
) -> dict[str, Any]:
    """Check whether session cookies change after authentication.

    Sends GET `path` to collect any pre-auth cookie, then POST to
    authenticate. If the session ID in Set-Cookie does not change after
    login, session fixation may be possible. For pure-JWT APIs without
    cookies this check is marked as not-applicable (not vulnerable).

    Args:
        path:     Login endpoint path, e.g. "/login".
        username: Valid username.
        password: Valid password.

    Returns: {check, vulnerable, session_changes, pre_auth_cookie,
    post_auth_cookie, description}.
    """
    with _tracer.start_as_current_span(
        "pentest.auth.session_fixation",
        attributes={"pentest.path": path},
    ):
        pre_resp = await _do_http_get(path)
        pre_cookie = pre_resp.headers.get("set-cookie", "")

        post_resp = await _do_http_post(
            path,
            body={"username": username, "password": password},
        )
        post_cookie = post_resp.headers.get("set-cookie", "")

    def _sid(cookie: str) -> str:
        for seg in cookie.split(";"):
            seg = seg.strip()
            if "=" in seg:
                name, _, val = seg.partition("=")
                if any(
                    s in name.lower()
                    for s in ("session", "sid", "token")
                ):
                    return val
        return ""

    pre_sid = _sid(pre_cookie)
    post_sid = _sid(post_cookie)

    if not pre_cookie:
        vulnerable = False
        session_changes = True
        note = (
            "No pre-auth cookie; JWT-based auth not vulnerable "
            "to session fixation"
        )
    elif pre_sid and post_sid and pre_sid == post_sid:
        vulnerable = True
        session_changes = False
        note = "Session ID unchanged after authentication"
    else:
        vulnerable = False
        session_changes = True
        note = "Session ID replaced after authentication"

    log.info(
        "tool.session_fixation_check",
        path=path,
        vulnerable=vulnerable,
        session_changes=session_changes,
    )
    return {
        "check": "session_fixation_check",
        "path": path,
        "vulnerable": vulnerable,
        "severity": "high" if vulnerable else "info",
        "session_changes": session_changes,
        "pre_auth_cookie": pre_cookie[:120] or None,
        "post_auth_cookie": post_cookie[:120] or None,
        "note": note,
        "description": note,
        "remediation": (
            "Regenerate the session ID upon successful authentication. "
            "Use session.regenerate() or equivalent in your framework."
        ),
    }


@tool
def token_entropy_check(token: str) -> dict[str, Any]:
    """Analyse the entropy and length of a session token or API key.

    Calculates Shannon entropy (bits per character) and total bits of
    randomness. Tokens with fewer than 128 bits of entropy or a very
    small character set are considered weak.

    Args:
        token: The raw token / key string to analyse.

    Returns: {check, length, unique_chars, entropy_per_char,
    total_bits, strength, issues, description}.
    """
    issues: list[str] = []
    length = len(token)
    unique = len(set(token))
    per_char = _shannon_entropy(token)
    total_bits = per_char * length

    if length < 16:
        issues.append(f"Token length {length} is below 16 characters")
    if unique < 10:
        issues.append(
            f"Only {unique} unique characters — low character diversity"
        )
    if total_bits < 64:
        issues.append(
            f"Total entropy ~{total_bits:.1f} bits — very weak"
        )
    elif total_bits < 128:
        issues.append(
            f"Total entropy ~{total_bits:.1f} bits — below 128 bit target"
        )

    if total_bits >= 128 and not issues:
        strength = "strong"
    elif total_bits >= 64:
        strength = "weak"
    else:
        strength = "very_weak"

    vulnerable = strength in ("weak", "very_weak")
    log.info(
        "tool.token_entropy_check",
        length=length,
        total_bits=round(total_bits, 1),
        strength=strength,
    )
    return {
        "check": "token_entropy_check",
        "vulnerable": vulnerable,
        "severity": "medium" if vulnerable else "info",
        "length": length,
        "unique_chars": unique,
        "entropy_per_char": round(per_char, 2),
        "total_bits": round(total_bits, 1),
        "strength": strength,
        "issues": issues,
        "description": (
            "; ".join(issues) if issues else
            f"Token entropy looks adequate ({total_bits:.1f} bits)"
        ),
        "remediation": (
            "Use a cryptographically secure random generator "
            "(e.g. secrets.token_urlsafe(32)). "
            "Aim for at least 128 bits of entropy."
        ),
    }


AUTH_TOOLS = [
    login_tool,
    me_tool,
    change_password_tool,
    logout_tool,
    jwt_analyze,
    brute_force_check,
    session_fixation_check,
    token_entropy_check,
]
