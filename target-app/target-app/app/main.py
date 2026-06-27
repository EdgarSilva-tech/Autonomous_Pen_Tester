"""
Target application for the Autonomous Pen Tester project.

Exposes:
  - A minimal authentication API (v1 contract).
  - Intentionally vulnerable endpoints for v2 attack-module testing.

Deliberate vulnerabilities (for testing only):
  - CORS middleware reflects any Origin with Allow-Credentials: true.
  - /api/search leaks SQL error strings when injection payloads are sent.
  - /api/users/{user_id} returns user data without authentication (IDOR).
  - /api/debug echoes a stack-trace style body on SQL-like input (error disclosure).
"""

from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass, field
from random import random
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TOKEN_TTL_SECONDS = int(os.getenv("TOKEN_TTL_SECONDS", "300"))
MAX_FAILED_LOGINS = int(os.getenv("MAX_FAILED_LOGINS", "3"))
LOCKOUT_SECONDS = int(os.getenv("LOCKOUT_SECONDS", "30"))
FLAKY_RATE = float(os.getenv("FLAKY_RATE", "0.0"))

# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------


@dataclass
class User:
    username: str
    password: str
    failed_attempts: int = 0
    locked_until: float = 0.0


@dataclass
class Session:
    token: str
    username: str
    expires_at: float


@dataclass
class State:
    users: dict[str, User] = field(default_factory=dict)
    sessions: dict[str, Session] = field(default_factory=dict)


state = State()


def _seed_users() -> None:
    """Seed the initial users. Idempotent."""
    for username, password in [("alice", "Alice#2025"), ("bob", "Bob#2025")]:
        state.users.setdefault(username, User(username=username, password=password))


_seed_users()

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class LoginResponse(BaseModel):
    token: str
    expires_in: int


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8)


class MessageResponse(BaseModel):
    message: str


class MeResponse(BaseModel):
    username: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now() -> float:
    return time.time()


def _maybe_flake() -> None:
    if FLAKY_RATE > 0 and random() < FLAKY_RATE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable",
        )


def _validate_password_strength(password: str) -> None:
    if len(password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long",
        )
    if password.lower() == password or password.upper() == password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain both uppercase and lowercase letters",
        )
    if not any(c.isdigit() for c in password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one digit",
        )


def _get_current_session(
    authorization: Annotated[str | None, Header()] = None,
) -> Session:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header",
        )
    token = authorization.split(" ", 1)[1].strip()
    session = state.sessions.get(token)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )
    if session.expires_at < _now():
        state.sessions.pop(token, None)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
        )
    return session


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------


app = FastAPI(
    title="Pentest Challenge - Target App",
    description="Authentication API and intentionally vulnerable endpoints.",
    version="2.0.0",
)


# -- CORS misconfiguration middleware ----------------------------------------
# Reflects any Origin header with Access-Control-Allow-Credentials: true.
# This is a CORS wildcard misconfiguration — intentionally vulnerable.

@app.middleware("http")
async def cors_reflect_middleware(request: Request, call_next):
    response = await call_next(request)
    origin = request.headers.get("origin")
    if origin:
        response.headers["access-control-allow-origin"] = origin
        response.headers["access-control-allow-credentials"] = "true"
        response.headers["access-control-allow-methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response


# ---------------------------------------------------------------------------
# v1 auth endpoints
# ---------------------------------------------------------------------------


@app.get("/health", response_model=MessageResponse, tags=["meta"])
def health() -> MessageResponse:
    return MessageResponse(message="ok")


@app.post("/login", response_model=LoginResponse, tags=["auth"])
def login(payload: LoginRequest) -> LoginResponse:
    _maybe_flake()

    user = state.users.get(payload.username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if user.locked_until > _now():
        retry_in = int(user.locked_until - _now())
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account locked. Retry in {retry_in}s",
        )

    if user.password != payload.password:
        user.failed_attempts += 1
        if user.failed_attempts >= MAX_FAILED_LOGINS:
            user.locked_until = _now() + LOCKOUT_SECONDS
            user.failed_attempts = 0
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    user.failed_attempts = 0
    user.locked_until = 0.0
    token = secrets.token_urlsafe(32)
    session = Session(
        token=token,
        username=user.username,
        expires_at=_now() + TOKEN_TTL_SECONDS,
    )
    state.sessions[token] = session
    return LoginResponse(token=token, expires_in=TOKEN_TTL_SECONDS)


@app.post("/change-password", response_model=MessageResponse, tags=["auth"])
def change_password(
    payload: ChangePasswordRequest,
    session: Annotated[Session, Depends(_get_current_session)],
) -> MessageResponse:
    _maybe_flake()

    user = state.users[session.username]

    if user.password != payload.current_password:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Current password is incorrect",
        )

    if payload.new_password == payload.current_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must differ from current password",
        )

    _validate_password_strength(payload.new_password)

    user.password = payload.new_password

    to_remove = [
        tok for tok, s in state.sessions.items() if s.username == user.username
    ]
    for tok in to_remove:
        state.sessions.pop(tok, None)

    return MessageResponse(message="Password changed successfully")


@app.post("/logout", response_model=MessageResponse, tags=["auth"])
def logout(
    session: Annotated[Session, Depends(_get_current_session)],
) -> MessageResponse:
    _maybe_flake()
    state.sessions.pop(session.token, None)
    return MessageResponse(message="Logged out")


@app.get("/me", response_model=MeResponse, tags=["auth"])
def me(
    session: Annotated[Session, Depends(_get_current_session)],
) -> MeResponse:
    _maybe_flake()
    return MeResponse(username=session.username)


@app.post("/_admin/reset", response_model=MessageResponse, tags=["admin"])
def reset() -> MessageResponse:
    """Reset all in-memory state to seed values."""
    state.users.clear()
    state.sessions.clear()
    _seed_users()
    return MessageResponse(message="State reset")


# ---------------------------------------------------------------------------
# v2 intentionally vulnerable endpoints
# ---------------------------------------------------------------------------


@app.get("/api/search", tags=["vulnerable"])
def search(q: str = "") -> dict:
    """SQL injection vulnerable: leaks DB error strings on injection payloads."""
    _SQL_CHARS = ("'", '"', "--", " OR ", " AND ", ";")
    if any(c in q for c in _SQL_CHARS):
        raise HTTPException(
            status_code=500,
            detail=f"sqlite_error: near \"{q}\": syntax error in SELECT * FROM users WHERE name = '{q}'",
        )
    results = [u for u in state.users if q.lower() in u.lower()]
    return {"results": results, "query": q}


@app.get("/api/users/{user_id}", tags=["vulnerable"])
def get_user(user_id: str) -> dict:
    """IDOR: returns user data without any authentication check."""
    user = state.users.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "username": user.username,
        "email": f"{user.username}@example.com",
        "role": "user",
    }


@app.get("/api/debug", tags=["vulnerable"])
@app.post("/api/debug", tags=["vulnerable"])
async def debug(request: Request, id: str = "") -> JSONResponse:
    """Error disclosure: leaks stack traces on SQL-like input."""
    _SQL_CHARS = ("'", '"', "--", "OR", "AND")
    if any(c in id for c in _SQL_CHARS):
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal Server Error",
                "traceback": (
                    "Traceback (most recent call last):\n"
                    "  File \"/app/main.py\", line 42, in process_id\n"
                    f"    cursor.execute(\"SELECT * FROM logs WHERE id = {id}\")\n"
                    "sqlite3.OperationalError: unrecognized token"
                ),
                "stack trace": f"at process_id(main.py:42)",
            },
        )
    return JSONResponse(status_code=200, content={"status": "ok", "id": id})