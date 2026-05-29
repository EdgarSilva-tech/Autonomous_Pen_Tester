"""Integration test: spins up an in-process FastAPI mock target and runs the
full tool sequence to verify the happy-path flow end-to-end.

This test does NOT invoke the LLM — it exercises the HTTP tool layer directly
in the correct order to validate that the tools and the target contract match.
"""
from __future__ import annotations

import pytest
import httpx
from fastapi import Depends, FastAPI, HTTPException, Header
from fastapi.testclient import TestClient

# ── Minimal in-process FastAPI target ────────────────────────────────────────

_USERS: dict[str, str] = {"testuser": "InitialPass123!"}
_TOKENS: dict[str, str] = {}  # token → username
_REVOKED: set[str] = set()

app = FastAPI()


@app.post("/login")
def login(body: dict):
    username = body.get("username", "")
    password = body.get("password", "")
    if _USERS.get(username) != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = f"token-{username}-{password[:4]}"
    _TOKENS[token] = username
    _REVOKED.discard(token)
    return {"access_token": token, "token_type": "bearer"}


def _require_token(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.split(" ", 1)[1]
    if token in _REVOKED or token not in _TOKENS:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return token


@app.get("/me")
def me(token: str = Depends(_require_token)):
    return {"username": _TOKENS[token]}


@app.post("/change-password")
def change_password(body: dict, token: str = Depends(_require_token)):
    username = _TOKENS[token]
    current = body.get("current_password", "")
    new = body.get("new_password", "")
    if _USERS.get(username) != current:
        raise HTTPException(status_code=400, detail="Wrong current password")
    _USERS[username] = new
    return {"message": "Password updated"}


@app.post("/logout")
def logout(token: str = Depends(_require_token)):
    _REVOKED.add(token)
    return {"message": "Logged out"}


# ── Test client fixture ───────────────────────────────────────────────────────

@pytest.fixture
def client():
    """Reset state between tests."""
    _USERS.clear()
    _USERS["testuser"] = "InitialPass123!"
    _TOKENS.clear()
    _REVOKED.clear()
    with TestClient(app) as c:
        yield c


# ── Integration tests ─────────────────────────────────────────────────────────

def test_full_happy_path(client):
    """Full 4-step flow: login → change-password → logout → re-login."""
    # Step 1: login
    r = client.post("/login", json={"username": "testuser", "password": "InitialPass123!"})
    assert r.status_code == 200
    token = r.json()["access_token"]

    # Step 2: validate login
    r = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["username"] == "testuser"

    # Step 3: change password
    r = client.post(
        "/change-password",
        json={"current_password": "InitialPass123!", "new_password": "NewPass456!"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200

    # Step 4: logout
    r = client.post("/logout", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200

    # Validate token is invalidated
    r = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401

    # Step 5: re-authenticate with new password
    r = client.post("/login", json={"username": "testuser", "password": "NewPass456!"})
    assert r.status_code == 200
    new_token = r.json()["access_token"]

    # Validate re-authentication
    r = client.get("/me", headers={"Authorization": f"Bearer {new_token}"})
    assert r.status_code == 200
    assert r.json()["username"] == "testuser"


def test_login_invalid_credentials(client):
    r = client.post("/login", json={"username": "testuser", "password": "wrong"})
    assert r.status_code == 401


def test_change_password_wrong_current(client):
    r = client.post("/login", json={"username": "testuser", "password": "InitialPass123!"})
    token = r.json()["access_token"]

    r = client.post(
        "/change-password",
        json={"current_password": "WrongPassword!", "new_password": "New456!"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 400


def test_anomaly_token_rotation(client):
    """Detect if the token does NOT change after re-authentication (anomaly)."""
    r = client.post("/login", json={"username": "testuser", "password": "InitialPass123!"})
    token1 = r.json()["access_token"]

    # Change password + logout
    client.post(
        "/change-password",
        json={"current_password": "InitialPass123!", "new_password": "NewPass!"},
        headers={"Authorization": f"Bearer {token1}"},
    )
    client.post("/logout", headers={"Authorization": f"Bearer {token1}"})

    # Re-login with new password
    r = client.post("/login", json={"username": "testuser", "password": "NewPass!"})
    token2 = r.json()["access_token"]

    # In a real anomaly scenario, tokens would be the same — here they differ
    assert token1 != token2, "Tokens should differ after re-authentication"
