"""Shared pytest fixtures."""
import pytest
import respx


BASE_URL = "http://test-target:8000"
TOKEN = "test-token-abc123"
NEW_TOKEN = "test-token-xyz789"
USERNAME = "testuser"
PASSWORD = "InitialPass123!"
NEW_PASSWORD = "NewPass456!"


@pytest.fixture(autouse=True)
def set_test_base_url(monkeypatch):
    """Point all HTTP tools at the mock base URL."""
    monkeypatch.setenv("TARGET_BASE_URL", BASE_URL)
    from agent.tools import set_base_url
    set_base_url(BASE_URL)


@pytest.fixture
def mock_router():
    """Return an active respx router that mocks the target app endpoints."""
    with respx.mock(base_url=BASE_URL, assert_all_called=False) as router:
        yield router
