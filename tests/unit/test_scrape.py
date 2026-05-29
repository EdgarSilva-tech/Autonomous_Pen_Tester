"""Unit tests for agent/scrape.py.

Groups:
  - Static HTML parsing (pure Python, no network I/O)
      - SPA detection via BeautifulSoup
      - Form extraction
      - JS bundle regex patterns
  - compare_scrape_fingerprints (pure Python)
  - scrape_frontend() with httpx mocked (no Playwright service)
"""
from __future__ import annotations

import pytest
import respx
from httpx import Response

from agent.scrape import (
    ScrapeFingerprint,
    ScrapeFormField,
    ScrapeFormInfo,
    compare_scrape_fingerprints,
)

BASE_URL = "http://test-target:8000"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _soup(html: str):
    from bs4 import BeautifulSoup
    return BeautifulSoup(html, "lxml")


def _empty_fp(has_html: bool = True) -> ScrapeFingerprint:
    return ScrapeFingerprint(
        probed_at="2026-05-23T10:00:00+00:00",
        has_html_frontend=has_html,
    )


def _fp_with_form(action: str, fields: list[str]) -> ScrapeFingerprint:
    fp = _empty_fp()
    fp.static_forms = [
        ScrapeFormInfo(
            action=action,
            method="POST",
            fields=[ScrapeFormField(name=f) for f in fields],
        )
    ]
    return fp


# ── SPA detection ─────────────────────────────────────────────────────────────

def test_spa_detection_empty_root_div():
    from agent.scrape import _detect_spa_from_soup
    html = "<html><body><div id='root'></div></body></html>"
    assert _detect_spa_from_soup(_soup(html)) is True


def test_spa_detection_populated_root_is_not_spa():
    """A server-rendered root with content is not treated as an empty SPA shell."""
    from agent.scrape import _detect_spa_from_soup
    content = "x" * 100
    html = f"<html><body><div id='root'>{content}</div></body></html>"
    assert _detect_spa_from_soup(_soup(html)) is False


def test_spa_detection_angular():
    from agent.scrape import _detect_spa_from_soup
    html = "<html><body><app-root ng-version='17.0.0'></app-root></body></html>"
    assert _detect_spa_from_soup(_soup(html)) is True


def test_spa_detection_react_inline_script():
    from agent.scrape import _detect_spa_from_soup
    html = "<html><body><script>window.__NEXT_DATA__ = {}</script></body></html>"
    assert _detect_spa_from_soup(_soup(html)) is True


def test_spa_detection_plain_html_is_not_spa():
    from agent.scrape import _detect_spa_from_soup
    html = """
    <html><body>
      <h1>Login</h1>
      <form action='/login' method='post'>
        <input name='username'><input name='password' type='password'>
        <button type='submit'>Login</button>
      </form>
    </body></html>
    """
    assert _detect_spa_from_soup(_soup(html)) is False


# ── Form extraction ───────────────────────────────────────────────────────────

def test_extract_static_forms_basic():
    from agent.scrape import _extract_static_forms
    html = """
    <html><body>
      <form action='/login' method='POST'>
        <input name='username' type='text' required>
        <input name='password' type='password' required>
        <input name='remember' type='checkbox'>
        <button type='submit'>Login</button>
      </form>
    </body></html>
    """
    forms = _extract_static_forms(_soup(html), BASE_URL)
    assert len(forms) == 1
    field_names = [f.name for f in forms[0].fields]
    assert "username" in field_names
    assert "password" in field_names
    assert "remember" in field_names


def test_extract_static_forms_required_flag():
    from agent.scrape import _extract_static_forms
    html = """
    <html><body>
      <form action='/login' method='post'>
        <input name='username' required>
        <input name='totp_code'>
      </form>
    </body></html>
    """
    forms = _extract_static_forms(_soup(html), BASE_URL)
    fields = {f.name: f for f in forms[0].fields}
    assert fields["username"].required is True
    assert fields["totp_code"].required is False


def test_extract_static_forms_multiple_forms():
    from agent.scrape import _extract_static_forms
    html = """
    <html><body>
      <form action='/login' method='post'>
        <input name='username'>
        <input name='password' type='password'>
      </form>
      <form action='/register' method='post'>
        <input name='email' type='email'>
        <input name='password' type='password'>
      </form>
    </body></html>
    """
    forms = _extract_static_forms(_soup(html), BASE_URL)
    assert len(forms) == 2
    actions = [f.action for f in forms]
    assert any("/login" in a for a in actions)
    assert any("/register" in a for a in actions)


def test_extract_static_forms_no_forms():
    from agent.scrape import _extract_static_forms
    html = "<html><body><p>No forms here</p></body></html>"
    forms = _extract_static_forms(_soup(html), BASE_URL)
    assert forms == []


# ── JS bundle analysis ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_analyze_js_bundle_fetch_pattern():
    from agent.scrape import _analyze_js_bundle
    js = "fetch('/api/login', {method:'POST', body: JSON.stringify(data)})"

    with respx.mock() as router:
        router.get("http://test-target:8000/main.js").mock(
            return_value=Response(200, text=js,
                                  headers={"content-type": "application/javascript"})
        )
        import httpx
        async with httpx.AsyncClient() as client:
            urls = await _analyze_js_bundle(
                "http://test-target:8000/main.js", client
            )

    assert "/api/login" in urls


@pytest.mark.asyncio
async def test_analyze_js_bundle_axios_pattern():
    from agent.scrape import _analyze_js_bundle
    js = "axios.post('/auth/token', payload)"

    with respx.mock() as router:
        router.get("http://test-target:8000/chunk.js").mock(
            return_value=Response(200, text=js,
                                  headers={"content-type": "application/javascript"})
        )
        import httpx
        async with httpx.AsyncClient() as client:
            urls = await _analyze_js_bundle(
                "http://test-target:8000/chunk.js", client
            )

    assert "/auth/token" in urls


@pytest.mark.asyncio
async def test_analyze_js_bundle_baseurl_pattern():
    from agent.scrape import _analyze_js_bundle
    js = "const client = axios.create({baseURL: '/api/v2', timeout: 5000})"

    with respx.mock() as router:
        router.get("http://test-target:8000/app.js").mock(
            return_value=Response(200, text=js,
                                  headers={"content-type": "application/javascript"})
        )
        import httpx
        async with httpx.AsyncClient() as client:
            urls = await _analyze_js_bundle(
                "http://test-target:8000/app.js", client
            )

    assert "/api/v2" in urls


@pytest.mark.asyncio
async def test_analyze_js_bundle_skips_template_strings():
    """Paths containing ${} or { should be filtered out as noise."""
    from agent.scrape import _analyze_js_bundle
    js = "fetch(`/api/${version}/users`)"

    with respx.mock() as router:
        router.get("http://test-target:8000/app.js").mock(
            return_value=Response(200, text=js)
        )
        import httpx
        async with httpx.AsyncClient() as client:
            urls = await _analyze_js_bundle(
                "http://test-target:8000/app.js", client
            )

    # Template string should not appear as a clean path
    assert not any("${" in u for u in urls)


@pytest.mark.asyncio
async def test_analyze_js_bundle_404_returns_empty():
    from agent.scrape import _analyze_js_bundle

    with respx.mock() as router:
        router.get("http://test-target:8000/missing.js").mock(
            return_value=Response(404)
        )
        import httpx
        async with httpx.AsyncClient() as client:
            urls = await _analyze_js_bundle(
                "http://test-target:8000/missing.js", client
            )

    assert urls == []


# ── compare_scrape_fingerprints ───────────────────────────────────────────────

def test_compare_no_html_frontend_returns_empty():
    prev = _empty_fp(has_html=False)
    curr = _empty_fp(has_html=False)
    assert compare_scrape_fingerprints(prev, curr) == []


def test_compare_none_previous_returns_empty():
    curr = _fp_with_form("/login", ["username", "password"])
    assert compare_scrape_fingerprints(None, curr) == []


def test_compare_new_form_field_detected():
    prev = _fp_with_form("/login", ["username", "password"])
    curr = _fp_with_form("/login", ["username", "password", "totp_code"])
    diffs = compare_scrape_fingerprints(prev, curr)
    assert any("totp_code" in d for d in diffs)
    assert any("new field" in d.lower() for d in diffs)


def test_compare_removed_form_field_detected():
    prev = _fp_with_form("/login", ["username", "password", "remember_me"])
    curr = _fp_with_form("/login", ["username", "password"])
    diffs = compare_scrape_fingerprints(prev, curr)
    assert any("remember_me" in d for d in diffs)


def test_compare_form_removed_entirely():
    prev = _fp_with_form("/login", ["username", "password"])
    curr = _empty_fp()
    curr.static_forms = []
    diffs = compare_scrape_fingerprints(prev, curr)
    assert any("removed" in d.lower() for d in diffs)


def test_compare_new_js_api_url():
    prev = _empty_fp()
    prev.js_api_urls = ["/api/login"]
    curr = _empty_fp()
    curr.js_api_urls = ["/api/login", "/api/v2/auth"]
    diffs = compare_scrape_fingerprints(prev, curr)
    assert any("/api/v2/auth" in d for d in diffs)


def test_compare_removed_js_api_url():
    prev = _empty_fp()
    prev.js_api_urls = ["/api/login", "/api/v1/users"]
    curr = _empty_fp()
    curr.js_api_urls = ["/api/login"]
    diffs = compare_scrape_fingerprints(prev, curr)
    assert any("/api/v1/users" in d for d in diffs)


def test_compare_spa_type_change():
    prev = _empty_fp()
    prev.is_spa_static = False
    prev.is_spa_rendered = False
    curr = _empty_fp()
    curr.is_spa_static = True
    curr.is_spa_rendered = True
    diffs = compare_scrape_fingerprints(prev, curr)
    assert any("SPA" in d for d in diffs)


def test_compare_identical_fingerprints_no_diffs():
    fp = _fp_with_form("/login", ["username", "password"])
    fp.js_api_urls = ["/api/login"]
    assert compare_scrape_fingerprints(fp, fp) == []


# ── scrape_frontend — non-HTML target (fast path) ─────────────────────────────

@pytest.mark.asyncio
async def test_scrape_frontend_non_html_returns_early():
    """API-only targets (no HTML) should return has_html_frontend=False."""
    from agent.scrape import scrape_frontend

    with respx.mock(base_url=BASE_URL, assert_all_called=False) as router:
        router.get("/").mock(
            return_value=Response(200, json={"message": "API root"},
                                  headers={"content-type": "application/json"})
        )
        result = await scrape_frontend(BASE_URL)

    assert result.has_html_frontend is False
    assert result.static_forms == []
    assert result.js_api_urls == []


@pytest.mark.asyncio
async def test_scrape_frontend_html_extracts_forms():
    """Static HTML with a form should populate static_forms."""
    from agent.scrape import scrape_frontend
    import httpx

    html = """
    <html><body>
      <form action='/login' method='post'>
        <input name='username' required>
        <input name='password' type='password' required>
      </form>
    </body></html>
    """

    with respx.mock(base_url=BASE_URL, assert_all_called=False) as router:
        router.get("/").mock(
            return_value=Response(200, text=html,
                                  headers={"content-type": "text/html"})
        )
        # Playwright service not available in unit tests
        router.post("http://scraper:9222/scrape").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        result = await scrape_frontend(BASE_URL)

    assert result.has_html_frontend is True
    assert len(result.static_forms) == 1
    assert result.playwright_available is False
    field_names = [f.name for f in result.static_forms[0].fields]
    assert "username" in field_names
    assert "password" in field_names
