"""Hybrid frontend scraper for drift detection.

Two complementary layers are combined into a single ``ScrapeFingerprint``:

Layer 1 — Static analysis (always runs, zero extra dependencies)
-----------------------------------------------------------------
  1. Fetch the root URL with httpx.
  2. If Content-Type is not text/html → no frontend, return early.
  3. Parse the HTML with BeautifulSoup:
       a. Extract all <form> elements (action, method, field names/types).
       b. Detect SPA signatures (empty #root, framework markers in attributes
          or inline <script> blocks).
       c. Collect <script src="..."> paths.
  4. Download each discovered JS bundle and run a set of regex patterns to
     extract API URL strings (fetch/axios calls, baseURL config, etc.).

Layer 2 — Dynamic analysis via Playwright service (runs when available)
-----------------------------------------------------------------------
  5. POST to the Playwright microservice (scraper container at SCRAPER_BASE_URL).
  6. The service returns:
       - Forms extracted from the **rendered** DOM (after JS hydration).
       - Every network request intercepted during page load (XHR / fetch).
       - Whether the page is a SPA.
  7. Playwright results are merged into the fingerprint, preferring rendered
     data over static data for forms (more accurate for SPAs).

If the scraper service is unreachable the agent falls back to static-only
analysis and logs a warning — the fingerprint is still useful.

Comparison
----------
``compare_scrape_fingerprints`` produces a list of human-readable diff
strings covering:
  - Form action URL changes
  - Added / removed form fields (name, type)
  - New / gone API endpoints found in JS bundles
  - New / gone endpoints intercepted by Playwright
  - SPA status change (server-rendered ↔ SPA)
"""
from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from agent.logger import get_logger

log = get_logger(__name__)

SCRAPER_BASE_URL = os.getenv("SCRAPER_BASE_URL", "http://scraper:9222")
_STATIC_TIMEOUT = float(os.getenv("SCRAPER_STATIC_TIMEOUT", "5"))
_PLAYWRIGHT_TIMEOUT = float(os.getenv("SCRAPER_PLAYWRIGHT_TIMEOUT", "20"))

# Static extensions that are not API endpoints
_STATIC_EXTS = frozenset({
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".map", ".webp",
})

# Regex patterns to extract API-like paths from minified JS bundles
_JS_API_RE: list[re.Pattern] = [
    # fetch('/path') or fetch("/path") or fetch(`/path`)
    re.compile(r'fetch\s*\(\s*[`\'"](\/[^`\'"?#\s]{2,60})[`\'"]'),
    # axios.{method}('/path')
    re.compile(r'axios\s*\.\s*\w+\s*\(\s*[`\'"](\/[^`\'"?#\s]{2,60})[`\'"]'),
    # baseURL: '/path'
    re.compile(r'baseURL\s*:\s*[`\'"](\/[^`\'"?#\s]{1,40})[`\'"]', re.I),
    # Common REST-style paths with meaningful prefixes
    re.compile(
        r'[`\'"](\/(?:api|auth|v\d+|login|logout|register|user|account)'
        r'[\/\w\-]{0,50})[`\'"]'
    ),
]

# HTML markers that suggest a SPA (checked before downloading JS)
_SPA_HTML_IDS = {"root", "app", "__next", "nuxt"}
_SPA_ATTRS = {"ng-version", "data-reactroot", "data-v-app", "data-vue-app"}
_SPA_SCRIPT_STRINGS = {
    "__NEXT_DATA__", "__NUXT__", "webpackBootstrap",
    "ReactDOM", "createApp", "bootstrapApplication",
}


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class ScrapeFormField:
    name: str
    type: str = "text"
    required: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ScrapeFormField":
        return cls(**d)


@dataclass
class ScrapeFormInfo:
    action: str
    method: str = "POST"
    fields: list[ScrapeFormField] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "method": self.method,
            "fields": [f.to_dict() for f in self.fields],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ScrapeFormInfo":
        return cls(
            action=d["action"],
            method=d["method"],
            fields=[ScrapeFormField.from_dict(f) for f in d.get("fields", [])],
        )


@dataclass
class ScrapeFingerprint:
    probed_at: str
    has_html_frontend: bool

    # Static analysis results
    is_spa_static: bool = False
    static_forms: list[ScrapeFormInfo] = field(default_factory=list)
    js_api_urls: list[str] = field(default_factory=list)
    js_files_found: list[str] = field(default_factory=list)

    # Playwright results (empty if service unavailable)
    playwright_available: bool = False
    is_spa_rendered: bool = False
    rendered_forms: list[ScrapeFormInfo] = field(default_factory=list)
    intercepted_api_requests: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "probed_at": self.probed_at,
            "has_html_frontend": self.has_html_frontend,
            "is_spa_static": self.is_spa_static,
            "static_forms": [f.to_dict() for f in self.static_forms],
            "js_api_urls": self.js_api_urls,
            "js_files_found": self.js_files_found,
            "playwright_available": self.playwright_available,
            "is_spa_rendered": self.is_spa_rendered,
            "rendered_forms": [f.to_dict() for f in self.rendered_forms],
            "intercepted_api_requests": self.intercepted_api_requests,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ScrapeFingerprint":
        return cls(
            probed_at=d["probed_at"],
            has_html_frontend=d["has_html_frontend"],
            is_spa_static=d.get("is_spa_static", False),
            static_forms=[
                ScrapeFormInfo.from_dict(f) for f in d.get("static_forms", [])
            ],
            js_api_urls=d.get("js_api_urls", []),
            js_files_found=d.get("js_files_found", []),
            playwright_available=d.get("playwright_available", False),
            is_spa_rendered=d.get("is_spa_rendered", False),
            rendered_forms=[
                ScrapeFormInfo.from_dict(f) for f in d.get("rendered_forms", [])
            ],
            intercepted_api_requests=d.get("intercepted_api_requests", []),
        )


# ── Layer 1: Static HTML + JS bundle analysis ─────────────────────────────────

def _detect_spa_from_soup(soup: BeautifulSoup) -> bool:
    """Heuristically detect SPAs from static HTML."""
    # Empty root/app container (content injected at runtime)
    for id_ in _SPA_HTML_IDS:
        tag = soup.find(id=id_)
        if tag and len(tag.get_text(strip=True)) < 10:
            return True

    # Framework-specific attributes on any element
    for attr in _SPA_ATTRS:
        if soup.find(attrs={attr: True}):
            return True

    # Framework globals referenced in inline scripts
    for script in soup.find_all("script", src=False):
        content = script.string or ""
        if any(marker in content for marker in _SPA_SCRIPT_STRINGS):
            return True

    return False


def _extract_static_forms(soup: BeautifulSoup, base_url: str) -> list[ScrapeFormInfo]:
    forms: list[ScrapeFormInfo] = []
    for form in soup.find_all("form"):
        action = urljoin(base_url, form.get("action") or "")
        method = (form.get("method") or "GET").upper()
        fields = [
            ScrapeFormField(
                name=inp.get("name", ""),
                type=inp.get("type", "text"),
                required=inp.has_attr("required"),
            )
            for inp in form.find_all("input")
            if inp.get("name")
        ]
        forms.append(ScrapeFormInfo(action=action, method=method, fields=fields))
    return forms


def _collect_js_urls(soup: BeautifulSoup, base_url: str) -> list[str]:
    urls: list[str] = []
    for script in soup.find_all("script", src=True):
        src = script["src"]
        if not any(src.endswith(ext) for ext in (".css",)):
            full = urljoin(base_url, src)
            urls.append(full)
    return urls


async def _analyze_js_bundle(js_url: str, client: httpx.AsyncClient) -> list[str]:
    """Download a JS bundle and extract API path strings."""
    found: set[str] = set()
    try:
        resp = await client.get(js_url, timeout=_STATIC_TIMEOUT)
        if resp.status_code != 200:
            return []
        content = resp.text
        for pattern in _JS_API_RE:
            for match in pattern.finditer(content):
                path = match.group(1)
                # Filter noise: skip paths that look like template strings
                if "{" not in path and "$" not in path:
                    found.add(path)
        log.debug(
            "scrape.js_bundle_analyzed",
            url=js_url[-60:],
            api_paths_found=len(found),
        )
    except Exception as exc:
        log.debug("scrape.js_bundle_failed", url=js_url[-60:], error=str(exc))
    return sorted(found)


# ── Layer 2: Playwright service call ──────────────────────────────────────────

async def _call_playwright_service(
    url: str,
    client: httpx.AsyncClient,
) -> dict[str, Any] | None:
    """POST to the Playwright scraper microservice. Returns raw JSON or None."""
    try:
        resp = await client.post(
            f"{SCRAPER_BASE_URL}/scrape",
            json={"url": url, "timeout_ms": int(_PLAYWRIGHT_TIMEOUT * 1000)},
            timeout=_PLAYWRIGHT_TIMEOUT + 5,
        )
        if resp.status_code == 200:
            return resp.json()
        log.warning(
            "scrape.playwright_http_error",
            status=resp.status_code,
            body=resp.text[:200],
        )
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        log.warning("scrape.playwright_unavailable", error=str(exc))
    return None


# ── Main entry point ──────────────────────────────────────────────────────────

async def scrape_frontend(base_url: str) -> ScrapeFingerprint:
    """Produce a ScrapeFingerprint for the given target URL.

    Combines static HTML/JS analysis (always) with Playwright dynamic
    rendering (when the scraper service is reachable).
    """
    now = datetime.now(timezone.utc).isoformat()

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=_STATIC_TIMEOUT,
    ) as client:
        # ── Step 1: fetch root HTML ───────────────────────────────────────────
        try:
            root_resp = await client.get(base_url)
            content_type = root_resp.headers.get("content-type", "")
            has_html = "text/html" in content_type
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            log.warning("scrape.root_unreachable", error=str(exc))
            return ScrapeFingerprint(
                probed_at=now,
                has_html_frontend=False,
            )

        if not has_html:
            log.info(
                "scrape.no_html_frontend",
                content_type=content_type,
                target=base_url,
            )
            return ScrapeFingerprint(probed_at=now, has_html_frontend=False)

        # ── Step 2: static HTML analysis ─────────────────────────────────────
        soup = BeautifulSoup(root_resp.text, "lxml")
        is_spa_static = _detect_spa_from_soup(soup)
        static_forms = _extract_static_forms(soup, base_url)
        js_file_urls = _collect_js_urls(soup, base_url)

        log.info(
            "scrape.static_complete",
            is_spa=is_spa_static,
            forms=len(static_forms),
            js_files=len(js_file_urls),
        )

        # ── Step 3: JS bundle analysis ────────────────────────────────────────
        all_api_urls: list[str] = []
        for js_url in js_file_urls[:10]:  # cap at 10 bundles to avoid runaway
            paths = await _analyze_js_bundle(js_url, client)
            all_api_urls.extend(paths)
        all_api_urls = sorted(set(all_api_urls))

        log.info(
            "scrape.js_analysis_complete",
            bundles_analyzed=min(len(js_file_urls), 10),
            api_paths=len(all_api_urls),
        )

        # ── Step 4: Playwright dynamic analysis ───────────────────────────────
        pw_result = await _call_playwright_service(base_url, client)
        playwright_available = pw_result is not None and pw_result.get("error") is None

        rendered_forms: list[ScrapeFormInfo] = []
        intercepted_api: list[str] = []
        is_spa_rendered = is_spa_static

        if playwright_available and pw_result:
            is_spa_rendered = pw_result.get("is_spa", is_spa_static)

            for f in pw_result.get("forms", []):
                rendered_forms.append(
                    ScrapeFormInfo(
                        action=f.get("action", ""),
                        method=f.get("method", "POST"),
                        fields=[
                            ScrapeFormField(**fld)
                            for fld in f.get("fields", [])
                        ],
                    )
                )

            for req in pw_result.get("intercepted_requests", []):
                url_str = req.get("url", "")
                method = req.get("method", "GET")
                # Keep only paths relative to the target host
                parsed = urlparse(url_str)
                if parsed.netloc == urlparse(base_url).netloc:
                    intercepted_api.append(f"{method} {parsed.path}")
            intercepted_api = sorted(set(intercepted_api))

            log.info(
                "scrape.playwright_complete",
                rendered_forms=len(rendered_forms),
                intercepted_endpoints=len(intercepted_api),
                is_spa=is_spa_rendered,
            )
        else:
            log.info(
                "scrape.playwright_skipped",
                available=playwright_available,
            )

        return ScrapeFingerprint(
            probed_at=now,
            has_html_frontend=True,
            is_spa_static=is_spa_static,
            static_forms=static_forms,
            js_api_urls=all_api_urls,
            js_files_found=js_file_urls,
            playwright_available=playwright_available,
            is_spa_rendered=is_spa_rendered,
            rendered_forms=rendered_forms,
            intercepted_api_requests=intercepted_api,
        )


# ── Comparison ────────────────────────────────────────────────────────────────

def _forms_to_map(
    forms: list[ScrapeFormInfo],
) -> dict[str, ScrapeFormInfo]:
    """Key forms by their action path (last segment) for stable comparison."""
    result: dict[str, ScrapeFormInfo] = {}
    for form in forms:
        key = urlparse(form.action).path or form.action
        result[key] = form
    return result


def compare_scrape_fingerprints(
    previous: "ScrapeFingerprint | None",
    current: ScrapeFingerprint,
) -> list[str]:
    """Return a list of human-readable drift strings between two fingerprints.

    Returns an empty list if no meaningful drift is detected.
    Prefer rendered data (Playwright) over static data when available.
    """
    if previous is None or not current.has_html_frontend:
        return []

    if not previous.has_html_frontend:
        return ["Frontend appeared: target now serves HTML (previously API-only)"]

    diffs: list[str] = []

    # ── SPA type change ───────────────────────────────────────────────────────
    prev_spa = previous.is_spa_rendered or previous.is_spa_static
    curr_spa = current.is_spa_rendered or current.is_spa_static
    if prev_spa != curr_spa:
        diffs.append(
            f"App rendering changed: "
            f"{'SPA' if prev_spa else 'server-rendered'} → "
            f"{'SPA' if curr_spa else 'server-rendered'}"
        )

    # ── Form comparison (prefer rendered > static) ────────────────────────────
    prev_forms = _forms_to_map(previous.rendered_forms or previous.static_forms)
    curr_forms = _forms_to_map(current.rendered_forms or current.static_forms)

    for action, prev_form in prev_forms.items():
        if action not in curr_forms:
            diffs.append(
                f"Form removed: {prev_form.method} {action} "
                f"(had fields: {[f.name for f in prev_form.fields]})"
            )
            continue
        curr_form = curr_forms[action]
        prev_field_names = {f.name for f in prev_form.fields}
        curr_field_names = {f.name for f in curr_form.fields}
        added = curr_field_names - prev_field_names
        removed = prev_field_names - curr_field_names
        if added:
            diffs.append(
                f"Form {action}: new field(s) detected: {sorted(added)} "
                f"(possible new required parameter, e.g. 2FA token)"
            )
        if removed:
            diffs.append(
                f"Form {action}: field(s) removed: {sorted(removed)}"
            )
        # Check if field type changed (e.g. username → email)
        prev_types = {f.name: f.type for f in prev_form.fields}
        curr_types = {f.name: f.type for f in curr_form.fields}
        for name in prev_field_names & curr_field_names:
            if prev_types.get(name) != curr_types.get(name):
                diffs.append(
                    f"Form {action}: field '{name}' type changed "
                    f"{prev_types[name]} → {curr_types[name]}"
                )

    for action, curr_form in curr_forms.items():
        if action not in prev_forms:
            diffs.append(
                f"New form detected: {curr_form.method} {action} "
                f"(fields: {[f.name for f in curr_form.fields]})"
            )

    # ── JS API URL comparison ─────────────────────────────────────────────────
    prev_js = set(previous.js_api_urls)
    curr_js = set(current.js_api_urls)
    added_js = curr_js - prev_js
    removed_js = prev_js - curr_js
    if added_js:
        diffs.append(f"New API paths in JS bundles: {sorted(added_js)}")
    if removed_js:
        diffs.append(f"API paths removed from JS bundles: {sorted(removed_js)}")

    # ── Playwright intercepted endpoints ──────────────────────────────────────
    if previous.playwright_available and current.playwright_available:
        prev_intercepted = set(previous.intercepted_api_requests)
        curr_intercepted = set(current.intercepted_api_requests)
        new_ep = curr_intercepted - prev_intercepted
        gone_ep = prev_intercepted - curr_intercepted
        if new_ep:
            diffs.append(
                f"New endpoints intercepted at page load: {sorted(new_ep)}"
            )
        if gone_ep:
            diffs.append(
                f"Endpoints no longer called at page load: {sorted(gone_ep)}"
            )

    return diffs
