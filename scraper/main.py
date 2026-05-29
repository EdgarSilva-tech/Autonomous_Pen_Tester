"""Playwright scraper microservice.

Exposes a single POST /scrape endpoint that:
  1. Launches a headless Chromium page
  2. Intercepts every network request (captures method + URL + resource type)
  3. Navigates to the target URL and waits for networkidle
  4. Extracts all rendered forms and their input fields from the live DOM
  5. Detects whether the page is a SPA (React / Vue / Angular / Next.js / Nuxt)
  6. Returns a structured JSON payload

A shared Browser instance is kept alive for the lifetime of the service
(created during startup, closed on shutdown). Each scrape request creates
a new BrowserContext so cookies / localStorage are fully isolated.

Observability
-------------
  - structlog JSON lines on every request — consistent format with the agent.
  - OpenTelemetry spans exported via OTLP gRPC to the otel-collector.
  - Incoming W3C TraceContext headers (traceparent / tracestate) are
    propagated automatically by FastAPIInstrumentor, so scraper spans appear
    as children of the agent's outgoing `POST /scrape` span in Grafana Tempo.
  - Manual child spans are created for: browser context setup, page.goto,
    DOM extraction, and network filtering — giving per-phase latency detail.
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import Any

import structlog
from fastapi import FastAPI, Request
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from playwright.async_api import Browser, async_playwright
from pydantic import BaseModel

# ── Logging setup ─────────────────────────────────────────────────────────


def _setup_logging() -> None:
    """Configure structlog to emit JSON lines, mirroring the agent's format."""
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(message)s",
    )
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
    )


_setup_logging()
log = structlog.get_logger("scraper")


# ── OpenTelemetry setup ───────────────────────────────────────────────────

def _setup_telemetry() -> None:
    """Initialise OTel SDK and export spans to the otel-collector."""
    otlp_endpoint = os.getenv(
        "OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317"
    )
    resource = Resource.create(
        {"service.name": os.getenv("OTEL_SERVICE_NAME", "scraper")}
    )
    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    log.info(
        "scraper.telemetry_ready",
        otlp_endpoint=otlp_endpoint,
    )


_setup_telemetry()
_tracer = trace.get_tracer("scraper")


# ── Static asset extensions to exclude from intercepted requests ────────────
_STATIC_EXTS = frozenset({
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map",
    ".webp", ".avif",
})

_API_RESOURCE_TYPES = frozenset({"fetch", "xhr", "document"})

# ── Shared browser (created once at startup) ────────────────────────────────
_browser: Browser | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _browser
    async with async_playwright() as pw:
        _browser = await pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        log.info("scraper.browser_ready", browser="chromium")
        yield
        await _browser.close()
        _browser = None
        log.info("scraper.browser_closed")


app = FastAPI(title="Playwright Scraper", lifespan=lifespan)
FastAPIInstrumentor.instrument_app(app)


# ── Request / Response models ───────────────────────────────────────────────

class ScrapeRequest(BaseModel):
    url: str
    timeout_ms: int = 15_000


class FormField(BaseModel):
    name: str
    type: str = "text"
    required: bool = False


class FormInfo(BaseModel):
    action: str
    method: str = "POST"
    fields: list[FormField] = []


class InterceptedRequest(BaseModel):
    method: str
    url: str
    resource_type: str


class ScrapeResult(BaseModel):
    url: str
    is_spa: bool
    page_title: str
    forms: list[FormInfo] = []
    intercepted_requests: list[InterceptedRequest] = []
    error: str | None = None


# ── JS evaluated inside the page ────────────────────────────────────────────

_EXTRACT_FORMS_JS = """() => {
    return Array.from(document.forms).map(form => ({
        action: form.action || '',
        method: (form.method || 'GET').toUpperCase(),
        fields: Array.from(form.elements)
            .filter(el => el.tagName === 'INPUT' && el.name)
            .map(el => ({
                name: el.name,
                type: el.type || 'text',
                required: el.required || false
            }))
    }));
}"""

_DETECT_SPA_JS = """() => {
    const root = document.getElementById('root') || document.getElementById('app');
    if (root && root.innerHTML.trim().length > 50) return true;
    if (document.querySelector('[ng-version]')) return true;
    if (document.querySelector('[data-reactroot]')) return true;
    if (typeof window.__NEXT_DATA__ !== 'undefined') return true;
    if (typeof window.__NUXT__ !== 'undefined') return true;
    if (document.querySelector('[data-v-app]')) return true;
    return false;
}"""


# ── Endpoints ───────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict[str, Any]:
    ready = _browser is not None
    log.debug("scraper.health_check", browser_ready=ready)
    return {"ok": ready, "browser_ready": ready}


@app.post("/scrape", response_model=ScrapeResult)
async def scrape(req: ScrapeRequest, request: Request) -> ScrapeResult:
    """Render a page with Playwright and return forms + intercepted requests.
    """
    bound = log.bind(url=req.url, timeout_ms=req.timeout_ms)

    if _browser is None:
        bound.warning("scraper.browser_not_ready")
        return ScrapeResult(
            url=req.url,
            is_spa=False,
            page_title="",
            error="Browser not initialised — service is starting up",
        )

    intercepted: list[dict[str, str]] = []

    with _tracer.start_as_current_span("scrape") as span:
        span.set_attribute("scraper.url", req.url)
        span.set_attribute("scraper.timeout_ms", req.timeout_ms)

        try:
            # ── Browser context ───────────────────────────────────────────
            with _tracer.start_as_current_span("browser.new_context"):
                ctx = await _browser.new_context(
                    ignore_https_errors=True,
                    java_script_enabled=True,
                )
                page = await ctx.new_page()

            page.on(
                "request",
                lambda r: intercepted.append({
                    "method": r.method,
                    "url": r.url,
                    "resource_type": r.resource_type,
                }),
            )

            # ── Page navigation ───────────────────────────────────────────
            bound.info("scraper.navigating")
            with _tracer.start_as_current_span("page.goto") as nav_span:
                nav_span.set_attribute("scraper.wait_until", "networkidle")
                await page.goto(
                    req.url,
                    wait_until="networkidle",
                    timeout=req.timeout_ms,
                )

            # ── DOM extraction ────────────────────────────────────────────
            with _tracer.start_as_current_span("page.extract_dom"):
                title: str = await page.title()
                forms_raw: list[dict] = await page.evaluate(_EXTRACT_FORMS_JS)
                is_spa: bool = await page.evaluate(_DETECT_SPA_JS)

            await ctx.close()

            # ── Filter network requests ───────────────────────────────────
            with _tracer.start_as_current_span("filter.requests"):
                api_requests = [
                    InterceptedRequest(**r)
                    for r in intercepted
                    if r["resource_type"] in _API_RESOURCE_TYPES
                    and not any(
                        r["url"].split("?")[0].endswith(ext)
                        for ext in _STATIC_EXTS
                    )
                ]

            span.set_attribute("scraper.is_spa", is_spa)
            span.set_attribute("scraper.forms_found", len(forms_raw))
            span.set_attribute("scraper.api_requests", len(api_requests))
            span.set_attribute("scraper.total_requests", len(intercepted))

            bound.info(
                "scraper.complete",
                is_spa=is_spa,
                forms=len(forms_raw),
                api_requests=len(api_requests),
                total_intercepted=len(intercepted),
                page_title=title,
            )

            return ScrapeResult(
                url=req.url,
                is_spa=is_spa,
                page_title=title,
                forms=[
                    FormInfo(
                        action=f.get("action", ""),
                        method=f.get("method", "POST"),
                        fields=[FormField(**fld) for fld in f.get("fields", [])],
                    )
                    for f in forms_raw
                ],
                intercepted_requests=api_requests,
            )

        except Exception as exc:
            span.record_exception(exc)
            span.set_attribute("scraper.error", str(exc))
            bound.error("scraper.error", error=str(exc))
            return ScrapeResult(
                url=req.url,
                is_spa=False,
                page_title="",
                error=str(exc),
            )
