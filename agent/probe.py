"""Site fingerprint probe — detects structural changes between runs.

Three complementary fingerprinting strategies are combined:

1. OpenAPI schema (always attempted first)
   Fetches /openapi.json and records all paths, methods, and parameter
   schemas. Enables drift detection at the contract level (new/removed
   endpoints, changed request/response shapes) and enriches the LLM
   system prompt with real endpoint documentation.

2. API probe (always)
   Sends unauthenticated HTTP requests to key endpoints and records status
   codes and JSON response schemas. Fast and always applicable regardless
   of whether the target has a HTML frontend.

3. Frontend scrape (optional, via agent.scrape)
   Fetches the root HTML page, analyses JS bundles for API paths, and
   optionally calls the Playwright microservice for dynamic DOM rendering
   and network interception. Only activates when the target serves HTML.

The combined ``SiteFingerprint`` is stored in pgvector metadata at the
end of each run. At the start of the next run it is retrieved and compared
with the freshly produced fingerprint. Any drift is formatted as a
``drift_context`` string and injected into the LLM system prompt.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx
from opentelemetry import trace

from agent.logger import get_logger
from agent.scrape import (
    ScrapeFingerprint,
    compare_scrape_fingerprints,
    scrape_frontend,
)

log = get_logger(__name__)
_tracer = trace.get_tracer("agent.probe")

# Endpoints to probe — (method, path, body)
# All sent without an Authorization header.
_PROBES: list[tuple[str, str, dict[str, Any]]] = [
    ("POST", "/login",           {"username": "__probe__", "password": "__probe__"}),
    ("GET",  "/me",              {}),
    ("POST", "/change-password", {}),
    ("POST", "/logout",          {}),
]

_PROBE_TIMEOUT = 5.0  # seconds per request


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class EndpointProbe:
    method: str
    path: str
    status: int | None          # None = connection error / unreachable
    has_json_body: bool = False
    json_keys: list[str] = field(default_factory=list)

    def key(self) -> str:
        return f"{self.method} {self.path}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "status": self.status,
            "has_json_body": self.has_json_body,
            "json_keys": self.json_keys,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "EndpointProbe":
        return cls(**d)


@dataclass
class OpenAPIFingerprint:
    """Lightweight summary of a fetched OpenAPI schema for fingerprinting."""
    title: str
    version: str
    # {method path} → sorted list of parameter names, e.g. {"POST /login": ["password", "username"]}
    operations: dict[str, list[str]] = field(default_factory=dict)
    # raw schema kept for prompt enrichment (None if unreachable)
    raw: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "version": self.version,
            "operations": self.operations,
            # raw schema can be large — store it but serialise compactly
            "raw": self.raw,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "OpenAPIFingerprint":
        return cls(
            title=d.get("title", ""),
            version=d.get("version", ""),
            operations=d.get("operations", {}),
            raw=d.get("raw"),
        )


@dataclass
class SiteFingerprint:
    target_url: str
    probed_at: str
    endpoints: dict[str, EndpointProbe] = field(default_factory=dict)
    scrape: ScrapeFingerprint | None = None
    openapi: OpenAPIFingerprint | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "probed_at": self.probed_at,
            "endpoints": {k: v.to_dict() for k, v in self.endpoints.items()},
            "scrape": self.scrape.to_dict() if self.scrape else None,
            "openapi": self.openapi.to_dict() if self.openapi else None,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SiteFingerprint":
        endpoints = {
            k: EndpointProbe.from_dict(v)
            for k, v in d.get("endpoints", {}).items()
        }
        scrape_raw = d.get("scrape")
        scrape = ScrapeFingerprint.from_dict(scrape_raw) if scrape_raw else None
        openapi_raw = d.get("openapi")
        openapi = OpenAPIFingerprint.from_dict(openapi_raw) if openapi_raw else None
        return cls(
            target_url=d["target_url"],
            probed_at=d["probed_at"],
            endpoints=endpoints,
            scrape=scrape,
            openapi=openapi,
        )


# ── Probe ─────────────────────────────────────────────────────────────────────

async def _fetch_openapi(
    base_url: str,
    timeout: float,
) -> OpenAPIFingerprint | None:
    """Fetch and parse /openapi.json from the target.

    Returns None if the endpoint is absent or returns malformed JSON.
    Operations are extracted as {METHOD PATH} → sorted list of body/query
    param names so that schema drift is easy to diff later.
    """
    try:
        async with httpx.AsyncClient(base_url=base_url, timeout=timeout) as client:
            resp = await client.get("/openapi.json")
        if not resp.is_success:
            log.info("probe.openapi_unavailable", status=resp.status_code)
            return None

        schema = resp.json()
        info = schema.get("info", {})
        operations: dict[str, list[str]] = {}

        for path, path_item in schema.get("paths", {}).items():
            for method, operation in path_item.items():
                if method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                    continue
                key = f"{method.upper()} {path}"
                params: list[str] = []
                # query / path parameters
                for p in operation.get("parameters", []):
                    params.append(p.get("name", ""))
                # request body properties
                body = operation.get("requestBody", {})
                for media in body.get("content", {}).values():
                    props = (
                        media.get("schema", {})
                        .get("properties", {})
                    )
                    params.extend(props.keys())
                operations[key] = sorted(set(params))

        fp = OpenAPIFingerprint(
            title=info.get("title", ""),
            version=info.get("version", ""),
            operations=operations,
            raw=schema,
        )
        log.info(
            "probe.openapi_fetched",
            title=fp.title,
            version=fp.version,
            operation_count=len(operations),
        )
        return fp

    except Exception as exc:
        log.warning("probe.openapi_error", error=str(exc))
        return None


async def probe_site(
    base_url: str,
    timeout: float = _PROBE_TIMEOUT,
) -> SiteFingerprint:
    """Probe the target and produce a full SiteFingerprint.

    Runs the OpenAPI fetch, the API endpoint probe, and the frontend
    scraper. Individual failures are logged and never raise — the
    fingerprint is always returned with whatever data was collected.
    """
    with _tracer.start_as_current_span(
        "agent.probe",
        attributes={
            "probe.target": base_url,
            "probe.note": (
                "Unauthenticated reachability check — 401/404 responses are expected"
            ),
        },
    ):
        return await _probe_site_inner(base_url, timeout)


async def _probe_site_inner(
    base_url: str,
    timeout: float,
) -> SiteFingerprint:
    fp = SiteFingerprint(
        target_url=base_url,
        probed_at=datetime.now(timezone.utc).isoformat(),
    )

    # ── OpenAPI schema fetch ──────────────────────────────────────────────────
    fp.openapi = await _fetch_openapi(base_url, timeout)

    # ── API endpoint probes ───────────────────────────────────────────────────
    async with httpx.AsyncClient(
        base_url=base_url,
        timeout=timeout,
        follow_redirects=True,
    ) as client:
        for method, path, body in _PROBES:
            key = f"{method} {path}"
            try:
                if method == "GET":
                    resp = await client.get(path)
                else:
                    resp = await client.post(path, json=body)

                has_json = False
                json_keys: list[str] = []
                try:
                    parsed = resp.json()
                    has_json = True
                    if isinstance(parsed, dict):
                        json_keys = list(parsed.keys())
                except Exception:
                    pass

                fp.endpoints[key] = EndpointProbe(
                    method=method,
                    path=path,
                    status=resp.status_code,
                    has_json_body=has_json,
                    json_keys=json_keys,
                )
                log.debug(
                    "probe.endpoint",
                    key=key,
                    status=resp.status_code,
                    json_keys=json_keys,
                )

            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                fp.endpoints[key] = EndpointProbe(
                    method=method,
                    path=path,
                    status=None,
                )
                log.warning(
                    "probe.endpoint_unreachable",
                    key=key,
                    error=str(exc),
                )

    log.info(
        "probe.api_complete",
        target=base_url,
        endpoints=len(fp.endpoints),
        reachable=sum(
            1 for e in fp.endpoints.values() if e.status is not None
        ),
    )

    # ── Frontend scrape (Layer 1: static + Layer 2: Playwright) ──────────────
    try:
        fp.scrape = await scrape_frontend(base_url)
        log.info(
            "probe.scrape_complete",
            has_html=fp.scrape.has_html_frontend,
            playwright=fp.scrape.playwright_available,
        )
    except Exception as exc:
        log.warning("probe.scrape_failed", error=str(exc))

    return fp


# ── OpenAPI prompt enrichment ─────────────────────────────────────────────────

def build_openapi_context(openapi: OpenAPIFingerprint | None) -> str:
    """Format the OpenAPI schema into a concise prompt block.

    Returns a human-readable summary of all discovered endpoints with their
    request parameters. The LLM can use this to verify it is calling the
    right paths and using the correct field names.
    """
    if openapi is None or not openapi.operations:
        return "No OpenAPI schema available — rely on the API contract above."

    lines = [
        f"Discovered from /openapi.json (title: {openapi.title!r}, "
        f"version: {openapi.version!r}):",
        "",
    ]
    for op_key in sorted(openapi.operations):
        params = openapi.operations[op_key]
        param_str = ", ".join(params) if params else "—"
        lines.append(f"  {op_key}  [params: {param_str}]")

    return "\n".join(lines)


# ── Comparison ────────────────────────────────────────────────────────────────

def compare_fingerprints(
    previous: SiteFingerprint | None,
    current: SiteFingerprint,
) -> str | None:
    """Compare two fingerprints and return a human-readable drift report.

    Covers both API endpoint changes and frontend structure changes.
    Returns ``None`` if no meaningful drift is detected.
    """
    if previous is None:
        return None

    diffs: list[str] = []

    # ── OpenAPI schema diff ───────────────────────────────────────────────────
    prev_oa = previous.openapi
    curr_oa = current.openapi
    if prev_oa and curr_oa:
        if prev_oa.version != curr_oa.version:
            diffs.append(
                f"  • [OpenAPI] version changed: {prev_oa.version} → {curr_oa.version}"
            )
        prev_ops = set(prev_oa.operations)
        curr_ops = set(curr_oa.operations)
        for op in sorted(curr_ops - prev_ops):
            diffs.append(f"  • [OpenAPI] NEW operation: {op}")
        for op in sorted(prev_ops - curr_ops):
            diffs.append(f"  • [OpenAPI] REMOVED operation: {op}")
        for op in sorted(prev_ops & curr_ops):
            prev_params = prev_oa.operations[op]
            curr_params = curr_oa.operations[op]
            added = set(curr_params) - set(prev_params)
            removed = set(prev_params) - set(curr_params)
            if added:
                diffs.append(f"  • [OpenAPI] {op}: new params {sorted(added)}")
            if removed:
                diffs.append(f"  • [OpenAPI] {op}: removed params {sorted(removed)}")
    elif prev_oa and not curr_oa:
        diffs.append("  • [OpenAPI] schema was available, now unreachable")
    elif not prev_oa and curr_oa:
        diffs.append("  • [OpenAPI] schema newly available")

    # ── API endpoint diff ─────────────────────────────────────────────────────
    all_keys = set(previous.endpoints) | set(current.endpoints)
    for key in sorted(all_keys):
        prev_ep = previous.endpoints.get(key)
        curr_ep = current.endpoints.get(key)

        if prev_ep is None:
            diffs.append(
                f"  • NEW endpoint: {key} → HTTP {curr_ep.status}"
            )
            continue

        if curr_ep is None:
            diffs.append(
                f"  • MISSING endpoint: {key} was HTTP {prev_ep.status}, "
                f"now unreachable"
            )
            continue

        if prev_ep.status != curr_ep.status:
            diffs.append(
                f"  • {key}: status {prev_ep.status} → {curr_ep.status}"
            )

        if curr_ep.status is None and prev_ep.status is not None:
            diffs.append(
                f"  • {key}: was HTTP {prev_ep.status}, now connection error"
            )

        prev_jk = set(prev_ep.json_keys)
        curr_jk = set(curr_ep.json_keys)
        if curr_jk - prev_jk:
            diffs.append(
                f"  • {key}: new JSON keys: {sorted(curr_jk - prev_jk)}"
            )
        if prev_jk - curr_jk:
            diffs.append(
                f"  • {key}: removed JSON keys: {sorted(prev_jk - curr_jk)}"
            )

    # ── Frontend scrape diff ──────────────────────────────────────────────────
    scrape_diffs = compare_scrape_fingerprints(
        previous.scrape,
        current.scrape or ScrapeFingerprint(
            probed_at=current.probed_at,
            has_html_frontend=False,
        ),
    )
    for sd in scrape_diffs:
        diffs.append(f"  • [Frontend] {sd}")

    # ── Build final drift report ──────────────────────────────────────────────
    if not diffs:
        log.info(
            "probe.no_drift",
            previous_probed_at=previous.probed_at,
            current_probed_at=current.probed_at,
        )
        return None

    openapi_diffs = [d for d in diffs if "[OpenAPI]" in d]
    api_diffs = [d for d in diffs if "[OpenAPI]" not in d and "[Frontend]" not in d]
    frontend_diffs = [d for d in diffs if "[Frontend]" in d]

    report_lines = [
        f"DRIFT DETECTED — site changed since last run ({previous.probed_at}):",
        "",
        "OpenAPI contract layer:",
        *(openapi_diffs or ["  (no contract-level changes)"]),
        "",
        "API probe layer:",
        *(api_diffs or ["  (no probe-level changes)"]),
        "",
        "Frontend layer:",
        *(frontend_diffs or ["  (no frontend changes)"]),
        "",
        "Adapt your approach accordingly. Flag a 'structural_change' anomaly",
        "for any endpoint that is now missing or behaves differently.",
    ]

    # Remove empty sections
    clean_lines = []
    prev_was_empty = False
    for line in report_lines:
        if line == "" and prev_was_empty:
            continue
        clean_lines.append(line)
        prev_was_empty = line == ""

    drift_text = "\n".join(clean_lines)
    log.warning(
        "probe.drift_detected",
        openapi_diffs=sum(1 for d in diffs if "[OpenAPI]" in d),
        api_diffs=sum(1 for d in diffs if "[OpenAPI]" not in d and "[Frontend]" not in d),
        frontend_diffs=sum(1 for d in diffs if "[Frontend]" in d),
        previous_probed_at=previous.probed_at,
    )
    return drift_text
