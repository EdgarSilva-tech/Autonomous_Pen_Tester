# Architecture

## Current State (v1 — Auth Tester)

A LangGraph agent that executes a fixed 8-step authentication lifecycle test against a single FastAPI target.

### Components

| Component | File | Role |
|-----------|------|------|
| Graph | `agent/graph.py` | 5-node LangGraph StateGraph: llm → tools → summarize → evaluate → report |
| Tools | `agent/tools.py` | 4 hardwired HTTP tools: login, me, change_password, logout |
| Probe | `agent/probe.py` | OpenAPI fetch + unauthenticated HTTP probe + Playwright scrape |
| Prompts | `agent/prompts.py` | System prompt builder — injects API contract, past runs, drift context |
| State | `agent/state.py` | LangGraph TypedDict state schema |
| Memory | `agent/memory.py` | pgvector semantic search over past run summaries |
| Report | `agent/report.py` | Assembles final JSON report from ToolMessages |
| Evaluate | `agent/nodes/evaluate.py` | Independent evaluator LLM — validates completeness, up to 2 retries |
| Summarize | `agent/nodes/summarize.py` | Compresses message history beyond SUMMARY_THRESHOLD |
| MCP | `agent/mcp_client.py` | Discovers tools from MCP servers at startup; adds them to planner tool pool as Layer 3 |
| Telemetry | `agent/telemetry.py` | OpenTelemetry setup — traces exported to Tempo |
| Scraper | `scraper/` | Playwright microservice for dynamic DOM rendering |

### Infrastructure (Docker — 11 services)

```
target-app      :8000   FastAPI challenge target
agent                   Pentesting agent (runs once, writes to /output)
scraper         :9222   Playwright microservice
litellm-proxy   :4000   AI gateway (routing, fallback, cache, cost)
postgres        :5433   PostgreSQL + pgvector (langgraph, litellm, pentest_memory DBs)
redis           :6379   LiteLLM semantic cache
otel-collector  :4317   OTLP receiver → Prometheus + Tempo
prometheus      :9090   Metrics storage
grafana-tempo   :3200   Distributed trace backend
grafana         :3000   Unified dashboards
```

### Current Limitations

- Fixed 8-step flow — can't adapt to novel targets
- Tools hardwired to `/login`, `/me`, `/change-password`, `/logout`
- Only tests FastAPI-style REST auth
- Report covers only authentication anomalies
- No support for GraphQL, SOAP, gRPC, XML-RPC
- No injection, IDOR, header security, or OWASP Top 10 coverage

---

## Target State (v2 — General Security Scanner)

A fully agentic planner that discovers any web target, selects appropriate test modules, executes them, and produces a comprehensive OWASP-aligned security report.

### High-Level Flow

```
Input: target URL + scope config
        │
        ▼
┌─────────────────────┐
│  Phase 1: Recon     │  API type detection, endpoint discovery,
│  & Fingerprint      │  tech stack ID, auth mechanism detection
└────────┬────────────┘
         │  fingerprint result
         ▼
┌─────────────────────┐
│  Phase 2: Planner   │  LLM reasons over fingerprint, selects
│  (agentic)          │  test modules, builds execution plan
└────────┬────────────┘
         │  test plan
         ▼
┌─────────────────────┐
│  Phase 3: Test      │  Runs selected modules in parallel or
│  Execution          │  sequence; each module emits findings
└────────┬────────────┘
         │  raw findings
         ▼
┌─────────────────────┐
│  Phase 4: Evaluate  │  Independent LLM validates evidence,
│  & Deduplicate      │  deduplicates, assigns CVSS scores
└────────┬────────────┘
         │  validated findings
         ▼
┌─────────────────────┐
│  Phase 5: Report    │  JSON + Markdown report with severity,
│  Generation         │  evidence, and remediation guidance
└─────────────────────┘
```

### New Component Map

```
agent/
├── graph.py              # Refactored: planner node + dynamic module dispatch
├── state.py              # Extended: fingerprint, findings, test_plan fields
├── prompts.py            # Extended: planner prompt, per-module prompts
├── tools/
│   ├── __init__.py
│   ├── primitives.py     # Layer 1: http_get, http_post, http_put, http_delete,
│   │                     #          set_header, set_cookie, read_response
│   └── attacks/          # Layer 2: named attack tools (use Layer 1 internally)
│       ├── injection.py  # sqli_probe, nosql_probe, ssti_probe, xss_probe
│       ├── auth.py       # jwt_analyze, brute_force_check, session_probe
│       │                 # (current login tools refactored here)
│       ├── access.py     # idor_probe, privilege_escalation_check, bola_probe
│       ├── headers.py    # cors_check, security_headers_check, csp_check
│       ├── disclosure.py # error_disclosure_probe, pii_scan, path_traversal
│       └── ratelimit.py  # rate_limit_check, lockout_check
├── recon/
│   ├── fingerprint.py    # API type detection + tech stack ID
│   │                     # (extends current probe.py)
│   ├── discovery.py      # Endpoint discovery: OpenAPI, WSDL, GraphQL
│   │                     # introspection, path fuzzing
│   └── api_adapters/
│       ├── rest.py       # REST/OpenAPI adapter
│       ├── graphql.py    # GraphQL introspection + query builder
│       ├── soap.py       # WSDL parser + SOAP envelope builder
│       └── grpc.py       # gRPC reflection + protobuf adapter
├── nodes/
│   ├── planner.py        # NEW: reasons over fingerprint, emits test_plan
│   ├── evaluate.py       # Extended: CVSS scoring, deduplication
│   └── summarize.py      # Unchanged
├── report.py             # Extended: JSON + Markdown, CVSS, remediation
├── memory.py             # Extended: stores findings by target hash
├── mcp_client.py         # Extended: exposes discovered MCP tools to planner as Layer 3
├── telemetry.py          # Unchanged
└── logger.py             # Unchanged
```

### API Type Detection Strategy

| Signal | API Type |
|--------|----------|
| `/openapi.json` or `/swagger.json` responds | REST + OpenAPI spec |
| `/graphql` responds to introspection query | GraphQL |
| `?wsdl` param or `.wsdl` URL responds with XML | SOAP |
| `Content-Type: application/grpc` or port 50051 | gRPC |
| `Content-Type: text/xml` + `SOAPAction` header | SOAP |
| No spec detected | REST (specless) — path fuzzing |

### Tool Layering

```
Layer 3 (MCP Tools — optional, discovered at startup)
──────────────────────────────────────────────────────
nmap-mcp        →  port_scan(host), service_detect(host)
nuclei-mcp      →  nuclei_scan(target, templates)
sqlmap-mcp      →  sqlmap_probe(url, param)
playwright-mcp  →  browser_navigate(url), form_fill(selector, value)
shodan-mcp      →  shodan_lookup(ip), censys_lookup(domain)
        │
        │  discovered at startup via mcp_client.py; added to planner tool pool
        ▼
Layer 2 (Attack Tools — always present, baked in)
──────────────────────────────────────────────────
sqli_probe(url, param)    ───►  Layer 1
cors_check(url)           ───►  Layer 1
jwt_analyze(token)              (pure Python — no HTTP needed)
idor_probe(url, id_field) ───►  Layer 1
rate_limit_check(url, n)  ───►  Layer 1
        │
        │  uses internally
        ▼
Layer 1 (Primitives — always present, baked in)
────────────────────────────────────────────────
http_get(url, headers, params)
http_post(url, headers, body, content_type)
http_put(url, headers, body)
http_delete(url, headers)
```

The planner sees all three layers as a flat tool list. It calls Layer 3 MCP tools when available (broader coverage, external tools), Layer 2 for known attack classes, and Layer 1 directly for novel or API-specific probing.

The scanner works standalone with only Layer 1+2. Layer 3 is purely additive — no MCP servers configured means no change in behaviour.

### MCP Extension Points

| MCP Server | Provides | When useful |
|------------|----------|-------------|
| `nmap-mcp` | Port scan, service/version detection | Recon phase — discover non-HTTP services |
| `nuclei-mcp` | Community CVE + misconfiguration templates | Broad coverage pass after custom modules |
| `sqlmap-mcp` | Deep SQLi detection with tamper scripts | Complement `sqli_probe` on confirmed injection points |
| `playwright-mcp` | Full browser interaction, JS rendering | Replaces/augments the scraper microservice |
| `shodan-mcp` / `censys-mcp` | OSINT, exposed services, historical data | Passive recon before active scanning |

New MCP servers can be added without touching the agent — `mcp_client.py` discovers them at startup and the planner picks them up automatically.

### Finding Schema

```json
{
  "id": "uuid",
  "title": "SQL Injection in /api/login (username parameter)",
  "category": "A03:2021 – Injection",
  "severity": "Critical",
  "cvss_score": 9.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "endpoint": "POST /api/login",
  "parameter": "username",
  "evidence": {
    "payload": "' OR '1'='1",
    "request": "...",
    "response_snippet": "...SQL syntax error near...",
    "http_status": 500
  },
  "remediation": "Use parameterized queries / prepared statements.",
  "references": ["https://owasp.org/A03_2021-Injection/"],
  "confirmed": true,
  "timestamp": "2026-06-20T10:00:00Z"
}
```

### Report Structure

**JSON:** machine-readable, full findings list, CVSS scores, evidence, metadata  
**Markdown:** executive summary → severity breakdown → per-finding detail → remediation checklist
