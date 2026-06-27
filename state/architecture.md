# Architecture

## Current State (v2 â€” General Security Scanner, Phase 4 complete)

A LangGraph agent with a planner node that reasons over a site fingerprint and scope config to produce a prioritised test plan, then executes the plan via a ReAct executor loop with 30 built-in attack tools across 6 OWASP-aligned modules.

### Graph topology

```
START â†’ planner_node â†’ llm_node âŸº tools_node â†’ evaluate_node â†’ report_node â†’ END
```

`planner_node` runs once per scan; the `llm_node âŸº tools_node` ReAct loop iterates until the LLM stops calling tools; `evaluate_node` validates coverage and can route back to `llm_node` for corrective passes (max 2 retries).

### Components

| Component | File | Role |
|-----------|------|------|
| Graph | `agent/graph.py` | 6-node LangGraph StateGraph: planner â†’ llm â†’ tools â†’ summarize â†’ evaluate â†’ report |
| Planner | `agent/nodes/planner.py` | Reads fingerprint + scope â†’ structured `test_plan` via LLM with_structured_output |
| Scope | `agent/scope.py` | `ScopeConfig` Pydantic model + `load_scope()` for YAML-based constraints |
| Primitives | `agent/tools/primitives.py` | 6 low-level HTTP tools: http_get/post/put/delete, set/clear_session_header |
| Attack tools | `agent/tools/attacks/` | 24 tools across auth, injection, access, headers, disclosure, ratelimit modules |
| Recon | `agent/recon/` | API type detection, endpoint discovery, GraphQL/SOAP/REST adapters |
| Probe | `agent/probe.py` | OpenAPI fetch + unauthenticated HTTP probe + Playwright scrape (kept for drift) |
| Prompts | `agent/prompts.py` | Dual-mode: v2 executor prompt (fingerprint + test_plan) or v1 legacy auth prompt |
| State | `agent/state.py` | Extended TypedDict: fingerprint, test_plan, scope, findings, eval_result |
| Memory | `agent/memory.py` | pgvector semantic search over past run summaries |
| Report | `agent/report.py` | Assembles final JSON report; Phase 5 will add Markdown + CVSS |
| Evaluate | `agent/nodes/evaluate.py` | Dual-mode: v2 checks module coverage via _TOOL_TO_MODULE map; v1 checks 8-step auth |
| Summarize | `agent/nodes/summarize.py` | Compresses message history beyond SUMMARY_THRESHOLD |
| MCP | `agent/mcp_client.py` | Discovers tools from MCP servers at startup; appended to the 30 built-in tools |
| Telemetry | `agent/telemetry.py` | OpenTelemetry setup â€” traces exported to Tempo |
| Scraper | `scraper/` | Playwright microservice for dynamic DOM rendering |

### Infrastructure (Docker â€” 11 services)

```
target-app      :8000   FastAPI challenge target
agent                   Pentesting agent (runs once, writes to /output)
scraper         :9222   Playwright microservice
litellm-proxy   :4000   AI gateway (routing, fallback, cache, cost)
postgres        :5433   PostgreSQL + pgvector (langgraph, litellm, pentest_memory DBs)
redis           :6379   LiteLLM semantic cache
otel-collector  :4317   OTLP receiver â†’ Prometheus + Tempo
prometheus      :9090   Metrics storage
grafana-tempo   :3200   Distributed trace backend
grafana         :3000   Unified dashboards
```

### Current Limitations (remaining after Phase 4)

- Report is JSON-only; no Markdown output, no CVSS scores on findings (Phase 5)
- Target app has no intentionally vulnerable endpoints for v2 tools to find (Phase 5)
- gRPC adapter is a stub â€” full support requires HTTP/2 + protobuf via MCP
- No end-to-end integration test covering a full v2 scan with real findings (Phase 5)

---

## Target State (v2 â€” General Security Scanner)

A fully agentic planner that discovers any web target, selects appropriate test modules, executes them, and produces a comprehensive OWASP-aligned security report.

### High-Level Flow

```
Input: target URL + scope config
        â”‚
        â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  Phase 1: Recon     â”‚  API type detection, endpoint discovery,
â”‚  & Fingerprint      â”‚  tech stack ID, auth mechanism detection
â””â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
         â”‚  fingerprint result
         â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  Phase 2: Planner   â”‚  LLM reasons over fingerprint, selects
â”‚  (agentic)          â”‚  test modules, builds execution plan
â””â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
         â”‚  test plan
         â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  Phase 3: Test      â”‚  Runs selected modules in parallel or
â”‚  Execution          â”‚  sequence; each module emits findings
â””â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
         â”‚  raw findings
         â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  Phase 4: Evaluate  â”‚  Independent LLM validates evidence,
â”‚  & Deduplicate      â”‚  deduplicates, assigns CVSS scores
â””â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
         â”‚  validated findings
         â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  Phase 5: Report    â”‚  JSON + Markdown report with severity,
â”‚  Generation         â”‚  evidence, and remediation guidance
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

### Component Map (âœ“ = implemented, â—‹ = Phase 5)

```
agent/
â”œâ”€â”€ graph.py              # âœ“ 6-node graph: planner â†’ llm âŸº tools â†’ evaluate â†’ report
â”œâ”€â”€ state.py              # âœ“ Extended: fingerprint, test_plan, scope, findings, eval_result
â”œâ”€â”€ scope.py              # âœ“ ScopeConfig Pydantic model + load_scope() YAML loader
â”œâ”€â”€ prompts.py            # âœ“ Dual-mode: build_executor_prompt (v2) + _LEGACY_AUTH_PROMPT (v1)
â”œâ”€â”€ tools/
â”‚   â”œâ”€â”€ __init__.py       # âœ“ ALL_TOOLS flat list (30 tools)
â”‚   â”œâ”€â”€ primitives.py     # âœ“ Layer 1: http_get/post/put/delete, set/clear_session_header
â”‚   â””â”€â”€ attacks/          # âœ“ Layer 2: named attack tools
â”‚       â”œâ”€â”€ injection.py  # âœ“ sqli_probe, nosql_probe, ssti_probe, xss_probe
â”‚       â”œâ”€â”€ auth.py       # âœ“ login/me/change_password/logout + jwt_analyze,
â”‚       â”‚                 #   brute_force_check, session_fixation_check, token_entropy_check
â”‚       â”œâ”€â”€ access.py     # âœ“ idor_probe, bola_probe, privilege_escalation_check
â”‚       â”œâ”€â”€ headers.py    # âœ“ cors_check, security_headers_check, csp_check
â”‚       â”œâ”€â”€ disclosure.py # âœ“ error_disclosure_probe, pii_scan, path_traversal_probe,
â”‚       â”‚                 #   http_methods_check
â”‚       â””â”€â”€ ratelimit.py  # âœ“ rate_limit_check, ip_bypass_check
â”œâ”€â”€ recon/
â”‚   â”œâ”€â”€ fingerprint.py    # âœ“ API type detection + tech stack + auth mechanism ID
â”‚   â”œâ”€â”€ discovery.py      # âœ“ Endpoint discovery: OpenAPI, WSDL, GraphQL introspection,
â”‚   â”‚                     #   path fuzzing
â”‚   â””â”€â”€ api_adapters/
â”‚       â”œâ”€â”€ rest.py       # âœ“ REST/OpenAPI adapter
â”‚       â”œâ”€â”€ graphql.py    # âœ“ GraphQL introspection + query builder
â”‚       â”œâ”€â”€ soap.py       # âœ“ WSDL parser + SOAP envelope builder
â”‚       â””â”€â”€ grpc.py       # âœ“ stub (logging-only; full impl via MCP)
â”œâ”€â”€ nodes/
â”‚   â”œâ”€â”€ planner.py        # âœ“ PlanItem schema + planner_node (fingerprint â†’ test_plan)
â”‚   â”œâ”€â”€ evaluate.py       # âœ“ Dual-mode: v2 module coverage + v1 legacy 8-step
â”‚   â””â”€â”€ summarize.py      # âœ“ Compresses messages beyond SUMMARY_THRESHOLD
â”œâ”€â”€ report.py             # âœ“ JSON report; â—‹ Markdown + CVSS + remediation (Phase 5)
â”œâ”€â”€ memory.py             # âœ“ pgvector semantic search over past runs
â”œâ”€â”€ mcp_client.py         # âœ“ Discovers MCP tools at startup; appended to 30 built-ins
â”œâ”€â”€ telemetry.py          # âœ“ OTel TracerProvider + LangchainInstrumentor
â””â”€â”€ logger.py             # âœ“ structlog JSON lines
```

### API Type Detection Strategy

| Signal | API Type |
|--------|----------|
| `/openapi.json` or `/swagger.json` responds | REST + OpenAPI spec |
| `/graphql` responds to introspection query | GraphQL |
| `?wsdl` param or `.wsdl` URL responds with XML | SOAP |
| `Content-Type: application/grpc` or port 50051 | gRPC |
| `Content-Type: text/xml` + `SOAPAction` header | SOAP |
| No spec detected | REST (specless) â€” path fuzzing |

### Tool Layering

```
Layer 3 (MCP Tools â€” optional, discovered at startup)
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
nmap-mcp        â†’  port_scan(host), service_detect(host)
nuclei-mcp      â†’  nuclei_scan(target, templates)
sqlmap-mcp      â†’  sqlmap_probe(url, param)
playwright-mcp  â†’  browser_navigate(url), form_fill(selector, value)
shodan-mcp      â†’  shodan_lookup(ip), censys_lookup(domain)
        â”‚
        â”‚  discovered at startup via mcp_client.py; added to planner tool pool
        â–¼
Layer 2 (Attack Tools â€” always present, baked in)
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
sqli_probe(url, param)    â”€â”€â”€â–º  Layer 1
cors_check(url)           â”€â”€â”€â–º  Layer 1
jwt_analyze(token)              (pure Python â€” no HTTP needed)
idor_probe(url, id_field) â”€â”€â”€â–º  Layer 1
rate_limit_check(url, n)  â”€â”€â”€â–º  Layer 1
        â”‚
        â”‚  uses internally
        â–¼
Layer 1 (Primitives â€” always present, baked in)
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
http_get(url, headers, params)
http_post(url, headers, body, content_type)
http_put(url, headers, body)
http_delete(url, headers)
```

The planner sees all three layers as a flat tool list. It calls Layer 3 MCP tools when available (broader coverage, external tools), Layer 2 for known attack classes, and Layer 1 directly for novel or API-specific probing.

The scanner works standalone with only Layer 1+2. Layer 3 is purely additive â€” no MCP servers configured means no change in behaviour.

### MCP Extension Points

| MCP Server | Provides | When useful |
|------------|----------|-------------|
| `nmap-mcp` | Port scan, service/version detection | Recon phase â€” discover non-HTTP services |
| `nuclei-mcp` | Community CVE + misconfiguration templates | Broad coverage pass after custom modules |
| `sqlmap-mcp` | Deep SQLi detection with tamper scripts | Complement `sqli_probe` on confirmed injection points |
| `playwright-mcp` | Full browser interaction, JS rendering | Replaces/augments the scraper microservice |
| `shodan-mcp` / `censys-mcp` | OSINT, exposed services, historical data | Passive recon before active scanning |

New MCP servers can be added without touching the agent â€” `mcp_client.py` discovers them at startup and the planner picks them up automatically.

### Finding Schema

```json
{
  "id": "uuid",
  "title": "SQL Injection in /api/login (username parameter)",
  "category": "A03:2021 â€“ Injection",
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
**Markdown:** executive summary â†’ severity breakdown â†’ per-finding detail â†’ remediation checklist
