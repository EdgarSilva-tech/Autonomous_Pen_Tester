# Implementation Plan

## Overview

Transform the v1 auth tester into a v2 general-purpose security scanner in 5 phases.
Each phase is independently deployable and builds on the previous one.

---

## Phase 1 — Generic HTTP Primitives & State Refactor

**Goal:** Replace hardwired tools with a generic HTTP layer; extend state schema.  
**Prerequisite for:** Everything else.

### Tasks

1. **Create `agent/tools/primitives.py`**
   - `http_get(url, headers, params, timeout)` → `HttpResponse`
   - `http_post(url, headers, body, content_type, timeout)` → `HttpResponse`
   - `http_put(url, headers, body, timeout)` → `HttpResponse`
   - `http_delete(url, headers, timeout)` → `HttpResponse`
   - `HttpResponse` dataclass: status, headers, body, elapsed_ms, error
   - Session state: persistent header/cookie store across calls within a run

2. **Refactor `agent/tools.py` → `agent/tools/attacks/auth.py`**
   - Rewrite login, me, change_password, logout as thin wrappers over primitives
   - Preserve all existing tests

3. **Extend `agent/state.py`**
   - Add: `fingerprint`, `test_plan`, `findings`, `scope`
   - Rename: `step_results` → keep for backward compat; `anomalies` feeds into `findings`

4. **Create `agent/tools/__init__.py`**
   - Exports: all primitives + all attack tools + MCP tools as a single flat list for the graph
   - MCP tools merged in at import time from `mcp_client.py` (empty list if no servers configured)

5. **Update `agent/mcp_client.py`**
   - Ensure discovered MCP tools are returned in a form `tools/__init__.py` can merge
   - No behaviour change when no MCP servers are configured

6. **Update tests**
   - Unit tests for each primitive (mock httpx)
   - Regression tests for existing auth tools via new wrappers

---

## Phase 2 — Recon & API Type Detection

**Goal:** Replace the fixed probe with a generalized fingerprinting pipeline that detects API type and discovers endpoints for any target.

### Tasks

1. **Create `agent/recon/fingerprint.py`**
   - `detect_api_type(base_url)` → `ApiType` enum: REST_OPENAPI | REST_SPECLESS | GRAPHQL | SOAP | GRPC
   - Detection signals (see architecture.md)
   - Tech stack detection: response headers (`X-Powered-By`, `Server`), cookie names, error page patterns
   - Auth mechanism detection: Bearer, Basic, Cookie, API key (header/query), OAuth2

2. **Create `agent/recon/discovery.py`**
   - REST: fetch `/openapi.json`, `/swagger.json`, `/api-docs`
   - GraphQL: POST introspection query to `/graphql`, `/api/graphql`, `/query`
   - SOAP: fetch `?wsdl`, parse operations from WSDL XML
   - Specless REST: path fuzzing with a wordlist (common API paths)
   - Returns: `DiscoveredEndpoints` — list of `{method, path, params, auth_required}`

3. **Create `agent/recon/api_adapters/`**
   - `rest.py` — builds request context from OpenAPI operation objects
   - `graphql.py` — introspection query builder, mutation/query extractor
   - `soap.py` — WSDL parser, SOAP envelope builder
   - `grpc.py` — stub (gRPC reflection requires special handling; defer to later)

4. **Refactor `agent/probe.py`**
   - Becomes a thin orchestrator calling `fingerprint.py` + `discovery.py`
   - Keep drift detection logic

5. **Update `agent/state.py`**
   - `fingerprint: FingerprintResult` — api_type, tech_stack, auth_mechanisms, discovered_endpoints

---

## Phase 3 — Attack Tool Modules

**Goal:** Implement Layer 2 named attack tools covering OWASP Top 10.

### Tasks (per module)

#### `agent/tools/attacks/injection.py`
- `sqli_probe(url, param, method)` — tests 20+ SQLi payloads; detects error-based, time-based blind
- `nosql_probe(url, param)` — MongoDB operator injection (`$gt`, `$where`)
- `ssti_probe(url, param)` — template injection payloads (Jinja2, Twig, Freemarker)
- `xss_probe(url, param)` — reflected XSS payloads; checks if payload echoed unescaped

#### `agent/tools/attacks/auth.py` (extends Phase 1 refactor)
- `jwt_analyze(token)` — decode without verify; check alg:none, weak secret, exp, iat
- `brute_force_check(url, username, wordlist_size)` — attempt N logins; detect lockout/429
- `session_fixation_check(url)` — check if session ID changes on login
- `token_entropy_check(token)` — measure randomness of session token

#### `agent/tools/attacks/access.py`
- `idor_probe(url, id_field, known_id)` — enumerate ±10 IDs around known; detect 200 vs 403
- `bola_probe(url, user_a_token, user_b_resource)` — cross-user resource access
- `privilege_escalation_check(url, low_priv_token)` — attempt admin endpoints with low-priv token

#### `agent/tools/attacks/headers.py`
- `cors_check(url)` — test with null Origin, wildcard, evil.com; check ACAO header
- `security_headers_check(url)` — check for: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- `csp_check(url)` — parse CSP; flag unsafe-inline, unsafe-eval, wildcard sources

#### `agent/tools/attacks/disclosure.py`
- `error_disclosure_probe(url)` — trigger 400/404/500; scan response for stack traces, DB errors, paths
- `pii_scan(response_body)` — regex scan for emails, phone numbers, SSNs, credit card patterns
- `path_traversal_probe(url, param)` — `../` sequences in file path params
- `http_methods_check(url)` — OPTIONS/TRACE/PUT on endpoints; flag unexpected allowed methods

#### `agent/tools/attacks/ratelimit.py`
- `rate_limit_check(url, n, window_s)` — send N requests in window_s seconds; detect 429 / no limit
- `ip_bypass_check(url)` — retry with X-Forwarded-For spoofing after hitting rate limit

---

## Phase 4 — Planner Node & Graph Refactor

**Goal:** Replace fixed 8-step graph with an agentic planner that selects and sequences test modules.

### Tasks

1. **Create `agent/nodes/planner.py`**
   - Input: `fingerprint` from state
   - Output: `test_plan` — ordered list of `{module, priority, config}`
   - Planner LLM prompt: reasons over discovered endpoints + API type → selects relevant modules
   - Respects scope config (allowed hosts, excluded paths)

2. **Refactor `agent/graph.py`**
   - New node sequence: recon → planner → executor → evaluate → report
   - Executor node: iterates over `test_plan`, calls tools, aggregates findings into state
   - Conditional edges: planner can request additional recon if fingerprint is incomplete

3. **Update `agent/prompts.py`**
   - Planner system prompt: knows all available Layer 1/2 modules and their inputs; describes Layer 3 MCP tool classes (port scanning, template scanning, browser interaction, OSINT) so the LLM selects them when available — but never assumes they exist
   - Executor system prompt: module-specific context injected per test
   - Evaluator prompt: CVSS scoring guidance, deduplication rules

4. **Scope config**
   - New CLI flag: `--scope-file path/to/scope.yaml`
   - Scope schema: `allowed_hosts`, `excluded_paths`, `max_requests`, `test_modules` (override)

---

## Phase 5 — Report Generation & Target App Extension

**Goal:** Rich report output; extend target app with more vulnerability types for testing.

### Tasks

1. **Refactor `agent/report.py`**
   - Consume `findings` list from state (not ToolMessages)
   - Render JSON report: full findings, CVSS scores, metadata, evidence
   - Render Markdown report: executive summary, severity table, per-finding sections, remediation checklist
   - Add CVSS vector calculator utility

2. **Extend `target-app`**
   - Add intentionally vulnerable endpoints for each attack module:
     - `/api/search?q=` — SQLi via string interpolation
     - `/api/user/{id}` — IDOR (no authorization check)
     - `/api/admin` — returns 200 for any Bearer token (broken access control)
     - Missing security headers
     - Verbose error messages with stack traces
     - No rate limiting on `/api/login` (remove existing limiter)
   - Keep current auth endpoints intact

3. **Update `docker-compose.yml`**
   - No new services needed for Phase 5

4. **Update tests**
   - Integration tests against extended target app
   - Report rendering unit tests
   - End-to-end test: full scan of extended target → verified findings in report

---

## Dependency Graph

```
Phase 1 (Primitives)
    └── Phase 2 (Recon)
            └── Phase 3 (Attack Tools)   ← can be done in parallel with Phase 2
                    └── Phase 4 (Planner + Graph)
                                └── Phase 5 (Reports + Target App)
```

Phase 3 modules can be developed independently of each other once Phase 1 is done.

---

## Decisions Made

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Test strategy | Fully agentic planner | Adapts to novel targets; more powerful |
| HTTP tools | Three-layer (primitives + attack tools + MCP) | Generic where needed, structured for known attacks, extensible via MCP |
| MCP role | Layer 3 extensibility — optional, additive | Already wired in; new tools need no agent code changes |
| Report formats | JSON + Markdown | Machine-readable + human-readable |
| Auth tools | Refactor into `tools/attacks/auth.py` | Preserves existing functionality |
