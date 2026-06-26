# Tasks

Status legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[-]` blocked

---

## Phase 1 — Generic HTTP Primitives & State Refactor ✓ COMPLETE

- [x] Create `agent/tools/primitives.py` with http_get, http_post, http_put, http_delete
- [x] Define `HttpResponse` dataclass (status, headers, body, elapsed_ms, error)
- [x] Add persistent session header/cookie store to primitives
- [x] Refactor `agent/tools.py` → `agent/tools/attacks/auth.py` (thin wrappers over primitives)
- [x] Create `agent/tools/__init__.py` exporting all tools as flat list
- [x] Extend `agent/state.py` with: `fingerprint`, `test_plan`, `findings`, `scope`
- [x] Update `agent/mcp_client.py` — existing pattern already correct; `graph.py` merges MCP tools at runtime
- [x] Update unit tests for new primitives (18 new tests in `tests/unit/test_primitives.py`)
- [x] Regression tests: 108/108 passing including all pre-existing auth flow tests

**Note:** Discovered that LangChain runs `@tool` sync functions via `context.run()` (copied context), so `ContextVar.set()` inside sync tools doesn't propagate back. Fixed `clear_session_headers` to mutate the dict in place (same approach as `set_session_header`).

## Phase 2 — Recon & API Type Detection ✓ COMPLETE

- [x] Create `agent/recon/fingerprint.py` — API type + tech stack + auth mechanism detection
- [x] Create `agent/recon/discovery.py` — endpoint discovery (OpenAPI, GraphQL introspection, WSDL, path fuzzing)
- [x] Create `agent/recon/api_adapters/rest.py`
- [x] Create `agent/recon/api_adapters/graphql.py`
- [x] Create `agent/recon/api_adapters/soap.py`
- [x] Create `agent/recon/api_adapters/grpc.py` (stub)
- [x] `agent/probe.py` kept intact (backward compat); new recon layer runs alongside it
- [x] `agent/main.py` updated — runs probe_site + fingerprint_target in parallel; v2 fingerprint dict stored in state["fingerprint"]
- [x] `agent/state.py` already had `fingerprint: dict[str, Any] | None` from Phase 1 — sufficient
- [x] 44 new tests across `test_fingerprint.py` and `test_discovery.py`; 152/152 passing

**Detection priority:** REST_OPENAPI → GRAPHQL → SOAP → GRPC → REST_SPECLESS
**Parallel probes:** OpenAPI spec + GraphQL introspection + WSDL + root header collection run concurrently via asyncio.gather
**Note:** gRPC adapter is a stub (logging-only); full support requires HTTP/2 + protobuf reflection via MCP server

## Phase 3 — Attack Tool Modules ✓ COMPLETE

- [x] `agent/tools/attacks/injection.py`: sqli_probe, nosql_probe, ssti_probe, xss_probe
- [x] `agent/tools/attacks/auth.py`: added jwt_analyze, brute_force_check, session_fixation_check, token_entropy_check (flow tools preserved)
- [x] `agent/tools/attacks/access.py`: idor_probe, bola_probe, privilege_escalation_check
- [x] `agent/tools/attacks/headers.py`: cors_check, security_headers_check, csp_check
- [x] `agent/tools/attacks/disclosure.py`: error_disclosure_probe, pii_scan, path_traversal_probe, http_methods_check
- [x] `agent/tools/attacks/ratelimit.py`: rate_limit_check, ip_bypass_check
- [x] `agent/tools/__init__.py` updated — ALL_TOOLS now includes all 6 modules
- [x] Unit tests: test_injection, test_auth_attacks, test_access, test_headers, test_disclosure, test_ratelimit

**Tool count:** 6 primitives + 8 auth (4 flow + 4 attack) + 4 injection + 3 access + 3 headers + 4 disclosure + 2 ratelimit = **30 tools total bound to LLM**
**OWASP coverage:** SQLi, NoSQLi, SSTI, XSS, IDOR/BOLA, privilege escalation, CORS, security headers, CSP, error disclosure, PII exposure, path traversal, HTTP methods, rate limiting, IP bypass

## Phase 4 — Planner Node & Graph Refactor ✓ COMPLETE

- [x] `agent/nodes/planner.py` — `TestPlanItem` + `planner_node`; LLM with structured output reads fingerprint + scope → emits test_plan list
- [x] `agent/graph.py` refactored: `START → planner_node → llm_node(executor) → tools_node → evaluate_node → report_node`
- [x] `agent/scope.py` — `ScopeConfig` Pydantic model + `load_scope(path)`
- [x] `agent/main.py` — added `--scope-file` CLI flag (envvar `SCOPE_FILE`); scope loaded into `initial_state["scope"]`
- [x] `requirements.txt` — added `pyyaml>=6.0,<7`
- [x] `agent/prompts.py` — full rewrite: `build_executor_prompt()` (v2 general), `build_system_prompt()` (routes v1/v2 based on fingerprint presence)
- [x] `agent/nodes/evaluate.py` — dual-mode evaluator: v2 uses `_TOOL_TO_MODULE` map + module coverage summary when `test_plan` present; v1 legacy auth-step logic unchanged
- [x] `tests/integration/test_planner_flow.py` — 7 tests: planner node (4 scenarios), evaluate_node v2 mode (3 scenarios)

**Graph topology:** `START → planner_node → llm_node ⟺ tools_node → evaluate_node → report_node`
**Planner output schema:** `{module, tools, priority, paths, reason, config}`
**Scope YAML keys:** `allowed_hosts`, `excluded_paths`, `max_requests_per_tool`, `enabled_modules`, `disabled_modules`, `severity_threshold`
**MCP note:** planner prompt explicitly tells LLM that MCP tools may be available at runtime but are not assumed

## Phase 5 — Report Generation & Target App Extension

- [ ] Refactor `agent/report.py` to consume `findings` list with CVSS scores
- [ ] Implement JSON report renderer
- [ ] Implement Markdown report renderer with executive summary + remediation checklist
- [ ] Add CVSS vector calculator utility
- [ ] Extend `target-app` with intentionally vulnerable endpoints (SQLi, IDOR, broken access control, missing headers, verbose errors)
- [ ] End-to-end integration test: full scan → verified findings in report

---

## Backlog / Future

- [ ] HTML report renderer
- [ ] gRPC adapter (full implementation)
- [ ] CI/CD integration: fail pipeline on Critical/High findings
- [ ] Authenticated scanning: OAuth2 flows, API key injection
- [ ] Rate limiting for the scanner itself (polite mode)
- [ ] CVE database lookup for detected tech stack versions
- [ ] MCP servers to build/integrate:
  - [ ] `nmap-mcp` — port scan + service detection for recon phase
  - [ ] `nuclei-mcp` — community CVE + misconfiguration templates
  - [ ] `sqlmap-mcp` — deep SQLi with tamper scripts (complement Layer 2 sqli_probe)
  - [ ] `playwright-mcp` — replace/augment scraper microservice with browser MCP
  - [ ] `shodan-mcp` / `censys-mcp` — passive OSINT recon
