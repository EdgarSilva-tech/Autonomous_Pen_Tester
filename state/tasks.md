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

## Phase 2 — Recon & API Type Detection

- [ ] Create `agent/recon/fingerprint.py` — API type + tech stack + auth mechanism detection
- [ ] Create `agent/recon/discovery.py` — endpoint discovery (OpenAPI, GraphQL introspection, WSDL, path fuzzing)
- [ ] Create `agent/recon/api_adapters/rest.py`
- [ ] Create `agent/recon/api_adapters/graphql.py`
- [ ] Create `agent/recon/api_adapters/soap.py`
- [ ] Create `agent/recon/api_adapters/grpc.py` (stub)
- [ ] Refactor `agent/probe.py` to use new recon modules
- [ ] Update `agent/state.py` with `FingerprintResult` type

## Phase 3 — Attack Tool Modules

- [ ] `agent/tools/attacks/injection.py`: sqli_probe, nosql_probe, ssti_probe, xss_probe
- [ ] `agent/tools/attacks/auth.py`: jwt_analyze, brute_force_check, session_fixation_check, token_entropy_check
- [ ] `agent/tools/attacks/access.py`: idor_probe, bola_probe, privilege_escalation_check
- [ ] `agent/tools/attacks/headers.py`: cors_check, security_headers_check, csp_check
- [ ] `agent/tools/attacks/disclosure.py`: error_disclosure_probe, pii_scan, path_traversal_probe, http_methods_check
- [ ] `agent/tools/attacks/ratelimit.py`: rate_limit_check, ip_bypass_check
- [ ] Unit tests for each attack module

## Phase 4 — Planner Node & Graph Refactor

- [ ] Create `agent/nodes/planner.py` — LLM reasons over fingerprint → emits test_plan
- [ ] Refactor `agent/graph.py`: recon → planner → executor → evaluate → report
- [ ] Add scope config: `--scope-file` CLI flag + YAML schema
- [ ] Update planner prompt — must describe Layer 3 MCP tool classes so LLM uses them appropriately when available; must not assume any MCP tool exists
- [ ] Update executor, evaluator prompts in `agent/prompts.py`
- [ ] Integration test: full planner flow end-to-end (with and without MCP servers)

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
