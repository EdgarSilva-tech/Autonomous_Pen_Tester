# Autonomous Pentesting Agent — Architecture Deep Dive

> Detailed description of every component and the internal functioning of the agentic layer.

---

## Diagrams

**Full architecture:**
![Architecture Diagram](architecture-diagram.png)

**Agent graph (LangGraph):**
![Agent Graph](agent-graph.png)

### Agent graph (Phase 4 — ASCII)

```
START
  │
  ▼
planner_node  ◄── reads fingerprint + scope via structured LLM output
  │                produces test_plan: list[PlanItem]
  ▼
llm_node ◄──────────────────────────────────────────────────────────┐
  │                                                                  │
  ├─ tool_calls present? ──► tools_node                              │ ReAct loop
  │                              │                                   │
  │                    len(messages) > threshold?                    │
  │                         │           │                            │
  │                    summarize_node  llm_node ─────────────────────┘
  │                         │
  │                    llm_node ──────────────────────────────────────┐
  │                                                                   │
  └─ no tool calls ──► evaluate_node                                  │
                            │                                         │
                  approved or max retries?                            │
                         │         │                                  │
                    report_node  llm_node (corrective pass) ──────────┘
                         │
                        END
```

---

## Table of Contents

1. [Startup Sequence](#1-startup-sequence--agentmainpy)
2. [Custom LangGraph Graph](#2-custom-langgraph-graph--agentgraphpy)
3. [Planner Node](#3-planner-node--agentnodesplannerpy)
4. [Scope Config](#4-scope-config--agentscopepy)
5. [Summary Node](#5-summary-node--agentnodessummarizepy)
6. [Evaluation Node](#6-evaluation-node--agentnodesevaluatepy)
7. [The System Prompt](#7-the-system-prompt--agentpromptspy)
8. [HTTP Tools & Attack Modules](#8-http-tools--attack-modules)
9. [The 8-Step Test Protocol (v1 Legacy Mode)](#9-the-8-step-test-protocol-v1-legacy-mode)
10. [Error Handling and Autonomous Decisions](#10-error-handling-and-autonomous-decisions)
11. [The Three Memory Layers](#11-the-three-memory-layers)
12. [Drift Detection & Site Fingerprinting](#12-drift-detection--site-fingerprinting)
13. [Frontend Scraping](#13-frontend-scraping--agentscrapepy)
14. [LiteLLM AI Gateway](#14-litellm-ai-gateway--litellmconfigyaml)
15. [MCP Client](#15-mcp-client--agentmcp_clientpy)
16. [Observability Stack](#16-observability-stack)
17. [Report Assembly](#17-report-assembly--agentreportpy)
18. [Docker Infrastructure](#18-docker-infrastructure--11-services)

---

## 1. Startup Sequence — `agent/main.py`

When Docker starts the agent container, the entrypoint runs `python -m agent.main`. The Click CLI resolves environment variables and delegates to `_run()` via `asyncio.run()`. Eleven steps always execute in this fixed order:

| # | Step | What happens |
|---|---|---|
| 1 | **Logging** | `setup_logging()` — structlog JSON lines with OTel `trace_id` and `span_id` correlation |
| 2 | **Telemetry** | `setup_telemetry()` — OTel `TracerProvider`, root span `agent.run`, `OTLPSpanExporter`, `LangchainInstrumentor`, `HTTPXClientInstrumentor` |
| 3 | **New Password** | `AGENT_NEW_PASSWORD` env var, or `secrets.token_urlsafe(16)` generated at runtime |
| 4 | **Thread ID** | Unique UUID per run; if `--thread-id` is passed, resumes the existing checkpoint in Postgres |
| 5 | **Scope** | `load_scope(scope_file)` — reads YAML scope config (`--scope-file` / `SCOPE_FILE`); defaults to permissive `ScopeConfig()` if not provided |
| 6 | **Long-term Memory** | `retrieve_similar_runs(target_url, k=3)` — returns top-3 past run summaries **and** the most recent stored `SiteFingerprint` |
| 7 | **Site Probe** | `probe_site(target_url)` — OpenAPI fetch + unauthenticated HTTP probe + frontend scrape |
| 8 | **Drift + OpenAPI context** | `compare_fingerprints()` → `drift_context`; `build_openapi_context()` → `openapi_context` for system prompt |
| 9 | **Build Graph** | `build_graph()` — constructs the LLM, Postgres checkpointer, MCP tools, HTTP tools, and `StateGraph` |
| 10 | **Run Graph** | `graph.ainvoke(initial_state, config={thread_id})` — starts the 6-node graph (planner + executor loop) |
| 11 | **Store Memory** | `store_run(report, target_url, fingerprint)` — stores report embedding + current fingerprint in pgvector |

> **Critical ordering:** Step 2 (telemetry) must happen before any LLM or HTTP calls. `LangchainInstrumentor` and `HTTPXClientInstrumentor` install themselves via global monkey-patch. If called after the first invocations they do not correctly instrument already-created spans.

---

## 2. Custom LangGraph Graph — `agent/graph.py`

The agent uses a fully custom `StateGraph` with six nodes and conditional edges. This gives precise control over the message flow and enables the `planner_node`, `summarize_node`, and `evaluate_node` to be wired into the graph.

### Node topology

```
START → planner_node → llm_node ⟺ tools_node → evaluate_node → report_node → END
```

### Conditional edges

| Source node | Condition | Routes to |
|---|---|---|
| `planner_node` | Always | `llm_node` |
| `llm_node` | Last message has `tool_calls` | `tools_node` |
| `llm_node` | No `tool_calls` in last message | `evaluate_node` |
| `tools_node` | Non-system messages > `SUMMARY_THRESHOLD` | `summarize_node` |
| `tools_node` | Non-system messages ≤ `SUMMARY_THRESHOLD` | `llm_node` |
| `summarize_node` | Always | `llm_node` |
| `evaluate_node` | `approved=True` or `eval_attempts ≥ MAX_EVAL_RETRIES` | `report_node` |
| `evaluate_node` | `approved=False` and retries remaining | `llm_node` (corrective pass) |

### System prompt injection

The system prompt is built and injected as a `SystemMessage` only on the **first** invocation of `llm_node`. Subsequent calls see the already-prepended `SystemMessage` at index 0 of the messages list and skip re-injection. `build_system_prompt()` routes to the v2 executor prompt when `fingerprint` and `test_plan` are present (set by `planner_node`), and falls back to the legacy auth prompt otherwise.

---

## 3. Planner Node — `agent/nodes/planner.py`

### Purpose

`planner_node` runs **once at the start of every scan**, before the ReAct executor loop. It reads the site fingerprint (from `probe_site` + recon) and the scope config, calls the LLM with structured output, and produces a prioritised `test_plan` — a list of `PlanItem` objects telling the executor which attack modules to run, on which paths, in what priority order.

### Output schema

```python
class PlanItem(BaseModel):
    module: str          # auth | injection | access | headers | disclosure | ratelimit
    tools: list[str]     # Layer 2 tool names to invoke
    priority: Literal["critical", "high", "medium", "low"]
    paths: list[str]     # target paths (max 5)
    reason: str          # one-sentence justification
    config: dict         # optional per-module config
```

The `PlanItem` list is stored in `state["test_plan"]` and consumed by both the executor (`build_system_prompt`) and the evaluator (`evaluate_node` v2 mode).

### How it works

```
fingerprint (state) ──┐
                       ├─► _build_human_msg() ──► ChatOpenAI.with_structured_output(_TestPlan)
scope (state) ─────────┘                                │
                                                         ▼
                                               _TestPlan.items → list[dict]
                                                         │
                                                state["test_plan"]
```

1. Reads `state["fingerprint"]` and `state["scope"]` (both dicts).
2. Formats them into a human message listing API type, endpoints, auth mechanisms, tech stack, enabled modules, and excluded paths.
3. Calls the LLM via `with_structured_output(_TestPlan)` — response is parsed directly into Pydantic, no JSON wrangling needed.
4. Serialises `PlanItem` objects to dicts and returns `{"test_plan": items}`.

### Planning rules (system prompt)

- Only include modules that are in `scope.active_modules`.
- Priority ordering: `critical > high > medium > low`.
- List specific tool names from Layer 2; do not reference MCP tool names (those are discovered at runtime).
- If no endpoints were discovered, fall back to common paths: `/`, `/api`, `/login`, `/health`.

---

## 4. Scope Config — `agent/scope.py`

### Purpose

`ScopeConfig` is a Pydantic model that constrains what the agent is allowed to test. It is loaded from a YAML file at startup and stored in `state["scope"]` as a dict.

### Schema

```python
class ScopeConfig(BaseModel):
    allowed_hosts: list[str]        # empty = all hosts allowed
    excluded_paths: list[str]       # paths the agent must not test
    max_requests_per_tool: int      # default: 50
    enabled_modules: list[str]      # default: all 6 modules
    disabled_modules: list[str]     # default: none
    severity_threshold: str         # minimum severity to report (default: "low")

    @property
    def active_modules(self) -> list[str]:
        return [m for m in self.enabled_modules if m not in self.disabled_modules]
```

`to_dict()` adds an `active_modules` key to the serialised form so the planner and evaluator don't have to recompute it.

### YAML example

```yaml
allowed_hosts:
  - "api.example.com"
excluded_paths:
  - "/admin"
  - "/internal"
enabled_modules:
  - auth
  - injection
  - headers
disabled_modules: []
max_requests_per_tool: 20
severity_threshold: medium
```

### CLI flag

```bash
python -m agent.main --target-url http://api.example.com \
                     --scope-file scope.yaml
# or via env var:
SCOPE_FILE=scope.yaml python -m agent.main ...
```

If `--scope-file` is not provided, a default `ScopeConfig()` is used — all 6 modules enabled, no path exclusions, 50 requests per tool, threshold `low`.

---

## 5. Summary Node — `agent/nodes/summarize.py`

### Purpose

The ReAct loop accumulates one `AIMessage` + N `ToolMessage`s per iteration. For a multi-module scan with many tool calls this can reach 30–50 messages. Together with the system prompt this approaches the context window of smaller models and increases cost on every iteration.

### How it works

When `tools_node` completes, the conditional edge calls `should_summarise()`:

```
non_system_messages = len(messages) - count(SystemMessage)
if non_system_messages > SUMMARY_THRESHOLD → route to summarize_node
else → route to llm_node
```

`summarize_node` then:
1. Keeps `messages[0]` (the system prompt `SystemMessage`)
2. Keeps the last `RECENT_KEEP` messages verbatim
3. Calls the LLM with a dedicated summarisation prompt over the middle portion
4. Replaces the middle with a single `SystemMessage("[HISTORY SUMMARY #N]")`
5. Increments `state["summary_count"]`
6. Returns the compressed list — LangGraph's `add_messages` reducer is **not** used here; the full `messages` field is overwritten

### Configuration

| Env var | Default | Effect |
|---|---|---|
| `SUMMARY_THRESHOLD` | `30` | Non-system message count that triggers summarisation |
| `SUMMARY_RECENT_KEEP` | `12` | Messages preserved verbatim at the tail of the list |

> The PostgreSQL checkpointer always stores the full pre-compression state after each node. The original conversation is never lost — only the active LLM context is compressed.

---

## 6. Evaluation Node — `agent/nodes/evaluate.py`

### Purpose

The ReAct agent may stop prematurely, claim findings without evidence, or skip entire modules. The evaluation node acts as an **independent judge** that re-reads the full conversation and validates every claim before the report is emitted.

### Dual-mode operation

The evaluator dispatches on whether `state["test_plan"]` is populated:

| Mode | Trigger | What it validates |
|---|---|---|
| **v2 (general scan)** | `test_plan` is present (set by `planner_node`) | Module coverage: did every planned module get at least one tool call? Evidence quality per finding. |
| **v1 (legacy auth)** | `test_plan` is `None` or absent | All 8 auth steps completed with correct HTTP status codes. |

### v2 module coverage check

```python
_TOOL_TO_MODULE: dict[str, str] = {
    "login_tool": "auth", "me_tool": "auth", ...,
    "sqli_probe": "injection", "nosql_probe": "injection", ...,
    "idor_probe": "access", ...,
    "cors_check": "headers", ...,
    "error_disclosure_probe": "disclosure", ...,
    "rate_limit_check": "ratelimit", ...,
}
```

`_build_module_summary(messages, test_plan)` scans all `ToolMessage` names in the conversation, maps each to its module via `_TOOL_TO_MODULE`, and produces a coverage table (planned vs. executed). This summary is prepended to the v2 eval prompt so the LLM can confirm coverage.

### Structured output

The LLM is called with `with_structured_output(EvaluationResult)`:

```python
class EvaluationResult(BaseModel):
    approved: bool
    confidence: float          # 0.0 – 1.0
    feedback: str
    missing_steps: list[str]
    unsupported_anomalies: list[str]
    suggested_actions: list[str]
```

### Retry mechanism

If `approved=False` and `eval_attempts < MAX_EVAL_RETRIES`:
1. A `HumanMessage` is appended with precise feedback (which modules are missing, which findings lack evidence)
2. The graph routes back to `llm_node` for a **corrective pass** — the LLM sees the feedback and can re-execute missing modules or revise its conclusions

After `MAX_EVAL_RETRIES` (default: 2) the node force-approves with `confidence=0.5` and records outstanding issues in the `EvaluationResult` for the report — preventing infinite loops.

The final `EvaluationResult` is attached to the `PentestReport` in the `evaluation` field and is fully auditable.

---

## 7. The System Prompt — `agent/prompts.py`

The system prompt is the agent's constitution. `build_system_prompt()` routes to one of two prompts based on state:

```python
def build_system_prompt(..., *, fingerprint, test_plan, scope) -> str:
    if fingerprint and test_plan is not None:
        return build_executor_prompt(...)   # v2 — general scan
    return _LEGACY_AUTH_PROMPT              # v1 — hardcoded auth flow
```

The `is not None` check (not truthiness) is intentional: an empty `test_plan = []` still signals that `planner_node` ran and v2 mode should be used.

### v2 executor prompt sections

| Section | Content |
|---|---|
| **Objective** | Execute the test plan modules in priority order using the available tools |
| **Fingerprint** | JSON dump of the site fingerprint from recon (api_type, endpoints, auth_mechanisms, tech_stack) |
| **Test Plan** | JSON dump of `PlanItem` list from `planner_node` |
| **Scope** | Enabled modules, excluded paths, max requests per tool |
| **Credentials** | Username, current password, new password |
| **Past Runs Context** | Top-3 reports from previous runs |
| **Drift Context** | Result of `compare_fingerprints()` |
| **MCP Note** | Present only when MCP servers are configured; lists discovered MCP tool names |

### v1 legacy prompt sections

| Section | Content |
|---|---|
| **Objective** | 8 ordered steps with specific tools and expected validations |
| **Error Handling Rules** | 401 → abort; 429 → wait; 5xx → retry ×3; token expired → re-auth; 404 → flag anomaly |
| **Anomaly Detection** | `weak_password_policy`, `session_not_invalidated`, `token_not_rotated`, `rate_limiting_absent`, `structural_change` |
| **Discovered API Endpoints** | Summary from `/openapi.json` injected at runtime |
| **Site Drift Context** | Result of `compare_fingerprints()` |
| **Past Runs Context** | Top-3 past report summaries |

---

## 8. HTTP Tools & Attack Modules

The agent exposes **30 tools total** across three layers. All Layer 2 attack tools are async Python functions decorated with `@tool` from LangChain.

### Layer 1 — Primitives (`agent/tools/primitives.py`)

| Tool | Purpose |
|---|---|
| `http_get` | GET request with configurable headers and params |
| `http_post` | POST request with body and content-type control |
| `http_put` | PUT request |
| `http_delete` | DELETE request |
| `set_session_header` | Persist a header across all subsequent requests |
| `clear_session_headers` | Reset the persistent header store |

### Layer 2 — Attack Modules (`agent/tools/attacks/`)

| Module | File | Tools |
|---|---|---|
| **Auth** | `auth.py` | `login_tool`, `me_tool`, `change_password_tool`, `logout_tool`, `jwt_analyze`, `brute_force_check`, `session_fixation_check`, `token_entropy_check` |
| **Injection** | `injection.py` | `sqli_probe`, `nosql_probe`, `ssti_probe`, `xss_probe` |
| **Access Control** | `access.py` | `idor_probe`, `bola_probe`, `privilege_escalation_check` |
| **Headers** | `headers.py` | `cors_check`, `security_headers_check`, `csp_check` |
| **Disclosure** | `disclosure.py` | `error_disclosure_probe`, `pii_scan`, `path_traversal_probe`, `http_methods_check` |
| **Rate Limiting** | `ratelimit.py` | `rate_limit_check`, `ip_bypass_check` |

**Total: 6 primitives + 24 attack tools = 30 tools bound to the LLM**

### Layer 3 — MCP Tools (optional, discovered at startup)

See [MCP Client](#15-mcp-client--agentmcp_clientpy). MCP tools are appended to the flat tool list at runtime; the planner is informed they may exist but does not name them.

### Common implementation details

| Aspect | Detail |
|---|---|
| HTTP client | `httpx.AsyncClient` via Layer 1 primitives with configurable timeout |
| Base URL | `ContextVar` — thread-safe and injectable in tests |
| Result shape | `{step, http_status, body, ok}` or module-specific `{vulnerable, evidence, ...}` |
| Logging | Each tool logs before and after with structlog + OTel `trace_id` |
| Custom OTel spans | `pentest.login`, `pentest.validate_session`, etc. with `http.status_code` attributes |

---

## 9. The 8-Step Test Protocol (v1 Legacy Mode)

When the agent runs without a fingerprint or scope (i.e. `planner_node` is absent or produces no plan), it falls back to the legacy v1 auth-only flow. This is preserved for backward compatibility with existing target apps that only expose the `/login`, `/me`, `/change-password`, `/logout` surface.

| Step | Tool | Endpoint | Expected HTTP | Notes |
|---|---|---|---|---|
| 1 · Login | `login_tool` | POST /login | 200 | Extract `token` from response |
| 2 · Validate Login | `me_tool` | GET /me | 200 | Confirm authenticated username |
| 3 · Change Password | `change_password_tool` | POST /change-password | 200 | Invalidates all existing sessions |
| 4 · Validate Session Invalidation | `me_tool` | GET /me (old token) | **401** | Confirms old token rejected |
| 5 · Re-authenticate | `login_tool` | POST /login | 200 | Login with new password |
| 6 · Validate Reauth | `me_tool` | GET /me | 200 | Confirm new session works |
| 7 · Logout | `logout_tool` | POST /logout | 200 | Invalidate session |
| 8 · Validate Logout | `me_tool` | GET /me (new token) | **401** | Confirms token rejected after logout |

In v2 mode, the executor uses the `test_plan` from `planner_node` instead of this fixed protocol.

---

## 10. Error Handling and Autonomous Decisions

The LLM is the decision-maker. When it receives a tool result with `ok: false` or `vulnerable: true`, it consults the system prompt rules and decides. Decisions are recorded in the final report.

| Scenario | LLM Decision |
|---|---|
| HTTP 401 on /login | Abort — do not retry with same credentials |
| Timeout or 5xx | Retry up to 3× with backoff 2s → 4s → 8s |
| Token expired mid-flow (401 on authenticated endpoint) | Re-authenticate and resume from failed step |
| Endpoint returns 404 | Try reasonable alternatives; flag `structural_change` anomaly |
| Unexpected HTTP (e.g. 422) | Log + graceful abort |
| `evaluate_node` rejects conclusion | Address feedback items, re-execute missing modules |
| Module not in `scope.active_modules` | Skip — do not invoke any tools for that module |

---

## 11. The Three Memory Layers

### Runtime Memory (ephemeral, in-context)

The `messages: list[AnyMessage]` field in `PentestState` is managed by LangGraph's `add_messages` reducer. The `summarize_node` periodically compresses it to prevent context overflow. The full history is always preserved in the PostgreSQL checkpoint.

| Message type | Content |
|---|---|
| `SystemMessage` | System prompt (index 0) + summary blocks (if summarised) |
| `AIMessage` | LLM reasoning + `tool_calls` (each iteration) |
| `ToolMessage` | Tool result (each tool call) |
| `HumanMessage` | Evaluation feedback (injected by `evaluate_node` on retry) |

### Short-term Memory (PostgreSQL checkpointing)

`AsyncPostgresSaver` (`langgraph-checkpoint-postgres`) serialises the full `PentestState` after each graph node. Stored in the `langgraph` database indexed by `thread_id`.

| Functionality | How it works |
|---|---|
| Resume after crash | Same `thread_id` → LangGraph loads the last checkpoint and resumes |
| Idempotency | Re-running with the same `thread_id` after success does not re-execute |
| Audit trail | Each node has a state snapshot — complete execution history |

### Long-term Memory (pgvector)

At the end of each run, `store_run()` in `agent/memory.py` embeds the final JSON report via `text-embedding-3-small` (through LiteLLM) and stores it in the `pentest_runs` table alongside the current `SiteFingerprint` serialised as JSONB metadata.

| Operation | Detail |
|---|---|
| Embedding model | `text-embedding-3-small` (1536 dims) via LiteLLM proxy |
| Similarity search | Cosine similarity — top-k=3 most similar past runs by URL |
| Metadata stored | target URL, status, `thread_id`, `anomaly_count`, `site_fingerprint` (JSON) |
| Retrieval | `retrieve_similar_runs()` returns both past summaries **and** the most recent stored fingerprint |
| Injection into prompt | Summaries in **Past Runs Context**; fingerprint used for drift comparison |

---

## 12. Drift Detection & Site Fingerprinting

Before each run, `probe_site()` in `agent/probe.py` builds a `SiteFingerprint` that captures the target's current behaviour. This fingerprint is compared against the one stored from the previous run. Any difference is summarised as a `drift_context` string and injected into the system prompt.

### OpenAPI schema layer (always attempted first)

```
GET /openapi.json
  → parse paths, methods, request body properties, query/header params
  → store OpenAPIFingerprint { title, version, operations, raw }
  → build_openapi_context() injects a human-readable summary into the system prompt
```

Drift detection compares: version changes, new/removed operations, added/removed
parameter names per operation.

### API probe layer (always runs)

Four unauthenticated HTTP requests are sent to the target's key endpoints:

| Probe | Method | Purpose |
|---|---|---|
| `/login` (dummy creds) | POST | Confirms endpoint exists; records status code + JSON keys |
| `/me` (no token) | GET | Expects 401; detects if now open or moved |
| `/change-password` (no auth) | POST | Expects 401; detects removal or schema change |
| `/logout` (no auth) | POST | Expects 401; detects removal |

The `EndpointProbe` dataclass records: `status`, `has_json_body`, `json_keys` (top-level keys of the response JSON).

### Comparison and drift report

`compare_fingerprints(previous, current)` iterates over all endpoint keys and generates diff strings for:
- Status code changes (`401 → 404`)
- Endpoint becoming unreachable (connection error)
- JSON response schema changes (keys added or removed)
- Frontend-level differences (delegated to `compare_scrape_fingerprints`)

The combined drift report is formatted with separate **OpenAPI contract layer**,
**API probe layer**, and **Frontend layer** sections. If no differences are found,
`None` is returned and the prompt block reads "No drift detected — proceed with
the standard protocol."

### PentestState fields

| Field | Type | Purpose |
|---|---|---|
| `fingerprint` | `dict \| None` | v2 recon result: api_type, endpoints, auth_mechanisms, tech_stack |
| `test_plan` | `list[dict] \| None` | Planner output: list of PlanItem dicts |
| `scope` | `dict \| None` | Serialised ScopeConfig (includes `active_modules`) |
| `drift_context` | `str \| None` | Drift report injected into the system prompt |
| `openapi_context` | `str \| None` | Discovered endpoints summary injected into the system prompt |

---

## 13. Frontend Scraping — `agent/scrape.py`

`scrape_frontend()` adds a **presentation-layer** fingerprint on top of the API probe. It only activates when the root URL returns `Content-Type: text/html`, making it a no-op for pure API targets.

### Layer 1 — Static HTML analysis

```
GET /  →  BeautifulSoup parse
          ├── _detect_spa_from_soup()    → is_spa_static
          ├── _extract_static_forms()   → static_forms (action, method, fields)
          └── _collect_js_urls()        → js_file_urls
                     │
                     └── _analyze_js_bundle() per file
                             regex patterns:
                             • fetch('/path')
                             • axios.post('/path')
                             • baseURL: '/path'
                             • known REST prefixes (/api, /auth, /login…)
                             → js_api_urls
```

SPA detection inspects static HTML for framework signatures: empty `#root` / `#app` containers, `ng-version` attributes, `data-reactroot`, inline references to `__NEXT_DATA__`, `__NUXT__`, `webpackBootstrap`.

### Layer 2 — Dynamic rendering via Playwright microservice

When the `scraper` service is reachable at `SCRAPER_BASE_URL`:

```
POST /scrape → {url, timeout_ms}
             ← {is_spa, forms[], intercepted_requests[], page_title}
```

The Playwright service:
1. Launches a shared headless Chromium browser (created once at startup)
2. Creates an isolated `BrowserContext` per request
3. Installs a request interceptor (`page.on("request", ...)`)
4. Navigates to the URL and waits for `networkidle`
5. Evaluates JS in the page to extract live DOM forms and detect SPA globals
6. Returns intercepted requests filtered to fetch/XHR only, excluding static assets

### ScrapeFingerprint comparison

`compare_scrape_fingerprints(previous, current)` detects:

| Signal | Example diff string |
|---|---|
| SPA type change | `"App rendering changed: server-rendered → SPA"` |
| Form removed | `"Form removed: POST /login (had fields: ['username', 'password'])"` |
| New form field | `"Form /auth/login: new field(s) detected: ['totp_code']"` |
| Field type change | `"Form /login: field 'username' type changed text → email"` |
| New JS API path | `"New API paths in JS bundles: ['/api/v2/auth']"` |
| Removed JS API path | `"API paths removed from JS bundles: ['/api/login']"` |
| Intercepted endpoint | `"New endpoints intercepted at page load: ['POST /auth/token']"` |

Rendered forms (from Playwright) take precedence over static forms when both are available.

---

## 14. LiteLLM AI Gateway — `litellm/config.yaml`

The agent never calls the OpenAI API directly. It always points to `http://litellm-proxy:4000`, which behaves as an OpenAI-compatible endpoint.

| Feature | Configuration | Effect |
|---|---|---|
| Model routing | `model_list`: `gpt-4o-mini`, `claude-haiku-fallback`, `text-embedding-3-small` | Primary chat + Anthropic fallback + embeddings |
| Fallback | `gpt-4o-mini` → `claude-haiku-fallback` | After OpenAI failures, switches to Anthropic |
| Retry | `num_retries: 3`, `retry_after: 5s` | Retries automatically before activating fallback |
| Semantic cache | Redis · TTL 600s | Identical responses returned from cache |
| Spend tracking | PostgreSQL `db:litellm` | Records cost per model, token usage, and latency |
| OTel integration | `success_callback: otel` | Emits spans for each LLM call |
| Embeddings | `text-embedding-3-small` | Used by `memory.py` to generate report embeddings |
| Dashboard UI | `/ui` on port 4000 | Web interface to monitor usage and configure models |

---

## 15. MCP Client — `agent/mcp_client.py`

The Model Context Protocol allows the agent to discover tools from external servers without code changes. The agent acts as an **MCP Client** — it connects, discovers tools, and adds them to the tool pool.

### Discovery process (during `build_graph()`)

1. `MCP_SERVERS` env var is parsed as JSON — map of name → `{url, transport}`
2. `MultiServerMCPClient` connects to each MCP server
3. `client.get_tools()` returns a list of LangChain `BaseTool` instances
4. `all_tools = HTTP_TOOLS + mcp_tools` (HTTP_TOOLS = all 30 built-in tools)
5. `llm.bind_tools(all_tools)` exposes the full pool to the LLM

Fails gracefully — if no MCP servers are configured or reachable, returns `[]`.

```bash
MCP_SERVERS='{"security-scanner": {"url": "http://mcp-scanner:8080/mcp", "transport": "streamable_http"}}'
```

---

## 16. Observability Stack

Everything the agent does is automatically instrumented and visible in Grafana at `http://localhost:3000`.

| Component | Spans generated | Instrumentation |
|---|---|---|
| Each LLM call | model, tokens, latency, status | `LangchainInstrumentor` |
| Each tool call | tool name, arguments, result | `LangchainInstrumentor` |
| Each HTTP request (agent) | URL, method, status, latency | `HTTPXClientInstrumentor` (child spans) |
| Pentest steps | `pentest.login`, `pentest.validate_session`, etc. | Custom spans in `agent/tools/` |
| Site probe | `agent.probe` wrapping OpenAPI + HTTP + scrape | Custom span in `agent/probe.py` |
| Root run span | `agent.run` with target URL and username | `setup_telemetry()` in `agent/telemetry.py` |
| LLM calls via LiteLLM | provider, model, cost | `success_callback: otel` in LiteLLM config |

### Grafana dashboard

The provisioned dashboard **Autonomous Pen Tester — Agent Overview** (`infra/grafana/provisioning/dashboards/agent-overview.json`) includes:
- Tempo trace panels filtered by `resource.service.name` (agent, litellm, scraper)
- Prometheus `up` stat panel for scrape target health

To inspect a specific run: copy `trace_id` from logs → Grafana **Explore** → Tempo → paste ID.

### Data pipeline

| From | To | Protocol | Data |
|---|---|---|---|
| Agent | otel-collector | OTLP gRPC :4317 | spans + metrics |
| otel-collector | prometheus | remote_write HTTP | aggregated metrics |
| otel-collector | grafana-tempo | OTLP HTTP | distributed traces |
| litellm-proxy | prometheus | scrape /metrics | cost, tokens, latency |
| prometheus + tempo | grafana | datasource API | unified dashboard |

Clicking a latency spike in Grafana navigates directly to the Tempo trace via exemplars. The same `trace_id` appears on every JSON log line, correlating logs, metrics, and traces.

---

## 17. Report Assembly — `agent/report.py`

`report_node` is the last graph node. It calls `assemble_report(state, elapsed_ms)` which builds a `PentestReport` Pydantic model, attaches the `EvaluationResult` from `state["eval_result"]`, and serialises it.

### Status inference logic

| Condition | Inferred status |
|---|---|
| `state.error` is populated | `"failure"` |
| Any `step_result.status == "error"` | `"partial_failure"` |
| All steps with `status == "ok"` | `"success"` |

### Report fields

| Field | Source |
|---|---|
| `status` | LLM final state or status inference |
| `steps` | `state["step_results"]` if populated; otherwise reconstructed from `ToolMessage` history in `report.py` |
| `anomalies` | `state["anomalies"]` — one `Anomaly` per finding |
| `elapsed_ms` | Wall-clock time from `_start_time` in `graph.py` |
| `thread_id` | From `state["thread_id"]` |
| `evaluation` | `EvaluationResult(**state["eval_result"])` — the judge's verdict |
| `test_plan` | Echoed from `state["test_plan"]` — which modules were planned vs. executed |

### Output destinations

| Destination | Format | When |
|---|---|---|
| stdout | JSON (1 line) | Always |
| `REPORT_OUTPUT_PATH` | Pretty-printed JSON (indent=2) | If env var set |
| pgvector (`memory.py`) | JSON embedding + fingerprint metadata | After `report_node`, in `main.py` |

> **Phase 5 (upcoming):** `report.py` will be extended to emit Markdown reports with executive summary, CVSS-scored findings table, per-finding evidence, and a remediation checklist.

---

## 18. Docker Infrastructure — 11 Services

| Service | Image | Port | Purpose | Depends on |
|---|---|---|---|---|
| `target-app` | supplied FastAPI image | :8000 | Target application (black-box) | — |
| `postgres` | `pgvector/pgvector:pg16` | :5433 (host) / :5432 (internal) | Shared DB: `litellm`, `langgraph`, `pentest_memory` + pgvector. Default DB `pentest` is maintenance-only (empty). | — |
| `redis` | `redis:7-alpine` | :6379 | LiteLLM semantic cache | — |
| `litellm-proxy` | `ghcr.io/berriai/litellm:main-stable` | :4000 | AI Gateway: routing, fallback, cache, tracking, UI | postgres, redis |
| `otel-collector` | `otel/opentelemetry-collector-contrib:0.101` | :4317 | OTLP receiver → Prometheus + Tempo exporter | grafana-tempo |
| `prometheus` | `prom/prometheus:v2.52.0` | :9090 | Metrics storage + remote_write receiver | — |
| `grafana-tempo` | `grafana/tempo:2.4.1` | :3200 | Distributed trace backend (local storage) | — |
| `grafana` | `grafana/grafana:11.5.2` | :3000 | Unified dashboard with Prometheus + Tempo datasources | prometheus, grafana-tempo |
| `scraper` | `./scraper/Dockerfile` (Playwright) | :9222 | Headless Chromium microservice for dynamic frontend scraping | — |
| `agent` | `./Dockerfile` (Python 3.11-slim) | — | The pentesting agent — starts when all dependencies are healthy | target-app, litellm-proxy, postgres, scraper |

> **Why is `scraper` a separate service?** The Playwright browser binary is ~400 MB. Keeping it isolated means the agent image stays lean (`python:3.11-slim` base), the browser can restart independently without touching the agent, and future proxy / auth-bypass capabilities can be added without changing agent code.

> **PostgreSQL image:** `pgvector/pgvector:pg16` (not official `postgres:16`) because it includes the pgvector extension pre-compiled. `infra/postgres/init.sql` creates the 3 databases and activates `CREATE EXTENSION vector` on `pentest_memory`.

---

*Architecture deep-dive · Autonomous Pentesting Agent · Phase 4 complete · June 2026*
