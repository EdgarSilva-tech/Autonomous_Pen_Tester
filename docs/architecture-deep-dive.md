# Autonomous Pentesting Agent — Architecture Deep Dive

> Detailed description of every component and the internal functioning of the agentic layer.

---

## Diagrams

**Full architecture:**
![Architecture Diagram](architecture-diagram.png)

**Agent graph (LangGraph):**
![Agent Graph](agent-graph.png)

---

## Table of Contents

1. [Startup Sequence](#1-startup-sequence--agentmainpy)
2. [Custom LangGraph Graph](#2-custom-langgraph-graph--agentgraphpy)
3. [Summary Node](#3-summary-node--agentnodessummarizepy)
4. [Evaluation Node](#4-evaluation-node--agentnodesevaluatepy)
5. [The System Prompt](#5-the-system-prompt--agentpromptspy)
6. [HTTP Tools](#6-http-tools--agenttoolspy)
7. [The 8-Step Test Protocol](#7-the-8-step-test-protocol)
8. [Error Handling and Autonomous Decisions](#8-error-handling-and-autonomous-decisions)
9. [The Three Memory Layers](#9-the-three-memory-layers)
10. [Drift Detection & Site Fingerprinting](#10-drift-detection--site-fingerprinting)
11. [Frontend Scraping](#11-frontend-scraping--agentscrapepy)
12. [LiteLLM AI Gateway](#12-litellm-ai-gateway--litellmconfigyaml)
13. [MCP Client](#13-mcp-client--agentmcp_clientpy)
14. [Observability Stack](#14-observability-stack)
15. [Report Assembly](#15-report-assembly--agentreportpy)
16. [Docker Infrastructure](#16-docker-infrastructure--11-services)

---

## 1. Startup Sequence — `agent/main.py`

When Docker starts the agent container, the entrypoint runs `python -m agent.main`. The Click CLI resolves environment variables and delegates to `_run()` via `asyncio.run()`. Ten steps always execute in this fixed order:

| # | Step | What happens |
|---|---|---|
| 1 | **Logging** | `setup_logging()` — structlog JSON lines with OTel `trace_id` and `span_id` correlation |
| 2 | **Telemetry** | `setup_telemetry()` — OTel `TracerProvider`, root span `agent.run`, `OTLPSpanExporter`, `LangchainInstrumentor`, `HTTPXClientInstrumentor` |
| 3 | **New Password** | `AGENT_NEW_PASSWORD` env var, or `secrets.token_urlsafe(16)` generated at runtime |
| 4 | **Thread ID** | Unique UUID per run; if `--thread-id` is passed, resumes the existing checkpoint in Postgres |
| 5 | **Long-term Memory** | `retrieve_similar_runs(target_url, k=3)` — returns top-3 past run summaries **and** the most recent stored `SiteFingerprint` |
| 6 | **Site Probe** | `probe_site(target_url)` — OpenAPI fetch + unauthenticated HTTP probe + frontend scrape |
| 7 | **Drift + OpenAPI context** | `compare_fingerprints()` → `drift_context`; `build_openapi_context()` → `openapi_context` for system prompt |
| 8 | **Build Graph** | `build_graph()` — constructs the LLM, Postgres checkpointer, MCP tools, HTTP tools, and `StateGraph` |
| 9 | **Run Graph** | `graph.ainvoke(initial_state, config={thread_id})` — starts the 5-node graph |
| 10 | **Store Memory** | `store_run(report, target_url, fingerprint)` — stores report embedding + current fingerprint in pgvector |

> **Critical ordering:** Step 2 (telemetry) must happen before any LLM or HTTP calls. `LangchainInstrumentor` and `HTTPXClientInstrumentor` install themselves via global monkey-patch. If called after the first invocations they do not correctly instrument already-created spans.

---

## 2. Custom LangGraph Graph — `agent/graph.py`

The agent uses a fully custom `StateGraph` with five nodes and conditional edges. This replaces the earlier `create_react_agent` shortcut and gives precise control over the message flow, enabling the `summarize_node` and `evaluate_node` to be wired into the loop.

### Node topology

```
START
  │
  ▼
llm_node ◄──────────────────────────────────────────────────┐
  │                                                          │
  ├─ tool_calls present? ──► tools_node                      │ ReAct loop
  │                              │                           │
  │                    len(messages) > threshold?            │
  │                         │           │                    │
  │                    summarize_node  llm_node ─────────────┘
  │                         │
  │                    llm_node ────────────────────────────────┐
  │                                                             │
  └─ no tool calls ──► evaluate_node                            │
                            │                                   │
                  approved or max retries?                      │
                         │         │                            │
                    report_node  llm_node (corrective pass) ────┘
                         │
                        END
```

### Conditional edges

| Source node | Condition | Routes to |
|---|---|---|
| `llm_node` | Last message has `tool_calls` | `tools_node` |
| `llm_node` | No `tool_calls` in last message | `evaluate_node` |
| `tools_node` | Non-system messages > `SUMMARY_THRESHOLD` | `summarize_node` |
| `tools_node` | Non-system messages ≤ `SUMMARY_THRESHOLD` | `llm_node` |
| `summarize_node` | Always | `llm_node` |
| `evaluate_node` | `approved=True` or `eval_attempts ≥ MAX_EVAL_RETRIES` | `report_node` |
| `evaluate_node` | `approved=False` and retries remaining | `llm_node` (corrective pass) |

### System prompt injection

The system prompt is built and injected as a `SystemMessage` only on the **first** invocation of `llm_node`. Subsequent calls see the already-prepended `SystemMessage` at index 0 of the messages list and skip re-injection. The prompt includes `drift_context` from the fingerprint comparison.

---

## 3. Summary Node — `agent/nodes/summarize.py`

### Purpose

The ReAct loop accumulates one `AIMessage` + N `ToolMessage`s per iteration. For an 8-step protocol with validation calls this easily reaches 15–20 messages. Together with the system prompt this can approach the context window of smaller models and increases cost on every iteration.

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

## 4. Evaluation Node — `agent/nodes/evaluate.py`

### Purpose

The ReAct agent may stop prematurely, claim anomalies without evidence, or mislabel step statuses due to ambiguous tool output. The evaluation node acts as an **independent judge** that re-reads the full conversation and validates every claim before the report is emitted.

### What it validates

| Check | Question |
|---|---|
| **Completeness** | Were all 7 required steps executed and validated? |
| **Evidence** | Is each anomaly backed by explicit HTTP status + body evidence? |
| **Consistency** | Do step statuses match the actual tool responses seen in messages? |

### Structured output

The LLM is called with `with_structured_output(EvaluationResult)` producing a deterministic Pydantic model:

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
1. A `HumanMessage` is appended with precise feedback (which steps are missing, which anomalies lack evidence)
2. The graph routes back to `llm_node` for a **corrective pass** — the LLM sees the feedback and can re-execute missing steps or revise its conclusions

After `MAX_EVAL_RETRIES` (default: 2) the node force-approves with `confidence=0.5` and records outstanding issues in the `EvaluationResult` for the report — preventing infinite loops.

The final `EvaluationResult` is attached to the `PentestReport` in the `evaluation` field and is fully auditable.

---

## 5. The System Prompt — `agent/prompts.py`

The system prompt acts as the agent's constitution — five sections the LLM must respect throughout execution:

| Section | Content |
|---|---|
| **Objective** | 8 ordered steps with specific tools and expected validations |
| **Error Handling Rules** | 401 on login → abort; 429 → wait; 5xx → retry ×3; token expired → re-auth; 404 → flag `structural_change` |
| **Anomaly Detection** | `weak_password_policy`, `session_not_invalidated`, `token_not_rotated`, `rate_limiting_absent`, `structural_change` |
| **Discovered API Endpoints** | Summary from `/openapi.json` — operations and params injected at runtime |
| **Site Drift Context** | Result of `compare_fingerprints()` — API, OpenAPI contract, and frontend diffs |
| **Past Runs Context** | Top-3 reports from previous runs formatted as `[Run N]: ...` |

The prompt is built dynamically by `build_system_prompt()`, which accepts
`drift_context` and `openapi_context`. If either is missing, a placeholder is
injected so the LLM always has a complete, consistent prompt.

---

## 6. HTTP Tools — `agent/tools.py`

The four tools are async Python functions decorated with `@tool` from LangChain. The decorator automatically extracts the name, description (docstring), and input schema (type annotations) to expose to the LLM as JSON Schema.

| Tool | Input | What the LLM expects back |
|---|---|---|
| `login_tool` | `username: str, password: str` | HTTP 200 + `token` field in response body |
| `me_tool` | `token: str` | HTTP 200 + username = OK; HTTP 401 = invalid/expired (expected after password change or logout) |
| `change_password_tool` | `token: str, current_password: str, new_password: str` | HTTP 200 = success; invalidates all sessions |
| `logout_tool` | `token: str` | HTTP 200 = logout; follow-up `me_tool` must return 401 |

### Implementation details

| Aspect | Detail |
|---|---|
| HTTP client | `httpx.AsyncClient` with configurable timeout (default 10s) |
| Base URL | `ContextVar` — thread-safe and injectable in tests |
| Normalised response | `_result()` returns `{step, http_status, body, ok}` |
| Logging | Each tool logs before and after with structlog + OTel `trace_id` |
| Custom OTel spans | `pentest.login`, `pentest.validate_session`, `pentest.change_password`, `pentest.logout` with `http.status_code` attributes |
| Auto-instrumentation | `HTTPXClientInstrumentor` creates child httpx spans for every request |

---

## 7. The 8-Step Test Protocol

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

---

## 8. Error Handling and Autonomous Decisions

The LLM is the decision-maker. When it receives a tool result with `ok: false`, it consults the system prompt rules and decides. Decisions are recorded in the final report as the `decision` field on each step.

| Scenario | LLM Decision |
|---|---|
| HTTP 401 on /login | Abort — do not retry with same credentials |
| Timeout or 5xx | Retry up to 3× with backoff 2s → 4s → 8s |
| Token expired mid-flow (401 on authenticated endpoint) | Re-authenticate and resume from failed step |
| Endpoint returns 404 | Try reasonable alternatives; flag `structural_change` anomaly |
| Unexpected HTTP (e.g. 422) | Log + graceful abort |
| `evaluate_node` rejects conclusion | Address feedback items, re-execute missing steps |

---

## 9. The Three Memory Layers

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

## 10. Drift Detection & Site Fingerprinting

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
| `drift_context` | `str \| None` | Drift report injected into the system prompt |
| `openapi_context` | `str \| None` | Discovered endpoints summary injected into the system prompt |

---

## 11. Frontend Scraping — `agent/scrape.py`

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

## 12. LiteLLM AI Gateway — `litellm/config.yaml`

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

## 13. MCP Client — `agent/mcp_client.py`

The Model Context Protocol allows the agent to discover tools from external servers without code changes. The agent acts as an **MCP Client** — it connects, discovers tools, and adds them to the tool pool.

### Discovery process (during `build_graph()`)

1. `MCP_SERVERS` env var is parsed as JSON — map of name → `{url, transport}`
2. `MultiServerMCPClient` connects to each MCP server
3. `client.get_tools()` returns a list of LangChain `BaseTool` instances
4. `all_tools = HTTP_TOOLS + mcp_tools`
5. `llm.bind_tools(all_tools)` exposes the full pool to the LLM

Fails gracefully — if no MCP servers are configured or reachable, returns `[]`.

```bash
MCP_SERVERS='{"security-scanner": {"url": "http://mcp-scanner:8080/mcp", "transport": "streamable_http"}}'
```

---

## 14. Observability Stack

Everything the agent does is automatically instrumented and visible in Grafana at `http://localhost:3000`.

| Component | Spans generated | Instrumentation |
|---|---|---|
| Each LLM call | model, tokens, latency, status | `LangchainInstrumentor` |
| Each tool call | tool name, arguments, result | `LangchainInstrumentor` |
| Each HTTP request (agent) | URL, method, status, latency | `HTTPXClientInstrumentor` (child spans) |
| Pentest steps | `pentest.login`, `pentest.validate_session`, etc. | Custom spans in `agent/tools.py` |
| Site probe | `agent.probe` wrapping OpenAPI + HTTP + scrape | Custom span in `agent/probe.py` |
| Root run span | `agent.run` with target URL and username | `setup_telemetry()` in `agent/telemetry.py` |
| LLM calls via LiteLLM | provider, model, cost | `success_callback: otel` in LiteLLM config |

### Grafana dashboard

The provisioned dashboard **Autonomous Pen Tester — Agent Overview** (`infra/grafana/provisioning/dashboards/agent-overview.json`) includes:
- Tempo trace panels filtered by `resource.service.name` (agent, litellm, scraper)
- Prometheus `up` stat panel for scrape target health

To inspect a specific run: copy `trace_id` from logs → Grafana **Explore** → Tempo → paste ID.

### Data pipeline

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

## 15. Report Assembly — `agent/report.py`

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

### Output destinations

| Destination | Format | When |
|---|---|---|
| stdout | JSON (1 line) | Always |
| `REPORT_OUTPUT_PATH` | Pretty-printed JSON (indent=2) | If env var set |
| pgvector (`memory.py`) | JSON embedding + fingerprint metadata | After `report_node`, in `main.py` |

---

## 16. Docker Infrastructure — 11 Services

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

*Architecture deep-dive · Autonomous Pentesting Agent · May 2026*
