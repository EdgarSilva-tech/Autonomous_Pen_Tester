# Architectural Decisions

A log of decisions made and their rationale. Update this when a decision changes.

---

## ADR-001 — Test execution strategy: fully agentic planner

**Date:** 2026-06-20  
**Status:** Decided

**Decision:** The agent uses an LLM planner node that reasons over the fingerprint result and autonomously selects, sequences, and configures which test modules to run.

**Alternatives considered:**
- Fixed pipeline (always run all modules in order) — rejected: inefficient, not adaptive
- Hybrid planner selecting from fixed modules — rejected: planner is more powerful without the constraint

**Consequences:** The planner prompt is critical; needs careful engineering. Test coverage is not guaranteed — the evaluator node must verify completeness.

---

## ADR-002 — HTTP tool layering: three layers (primitives + attack tools + MCP)

**Date:** 2026-06-20  
**Status:** Updated 2026-06-20 (Layer 3 added)

**Decision:** Three-layer tool architecture:
- **Layer 1 (primitives):** `http_get`, `http_post`, `http_put`, `http_delete` — generic, API-agnostic, always present
- **Layer 2 (attack tools):** named tools per vulnerability class that use Layer 1 internally, always present
- **Layer 3 (MCP tools):** external tools discovered at startup via `mcp_client.py` — optional, additive

The planner sees all layers as a flat tool list and chooses accordingly. Scanner works standalone on Layer 1+2 alone.

**Alternatives considered:**
- Pure primitives — rejected: LLM has too much surface area to hallucinate attack details
- Pure named tools — rejected: can't anticipate every attack type; inflexible for novel endpoints
- MCP-only extensibility — rejected: scanner must work without any MCP servers configured

**Consequences:** Three layers to understand but clean separation. Layer 3 is zero-cost when not configured.

---

## ADR-003 — Report formats: JSON + Markdown

**Date:** 2026-06-20  
**Status:** Decided

**Decision:** Generate both JSON (machine-readable, for integrations) and Markdown (human-readable, for review) reports.

**Deferred:** HTML report — useful for sharing, but lower priority than getting the core scanner working.

---

## ADR-004 — Existing auth tools: refactor, not replace

**Date:** 2026-06-20  
**Status:** Decided

**Decision:** The current auth tools (login, me, change_password, logout) are refactored into `agent/tools/attacks/auth.py` as thin wrappers over the new primitives. They are not deleted. All existing tests must continue to pass.

**Rationale:** Preserves working functionality; auth testing is still a core module of the v2 scanner.

---

## ADR-005 — API type detection: signal-based heuristics

**Date:** 2026-06-20  
**Status:** Decided

**Decision:** API type is detected by probing known signals in priority order:
1. `/openapi.json` or `/swagger.json` → REST + OpenAPI
2. GraphQL introspection query → GraphQL
3. `?wsdl` response with XML → SOAP
4. `Content-Type: application/grpc` → gRPC
5. Fallback → REST specless (path fuzzing)

**Consequences:** gRPC detection is limited without a live protobuf reflection endpoint. gRPC adapter is a stub for now (ADR-006).

---

## ADR-006 — gRPC adapter: stub for now

**Date:** 2026-06-20  
**Status:** Decided

**Decision:** The gRPC adapter (`agent/recon/api_adapters/grpc.py`) is implemented as a stub that detects gRPC and reports it, but does not execute test modules against it.

**Rationale:** gRPC testing requires protobuf reflection, which needs the `grpc` library and a different HTTP transport. Out of scope for the initial v2 release.

**Revisit when:** A gRPC target is actually needed.

---

## ADR-007 — MCP as Layer 3 extensibility mechanism

**Date:** 2026-06-20  
**Status:** Decided

**Decision:** External security tools (nmap, nuclei, sqlmap, playwright, shodan) are integrated via MCP servers as an optional Layer 3. `mcp_client.py` discovers available MCP tools at startup and adds them to the planner's tool pool. No MCP servers configured = no behaviour change.

**Rationale:** MCP is already wired in via `mcp_client.py`. Using it as the extension point means new tools can be added without modifying the agent — just run a new MCP server and point the env config at it. The planner prompt already reasons over the available tool pool, so MCP tools are picked up automatically.

**Consequences:**
- The planner prompt must describe what each class of MCP tool is good for (so the LLM uses them appropriately)
- MCP server availability is non-deterministic at runtime — the planner must not assume any Layer 3 tool exists
- The scraper microservice may eventually be replaced by `playwright-mcp` (tracked in backlog)

**Revisit when:** A specific MCP server is being added — document it in this ADR.
