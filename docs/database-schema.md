# Database Schema

The agent uses a single PostgreSQL instance (with the `pgvector` extension) that is
divided into **three logical databases**, each owned by a different subsystem.

```
postgres:5432 (internal) / localhost:5433 (host via pgAdmin)
├── pentest          ← default maintenance DB (empty — not used by the app)
├── langgraph        ← LangGraph short-term checkpoints
├── litellm          ← LiteLLM spend / model-key tracking (65 tables via Prisma)
└── pentest_memory   ← pgvector long-term memory + site fingerprints
```

---

## 1. `langgraph` — Short-term / resumable run state

Managed entirely by `langgraph-checkpoint-postgres` (`AsyncPostgresSaver`).  
The agent never writes to this database directly.

### Tables (created by `checkpointer.setup()`)

#### `checkpoints`

Persists the full `PentestState` snapshot after **every node transition**.

| Column | Type | Description |
|---|---|---|
| `thread_id` | `TEXT` | Unique run identifier (UUID). One thread = one pentest run. |
| `checkpoint_ns` | `TEXT` | Namespace within the thread (always `""` for the root graph). |
| `checkpoint_id` | `TEXT` | UUID identifying this specific checkpoint version. |
| `parent_checkpoint_id` | `TEXT \| NULL` | Previous checkpoint in the same thread (linked list). |
| `type` | `TEXT` | Serializer type (`"msgpack"` or `"json"`). |
| `checkpoint` | `BYTEA` | Serialised `PentestState` — includes the full `messages` list, all accumulated `step_results`, `anomalies`, `drift_context`, `eval_result`, etc. |
| `metadata` | `BYTEA` | LangGraph internal routing metadata. |

> **Why it matters:** if the agent crashes mid-run, re-running with the same
> `--thread-id` resumes from the last persisted node rather than starting over.

#### `checkpoint_blobs`

Stores large binary values referenced by checkpoints (overflow for very large
message histories after many summarisation cycles).

| Column | Type | Description |
|---|---|---|
| `thread_id` | `TEXT` | Foreign key to `checkpoints`. |
| `checkpoint_ns` | `TEXT` | Namespace. |
| `channel` | `TEXT` | State key name (e.g. `"messages"`). |
| `version` | `TEXT` | Monotonically increasing version tag. |
| `type` | `TEXT` | Serializer type. |
| `blob` | `BYTEA \| NULL` | The serialised channel value. |

#### `checkpoint_writes`

Write-ahead log for in-progress node outputs (used for fault tolerance).

| Column | Type | Description |
|---|---|---|
| `thread_id` | `TEXT` | Run identifier. |
| `checkpoint_ns` | `TEXT` | Namespace. |
| `checkpoint_id` | `TEXT` | Associated checkpoint. |
| `task_id` | `TEXT` | Node task identifier. |
| `idx` | `INTEGER` | Write index within the task. |
| `channel` | `TEXT` | State key being written. |
| `type` | `TEXT` | Serializer type. |
| `blob` | `BYTEA` | Serialised partial state. |

---

## 2. `litellm` — AI gateway spend & model-key tracking

Managed entirely by the LiteLLM proxy container.  
The agent never writes to this database directly.

### Notable tables

#### `"LiteLLM_SpendLogs"`

One row per LLM API call routed through the proxy. (Table name is case-sensitive.)

| Column | Type | Description |
|---|---|---|
| `request_id` | `TEXT` | Unique request UUID. |
| `call_type` | `TEXT` | `"completion"`, `"embedding"`, etc. |
| `spend` | `FLOAT` | Estimated USD cost for this call. |
| `total_tokens` | `INTEGER` | Prompt + completion tokens. |
| `model` | `TEXT` | Resolved model name (e.g. `"gpt-4o-mini"`). |
| `startTime` | `TIMESTAMP` | Request start timestamp. |
| `endTime` | `TIMESTAMP` | Response received timestamp. |

> **Note:** `"LiteLLM_ModelTable"` is often empty when models are defined in
> `litellm/config.yaml` rather than via the LiteLLM UI. Spend logs and daily
> spend aggregation tables are the most useful for demos.

> **Dashboard:** `http://localhost:4000/ui` shows spend graphs and call logs.

---

## 3. `pentest_memory` — Long-term memory (pgvector)

Managed by `langchain-postgres` (`PGVector`) via the `agent/memory.py` module.

### Extension

```sql
CREATE EXTENSION IF NOT EXISTS vector;
```

### Tables (created automatically by `PGVector` on first write)

#### `langchain_pg_collection`

One row per named collection. The agent uses the collection `pentest_runs`.

| Column | Type | Description |
|---|---|---|
| `uuid` | `UUID PK` | Collection identifier. |
| `name` | `TEXT UNIQUE` | Collection name — `"pentest_runs"`. |
| `cmetadata` | `JSONB` | Optional collection-level metadata. |

#### `langchain_pg_embedding`

One row per stored pentest run report.

| Column | Type | Description |
|---|---|---|
| `id` | `VARCHAR PK` | Document identifier. |
| `collection_id` | `UUID FK` | References `langchain_pg_collection.uuid`. |
| `embedding` | `VECTOR(1536)` | 1 536-dimension embedding of the report JSON, produced by `text-embedding-3-small` via the LiteLLM proxy. Used for cosine-similarity retrieval. |
| `document` | `TEXT` | The full `PentestReport` serialised as JSON (see schema below). |
| `cmetadata` | `JSONB` | Per-document metadata (see below). |

##### `document` content — `PentestReport` JSON

```json
{
  "status": "success | partial_failure | failure",
  "elapsed_ms": 4321,
  "thread_id": "fa3755d1-...",
  "steps": [
    {
      "name": "login",
      "status": "ok",
      "http_status": 200,
      "error_msg": null,
      "timestamp": "2026-05-25T09:22:37Z",
      "decision": "Received access_token. Proceeding."
    }
  ],
  "anomalies": [
    {
      "type": "predictable_token",
      "description": "Token is deterministic and encodes partial password",
      "evidence": "tok-testuser-Init — first 4 chars of password visible"
    }
  ],
  "evaluation": {
    "approved": true,
    "confidence": 0.95,
    "feedback": "All steps completed with supporting evidence.",
    "missing_steps": [],
    "unsupported_anomalies": [],
    "suggested_actions": []
  }
}
```

##### `cmetadata` fields

| Key | Type | Description |
|---|---|---|
| `target` | `string` | Target base URL (e.g. `"http://target-app:8000"`). Used as the similarity-search query on the next run. |
| `status` | `string` | `"success"`, `"partial_failure"`, or `"failure"`. |
| `thread_id` | `string` | UUID of the run that produced this document. |
| `anomaly_count` | `integer` | Number of anomalies found — quick filter without deserialising the document. |
| `site_fingerprint` | `string` | JSON-serialised `SiteFingerprint` (see below). Stored as a string because JSONB metadata values must be scalars or flat JSON. |

##### `site_fingerprint` sub-schema

When deserialised, this is a `SiteFingerprint` dataclass:

```json
{
  "target_url": "http://target-app:8000",
  "probed_at": "2026-05-25T09:22:37.213191+00:00",
  "openapi": {
    "title": "Pentest Challenge — Target App",
    "version": "1.0.0",
    "operations": {
      "POST /login": ["password", "username"],
      "GET /me": ["authorization"],
      "POST /change-password": ["authorization"],
      "POST /logout": ["authorization"]
    },
    "raw": { "... full /openapi.json schema ..." }
  },
  "endpoints": {
    "POST /login": {
      "method": "POST",
      "path": "/login",
      "status": 401,
      "has_json_body": true,
      "json_keys": ["detail"]
    },
    "GET /me": { "method": "GET", "path": "/me", "status": 401, "...": "..." },
    "POST /change-password": { "...": "..." },
    "POST /logout": { "...": "..." }
  },
  "scrape": {
    "has_html_frontend": false,
    "is_spa_static": false,
    "static_forms": [],
    "js_api_urls": [],
    "playwright_available": false
  }
}
```

> **How drift detection works:** at the start of each run, the most recent
> `site_fingerprint` for the target is retrieved from `cmetadata`. The agent
> probes the live site and compares OpenAPI operations/params, endpoint status
> codes, JSON key sets, and frontend scrape data. Any differences are formatted
> as a `drift_context` string and injected into the LLM system prompt before
> the ReAct loop begins.

##### Querying the fingerprint in pgAdmin

```sql
SELECT jsonb_pretty(
    (cmetadata->>'site_fingerprint')::jsonb -> 'openapi' -> 'operations'
) AS openapi_operations
FROM langchain_pg_embedding
WHERE cmetadata ? 'site_fingerprint'
ORDER BY id DESC
LIMIT 1;
```

---

## Data flow summary

```
Run N ends
  └─► agent/memory.py::store_run()
        ├─ embed PentestReport JSON  (OpenAI text-embedding-3-small via LiteLLM)
        └─ INSERT INTO langchain_pg_embedding
             document  = PentestReport JSON
             embedding = 1536-dim vector
             cmetadata = { target, status, thread_id, anomaly_count,
                           site_fingerprint: SiteFingerprint JSON }

Run N+1 starts
  └─► agent/memory.py::retrieve_similar_runs(target_url, k=3)
        ├─ cosine similarity search against stored embeddings
        ├─ returns top-3 past report texts  → injected into system prompt
        └─ returns most recent SiteFingerprint → used for drift detection

  └─► agent/probe.py::probe_site()          (OpenAPI + live HTTP + scrape)
  └─► agent/probe.py::compare_fingerprints() (old vs new — OpenAPI + API + frontend)
        └─► drift_context string → injected into LLM system prompt
  └─► agent/probe.py::build_openapi_context()
        └─► openapi_context string → injected into LLM system prompt
```

---

## Connection strings

| Database | URI pattern | Driver |
|---|---|---|
| `langgraph` | `postgresql://pentest:pentest@postgres:5432/langgraph` | `psycopg3` (via `AsyncConnectionPool`) |
| `pentest_memory` | `postgresql+psycopg://pentest:pentest@postgres:5432/pentest_memory` | `psycopg3` (sync, via `langchain-postgres`) |
| `litellm` | `postgresql://pentest:pentest@postgres:5432/litellm` | managed by LiteLLM container |

All three application databases share the same PostgreSQL instance and the same
`pentest / pentest` credentials (configurable via `.env`).

**External access (pgAdmin / DBeaver):** `localhost:5433` — mapped in
`docker-compose.yml` to avoid conflict with a local PostgreSQL on `:5432`.
Inside the Docker network, services connect to `postgres:5432`.
