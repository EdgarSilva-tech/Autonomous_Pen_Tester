"""Long-term memory backed by pgvector.

At the end of every run the final JSON report is embedded and stored.
At the start of every run the top-k most similar past reports are retrieved
and injected into the system prompt as contextual memory.

Additionally, the site fingerprint (produced by ``agent.probe``) is stored
in the document's metadata and retrieved on the next run so that structural
changes (drift) can be detected before the main agent loop starts.

Embeddings are generated via the LiteLLM proxy (text-embedding-3-small),
which means OpenAI usage is tracked and cached alongside LLM calls.
"""
from __future__ import annotations

import json
import os
from typing import Any

from agent.logger import get_logger
from agent.probe import SiteFingerprint
from agent.state import PentestReport

log = get_logger(__name__)

_COLLECTION = "pentest_runs"
_EMBEDDING_MODEL = "text-embedding-3-small"


def _get_embeddings():
    """Build an OpenAIEmbeddings instance pointing at the LiteLLM proxy."""
    from langchain_openai import OpenAIEmbeddings  # type: ignore

    return OpenAIEmbeddings(
        model=_EMBEDDING_MODEL,
        openai_api_base=os.getenv("LITELLM_BASE_URL", "http://localhost:4000"),
        openai_api_key=os.getenv("LITELLM_API_KEY", "sk-pentest-master"),
    )


def _get_store():
    """Build a PGVector store for the pentest_memory database."""
    from langchain_postgres.vectorstores import PGVector  # type: ignore

    connection_string = os.getenv(
        "MEMORY_DB_URI",
        "postgresql+asyncpg://pentest:pentest@localhost:5432/pentest_memory",
    )
    # Use psycopg3 (sync) driver — psycopg2 is not installed
    sync_uri = connection_string.replace("+asyncpg", "+psycopg")

    return PGVector(
        embeddings=_get_embeddings(),
        collection_name=_COLLECTION,
        connection=sync_uri,
        use_jsonb=True,
    )


async def retrieve_similar_runs(
    target_url: str,
    k: int = 3,
) -> tuple[list[str], SiteFingerprint | None]:
    """Return past run summaries and the most recent site fingerprint.

    Returns:
        summaries: list of past report strings (for prompt injection)
        last_fingerprint: the SiteFingerprint from the most recent run, or
                          None if no previous runs exist for this target.
    """
    try:
        store = _get_store()
        docs = store.similarity_search(target_url, k=k)

        summaries = [d.page_content for d in docs]

        # Extract the most recent fingerprint from metadata
        last_fingerprint: SiteFingerprint | None = None
        for doc in docs:
            fp_dict = (doc.metadata or {}).get("site_fingerprint")
            if fp_dict:
                try:
                    if isinstance(fp_dict, str):
                        fp_dict = json.loads(fp_dict)
                    last_fingerprint = SiteFingerprint.from_dict(fp_dict)
                    break  # take the first (most similar) fingerprint found
                except Exception as parse_exc:
                    log.warning(
                        "memory.fingerprint_parse_failed",
                        error=str(parse_exc),
                    )

        log.info(
            "memory.retrieved",
            count=len(summaries),
            target=target_url,
            has_fingerprint=last_fingerprint is not None,
        )
        return summaries, last_fingerprint

    except Exception as exc:
        log.warning("memory.retrieve_failed", error=str(exc))
        return [], None


async def store_run(
    report: PentestReport,
    target_url: str,
    fingerprint: SiteFingerprint | None = None,
) -> None:
    """Embed and store the completed run report in the pgvector store.

    The site fingerprint (if provided) is serialised and stored in the
    document's metadata so it can be retrieved on the next run for drift
    detection.
    """
    try:
        store = _get_store()
        text = report.model_dump_json(indent=None)
        metadata: dict[str, Any] = {
            "target": target_url,
            "status": report.status,
            "thread_id": report.thread_id,
            "anomaly_count": len(report.anomalies),
        }

        if fingerprint is not None:
            # Store as JSON string — pgvector metadata values must be scalars
            # or JSON-serialisable; we serialise the nested dict to a string.
            metadata["site_fingerprint"] = json.dumps(fingerprint.to_dict())

        store.add_texts(texts=[text], metadatas=[metadata])
        log.info(
            "memory.stored",
            target=target_url,
            status=report.status,
            thread_id=report.thread_id,
            fingerprint_stored=fingerprint is not None,
        )
    except Exception as exc:
        log.warning("memory.store_failed", error=str(exc))
