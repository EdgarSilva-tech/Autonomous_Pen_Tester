"""CLI entrypoint for the Autonomous Pentesting Agent.

Usage:
    python -m agent.main          # reads all config from environment variables
    python -m agent.main --help   # show options

Environment variables (all can also be passed as CLI flags):
    TARGET_BASE_URL         URL of the target FastAPI app
    AGENT_USERNAME          Username to test
    AGENT_PASSWORD          Initial password
    AGENT_NEW_PASSWORD      New password (generated randomly if not set)
    LITELLM_BASE_URL        LiteLLM proxy URL
    LITELLM_API_KEY         LiteLLM master key / virtual key
    LANGGRAPH_DB_URI        PostgreSQL URI for LangGraph checkpoints
    MEMORY_DB_URI           PostgreSQL+pgvector URI for long-term memory
    OTEL_EXPORTER_OTLP_ENDPOINT  OpenTelemetry collector gRPC endpoint
    LOG_LEVEL               Logging level (default: INFO)
    REPORT_OUTPUT_PATH      File path for JSON report (optional)
    SUMMARY_THRESHOLD       Max non-system messages before summarisation
    SUMMARY_RECENT_KEEP     Recent messages kept verbatim after summarisation
    MAX_EVAL_RETRIES        Max evaluation retry cycles (default: 2)
"""
from __future__ import annotations

import asyncio
import secrets
import uuid

import click

from agent.logger import get_logger, setup_logging
from agent.memory import retrieve_similar_runs, store_run
from agent.probe import (
    build_openapi_context,
    compare_fingerprints,
    probe_site,
)
from agent.recon.fingerprint import fingerprint_target
from agent.telemetry import (
    end_root_span,
    get_current_trace_id,
    setup_telemetry,
)


@click.command()
@click.option(
    "--target-url",
    envvar="TARGET_BASE_URL",
    required=True,
    help="Target app base URL",
)
@click.option(
    "--username",
    envvar="AGENT_USERNAME",
    required=True,
    help="Test username",
)
@click.option(
    "--password",
    envvar="AGENT_PASSWORD",
    required=True,
    help="Initial password",
)
@click.option(
    "--new-password",
    envvar="AGENT_NEW_PASSWORD",
    default="",
    help="New password (random if empty)",
)
@click.option(
    "--log-level",
    envvar="LOG_LEVEL",
    default="INFO",
    help="Logging level",
)
@click.option(
    "--thread-id",
    default="",
    help="Resume a previous run by thread ID",
)
def main(
    target_url: str,
    username: str,
    password: str,
    new_password: str,
    log_level: str,
    thread_id: str,
) -> None:
    """Autonomous Pentesting Agent — security scanner."""
    asyncio.run(
        _run(
            target_url=target_url,
            username=username,
            password=password,
            new_password=new_password,
            log_level=log_level,
            thread_id=thread_id,
        )
    )


async def _run(
    target_url: str,
    username: str,
    password: str,
    new_password: str,
    log_level: str,
    thread_id: str,
) -> None:
    # ── 1. Logging ─────────────────────────────────────────────────────────
    setup_logging(log_level)
    log = get_logger("main")

    # ── 2. Telemetry ────────────────────────────────────────────────────────
    tracer_provider = setup_telemetry(
        target_url=target_url, username=username
    )
    trace_id = get_current_trace_id()

    # ── 3. Resolve credentials and IDs ──────────────────────────────────────
    effective_new_password = new_password or secrets.token_urlsafe(16)
    effective_thread_id = thread_id or str(uuid.uuid4())

    log.info(
        "agent.starting",
        target=target_url,
        username=username,
        new_password=effective_new_password,
        thread_id=effective_thread_id,
        trace_id=trace_id,
        resuming=bool(thread_id),
    )

    # ── 4. Long-term memory ──────────────────────────────────────────────────
    past_context, last_fingerprint = await retrieve_similar_runs(
        target_url, k=3
    )
    if past_context:
        log.info("agent.memory_loaded", past_runs=len(past_context))

    # ── 5. Site probes (v1 drift + v2 fingerprint run in parallel) ──────────
    log.info("agent.probing_site", target=target_url)
    current_fingerprint, v2_fingerprint = await asyncio.gather(
        probe_site(target_url),
        fingerprint_target(target_url),
    )

    # ── 6. Drift detection + OpenAPI enrichment ──────────────────────────────
    drift_context = compare_fingerprints(
        last_fingerprint, current_fingerprint
    )
    openapi_context = build_openapi_context(current_fingerprint.openapi)

    if drift_context:
        log.warning(
            "agent.drift_detected",
            target=target_url,
            last_probed_at=(
                last_fingerprint.probed_at if last_fingerprint else None
            ),
            current_probed_at=current_fingerprint.probed_at,
        )
    else:
        log.info(
            "agent.no_drift",
            target=target_url,
            first_run=last_fingerprint is None,
        )

    log.info(
        "agent.fingerprint_ready",
        api_type=v2_fingerprint.api_type.value,
        endpoint_count=len(v2_fingerprint.endpoints),
        auth_mechanisms=v2_fingerprint.auth_mechanisms,
    )

    # ── 7. Build and run the graph ───────────────────────────────────────────
    from langchain_core.messages import HumanMessage
    # deferred import avoids circular at module load
    from agent.graph import build_graph

    graph = await build_graph()

    initial_state = {
        "messages": [
            HumanMessage(content="Begin the penetration test.")
        ],
        "base_url": target_url,
        "username": username,
        "current_password": password,
        "new_password": effective_new_password,
        "thread_id": effective_thread_id,
        "session_token": None,
        "retry_count": 0,
        "step_results": [],
        "anomalies": [],
        "error": None,
        "final_status": None,
        "past_context": past_context,
        "drift_context": drift_context,
        "openapi_context": openapi_context,
        "summary_count": 0,
        "eval_result": None,
        "eval_attempts": 0,
        "trace_id": trace_id,
        # v2 fields
        "fingerprint": v2_fingerprint.to_dict(),
        "test_plan": [],
        "findings": [],
        "scope": None,
    }

    config = {
        "configurable": {"thread_id": effective_thread_id},
        "recursion_limit": 60,
    }
    final_state = await graph.ainvoke(initial_state, config=config)

    # ── 8. Long-term memory — store the completed run ────────────────────────
    from agent.state import Anomaly, PentestReport, StepResult

    report = PentestReport(
        status=final_state.get("final_status") or "failure",
        steps=[
            StepResult(**s) for s in final_state.get("step_results", [])
        ],
        anomalies=[
            Anomaly(**a) for a in final_state.get("anomalies", [])
        ],
        thread_id=effective_thread_id,
    )
    await store_run(report, target_url, fingerprint=current_fingerprint)

    log.info(
        "agent.done",
        status=report.status,
        thread_id=effective_thread_id,
        trace_id=trace_id,
        drift_detected=drift_context is not None,
        summary_count=final_state.get("summary_count", 0),
        eval_attempts=final_state.get("eval_attempts", 0),
    )

    # ── 9. Close root span and flush OTel spans ──────────────────────────────
    end_root_span()
    if tracer_provider is not None:
        tracer_provider.force_flush(timeout_millis=5000)


if __name__ == "__main__":
    main()
