"""Main entrypoint for the Agentic PQC Workspace (Google ADK multi-agent system on Gemini / Vertex AI).

Commands:
- `python main.py serve`  — start the Workspace Portal + ADK /dev-ui/ (also served by `uvicorn main:app`).
- `python main.py ask --scope organizations/<id>` — run one real agent turn on Gemini and print the answer together with
  the model telemetry. If the model fails, the error is printed; no templated report is substituted.
- `python main.py tools --scope demo-pqc-project` — smoke-test the evidence/calculation tools (no LLM is invoked).
- `python main.py cbom --scope organizations/<id>` — export the CycloneDX v1.6 CBOM from the live KMS inventory.
- `python main.py deploy --project <id>` — deploy the agent to Vertex AI Agent Engine.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import threading
from typing import Any, Dict, Optional

from dotenv import load_dotenv

load_dotenv()

from pqc_agent.agent import DEFAULT_MODEL, DEFAULT_THINKING_LEVEL, create_pqc_agent, root_agent  # noqa: E402

agent = root_agent

_WORKSPACE_APP_LOCK = threading.Lock()
_WORKSPACE_APP: Optional[Any] = None


def get_workspace_app() -> Any:
    """Lazily initializes and returns the singleton FastAPI Workspace Portal application.

    Keeps non-server CLI paths (`deploy`, `tools`, `cbom`, `--help`) decoupled from database startup while preserving
    full fail-closed PostgreSQL, Alembic schema, and Secret Manager checks when the web server or `ask` path runs.
    """
    global _WORKSPACE_APP
    if _WORKSPACE_APP is not None:
        return _WORKSPACE_APP
    with _WORKSPACE_APP_LOCK:
        if _WORKSPACE_APP is None:
            preloaded = "pqc_agent.workspace_server" in sys.modules
            from pqc_agent import workspace_server as _ws

            _WORKSPACE_APP = _ws.create_workspace_app() if preloaded else _ws.app
        return _WORKSPACE_APP


def __getattr__(name: str) -> Any:
    """PEP 562 lazy module attributes so `uvicorn main:app` initializes the server only when accessed."""
    if name == "app":
        return get_workspace_app()
    if name == "session_service":
        return get_workspace_app().state.session_service
    if name == "artifact_service":
        return get_workspace_app().state.artifact_service
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def get_agent_engine_app():
    """Packages the ADK agent into an AdkApp for Vertex AI Agent Engine."""
    from vertexai import agent_engines

    return agent_engines.AdkApp(agent=agent, enable_tracing=True)


async def run_adk_agent_turn(
    prompt: str,
    user_id: str = "sec-architect",
    session_id: Optional[str] = None,
    model_name: str = DEFAULT_MODEL,
    thinking_level: Optional[str] = DEFAULT_THINKING_LEVEL,
) -> Dict[str, Any]:
    """Runs one real agent turn and returns the answer plus the model telemetry (or an explicit error)."""
    from google.adk.apps import App
    from google.adk.runners import Runner
    from google.genai import types

    from pqc_agent.telemetry import LlmCallTelemetryPlugin, capture_llm_calls, summarize_llm_calls

    ws_app = get_workspace_app()
    sess_service = ws_app.state.session_service
    art_service = ws_app.state.artifact_service
    cred_service = ws_app.state.credential_service

    runner = Runner(
        app=App(
            name="pqc_agent",
            root_agent=create_pqc_agent(model_name=model_name, thinking_level=thinking_level),
            plugins=[LlmCallTelemetryPlugin()],
        ),
        session_service=sess_service,
        artifact_service=art_service,
        credential_service=cred_service,
        auto_create_session=True,
    )
    session = None
    if session_id:
        session = await sess_service.get_session(app_name="pqc_agent", user_id=user_id, session_id=session_id)
    if session is None:
        session = await sess_service.create_session(app_name="pqc_agent", user_id=user_id)

    content = types.Content(role="user", parts=[types.Part.from_text(text=prompt)])
    text_parts = []
    error: Optional[Dict[str, Any]] = None
    with capture_llm_calls() as ledger:
        try:
            async for event in runner.run_async(user_id=user_id, session_id=session.id, new_message=content):
                if getattr(event, "error_code", None):
                    error = {"code": event.error_code, "message": event.error_message}
                if event.is_final_response() and event.content and event.content.parts:
                    text_parts.extend(p.text for p in event.content.parts if p.text and not getattr(p, "thought", False))
        except Exception as exc:
            error = {"code": type(exc).__name__, "message": str(exc)}

    answer = "\n".join(text_parts).strip()
    return {
        "session_id": session.id,
        "status": "OK" if answer else "MODEL_ERROR",
        "response": answer,
        "error": None if answer else (error or {"code": "EMPTY_MODEL_RESPONSE", "message": "No text returned."}),
        "served_by": summarize_llm_calls(ledger),
    }


def run_tools_smoke_test(scope: str = "demo-pqc-project", location: str = "all") -> Dict[str, Any]:
    """Runs the evidence and calculation tools only (no LLM). Useful to validate permissions and data collection."""
    from tools.gcp_inventory import collect_kms_inventory, collect_workload_evidence, compute_pqc_scorecard
    from tools.pqc_detectors import collect_kms_import_jobs, collect_tls_policies
    from tools.quantum_engine import run_quantum_cryptanalysis_simulation

    inventory = json.loads(collect_kms_inventory(scope=scope, location=location))
    return {
        "llm_invoked": False,
        "scope": scope,
        "kms_inventory_summary": {k: inventory.get(k) for k in ("data_source", "key_count", "active_keys_by_quantum_status", "collection_errors", "error")},
        "scorecard": json.loads(compute_pqc_scorecard(scope=scope, location=location)),
        "workload_evidence_counts": {
            k: json.loads(collect_workload_evidence(scope=scope)).get(k) for k in ("data_source", "workload_count", "cmek_reference_count", "error")
        },
        "tls": {k: json.loads(collect_tls_policies(scope=scope)).get(k) for k in ("data_source", "target_proxies", "error")},
        "import_jobs": {k: json.loads(collect_kms_import_jobs(scope=scope, location=location)).get(k) for k in ("data_source", "import_jobs", "error")},
        "quantum_counts": json.loads(run_quantum_cryptanalysis_simulation(scope=scope, location=location)).get("counts_by_quantum_status"),
    }


def _ensure_staging_bucket(project_id: str, location: str, bucket_uri: str) -> str:
    from google.cloud import storage

    bucket_name = bucket_uri.replace("gs://", "").strip("/")
    client = storage.Client(project=project_id)
    bucket = client.bucket(bucket_name)
    if not bucket.exists():
        print(f"[*] Creating GCS staging bucket 'gs://{bucket_name}' in '{location}'...")
        bucket.iam_configuration.uniform_bucket_level_access_enabled = True
        client.create_bucket(bucket, location=location)
    return f"gs://{bucket_name}"


def deploy_to_agent_engine(
    project_id: str,
    location: str = "us-central1",
    staging_bucket: Optional[str] = None,
    display_name: str = "Agentic PQC Workspace (Gemini multi-agent)",
) -> str:
    """Packages and deploys the multi-agent system to Vertex AI Agent Engine."""
    import vertexai
    from vertexai import agent_engines

    raw_bucket = staging_bucket or os.getenv("GOOGLE_CLOUD_STAGING_BUCKET") or f"gs://{project_id}-pqc-agent-staging"
    bucket = _ensure_staging_bucket(project_id=project_id, location=location, bucket_uri=raw_bucket)
    vertexai.init(project=project_id, location=location, staging_bucket=bucket)

    remote_agent = agent_engines.create(
        get_agent_engine_app(),
        requirements=[
            "google-adk>=2.0.0",
            "google-genai>=1.0.0",
            "google-cloud-aiplatform[adk,agent_engines]>=1.93.0",
            "google-cloud-asset>=3.26.0",
            "google-cloud-kms>=2.24.0",
            "google-cloud-storage>=2.16.0",
            "sqlalchemy>=2.0.0",
            "psycopg[binary]>=3.2.0",
            "asyncpg>=0.30.0",
            "alembic>=1.14.0",
            "cryptography>=43.0.0",
            "pypdf>=4.0.0",
            "python-docx>=1.1.0",
            "pydantic>=2.8.0",
            "python-dotenv>=1.0.1",
            "cloudpickle==3.1.2",
        ],
        extra_packages=["./pqc_agent", "./tools"],
        env_vars={"PQC_EXPORT_GCS_BUCKET": bucket, "PQC_SIMULATION_MODE": "FALSE"},
        display_name=display_name,
        description="Gemini multi-agent PQC readiness assessment over live Google Cloud cryptographic evidence.",
    )
    print(f"[+] Deployed: {remote_agent.resource_name}")
    return remote_agent.resource_name


def main() -> None:
    parser = argparse.ArgumentParser(description="Agentic PQC Workspace CLI (Google ADK + Gemini on Vertex AI)")
    sub = parser.add_subparsers(dest="command", required=True)

    serve_p = sub.add_parser("serve", help="Start the Workspace Portal and ADK /dev-ui/")
    serve_p.add_argument("--host", default="0.0.0.0")
    serve_p.add_argument("--port", type=int, default=int(os.getenv("PORT", "8080")))

    ask_p = sub.add_parser("ask", help="Run one real agent turn on Gemini")
    ask_p.add_argument("--scope", default="organizations/31564119954")
    ask_p.add_argument("--prompt", default="")
    ask_p.add_argument("--model", default=DEFAULT_MODEL)
    ask_p.add_argument("--thinking-level", default=DEFAULT_THINKING_LEVEL)

    tools_p = sub.add_parser("tools", help="Smoke-test the evidence tools (no LLM)")
    tools_p.add_argument("--scope", default="demo-pqc-project")
    tools_p.add_argument("--location", default="all")

    cbom_p = sub.add_parser("cbom", help="Export the CycloneDX v1.6 CBOM from the KMS inventory")
    cbom_p.add_argument("--scope", default="organizations/31564119954")
    cbom_p.add_argument("--location", default="all")

    deploy_p = sub.add_parser("deploy", help="Deploy to Vertex AI Agent Engine")
    deploy_p.add_argument("--project", default=os.getenv("GOOGLE_CLOUD_PROJECT"), required=not bool(os.getenv("GOOGLE_CLOUD_PROJECT")))
    deploy_p.add_argument("--location", default="us-central1")
    deploy_p.add_argument("--staging-bucket", default=os.getenv("GOOGLE_CLOUD_STAGING_BUCKET"))

    args = parser.parse_args()
    if args.command == "serve":
        import uvicorn

        uvicorn.run(get_workspace_app(), host=args.host, port=args.port)
    elif args.command == "ask":
        prompt = args.prompt or f"Run a complete post-quantum cryptography readiness assessment for scope '{args.scope}'."
        result = asyncio.run(run_adk_agent_turn(prompt, model_name=args.model, thinking_level=args.thinking_level))
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    elif args.command == "tools":
        print(json.dumps(run_tools_smoke_test(args.scope, args.location), indent=2, ensure_ascii=False))
    elif args.command == "cbom":
        from tools.gcp_inventory import export_cyclonedx_cbom

        print(json.dumps(json.loads(export_cyclonedx_cbom(scope=args.scope, location=args.location)), indent=2, ensure_ascii=False))
    elif args.command == "deploy":
        deploy_to_agent_engine(project_id=args.project, location=args.location, staging_bucket=args.staging_bucket)


if __name__ == "__main__":
    main()
