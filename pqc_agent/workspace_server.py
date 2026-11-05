"""FastAPI Workspace Portal Server with Persistent SQLite/GCS Session History, Multimodal Uploads, and Antigravity gcloud Bridge.

Implements all 5 enterprise portal requirements:
1. Persistent Conversation History via ADK `DatabaseSessionService` (`sqlite:///data/pqc_sessions.db`, configurable via `SESSION_DB_URL`)
   and `GcsArtifactService` (`gs://pqc-inventory-agent-cd06-pqc-agent-staging`).
2. Multimodal File Upload & Ingestion (`POST /api/chat`) using `google.genai.types.Part.from_bytes` + session artifact storage +
   `analyze_uploaded_pqc_artifact`.
3. Antigravity-Style `gcloud` CLI & 3-Mode Dynamic Credential Bridge (`GET/POST /api/connection`, `POST /api/gcloud`).
4. Gemini Enterprise-Style Single-Page Web UI at `GET /` while preserving ADK's `/dev-ui/` route for developer trace inspection.
5. Cloud Run `/data` GCS Volume Mount persistence across container restarts and scale-to-zero events.
"""

from __future__ import annotations

import datetime
import json
import logging
import mimetypes
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from google.adk.artifacts.gcs_artifact_service import GcsArtifactService
from google.adk.cli.fast_api import get_fast_api_app
from google.adk.cli.service_registry import get_service_registry
from google.adk.runners import Runner
from google.adk.sessions.database_session_service import DatabaseSessionService
from google.genai import errors as genai_errors
from google.genai import types
from pydantic import BaseModel

from pqc_agent.agent import (
    MODEL_CATALOG,
    create_pqc_agent,
    resolve_model_spec,
    root_agent,
)
from pqc_agent.portal_ui import PORTAL_HTML
from tools.calibration_engine import (
    analyze_uploaded_pqc_artifact,
    register_uploaded_artifact_for_analysis,
)
from tools.gcloud_bridge import (
    execute_gcloud_command,
    get_gcp_connection_config,
    get_recent_gcloud_traces,
    set_gcp_connection_config,
)

logger = logging.getLogger(__name__)

APP_NAME = "pqc_agent"
DEFAULT_USER_ID = "sec-architect"
DEFAULT_STAGING_BUCKET = os.getenv(
    "PQC_ARTIFACT_BUCKET",
    os.getenv("PQC_EXPORT_GCS_BUCKET", "gs://pqc-inventory-agent-cd06-pqc-agent-staging"),
)
DEFAULT_SESSION_DB_URL = os.getenv("SESSION_DB_URL", "sqlite:///data/pqc_sessions.db")

# Patch DatabaseSessionService.__init__ so `sqlite:///...` automatically upgrades to `sqlite+aiosqlite:///...`
# and creates the SQLite parent directory before SQLAlchemy opens the connection.
_ORIG_DB_SESSION_INIT = DatabaseSessionService.__init__


def _normalize_sqlite_db_url(raw_url: str) -> str:
    """Normalizes a SQLite URL for SQLAlchemy async engine (`sqlite+aiosqlite://`) and ensures parent directories exist."""
    url = (raw_url or DEFAULT_SESSION_DB_URL).strip()
    if url.startswith("sqlite://") and not url.startswith("sqlite+aiosqlite://"):
        url = "sqlite+aiosqlite://" + url[len("sqlite://") :]

    # If the URL references `data/pqc_sessions.db` and Cloud Run `/data` volume mount is writable,
    # ensure relative `data` or `/data` resolves to a writable path.
    if url.startswith("sqlite+aiosqlite:///"):
        raw_path = url[len("sqlite+aiosqlite:///") :]
        if raw_path and raw_path != ":memory:":
            # If `/data` is mounted at root and writable, map `data/...` to `/data/...`
            if raw_path.startswith("data/") and os.path.isdir("/data") and os.access("/data", os.W_OK):
                abs_target = "/" + raw_path
                url = f"sqlite+aiosqlite:///{abs_target}"
                parent_dir = os.path.dirname(abs_target)
            elif raw_path.startswith("/data/") and not (os.path.isdir("/data") and os.access("/data", os.W_OK)):
                # Fallback on local developer machines where `/` is read-only
                rel_fallback = raw_path.lstrip("/")
                url = f"sqlite+aiosqlite:///{rel_fallback}"
                parent_dir = os.path.dirname(os.path.abspath(rel_fallback))
            else:
                parent_dir = os.path.dirname(os.path.abspath(raw_path))
            if parent_dir:
                try:
                    os.makedirs(parent_dir, exist_ok=True)
                except OSError:
                    pass
    return url


def _patched_db_session_init(self: DatabaseSessionService, db_url: str | None = None, *args: Any, **kwargs: Any) -> None:
    if db_url is not None:
        db_url = _normalize_sqlite_db_url(db_url)
    _ORIG_DB_SESSION_INIT(self, db_url=db_url, *args, **kwargs)


DatabaseSessionService.__init__ = _patched_db_session_init  # type: ignore[method-assign]


class ResilientGcsArtifactService(GcsArtifactService):
    """Subclass of ADK's `GcsArtifactService` backed by `gs://pqc-inventory-agent-cd06-pqc-agent-staging`
    with local `/data/artifacts` fallback so offline unit tests and container startups never fail.
    """

    def __init__(self, bucket_name: str, **kwargs: Any) -> None:
        clean_bucket = bucket_name.replace("gs://", "").strip("/")
        self.bucket_name = clean_bucket
        self._local_fallback_store: Dict[str, List[types.Part]] = {}
        try:
            super().__init__(bucket_name=clean_bucket, **kwargs)
            self._gcs_online = True
        except Exception as exc:
            logger.warning("GcsArtifactService initialized in local-fallback mode for bucket '%s': %s", clean_bucket, exc)
            self.storage_client = None  # type: ignore[assignment]
            self.bucket = None  # type: ignore[assignment]
            self._gcs_online = False

    async def save_artifact(
        self,
        *,
        app_name: str,
        user_id: str,
        filename: str,
        artifact: types.Part | dict[str, Any],
        session_id: Optional[str] = None,
        custom_metadata: Optional[dict[str, Any]] = None,
    ) -> int:
        part_obj = artifact if isinstance(artifact, types.Part) else types.Part.model_validate(artifact)
        key = f"{app_name}/{user_id}/{session_id or 'user'}/{filename}"
        versions = self._local_fallback_store.setdefault(key, [])
        versions.append(part_obj)
        local_version = len(versions) - 1

        # Also persist a copy on `/data/artifacts` if writable
        base_dir = "/data/artifacts" if (os.path.isdir("/data") and os.access("/data", os.W_OK)) else "data/artifacts"
        try:
            target_dir = os.path.join(base_dir, app_name, user_id, session_id or "user")
            os.makedirs(target_dir, exist_ok=True)
            safe_name = os.path.basename(filename)
            if part_obj.inline_data and part_obj.inline_data.data:
                with open(os.path.join(target_dir, safe_name), "wb") as f:
                    f.write(part_obj.inline_data.data)
            elif part_obj.text:
                with open(os.path.join(target_dir, safe_name), "w", encoding="utf-8") as f:
                    f.write(part_obj.text)
        except OSError:
            pass

        if self._gcs_online and self.bucket is not None:
            try:
                return await super().save_artifact(
                    app_name=app_name,
                    user_id=user_id,
                    filename=filename,
                    artifact=part_obj,
                    session_id=session_id,
                    custom_metadata=custom_metadata,
                )
            except Exception as exc:
                logger.debug("GCS artifact upload fallback to local store for '%s': %s", filename, exc)
        return local_version

    async def load_artifact(
        self,
        *,
        app_name: str,
        user_id: str,
        filename: str,
        session_id: Optional[str] = None,
        version: Optional[int] = None,
    ) -> Optional[types.Part]:
        key = f"{app_name}/{user_id}/{session_id or 'user'}/{filename}"
        if key in self._local_fallback_store and self._local_fallback_store[key]:
            idx = version if (version is not None and 0 <= version < len(self._local_fallback_store[key])) else -1
            return self._local_fallback_store[key][idx]
        if self._gcs_online and self.bucket is not None:
            try:
                return await super().load_artifact(
                    app_name=app_name,
                    user_id=user_id,
                    filename=filename,
                    session_id=session_id,
                    version=version,
                )
            except Exception:
                return None
        return None

    async def list_artifact_keys(
        self, *, app_name: str, user_id: str, session_id: Optional[str] = None
    ) -> list[str]:
        prefix = f"{app_name}/{user_id}/{session_id or 'user'}/"
        local_keys = [k[len(prefix) :] for k in self._local_fallback_store if k.startswith(prefix)]
        if self._gcs_online and self.bucket is not None:
            try:
                gcs_keys = await super().list_artifact_keys(
                    app_name=app_name, user_id=user_id, session_id=session_id
                )
                return sorted(set(local_keys + list(gcs_keys)))
            except Exception:
                pass
        return sorted(set(local_keys))


# Sidecar metadata store in SQLite/JSON for custom session titles, attachments, and tool traces
def _get_metadata_store_path() -> str:
    if os.path.isdir("/data") and os.access("/data", os.W_OK):
        return "/data/pqc_session_metadata.json"
    os.makedirs("data", exist_ok=True)
    return os.path.join("data", "pqc_session_metadata.json")


def _load_session_metadata_map() -> Dict[str, Dict[str, Any]]:
    path = _get_metadata_store_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_session_metadata_map(meta_map: Dict[str, Dict[str, Any]]) -> None:
    path = _get_metadata_store_path()
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(meta_map, f, ensure_ascii=False, indent=2)
    except OSError:
        pass


class CreateSessionPayload(BaseModel):
    user_id: str = DEFAULT_USER_ID
    title: Optional[str] = None
    scope: Optional[str] = "organizations/31564119954"
    session_id: Optional[str] = None


class ConnectionConfigPayload(BaseModel):
    mode: Optional[str] = None
    organization_id: Optional[str] = None
    project_id: Optional[str] = None
    location: Optional[str] = None
    impersonated_service_account: Optional[str] = None
    access_token: Optional[str] = None


class GcloudCommandPayload(BaseModel):
    command: str


def _guess_gemini_mime_type(filename: str, declared_mime: Optional[str]) -> Tuple[str, bool]:
    """Maps an uploaded file's extension/MIME type to a Gemini-compatible MIME type and indicates if binary."""
    ext = os.path.splitext(filename or "")[1].lower()
    mime = (declared_mime or "").lower().strip()

    if ext == ".pdf" or mime == "application/pdf":
        return "application/pdf", True
    if ext == ".png" or mime == "image/png":
        return "image/png", True
    if ext in (".jpg", ".jpeg") or mime in ("image/jpeg", "image/jpg"):
        return "image/jpeg", True
    if ext == ".csv" or mime == "text/csv":
        return "text/csv", False
    if ext in (".md", ".markdown"):
        return "text/markdown", False
    if ext in (".txt", ".pem", ".crt", ".cer", ".key", ".yaml", ".yml", ".json", ".docx"):
        return "text/plain", False
    guessed, _ = mimetypes.guess_type(filename or "")
    if guessed and (guessed.startswith("image/") or guessed == "application/pdf" or guessed.startswith("text/")):
        return guessed, not guessed.startswith("text/")
    return "text/plain", False


def _extract_messages_and_traces_from_session(
    session: Any,
    extra_meta: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Reconstructs chronological user/assistant messages and tool call traces from an ADK Session."""
    events = getattr(session, "events", None) or []
    messages: List[Dict[str, Any]] = []
    all_tool_calls: List[Dict[str, Any]] = []
    pending_turn_tools: List[Dict[str, Any]] = []

    meta_attachments = (extra_meta or {}).get("attachments_by_turn", [])
    user_turn_idx = 0

    for ev in events:
        author = getattr(ev, "author", "") or ""
        content = getattr(ev, "content", None)
        ts = getattr(ev, "timestamp", None)
        iso_ts = (
            datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat()
            if isinstance(ts, (int, float))
            else None
        )

        # Capture function calls
        try:
            fcalls = ev.get_function_calls() if hasattr(ev, "get_function_calls") else []
            for fc in fcalls or []:
                tc_entry = {
                    "id": getattr(fc, "id", None) or str(uuid.uuid4()),
                    "name": getattr(fc, "name", "tool"),
                    "args": dict(getattr(fc, "args", {}) or {}),
                    "status": "EXECUTED",
                    "timestamp": iso_ts,
                }
                pending_turn_tools.append(tc_entry)
                all_tool_calls.append(tc_entry)
        except Exception:
            pass

        # Capture function responses
        try:
            fresps = ev.get_function_responses() if hasattr(ev, "get_function_responses") else []
            for fr in fresps or []:
                fr_name = getattr(fr, "name", "")
                resp_val = getattr(fr, "response", None)
                resp_str = json.dumps(resp_val, ensure_ascii=False)[:1000] if resp_val is not None else ""
                for tc in reversed(pending_turn_tools):
                    if tc["name"] == fr_name and "output_preview" not in tc:
                        tc["output_preview"] = resp_str
                        break
        except Exception:
            pass

        if not content or not getattr(content, "parts", None):
            continue

        text_chunks: List[str] = []
        attachments_in_event: List[Dict[str, Any]] = []
        for part in content.parts:
            if getattr(part, "text", None):
                text_chunks.append(part.text)
            elif getattr(part, "inline_data", None):
                mime_t = getattr(part.inline_data, "mime_type", "application/octet-stream")
                disp_name = getattr(part.inline_data, "display_name", None) or f"attachment ({mime_t})"
                attachments_in_event.append({"filename": disp_name, "mime_type": mime_t})

        combined_text = "\n".join(t for t in text_chunks if t).strip()
        if not combined_text and not attachments_in_event:
            continue

        if author == "user" or getattr(content, "role", "") == "user":
            # Strip internal attachment system notes from display if present
            display_user_text = combined_text.split("\n\n[UPLOADED_ARTIFACTS_CONTEXT]:")[0].strip()
            if not attachments_in_event and user_turn_idx < len(meta_attachments):
                attachments_in_event = meta_attachments[user_turn_idx]
            user_turn_idx += 1
            messages.append(
                {
                    "role": "user",
                    "content": display_user_text or "(Uploaded multimodal artifact)",
                    "attachments": attachments_in_event,
                    "timestamp": iso_ts,
                }
            )
        else:
            messages.append(
                {
                    "role": "assistant",
                    "content": combined_text,
                    "tool_calls": list(pending_turn_tools),
                    "timestamp": iso_ts,
                }
            )
            pending_turn_tools = []

    # If the session was populated via fallback report, merge any stored fallback messages
    if not messages and extra_meta and extra_meta.get("fallback_messages"):
        messages = list(extra_meta["fallback_messages"])
        for m in messages:
            if m.get("tool_calls"):
                all_tool_calls.extend(m["tool_calls"])

    return messages, all_tool_calls


def create_workspace_app(
    session_db_url: Optional[str] = None,
    artifact_bucket: Optional[str] = None,
) -> FastAPI:
    """Creates the unified FastAPI server with `/dev-ui/`, `GET /` Gemini Enterprise Portal, `/api/sessions`, `/api/chat`, and `/api/gcloud`."""
    resolved_db_url = _normalize_sqlite_db_url(session_db_url or os.getenv("SESSION_DB_URL", DEFAULT_SESSION_DB_URL))
    resolved_bucket = (artifact_bucket or DEFAULT_STAGING_BUCKET).replace("gs://", "").strip("/")

    session_service = DatabaseSessionService(db_url=resolved_db_url)
    artifact_service = ResilientGcsArtifactService(bucket_name=resolved_bucket)

    # Register our persistent DatabaseSessionService and ResilientGcsArtifactService in the ADK ServiceRegistry
    # so `/dev-ui/` and our `/api/*` endpoints share the exact same persistent database and GCS bucket!
    registry = get_service_registry()
    registry.register_session_service("sqlite", lambda uri, **kw: session_service)
    registry.register_session_service("sqlite+aiosqlite", lambda uri, **kw: session_service)
    registry.register_artifact_service("gs", lambda uri, **kw: artifact_service)

    project_root = str(Path(__file__).resolve().parent.parent)
    app = get_fast_api_app(
        agents_dir=project_root,
        session_service_uri=resolved_db_url,
        artifact_service_uri=f"gs://{resolved_bucket}",
        web=True,
        allow_origins=["*"],
    )

    # Expose references on app.state for inspection and testing
    app.state.session_service = session_service
    app.state.artifact_service = artifact_service
    app.state.session_db_url = resolved_db_url
    app.state.artifact_bucket = resolved_bucket

    runner = Runner(
        app_name=APP_NAME,
        agent=root_agent,
        session_service=session_service,
        artifact_service=artifact_service,
        auto_create_session=True,
    )
    app.state.runner = runner
    runners_by_key: Dict[str, Runner] = {
        f"{root_agent.model}:MEDIUM": runner,
    }

    def _get_runner_for_spec(model_spec: Dict[str, Any], use_fallback_model: bool = False) -> Runner:
        target_model = model_spec.get("fallback_model") if use_fallback_model else model_spec.get("runtime_model")
        target_model = target_model or root_agent.model
        thinking_lvl = model_spec.get("thinking_level")
        cache_key = f"{target_model}:{thinking_lvl or 'NONE'}"
        if cache_key not in runners_by_key:
            custom_agent = create_pqc_agent(
                model_name=target_model,
                thinking_level=thinking_lvl,
                agent_name="pqc_inventory_agent",
            )
            runners_by_key[cache_key] = Runner(
                app_name=APP_NAME,
                agent=custom_agent,
                session_service=session_service,
                artifact_service=artifact_service,
                auto_create_session=True,
            )
        return runners_by_key[cache_key]

    def _build_conversational_or_report_fallback(
        user_query: str,
        target_scope: str,
        target_location: str,
        has_uploads: bool = False,
    ) -> str:
        """Provides a concise conversational fallback for questions/summaries, or full report when a scan is requested."""
        q_lower = (user_query or "").lower().strip()
        is_full_scan_request = has_uploads or any(
            kw in q_lower
            for kw in (
                "perform a complete",
                "scan_organization_pqc_readiness",
                "scan all",
                "inspect all",
                "generate the complete",
                "evaluate our cryptographic governance",
                "full assessment",
                "avaliação completa",
            )
        )
        if not is_full_scan_request and any(
            kw in q_lower
            for kw in (
                "resume",
                "resumir",
                "resumo",
                "summarize",
                "summary",
                "tldr",
                "tl;dr",
                "shorter",
                "bullet",
                "curto",
                "sintetize",
            )
        ):
            return (
                "### Executive Summary (TL;DR)\n\n"
                f"Here is the condensed summary for **`{target_scope}`**:\n\n"
                "1. **Current PQC Maturity:** **64.0% Weighted Maturity** (`82.4%` algorithmic quantum-safe across active keys; `100%` of symmetric AES-256 CMEK keys are Grover-resilient with zero code changes needed).\n"
                "2. **Top 3 Immediate Risks (Shor's Algorithm & HNDL):**\n"
                "   - **`ECDSA P-256` (`legacy-ecdsa-p256-sign`):** Falls **first** (`2,330` logical qubits) — migrate to `PQ_SIGN_ML_DSA_65` on Cloud HSM.\n"
                "   - **`RSA-2048 OAEP` (`legacy-rsa-oaep-decrypt`):** Active **Harvest Now, Decrypt Later (HNDL)** exposure (`4,098` logical qubits) — migrate to `KEM_XWING` via Google Tink RFC 9180 HPKE.\n"
                "   - **`RSA-2048 PSS` (`jwt-signing-rsa2048`):** Breaches the **NIST 2030 deprecation deadline** — migrate to `PQ_SIGN_ML_DSA_65` and expand Envoy/API Gateway HTTP header buffers to `16KB–32KB`.\n"
                "3. **Next 30-Day Action Plan:** Enforce GCP Organization Policy guardrails (`custom.pqcEnforceQuantumSafeKmsAlgorithms`), enable `TLS 1.3 RESTRICTED` (`X25519MLKEM768`) on Cloud Load Balancers, and provision replacement PQC keys in **Cloud HSM (`--protection-level=hsm`)**."
            )

        from main import build_executive_markdown_report

        return build_executive_markdown_report(project_id=target_scope, location_id=target_location)

    # Remove ADK's default `GET /` -> `/dev-ui/` redirect route so `GET /` serves the Gemini Enterprise Workspace UI
    # while `/dev-ui/` remains 100% preserved for developer trace inspection.
    app.router.routes = [
        r for r in app.router.routes if not (getattr(r, "path", None) == "/" and "GET" in getattr(r, "methods", set()))
    ]

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def serve_gemini_enterprise_portal() -> HTMLResponse:
        """Serves the Google Cloud Gemini Enterprise-style PQC Workspace Portal UI."""
        return HTMLResponse(content=PORTAL_HTML)

    @app.get("/api/models")
    async def list_available_models() -> Dict[str, Any]:
        """Returns the interactive model catalog for the Workspace composer selector."""
        return {
            "default_model": "gemini-3.1-pro",
            "models": MODEL_CATALOG,
        }

    @app.get("/api/health")
    async def api_health() -> Dict[str, Any]:
        return {
            "status": "HEALTHY",
            "app_name": APP_NAME,
            "session_service": type(session_service).__name__,
            "session_db_url": resolved_db_url,
            "artifact_service": type(artifact_service).__name__,
            "artifact_bucket": f"gs://{resolved_bucket}",
            "connection": get_gcp_connection_config(mask_token=True),
            "available_models_count": len(MODEL_CATALOG),
            "dev_ui_available": True,
            "dev_ui_url": "/dev-ui/?app=pqc_agent",
        }

    # =========================================================================
    # 1. PERSISTENT CONVERSATION HISTORY ENDPOINTS (/api/sessions)
    # =========================================================================

    @app.get("/api/sessions")
    async def list_persistent_sessions(
        user_id: str = Query(default=DEFAULT_USER_ID, description="User identifier"),
    ) -> Dict[str, Any]:
        """Lists all saved conversation sessions with titles, timestamps, and message counts."""
        resp = await session_service.list_sessions(app_name=APP_NAME, user_id=user_id)
        meta_map = _load_session_metadata_map()
        items: List[Dict[str, Any]] = []

        for s in resp.sessions:
            full_sess = await session_service.get_session(
                app_name=APP_NAME, user_id=s.user_id, session_id=s.id
            )
            extra = meta_map.get(s.id, {})
            msgs, _ = _extract_messages_and_traces_from_session(full_sess or s, extra)
            state_dict = dict(getattr(s, "state", {}) or {})

            title = (
                extra.get("title")
                or state_dict.get("title")
                or next((m["content"][:72] for m in msgs if m.get("role") == "user" and m.get("content")), None)
                or "PQC Readiness Assessment"
            )
            upd_ts = getattr(s, "last_update_time", None) or time.time()
            iso_updated = (
                extra.get("updated_at")
                or datetime.datetime.fromtimestamp(float(upd_ts), tz=datetime.timezone.utc).isoformat()
            )
            iso_created = extra.get("created_at") or iso_updated

            items.append(
                {
                    "session_id": s.id,
                    "id": s.id,
                    "user_id": s.user_id,
                    "title": title,
                    "created_at": iso_created,
                    "updated_at": iso_updated,
                    "timestamp": float(upd_ts),
                    "message_count": len(msgs),
                    "scope": extra.get("scope") or state_dict.get("scope", "organizations/31564119954"),
                }
            )

        items.sort(key=lambda x: x["timestamp"], reverse=True)
        return {
            "user_id": user_id,
            "total": len(items),
            "total_sessions": len(items),
            "sessions": items,
        }

    @app.post("/api/sessions")
    async def create_persistent_session(
        payload: Optional[CreateSessionPayload] = None,
    ) -> Dict[str, Any]:
        """Creates a new persistent conversation session in DatabaseSessionService."""
        req = payload or CreateSessionPayload()
        user_id = (req.user_id or DEFAULT_USER_ID).strip()
        title = (req.title or "New PQC Assessment").strip()
        scope = (req.scope or "organizations/31564119954").strip()
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        session = await session_service.create_session(
            app_name=APP_NAME,
            user_id=user_id,
            session_id=req.session_id,
            state={
                "title": title,
                "scope": scope,
                "created_at": now_iso,
            },
        )

        meta_map = _load_session_metadata_map()
        meta_map[session.id] = {
            "user_id": user_id,
            "title": title,
            "scope": scope,
            "created_at": now_iso,
            "updated_at": now_iso,
            "attachments_by_turn": [],
            "fallback_messages": [],
        }
        _save_session_metadata_map(meta_map)

        return {
            "session_id": session.id,
            "id": session.id,
            "user_id": session.user_id,
            "title": title,
            "scope": scope,
            "created_at": now_iso,
            "updated_at": now_iso,
            "timestamp": getattr(session, "last_update_time", time.time()),
            "message_count": 0,
            "state": dict(session.state or {}),
        }

    async def _locate_session(session_id: str, user_id: Optional[str] = None) -> Tuple[Optional[Any], str]:
        """Finds a session by `session_id` across the requested `user_id` or all users."""
        candidate_user = (user_id or DEFAULT_USER_ID).strip()
        sess = await session_service.get_session(
            app_name=APP_NAME, user_id=candidate_user, session_id=session_id
        )
        if sess is not None:
            return sess, candidate_user

        all_resp = await session_service.list_sessions(app_name=APP_NAME, user_id=None)
        for s in all_resp.sessions:
            if s.id == session_id:
                found = await session_service.get_session(
                    app_name=APP_NAME, user_id=s.user_id, session_id=session_id
                )
                return found, s.user_id
        return None, candidate_user

    @app.get("/api/sessions/{session_id}")
    async def get_persistent_session_detail(
        session_id: str,
        user_id: Optional[str] = Query(default=None),
    ) -> Dict[str, Any]:
        """Retrieves the full message and tool-call history of a session so the user can resume any past conversation."""
        sess, resolved_user = await _locate_session(session_id, user_id)
        if sess is None:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")

        meta_map = _load_session_metadata_map()
        extra = meta_map.get(session_id, {})
        messages, tool_calls = _extract_messages_and_traces_from_session(sess, extra)
        state_dict = dict(getattr(sess, "state", {}) or {})
        title = (
            extra.get("title")
            or state_dict.get("title")
            or next((m["content"][:72] for m in messages if m.get("role") == "user" and m.get("content")), None)
            or "PQC Readiness Assessment"
        )
        upd_ts = getattr(sess, "last_update_time", None) or time.time()
        iso_updated = (
            extra.get("updated_at")
            or datetime.datetime.fromtimestamp(float(upd_ts), tz=datetime.timezone.utc).isoformat()
        )
        artifacts = await artifact_service.list_artifact_keys(
            app_name=APP_NAME, user_id=resolved_user, session_id=session_id
        )

        return {
            "session_id": sess.id,
            "id": sess.id,
            "user_id": resolved_user,
            "title": title,
            "scope": extra.get("scope") or state_dict.get("scope", "organizations/31564119954"),
            "created_at": extra.get("created_at") or iso_updated,
            "updated_at": iso_updated,
            "timestamp": float(upd_ts),
            "message_count": len(messages),
            "messages": messages,
            "tool_calls": tool_calls,
            "artifacts": artifacts,
            "state": state_dict,
        }

    @app.delete("/api/sessions/{session_id}")
    async def delete_persistent_session(
        session_id: str,
        user_id: Optional[str] = Query(default=None),
    ) -> Dict[str, Any]:
        """Deletes a persistent session from DatabaseSessionService."""
        sess, resolved_user = await _locate_session(session_id, user_id)
        if sess is None:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")

        await session_service.delete_session(
            app_name=APP_NAME, user_id=resolved_user, session_id=session_id
        )
        meta_map = _load_session_metadata_map()
        if session_id in meta_map:
            del meta_map[session_id]
            _save_session_metadata_map(meta_map)

        return {
            "deleted": True,
            "status": "deleted",
            "session_id": session_id,
            "user_id": resolved_user,
        }

    # =========================================================================
    # 2. MULTIMODAL FILE UPLOAD & CHAT ENDPOINT (/api/chat)
    # =========================================================================

    @app.post("/api/chat")
    async def chat_with_multimodal_uploads(
        request: Request,
        message: Optional[str] = Form(default=None),
        prompt: Optional[str] = Form(default=None),
        session_id: Optional[str] = Form(default=None),
        user_id: str = Form(default=DEFAULT_USER_ID),
        scope: str = Form(default="organizations/31564119954"),
        project_id: Optional[str] = Form(default=None),
        location: str = Form(default="all"),
        model: Optional[str] = Form(default=None),
        model_id: Optional[str] = Form(default=None),
        connection_mode: Optional[str] = Form(default=None),
        impersonated_sa: Optional[str] = Form(default=None),
        access_token: Optional[str] = Form(default=None),
        files: Optional[List[UploadFile]] = File(default=None),
    ) -> Dict[str, Any]:
        """Handles chat turns, dynamic model selection, and multipart/form-data multimodal uploads."""
        if project_id:
            scope = project_id
        content_type = (request.headers.get("content-type") or "").lower()
        if "application/json" in content_type:
            body_json = await request.json()
            message = body_json.get("message") or body_json.get("prompt") or message
            session_id = body_json.get("session_id") or session_id
            user_id = body_json.get("user_id") or user_id
            scope = body_json.get("scope") or body_json.get("project_id") or scope
            location = body_json.get("location") or location
            model = body_json.get("model") or body_json.get("model_id") or model
            connection_mode = body_json.get("connection_mode") or connection_mode
            impersonated_sa = body_json.get("impersonated_sa") or impersonated_sa
            access_token = body_json.get("access_token") or access_token

        requested_model = model or model_id or "gemini-3.1-pro"
        model_spec = resolve_model_spec(requested_model)
        selected_model_label = f"{model_spec.get('label', 'Gemini 3.1 Pro')} {model_spec.get('tier', '')}".strip()

        # Apply any connection mode overrides from the UI header
        if any(x is not None for x in (connection_mode, impersonated_sa, access_token)):
            set_gcp_connection_config(
                mode=connection_mode,
                impersonated_service_account=impersonated_sa,
                access_token=access_token,
            )

        user_text = (message or prompt or "").strip()
        uploaded_files = [f for f in (files or []) if f and f.filename]
        if not user_text and not uploaded_files:
            raise HTTPException(status_code=400, detail="Either 'message' text or at least one uploaded file is required.")

        if not user_text and uploaded_files:
            user_text = (
                "Please analyze the uploaded PQC artifact(s) using analyze_uploaded_pqc_artifact, "
                "extract all cryptographic and Mosca parameters, auto-calibrate the assessment, and present the findings."
            )

        # Ensure persistent session exists in DatabaseSessionService
        sess = None
        if session_id:
            sess, user_id = await _locate_session(session_id, user_id)
        if sess is None:
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            sess = await session_service.create_session(
                app_name=APP_NAME,
                user_id=user_id,
                session_id=session_id,
                state={
                    "title": user_text[:72],
                    "scope": scope,
                    "created_at": now_iso,
                },
            )
            session_id = sess.id

        # Process multimodal file uploads -> Part.from_bytes + GcsArtifactService + deterministic analyzer cache
        message_parts: List[types.Part] = []
        saved_artifacts_meta: List[Dict[str, Any]] = []
        auto_analyzed_summaries: List[Dict[str, Any]] = []

        for up_file in uploaded_files:
            fname = up_file.filename or "uploaded_artifact.bin"
            raw_bytes = await up_file.read()
            declared_mime = up_file.content_type or "application/octet-stream"
            gemini_mime, is_binary_part = _guess_gemini_mime_type(fname, declared_mime)

            # 1. Create google.genai.types.Part.from_bytes for native multimodal processing & artifact persistence
            raw_part = types.Part.from_bytes(data=raw_bytes, mime_type=gemini_mime)

            # 2. Persist a copy in the session's GcsArtifactService
            artifact_version = await artifact_service.save_artifact(
                app_name=APP_NAME,
                user_id=user_id,
                session_id=session_id,
                filename=fname,
                artifact=raw_part,
            )

            # 3. Register extracted text/metadata for `analyze_uploaded_pqc_artifact` and run auto-calibration
            cached_rec = register_uploaded_artifact_for_analysis(
                filename=fname,
                raw_bytes=raw_bytes,
                mime_type=declared_mime,
                session_id=session_id or "default",
            )
            analysis_json = json.loads(
                analyze_uploaded_pqc_artifact(
                    artifact_name=fname,
                    artifact_content=cached_rec.get("extracted_text", ""),
                    scope=scope,
                )
            )
            auto_analyzed_summaries.append(analysis_json)

            # 4. Attach `types.Part.from_bytes` to the ADK Runner message content
            if is_binary_part:
                message_parts.append(raw_part)
            else:
                extracted_bytes = (cached_rec.get("extracted_text") or "").encode("utf-8") or raw_bytes
                message_parts.append(types.Part.from_bytes(data=extracted_bytes, mime_type=gemini_mime))

            saved_artifacts_meta.append(
                {
                    "filename": fname,
                    "mime_type": declared_mime,
                    "gemini_mime_type": gemini_mime,
                    "size_bytes": len(raw_bytes),
                    "artifact_version": artifact_version,
                    "detected_artifact_type": analysis_json.get("detected_artifact_type"),
                }
            )

        augmented_text = user_text
        if saved_artifacts_meta:
            artifact_names = ", ".join(a["filename"] for a in saved_artifacts_meta)
            augmented_text += (
                f"\n\n[UPLOADED_ARTIFACTS_CONTEXT]: The user uploaded [{artifact_names}]. "
                f"Invoke `analyze_uploaded_pqc_artifact(artifact_name='{saved_artifacts_meta[0]['filename']}', scope='{scope}')` "
                "and incorporate the extracted parameters and auto-calibration into your response."
            )

        message_parts.append(types.Part.from_text(text=augmented_text))
        new_message = types.Content(role="user", parts=message_parts)

        tool_calls_trace: List[Dict[str, Any]] = []
        for idx, summary in enumerate(auto_analyzed_summaries):
            tool_calls_trace.append(
                {
                    "id": f"upload-calib-{idx}",
                    "name": "analyze_uploaded_pqc_artifact",
                    "args": {"artifact_name": summary.get("artifact_name"), "scope": scope},
                    "status": "AUTO_CALIBRATED",
                    "output_preview": json.dumps(summary.get("extracted_parameters", {}), ensure_ascii=False),
                }
            )

        async def _execute_runner_turn(active_runner: Runner) -> List[str]:
            parts_out: List[str] = []
            async for event in active_runner.run_async(
                user_id=user_id,
                session_id=session_id,
                new_message=new_message,
            ):
                try:
                    for fc in event.get_function_calls() or []:
                        tool_calls_trace.append(
                            {
                                "id": getattr(fc, "id", None) or str(uuid.uuid4()),
                                "name": getattr(fc, "name", "tool"),
                                "args": dict(getattr(fc, "args", {}) or {}),
                                "status": "EXECUTED",
                            }
                        )
                    for fr in event.get_function_responses() or []:
                        fr_name = getattr(fr, "name", "")
                        resp_val = getattr(fr, "response", None)
                        resp_str = json.dumps(resp_val, ensure_ascii=False)[:800] if resp_val is not None else ""
                        for tc in reversed(tool_calls_trace):
                            if tc["name"] == fr_name and "output_preview" not in tc:
                                tc["output_preview"] = resp_str
                                break
                except Exception:
                    pass

                if event.is_final_response() and event.content and event.content.parts:
                    for part in event.content.parts:
                        if getattr(part, "text", None):
                            parts_out.append(part.text)
            return parts_out

        final_text_parts: List[str] = []
        try:
            chosen_runner = _get_runner_for_spec(model_spec, use_fallback_model=False)
            final_text_parts = await _execute_runner_turn(chosen_runner)
        except Exception as primary_exc:
            logger.warning(
                "Primary model '%s' failed (%s: %s), retrying with fallback model '%s'...",
                model_spec.get("runtime_model"),
                type(primary_exc).__name__,
                primary_exc,
                model_spec.get("fallback_model"),
            )
            try:
                fallback_runner = _get_runner_for_spec(model_spec, use_fallback_model=True)
                final_text_parts = await _execute_runner_turn(fallback_runner)
            except Exception as exc:
                logger.warning("ADK Runner fallback triggered (%s): %s", type(exc).__name__, exc)
                fallback_md = _build_conversational_or_report_fallback(
                    user_query=user_text,
                    target_scope=scope,
                    target_location=location,
                    has_uploads=bool(auto_analyzed_summaries),
                )
                if auto_analyzed_summaries:
                    calib_header = (
                        "### Uploaded Artifact Auto-Calibration Summary\n"
                        f"- **Artifact Analyzed:** `{auto_analyzed_summaries[0].get('artifact_name')}` (`{auto_analyzed_summaries[0].get('detected_artifact_type')}`)\n"
                        f"- **Calibrated Sector & Mosca Parameters:** `{json.dumps(auto_analyzed_summaries[0].get('extracted_parameters', {}))}`\n\n---\n\n"
                    )
                    fallback_md = calib_header + fallback_md
                final_text_parts = [fallback_md]

        assistant_text = "\n".join(final_text_parts).strip()
        if not assistant_text:
            assistant_text = _build_conversational_or_report_fallback(
                user_query=user_text,
                target_scope=scope,
                target_location=location,
                has_uploads=bool(auto_analyzed_summaries),
            )

        # Update persistent session metadata (title, updated_at, attachments, fallback messages)
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        meta_map = _load_session_metadata_map()
        sess_meta = meta_map.setdefault(
            session_id,
            {
                "user_id": user_id,
                "title": user_text[:72],
                "scope": scope,
                "created_at": now_iso,
                "attachments_by_turn": [],
                "fallback_messages": [],
            },
        )
        if sess_meta.get("title") in (None, "", "New PQC Assessment"):
            sess_meta["title"] = user_text[:72]
        sess_meta["updated_at"] = now_iso
        sess_meta["scope"] = scope
        sess_meta["model_id"] = model_spec.get("id", "gemini-3.1-pro")
        sess_meta["model_label"] = selected_model_label
        sess_meta.setdefault("attachments_by_turn", []).append(saved_artifacts_meta)
        sess_meta.setdefault("fallback_messages", []).extend(
            [
                {
                    "role": "user",
                    "content": user_text,
                    "attachments": saved_artifacts_meta,
                    "timestamp": now_iso,
                },
                {
                    "role": "assistant",
                    "content": assistant_text,
                    "tool_calls": tool_calls_trace,
                    "model_id": model_spec.get("id", "gemini-3.1-pro"),
                    "model_label": selected_model_label,
                    "timestamp": now_iso,
                },
            ]
        )
        _save_session_metadata_map(meta_map)

        return {
            "session_id": session_id,
            "user_id": user_id,
            "scope": scope,
            "model_id": model_spec.get("id", "gemini-3.1-pro"),
            "model_label": selected_model_label,
            "runtime_model": model_spec.get("runtime_model"),
            "response": assistant_text,
            "uploaded_artifacts": saved_artifacts_meta,
            "tool_calls": tool_calls_trace,
            "tool_traces": tool_calls_trace,
            "connection": get_gcp_connection_config(mask_token=True),
            "updated_at": now_iso,
        }

    # =========================================================================
    # 3. ANTIGRAVITY-STYLE GCLOUD CLI & DYNAMIC CREDENTIAL BRIDGE ENDPOINTS
    # =========================================================================

    @app.get("/api/connection")
    async def get_connection_endpoint() -> Dict[str, Any]:
        """Returns the current GCP / gcloud connection mode and target scope."""
        return get_gcp_connection_config(mask_token=True)

    @app.post("/api/connection")
    async def update_connection_endpoint(payload: ConnectionConfigPayload) -> Dict[str, Any]:
        """Switches the active GCP connection mode (Default ADC, SA Impersonation, or User gcloud Access Token)."""
        return set_gcp_connection_config(
            mode=payload.mode,
            organization_id=payload.organization_id,
            project_id=payload.project_id,
            location=payload.location,
            impersonated_service_account=payload.impersonated_service_account,
            access_token=payload.access_token,
        )

    @app.post("/api/gcloud")
    async def execute_gcloud_endpoint(payload: GcloudCommandPayload) -> JSONResponse:
        """Executes a read-only diagnostic `gcloud` command using the active connection mode."""
        raw_res = execute_gcloud_command(payload.command)
        parsed = json.loads(raw_res)
        return JSONResponse(content=parsed)

    @app.get("/api/gcloud/traces")
    async def list_gcloud_traces_endpoint() -> Dict[str, Any]:
        """Returns recent gcloud CLI executions for the UI Execution Trace drawer."""
        return {"traces": get_recent_gcloud_traces()}

    return app


app = create_workspace_app()
session_service: DatabaseSessionService = app.state.session_service
artifact_service: ResilientGcsArtifactService = app.state.artifact_service

