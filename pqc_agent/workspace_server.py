"""FastAPI Workspace Portal server for the Agentic PQC Workspace (Gemini on Vertex AI via Google ADK).

Guarantees implemented here:
1. Only Gemini models VERIFIED on Vertex AI in this project can be selected (`/api/models`).
2. Every answer reports which model really served it: Vertex AI `model_version` and token usage of every LLM call,
   including the specialist sub-agents (`served_by`).
3. No silent fallbacks: if the model fails, the API returns an explicit error and no canned or templated text.
4. Persistent history (ADK DatabaseSessionService + GCS artifacts), multimodal uploads, read-only gcloud bridge,
   and ADK's `/dev-ui/` for trace inspection.
"""

from __future__ import annotations

import asyncio
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
from google.adk.apps import App
from google.adk.artifacts.gcs_artifact_service import GcsArtifactService
from google.adk.cli.fast_api import get_fast_api_app
from google.adk.cli.service_registry import get_service_registry
from google.adk.runners import Runner
from google.adk.sessions.database_session_service import DatabaseSessionService
from google.genai import types
from pydantic import BaseModel

from pqc_agent.agent import create_pqc_agent
from pqc_agent.model_registry import ModelRegistry
from pqc_agent.portal_ui import PORTAL_HTML
from pqc_agent.telemetry import LlmCallTelemetryPlugin, capture_llm_calls, summarize_llm_calls
from tools.calibration_engine import register_uploaded_artifact_for_analysis
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
MAX_TELEMETRY_CALLS_RETURNED = 60

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


def _compact_served_by(served_by: Dict[str, Any]) -> Dict[str, Any]:
    compact = dict(served_by)
    compact["calls"] = list(served_by.get("calls", []))[:MAX_TELEMETRY_CALLS_RETURNED]
    return compact


def _event_usage_block(ev: Any) -> Optional[Dict[str, Any]]:
    """Telemetry carried by an ADK event itself (root agent call): model_version + usage metadata."""
    model_version = getattr(ev, "model_version", None)
    usage = getattr(ev, "usage_metadata", None)
    if not model_version and not usage:
        return None
    return {
        "llm_call_count": 1,
        "models_used": [model_version] if model_version else [],
        "agents_involved": [getattr(ev, "author", None)],
        "prompt_tokens": getattr(usage, "prompt_token_count", None) if usage else None,
        "output_tokens": getattr(usage, "candidates_token_count", None) if usage else None,
        "thinking_tokens": getattr(usage, "thoughts_token_count", None) if usage else None,
        "errors": [],
        "calls": [],
        "source": "adk_event",
    }


def _extract_messages_and_traces_from_session(
    session: Any,
    extra_meta: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Rebuilds the chat history (with per-turn model telemetry and explicit errors) from an ADK session."""
    events = getattr(session, "events", None) or []
    meta = extra_meta or {}
    turn_telemetry: Dict[str, Any] = meta.get("turn_telemetry", {})
    meta_attachments = meta.get("attachments_by_turn", [])
    messages: List[Dict[str, Any]] = []
    all_tool_calls: List[Dict[str, Any]] = []
    pending_turn_tools: List[Dict[str, Any]] = []
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

        try:
            for fc in (ev.get_function_calls() if hasattr(ev, "get_function_calls") else []) or []:
                name = getattr(fc, "name", "tool")
                entry = {
                    "id": getattr(fc, "id", None) or str(uuid.uuid4()),
                    "name": name,
                    "kind": "specialist_agent" if name.endswith("_agent") else "tool",
                    "args": dict(getattr(fc, "args", {}) or {}),
                    "status": "EXECUTED",
                    "timestamp": iso_ts,
                }
                pending_turn_tools.append(entry)
                all_tool_calls.append(entry)
            for fr in (ev.get_function_responses() if hasattr(ev, "get_function_responses") else []) or []:
                resp_val = getattr(fr, "response", None)
                preview = json.dumps(resp_val, ensure_ascii=False, default=str)[:1000] if resp_val is not None else ""
                for tc in reversed(pending_turn_tools):
                    if tc["name"] == getattr(fr, "name", "") and "output_preview" not in tc:
                        tc["output_preview"] = preview
                        break
        except Exception:
            pass

        invocation_id = getattr(ev, "invocation_id", None)
        error_code = getattr(ev, "error_code", None)
        if error_code and author != "user" and not (content and getattr(content, "parts", None)):
            telemetry = turn_telemetry.get(invocation_id or "", {})
            messages.append(
                {
                    "role": "assistant",
                    "content": "",
                    "status": "MODEL_ERROR",
                    "error": {"code": error_code, "message": getattr(ev, "error_message", None)},
                    "tool_calls": list(pending_turn_tools),
                    "served_by": telemetry.get("served_by"),
                    "model_label": telemetry.get("model_label"),
                    "timestamp": iso_ts,
                }
            )
            pending_turn_tools = []
            continue

        if not content or not getattr(content, "parts", None):
            continue

        text_chunks: List[str] = []
        attachments_in_event: List[Dict[str, Any]] = []
        for part in content.parts:
            if getattr(part, "thought", False):
                continue
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
            display_user_text = combined_text.split("\n\n[UPLOADED_ARTIFACTS_CONTEXT]:")[0].strip()
            if user_turn_idx < len(meta_attachments) and meta_attachments[user_turn_idx]:
                attachments_in_event = meta_attachments[user_turn_idx]
            user_turn_idx += 1
            messages.append(
                {
                    "role": "user",
                    "content": display_user_text or "(Uploaded file)",
                    "attachments": attachments_in_event,
                    "timestamp": iso_ts,
                }
            )
        else:
            telemetry = turn_telemetry.get(invocation_id or "", {})
            messages.append(
                {
                    "role": "assistant",
                    "content": combined_text,
                    "status": "OK",
                    "tool_calls": list(pending_turn_tools),
                    "served_by": telemetry.get("served_by") or _event_usage_block(ev),
                    "model_label": telemetry.get("model_label"),
                    "timestamp": iso_ts,
                }
            )
            pending_turn_tools = []

    # Sessions created by the previous version may only have locally stored template responses. Show them, but
    # flag them so the UI can say they were NOT produced by a model.
    if not messages and meta.get("fallback_messages"):
        for m in meta["fallback_messages"]:
            legacy = dict(m)
            if legacy.get("role") == "assistant":
                legacy["legacy_template_response"] = True
            messages.append(legacy)

    return messages, all_tool_calls


def create_workspace_app(
    session_db_url: Optional[str] = None,
    artifact_bucket: Optional[str] = None,
    model_registry: Optional[ModelRegistry] = None,
    verify_models_on_startup: Optional[bool] = None,
) -> FastAPI:
    """Creates the FastAPI server with `/dev-ui/`, the portal at `GET /`, `/api/models`, `/api/sessions`, `/api/chat`."""
    resolved_db_url = _normalize_sqlite_db_url(session_db_url or os.getenv("SESSION_DB_URL", DEFAULT_SESSION_DB_URL))
    resolved_bucket = (artifact_bucket or DEFAULT_STAGING_BUCKET).replace("gs://", "").strip("/")

    session_service = DatabaseSessionService(db_url=resolved_db_url)
    artifact_service = ResilientGcsArtifactService(bucket_name=resolved_bucket)
    registry_obj = model_registry or ModelRegistry()

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

    app.state.session_service = session_service
    app.state.artifact_service = artifact_service
    app.state.session_db_url = resolved_db_url
    app.state.artifact_bucket = resolved_bucket
    app.state.model_registry = registry_obj

    if verify_models_on_startup is None:
        verify_models_on_startup = os.getenv("PQC_MODEL_VERIFICATION_ON_STARTUP", "true").strip().lower() == "true"
    if verify_models_on_startup:
        registry_obj.start_background_verification()

    telemetry_plugin = LlmCallTelemetryPlugin()
    runners_by_key: Dict[str, Runner] = {}

    def _get_runner(model_name: str, thinking_level: Optional[str]) -> Runner:
        cache_key = f"{model_name}:{thinking_level or 'NONE'}"
        if cache_key not in runners_by_key:
            runners_by_key[cache_key] = Runner(
                app=App(
                    name=APP_NAME,
                    root_agent=create_pqc_agent(model_name=model_name, thinking_level=thinking_level),
                    plugins=[telemetry_plugin],
                ),
                session_service=session_service,
                artifact_service=artifact_service,
                auto_create_session=True,
            )
        return runners_by_key[cache_key]

    app.state.get_runner = _get_runner

    # Replace ADK's default `GET /` redirect so `/` serves the portal while `/dev-ui/` stays available.
    app.router.routes = [
        r for r in app.router.routes if not (getattr(r, "path", None) == "/" and "GET" in getattr(r, "methods", set()))
    ]

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def serve_portal() -> HTMLResponse:
        return HTMLResponse(content=PORTAL_HTML)

    @app.get("/api/models")
    async def list_available_models(refresh: bool = Query(default=False)) -> Dict[str, Any]:
        """Lists ONLY Gemini models verified to answer on Vertex AI in this project."""
        if refresh:
            await asyncio.to_thread(registry_obj.verify_all, True)
        return registry_obj.catalog()

    @app.get("/api/health")
    async def api_health() -> Dict[str, Any]:
        catalog = registry_obj.catalog()
        return {
            "status": "HEALTHY",
            "app_name": APP_NAME,
            "session_service": type(session_service).__name__,
            "session_db_url": resolved_db_url,
            "artifact_service": type(artifact_service).__name__,
            "artifact_bucket": f"gs://{resolved_bucket}",
            "connection": get_gcp_connection_config(mask_token=True),
            "simulation_mode": os.getenv("PQC_SIMULATION_MODE", "FALSE"),
            "verified_models": [m["id"] for m in catalog["models"]],
            "model_verification": catalog["verification"],
            "dev_ui_available": True,
            "dev_ui_url": "/dev-ui/?app=pqc_agent",
        }

    # =========================================================================
    # Persistent conversation history (/api/sessions)
    # =========================================================================

    @app.get("/api/sessions")
    async def list_persistent_sessions(
        user_id: str = Query(default=DEFAULT_USER_ID, description="User identifier"),
    ) -> Dict[str, Any]:
        resp = await session_service.list_sessions(app_name=APP_NAME, user_id=user_id)
        meta_map = _load_session_metadata_map()
        items: List[Dict[str, Any]] = []
        for s in resp.sessions:
            full_sess = await session_service.get_session(app_name=APP_NAME, user_id=s.user_id, session_id=s.id)
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
            iso_updated = extra.get("updated_at") or datetime.datetime.fromtimestamp(
                float(upd_ts), tz=datetime.timezone.utc
            ).isoformat()
            items.append(
                {
                    "session_id": s.id,
                    "id": s.id,
                    "user_id": s.user_id,
                    "title": title,
                    "created_at": extra.get("created_at") or iso_updated,
                    "updated_at": iso_updated,
                    "timestamp": float(upd_ts),
                    "message_count": len(msgs),
                    "scope": extra.get("scope") or state_dict.get("scope", "organizations/31564119954"),
                }
            )
        items.sort(key=lambda x: x["timestamp"], reverse=True)
        return {"user_id": user_id, "total": len(items), "total_sessions": len(items), "sessions": items}

    @app.post("/api/sessions")
    async def create_persistent_session(payload: Optional[CreateSessionPayload] = None) -> Dict[str, Any]:
        req = payload or CreateSessionPayload()
        user_id = (req.user_id or DEFAULT_USER_ID).strip()
        title = (req.title or "New PQC Assessment").strip()
        scope = (req.scope or "organizations/31564119954").strip()
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        session = await session_service.create_session(
            app_name=APP_NAME,
            user_id=user_id,
            session_id=req.session_id,
            state={"title": title, "scope": scope, "created_at": now_iso},
        )
        meta_map = _load_session_metadata_map()
        meta_map[session.id] = {
            "user_id": user_id,
            "title": title,
            "scope": scope,
            "created_at": now_iso,
            "updated_at": now_iso,
            "attachments_by_turn": [],
            "turn_telemetry": {},
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
        candidate_user = (user_id or DEFAULT_USER_ID).strip()
        sess = await session_service.get_session(app_name=APP_NAME, user_id=candidate_user, session_id=session_id)
        if sess is not None:
            return sess, candidate_user
        all_resp = await session_service.list_sessions(app_name=APP_NAME, user_id=None)
        for s in all_resp.sessions:
            if s.id == session_id:
                found = await session_service.get_session(app_name=APP_NAME, user_id=s.user_id, session_id=session_id)
                return found, s.user_id
        return None, candidate_user

    @app.get("/api/sessions/{session_id}")
    async def get_persistent_session_detail(session_id: str, user_id: Optional[str] = Query(default=None)) -> Dict[str, Any]:
        sess, resolved_user = await _locate_session(session_id, user_id)
        if sess is None:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")
        extra = _load_session_metadata_map().get(session_id, {})
        messages, tool_calls = _extract_messages_and_traces_from_session(sess, extra)
        state_dict = dict(getattr(sess, "state", {}) or {})
        title = (
            extra.get("title")
            or state_dict.get("title")
            or next((m["content"][:72] for m in messages if m.get("role") == "user" and m.get("content")), None)
            or "PQC Readiness Assessment"
        )
        upd_ts = getattr(sess, "last_update_time", None) or time.time()
        iso_updated = extra.get("updated_at") or datetime.datetime.fromtimestamp(
            float(upd_ts), tz=datetime.timezone.utc
        ).isoformat()
        artifacts = await artifact_service.list_artifact_keys(app_name=APP_NAME, user_id=resolved_user, session_id=session_id)
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
    async def delete_persistent_session(session_id: str, user_id: Optional[str] = Query(default=None)) -> Dict[str, Any]:
        sess, resolved_user = await _locate_session(session_id, user_id)
        if sess is None:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")
        await session_service.delete_session(app_name=APP_NAME, user_id=resolved_user, session_id=session_id)
        meta_map = _load_session_metadata_map()
        if session_id in meta_map:
            del meta_map[session_id]
            _save_session_metadata_map(meta_map)
        return {"deleted": True, "status": "deleted", "session_id": session_id, "user_id": resolved_user}

    # =========================================================================
    # Chat with multimodal uploads (/api/chat)
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
    ) -> JSONResponse:
        """Runs one agent turn on the selected verified Gemini model and returns the answer with model telemetry."""
        if project_id:
            scope = project_id
        if "application/json" in (request.headers.get("content-type") or "").lower():
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

        requested_model = model or model_id
        entry = await asyncio.to_thread(registry_obj.resolve, requested_model)
        if entry is None:
            if not registry_obj.verified_entries():
                await asyncio.to_thread(registry_obj.verify_all)
            return JSONResponse(
                status_code=400,
                content={
                    "status": "MODEL_NOT_AVAILABLE",
                    "response": "",
                    "error": {
                        "code": "MODEL_NOT_AVAILABLE",
                        "message": (
                            f"'{requested_model or 'default'}' is not a Gemini model verified on Vertex AI in this project. "
                            "Choose one of the available models."
                        ),
                    },
                    "available_models": [e["id"] for e in registry_obj.verified_entries()],
                },
            )
        model_label = f"{entry['label']} {entry.get('tier', '')}".strip()

        if any(x is not None for x in (connection_mode, impersonated_sa, access_token)):
            set_gcp_connection_config(mode=connection_mode, impersonated_service_account=impersonated_sa, access_token=access_token)

        user_text = (message or prompt or "").strip()
        uploaded_files = [f for f in (files or []) if f and f.filename]
        if not user_text and not uploaded_files:
            raise HTTPException(status_code=400, detail="Either 'message' text or at least one uploaded file is required.")
        if not user_text:
            user_text = "Please read the attached file(s), explain what they contain and how they affect our PQC assessment."

        sess = None
        if session_id:
            sess, user_id = await _locate_session(session_id, user_id)
        if sess is None:
            sess = await session_service.create_session(
                app_name=APP_NAME,
                user_id=user_id,
                state={
                    "title": user_text[:72],
                    "scope": scope,
                    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                },
            )
            session_id = sess.id

        # Uploaded files: persist as session artifacts, cache extracted text, attach to the model message.
        message_parts: List[types.Part] = []
        saved_artifacts_meta: List[Dict[str, Any]] = []
        for up_file in uploaded_files:
            fname = up_file.filename or "uploaded_artifact.bin"
            raw_bytes = await up_file.read()
            declared_mime = up_file.content_type or "application/octet-stream"
            gemini_mime, is_binary_part = _guess_gemini_mime_type(fname, declared_mime)
            raw_part = types.Part.from_bytes(data=raw_bytes, mime_type=gemini_mime)
            artifact_version = await artifact_service.save_artifact(
                app_name=APP_NAME, user_id=user_id, session_id=session_id, filename=fname, artifact=raw_part
            )
            cached = register_uploaded_artifact_for_analysis(
                filename=fname, raw_bytes=raw_bytes, mime_type=declared_mime, session_id=session_id or "default"
            )
            if is_binary_part:
                message_parts.append(raw_part)
            else:
                text_bytes = (cached.get("extracted_text") or "").encode("utf-8") or raw_bytes
                message_parts.append(types.Part.from_bytes(data=text_bytes, mime_type=gemini_mime))
            saved_artifacts_meta.append(
                {
                    "filename": fname,
                    "mime_type": declared_mime,
                    "gemini_mime_type": gemini_mime,
                    "size_bytes": len(raw_bytes),
                    "artifact_version": artifact_version,
                }
            )

        augmented_text = user_text
        if saved_artifacts_meta:
            names = ", ".join(a["filename"] for a in saved_artifacts_meta)
            augmented_text += (
                f"\n\n[UPLOADED_ARTIFACTS_CONTEXT]: The user attached: {names}. Their content is included in this message. "
                "You can also call read_uploaded_artifact with the file name to read the extracted text."
            )
        message_parts.append(types.Part.from_text(text=augmented_text))
        new_message = types.Content(role="user", parts=message_parts)

        runner = _get_runner(entry["model"], entry.get("thinking_level"))
        tool_calls_trace: List[Dict[str, Any]] = []
        error_events: List[Dict[str, Any]] = []
        final_text_parts: List[str] = []
        invocation_id: Optional[str] = None

        with capture_llm_calls() as ledger:
            try:
                async for event in runner.run_async(user_id=user_id, session_id=session_id, new_message=new_message):
                    invocation_id = invocation_id or getattr(event, "invocation_id", None)
                    if getattr(event, "error_code", None):
                        error_events.append({"code": event.error_code, "message": getattr(event, "error_message", None)})
                    try:
                        for fc in event.get_function_calls() or []:
                            name = getattr(fc, "name", "tool")
                            tool_calls_trace.append(
                                {
                                    "id": getattr(fc, "id", None) or str(uuid.uuid4()),
                                    "name": name,
                                    "kind": "specialist_agent" if name.endswith("_agent") else "tool",
                                    "args": dict(getattr(fc, "args", {}) or {}),
                                    "status": "EXECUTED",
                                }
                            )
                        for fr in event.get_function_responses() or []:
                            resp_val = getattr(fr, "response", None)
                            preview = json.dumps(resp_val, ensure_ascii=False, default=str)[:800] if resp_val is not None else ""
                            for tc in reversed(tool_calls_trace):
                                if tc["name"] == getattr(fr, "name", "") and "output_preview" not in tc:
                                    tc["output_preview"] = preview
                                    break
                    except Exception:
                        pass
                    if event.is_final_response() and event.content and event.content.parts:
                        for part in event.content.parts:
                            if getattr(part, "text", None) and not getattr(part, "thought", False):
                                final_text_parts.append(part.text)
            except Exception as exc:
                logger.warning("Model turn failed on '%s': %s: %s", entry["model"], type(exc).__name__, exc)
                error_events.append({"code": type(exc).__name__, "message": str(exc)[:600]})

        served_by = _compact_served_by(summarize_llm_calls(ledger))
        assistant_text = "\n".join(final_text_parts).strip()
        status = "OK" if assistant_text else "MODEL_ERROR"
        error: Optional[Dict[str, Any]] = None
        if not assistant_text:
            if error_events:
                error = error_events[-1]
            elif served_by["errors"]:
                last = served_by["errors"][-1]
                error = {"code": last.get("error_code"), "message": last.get("error_message")}
            else:
                error = {"code": "EMPTY_MODEL_RESPONSE", "message": "The model finished without returning text."}

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        meta_map = _load_session_metadata_map()
        sess_meta = meta_map.setdefault(
            session_id,
            {"user_id": user_id, "title": user_text[:72], "scope": scope, "created_at": now_iso, "attachments_by_turn": []},
        )
        if sess_meta.get("title") in (None, "", "New PQC Assessment"):
            sess_meta["title"] = user_text[:72]
        sess_meta["updated_at"] = now_iso
        sess_meta["scope"] = scope
        sess_meta["model_id"] = entry["id"]
        sess_meta["model_label"] = model_label
        sess_meta.setdefault("attachments_by_turn", []).append(saved_artifacts_meta)
        if invocation_id:
            sess_meta.setdefault("turn_telemetry", {})[invocation_id] = {
                "served_by": served_by,
                "model_id": entry["id"],
                "model_label": model_label,
                "status": status,
                "error": error,
            }
        _save_session_metadata_map(meta_map)

        payload = {
            "session_id": session_id,
            "user_id": user_id,
            "scope": scope,
            "status": status,
            "model_id": entry["id"],
            "model_label": model_label,
            "runtime_model": entry["model"],
            "thinking_level": entry.get("thinking_level"),
            "response": assistant_text,
            "error": error,
            "served_by": served_by,
            "uploaded_artifacts": saved_artifacts_meta,
            "tool_calls": tool_calls_trace,
            "tool_traces": tool_calls_trace,
            "connection": get_gcp_connection_config(mask_token=True),
            "updated_at": now_iso,
        }
        return JSONResponse(status_code=200 if status == "OK" else 502, content=payload)

    # =========================================================================
    # gcloud CLI and dynamic credential bridge
    # =========================================================================

    @app.get("/api/connection")
    async def get_connection_endpoint() -> Dict[str, Any]:
        return get_gcp_connection_config(mask_token=True)

    @app.post("/api/connection")
    async def update_connection_endpoint(payload: ConnectionConfigPayload) -> Dict[str, Any]:
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
        return JSONResponse(content=json.loads(execute_gcloud_command(payload.command)))

    @app.get("/api/gcloud/traces")
    async def list_gcloud_traces_endpoint() -> Dict[str, Any]:
        return {"traces": get_recent_gcloud_traces()}

    return app


app = create_workspace_app()
session_service: DatabaseSessionService = app.state.session_service
artifact_service: ResilientGcsArtifactService = app.state.artifact_service
