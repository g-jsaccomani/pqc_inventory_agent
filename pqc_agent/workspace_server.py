"""FastAPI Workspace Portal server for the Agentic PQC Workspace (Gemini on Vertex AI via Google ADK).

Guarantees implemented here:
1. Only Gemini models VERIFIED on Vertex AI in this project can be selected (`/api/models`).
2. Every answer reports which model really served it: Vertex AI `model_version` and token usage of every LLM call,
   including the specialist sub-agents (`served_by`).
3. No silent fallbacks: if the model fails, the API returns an explicit error and no canned or templated text.
4. Persistent history (ADK DatabaseSessionService + GCS artifacts), multimodal uploads, read-only gcloud bridge,
   and ADK's `/dev-ui/` for trace inspection (local development only; disabled on Cloud Run).
5. Authentication (see `pqc_agent/auth_guard.py`): sign-in requires a verified Google credential, the authenticated
   identity (signed session token/cookie or verified Cloud IAP JWT) is the only source of `user_id`, ADK-native REST
   routes are 404 on Cloud Run (and identity-bound when enabled), no wildcard CORS, no constant HMAC key.
"""

from __future__ import annotations

import asyncio
import contextvars
import datetime
import hmac
import html
import json
import logging
import mimetypes
import os
import secrets
import threading
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from google.adk.apps import App
from google.adk.artifacts.gcs_artifact_service import GcsArtifactService
from google.adk.auth import (
    AuthConfig,
    AuthCredential,
    AuthCredentialTypes,
    OAuth2Auth,
    OpenIdConnectWithConfig,
)
from google.adk.auth.credential_service.in_memory_credential_service import InMemoryCredentialService
from google.adk.cli.fast_api import get_fast_api_app
from google.adk.cli.service_registry import get_service_registry
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.runners import Runner
from google.adk.sessions.database_session_service import DatabaseSessionService
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.tool_context import ToolContext
from google.genai import types
from pydantic import BaseModel

from pqc_agent import auth_guard
from pqc_agent.agent import create_pqc_agent
from pqc_agent.model_registry import ModelRegistry
from pqc_agent.portal_ui import PORTAL_HTML
from pqc_agent.telemetry import LlmCallTelemetryPlugin, capture_llm_calls, summarize_llm_calls
from tools.calibration_engine import register_uploaded_artifact_for_analysis
from tools.gcloud_bridge import (
    clear_user_access_token,
    execute_gcloud_command,
    get_gcp_connection_config,
    get_recent_gcloud_traces,
    normalize_user_id,
    set_current_tenant_user,
    set_gcp_connection_config,
)

logger = logging.getLogger(__name__)

APP_NAME = "pqc_agent"
DEFAULT_USER_ID = "sec-architect"
SESSION_COOKIE_NAME = "pqc_session_token"
SESSION_TOKEN_TTL_SECONDS = 30 * 24 * 3600  # 30 days
SESSION_TOKEN_TYPE = "pqc_session"  # `typ` claim: OAuth state values can never be replayed as session tokens
OAUTH_STATE_TYPE = "pqc_oauth_state"
OAUTH_STATE_TTL_SECONDS = 600
OAUTH_NONCE_COOKIE_NAME = "pqc_oauth_nonce"
ALLOWED_AUTH_DOMAINS = tuple(
    d.strip().lower()
    for d in os.getenv(
        "PQC_ALLOWED_AUTH_DOMAINS",
        "google.com,jsaccomani.altostrat.com,altostrat.com",
    ).split(",")
    if d.strip()
)
SUPPORTED_REGIONS: List[Dict[str, str]] = [
    {"id": "NorthAm", "label": "NorthAm (US & Canada)"},
    {"id": "EMEA", "label": "EMEA (Europe, Middle East & Africa)"},
    {"id": "India", "label": "India (Bengaluru / Hyderabad / Mumbai)"},
    {"id": "APAC", "label": "APAC (Singapore / Tokyo / Sydney / Seoul)"},
    {"id": "LATAM", "label": "LATAM (São Paulo / Mexico City / Bogotá)"},
]
VALID_REGION_IDS = {r["id"].lower(): r["id"] for r in SUPPORTED_REGIONS}

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
    # Harden SQLite concurrency with 30s busy_timeout and WAL journal mode so concurrent requests never fail with
    # 'database is locked' or partial writes.
    if db_url and db_url.startswith("sqlite") and hasattr(self, "db_engine"):
        try:
            import sqlalchemy.event

            @sqlalchemy.event.listens_for(self.db_engine.sync_engine, "connect")
            def _set_sqlite_pragmas(dbapi_conn: Any, _conn_record: Any) -> None:
                try:
                    cur = dbapi_conn.cursor()
                    cur.execute("PRAGMA busy_timeout=30000;")
                    if ":memory:" not in (db_url or ""):
                        cur.execute("PRAGMA journal_mode=WAL;")
                    cur.execute("PRAGMA synchronous=NORMAL;")
                    cur.close()
                except Exception:
                    pass
        except Exception:
            pass


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


# =============================================================================
# Partitioned Per-Tenant / Per-Session Atomic Storage + Optional Cloud Firestore
# =============================================================================
import re as _re
import subprocess as _subprocess
import tempfile as _tempfile

_STORAGE_LOCK = threading.RLock()
_FIRESTORE_CLIENT: Any = None
_FIRESTORE_CHECKED = False


def _get_firestore_client() -> Any:
    """Returns a Cloud Firestore client when `PQC_ENABLE_FIRESTORE=true` and `google-cloud-firestore` is installed."""
    global _FIRESTORE_CLIENT, _FIRESTORE_CHECKED
    if auth_guard.env_flag("PQC_ENABLE_FIRESTORE") is not True:
        return None
    if _FIRESTORE_CHECKED:
        return _FIRESTORE_CLIENT
    _FIRESTORE_CHECKED = True
    try:
        from google.cloud import firestore  # type: ignore[import-untyped]

        db_id = os.getenv("PQC_FIRESTORE_DATABASE", "(default)").strip() or "(default)"
        proj_id = os.getenv("GOOGLE_CLOUD_PROJECT", "pqc-inventory-agent-cd06").strip()
        _FIRESTORE_CLIENT = firestore.Client(project=proj_id, database=db_id)
    except Exception as exc:
        logger.warning("Cloud Firestore client unavailable (falling back to partitioned /data/tenants): %s", exc)
        _FIRESTORE_CLIENT = None
    return _FIRESTORE_CLIENT


def _get_data_dir() -> str:
    override = os.getenv("PQC_DATA_DIR", "").strip()
    if override:
        os.makedirs(override, exist_ok=True)
        return override
    if os.path.isdir("/data") and os.access("/data", os.W_OK):
        return "/data"
    os.makedirs("data", exist_ok=True)
    return "data"


def _safe_fs_segment(value: str, fallback: str = "default") -> str:
    cleaned = _re.sub(r"[^a-zA-Z0-9._@-]", "_", str(value or "").strip()).strip("._")
    return cleaned or fallback


def _get_tenant_partition_dir(uid: str) -> str:
    return os.path.join(_get_data_dir(), "tenants", _safe_fs_segment(normalize_user_id(uid), DEFAULT_USER_ID))


def _atomic_write_json(path: str, payload: Any) -> None:
    """Writes JSON atomically via a unique temporary file + fsync + `os.replace` so concurrent readers never see partial data."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    fd, tmp_path = _tempfile.mkstemp(prefix=".tmp_pqc_", suffix=".json", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(tmp_path, path)
    except Exception:
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _get_metadata_store_path() -> str:
    return os.path.join(_get_data_dir(), "pqc_session_metadata.json")


def _load_session_metadata_map() -> Dict[str, Dict[str, Any]]:
    with _STORAGE_LOCK:
        merged: Dict[str, Dict[str, Any]] = {}
        path = _get_metadata_store_path()
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                if isinstance(raw, dict):
                    merged.update(raw)
            except Exception:
                pass
        # Load partitioned per-tenant / per-session metadata files (/data/tenants/<uid>/sessions/<session_id>.json)
        tenants_dir = os.path.join(_get_data_dir(), "tenants")
        if os.path.isdir(tenants_dir):
            try:
                for tenant_entry in os.scandir(tenants_dir):
                    if not tenant_entry.is_dir():
                        continue
                    sess_dir = os.path.join(tenant_entry.path, "sessions")
                    if not os.path.isdir(sess_dir):
                        continue
                    for sess_file in os.scandir(sess_dir):
                        if not sess_file.is_file() or not sess_file.name.endswith(".json"):
                            continue
                        try:
                            with open(sess_file.path, "r", encoding="utf-8") as sf:
                                sdata = json.load(sf)
                            if isinstance(sdata, dict):
                                sid = str(sdata.get("session_id") or sess_file.name[:-5])
                                merged[sid] = sdata
                        except Exception:
                            pass
            except OSError:
                pass
        return merged


def _save_session_metadata_map(meta_map: Dict[str, Dict[str, Any]], changed_session_id: Optional[str] = None) -> None:
    with _STORAGE_LOCK:
        try:
            for sid, sdata in meta_map.items():
                if not isinstance(sdata, dict):
                    continue
                if changed_session_id is not None and sid != changed_session_id:
                    continue
                uid = normalize_user_id(sdata.get("user_id") or DEFAULT_USER_ID)
                sdata_copy = dict(sdata)
                sdata_copy["session_id"] = sid
                sdata_copy["user_id"] = uid
                sess_path = os.path.join(
                    _get_tenant_partition_dir(uid),
                    "sessions",
                    f"{_safe_fs_segment(sid, 'session')}.json",
                )
                _atomic_write_json(sess_path, sdata_copy)
                fs_client = _get_firestore_client()
                if fs_client is not None:
                    try:
                        (
                            fs_client.collection("pqc_tenants")
                            .document(uid)
                            .collection("sessions")
                            .document(sid)
                            .set(sdata_copy, merge=True)
                        )
                    except Exception:
                        pass
            _atomic_write_json(_get_metadata_store_path(), meta_map)
        except OSError:
            pass


def _delete_partitioned_session_metadata(uid: str, session_id: str) -> None:
    with _STORAGE_LOCK:
        sess_path = os.path.join(
            _get_tenant_partition_dir(uid),
            "sessions",
            f"{_safe_fs_segment(session_id, 'session')}.json",
        )
        try:
            if os.path.exists(sess_path):
                os.unlink(sess_path)
        except OSError:
            pass
        fs_client = _get_firestore_client()
        if fs_client is not None:
            try:
                (
                    fs_client.collection("pqc_tenants")
                    .document(normalize_user_id(uid))
                    .collection("sessions")
                    .document(session_id)
                    .delete()
                )
            except Exception:
                pass


# =============================================================================
# Multi-Tenant @google.com Identity, Region & Persistent Session Token Manager
# =============================================================================


def _get_tenant_users_path() -> str:
    return os.path.join(_get_data_dir(), "pqc_tenant_users.json")


def _load_tenant_users_map() -> Dict[str, Dict[str, Any]]:
    with _STORAGE_LOCK:
        users_map: Dict[str, Dict[str, Any]] = {}
        path = _get_tenant_users_path()
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    users_map.update(data)
            except Exception:
                pass
        # Also load partitioned per-tenant profile files (/data/tenants/<uid>/profile.json)
        tenants_dir = os.path.join(_get_data_dir(), "tenants")
        if os.path.isdir(tenants_dir):
            try:
                for entry in os.scandir(tenants_dir):
                    if not entry.is_dir():
                        continue
                    prof_file = os.path.join(entry.path, "profile.json")
                    if os.path.isfile(prof_file):
                        try:
                            with open(prof_file, "r", encoding="utf-8") as pf:
                                pdata = json.load(pf)
                            if isinstance(pdata, dict) and pdata.get("email"):
                                uid = normalize_user_id(pdata["email"])
                                users_map[uid] = pdata
                        except Exception:
                            pass
            except OSError:
                pass
        return users_map


def _save_tenant_users_map(users_map: Dict[str, Dict[str, Any]], changed_uid: Optional[str] = None) -> None:
    with _STORAGE_LOCK:
        try:
            for uid, profile in users_map.items():
                if not isinstance(profile, dict):
                    continue
                if changed_uid is not None and uid != changed_uid:
                    continue
                prof_path = os.path.join(_get_tenant_partition_dir(uid), "profile.json")
                _atomic_write_json(prof_path, profile)
                fs_client = _get_firestore_client()
                if fs_client is not None:
                    try:
                        fs_client.collection("pqc_tenants").document(uid).set(profile, merge=True)
                    except Exception:
                        pass
            _atomic_write_json(_get_tenant_users_path(), users_map)
        except OSError:
            pass



_AUTH_SECRET_CACHE: Optional[bytes] = None


def _get_auth_secret() -> bytes:
    """Returns the HMAC key for session tokens and OAuth state: `PQC_AUTH_SECRET` > persisted random key on the data
    dir > ephemeral random key (with a warning). There is no constant fallback key."""
    global _AUTH_SECRET_CACHE
    if _AUTH_SECRET_CACHE is not None:
        return _AUTH_SECRET_CACHE
    try:
        data_dir: Optional[str] = _get_data_dir()
    except OSError:
        data_dir = None
    _AUTH_SECRET_CACHE = auth_guard.load_or_create_hmac_secret(data_dir)
    return _AUTH_SECRET_CACHE


def infer_region_from_timezone(timezone_str: Optional[str] = None, explicit_region: Optional[str] = None) -> str:
    """Normalizes an explicit region ('NorthAm', 'EMEA', 'India', 'APAC', 'LATAM') or infers it from IANA timezone."""
    if explicit_region:
        clean_r = str(explicit_region).strip().lower()
        if clean_r in VALID_REGION_IDS:
            return VALID_REGION_IDS[clean_r]
        if clean_r in ("us", "usa", "na", "namer", "north america", "northam"):
            return "NorthAm"
        if clean_r in ("eu", "europe", "uk", "mea", "emea"):
            return "EMEA"
        if clean_r in ("in", "ind", "india", "bengaluru", "hyderabad", "mumbai"):
            return "India"
        if clean_r in ("apac", "japa", "asia", "au", "sg", "jp", "kr"):
            return "APAC"
        if clean_r in ("latam", "br", "brazil", "mx", "ar", "co", "cl"):
            return "LATAM"

    tz = (timezone_str or "").strip()
    tz_lower = tz.lower()
    if any(k in tz_lower for k in ("kolkata", "calcutta", "mumbai", "chennai", "delhi", "colombo")):
        return "India"
    if tz_lower.startswith(("europe/", "africa/", "atlantic/")) or any(
        k in tz_lower for k in ("dubai", "riyadh", "jerusalem", "tel_aviv", "istanbul", "cairo", "johannesburg")
    ):
        return "EMEA"
    if tz_lower.startswith(("asia/", "australia/", "pacific/")):
        return "APAC"
    if any(
        k in tz_lower
        for k in (
            "sao_paulo",
            "buenos_aires",
            "santiago",
            "bogota",
            "lima",
            "mexico",
            "montevideo",
            "caracas",
            "recife",
            "fortaleza",
            "manaus",
        )
    ):
        return "LATAM"
    return "NorthAm"


def is_allowed_corporate_email(email: str) -> Tuple[bool, str]:
    """Validates that an email belongs to @google.com (or an explicitly configured corporate domain)."""
    clean = normalize_user_id(email)
    if "@" not in clean:
        return False, "Please provide a valid corporate email address (e.g., username@google.com)."
    local_part, domain = clean.rsplit("@", 1)
    if not local_part or not domain:
        return False, "Invalid email address format."
    if domain not in ALLOWED_AUTH_DOMAINS:
        allowed_str = ", ".join(f"@{d}" for d in ALLOWED_AUTH_DOMAINS)
        return False, f"Access restricted to authorized corporate accounts ({allowed_str}). '{clean}' is not permitted."
    return True, clean


def _format_display_name(email: str, provided_name: Optional[str] = None) -> str:
    if provided_name and str(provided_name).strip():
        return str(provided_name).strip()
    local = email.split("@", 1)[0]
    parts = [p.capitalize() for p in local.replace("_", ".").replace("-", ".").split(".") if p]
    return " ".join(parts) if parts else local


def sign_tenant_session_token(user_profile: Dict[str, Any]) -> str:
    """Creates an HMAC-SHA256 signed session token encoding the authenticated @google.com user profile."""
    now_ts = int(time.time())
    payload = {
        "uid": normalize_user_id(user_profile["email"]),
        "email": normalize_user_id(user_profile["email"]),
        "name": user_profile.get("name") or _format_display_name(user_profile["email"]),
        "picture": user_profile.get("picture") or "",
        "region": user_profile.get("region") or "NorthAm",
        "auth_method": user_profile.get("auth_method") or "google_workspace_signin",
        "typ": SESSION_TOKEN_TYPE,
        "iat": now_ts,
        "exp": now_ts + SESSION_TOKEN_TTL_SECONDS,
    }
    return auth_guard.sign_payload(payload, _get_auth_secret())


def verify_tenant_session_token(token: Optional[str]) -> Optional[Dict[str, Any]]:
    """Verifies an HMAC-SHA256 signed session token (`typ` = session, unexpired, allowed corporate domain)."""
    decoded = auth_guard.verify_signed_payload(token, _get_auth_secret(), expected_type=SESSION_TOKEN_TYPE)
    if not decoded:
        return None
    email = normalize_user_id(decoded.get("email") or decoded.get("uid"))
    ok, _ = is_allowed_corporate_email(email)
    if not ok:
        return None
    return decoded


def sign_oauth_state(payload: Dict[str, Any]) -> str:
    """Signs an OAuth `state` value (typ = oauth_state, 10 minute expiry) so callbacks cannot be forged."""
    now_ts = int(time.time())
    body = dict(payload)
    body.update({"typ": OAUTH_STATE_TYPE, "iat": now_ts, "exp": now_ts + OAUTH_STATE_TTL_SECONDS})
    return auth_guard.sign_payload(body, _get_auth_secret())


def verify_oauth_state(state: Optional[str]) -> Optional[Dict[str, Any]]:
    return auth_guard.verify_signed_payload(state, _get_auth_secret(), expected_type=OAUTH_STATE_TYPE)


def _is_true_claim(value: Any) -> bool:
    return value in (True, 1, "true", "True", "TRUE", "1")


def _accepted_id_token_audiences() -> Tuple[str, ...]:
    """OAuth client IDs accepted as ID-token audience: `PQC_GOOGLE_ID_TOKEN_AUDIENCES` + the configured OAuth client."""
    audiences = [a.strip() for a in os.getenv("PQC_GOOGLE_ID_TOKEN_AUDIENCES", "").split(",") if a.strip()]
    try:
        client_id = (load_oauth_client_config().get("client_id") or "").strip()
    except Exception:
        client_id = ""
    if client_id:
        audiences.append(client_id)
    return tuple(dict.fromkeys(audiences))


def _verify_google_oauth_or_id_token(
    id_token_jwt: Optional[str] = None,
    google_access_token: Optional[str] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Verifies a Google ID token (JWT) or a Google OAuth access token with Google's tokeninfo endpoint.

    Returns `({"email", "email_verified": True, ...}, None)` only for a VERIFIED email in `ALLOWED_AUTH_DOMAINS`;
    ID tokens must come from accounts.google.com and, when OAuth client IDs are configured, carry one of them as `aud`.
    """
    if id_token_jwt:
        tok = id_token_jwt.strip()
        try:
            url = f"https://oauth2.googleapis.com/tokeninfo?id_token={urllib.parse.quote(tok)}"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                info = json.loads(resp.read().decode("utf-8"))
            if info.get("iss") not in ("accounts.google.com", "https://accounts.google.com"):
                return None, "Google ID token has an unexpected issuer."
            audiences = _accepted_id_token_audiences()
            if audiences and info.get("aud") not in audiences:
                return None, "Google ID token was issued for a different OAuth client (audience mismatch)."
            raw_email = str(info.get("email") or "").strip()
            if not raw_email or not _is_true_claim(info.get("email_verified")):
                return None, "Google ID token does not contain a verified email address."
            email = normalize_user_id(raw_email)
            ok, msg = is_allowed_corporate_email(email)
            if not ok:
                return None, msg
            return {
                "email": email,
                "email_verified": True,
                "name": info.get("name") or _format_display_name(email),
                "picture": info.get("picture") or "",
                "hd": info.get("hd") or email.split("@")[-1],
                "auth_method": "google_id_token",
            }, None
        except Exception as exc:
            return None, f"Google ID token verification failed: {exc}"

    if google_access_token:
        tok = google_access_token.strip()
        if tok.lower().startswith("bearer "):
            tok = tok[7:].strip()
        try:
            url = f"https://oauth2.googleapis.com/tokeninfo?access_token={urllib.parse.quote(tok)}"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                info = json.loads(resp.read().decode("utf-8"))
            raw_email = str(info.get("email") or "").strip()
            if not raw_email:
                return None, (
                    "Google access token has no email claim: create it with the userinfo.email scope "
                    "(e.g. `gcloud auth print-access-token`)."
                )
            if not _is_true_claim(info.get("email_verified")):
                return None, "Google access token does not belong to a verified email address."
            email = normalize_user_id(raw_email)
            ok, msg = is_allowed_corporate_email(email)
            if not ok:
                return None, msg
            try:
                expires_in = int(info.get("expires_in") or 0) or None
            except (TypeError, ValueError):
                expires_in = None

            # Enrich with real Google profile photo (`picture`) and full display name (`name`) from userinfo
            user_full_name = str(info.get("name") or "").strip() or _format_display_name(email)
            user_picture = str(info.get("picture") or "").strip()
            user_hd = str(info.get("hd") or "").strip() or email.split("@")[-1]
            if not user_picture or user_full_name == _format_display_name(email):
                try:
                    u_req = urllib.request.Request(
                        "https://www.googleapis.com/oauth2/v3/userinfo",
                        headers={"Authorization": f"Bearer {tok}", "Accept": "application/json"},
                    )
                    with urllib.request.urlopen(u_req, timeout=3) as u_resp:
                        u_info = json.loads(u_resp.read().decode("utf-8"))
                    if isinstance(u_info, dict) and normalize_user_id(u_info.get("email") or "") == email:
                        if u_info.get("name"):
                            user_full_name = str(u_info["name"]).strip()
                        if u_info.get("picture"):
                            user_picture = str(u_info["picture"]).strip()
                        if u_info.get("hd"):
                            user_hd = str(u_info["hd"]).strip()
                except Exception:
                    pass

            return {
                "email": email,
                "email_verified": True,
                "name": user_full_name,
                "picture": user_picture,
                "hd": user_hd,
                "auth_method": "google_access_token",
                "expires_in": expires_in,
            }, None
        except Exception as exc:
            return None, f"Google OAuth access token verification failed: {exc}"

    return None, "No token provided."


def _try_workstation_auto_gcloud_token() -> Optional[str]:
    """On a corporate workstation (not Cloud Run), checks if `gcloud auth print-access-token` yields a valid token."""
    if auth_guard.running_on_cloud_run():
        return None
    if auth_guard.env_flag("PQC_AUTO_WORKSTATION_GCLOUD_AUTH") is False:
        return None
    if "PYTEST_CURRENT_TEST" in os.environ and os.getenv("PQC_ENABLE_AUTO_GCLOUD_IN_TESTS") != "1":
        return None
    try:
        env = os.environ.copy()
        venv_py = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".venv", "bin", "python"))
        if os.path.isfile(venv_py) and not env.get("CLOUDSDK_PYTHON"):
            env["CLOUDSDK_PYTHON"] = venv_py
        out = _subprocess.check_output(
            ["gcloud", "auth", "print-access-token", "--quiet"],
            env=env,
            stderr=_subprocess.DEVNULL,
            text=True,
            timeout=4,
        )
        lines = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
        tok = lines[-1] if lines else ""
        return tok if tok.startswith("ya29.") else None
    except Exception:
        return None


def upsert_tenant_user_profile(
    email: str,
    name: Optional[str] = None,
    region: Optional[str] = None,
    timezone_str: Optional[str] = None,
    auth_method: str = "google_workspace_signin",
    picture: Optional[str] = None,
) -> Dict[str, Any]:
    """Creates or updates a persistent @google.com tenant user profile in `/data/tenants/<uid>/profile.json`."""
    clean_email = normalize_user_id(email)
    users_map = _load_tenant_users_map()
    existing = users_map.get(clean_email, {})
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    resolved_region = infer_region_from_timezone(
        timezone_str=timezone_str or existing.get("timezone"),
        explicit_region=region or existing.get("region"),
    )
    resolved_name = _format_display_name(clean_email, name or existing.get("name"))
    domain = clean_email.split("@", 1)[-1] if "@" in clean_email else "google.com"
    resolved_picture = picture if (picture is not None and str(picture).strip()) else existing.get("picture", "")

    profile = {
        "user_id": clean_email,
        "email": clean_email,
        "name": resolved_name,
        "domain": domain,
        "region": resolved_region,
        "timezone": timezone_str or existing.get("timezone") or "UTC",
        "auth_method": auth_method or existing.get("auth_method") or "google_workspace_signin",
        "picture": resolved_picture,
        "created_at": existing.get("created_at") or now_iso,
        "last_login_at": now_iso,
    }
    users_map[clean_email] = profile
    _save_tenant_users_map(users_map, changed_uid=clean_email)
    return profile


_IDENTITY_RESOLVER = auth_guard.IdentityResolver(
    # Lambdas keep module-level lookups late-bound (monkeypatch friendly in tests).
    verify_session_token=lambda token: verify_tenant_session_token(token),
    is_allowed_email=lambda email: is_allowed_corporate_email(email)[0],
    session_cookie_name=SESSION_COOKIE_NAME,
    session_token_headers=("X-PQC-User-Token", "Authorization"),
    normalize_user_id=normalize_user_id,
)


def resolve_request_identity(conn: Any) -> Optional[auth_guard.AuthenticatedIdentity]:
    """Authenticated identity of a request/connection: verified Cloud IAP JWT or signed portal session token.

    `X-PQC-User-Id`, `user_id` parameters and the plain `X-Goog-Authenticated-User-Email` header are never trusted.
    """
    return _IDENTITY_RESOLVER.resolve(conn)


def resolve_authenticated_tenant_from_request(request: Request) -> Tuple[Optional[Dict[str, Any]], bool]:
    """Returns `(tenant_profile_or_None, iap_active)` for the request's authenticated identity (if any)."""
    identity = resolve_request_identity(request)
    if identity is None:
        return None, False
    if identity.source == "iap":
        existing = _load_tenant_users_map().get(identity.user_id, {})
        claims = identity.claims or {}
        profile = upsert_tenant_user_profile(
            email=identity.email,
            name=existing.get("name") or claims.get("name"),
            region=existing.get("region") or request.headers.get("X-PQC-User-Region"),
            timezone_str=existing.get("timezone") or request.headers.get("X-PQC-User-Timezone"),
            auth_method="cloud_iap",
            picture=existing.get("picture") or claims.get("picture"),
        )
        return profile, True
    profile = _load_tenant_users_map().get(identity.user_id)
    if not profile:
        claims = identity.claims or {}
        profile = upsert_tenant_user_profile(
            email=identity.email,
            name=claims.get("name"),
            region=claims.get("region"),
            auth_method=claims.get("auth_method", "google_workspace_signin"),
        )
    return profile, False


def activate_request_tenant_user(request: Request, explicit_user_id: Optional[str] = None) -> str:
    """Returns the authenticated user_id for a tenant-scoped request and binds it to the tenant `ContextVar`.

    The authenticated identity is the ONLY source of the user id: HTTP 401 without one, HTTP 403 when an explicit
    `user_id` parameter names somebody else. `X-PQC-User-Id` is ignored entirely.
    """
    identity = resolve_request_identity(request)
    uid = auth_guard.bind_user_id(identity, explicit_user_id, normalize_user_id=normalize_user_id)
    set_current_tenant_user(uid)
    return uid


# =============================================================================
# ADK Native 3-Legged OAuth (3LO) & ToolContext Consent Manager
# =============================================================================

GCP_OAUTH_CREDENTIAL_KEY = "gcp_pqc_oauth_3lo_credential"
GCP_OAUTH_SCOPES: Tuple[str, ...] = (
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/cloud-platform.read-only",
)
PROTECTED_GCP_TOOLS = frozenset({
    "collect_kms_inventory",
    "collect_tls_policies",
    "collect_cas_hierarchies",
    "collect_Compute_and_GKE_crypto",
    "collect_workspace_cse_configs",
    "execute_gcloud_command",
    "fetch_live_gcp_context",
})

_TURN_OAUTH_CONSENT_CARDS: contextvars.ContextVar[Optional[List[Dict[str, Any]]]] = contextvars.ContextVar(
    "pqc_turn_oauth_consent_cards", default=None
)


def _record_turn_oauth_consent_card(card: Dict[str, Any]) -> None:
    cards = _TURN_OAUTH_CONSENT_CARDS.get()
    if cards is not None:
        cards.append(card)


def _get_oauth_config_path() -> str:
    return os.path.join(_get_data_dir(), "pqc_oauth_config.json")


def load_oauth_client_config() -> Dict[str, Any]:
    """Loads the Google OAuth 2.0 3LO Client configuration from `/data/pqc_oauth_config.json` or env vars."""
    cfg: Dict[str, Any] = {
        "client_id": os.getenv("GOOGLE_OAUTH_CLIENT_ID", "").strip(),
        "client_secret": os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", "").strip(),
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
        "scopes": list(GCP_OAUTH_SCOPES),
    }
    path = _get_oauth_config_path()
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                saved = json.load(f)
            if isinstance(saved, dict):
                if saved.get("client_id"):
                    cfg["client_id"] = str(saved["client_id"]).strip()
                if saved.get("client_secret"):
                    cfg["client_secret"] = str(saved["client_secret"]).strip()
        except Exception:
            pass
    return cfg


def save_oauth_client_config(client_id: Optional[str] = None, client_secret: Optional[str] = None) -> Dict[str, Any]:
    """Persists Google OAuth 2.0 Client ID (and optional Client Secret) in `/data/pqc_oauth_config.json`."""
    current = load_oauth_client_config()
    if client_id is not None:
        current["client_id"] = str(client_id).strip()
        os.environ["GOOGLE_OAUTH_CLIENT_ID"] = current["client_id"]
    if client_secret is not None:
        current["client_secret"] = str(client_secret).strip()
        os.environ["GOOGLE_OAUTH_CLIENT_SECRET"] = current["client_secret"]
    path = _get_oauth_config_path()
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "client_id": current["client_id"],
                    "client_secret": current["client_secret"],
                    "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                },
                f,
                ensure_ascii=False,
                indent=2,
            )
    except OSError:
        pass
    return {
        "client_id": current["client_id"],
        "has_client_secret": bool(current["client_secret"]),
        "scopes": current["scopes"],
        "authorization_endpoint": current["authorization_endpoint"],
    }


def build_oauth_authorize_uri(
    user_id: str,
    session_id: Optional[str] = None,
    target_scope: Optional[str] = None,
    redirect_uri: Optional[str] = None,
) -> str:
    """Builds the 3-Legged OAuth (3LO) authorization URI for the user/session."""
    params = {
        "user_id": normalize_user_id(user_id),
        "session_id": session_id or "",
        "scope": target_scope or "organizations/31564119954",
    }
    if redirect_uri:
        params["redirect_uri"] = redirect_uri
    return f"/api/auth/oauth/authorize?{urllib.parse.urlencode(params)}"


def build_gcp_oauth_auth_config(
    user_id: str = DEFAULT_USER_ID,
    session_id: Optional[str] = None,
    target_scope: Optional[str] = None,
    access_token: Optional[str] = None,
) -> AuthConfig:
    """Constructs a native Google ADK `AuthConfig` for 3-Legged OAuth 2.0 (`ToolContext.request_credential`)."""
    oauth_cfg = load_oauth_client_config()
    auth_uri = build_oauth_authorize_uri(user_id=user_id, session_id=session_id, target_scope=target_scope)
    scheme = OpenIdConnectWithConfig(
        openIdConnectUrl="https://accounts.google.com/.well-known/openid-configuration",
        authorization_endpoint=oauth_cfg["authorization_endpoint"],
        token_endpoint=oauth_cfg["token_endpoint"],
        userinfo_endpoint=oauth_cfg["userinfo_endpoint"],
        scopes=list(GCP_OAUTH_SCOPES),
    )
    oauth2_cred = OAuth2Auth(
        client_id=oauth_cfg["client_id"] or "pqc-workspace-3lo-client",
        client_secret=oauth_cfg["client_secret"] or None,
        auth_uri=auth_uri,
        access_token=access_token,
    )
    raw_cred = AuthCredential(
        auth_type=AuthCredentialTypes.OAUTH2,
        oauth2=oauth2_cred,
    )
    return AuthConfig(
        auth_scheme=scheme,
        raw_auth_credential=raw_cred,
        exchanged_auth_credential=raw_cred.model_copy(deep=True),
        credential_key=GCP_OAUTH_CREDENTIAL_KEY,
    )


class PqcOAuth3LOPlugin(BasePlugin):
    """ADK Plugin that integrates `ToolContext` 3-Legged OAuth (3LO) credentials with GCP discovery tools.

    Responsibilities:
    1. Synchronizes delegated OAuth 2.0 tokens between ADK's `ToolContext` (in-memory credential service)
       and the isolated per-user `gcloud_bridge` connection state.
    2. When a user is in 3-Legged OAuth mode (`mode == 'access_token'`) and has not yet granted a token,
       calls `tool_context.request_credential(auth_config)` before the tool executes and emits an interactive
       In-Chat OAuth 2.0 Consent Card.
    3. When a tool running in default Service Account (`adc`) mode encounters a `403 PermissionDenied` error
       on an external project/organization, automatically triggers `tool_context.request_credential(auth_config)`
       so the user can authorize with their own `@google.com` credentials right in the chat.
    """

    def __init__(self) -> None:
        super().__init__(name="pqc_oauth_3lo_plugin")

    async def before_tool_callback(
        self,
        *,
        tool: BaseTool,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
    ) -> Optional[dict[str, Any]]:
        inv_ctx = getattr(tool_context, "_invocation_context", None)
        inv_uid = getattr(inv_ctx, "user_id", None)
        inv_sess = getattr(getattr(inv_ctx, "session", None), "id", None)
        if inv_uid:
            set_current_tenant_user(inv_uid)
        uid = normalize_user_id(inv_uid)

        if tool.name not in PROTECTED_GCP_TOOLS:
            return None

        target_scope = str(
            (tool_args or {}).get("scope")
            or (tool_args or {}).get("project_id")
            or (tool_args or {}).get("command")
            or "organizations/31564119954"
        )
        conn = get_gcp_connection_config(mask_token=False, user_id=uid)
        auth_config = build_gcp_oauth_auth_config(
            user_id=uid,
            session_id=inv_sess,
            target_scope=target_scope,
        )

        # 1. Check if ADK ToolContext already holds a delegated OAuth 2.0 token
        try:
            loaded_cred = await tool_context.load_credential(auth_config)
            if (
                loaded_cred
                and loaded_cred.oauth2
                and loaded_cred.oauth2.access_token
                and not conn.get("has_access_token")
            ):
                set_gcp_connection_config(
                    mode="access_token",
                    access_token=loaded_cred.oauth2.access_token,
                    user_id=uid,
                )
                conn = get_gcp_connection_config(mask_token=False, user_id=uid)
            elif conn.get("has_access_token") and conn.get("access_token_preview"):
                save_cfg = build_gcp_oauth_auth_config(
                    user_id=uid,
                    session_id=inv_sess,
                    target_scope=target_scope,
                    access_token=conn["access_token_preview"],
                )
                await tool_context.save_credential(save_cfg)
        except Exception as exc:
            logger.debug("ToolContext credential sync skipped: %s", exc)

        # 2. If the user is in 3-Legged OAuth mode ('access_token') and no token is present, request consent!
        if conn.get("mode") == "access_token" and not conn.get("has_access_token"):
            try:
                tool_context.request_credential(auth_config)
            except Exception as exc:
                logger.debug("tool_context.request_credential note: %s", exc)

            auth_uri = build_oauth_authorize_uri(user_id=uid, session_id=inv_sess, target_scope=target_scope)
            consent_card = {
                "consent_id": tool_context.function_call_id or f"consent-{uuid.uuid4().hex[:10]}",
                "function_call_id": tool_context.function_call_id,
                "credential_key": GCP_OAUTH_CREDENTIAL_KEY,
                "status": "PENDING_USER_CONSENT",
                "reason": "oauth_3lo_mode_missing_token",
                "tool_name": tool.name,
                "tool_args": dict(tool_args or {}),
                "target_scope": target_scope,
                "user_id": uid,
                "session_id": inv_sess,
                "auth_flow": "oauth2_3lo",
                "auth_uri": auth_uri,
                "scopes": list(GCP_OAUTH_SCOPES),
                "title": "Google Cloud OAuth 2.0 (3LO) Authorization Required",
                "description": (
                    f"The agent requires your delegated Google Cloud consent to execute '{tool.name}' "
                    f"on '{target_scope}' on behalf of '{uid}'."
                ),
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
            try:
                tool_context.state["pending_oauth_consent"] = consent_card
            except Exception:
                pass
            _record_turn_oauth_consent_card(consent_card)
            return {
                "status": "OAUTH_3LO_CONSENT_REQUIRED",
                "oauth_consent_required": True,
                "tool_name": tool.name,
                "target_scope": target_scope,
                "user_id": uid,
                "required_scopes": list(GCP_OAUTH_SCOPES),
                "auth_uri": auth_uri,
                "consent_card": consent_card,
                "message": (
                    f"3-Legged OAuth (3LO) user consent is required before '{tool.name}' can inspect "
                    f"'{target_scope}' on behalf of '{uid}'. An interactive Google Cloud OAuth 2.0 Consent Card "
                    "has been displayed in the chat. Please ask the user to authorize access in the card to continue."
                ),
            }

        return None

    async def after_tool_callback(
        self,
        *,
        tool: BaseTool,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
        result: dict[str, Any],
    ) -> Optional[dict[str, Any]]:
        if tool.name not in PROTECTED_GCP_TOOLS:
            return None

        inv_ctx = getattr(tool_context, "_invocation_context", None)
        inv_uid = getattr(inv_ctx, "user_id", None)
        inv_sess = getattr(getattr(inv_ctx, "session", None), "id", None)
        uid = normalize_user_id(inv_uid)
        conn = get_gcp_connection_config(mask_token=False, user_id=uid)

        serialized = json.dumps(result, ensure_ascii=False, default=str) if result is not None else ""
        permission_failure = any(
            marker in serialized
            for marker in (
                "ACCESS_TOKEN_REQUIRED",
                "PermissionDenied",
                "PERMISSION_DENIED",
                "does not have required permission",
                "Caller does not have permission",
            )
        )
        if permission_failure and not conn.get("has_access_token"):
            target_scope = str(
                (tool_args or {}).get("scope")
                or (tool_args or {}).get("project_id")
                or (tool_args or {}).get("command")
                or conn.get("organization_id")
                or "organizations/31564119954"
            )
            auth_config = build_gcp_oauth_auth_config(
                user_id=uid,
                session_id=inv_sess,
                target_scope=target_scope,
            )
            try:
                tool_context.request_credential(auth_config)
            except Exception:
                pass
            auth_uri = build_oauth_authorize_uri(user_id=uid, session_id=inv_sess, target_scope=target_scope)
            consent_card = {
                "consent_id": tool_context.function_call_id or f"consent-{uuid.uuid4().hex[:10]}",
                "function_call_id": tool_context.function_call_id,
                "credential_key": GCP_OAUTH_CREDENTIAL_KEY,
                "status": "PENDING_USER_CONSENT",
                "reason": "permission_denied_fallback_to_3lo",
                "tool_name": tool.name,
                "tool_args": dict(tool_args or {}),
                "target_scope": target_scope,
                "user_id": uid,
                "session_id": inv_sess,
                "auth_flow": "oauth2_3lo",
                "auth_uri": auth_uri,
                "scopes": list(GCP_OAUTH_SCOPES),
                "title": "Additional Google Cloud Permissions Required (OAuth 2.0 3LO)",
                "description": (
                    f"The default Service Account could not access '{target_scope}' during '{tool.name}'. "
                    f"Authorize with your personal Google Cloud credentials ({uid}) to continue."
                ),
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
            try:
                tool_context.state["pending_oauth_consent"] = consent_card
            except Exception:
                pass
            _record_turn_oauth_consent_card(consent_card)
        return None


class GoogleAuthSignInPayload(BaseModel):
    email: Optional[str] = None
    name: Optional[str] = None
    region: Optional[str] = None
    timezone: Optional[str] = None
    credential: Optional[str] = None  # Google Identity Services JWT id_token
    id_token: Optional[str] = None
    google_access_token: Optional[str] = None
    use_token_for_gcp_connection: bool = False
    oauth_state: Optional[str] = None  # set by the OAuth popup (implicit flow); verified + bound to this browser


class ToolConsentPayload(BaseModel):
    user_id: Optional[str] = None  # optional; must equal the authenticated user when given
    session_id: Optional[str] = None
    access_token: str
    function_call_id: Optional[str] = None
    tool_name: Optional[str] = None
    target_scope: Optional[str] = None
    verify_with_google: bool = False
    oauth_state: Optional[str] = None  # set by the OAuth popup (implicit flow); verified + bound to this browser


class OAuthClientConfigPayload(BaseModel):
    client_id: Optional[str] = None
    client_secret: Optional[str] = None


class CreateSessionPayload(BaseModel):
    user_id: Optional[str] = None  # optional; must equal the authenticated user when given
    title: Optional[str] = None
    scope: Optional[str] = None
    session_id: Optional[str] = None


class ConnectionConfigPayload(BaseModel):
    user_id: Optional[str] = None
    mode: Optional[str] = None
    organization_id: Optional[str] = None
    project_id: Optional[str] = None
    location: Optional[str] = None
    impersonated_service_account: Optional[str] = None
    access_token: Optional[str] = None


class GcloudCommandPayload(BaseModel):
    command: str
    user_id: Optional[str] = None


EMAIL_ONLY_SIGNIN_DISABLED_DETAIL = (
    "Email-only sign-in is disabled: a verified Google credential is required. Run `gcloud auth print-access-token` "
    "and paste the token in the sign-in dialog, or use 'Sign in with Google' when it is configured. "
    "(Email-only sign-in exists only for local development with PQC_ALLOW_UNVERIFIED_SIGNIN=true.)"
)
_SENSITIVE_STATE_KEY_MARKERS = ("credential", "token", "secret")
_USED_OAUTH_NONCES: Dict[str, float] = {}
_USED_OAUTH_NONCES_LOCK = threading.Lock()


def _adk_dev_ui_enabled() -> bool:
    """ADK DevServer switch: True if PQC_ENABLE_ADK_DEV_UI in (true, 1, yes), False if in (false, 0, no), otherwise
    `not os.getenv('K_SERVICE')` (enabled for local development, disabled on Cloud Run)."""
    return auth_guard.adk_dev_ui_enabled()


def _bind_tenant_context(identity: auth_guard.AuthenticatedIdentity) -> None:
    """Binds the per-tenant `ContextVar` (gcloud bridge / tools) for ADK-native routes guarded by the middleware."""
    set_current_tenant_user(identity.user_id)


def _js_literal(value: Any) -> str:
    """JSON-encodes `value` for safe embedding in an inline <script> block (no `</script>` break-out)."""
    return json.dumps(value).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _redact_session_state(state: Dict[str, Any]) -> Dict[str, Any]:
    """Removes credential material (ADK auth credentials, OAuth tokens) from session state returned to clients."""
    return {
        key: value
        for key, value in (state or {}).items()
        if not any(marker in str(key).lower() for marker in _SENSITIVE_STATE_KEY_MARKERS)
    }


def _consume_oauth_nonce(nonce: str) -> bool:
    """Single-use OAuth state nonces (replays of a completed callback are rejected)."""
    now = time.time()
    with _USED_OAUTH_NONCES_LOCK:
        for key, expires_at in list(_USED_OAUTH_NONCES.items()):
            if expires_at < now:
                del _USED_OAUTH_NONCES[key]
        if nonce in _USED_OAUTH_NONCES:
            return False
        _USED_OAUTH_NONCES[nonce] = now + OAUTH_STATE_TTL_SECONDS
        return True


def _validate_oauth_state_for_request(request: Request, state_value: Optional[str]) -> Optional[Dict[str, Any]]:
    """Verifies a signed OAuth `state`: HMAC + `typ` + expiry, nonce equal to this browser's nonce cookie, single use."""
    decoded = verify_oauth_state(state_value)
    if not decoded:
        return None
    cookie_nonce = request.cookies.get(OAUTH_NONCE_COOKIE_NAME) or ""
    state_nonce = str(decoded.get("nonce") or "")
    if not cookie_nonce or not state_nonce:
        return None
    if not hmac.compare_digest(cookie_nonce.encode("utf-8"), state_nonce.encode("utf-8")):
        return None
    if not _consume_oauth_nonce(state_nonce):
        return None
    return decoded


def _exchange_oauth_code(code: str, redirect_uri: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Exchanges an OAuth authorization code server-side (the token is never embedded in an HTML page)."""
    oauth_cfg = load_oauth_client_config()
    try:
        form_data = urllib.parse.urlencode(
            {
                "code": code,
                "client_id": oauth_cfg.get("client_id", ""),
                "client_secret": oauth_cfg.get("client_secret", ""),
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            oauth_cfg["token_endpoint"],
            data=form_data,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            tok_data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        return None, f"OAuth code exchange failed: {exc}"
    if not tok_data.get("access_token"):
        return None, "OAuth code exchange returned no access_token."
    return tok_data, None


def _bind_delegated_gcp_token(uid: str, access_token: str, expires_in: Optional[Any] = None) -> Dict[str, Any]:
    """Binds a delegated OAuth access token to `uid`'s gcloud/GCP connection (process memory only)."""
    try:
        ttl = float(expires_in) if expires_in else None
    except (TypeError, ValueError):
        ttl = None
    return set_gcp_connection_config(mode="access_token", access_token=access_token, user_id=uid, access_token_expires_in=ttl)


def _oauth_popup_result_html(message_type: str, payload: Dict[str, Any], message: str, ok: bool) -> str:
    """Small popup page that reports an OAuth result to the opener (same origin only) and closes itself."""
    color = "#81c995" if ok else "#f87171"
    close_js = "setTimeout(function () { window.close(); }, 400);" if ok else ""
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>PQC Workspace - Google authorization</title></head>
<body style="background:#0b0f17;color:#e2e8f0;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">
<div id="msg" style="color:{color};max-width:480px;text-align:center;line-height:1.5;">{html.escape(message)}</div>
<script>
(function () {{
  var payload = {_js_literal(payload)};
  if (window.opener) {{
    window.opener.postMessage({{ type: {_js_literal(message_type)}, payload: payload }}, window.location.origin);
    {close_js}
  }}
}})();
</script></body></html>"""


# Implicit OAuth flow (no client secret configured): Google returns the token and `state` in the URL fragment, which
# only the browser sees. This static page forwards both to the API (state verified server-side) and reports back.
_OAUTH_IMPLICIT_CALLBACK_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>PQC Workspace - completing Google authorization</title></head>
<body style="background:#0b0f17;color:#e2e8f0;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">
<div id="msg" style="max-width:480px;text-align:center;line-height:1.5;">Completing Google authorization...</div>
<script>
(async function () {
  var msg = document.getElementById('msg');
  var params = new URLSearchParams(window.location.hash.replace(/^#/, ''));
  try { history.replaceState(null, '', window.location.pathname); } catch (e) {}
  var accessToken = params.get('access_token') || '';
  var state = params.get('state') || '';
  var error = params.get('error') || '';
  var statePayload = {};
  try {
    var b64 = (state.split('.')[0] || '').replace(/-/g, '+').replace(/_/g, '/');
    b64 += '='.repeat((4 - (b64.length % 4)) % 4);
    statePayload = JSON.parse(atob(b64)) || {};
  } catch (e) { statePayload = {}; }
  var mode = statePayload.mode === 'signin' ? 'signin' : '3lo';
  var type = mode === 'signin' ? 'PQC_SIGNIN_COMPLETE' : 'PQC_OAUTH_3LO_AUTHORIZED';
  function finish(ok, payload, text) {
    msg.textContent = text;
    msg.style.color = ok ? '#81c995' : '#f87171';
    if (window.opener) {
      window.opener.postMessage({ type: type, payload: payload }, window.location.origin);
      if (ok) { setTimeout(function () { window.close(); }, 400); }
    }
  }
  if (error || !accessToken || !state) {
    finish(false, { authenticated: false, error: error || 'missing access_token or state' }, 'Authorization did not complete: ' + (error || 'missing access_token or state'));
    return;
  }
  var headers = { 'Content-Type': 'application/json' };
  var sessionToken = localStorage.getItem('pqc_session_token');
  if (sessionToken && mode !== 'signin') { headers['X-PQC-User-Token'] = sessionToken; }
  var url = mode === 'signin' ? '/api/auth/google' : '/api/auth/tool-consent';
  var body = mode === 'signin'
    ? { google_access_token: accessToken, oauth_state: state, region: statePayload.region || undefined, timezone: statePayload.timezone || undefined, use_token_for_gcp_connection: false }
    : { access_token: accessToken, oauth_state: state, session_id: statePayload.session_id || undefined, target_scope: statePayload.target_scope || undefined };
  try {
    var res = await fetch(url, { method: 'POST', credentials: 'same-origin', headers: headers, body: JSON.stringify(body) });
    var data = {};
    try { data = await res.json(); } catch (e) { data = {}; }
    if (!res.ok) {
      finish(false, Object.assign({ authenticated: false }, data), 'Authorization failed: ' + (data.detail || ('HTTP ' + res.status)));
      return;
    }
    finish(true, data, mode === 'signin' ? 'Signed in. You can close this window.' : 'Authorized. You can close this window.');
  } catch (e) {
    finish(false, { authenticated: false, error: String(e) }, 'Authorization error: ' + e);
  }
})();
</script></body></html>"""


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
                    "status": telemetry.get("status", "OK"),
                    "tool_calls": list(pending_turn_tools),
                    "served_by": telemetry.get("served_by") or _event_usage_block(ev),
                    "model_label": telemetry.get("model_label"),
                    "oauth_consent_required": telemetry.get("oauth_consent_required"),
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
    """Creates the FastAPI server: the portal at `GET /`, `/api/*` (identity-bound), and ADK's native routes.

    ADK-native REST routes and the ADK DevServer (`/dev-ui`, `/dev/apps/*`) are disabled on Cloud Run unless
    PQC_ENABLE_ADK_API / PQC_ENABLE_ADK_DEV_UI say otherwise; when enabled they require an authenticated identity.
    """
    resolved_db_url = _normalize_sqlite_db_url(session_db_url or os.getenv("SESSION_DB_URL", DEFAULT_SESSION_DB_URL))
    resolved_bucket = (artifact_bucket or DEFAULT_STAGING_BUCKET).replace("gs://", "").strip("/")

    session_service = DatabaseSessionService(db_url=resolved_db_url)
    artifact_service = ResilientGcsArtifactService(bucket_name=resolved_bucket)
    # Delegated OAuth credentials stay in process memory: SessionStateCredentialService would store user tokens in
    # clear text in the session DB on /data (a GCS bucket on Cloud Run) and echo them through session reads.
    credential_service = InMemoryCredentialService()
    registry_obj = model_registry or ModelRegistry()

    registry = get_service_registry()
    registry.register_session_service("sqlite", lambda uri, **kw: session_service)
    registry.register_session_service("sqlite+aiosqlite", lambda uri, **kw: session_service)
    registry.register_artifact_service("gs", lambda uri, **kw: artifact_service)

    project_root = str(Path(__file__).resolve().parent.parent)
    dev_ui_on = _adk_dev_ui_enabled()
    adk_api_on = auth_guard.adk_api_enabled()
    cors_origins = auth_guard.allowed_cors_origins()  # None => same-origin portal only (no CORS headers)
    app = get_fast_api_app(
        agents_dir=project_root,
        session_service_uri=resolved_db_url,
        artifact_service_uri=f"gs://{resolved_bucket}",
        web=dev_ui_on,
        allow_origins=cors_origins,
    )
    if not dev_ui_on:
        # Defense in depth: no DevServer route (builder/save, deploy/*, eval, /dev-ui) may exist when disabled.
        app.router.routes = [
            r for r in app.router.routes if not str(getattr(r, "path", "")).startswith(("/dev/", "/dev-ui"))
        ]
    # Outermost middleware: every non-portal (ADK-native) route is 404 unless enabled, then identity-bound.
    app.add_middleware(
        auth_guard.AdkRouteGuardMiddleware,
        resolver=resolve_request_identity,
        api_enabled=adk_api_on,
        dev_ui_static=dev_ui_on,
        on_identity=_bind_tenant_context,
        normalize_user_id=normalize_user_id,
        allowed_origins=cors_origins,
    )
    if auth_guard.allow_unverified_signin():
        logger.warning(
            "PQC_ALLOW_UNVERIFIED_SIGNIN=true: email-only sign-in is ENABLED (development only)%s.",
            " -- WARNING: this instance runs on Cloud Run" if auth_guard.running_on_cloud_run() else "",
        )

    app.state.adk_dev_ui_enabled = dev_ui_on
    app.state.adk_api_enabled = adk_api_on
    app.state.cors_allowed_origins = list(cors_origins or [])
    app.state.session_service = session_service
    app.state.artifact_service = artifact_service
    app.state.credential_service = credential_service
    app.state.session_db_url = resolved_db_url
    app.state.artifact_bucket = resolved_bucket
    app.state.model_registry = registry_obj

    if verify_models_on_startup is None:
        verify_models_on_startup = os.getenv("PQC_MODEL_VERIFICATION_ON_STARTUP", "true").strip().lower() == "true"
    if verify_models_on_startup:
        registry_obj.start_background_verification()

    telemetry_plugin = LlmCallTelemetryPlugin()
    oauth_3lo_plugin = PqcOAuth3LOPlugin()
    runners_by_key: Dict[str, Runner] = {}

    def _get_runner(model_name: str, thinking_level: Optional[str]) -> Runner:
        cache_key = f"{model_name}:{thinking_level or 'NONE'}"
        if cache_key not in runners_by_key:
            runners_by_key[cache_key] = Runner(
                app=App(
                    name=APP_NAME,
                    root_agent=create_pqc_agent(model_name=model_name, thinking_level=thinking_level),
                    plugins=[telemetry_plugin, oauth_3lo_plugin],
                ),
                session_service=session_service,
                artifact_service=artifact_service,
                credential_service=credential_service,
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

    assets_dir = Path(__file__).resolve().parent / "assets"

    @app.get("/favicon.ico", include_in_schema=False)
    async def serve_favicon() -> FileResponse:
        return FileResponse(
            path=str(assets_dir / "favicon.ico"),
            media_type="image/x-icon",
            headers={"Cache-Control": "public, max-age=86400"},
        )

    @app.get("/static/pqc-favicon-64.png", include_in_schema=False)
    async def serve_favicon_64() -> FileResponse:
        return FileResponse(
            path=str(assets_dir / "pqc_favicon_64.png"),
            media_type="image/png",
            headers={"Cache-Control": "public, max-age=86400"},
        )

    @app.get("/static/pqc-logo-shield.png", include_in_schema=False)
    async def serve_logo_shield() -> FileResponse:
        return FileResponse(
            path=str(assets_dir / "pqc_logo_shield.png"),
            media_type="image/png",
            headers={"Cache-Control": "public, max-age=86400"},
        )

    @app.get("/static/pqc-logo-full.png", include_in_schema=False)
    async def serve_logo_full() -> FileResponse:
        return FileResponse(
            path=str(assets_dir / "pqc_logo_full.png"),
            media_type="image/png",
            headers={"Cache-Control": "public, max-age=86400"},
        )

    def _is_https(request: Request) -> bool:
        return (request.headers.get("x-forwarded-proto") or request.url.scheme).split(",")[0].strip() == "https"

    def _set_session_cookie(resp: Any, request: Request, token: str) -> None:
        resp.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=token,
            max_age=SESSION_TOKEN_TTL_SECONDS,
            httponly=True,
            samesite="lax",
            secure=_is_https(request),
            path="/",
        )

    def _set_oauth_nonce_cookie(resp: Any, request: Request, nonce: str) -> None:
        # Binds the OAuth `state` to this browser (login-CSRF / token-injection protection).
        resp.set_cookie(
            key=OAUTH_NONCE_COOKIE_NAME,
            value=nonce,
            max_age=OAUTH_STATE_TTL_SECONDS,
            httponly=True,
            samesite="lax",
            secure=_is_https(request),
            path="/api/auth",
        )

    def _oauth_callback_uri(request: Request) -> str:
        proto = (request.headers.get("x-forwarded-proto") or request.url.scheme).split(",")[0].strip()
        host = request.headers.get("host") or request.url.netloc
        return f"{proto}://{host}/api/auth/oauth/callback"

    def _require_identity(request: Request, explicit_user_id: Optional[str] = None) -> auth_guard.AuthenticatedIdentity:
        """401 without an authenticated identity, 403 if `explicit_user_id` names someone else; binds the tenant."""
        identity = resolve_request_identity(request)
        auth_guard.bind_user_id(identity, explicit_user_id, normalize_user_id=normalize_user_id)
        assert identity is not None
        set_current_tenant_user(identity.user_id)
        return identity

    def _auth_config_payload() -> Dict[str, Any]:
        oauth_cfg = load_oauth_client_config()
        client_id = oauth_cfg.get("client_id", "")
        return {
            "allow_unverified_signin": auth_guard.allow_unverified_signin(),
            "google_oauth_client_configured": bool(client_id),
            "google_oauth_client_id": client_id,
            "oauth_signin_url": "/api/auth/oauth/signin" if client_id else None,
            "access_token_command": "gcloud auth print-access-token",
            "allowed_domains": list(ALLOWED_AUTH_DOMAINS),
            "supported_regions": SUPPORTED_REGIONS,
            "iap_jwt_verification": True,
            "iap_audience_configured": bool(os.getenv(auth_guard.ENV_IAP_AUDIENCE, "").strip()),
        }

    async def _complete_signin(
        *,
        email: str,
        name: Optional[str],
        region: Optional[str],
        timezone_str: Optional[str],
        auth_method: str,
        picture: Optional[str],
        gcp_access_token: Optional[str] = None,
        gcp_access_token_expires_in: Optional[Any] = None,
    ) -> Tuple[Dict[str, Any], str]:
        profile = upsert_tenant_user_profile(
            email=email,
            name=name,
            region=region,
            timezone_str=timezone_str,
            auth_method=auth_method,
            picture=picture,
        )
        uid = profile["user_id"]
        set_current_tenant_user(uid)
        if gcp_access_token:
            _bind_delegated_gcp_token(uid, gcp_access_token, gcp_access_token_expires_in)
        signed_token = sign_tenant_session_token(profile)
        sess_resp = await session_service.list_sessions(app_name=APP_NAME, user_id=uid)
        content = {
            "authenticated": True,
            "user": profile,
            "user_id": uid,
            "token": signed_token,
            "session_count": len(sess_resp.sessions),
            "connection": get_gcp_connection_config(mask_token=True, user_id=uid),
            "supported_regions": SUPPORTED_REGIONS,
        }
        return content, signed_token

    def _validated_google_identity(verified_info: Optional[Dict[str, Any]], err_msg: Optional[str]) -> Tuple[int, str]:
        """(status, email_or_error): 200 + email for a verified allowed-domain identity, else 401/403 + reason."""
        if not verified_info:
            return 401, err_msg or "Google credential verification failed."
        if verified_info.get("email_verified") is not True:
            return 401, "The Google account email address is not verified."
        ok, validated_or_err = is_allowed_corporate_email(str(verified_info.get("email") or ""))
        if not ok:
            return 403, validated_or_err
        return 200, validated_or_err

    @app.get("/api/models")
    async def list_available_models(request: Request, refresh: bool = Query(default=False)) -> Dict[str, Any]:
        """Lists ONLY Gemini Pro models verified to answer on Vertex AI in this project (public).

        `refresh=true` re-probes every candidate with real (billed) Vertex AI calls, so it requires a signed-in user.
        """
        if refresh:
            activate_request_tenant_user(request)
            await asyncio.to_thread(registry_obj.verify_all, True)
        return registry_obj.catalog()

    @app.get("/api/health")
    async def api_health(request: Request) -> Dict[str, Any]:
        """Public status endpoint. Never activates a tenant from request parameters; connection only when signed in."""
        identity = resolve_request_identity(request)
        catalog = registry_obj.catalog()
        oauth_cfg = load_oauth_client_config()
        return {
            "status": "HEALTHY",
            "app_name": APP_NAME,
            "multi_tenant_enabled": True,
            "oauth_3lo_enabled": True,
            "google_oauth_client_configured": bool(oauth_cfg.get("client_id")),
            "allow_unverified_signin": auth_guard.allow_unverified_signin(),
            "authenticated": identity is not None,
            "supported_regions": [r["id"] for r in SUPPORTED_REGIONS],
            "allowed_auth_domains": list(ALLOWED_AUTH_DOMAINS),
            "session_service": type(session_service).__name__,
            "session_db_url": resolved_db_url,
            "artifact_service": type(artifact_service).__name__,
            "artifact_bucket": f"gs://{resolved_bucket}",
            "credential_service": type(credential_service).__name__,
            "connection": get_gcp_connection_config(mask_token=True, user_id=identity.user_id) if identity else None,
            "simulation_mode": os.getenv("PQC_SIMULATION_MODE", "FALSE"),
            "verified_models": [m["id"] for m in catalog["models"]],
            "model_verification": catalog["verification"],
            "adk_api_enabled": adk_api_on,
            "dev_ui_available": dev_ui_on,
            "dev_ui_url": "/dev-ui/?app=pqc_agent" if dev_ui_on else None,
        }

    # =========================================================================
    # Multi-Tenant @google.com Authentication & Regional Profile (/api/auth/*)
    # =========================================================================

    @app.get("/api/auth/config")
    async def auth_config_endpoint() -> Dict[str, Any]:
        """Public sign-in configuration for the portal sign-in dialog (which credential types are accepted)."""
        return _auth_config_payload()

    @app.get("/api/auth/me")
    async def auth_me(request: Request) -> Dict[str, Any]:
        profile, iap_active = resolve_authenticated_tenant_from_request(request)
        uid = profile["user_id"] if profile else None
        conn: Optional[Dict[str, Any]] = None
        session_count = 0
        signed_token: Optional[str] = None
        if uid and profile:
            set_current_tenant_user(uid)
            signed_token = sign_tenant_session_token(profile)
            conn = get_gcp_connection_config(mask_token=True, user_id=uid)
            try:
                sess_resp = await session_service.list_sessions(app_name=APP_NAME, user_id=uid)
                session_count = len(sess_resp.sessions)
            except Exception:
                session_count = 0
        cfg = _auth_config_payload()
        return {
            "authenticated": profile is not None,
            "iap_active": iap_active,
            "google_oauth_client_id": cfg["google_oauth_client_id"],
            "google_oauth_client_configured": cfg["google_oauth_client_configured"],
            "allow_unverified_signin": cfg["allow_unverified_signin"],
            "oauth_3lo_enabled": True,
            "oauth_scopes": list(GCP_OAUTH_SCOPES),
            "allowed_domains": list(ALLOWED_AUTH_DOMAINS),
            "supported_regions": SUPPORTED_REGIONS,
            "user": profile,
            "user_id": uid,
            "token": signed_token,
            "session_count": session_count,
            "connection": conn,
        }

    @app.post("/api/auth/google")
    async def auth_google_signin(request: Request, payload: GoogleAuthSignInPayload) -> JSONResponse:
        """Signs a user in from a VERIFIED Google credential and sets a signed 30-day session cookie.

        Accepted credentials: a Google ID token (`credential` / `id_token`) or a Google OAuth access token
        (`google_access_token`, e.g. `gcloud auth print-access-token`), both verified with Google. The email must be
        verified and belong to ALLOWED_AUTH_DOMAINS (403 otherwise). Email-only sign-in returns 401 unless
        PQC_ALLOW_UNVERIFIED_SIGNIN=true (local development only).
        """
        if payload.oauth_state is not None:
            st = _validate_oauth_state_for_request(request, payload.oauth_state)
            if not st or st.get("mode") != "signin":
                raise HTTPException(status_code=400, detail="Invalid or expired OAuth state. Start the sign-in again.")
        id_jwt = (payload.credential or payload.id_token or "").strip() or None
        access_tok = (payload.google_access_token or "").strip() or None
        if access_tok and access_tok.lower().startswith("bearer "):
            access_tok = access_tok[7:].strip() or None
        expires_in: Optional[Any] = None
        if id_jwt or access_tok:
            verified_info, err_msg = await asyncio.to_thread(_verify_google_oauth_or_id_token, id_jwt, access_tok)
            status_code, email_or_err = _validated_google_identity(verified_info, err_msg)
            if status_code != 200:
                raise HTTPException(status_code=status_code, detail=email_or_err)
            assert verified_info is not None
            target_email = email_or_err
            display_name = payload.name or verified_info.get("name")
            auth_method = verified_info.get("auth_method", "google_id_token")
            picture = verified_info.get("picture", "")
            expires_in = verified_info.get("expires_in")
        elif auth_guard.allow_unverified_signin():
            ok, validated_or_err = is_allowed_corporate_email((payload.email or "").strip())
            if not ok:
                raise HTTPException(status_code=403, detail=validated_or_err)
            logger.warning("UNVERIFIED email-only sign-in for %s (PQC_ALLOW_UNVERIFIED_SIGNIN=true).", validated_or_err)
            target_email = validated_or_err
            display_name = payload.name
            auth_method = "unverified_email_dev_only"
            picture = None
        else:
            raise HTTPException(status_code=401, detail=EMAIL_ONLY_SIGNIN_DISABLED_DETAIL)

        content, signed_token = await _complete_signin(
            email=target_email,
            name=display_name,
            region=payload.region,
            timezone_str=payload.timezone,
            auth_method=auth_method,
            picture=picture,
            gcp_access_token=access_tok if (access_tok and payload.use_token_for_gcp_connection) else None,
            gcp_access_token_expires_in=expires_in,
        )
        resp = JSONResponse(content=content)
        _set_session_cookie(resp, request, signed_token)
        return resp

    @app.post("/api/auth/logout")
    async def auth_logout(request: Request) -> JSONResponse:
        identity = resolve_request_identity(request)
        if identity is not None:
            clear_user_access_token(identity.user_id)
        resp = JSONResponse(content={"authenticated": False, "status": "logged_out"})
        resp.delete_cookie(key=SESSION_COOKIE_NAME, path="/")
        return resp

    @app.post("/api/auth/auto")
    async def auth_auto_signin(request: Request) -> JSONResponse:
        """Automatic zero-typing sign-in: restores an existing verified session/IAP identity or, on a corporate
        workstation, automatically verifies the active `gcloud` corporate identity with Google (`tokeninfo` + `userinfo`).
        """
        profile, iap_active = resolve_authenticated_tenant_from_request(request)
        if profile is not None:
            uid = profile["user_id"]
            set_current_tenant_user(uid)
            signed_token = sign_tenant_session_token(profile)
            sess_resp = await session_service.list_sessions(app_name=APP_NAME, user_id=uid)
            resp = JSONResponse(
                content={
                    "authenticated": True,
                    "iap_active": iap_active,
                    "user": profile,
                    "user_id": uid,
                    "token": signed_token,
                    "session_count": len(sess_resp.sessions),
                    "connection": get_gcp_connection_config(mask_token=True, user_id=uid),
                    "supported_regions": SUPPORTED_REGIONS,
                }
            )
            _set_session_cookie(resp, request, signed_token)
            return resp

        auto_tok = await asyncio.to_thread(_try_workstation_auto_gcloud_token)
        if auto_tok:
            verified_info, err_msg = await asyncio.to_thread(_verify_google_oauth_or_id_token, None, auto_tok)
            status_code, email_or_err = _validated_google_identity(verified_info, err_msg)
            if status_code == 200 and verified_info is not None:
                content, signed_token = await _complete_signin(
                    email=email_or_err,
                    name=verified_info.get("name"),
                    region=request.headers.get("X-PQC-User-Region"),
                    timezone_str=request.headers.get("X-PQC-User-Timezone"),
                    auth_method="google_auto_session",
                    picture=verified_info.get("picture", ""),
                )
                resp = JSONResponse(content=content)
                _set_session_cookie(resp, request, signed_token)
                return resp

        return JSONResponse(status_code=200, content={"authenticated": False})

    @app.post("/api/auth/switch")
    async def auth_switch_account(request: Request) -> JSONResponse:
        """Switches the active browser session between verified Google accounts stored in the Gemini Account Switcher."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        candidate_token = str((body or {}).get("token") or "").strip()
        decoded = verify_tenant_session_token(candidate_token) if candidate_token else None
        if not decoded:
            identity = resolve_request_identity(request)
            if identity and identity.source == "iap":
                existing = _load_tenant_users_map().get(identity.user_id, {})
                decoded = {
                    "email": identity.email,
                    "uid": identity.user_id,
                    "name": existing.get("name"),
                    "region": existing.get("region"),
                    "auth_method": "cloud_iap",
                    "picture": existing.get("picture"),
                }
            else:
                raise HTTPException(status_code=401, detail="Saved account session has expired. Please sign in again.")
        email = normalize_user_id(decoded.get("email") or decoded.get("uid"))
        profile = upsert_tenant_user_profile(
            email=email,
            name=decoded.get("name"),
            region=(body or {}).get("region") or decoded.get("region"),
            timezone_str=(body or {}).get("timezone") or request.headers.get("X-PQC-User-Timezone"),
            auth_method=decoded.get("auth_method") or "google_workspace_signin",
            picture=decoded.get("picture"),
        )
        uid = profile["user_id"]
        set_current_tenant_user(uid)
        fresh_token = sign_tenant_session_token(profile)
        sess_resp = await session_service.list_sessions(app_name=APP_NAME, user_id=uid)
        content = {
            "authenticated": True,
            "user": profile,
            "user_id": uid,
            "token": fresh_token,
            "session_count": len(sess_resp.sessions),
            "connection": get_gcp_connection_config(mask_token=True, user_id=uid),
            "supported_regions": SUPPORTED_REGIONS,
        }
        resp = JSONResponse(content=content)
        _set_session_cookie(resp, request, fresh_token)
        return resp


    @app.get("/api/auth/tenants")
    async def list_registered_tenants(request: Request) -> Dict[str, Any]:
        """Tenant directory: aggregate counts for signed-in users; individual profiles only for admins."""
        identity = _require_identity(request)
        users_map = _load_tenant_users_map()
        tenants = sorted(users_map.values(), key=lambda u: u.get("last_login_at", ""), reverse=True)
        by_region: Dict[str, int] = {}
        for t in tenants:
            reg = t.get("region", "NorthAm")
            by_region[reg] = by_region.get(reg, 0) + 1
        is_admin = auth_guard.is_admin_identity(identity)
        return {
            "total_tenants": len(tenants),
            "by_region": by_region,
            "full_directory": is_admin,
            "tenants": tenants if is_admin else [t for t in tenants if t.get("user_id") == identity.user_id],
        }

    # =========================================================================
    # 3-Legged OAuth (3LO) Consent & ADK ToolContext Credential Injection
    # =========================================================================

    @app.get("/api/auth/oauth/config")
    async def get_oauth_config_endpoint() -> Dict[str, Any]:
        cfg = load_oauth_client_config()
        return {
            "client_id": cfg["client_id"],
            "has_client_secret": bool(cfg["client_secret"]),
            "scopes": cfg["scopes"],
            "authorization_endpoint": cfg["authorization_endpoint"],
            "credential_key": GCP_OAUTH_CREDENTIAL_KEY,
        }

    @app.post("/api/auth/oauth/config")
    async def update_oauth_config_endpoint(request: Request, payload: OAuthClientConfigPayload) -> Dict[str, Any]:
        """Changes the GLOBAL OAuth client used by every tenant: signed-in administrators only (PQC_ADMIN_EMAILS;
        without that list only local, non-Cloud Run instances treat signed-in users as administrators)."""
        identity = _require_identity(request)
        if not auth_guard.is_admin_identity(identity):
            raise HTTPException(
                status_code=403,
                detail="Only portal administrators (PQC_ADMIN_EMAILS) can change the OAuth client configuration.",
            )
        return save_oauth_client_config(client_id=payload.client_id, client_secret=payload.client_secret)

    @app.get("/api/auth/oauth/signin")
    async def oauth_signin_start_endpoint(
        request: Request,
        region: Optional[str] = Query(default=None),
        timezone: Optional[str] = Query(default=None),
    ) -> Any:
        """Public: starts 'Sign in with Google' (OpenID Connect, popup) when an OAuth client is configured."""
        oauth_cfg = load_oauth_client_config()
        client_id = oauth_cfg.get("client_id", "")
        if not client_id:
            return HTMLResponse(
                status_code=404,
                content=_oauth_popup_result_html(
                    "PQC_SIGNIN_COMPLETE",
                    {"authenticated": False, "error": "GOOGLE_OAUTH_CLIENT_NOT_CONFIGURED"},
                    "Google OAuth sign-in is not configured on this server. Close this window and paste the output "
                    "of `gcloud auth print-access-token` in the sign-in dialog instead.",
                    ok=False,
                ),
            )
        nonce = secrets.token_urlsafe(16)
        state = sign_oauth_state({"mode": "signin", "nonce": nonce, "region": region or "", "timezone": timezone or ""})
        params = {
            "client_id": client_id,
            "redirect_uri": _oauth_callback_uri(request),
            "response_type": "code" if oauth_cfg.get("client_secret") else "token",
            "scope": "openid email profile",
            "state": state,
            "prompt": "select_account",
        }
        resp = RedirectResponse(url=f"{oauth_cfg['authorization_endpoint']}?{urllib.parse.urlencode(params)}", status_code=302)
        _set_oauth_nonce_cookie(resp, request, nonce)
        return resp

    @app.get("/api/auth/oauth/authorize")
    async def oauth_3lo_authorize_endpoint(
        request: Request,
        user_id: Optional[str] = Query(default=None),
        session_id: Optional[str] = Query(default=None),
        scope: Optional[str] = Query(default="organizations/31564119954"),
        redirect_uri: Optional[str] = Query(default=None),
        format: Optional[str] = Query(default=None),
    ) -> Any:
        """Initiates the 3-Legged OAuth 2.0 (3LO) flow for Google Cloud APIs on behalf of the SIGNED-IN user.

        - Requires an authenticated identity (401) and `user_id`, if given, must be that identity (403).
        - The OAuth `state` is HMAC-signed, expires in 10 minutes, is single use and bound to this browser (nonce
          cookie). `redirect_uri` is ignored: the callback is always this service's `/api/auth/oauth/callback`.
        - `format=json` returns the authorization URL; `direct=1` redirects to Google; otherwise renders a popup.
        """
        uid = activate_request_tenant_user(request, explicit_user_id=user_id)
        oauth_cfg = load_oauth_client_config()
        client_id = oauth_cfg.get("client_id", "")
        has_secret = bool(oauth_cfg.get("client_secret"))
        cb_uri = _oauth_callback_uri(request)
        target_scope = scope or "organizations/31564119954"
        nonce = secrets.token_urlsafe(16)
        encoded_state = sign_oauth_state(
            {"mode": "3lo", "uid": uid, "session_id": session_id or "", "target_scope": target_scope, "nonce": nonce}
        )

        google_auth_url = ""
        if client_id:
            params = {
                "client_id": client_id,
                "redirect_uri": cb_uri,
                "response_type": "code" if has_secret else "token",
                "scope": " ".join(GCP_OAUTH_SCOPES),
                "include_granted_scopes": "true",
                "prompt": "consent",
                "state": encoded_state,
            }
            if has_secret:
                params["access_type"] = "online"
            if "@" in uid:
                params["login_hint"] = uid
            google_auth_url = f"{oauth_cfg['authorization_endpoint']}?{urllib.parse.urlencode(params)}"

        if format == "json":
            json_resp = JSONResponse(
                content={
                    "user_id": uid,
                    "session_id": session_id,
                    "target_scope": target_scope,
                    "client_id_configured": bool(client_id),
                    "client_id": client_id,
                    "redirect_uri": cb_uri,
                    "scopes": list(GCP_OAUTH_SCOPES),
                    "google_auth_url": google_auth_url,
                    "state": encoded_state,
                }
            )
            _set_oauth_nonce_cookie(json_resp, request, nonce)
            return json_resp

        if google_auth_url and request.query_params.get("direct") == "1":
            redirect_resp = RedirectResponse(url=google_auth_url, status_code=302)
            _set_oauth_nonce_cookie(redirect_resp, request, nonce)
            return redirect_resp

        google_button_html = ""
        if google_auth_url:
            google_button_html = (
                f'<a href="{html.escape(google_auth_url, quote=True)}" style="text-decoration:none;">'
                '<button type="button" class="btn btn-google">Continue to Google Consent Screen (accounts.google.com)'
                "</button></a>"
            )
        # Every reflected value is HTML-escaped (markup) or JSON/script-escaped (inline JS): no reflected XSS.
        popup_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Sign in with Google — PQC Inventory Agent (OAuth 2.0 3LO)</title>
<style>
  body {{ margin:0; font-family:'Google Sans','Inter',system-ui,sans-serif; background:#0b0f17; color:#e2e8f0; display:flex; align-items:center; justify-content:center; min-height:100vh; padding:16px; box-sizing:border-box; }}
  .card {{ width:100%; max-width:460px; background:#111827; border:1px solid #1e293b; border-radius:16px; padding:26px; box-shadow:0 24px 60px rgba(0,0,0,0.65); }}
  .hdr {{ display:flex; align-items:center; gap:12px; margin-bottom:14px; }}
  .badge {{ font-size:11px; font-weight:600; color:#8ab4f8; background:rgba(66,133,244,0.14); border:1px solid rgba(66,133,244,0.35); padding:3px 9px; border-radius:999px; }}
  h2 {{ margin:0 0 6px 0; font-size:18px; color:#f8fafc; }}
  p {{ margin:0 0 14px 0; font-size:13px; color:#94a3b8; line-height:1.5; }}
  .scope-box {{ background:#0b1120; border:1px solid #1e293b; border-radius:10px; padding:12px; margin-bottom:16px; font-size:12px; }}
  .scope-item {{ display:flex; align-items:center; gap:8px; color:#cbd5e1; margin:5px 0; font-family:'JetBrains Mono',monospace; font-size:11.5px; }}
  .btn {{ width:100%; padding:11px 14px; border-radius:9px; border:none; font-weight:600; font-size:13px; cursor:pointer; display:flex; align-items:center; justify-content:center; gap:8px; margin-bottom:10px; }}
  .btn-google {{ background:#4285F4; color:#fff; }}
  .btn-google:hover {{ background:#3b78e7; }}
  .btn-sec {{ background:#1e293b; color:#e2e8f0; border:1px solid #334155; }}
  input {{ width:100%; box-sizing:border-box; padding:10px 12px; border-radius:8px; border:1px solid #334155; background:#0b0f17; color:#f8fafc; font-family:'JetBrains Mono',monospace; font-size:12px; margin-bottom:10px; }}
  .err {{ color:#f87171; font-size:12px; margin-bottom:10px; display:none; }}
  .cmd {{ background:#070b12; border:1px solid #1e293b; padding:7px 10px; border-radius:6px; font-family:'JetBrains Mono',monospace; font-size:11px; color:#93c5fd; margin-bottom:10px; word-break:break-all; }}
</style>
</head>
<body>
<div class="card">
  <div class="hdr">
    <div>
      <span class="badge">3-Legged OAuth 2.0 • ADK ToolContext</span>
    </div>
  </div>
  <h2>Authorize PQC Inventory Agent</h2>
  <p>Allow the agent to inspect <b>{html.escape(target_scope)}</b> on behalf of <b>{html.escape(uid)}</b> using read-only Google Cloud permissions:</p>
  <div class="scope-box">
    <div style="font-size:11px;color:#64748b;margin-bottom:6px;text-transform:uppercase;letter-spacing:0.05em;">Requested OAuth 2.0 Scopes</div>
    <div class="scope-item">✓ openid email profile (@google.com identity)</div>
    <div class="scope-item">✓ https://www.googleapis.com/auth/cloud-platform.read-only</div>
  </div>
  <div id="errBox" class="err"></div>
  {google_button_html}
  <div style="font-size:12px;color:#cbd5e1;margin:10px 0 6px 0;font-weight:600;">Authorize with your Google Cloud OAuth Token:</div>
  <div class="cmd">gcloud auth print-access-token</div>
  <input id="tokInput" type="password" placeholder="Paste ya29... OAuth 2.0 access token" autofocus />
  <button type="button" class="btn btn-google" onclick="submitConsent()">Allow &amp; Inject into ADK ToolContext</button>
  <details style="margin-top:10px;font-size:11.5px;color:#94a3b8;">
    <summary style="cursor:pointer;color:#8ab4f8;">Configure Google OAuth 2.0 Web Client ID (administrators)</summary>
    <div style="margin-top:8px;">
      <input id="cidInput" type="text" placeholder="123456-abc.apps.googleusercontent.com" value="{html.escape(client_id, quote=True)}" />
      <button type="button" class="btn btn-sec" onclick="saveClientId()">Save OAuth Client ID &amp; Redirect to Google</button>
    </div>
  </details>
</div>
<script>
const PQC_SESSION_ID = {_js_literal(session_id or "")};
const PQC_TARGET_SCOPE = {_js_literal(target_scope)};
function pqcAuthHeaders() {{
  const headers = {{ 'Content-Type': 'application/json' }};
  const sessionToken = localStorage.getItem('pqc_session_token');
  if (sessionToken) headers['X-PQC-User-Token'] = sessionToken;
  return headers;
}}
function showError(message) {{
  const err = document.getElementById('errBox');
  err.textContent = message;
  err.style.display = 'block';
}}
async function submitConsent() {{
  const tok = document.getElementById('tokInput').value.trim();
  document.getElementById('errBox').style.display = 'none';
  if (!tok) {{ showError('Please paste a valid Google OAuth 2.0 access token.'); return; }}
  try {{
    const res = await fetch('/api/auth/tool-consent', {{
      method: 'POST',
      credentials: 'same-origin',
      headers: pqcAuthHeaders(),
      body: JSON.stringify({{ session_id: PQC_SESSION_ID, access_token: tok, target_scope: PQC_TARGET_SCOPE }})
    }});
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Consent authorization failed.');
    if (window.opener) {{
      window.opener.postMessage({{ type: 'PQC_OAUTH_3LO_AUTHORIZED', payload: data }}, window.location.origin);
      window.close();
    }} else {{
      window.location.href = '/';
    }}
  }} catch (e) {{
    showError(e.message);
  }}
}}
async function saveClientId() {{
  const cid = document.getElementById('cidInput').value.trim();
  if (!cid) return;
  const res = await fetch('/api/auth/oauth/config', {{
    method: 'POST',
    credentials: 'same-origin',
    headers: pqcAuthHeaders(),
    body: JSON.stringify({{ client_id: cid }})
  }});
  if (!res.ok) {{
    let detail = 'HTTP ' + res.status;
    try {{ detail = (await res.json()).detail || detail; }} catch (e) {{}}
    showError(detail);
    return;
  }}
  window.location.href = window.location.pathname + window.location.search + '&direct=1';
}}
</script>
</body>
</html>"""
        popup_resp = HTMLResponse(content=popup_html)
        _set_oauth_nonce_cookie(popup_resp, request, nonce)
        return popup_resp

    @app.get("/api/auth/oauth/callback", response_class=HTMLResponse)
    async def oauth_3lo_callback_endpoint(
        request: Request,
        code: Optional[str] = Query(default=None),
        state: Optional[str] = Query(default=None),
        error: Optional[str] = Query(default=None),
    ) -> HTMLResponse:
        """Public OAuth redirect target for both 'Sign in with Google' and 3LO consent.

        The signed `state` is mandatory (HMAC, `typ`, 10 min expiry, single use, nonce cookie of this browser). Codes
        are exchanged server-side and tokens are never embedded in the returned page. Implicit-flow results (token in
        the URL fragment) are forwarded by the browser to `/api/auth/google` or `/api/auth/tool-consent`, which verify
        the same state.
        """
        hinted = verify_oauth_state(state) or {}
        message_type = "PQC_SIGNIN_COMPLETE" if hinted.get("mode") == "signin" else "PQC_OAUTH_3LO_AUTHORIZED"
        if error:
            return HTMLResponse(
                status_code=400,
                content=_oauth_popup_result_html(
                    message_type,
                    {"authenticated": False, "status": "OAUTH_ERROR", "error": error},
                    f"Authorization did not complete: {error}",
                    ok=False,
                ),
            )
        if not code:
            return HTMLResponse(content=_OAUTH_IMPLICIT_CALLBACK_HTML)

        st = _validate_oauth_state_for_request(request, state)
        if not st:
            return HTMLResponse(
                status_code=400,
                content=_oauth_popup_result_html(
                    message_type,
                    {"authenticated": False, "status": "INVALID_STATE"},
                    "Invalid or expired OAuth state. Close this window and start again from the portal.",
                    ok=False,
                ),
            )
        tok_data, exchange_err = await asyncio.to_thread(_exchange_oauth_code, code, _oauth_callback_uri(request))
        if not tok_data:
            return HTMLResponse(
                status_code=502,
                content=_oauth_popup_result_html(
                    message_type, {"authenticated": False, "status": "EXCHANGE_FAILED"}, exchange_err or "OAuth error.", ok=False
                ),
            )

        if st.get("mode") == "signin":
            id_tok = tok_data.get("id_token")
            verified_info, err_msg = await asyncio.to_thread(
                _verify_google_oauth_or_id_token, id_tok, None if id_tok else tok_data.get("access_token")
            )
            status_code, email_or_err = _validated_google_identity(verified_info, err_msg)
            if status_code != 200 or verified_info is None:
                return HTMLResponse(
                    status_code=status_code,
                    content=_oauth_popup_result_html(
                        message_type, {"authenticated": False, "status": "REJECTED", "detail": email_or_err}, email_or_err, ok=False
                    ),
                )
            content, signed_token = await _complete_signin(
                email=email_or_err,
                name=verified_info.get("name"),
                region=st.get("region") or None,
                timezone_str=st.get("timezone") or None,
                auth_method=verified_info.get("auth_method", "google_id_token"),
                picture=verified_info.get("picture", ""),
            )
            signin_resp = HTMLResponse(
                content=_oauth_popup_result_html(message_type, content, "Signed in. You can close this window.", ok=True)
            )
            _set_session_cookie(signin_resp, request, signed_token)
            signin_resp.delete_cookie(key=OAUTH_NONCE_COOKIE_NAME, path="/api/auth")
            return signin_resp

        uid = normalize_user_id(st.get("uid"))
        identity = resolve_request_identity(request)
        if "@" not in uid or (identity is not None and identity.user_id != uid):
            return HTMLResponse(
                status_code=403,
                content=_oauth_popup_result_html(
                    message_type, {"authenticated": False, "status": "USER_MISMATCH"}, auth_guard.USER_MISMATCH_DETAIL, ok=False
                ),
            )
        conn = _bind_delegated_gcp_token(uid, tok_data["access_token"], tok_data.get("expires_in"))
        result_payload = {
            "status": "AUTHORIZED",
            "authenticated": True,
            "user_id": uid,
            "session_id": st.get("session_id") or None,
            "target_scope": st.get("target_scope"),
            "credential_key": GCP_OAUTH_CREDENTIAL_KEY,
            "token_storage": "in_memory_only",
            "connection": conn,
        }
        consent_resp = HTMLResponse(
            content=_oauth_popup_result_html(message_type, result_payload, "Authorized. You can close this window.", ok=True)
        )
        consent_resp.delete_cookie(key=OAUTH_NONCE_COOKIE_NAME, path="/api/auth")
        return consent_resp

    @app.post("/api/auth/tool-consent")
    async def grant_tool_oauth_consent_endpoint(
        request: Request,
        payload: ToolConsentPayload,
    ) -> Dict[str, Any]:
        """Binds a delegated OAuth 2.0 access token to the SIGNED-IN user's gcloud/GCP connection so the paused ADK
        tool can resume on their behalf. The token is kept in process memory only (never in session state or on disk).
        """
        uid = activate_request_tenant_user(request, explicit_user_id=payload.user_id)
        if payload.oauth_state is not None:
            st = _validate_oauth_state_for_request(request, payload.oauth_state)
            if not st or st.get("mode") != "3lo" or normalize_user_id(st.get("uid")) != uid:
                raise HTTPException(status_code=400, detail="Invalid or expired OAuth state. Start the authorization again.")
        raw_token = (payload.access_token or "").strip()
        if raw_token.lower().startswith("bearer "):
            raw_token = raw_token[7:].strip()
        if not raw_token:
            raise HTTPException(status_code=400, detail="A valid OAuth 2.0 access_token is required.")

        verified_email: Optional[str] = None
        expires_in: Optional[Any] = None
        if payload.verify_with_google:
            info, err_msg = await asyncio.to_thread(_verify_google_oauth_or_id_token, None, raw_token)
            if not info:
                raise HTTPException(status_code=401, detail=err_msg or "Invalid Google OAuth access token.")
            verified_email = info["email"]
            expires_in = info.get("expires_in")

        conn = _bind_delegated_gcp_token(uid, raw_token, expires_in)
        session_found = False
        if payload.session_id:
            sess, _ = await _locate_session(payload.session_id, uid)
            session_found = sess is not None

        return {
            "status": "AUTHORIZED",
            "authenticated": True,
            "user_id": uid,
            "verified_email": verified_email or uid,
            "session_id": payload.session_id,
            "session_found": session_found,
            "session_credential_injected": False,
            "token_storage": "in_memory_only",
            "credential_key": GCP_OAUTH_CREDENTIAL_KEY,
            "tool_name": payload.tool_name,
            "target_scope": payload.target_scope,
            "connection": conn,
        }

    # =========================================================================
    # Persistent conversation history (/api/sessions)
    # =========================================================================

    @app.get("/api/sessions")
    async def list_persistent_sessions(
        request: Request,
        user_id: Optional[str] = Query(default=None, description="User identifier"),
    ) -> Dict[str, Any]:
        resolved_uid = activate_request_tenant_user(request, explicit_user_id=user_id)
        resp = await session_service.list_sessions(app_name=APP_NAME, user_id=resolved_uid)
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
        return {"user_id": resolved_uid, "total": len(items), "total_sessions": len(items), "sessions": items}

    @app.post("/api/sessions")
    async def create_persistent_session(
        request: Request,
        payload: Optional[CreateSessionPayload] = None,
    ) -> Dict[str, Any]:
        req = payload or CreateSessionPayload()
        user_id = activate_request_tenant_user(request, explicit_user_id=req.user_id)
        title = (req.title or "New PQC Assessment").strip()
        conn_org = get_gcp_connection_config(mask_token=True, user_id=user_id).get("organization_id", "31564119954")
        scope = (req.scope or f"organizations/{conn_org}").strip()
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
        _save_session_metadata_map(meta_map, changed_session_id=session.id)
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

    async def _locate_session(session_id: str, user_id: str) -> Tuple[Optional[Any], str]:
        """Strict tenant boundary: a session is only ever looked up under the authenticated user's own id."""
        candidate_user = normalize_user_id(user_id)
        sess = await session_service.get_session(app_name=APP_NAME, user_id=candidate_user, session_id=session_id)
        return sess, candidate_user

    @app.get("/api/sessions/{session_id}")
    async def get_persistent_session_detail(
        request: Request,
        session_id: str,
        user_id: Optional[str] = Query(default=None),
    ) -> Dict[str, Any]:
        active_uid = activate_request_tenant_user(request, explicit_user_id=user_id)
        sess, resolved_user = await _locate_session(session_id, active_uid)
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
            "state": _redact_session_state(state_dict),
        }

    @app.delete("/api/sessions/{session_id}")
    async def delete_persistent_session(
        request: Request,
        session_id: str,
        user_id: Optional[str] = Query(default=None),
    ) -> Dict[str, Any]:
        active_uid = activate_request_tenant_user(request, explicit_user_id=user_id)
        sess, resolved_user = await _locate_session(session_id, active_uid)
        if sess is None:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")
        await session_service.delete_session(app_name=APP_NAME, user_id=resolved_user, session_id=session_id)
        _delete_partitioned_session_metadata(resolved_user, session_id)
        meta_map = _load_session_metadata_map()
        if session_id in meta_map:
            del meta_map[session_id]
            _save_session_metadata_map(meta_map, changed_session_id="__deleted__")
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
        user_id: Optional[str] = Form(default=None),  # optional; must equal the authenticated user when given
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

        user_id = activate_request_tenant_user(request, explicit_user_id=user_id)

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
            set_gcp_connection_config(
                mode=connection_mode,
                impersonated_service_account=impersonated_sa,
                access_token=access_token,
                user_id=user_id,
            )

        user_text = (message or prompt or "").strip()
        uploaded_files = [f for f in (files or []) if f and f.filename]
        if not user_text and not uploaded_files:
            raise HTTPException(status_code=400, detail="Either 'message' text or at least one uploaded file is required.")
        if not user_text:
            user_text = "Please read the attached file(s), explain what they contain and how they affect our PQC assessment."

        sess = None
        if session_id:
            sess, user_id = await _locate_session(session_id, user_id)
            set_current_tenant_user(user_id)
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
        turn_consent_cards: List[Dict[str, Any]] = []
        invocation_id: Optional[str] = None
        consent_ctx_token = _TURN_OAUTH_CONSENT_CARDS.set(turn_consent_cards)

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
                                    "kind": (
                                        "oauth_consent_request"
                                        if name == "adk_request_credential"
                                        else ("specialist_agent" if name.endswith("_agent") else "tool")
                                    ),
                                    "args": dict(getattr(fc, "args", {}) or {}),
                                    "status": "CONSENT_REQUIRED" if name == "adk_request_credential" else "EXECUTED",
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
            finally:
                _TURN_OAUTH_CONSENT_CARDS.reset(consent_ctx_token)

        active_consent_card: Optional[Dict[str, Any]] = turn_consent_cards[-1] if turn_consent_cards else None
        if active_consent_card:
            active_consent_card["original_prompt"] = user_text

        served_by = _compact_served_by(summarize_llm_calls(ledger))
        assistant_text = "\n".join(final_text_parts).strip()
        if not assistant_text and active_consent_card:
            assistant_text = (
                f"### 🔐 Google Cloud OAuth 2.0 (3-Legged OAuth) Consent Required\n\n"
                f"To execute **`{active_consent_card.get('tool_name')}`** on **`{active_consent_card.get('target_scope')}`** "
                f"in your name (**`{user_id}`**), ADK `ToolContext.request_credential` paused tool execution and "
                f"requested delegated OAuth 2.0 authorization (`cloud-platform.read-only`).\n\n"
                f"Please click **Authorize with Google Cloud (OAuth 2.0)** in the consent card below to inject your "
                f"delegated credential into `ToolContext` and automatically resume this scan."
            )

        status = "OAUTH_CONSENT_REQUIRED" if active_consent_card else ("OK" if assistant_text else "MODEL_ERROR")
        error: Optional[Dict[str, Any]] = None
        if not assistant_text and not active_consent_card:
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
                "oauth_consent_required": active_consent_card,
            }
        _save_session_metadata_map(meta_map, changed_session_id=session_id)

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
            "oauth_consent_required": active_consent_card,
            "oauth_consent_cards": turn_consent_cards,
            "served_by": served_by,
            "uploaded_artifacts": saved_artifacts_meta,
            "tool_calls": tool_calls_trace,
            "tool_traces": tool_calls_trace,
            "connection": get_gcp_connection_config(mask_token=True, user_id=user_id),
            "updated_at": now_iso,
        }
        return JSONResponse(status_code=200 if status in ("OK", "OAUTH_CONSENT_REQUIRED") else 502, content=payload)

    # =========================================================================
    # gcloud CLI and dynamic credential bridge (isolated per tenant user)
    # =========================================================================

    @app.get("/api/connection")
    async def get_connection_endpoint(
        request: Request,
        user_id: Optional[str] = Query(default=None),
    ) -> Dict[str, Any]:
        uid = activate_request_tenant_user(request, explicit_user_id=user_id)
        return get_gcp_connection_config(mask_token=True, user_id=uid)

    @app.post("/api/connection")
    async def update_connection_endpoint(
        request: Request,
        payload: ConnectionConfigPayload,
    ) -> Dict[str, Any]:
        uid = activate_request_tenant_user(request, explicit_user_id=payload.user_id)
        return set_gcp_connection_config(
            mode=payload.mode,
            organization_id=payload.organization_id,
            project_id=payload.project_id,
            location=payload.location,
            impersonated_service_account=payload.impersonated_service_account,
            access_token=payload.access_token,
            user_id=uid,
        )

    @app.post("/api/gcloud")
    async def execute_gcloud_endpoint(
        request: Request,
        payload: GcloudCommandPayload,
    ) -> JSONResponse:
        activate_request_tenant_user(request, explicit_user_id=payload.user_id)
        return JSONResponse(content=json.loads(execute_gcloud_command(payload.command)))

    @app.get("/api/gcloud/traces")
    async def list_gcloud_traces_endpoint(
        request: Request,
        user_id: Optional[str] = Query(default=None),
    ) -> Dict[str, Any]:
        uid = activate_request_tenant_user(request, explicit_user_id=user_id)
        return {"user_id": uid, "traces": get_recent_gcloud_traces(user_id=uid)}

    return app


app = create_workspace_app()
session_service: DatabaseSessionService = app.state.session_service
artifact_service: ResilientGcsArtifactService = app.state.artifact_service
