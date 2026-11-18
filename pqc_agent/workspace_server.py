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
import concurrent.futures
import contextvars
import datetime
import hashlib
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
from typing import Any, Dict, List, Mapping, Optional, Tuple

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
from google.adk.cli.fast_api import get_fast_api_app
from google.adk.cli.service_registry import get_service_registry
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.runners import Runner
from google.adk.sessions.database_session_service import DatabaseSessionService
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.tool_context import ToolContext
from google.genai import types
from pydantic import BaseModel, ConfigDict

from pqc_agent import auth_guard, auth_store, credential_service, egress_guard
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
    normalize_connection_mode,
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
MAX_TELEMETRY_CALLS_RETURNED = 60


class ManagedSchemaDatabaseSessionService(DatabaseSessionService):
    """Subclass of ADK ``DatabaseSessionService`` that prohibits ``metadata.create_all()`` in production.

    In production, Alembic is the sole schema authority: ``prepare_tables()`` performs a strictly read-only
    check that the Alembic-managed ADK v1 tables and schema metadata exist, failing closed if missing or outdated.
    In non-production local development and isolated unit tests, ADK's standard table setup remains available.
    """

    async def prepare_tables(self) -> None:
        if not auth_guard.is_production_environment():
            await super().prepare_tables()
            return
        if self._tables_created:
            return
        async with self._table_creation_lock:
            if self._tables_created:
                return
            from google.adk.sessions.migration import _schema_check_utils

            def _verify_adk_schema_readonly(sync_conn: Any) -> str:
                existing = set(auth_store.sa_inspect(sync_conn).get_table_names())
                missing = sorted(set(auth_store.REQUIRED_ADK_V1_TABLES) - existing)
                if missing:
                    raise RuntimeError(
                        "Production ADK session schema verification failed: missing tables "
                        f"{', '.join(missing)}. Run 'alembic upgrade head' before starting."
                    )
                ver = _schema_check_utils.get_db_schema_version_from_connection(sync_conn)
                if ver != _schema_check_utils.LATEST_SCHEMA_VERSION:
                    raise RuntimeError(
                        f"Production ADK session schema verification failed: expected schema_version "
                        f"{_schema_check_utils.LATEST_SCHEMA_VERSION!r}, found {ver!r}."
                    )
                return ver

            async with self.db_engine.connect() as conn:
                self._db_schema_version = await conn.run_sync(_verify_adk_schema_readonly)
            self._tables_created = True


class ResilientGcsArtifactService(GcsArtifactService):
    """Subclass of ADK's ``GcsArtifactService`` backed by Cloud Storage object storage in production,
    with isolated non-production memory fallback exclusively for offline local development and unit tests.
    """

    def __init__(self, bucket_name: str, **kwargs: Any) -> None:
        clean_bucket = (bucket_name or "").replace("gs://", "").strip("/")
        self.bucket_name = clean_bucket
        self._local_fallback_store: Dict[str, List[types.Part]] = {}
        if not clean_bucket:
            if auth_guard.is_production_environment():
                raise RuntimeError("Production artifact storage failure: PQC_ARTIFACT_BUCKET must be configured.")
            self.storage_client = None  # type: ignore[assignment]
            self.bucket = None  # type: ignore[assignment]
            self._gcs_online = False
            return
        try:
            super().__init__(bucket_name=clean_bucket, **kwargs)
            self._gcs_online = True
        except Exception as exc:
            if auth_guard.is_production_environment():
                raise RuntimeError(
                    f"Production artifact storage failure: unable to initialize GcsArtifactService for '{clean_bucket}': {exc}"
                ) from exc
            logger.warning("GcsArtifactService initialized in local-dev fallback mode for bucket '%s': %s", clean_bucket, exc)
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
                if auth_guard.is_production_environment():
                    raise
                logger.debug("GCS artifact upload fallback to local-dev store for '%s': %s", filename, exc)

        key = f"{app_name}/{user_id}/{session_id or 'user'}/{os.path.basename(filename)}"
        versions = self._local_fallback_store.setdefault(key, [])
        versions.append(part_obj)
        return len(versions) - 1

    async def load_artifact(
        self,
        *,
        app_name: str,
        user_id: str,
        filename: str,
        session_id: Optional[str] = None,
        version: Optional[int] = None,
    ) -> Optional[types.Part]:
        if self._gcs_online and self.bucket is not None:
            try:
                loaded = await super().load_artifact(
                    app_name=app_name,
                    user_id=user_id,
                    filename=filename,
                    session_id=session_id,
                    version=version,
                )
                if loaded is not None:
                    return loaded
            except Exception:
                if auth_guard.is_production_environment():
                    raise
        key = f"{app_name}/{user_id}/{session_id or 'user'}/{os.path.basename(filename)}"
        if key in self._local_fallback_store and self._local_fallback_store[key]:
            idx = version if (version is not None and 0 <= version < len(self._local_fallback_store[key])) else -1
            return self._local_fallback_store[key][idx]
        return None

    async def list_artifact_keys(
        self, *, app_name: str, user_id: str, session_id: Optional[str] = None
    ) -> list[str]:
        if self._gcs_online and self.bucket is not None:
            try:
                gcs_keys = await super().list_artifact_keys(
                    app_name=app_name, user_id=user_id, session_id=session_id
                )
                if gcs_keys or auth_guard.is_production_environment():
                    return sorted(set(gcs_keys))
            except Exception:
                if auth_guard.is_production_environment():
                    raise
        prefix = f"{app_name}/{user_id}/{session_id or 'user'}/"
        local_keys = [k[len(prefix) :] for k in self._local_fallback_store if k.startswith(prefix)]
        return sorted(set(local_keys))


import subprocess as _subprocess


def _get_data_dir() -> str:
    """Returns local developer workspace directory (never used in production or for authoritative state)."""
    override = os.getenv("PQC_DATA_DIR", "").strip()
    if override and not override.startswith("/data"):
        os.makedirs(override, exist_ok=True)
        return override
    os.makedirs("data", exist_ok=True)
    return "data"


def export_workspace_json_backup(output_path: Optional[str] = None, *, user_id: Optional[str] = None) -> Dict[str, Any]:
    """Exports a non-authoritative JSON snapshot of database records for explicit backup/portability only."""
    snapshot = auth_store.get_active_auth_store().export_workspace_backup_snapshot(user_id=user_id)
    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(snapshot, fh, ensure_ascii=False, indent=2)
    return snapshot



_AUTH_SECRET_CACHE: Optional[bytes] = None
_AUTH_SECRET_CACHE_KEY: Optional[Tuple[str, ...]] = None
_ACTIVE_PKCE_VERIFIER: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("pqc_active_pkce_verifier", default=None)
_ACTIVE_OIDC_NONCE: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("pqc_active_oidc_nonce", default=None)
ACCOUNT_JAR_COOKIE_NAME = "pqc_account_jar"


def _current_secret_env_key() -> Tuple[str, ...]:
    return (
        os.getenv(auth_guard.ENV_AUTH_SECRET, ""),
        os.getenv(auth_guard.ENV_AUTH_SECRET_FILE, ""),
        os.getenv("K_SERVICE", ""),
        os.getenv(auth_guard.ENV_PRODUCTION_MODE, ""),
        os.getenv("PQC_ENV", ""),
        os.getenv("PQC_DATA_DIR", ""),
    )


def _get_auth_secret() -> bytes:
    """Returns the HMAC key for session tokens and account jar cookies.

    In production (Cloud Run / `PQC_PRODUCTION_MODE=true`), fails closed if `PQC_AUTH_SECRET` is missing or < 32 chars.
    """
    global _AUTH_SECRET_CACHE, _AUTH_SECRET_CACHE_KEY
    env_key = _current_secret_env_key()
    if _AUTH_SECRET_CACHE is not None and _AUTH_SECRET_CACHE_KEY == env_key:
        return _AUTH_SECRET_CACHE
    data_dir: Optional[str] = None
    if not auth_guard.is_production_environment():
        try:
            data_dir = _get_data_dir()
        except OSError:
            data_dir = None
    _AUTH_SECRET_CACHE = auth_guard.load_or_create_hmac_secret(data_dir)
    _AUTH_SECRET_CACHE_KEY = env_key
    return _AUTH_SECRET_CACHE


def revoke_tenant_session_token(token: Optional[str], *, reason: str = "logout") -> None:
    """Revokes a signed session token in the shared transactional database across all application instances."""
    if not token:
        return
    try:
        decoded = auth_guard.verify_signed_payload(token, _get_auth_secret(), expected_type=SESSION_TOKEN_TYPE)
    except Exception:
        decoded = None
    jti = str((decoded or {}).get("jti") or "") or None
    uid = normalize_user_id((decoded or {}).get("email") or (decoded or {}).get("uid")) if decoded else None
    exp_ts = float((decoded or {}).get("exp") or (time.time() + SESSION_TOKEN_TTL_SECONDS))
    auth_store.get_active_auth_store().revoke_session(
        jti=jti,
        raw_token=token,
        user_id=uid,
        expires_at=exp_ts,
        reason=reason,
    )


def is_tenant_session_token_revoked(decoded: Mapping[str, Any], raw_token: Optional[str] = None) -> bool:
    """Checks authoritative database state to determine whether a session token has been revoked or expired (fail-closed)."""
    jti = str(decoded.get("jti") or "") or None
    try:
        return auth_store.get_active_auth_store().is_session_revoked_or_expired(jti=jti, raw_token=raw_token)
    except Exception as exc:
        logger.error("Session revocation check failed closed due to persistence error: %s", exc)
        return True


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
    """Creates an HMAC-SHA256 signed session token with a unique `jti` and registers it in the distributed auth store."""
    now_ts = int(time.time())
    uid = normalize_user_id(user_profile["email"])
    jti = str(user_profile.get("jti") or secrets.token_urlsafe(24))
    exp_ts = int(user_profile.get("exp") or (now_ts + SESSION_TOKEN_TTL_SECONDS))
    region = str(user_profile.get("region") or "NorthAm")
    auth_method = str(user_profile.get("auth_method") or "google_workspace_signin")
    payload = {
        "uid": uid,
        "email": uid,
        "name": user_profile.get("name") or _format_display_name(user_profile["email"]),
        "picture": user_profile.get("picture") or "",
        "region": region,
        "auth_method": auth_method,
        "jti": jti,
        "typ": SESSION_TOKEN_TYPE,
        "iat": now_ts,
        "exp": exp_ts,
    }
    signed = auth_guard.sign_payload(payload, _get_auth_secret())
    auth_store.get_active_auth_store().register_session(
        jti=jti,
        raw_token=signed,
        user_id=uid,
        email=uid,
        region=region,
        auth_method=auth_method,
        issued_at=float(now_ts),
        expires_at=float(exp_ts),
    )
    return signed


def verify_tenant_session_token(token: Optional[str]) -> Optional[Dict[str, Any]]:
    """Verifies an HMAC-SHA256 signed session token (`typ` = session, unexpired, unrevoked in DB, allowed domain)."""
    decoded = auth_guard.verify_signed_payload(token, _get_auth_secret(), expected_type=SESSION_TOKEN_TYPE)
    if not decoded:
        return None
    if is_tenant_session_token_revoked(decoded, token):
        return None
    email = normalize_user_id(decoded.get("email") or decoded.get("uid"))
    ok, _ = is_allowed_corporate_email(email)
    if not ok:
        return None
    return decoded


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
    expected_nonce: Optional[str] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Verifies a Google OIDC ID token (cryptographic JWT verification) or a Google OAuth access token.

    Returns `({"email", "email_verified": True, ...}, None)` only for a VERIFIED email in `ALLOWED_AUTH_DOMAINS`.
    Enforces issuer, audience, cryptographic signature, expiration, and distributed single-use OIDC `nonce` binding.
    """
    active_nonce = expected_nonce if expected_nonce is not None else _ACTIVE_OIDC_NONCE.get()
    if id_token_jwt:
        tok = id_token_jwt.strip()
        audiences = _accepted_id_token_audiences()
        if tok.count(".") == 2 or auth_guard.is_production_environment():
            if tok.count(".") != 2:
                return None, "Malformed Google ID token JWT."
            info, sig_err = auth_guard.verify_google_oidc_id_token(
                tok,
                audiences=audiences,
                expected_nonce=active_nonce,
            )
            if info is None:
                return None, sig_err or "Google ID token verification failed."
        else:
            # Offline synthetic unit-test fallback (only when not in production and token is not a 3-segment JWT)
            try:
                url = f"https://oauth2.googleapis.com/tokeninfo?id_token={urllib.parse.quote(tok)}"
                req = urllib.request.Request(url, headers={"Accept": "application/json"})
                with egress_guard.safe_urlopen(
                    req,
                    timeout=8.0,
                    max_bytes=egress_guard.DEFAULT_MAX_RESPONSE_BYTES,
                    allowed_hosts=egress_guard.GOOGLE_OAUTH_ALLOWED_HOSTS,
                ) as resp:
                    info = json.loads(resp.read().decode("utf-8"))
            except Exception as exc:
                return None, f"Google ID token verification failed: {egress_guard.redact_sensitive_text(exc)}"
            if info.get("iss") not in ("accounts.google.com", "https://accounts.google.com"):
                return None, "Google ID token has an unexpected issuer."
            if audiences and info.get("aud") not in audiences:
                return None, "Google ID token was issued for a different OAuth client (audience mismatch)."
            if "exp" in info:
                try:
                    if int(info["exp"]) < int(time.time()):
                        return None, "Google ID token has expired."
                except (TypeError, ValueError):
                    return None, "Google ID token has an invalid exp claim."
            if active_nonce is not None:
                claim_nonce = str(info.get("nonce") or "")
                if not claim_nonce or not hmac.compare_digest(claim_nonce.encode("utf-8"), active_nonce.encode("utf-8")):
                    return None, "Google ID token nonce mismatch."

        nonce_to_consume = str(info.get("nonce") or active_nonce or "").strip()
        if nonce_to_consume:
            if not auth_store.get_active_auth_store().consume_replay_token(
                "oidc_nonce", nonce_to_consume, ttl_seconds=3600
            ):
                return None, "Google ID token nonce has already been used (replay rejected)."

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

    if google_access_token:
        tok = google_access_token.strip()
        if tok.lower().startswith("bearer "):
            tok = tok[7:].strip()
        try:
            url = f"https://oauth2.googleapis.com/tokeninfo?access_token={urllib.parse.quote(tok)}"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with egress_guard.safe_urlopen(
                req,
                timeout=8.0,
                max_bytes=egress_guard.DEFAULT_MAX_RESPONSE_BYTES,
                allowed_hosts=egress_guard.GOOGLE_OAUTH_ALLOWED_HOSTS,
            ) as resp:
                info = json.loads(resp.read().decode("utf-8"))
            if "expires_in" in info:
                try:
                    if int(info["expires_in"]) <= 0:
                        return None, "Google access token has expired."
                except (TypeError, ValueError):
                    pass
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
                    with egress_guard.safe_urlopen(
                        u_req,
                        timeout=3.0,
                        max_bytes=egress_guard.DEFAULT_MAX_RESPONSE_BYTES,
                        allowed_hosts=egress_guard.GOOGLE_OAUTH_ALLOWED_HOSTS,
                    ) as u_resp:
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
            return None, f"Google OAuth access token verification failed: {egress_guard.redact_sensitive_text(exc)}"

    return None, "No token provided."


def _try_workstation_auto_gcloud_token() -> Optional[str]:
    """On a local developer workstation only when explicitly opted in via `PQC_AUTO_WORKSTATION_GCLOUD_AUTH=true`."""
    if auth_guard.is_production_environment():
        return None
    if auth_guard.env_flag("PQC_AUTO_WORKSTATION_GCLOUD_AUTH") is not True:
        return None
    if "PYTEST_CURRENT_TEST" in os.environ and os.getenv("PQC_ENABLE_AUTO_GCLOUD_IN_TESTS") != "1":
        return None
    venv_py = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".venv", "bin", "python"))
    candidate_configs: List[Optional[str]] = [
        os.environ.get("CLOUDSDK_CONFIG"),
        os.path.expanduser("~/.config/gcloud"),
        os.path.expanduser("~/.config/gcloud-argolis"),
    ]
    seen_cfgs: set[str] = set()
    for cfg in candidate_configs:
        key = cfg or ""
        if key in seen_cfgs:
            continue
        seen_cfgs.add(key)
        try:
            env = os.environ.copy()
            if os.path.isfile(venv_py) and not env.get("CLOUDSDK_PYTHON"):
                env["CLOUDSDK_PYTHON"] = venv_py
            if cfg and os.path.isdir(cfg):
                env["CLOUDSDK_CONFIG"] = cfg
            out = _subprocess.check_output(
                ["gcloud", "auth", "print-access-token", "--quiet"],
                env=env,
                stderr=_subprocess.DEVNULL,
                text=True,
                timeout=4,
            )
            lines = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
            tok = lines[-1] if lines else ""
            if tok.startswith("ya29."):
                return tok
        except Exception:
            continue
    return None


def upsert_tenant_user_profile(
    email: str,
    name: Optional[str] = None,
    region: Optional[str] = None,
    timezone_str: Optional[str] = None,
    auth_method: str = "google_workspace_signin",
    picture: Optional[str] = None,
) -> Dict[str, Any]:
    """Atomically creates or updates an authoritative corporate tenant user profile in ``pqc_tenant_users``."""
    clean_email = normalize_user_id(email)
    store = auth_store.get_active_auth_store()
    existing = store.get_tenant_user(clean_email) or {}
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    resolved_region = infer_region_from_timezone(
        timezone_str=timezone_str or existing.get("timezone"),
        explicit_region=region or existing.get("region"),
    )
    resolved_name = _format_display_name(clean_email, name or existing.get("name"))
    resolved_picture = picture if (picture is not None and str(picture).strip()) else existing.get("picture", "")

    return store.upsert_tenant_user(
        user_id=clean_email,
        email=clean_email,
        name=resolved_name,
        region=resolved_region,
        timezone=timezone_str or existing.get("timezone") or "UTC",
        auth_method=auth_method or existing.get("auth_method") or "google_workspace_signin",
        picture=resolved_picture,
        created_at=existing.get("created_at") or now_iso,
        last_login_at=now_iso,
    )


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


def _request_origin(request: Request) -> str:
    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "http").split(",")[0].strip().lower()
    host = (request.headers.get("host") or request.url.netloc or "").strip().lower()
    return f"{proto}://{host}" if host else ""


def _enforce_csrf_and_origin(
    request: Request,
    identity: Optional[auth_guard.AuthenticatedIdentity],
    *,
    require_csrf_for_cookie: bool = True,
) -> None:
    """Enforces same-origin / allowed-CORS origin checks and session-bound CSRF token verification on state-changing requests."""
    if request.method.upper() not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    allowed = set(o.lower() for o in (auth_guard.allowed_cors_origins() or []))
    own_origin = _request_origin(request)
    if own_origin:
        allowed.add(own_origin)

    sec_fetch_site = (request.headers.get("sec-fetch-site") or "").strip().lower()
    origin_hdr = (request.headers.get("origin") or "").strip().rstrip("/").lower()
    referer_hdr = (request.headers.get("referer") or "").strip()

    if sec_fetch_site == "cross-site" and (not origin_hdr or origin_hdr not in allowed):
        raise HTTPException(status_code=403, detail=auth_guard.CSRF_REJECTED_DETAIL)
    if origin_hdr and allowed and origin_hdr not in allowed:
        raise HTTPException(status_code=403, detail=auth_guard.CSRF_REJECTED_DETAIL)
    if not origin_hdr and referer_hdr and allowed:
        parsed_ref = urllib.parse.urlparse(referer_hdr)
        if parsed_ref.scheme and parsed_ref.netloc:
            ref_origin = f"{parsed_ref.scheme.lower()}://{parsed_ref.netloc.lower()}"
            if ref_origin not in allowed:
                raise HTTPException(status_code=403, detail=auth_guard.CSRF_REJECTED_DETAIL)

    if require_csrf_for_cookie and identity is not None and identity.auth_transport == "cookie":
        csrf_hdr = request.headers.get(auth_guard.CSRF_HEADER_NAME)
        if not auth_guard.verify_csrf_token(csrf_hdr, identity.raw_token, _get_auth_secret()):
            raise HTTPException(status_code=403, detail=auth_guard.CSRF_REJECTED_DETAIL)


def resolve_authenticated_tenant_from_request(request: Request) -> Tuple[Optional[Dict[str, Any]], bool]:
    """Returns `(tenant_profile_or_None, iap_active)` for the request's authenticated identity (if any)."""
    identity = resolve_request_identity(request)
    if identity is None:
        return None, False
    store = auth_store.get_active_auth_store()
    if identity.source == "iap":
        existing = store.get_tenant_user(identity.user_id) or {}
        claims = identity.claims or {}
        req_region = request.headers.get("X-PQC-User-Region")
        req_tz = request.headers.get("X-PQC-User-Timezone")
        if (
            existing
            and existing.get("auth_method") == "cloud_iap"
            and (not req_region or req_region == existing.get("region"))
            and (not req_tz or req_tz == existing.get("timezone"))
        ):
            return existing, True
        profile = upsert_tenant_user_profile(
            email=identity.email,
            name=existing.get("name") or claims.get("name"),
            region=existing.get("region") or req_region,
            timezone_str=existing.get("timezone") or req_tz,
            auth_method="cloud_iap",
            picture=existing.get("picture") or claims.get("picture"),
        )
        return profile, True
    profile = store.get_tenant_user(identity.user_id)
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
    `user_id` parameter names somebody else or when CSRF/origin verification fails. `X-PQC-User-Id` is ignored.
    """
    identity = resolve_request_identity(request)
    uid = auth_guard.bind_user_id(identity, explicit_user_id, normalize_user_id=normalize_user_id)
    _enforce_csrf_and_origin(request, identity)
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


def load_oauth_client_config() -> Dict[str, Any]:
    """Loads the Google OAuth 2.0 Client configuration from Secret Manager env vars and ``pqc_oauth_client_configs``."""
    cfg: Dict[str, Any] = {
        "client_id": (os.getenv("PQC_GOOGLE_OAUTH_CLIENT_ID") or os.getenv("GOOGLE_OAUTH_CLIENT_ID") or "").strip(),
        "client_secret": (
            os.getenv("PQC_GOOGLE_OAUTH_CLIENT_SECRET") or os.getenv("GOOGLE_OAUTH_CLIENT_SECRET") or ""
        ).strip(),
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
        "scopes": list(GCP_OAUTH_SCOPES),
    }
    try:
        saved = auth_store.get_active_auth_store().get_oauth_client_config_record("global")
    except Exception:
        saved = None
    if isinstance(saved, dict):
        if saved.get("client_id"):
            cfg["client_id"] = str(saved["client_id"]).strip()
        enc_secret = saved.get("encrypted_client_secret")
        if enc_secret:
            decrypted = credential_service.get_active_credential_service().decrypt_config_secret(
                str(enc_secret), config_key="global"
            )
            if decrypted:
                cfg["client_secret"] = decrypted
    return cfg


def save_oauth_client_config(
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    *,
    updated_by: Optional[str] = None,
) -> Dict[str, Any]:
    """Persists Google OAuth 2.0 Client ID and envelope-encrypted Client Secret in ``pqc_oauth_client_configs``."""
    current = load_oauth_client_config()
    next_client_id = str(client_id).strip() if client_id is not None else current["client_id"]
    encrypted_secret: Optional[str] = None
    next_secret_present = bool(current["client_secret"])
    if client_secret is not None:
        clean_secret = str(client_secret).strip()
        next_secret_present = bool(clean_secret)
        encrypted_secret = (
            credential_service.get_active_credential_service().encrypt_config_secret(clean_secret, config_key="global")
            if clean_secret
            else ""
        )
    auth_store.get_active_auth_store().save_oauth_client_config_record(
        client_id=next_client_id,
        encrypted_client_secret=encrypted_secret,
        updated_by=updated_by,
        config_key="global",
    )
    return {
        "client_id": next_client_id,
        "has_client_secret": next_secret_present,
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


def _is_builtin_demo_scope(target_scope: Optional[str], conn: Optional[Dict[str, Any]] = None) -> bool:
    """Returns True when `target_scope` and `conn` target the built-in Argolis lab/demo environment
    (`31564119954` / `pqc-inventory-agent-cd06`), where Cloud Run ADC already holds full read-only permissions."""
    import re as _re

    raw = str(target_scope or "").strip()
    if _re.search(r"organizations/(?!31564119954\b)\d+", raw):
        return False
    if _re.search(r"projects/(?!pqc-inventory-agent-cd06\b)[a-z0-9-]+", raw):
        return False
    if conn and str(conn.get("organization_id") or "") not in ("", "31564119954"):
        return False
    if conn and str(conn.get("project_id") or "") not in ("", "pqc-inventory-agent-cd06"):
        return False
    if "31564119954" in raw or "pqc-inventory-agent-cd06" in raw or not raw:
        return True
    return True


class PqcOAuth3LOPlugin(BasePlugin):
    """ADK Plugin that integrates `ToolContext` 3-Legged OAuth (3LO) credentials with GCP discovery tools.

    Responsibilities:
    1. Synchronizes delegated OAuth 2.0 tokens between ADK's `ToolContext` (in-memory credential service)
       and the isolated per-user `gcloud_bridge` connection state.
    2. When a user is in 3-Legged OAuth mode (`mode == 'access_token'`) and has not yet granted a token,
       calls `tool_context.request_credential(auth_config)` before the tool executes and emits an interactive
       In-Chat OAuth 2.0 Consent Card (or auto-heals to `adc` when targeting the built-in demo org `31564119954`).
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

        # 2. If the user is in 3-Legged OAuth mode ('access_token') and no token is present:
        #    - For the built-in Argolis lab/demo org (31564119954 / pqc-inventory-agent-cd06), auto-heal to ADC
        #      so the Cloud Run Service Account executes immediately without blocking the demo.
        #    - For external organizations/projects, request 3LO OAuth consent.
        if conn.get("mode") == "access_token" and not conn.get("has_access_token"):
            if _is_builtin_demo_scope(target_scope, conn):
                set_gcp_connection_config(mode="adc", user_id=uid)
                return None
            agent_name = getattr(getattr(inv_ctx, "agent", None), "name", None)
            if not isinstance(agent_name, str) or agent_name in ("", "pqc_inventory_agent"):
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
            if _is_builtin_demo_scope(target_scope, conn):
                return None
            auth_config = build_gcp_oauth_auth_config(
                user_id=uid,
                session_id=inv_sess,
                target_scope=target_scope,
            )
            agent_name = getattr(getattr(inv_ctx, "agent", None), "name", None)
            if not isinstance(agent_name, str) or agent_name in ("", "pqc_inventory_agent"):
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
    access_token: Optional[str] = None
    use_token_for_gcp_connection: bool = False
    oauth_state: Optional[str] = None  # rejected if passed (legacy implicit flow disabled)


class ToolConsentPayload(BaseModel):
    user_id: Optional[str] = None  # optional; must equal the authenticated user when given
    session_id: Optional[str] = None
    access_token: str
    function_call_id: Optional[str] = None
    tool_name: Optional[str] = None
    target_scope: Optional[str] = None
    verify_with_google: bool = False
    oauth_state: Optional[str] = None  # rejected if passed (legacy implicit flow disabled)


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
    model_config = ConfigDict(extra="forbid")

    command: str
    user_id: Optional[str] = None


EMAIL_ONLY_SIGNIN_DISABLED_DETAIL = (
    "Email-only sign-in is disabled: a verified Google credential is required. Run `gcloud auth print-access-token` "
    "and paste the token in the sign-in dialog, or use 'Sign in with Google' when it is configured. "
    "(Email-only sign-in exists only for local development with PQC_ALLOW_UNVERIFIED_SIGNIN=true.)"
)
IMPLICIT_FLOW_DISABLED_DETAIL = (
    "OAuth 2.0 Implicit Flow and token-bearing redirects are prohibited. Use Authorization Code Flow with PKCE."
)
_SENSITIVE_STATE_KEY_MARKERS = ("credential", "token", "secret")


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


def _exchange_oauth_code(
    code: str,
    redirect_uri: str,
    code_verifier: Optional[str] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Exchanges an OAuth authorization code server-side with mandatory PKCE `code_verifier`.

    Supports both confidential clients (`client_secret` configured) and public clients (PKCE `code_verifier` without
    `client_secret`). Tokens never touch browser URLs or HTML.
    """
    oauth_cfg = load_oauth_client_config()
    client_id = (oauth_cfg.get("client_id") or "").strip()
    client_secret = (oauth_cfg.get("client_secret") or "").strip()
    effective_verifier = (code_verifier if code_verifier is not None else _ACTIVE_PKCE_VERIFIER.get()) or ""
    if not client_id:
        return None, "OAuth code exchange failed: OAuth client_id is not configured."
    if not effective_verifier:
        return None, "OAuth code exchange failed: missing server-side PKCE code_verifier."
    try:
        form_params: Dict[str, str] = {
            "code": code,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": effective_verifier,
        }
        if client_secret:
            form_params["client_secret"] = client_secret
        form_data = urllib.parse.urlencode(form_params).encode("utf-8")
        req = urllib.request.Request(
            oauth_cfg["token_endpoint"],
            data=form_data,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        )
        with egress_guard.safe_urlopen(
            req,
            timeout=10.0,
            max_bytes=egress_guard.DEFAULT_MAX_RESPONSE_BYTES,
            allowed_hosts=egress_guard.GOOGLE_OAUTH_ALLOWED_HOSTS,
        ) as resp:
            tok_data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        return None, f"OAuth code exchange failed: {egress_guard.redact_sensitive_text(exc)}"
    if not tok_data.get("access_token"):
        return None, "OAuth code exchange returned no access_token."
    return tok_data, None


def _bind_delegated_gcp_token(
    uid: str,
    access_token: str,
    expires_in: Optional[Any] = None,
    *,
    refresh_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Binds a delegated OAuth access/refresh token to ``uid`` via envelope-encrypted database storage."""
    try:
        ttl = float(expires_in) if expires_in else None
    except (TypeError, ValueError):
        ttl = None
    oauth_cfg = load_oauth_client_config()
    return set_gcp_connection_config(
        mode="access_token",
        access_token=access_token,
        user_id=uid,
        access_token_expires_in=ttl,
        refresh_token=refresh_token,
        oauth_client_id=oauth_cfg.get("client_id") or None,
        oauth_client_secret=oauth_cfg.get("client_secret") or None,
    )


_FORBIDDEN_POPUP_PAYLOAD_KEYS = frozenset({
    "token",
    "csrf_token",
    "access_token",
    "google_access_token",
    "id_token",
    "refresh_token",
    "credential",
    "code",
    "client_secret",
    "code_verifier",
})


def _sanitize_popup_postmessage_payload(payload: Mapping[str, Any]) -> Dict[str, Any]:
    """Strips all credentials, tokens, and secrets so popup `postMessage` communicates completion status only."""
    cleaned: Dict[str, Any] = {}
    for k, v in (payload or {}).items():
        if str(k).lower() in _FORBIDDEN_POPUP_PAYLOAD_KEYS:
            continue
        if isinstance(v, Mapping):
            cleaned[k] = _sanitize_popup_postmessage_payload(v)
        else:
            cleaned[k] = v
    return cleaned


def _oauth_popup_result_html(message_type: str, payload: Mapping[str, Any], message: str, ok: bool) -> str:
    """Small popup page that reports an OAuth completion status to the opener (same origin only, no credentials)."""
    color = "#81c995" if ok else "#f87171"
    close_js = "setTimeout(function () { window.close(); }, 400);" if ok else ""
    safe_payload = _sanitize_popup_postmessage_payload(payload)
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>PQC Workspace - Google authorization</title></head>
<body style="background:#0b0f17;color:#e2e8f0;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">
<div id="msg" style="color:{color};max-width:480px;text-align:center;line-height:1.5;">{html.escape(message)}</div>
<script>
(function () {{
  var payload = {_js_literal(safe_payload)};
  if (window.opener) {{
    window.opener.postMessage({{ type: {_js_literal(message_type)}, payload: payload }}, window.location.origin);
    {close_js}
  }}
}})();
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
    kms_client: Optional[Any] = None,
) -> FastAPI:
    """Creates the FastAPI server: the portal at `GET /`, `/api/*` (identity-bound), and ADK's native routes.

    Production fails closed unless PostgreSQL is configured and reachable. ADK-native REST routes and the ADK DevServer
    (`/dev-ui`, `/dev/apps/*`) are disabled on Cloud Run unless PQC_ENABLE_ADK_API / PQC_ENABLE_ADK_DEV_UI say otherwise.
    """
    resolved_db_url = auth_store.resolve_configured_database_url(session_db_url, async_driver=True)
    raw_bucket = (
        artifact_bucket
        if artifact_bucket is not None
        else os.getenv("PQC_ARTIFACT_BUCKET", os.getenv("PQC_EXPORT_GCS_BUCKET", DEFAULT_STAGING_BUCKET))
    )
    resolved_bucket = (raw_bucket or "").replace("gs://", "").strip("/")

    # Fail closed in production if HMAC secret is missing or weak before accepting traffic
    if auth_guard.is_production_environment():
        _get_auth_secret()

    instance_auth_store = auth_store.DistributedAuthStore(resolved_db_url)
    instance_credential_service = credential_service.EncryptedDatabaseCredentialService(
        store=instance_auth_store,
        kms_client=kms_client,
    )
    engine_kwargs = auth_store.build_async_engine_kwargs(resolved_db_url)
    session_service = ManagedSchemaDatabaseSessionService(db_url=resolved_db_url, **engine_kwargs)
    artifact_service = ResilientGcsArtifactService(bucket_name=resolved_bucket)
    registry_obj = model_registry or ModelRegistry()

    registry = get_service_registry()
    registry.register_session_service("sqlite", lambda uri, **kw: session_service)
    registry.register_session_service("sqlite+aiosqlite", lambda uri, **kw: session_service)
    registry.register_session_service("postgresql", lambda uri, **kw: session_service)
    registry.register_session_service("postgresql+asyncpg", lambda uri, **kw: session_service)
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
    # Guard every non-portal (ADK-native) route: 404 unless enabled, then identity-bound.
    app.add_middleware(
        auth_guard.AdkRouteGuardMiddleware,
        resolver=resolve_request_identity,
        api_enabled=adk_api_on,
        dev_ui_static=dev_ui_on,
        on_identity=_bind_tenant_context,
        normalize_user_id=normalize_user_id,
        allowed_origins=cors_origins,
    )

    @app.middleware("http")
    async def attach_pqc_security_headers(request: Request, call_next: Any):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    class _AuthStoreContextMiddleware:
        """Binds this FastAPI instance's independent `DistributedAuthStore` & `EncryptedDatabaseCredentialService`."""

        def __init__(
            self,
            inner_app: Any,
            *,
            store: auth_store.DistributedAuthStore,
            cred_svc: credential_service.EncryptedDatabaseCredentialService,
        ) -> None:
            self.app = inner_app
            self._store = store
            self._cred_svc = cred_svc

        async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
            if scope.get("type") not in ("http", "websocket"):
                await self.app(scope, receive, send)
                return
            store_tok = auth_store.set_active_auth_store(self._store)
            cred_tok = credential_service.set_active_credential_service(self._cred_svc)
            try:
                await self.app(scope, receive, send)
            finally:
                credential_service.reset_active_credential_service(cred_tok)
                auth_store.reset_active_auth_store(store_tok)

    app.add_middleware(_AuthStoreContextMiddleware, store=instance_auth_store, cred_svc=instance_credential_service)

    if auth_guard.allow_unverified_signin():
        logger.warning(
            "PQC_ALLOW_UNVERIFIED_SIGNIN=true: email-only sign-in is ENABLED (development only)%s.",
            " -- WARNING: this instance runs on Cloud Run" if auth_guard.running_on_cloud_run() else "",
        )

    app.state.adk_dev_ui_enabled = dev_ui_on
    app.state.adk_api_enabled = adk_api_on
    app.state.cors_allowed_origins = list(cors_origins or [])
    app.state.auth_store = instance_auth_store
    app.state.session_service = session_service
    app.state.artifact_service = artifact_service
    app.state.credential_service = instance_credential_service
    app.state.session_db_url = auth_store.redact_db_url(resolved_db_url)
    app.state.artifact_bucket = resolved_bucket
    app.state.model_registry = registry_obj

    if verify_models_on_startup is None:
        verify_models_on_startup = os.getenv("PQC_MODEL_VERIFICATION_ON_STARTUP", "true").strip().lower() == "true"
    if verify_models_on_startup:
        registry_obj.start_background_verification()

        def _warm_inventory_cache() -> None:
            try:
                from tools.gcp_inventory import (
                    DEFAULT_ORGANIZATION_ID,
                    collect_kms_inventory,
                    collect_workload_evidence,
                    compute_pqc_scorecard,
                    discover_all_crypto_assets,
                )
                from tools.pqc_detectors import collect_kms_import_jobs, collect_tls_policies

                default_scope = f"organizations/{DEFAULT_ORGANIZATION_ID}"
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
                    futs = [
                        pool.submit(collect_kms_inventory, default_scope),
                        pool.submit(collect_workload_evidence, default_scope),
                        pool.submit(collect_tls_policies, default_scope),
                        pool.submit(collect_kms_import_jobs, default_scope),
                        pool.submit(discover_all_crypto_assets, default_scope),
                    ]
                    concurrent.futures.wait(futs, timeout=45)
                compute_pqc_scorecard(default_scope)
                logger.info("Pre-warmed live GCP PQC inventory cache for %s.", default_scope)
            except Exception as exc:
                logger.debug("Background inventory cache warm-up skipped: %s", exc)

        threading.Thread(target=_warm_inventory_cache, name="pqc-inventory-warmup", daemon=True).start()

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
                credential_service=instance_credential_service,
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
        if auth_guard.is_production_environment():
            return True
        return (request.headers.get("x-forwarded-proto") or request.url.scheme).split(",")[0].strip() == "https"

    def _load_account_jar(request: Request) -> Dict[str, str]:
        """Returns `{email: session_jti}` from the signed HttpOnly account jar cookie (contains no bearer tokens)."""
        raw = request.cookies.get(ACCOUNT_JAR_COOKIE_NAME)
        if not raw:
            return {}
        decoded = auth_guard.verify_signed_payload(raw, _get_auth_secret(), expected_type="account_jar_v2")
        if not decoded or not isinstance(decoded.get("accounts"), dict):
            return {}
        return {normalize_user_id(k): str(v) for k, v in decoded["accounts"].items() if k and v}

    def _save_account_jar(resp: Any, request: Request, jar: Dict[str, str]) -> None:
        now_ts = int(time.time())
        clean_jar = {normalize_user_id(k): str(v) for idx, (k, v) in enumerate(jar.items()) if k and v and idx < 5}
        signed_jar = auth_guard.sign_payload(
            {"typ": "account_jar_v2", "accounts": clean_jar, "iat": now_ts, "exp": now_ts + SESSION_TOKEN_TTL_SECONDS},
            _get_auth_secret(),
        )
        resp.set_cookie(
            key=ACCOUNT_JAR_COOKIE_NAME,
            value=signed_jar,
            max_age=SESSION_TOKEN_TTL_SECONDS,
            httponly=True,
            samesite="lax",
            secure=_is_https(request),
            path="/api/auth",
        )

    def _set_session_cookie(resp: Any, request: Request, token: str, *, rotate_previous: bool = True) -> None:
        decoded = verify_tenant_session_token(token)
        if rotate_previous:
            prev_cookie = request.cookies.get(SESSION_COOKIE_NAME)
            if prev_cookie and prev_cookie != token:
                prev_decoded = verify_tenant_session_token(prev_cookie)
                # Revoke unauthenticated/invalid pre-planted cookies or explicit rotation requests;
                # preserve valid sessions of other accounts in the multi-account switcher jar.
                if prev_decoded is None or request.headers.get("X-PQC-Rotate-Session") == "1":
                    revoke_tenant_session_token(prev_cookie, reason="session_rotation")
        sec = _is_https(request)
        resp.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=token,
            max_age=SESSION_TOKEN_TTL_SECONDS,
            httponly=True,
            samesite="lax",
            secure=sec,
            path="/",
        )
        csrf_token = auth_guard.derive_csrf_token(token, _get_auth_secret())
        resp.set_cookie(
            key=auth_guard.CSRF_COOKIE_NAME,
            value=csrf_token,
            max_age=SESSION_TOKEN_TTL_SECONDS,
            httponly=False,
            samesite="lax",
            secure=sec,
            path="/",
        )
        if decoded and decoded.get("email") and decoded.get("jti"):
            jar = _load_account_jar(request)
            jar[normalize_user_id(decoded["email"])] = str(decoded["jti"])
            _save_account_jar(resp, request, jar)

    def _set_oauth_nonce_cookie(resp: Any, request: Request, binding_token: str) -> None:
        # Binds the server-side OAuth transaction to this browser via SHA-256 hash comparison.
        resp.set_cookie(
            key=OAUTH_NONCE_COOKIE_NAME,
            value=binding_token,
            max_age=_oauth_ttl_seconds(),
            httponly=True,
            samesite="lax",
            secure=_is_https(request),
            path="/api/auth",
        )

    def _allowed_oauth_redirect_uris() -> Tuple[str, ...]:
        raw = (os.getenv("PQC_OAUTH_REDIRECT_URIS") or "").strip()
        if not raw:
            return ()
        uris: List[str] = []
        for item in raw.split(","):
            cleaned = item.strip()
            if cleaned and "*" not in cleaned and cleaned.startswith(("https://", "http://")):
                if auth_guard.is_production_environment() and not cleaned.startswith("https://"):
                    continue
                if cleaned not in uris:
                    uris.append(cleaned)
        return tuple(uris)

    def _oauth_callback_uri(request: Request) -> str:
        proto = (request.headers.get("x-forwarded-proto") or request.url.scheme).split(",")[0].strip().lower()
        if auth_guard.is_production_environment():
            proto = "https"
        host = (request.headers.get("host") or request.url.netloc).strip()
        return f"{proto}://{host}/api/auth/oauth/callback"

    def _validate_oauth_redirect_uri(request: Request, explicit_redirect_uri: Optional[str]) -> str:
        cb_uri = _oauth_callback_uri(request)
        allowlist = _allowed_oauth_redirect_uris()
        if allowlist and cb_uri not in allowlist:
            raise HTTPException(status_code=400, detail="Callback redirect_uri is not in PQC_OAUTH_REDIRECT_URIS allowlist.")
        if explicit_redirect_uri and explicit_redirect_uri.strip() != cb_uri:
            raise HTTPException(status_code=400, detail="Redirect URI mismatch: open redirects are not permitted.")
        if auth_guard.is_production_environment() and not cb_uri.startswith("https://"):
            raise HTTPException(status_code=400, detail="HTTPS redirect_uri is required in production.")
        return cb_uri

    def _oauth_ttl_seconds() -> int:
        try:
            return max(
                auth_store.MIN_OAUTH_TRANSACTION_TTL_SECONDS,
                min(
                    int(os.getenv("PQC_OAUTH_STATE_TTL_SECONDS", str(OAUTH_STATE_TTL_SECONDS))),
                    auth_store.MAX_OAUTH_TRANSACTION_TTL_SECONDS,
                ),
            )
        except ValueError:
            return OAUTH_STATE_TTL_SECONDS

    def _allowed_popup_origins(request: Request) -> List[str]:
        origins: List[str] = []
        own = _request_origin(request)
        if own:
            origins.append(own)
        for item in auth_guard.allowed_cors_origins() or []:
            if item.lower() not in origins:
                origins.append(item.lower())
        for item in (os.getenv("PQC_BRIDGE_ALLOWED_ORIGINS") or "").split(","):
            clean = item.strip().rstrip("/").lower()
            if clean and "*" not in clean and clean.startswith(("https://", "http://")) and clean not in origins:
                origins.append(clean)
        return origins

    def _require_identity(request: Request, explicit_user_id: Optional[str] = None) -> auth_guard.AuthenticatedIdentity:
        """401 without an authenticated identity, 403 if `explicit_user_id` names someone else or CSRF fails."""
        identity = resolve_request_identity(request)
        auth_guard.bind_user_id(identity, explicit_user_id, normalize_user_id=normalize_user_id)
        assert identity is not None
        _enforce_csrf_and_origin(request, identity)
        set_current_tenant_user(identity.user_id)
        return identity

    def _auth_config_payload() -> Dict[str, Any]:
        oauth_cfg = load_oauth_client_config()
        client_id = oauth_cfg.get("client_id", "")
        gis_js_enabled = auth_guard.env_flag("PQC_ENABLE_GIS_JAVASCRIPT_CLIENT") is True
        return {
            "allow_unverified_signin": auth_guard.allow_unverified_signin(),
            "google_oauth_client_configured": bool(client_id),
            "google_oauth_client_id": client_id if gis_js_enabled else "",
            "gis_javascript_origin_enabled": bool(client_id and gis_js_enabled),
            "oauth_signin_url": "/api/auth/oauth/signin" if client_id else None,
            "oauth_flow": "authorization_code_pkce_s256",
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
        """Creates/updates the tenant profile, mints an HttpOnly session token, and returns token-free JSON."""
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
        csrf_token = auth_guard.derive_csrf_token(signed_token, _get_auth_secret())
        sess_resp = await session_service.list_sessions(app_name=APP_NAME, user_id=uid)
        content = {
            "authenticated": True,
            "user": profile,
            "user_id": uid,
            "csrf_token": csrf_token,
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
        db_healthy = True
        try:
            with instance_auth_store._session_factory() as db_probe:
                db_probe.execute(auth_store.text("SELECT 1"))
        except Exception:
            db_healthy = False
        identity = resolve_request_identity(request)
        catalog = registry_obj.catalog()
        oauth_cfg = load_oauth_client_config()
        return {
            "status": "HEALTHY" if db_healthy else "DEGRADED",
            "database_healthy": db_healthy,
            "app_name": APP_NAME,
            "multi_tenant_enabled": True,
            "oauth_3lo_enabled": True,
            "google_oauth_client_configured": bool(oauth_cfg.get("client_id")),
            "allow_unverified_signin": auth_guard.allow_unverified_signin(),
            "authenticated": identity is not None,
            "supported_regions": [r["id"] for r in SUPPORTED_REGIONS],
            "allowed_auth_domains": list(ALLOWED_AUTH_DOMAINS),
            "session_service": type(session_service).__name__,
            "session_db_url": auth_store.redact_db_url(resolved_db_url),
            "artifact_service": type(artifact_service).__name__,
            "artifact_bucket": f"gs://{resolved_bucket}",
            "credential_service": type(instance_credential_service).__name__,
            "connection": get_gcp_connection_config(mask_token=True, user_id=identity.user_id) if (identity and db_healthy) else None,
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
    async def auth_me(request: Request) -> JSONResponse:
        identity = resolve_request_identity(request)
        profile, iap_active = resolve_authenticated_tenant_from_request(request)
        uid = profile["user_id"] if profile else None
        conn: Optional[Dict[str, Any]] = None
        session_count = 0
        csrf_token: Optional[str] = None
        if uid and profile:
            set_current_tenant_user(uid)
            if identity and identity.raw_token:
                csrf_token = auth_guard.derive_csrf_token(identity.raw_token, _get_auth_secret())
            conn = get_gcp_connection_config(mask_token=True, user_id=uid)
            if conn.get("mode") == "access_token" and not conn.get("has_access_token") and _is_builtin_demo_scope(None, conn):
                conn = set_gcp_connection_config(mode="adc", user_id=uid)
            try:
                sess_resp = await session_service.list_sessions(app_name=APP_NAME, user_id=uid)
                session_count = len(sess_resp.sessions)
            except Exception:
                session_count = 0
        cfg = _auth_config_payload()
        resp = JSONResponse(
            content={
                "authenticated": profile is not None,
                "iap_active": iap_active,
                "google_oauth_client_id": cfg["google_oauth_client_id"],
                "google_oauth_client_configured": cfg["google_oauth_client_configured"],
                "gis_javascript_origin_enabled": cfg["gis_javascript_origin_enabled"],
                "allow_unverified_signin": cfg["allow_unverified_signin"],
                "oauth_3lo_enabled": True,
                "oauth_scopes": list(GCP_OAUTH_SCOPES),
                "allowed_domains": list(ALLOWED_AUTH_DOMAINS),
                "supported_regions": SUPPORTED_REGIONS,
                "user": profile,
                "user_id": uid,
                "csrf_token": csrf_token,
                "session_count": session_count,
                "connection": conn,
            }
        )
        if csrf_token and identity and identity.source == "session_token":
            resp.set_cookie(
                key=auth_guard.CSRF_COOKIE_NAME,
                value=csrf_token,
                max_age=SESSION_TOKEN_TTL_SECONDS,
                httponly=False,
                samesite="lax",
                secure=_is_https(request),
                path="/",
            )
        return resp

    @app.post("/api/auth/google")
    async def auth_google_signin(request: Request, payload: GoogleAuthSignInPayload) -> JSONResponse:
        """Signs a user in from a VERIFIED Google credential and sets an HttpOnly, Secure 30-day session cookie.

        No reusable session token is ever returned in the JSON response body.
        """
        if payload.oauth_state is not None:
            raise HTTPException(status_code=400, detail=IMPLICIT_FLOW_DISABLED_DETAIL)
        id_jwt = (payload.credential or payload.id_token or "").strip() or None
        access_tok = (payload.google_access_token or payload.access_token or "").strip() or None
        if access_tok and access_tok.lower().startswith("bearer "):
            access_tok = access_tok[7:].strip() or None
        expires_in: Optional[Any] = None
        existing_identity = resolve_request_identity(request)
        _enforce_csrf_and_origin(
            request,
            existing_identity,
            require_csrf_for_cookie=bool(existing_identity is not None and not id_jwt and not access_tok),
        )
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
        elif existing_identity is not None:
            requested_email = (payload.email or "").strip()
            if requested_email:
                ok, norm_req = is_allowed_corporate_email(requested_email)
                if not ok:
                    raise HTTPException(status_code=403, detail=norm_req)
                if norm_req != existing_identity.email and not auth_guard.allow_unverified_signin():
                    raise HTTPException(
                        status_code=403,
                        detail=f"Authenticated as {existing_identity.email}; use Switch Account to sign in as {norm_req}.",
                    )
            target_email = existing_identity.email
            existing_prof = auth_store.get_active_auth_store().get_tenant_user(existing_identity.user_id) or {}
            display_name = payload.name or existing_prof.get("name") or (existing_identity.claims or {}).get("name")
            auth_method = "cloud_iap" if existing_identity.source == "iap" else (existing_prof.get("auth_method") or "google_workspace_signin")
            picture = existing_prof.get("picture") or (existing_identity.claims or {}).get("picture")
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
        _set_session_cookie(resp, request, signed_token, rotate_previous=True)
        return resp

    @app.post("/api/auth/logout")
    async def auth_logout(request: Request) -> JSONResponse:
        identity = resolve_request_identity(request)
        _enforce_csrf_and_origin(request, identity)
        cookie_tok = request.cookies.get(SESSION_COOKIE_NAME)
        if cookie_tok:
            revoke_tenant_session_token(cookie_tok, reason="logout")
        if identity is not None:
            if identity.raw_token and identity.source == "session_token":
                revoke_tenant_session_token(identity.raw_token, reason="logout")
            if identity.claims and identity.claims.get("jti"):
                auth_store.get_active_auth_store().revoke_session(
                    jti=str(identity.claims["jti"]), user_id=identity.user_id, reason="logout"
                )
            clear_user_access_token(identity.user_id)
        sec = _is_https(request)
        resp = JSONResponse(content={"authenticated": False, "status": "logged_out"})
        resp.delete_cookie(key=SESSION_COOKIE_NAME, path="/", secure=sec, httponly=True, samesite="lax")
        resp.delete_cookie(key=auth_guard.CSRF_COOKIE_NAME, path="/", secure=sec, httponly=False, samesite="lax")
        if identity is not None:
            jar = _load_account_jar(request)
            jar_jti = jar.pop(identity.user_id, None)
            if jar_jti:
                auth_store.get_active_auth_store().revoke_session(
                    jti=jar_jti, user_id=identity.user_id, reason="logout_jar"
                )
            _save_account_jar(resp, request, jar)
        return resp

    @app.post("/api/auth/auto")
    async def auth_auto_signin(request: Request) -> JSONResponse:
        """Automatic zero-typing sign-in: restores an existing verified session/IAP identity without invalidating
        concurrent browser tabs, or verifies active `gcloud` workstation identity when explicitly opted in.
        """
        identity = resolve_request_identity(request)
        _enforce_csrf_and_origin(request, identity, require_csrf_for_cookie=False)
        profile, iap_active = resolve_authenticated_tenant_from_request(request)
        if profile is not None:
            uid = profile["user_id"]
            set_current_tenant_user(uid)
            if identity and identity.source == "session_token" and identity.raw_token:
                signed_token = identity.raw_token
                reused_existing = True
            else:
                signed_token = sign_tenant_session_token(profile)
                reused_existing = False
            csrf_token = auth_guard.derive_csrf_token(signed_token, _get_auth_secret())
            conn = get_gcp_connection_config(mask_token=True, user_id=uid)
            if conn.get("mode") == "access_token" and not conn.get("has_access_token") and _is_builtin_demo_scope(None, conn):
                conn = set_gcp_connection_config(mode="adc", user_id=uid)
            sess_resp = await session_service.list_sessions(app_name=APP_NAME, user_id=uid)
            resp = JSONResponse(
                content={
                    "authenticated": True,
                    "iap_active": iap_active,
                    "user": profile,
                    "user_id": uid,
                    "csrf_token": csrf_token,
                    "session_count": len(sess_resp.sessions),
                    "connection": conn,
                    "supported_regions": SUPPORTED_REGIONS,
                }
            )
            _set_session_cookie(resp, request, signed_token, rotate_previous=not reused_existing)
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
                _set_session_cookie(resp, request, signed_token, rotate_previous=True)
                return resp

        return JSONResponse(status_code=200, content={"authenticated": False})

    @app.post("/api/auth/switch")
    async def auth_switch_account(request: Request) -> JSONResponse:
        """Switches the active browser session between verified Google accounts stored in the HttpOnly Account Jar."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        if (body or {}).get("token"):
            raise HTTPException(
                status_code=400,
                detail="Session bearer tokens are prohibited in JSON payloads; account switching uses HttpOnly cookies.",
            )
        identity = resolve_request_identity(request)
        _enforce_csrf_and_origin(
            request,
            identity,
            require_csrf_for_cookie=bool(identity is not None and identity.auth_transport == "cookie"),
        )
        raw_email_req = str((body or {}).get("email") or "").strip()
        target_email_req = normalize_user_id(raw_email_req) if raw_email_req else ""
        store = auth_store.get_active_auth_store()
        decoded: Optional[Dict[str, Any]] = None
        if target_email_req:
            jar = _load_account_jar(request)
            candidate_jti = jar.get(target_email_req, "")
            if candidate_jti:
                decoded = store.get_active_session_by_jti(candidate_jti, expected_user_id=target_email_req)
        if not decoded:
            if identity and identity.source == "iap" and (not target_email_req or target_email_req == identity.email):
                existing = store.get_tenant_user(identity.user_id) or {}
                decoded = {
                    "email": identity.email,
                    "user_id": identity.user_id,
                    "region": existing.get("region"),
                    "auth_method": "cloud_iap",
                }
            elif identity and (not target_email_req or target_email_req == identity.email):
                decoded = dict(identity.claims or {"email": identity.email, "uid": identity.user_id})
            else:
                raise HTTPException(status_code=401, detail="Saved account session has expired or been revoked. Please sign in again.")

        email = normalize_user_id(decoded.get("email") or decoded.get("user_id") or decoded.get("uid"))
        existing_prof = store.get_tenant_user(email) or {}
        profile = upsert_tenant_user_profile(
            email=email,
            name=existing_prof.get("name") or decoded.get("name"),
            region=(body or {}).get("region") or existing_prof.get("region") or decoded.get("region"),
            timezone_str=(body or {}).get("timezone") or request.headers.get("X-PQC-User-Timezone"),
            auth_method=decoded.get("auth_method") or existing_prof.get("auth_method") or "google_workspace_signin",
            picture=existing_prof.get("picture") or decoded.get("picture"),
        )
        uid = profile["user_id"]
        set_current_tenant_user(uid)
        fresh_token = sign_tenant_session_token(profile)
        csrf_token = auth_guard.derive_csrf_token(fresh_token, _get_auth_secret())
        sess_resp = await session_service.list_sessions(app_name=APP_NAME, user_id=uid)
        content = {
            "authenticated": True,
            "user": profile,
            "user_id": uid,
            "csrf_token": csrf_token,
            "session_count": len(sess_resp.sessions),
            "connection": get_gcp_connection_config(mask_token=True, user_id=uid),
            "supported_regions": SUPPORTED_REGIONS,
        }
        resp = JSONResponse(content=content)
        _set_session_cookie(resp, request, fresh_token, rotate_previous=False)
        return resp

    @app.get("/api/auth/tenants")
    async def list_registered_tenants(request: Request) -> Dict[str, Any]:
        """Tenant directory: aggregate counts for signed-in users; individual profiles only for admins."""
        identity = _require_identity(request)
        tenants = auth_store.get_active_auth_store().list_tenant_users()
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
        return save_oauth_client_config(
            client_id=payload.client_id,
            client_secret=payload.client_secret,
            updated_by=identity.user_id,
        )

    @app.get("/api/auth/bridge", response_class=HTMLResponse)
    async def oauth_google_bridge_endpoint(
        request: Request,
        origin: Optional[str] = Query(default=None),
        target_origin: Optional[str] = Query(default=None),
    ) -> HTMLResponse:
        """Public Verified Google Identity Bridge popup for allowlisted origins only (Authorization Code + PKCE)."""
        allowed_origins = _allowed_popup_origins(request)
        raw_origin = (origin or target_origin or "").strip().rstrip("/").lower()
        if raw_origin:
            if raw_origin not in allowed_origins:
                return HTMLResponse(
                    status_code=400,
                    content="<!DOCTYPE html><html><body>Untrusted popup origin.</body></html>",
                )
            resolved_origin = raw_origin
        else:
            resolved_origin = _request_origin(request)
        oauth_cfg = load_oauth_client_config()
        gis_js_enabled = auth_guard.env_flag("PQC_ENABLE_GIS_JAVASCRIPT_CLIENT") is True
        client_id = oauth_cfg.get("client_id", "") if gis_js_enabled else ""
        bridge_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Sign in with Google — Google Cloud Security Consulting</title>
<style>
  body {{ margin:0; font-family:'Google Sans','Inter',system-ui,sans-serif; background:#0b0f17; color:#e2e8f0; display:flex; align-items:center; justify-content:center; min-height:100vh; padding:16px; box-sizing:border-box; }}
  .card {{ width:100%; max-width:420px; background:#111827; border:1px solid #1e293b; border-radius:16px; padding:28px 24px; box-shadow:0 24px 60px rgba(0,0,0,0.65); text-align:center; }}
  .badge {{ display:inline-block; font-size:11px; font-weight:600; color:#8ab4f8; background:rgba(66,133,244,0.14); border:1px solid rgba(66,133,244,0.35); padding:3px 10px; border-radius:999px; margin-bottom:12px; }}
  h2 {{ margin:0 0 8px 0; font-size:18px; color:#f8fafc; }}
  p {{ margin:0 0 18px 0; font-size:13px; color:#94a3b8; line-height:1.5; }}
  .slot {{ display:flex; justify-content:center; min-height:44px; margin-bottom:12px; }}
  .btn {{ width:100%; padding:11px 14px; border-radius:999px; border:1px solid #334155; background:#1e293b; color:#f8fafc; font-weight:600; font-size:13px; cursor:pointer; display:inline-flex; align-items:center; justify-content:center; gap:8px; }}
  .btn:hover {{ background:#334155; }}
  .err {{ color:#f87171; font-size:12px; margin-top:12px; display:none; }}
</style>
<script src="https://accounts.google.com/gsi/client" async defer></script>
</head>
<body>
<div class="card">
  <span class="badge">Google Cloud OIDC • Authorization Code + PKCE</span>
  <h2>Sign in with Google</h2>
  <p>Select your verified <b>@google.com</b> or <b>@jsaccomani.altostrat.com</b> account to continue.</p>
  <div id="gisSlot" class="slot"></div>
  <button type="button" class="btn" onclick="startPkceFlow()">Continue with Google OAuth 2.0 (PKCE)</button>
  <div id="errBox" class="err"></div>
</div>
<script>
const TARGET_ORIGIN = {_js_literal(resolved_origin)};
const CLIENT_ID = {_js_literal(client_id)};
async function completeServerSignIn(authPayload) {{
  try {{
    const res = await fetch('/api/auth/google', {{
      method: 'POST',
      credentials: 'same-origin',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify(authPayload)
    }});
    const data = await res.json().catch(() => ({{}}));
    if (!res.ok || !data.authenticated) {{
      showErr((data && data.detail) || ('Sign-in failed (HTTP ' + res.status + ').'));
      return;
    }}
    if (window.opener && TARGET_ORIGIN) {{
      window.opener.postMessage(
        {{ type: 'PQC_SIGNIN_COMPLETE', payload: {{ authenticated: true, status: 'OK', user_id: data.user_id }} }},
        TARGET_ORIGIN
      );
      setTimeout(() => window.close(), 150);
    }}
  }} catch (e) {{
    showErr('Sign-in error: ' + e);
  }}
}}
function showErr(m) {{
  const el = document.getElementById('errBox');
  el.textContent = m;
  el.style.display = 'block';
}}
function startPkceFlow() {{
  window.location.href = '/api/auth/oauth/signin';
}}
window.addEventListener('load', () => {{
  const iv = setInterval(() => {{
    if (window.google && window.google.accounts && window.google.accounts.id && CLIENT_ID) {{
      clearInterval(iv);
      window.google.accounts.id.initialize({{
        client_id: CLIENT_ID,
        callback: (resp) => {{
          if (resp && resp.credential) {{
            completeServerSignIn({{ credential: resp.credential }});
          }}
        }},
        auto_select: true,
        cancel_on_tap_outside: false
      }});
      const slot = document.getElementById('gisSlot');
      if (slot) {{
        window.google.accounts.id.renderButton(slot, {{
          theme: 'filled_blue',
          size: 'large',
          shape: 'pill',
          text: 'continue_with',
          width: 340
        }});
      }}
    }}
  }}, 100);
}});
</script>
</body>
</html>"""
        return HTMLResponse(content=bridge_html)

    @app.get("/api/auth/oauth/signin")
    async def oauth_signin_start_endpoint(
        request: Request,
        region: Optional[str] = Query(default=None),
        timezone: Optional[str] = Query(default=None),
        redirect_uri: Optional[str] = Query(default=None),
        response_type: Optional[str] = Query(default=None),
    ) -> Any:
        """Public: starts 'Sign in with Google' via OAuth 2.0 Authorization Code Flow + PKCE (S256)."""
        if response_type is not None and response_type.strip().lower() != "code":
            raise HTTPException(status_code=400, detail=IMPLICIT_FLOW_DISABLED_DETAIL)
        cb_uri = _validate_oauth_redirect_uri(request, redirect_uri)
        oauth_cfg = load_oauth_client_config()
        client_id = (oauth_cfg.get("client_id") or "").strip()
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
        has_secret = bool((oauth_cfg.get("client_secret") or "").strip())
        existing_identity = resolve_request_identity(request)
        tx = auth_store.get_active_auth_store().create_oauth_transaction(
            flow_mode="signin",
            redirect_uri=cb_uri,
            client_type="confidential" if has_secret else "public",
            initiating_user_id=existing_identity.user_id if existing_identity else None,
            initiating_session_jti=str((existing_identity.claims or {}).get("jti") or "") or None if existing_identity else None,
            region=region or "",
            timezone=timezone or "",
            ttl_seconds=_oauth_ttl_seconds(),
        )
        assert tx.browser_binding_token is not None
        code_challenge = auth_guard.compute_pkce_challenge(tx.code_verifier)
        params = {
            "client_id": client_id,
            "redirect_uri": cb_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": tx.state_id,
            "nonce": tx.oidc_nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "prompt": "select_account",
        }
        resp = RedirectResponse(url=f"{oauth_cfg['authorization_endpoint']}?{urllib.parse.urlencode(params)}", status_code=302)
        _set_oauth_nonce_cookie(resp, request, tx.browser_binding_token)
        return resp

    @app.get("/api/auth/oauth/authorize")
    async def oauth_3lo_authorize_endpoint(
        request: Request,
        user_id: Optional[str] = Query(default=None),
        session_id: Optional[str] = Query(default=None),
        scope: Optional[str] = Query(default="organizations/31564119954"),
        redirect_uri: Optional[str] = Query(default=None),
        response_type: Optional[str] = Query(default=None),
        format: Optional[str] = Query(default=None),
    ) -> Any:
        """Initiates 3-Legged OAuth 2.0 (3LO) via Authorization Code Flow + PKCE (S256) for the signed-in user.

        - Never falls back to `response_type=token` (supports both public and confidential OAuth clients via PKCE).
        - Stores `code_verifier` and `oidc_nonce` server-side in `pqc_oauth_transactions`; `state` is opaque & random.
        """
        identity = _require_identity(request, explicit_user_id=user_id)
        uid = identity.user_id
        if response_type is not None and response_type.strip().lower() != "code":
            raise HTTPException(status_code=400, detail=IMPLICIT_FLOW_DISABLED_DETAIL)
        cb_uri = _validate_oauth_redirect_uri(request, redirect_uri)
        oauth_cfg = load_oauth_client_config()
        client_id = (oauth_cfg.get("client_id") or "").strip()
        has_secret = bool((oauth_cfg.get("client_secret") or "").strip())
        target_scope = scope or "organizations/31564119954"
        tx = auth_store.get_active_auth_store().create_oauth_transaction(
            flow_mode="3lo",
            redirect_uri=cb_uri,
            client_type="confidential" if has_secret else "public",
            initiating_user_id=uid,
            initiating_session_jti=str((identity.claims or {}).get("jti") or "") or None,
            app_session_id=session_id or None,
            target_scope=target_scope,
            ttl_seconds=_oauth_ttl_seconds(),
        )
        assert tx.browser_binding_token is not None
        code_challenge = auth_guard.compute_pkce_challenge(tx.code_verifier)

        google_auth_url = ""
        if client_id:
            params: Dict[str, str] = {
                "client_id": client_id,
                "redirect_uri": cb_uri,
                "response_type": "code",
                "scope": " ".join(GCP_OAUTH_SCOPES),
                "include_granted_scopes": "true",
                "access_type": "online",
                "prompt": "consent",
                "state": tx.state_id,
                "nonce": tx.oidc_nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
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
                    "client_type": tx.client_type,
                    "redirect_uri": cb_uri,
                    "scopes": list(GCP_OAUTH_SCOPES),
                    "google_auth_url": google_auth_url,
                    "state": tx.state_id,
                    "response_type": "code",
                    "code_challenge_method": "S256",
                }
            )
            _set_oauth_nonce_cookie(json_resp, request, tx.browser_binding_token)
            return json_resp

        if google_auth_url and request.query_params.get("direct") == "1":
            redirect_resp = RedirectResponse(url=google_auth_url, status_code=302)
            _set_oauth_nonce_cookie(redirect_resp, request, tx.browser_binding_token)
            return redirect_resp

        google_button_html = ""
        if google_auth_url:
            google_button_html = (
                '<button type="button" class="btn btn-google" onclick="startServerPkceAuthorize()">'
                "Authorize with Google Account (OAuth 2.0 + PKCE)"
                "</button>"
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
      <span class="badge">3-Legged OAuth 2.0 (PKCE S256) • ADK ToolContext</span>
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
  <button type="button" class="btn btn-sec" onclick="switchToAdcMode()">Use Cloud Run Service Account (ADC) Instead</button>
  <div style="font-size:12px;color:#cbd5e1;margin:10px 0 6px 0;font-weight:600;">Or paste your Google Cloud OAuth Token:</div>
  <div class="cmd">gcloud auth print-access-token</div>
  <input id="tokInput" type="password" placeholder="Paste ya29... OAuth 2.0 access token" autofocus />
  <button type="button" class="btn btn-google" onclick="submitConsent()">Allow &amp; Inject into ADK ToolContext</button>
  <details style="margin-top:10px;font-size:11.5px;color:#94a3b8;">
    <summary style="cursor:pointer;color:#8ab4f8;">Configure Google OAuth 2.0 Web Client ID (administrators)</summary>
    <div style="margin-top:8px;">
      <input id="cidInput" type="text" placeholder="123456-abc.apps.googleusercontent.com" value="{html.escape(client_id, quote=True)}" />
      <button type="button" class="btn btn-sec" onclick="saveClientId()">Save OAuth Client ID</button>
    </div>
  </details>
</div>
<script>
const PQC_SESSION_ID = {_js_literal(session_id or "")};
const PQC_TARGET_SCOPE = {_js_literal(target_scope)};
const PQC_GOOGLE_AUTH_URL = {_js_literal(google_auth_url)};
function getCookie(name) {{
  const match = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/([.$?*|{{}}()\\[\\]\\\\/+^])/g, '\\\\$1') + '=([^;]*)'));
  return match ? decodeURIComponent(match[1]) : '';
}}
function pqcAuthHeaders() {{
  const headers = {{ 'Content-Type': 'application/json' }};
  const csrfToken = getCookie('pqc_csrf_token');
  if (csrfToken) headers['X-PQC-CSRF-Token'] = csrfToken;
  return headers;
}}
function sanitizePopupData(raw) {{
  const copy = Object.assign({{}}, raw || {{}});
  delete copy.token;
  delete copy.csrf_token;
  delete copy.access_token;
  delete copy.id_token;
  delete copy.refresh_token;
  delete copy.credential;
  return copy;
}}
function showError(message) {{
  const err = document.getElementById('errBox');
  err.textContent = message;
  err.style.display = 'block';
}}
function startServerPkceAuthorize() {{
  if (PQC_GOOGLE_AUTH_URL) {{
    window.location.href = PQC_GOOGLE_AUTH_URL;
  }}
}}
async function switchToAdcMode() {{
  document.getElementById('errBox').style.display = 'none';
  try {{
    const res = await fetch('/api/connection', {{
      method: 'POST',
      credentials: 'same-origin',
      headers: pqcAuthHeaders(),
      body: JSON.stringify({{ mode: 'adc' }})
    }});
    const conn = await res.json();
    if (!res.ok) throw new Error(conn.detail || 'Failed to switch to ADC.');
    if (window.opener) {{
      window.opener.postMessage({{ type: 'PQC_OAUTH_3LO_AUTHORIZED', payload: {{ status: 'AUTHORIZED', connection: sanitizePopupData(conn) }} }}, window.location.origin);
      window.close();
    }} else {{
      window.location.href = '/';
    }}
  }} catch (e) {{
    showError(e.message);
  }}
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
      window.opener.postMessage({{ type: 'PQC_OAUTH_3LO_AUTHORIZED', payload: sanitizePopupData(data) }}, window.location.origin);
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
  window.location.reload();
}}
</script>
</body>
</html>"""
        popup_resp = HTMLResponse(content=popup_html)
        _set_oauth_nonce_cookie(popup_resp, request, tx.browser_binding_token)
        return popup_resp

    @app.get("/api/auth/oauth/callback", response_class=HTMLResponse)
    async def oauth_3lo_callback_endpoint(
        request: Request,
        code: Optional[str] = Query(default=None),
        state: Optional[str] = Query(default=None),
        error: Optional[str] = Query(default=None),
        redirect_uri: Optional[str] = Query(default=None),
    ) -> HTMLResponse:
        """Public OAuth 2.0 Authorization Code + PKCE callback target for 'Sign in with Google' and 3LO consent.

        - Rejects implicit / token-bearing redirects (`access_token`, `id_token`, `token_type`, or missing `code`).
        - Atomically validates and consumes the opaque `state` in the shared database (single-use, race-free).
        - Exchanges the authorization code server-side using the server-stored PKCE `code_verifier`.
        """
        store = auth_store.get_active_auth_store()
        hinted_mode = store.peek_oauth_transaction_mode(state)
        message_type = "PQC_SIGNIN_COMPLETE" if hinted_mode == "signin" else "PQC_OAUTH_3LO_AUTHORIZED"
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
        # Reject any implicit-flow / token-bearing redirect parameters or missing authorization code
        if any(
            request.query_params.get(k) is not None
            for k in ("access_token", "id_token", "token_type", "response_type")
        ) or not code:
            return HTMLResponse(
                status_code=400,
                content=_oauth_popup_result_html(
                    message_type,
                    {"authenticated": False, "status": "IMPLICIT_FLOW_PROHIBITED"},
                    IMPLICIT_FLOW_DISABLED_DETAIL,
                    ok=False,
                ),
            )

        try:
            expected_cb_uri = _validate_oauth_redirect_uri(request, redirect_uri)
        except HTTPException as exc:
            return HTMLResponse(
                status_code=exc.status_code,
                content=_oauth_popup_result_html(
                    message_type,
                    {"authenticated": False, "status": "REDIRECT_URI_MISMATCH"},
                    str(exc.detail),
                    ok=False,
                ),
            )

        tx = store.consume_oauth_transaction(
            state_id=state,
            browser_binding_token=request.cookies.get(OAUTH_NONCE_COOKIE_NAME),
            expected_redirect_uri=expected_cb_uri,
        )
        if tx is None:
            return HTMLResponse(
                status_code=400,
                content=_oauth_popup_result_html(
                    message_type,
                    {"authenticated": False, "status": "INVALID_STATE"},
                    "Invalid, expired, or already consumed OAuth state. Close this window and start again from the portal.",
                    ok=False,
                ),
            )
        message_type = "PQC_SIGNIN_COMPLETE" if tx.flow_mode == "signin" else "PQC_OAUTH_3LO_AUTHORIZED"

        if not store.consume_replay_token("auth_code", code, ttl_seconds=OAUTH_STATE_TTL_SECONDS):
            return HTMLResponse(
                status_code=400,
                content=_oauth_popup_result_html(
                    message_type,
                    {"authenticated": False, "status": "REPLAYED_CODE"},
                    "Authorization code replay rejected.",
                    ok=False,
                ),
            )

        if tx.flow_mode == "3lo":
            uid = normalize_user_id(tx.initiating_user_id)
            identity = resolve_request_identity(request)
            if "@" not in uid or identity is None or identity.user_id != uid:
                return HTMLResponse(
                    status_code=403,
                    content=_oauth_popup_result_html(
                        message_type, {"authenticated": False, "status": "USER_MISMATCH"}, auth_guard.USER_MISMATCH_DETAIL, ok=False
                    ),
                )

        pkce_ctx = _ACTIVE_PKCE_VERIFIER.set(tx.code_verifier)
        try:
            tok_data, exchange_err = await asyncio.to_thread(_exchange_oauth_code, code, expected_cb_uri)
        finally:
            _ACTIVE_PKCE_VERIFIER.reset(pkce_ctx)
        if not tok_data:
            return HTMLResponse(
                status_code=502,
                content=_oauth_popup_result_html(
                    message_type, {"authenticated": False, "status": "EXCHANGE_FAILED"}, exchange_err or "OAuth error.", ok=False
                ),
            )

        sec = _is_https(request)
        if tx.flow_mode == "signin":
            id_tok = tok_data.get("id_token")
            if not id_tok:
                return HTMLResponse(
                    status_code=401,
                    content=_oauth_popup_result_html(
                        message_type,
                        {"authenticated": False, "status": "MISSING_ID_TOKEN"},
                        "OpenID Connect id_token is required for authorization code sign-in.",
                        ok=False,
                    ),
                )
            nonce_ctx = _ACTIVE_OIDC_NONCE.set(tx.oidc_nonce)
            try:
                verified_info, err_msg = await asyncio.to_thread(_verify_google_oauth_or_id_token, id_tok, None)
            finally:
                _ACTIVE_OIDC_NONCE.reset(nonce_ctx)
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
                region=tx.region or None,
                timezone_str=tx.timezone or None,
                auth_method=verified_info.get("auth_method", "google_id_token"),
                picture=verified_info.get("picture", ""),
            )
            signin_resp = HTMLResponse(
                content=_oauth_popup_result_html(message_type, content, "Signed in. You can close this window.", ok=True)
            )
            _set_session_cookie(signin_resp, request, signed_token, rotate_previous=True)
            signin_resp.delete_cookie(key=OAUTH_NONCE_COOKIE_NAME, path="/api/auth", secure=sec, httponly=True, samesite="lax")
            return signin_resp

        uid = normalize_user_id(tx.initiating_user_id)
        if tok_data.get("id_token"):
            nonce_ctx = _ACTIVE_OIDC_NONCE.set(tx.oidc_nonce)
            try:
                verified_3lo, err_3lo = await asyncio.to_thread(_verify_google_oauth_or_id_token, tok_data["id_token"], None)
            finally:
                _ACTIVE_OIDC_NONCE.reset(nonce_ctx)
            st_3lo, email_or_err_3lo = _validated_google_identity(verified_3lo, err_3lo)
            if st_3lo != 200 or verified_3lo is None:
                return HTMLResponse(
                    status_code=st_3lo,
                    content=_oauth_popup_result_html(
                        message_type,
                        {"authenticated": False, "status": "REJECTED", "detail": email_or_err_3lo},
                        email_or_err_3lo,
                        ok=False,
                    ),
                )
            if normalize_user_id(email_or_err_3lo) != uid:
                return HTMLResponse(
                    status_code=403,
                    content=_oauth_popup_result_html(
                        message_type,
                        {"authenticated": False, "status": "USER_MISMATCH"},
                        auth_guard.USER_MISMATCH_DETAIL,
                        ok=False,
                    ),
                )
        elif tx.oidc_nonce:
            if not store.consume_replay_token("oidc_nonce", tx.oidc_nonce, ttl_seconds=3600):
                return HTMLResponse(
                    status_code=400,
                    content=_oauth_popup_result_html(
                        message_type,
                        {"authenticated": False, "status": "REPLAYED_NONCE"},
                        "OIDC nonce replay rejected.",
                        ok=False,
                    ),
                )

        conn = _bind_delegated_gcp_token(
            uid,
            tok_data["access_token"],
            tok_data.get("expires_in"),
            refresh_token=tok_data.get("refresh_token"),
        )
        result_payload = {
            "status": "AUTHORIZED",
            "authenticated": True,
            "user_id": uid,
            "session_id": tx.app_session_id or None,
            "target_scope": tx.target_scope,
            "credential_key": GCP_OAUTH_CREDENTIAL_KEY,
            "token_storage": "encrypted_db_envelope",
            "connection": conn,
        }
        consent_resp = HTMLResponse(
            content=_oauth_popup_result_html(message_type, result_payload, "Authorized. You can close this window.", ok=True)
        )
        consent_resp.delete_cookie(key=OAUTH_NONCE_COOKIE_NAME, path="/api/auth", secure=sec, httponly=True, samesite="lax")
        return consent_resp

    @app.post("/api/auth/tool-consent")
    async def grant_tool_oauth_consent_endpoint(
        request: Request,
        payload: ToolConsentPayload,
    ) -> Dict[str, Any]:
        """Binds a delegated OAuth 2.0 access token to the SIGNED-IN user's gcloud/GCP connection so the paused ADK
        tool can resume on their behalf.
        """
        uid = activate_request_tenant_user(request, explicit_user_id=payload.user_id)
        if payload.oauth_state is not None:
            raise HTTPException(status_code=400, detail=IMPLICIT_FLOW_DISABLED_DETAIL)
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
            "token_storage": "encrypted_db_envelope",
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
        meta_map = auth_store.get_active_auth_store().list_user_session_metadata(resolved_uid)
        items: List[Dict[str, Any]] = []
        for s in resp.sessions:
            extra = meta_map.get(s.id, {})
            state_dict = dict(getattr(s, "state", {}) or {})
            cached_title = extra.get("title") or state_dict.get("title")
            if cached_title and "message_count" in extra:
                title = cached_title
                msg_count = int(extra.get("message_count") or 0)
            else:
                full_sess = await session_service.get_session(app_name=APP_NAME, user_id=s.user_id, session_id=s.id)
                msgs, _ = _extract_messages_and_traces_from_session(full_sess or s, extra)
                title = (
                    cached_title
                    or next((m["content"][:72] for m in msgs if m.get("role") == "user" and m.get("content")), None)
                    or "PQC Readiness Assessment"
                )
                msg_count = len(msgs)
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
                    "message_count": msg_count,
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
        try:
            auth_store.get_active_auth_store().upsert_session_metadata(
                session_id=session.id,
                user_id=user_id,
                title=title,
                scope=scope,
                message_count=0,
                attachments_by_turn=[],
                turn_telemetry={},
                created_at=now_iso,
                updated_at=now_iso,
            )
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
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
        extra = auth_store.get_active_auth_store().get_session_metadata(session_id, user_id=resolved_user) or {}
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
        auth_store.get_active_auth_store().delete_session_metadata(session_id, user_id=resolved_user)
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
            effective_mode = connection_mode
            if (
                effective_mode
                and normalize_connection_mode(effective_mode) == "access_token"
                and not (access_token or "").strip()
            ):
                current_conn = get_gcp_connection_config(mask_token=True, user_id=user_id)
                if not current_conn.get("has_access_token") and _is_builtin_demo_scope(scope, current_conn):
                    effective_mode = "adc"
            try:
                set_gcp_connection_config(
                    mode=effective_mode,
                    impersonated_service_account=impersonated_sa,
                    access_token=access_token,
                    user_id=user_id,
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            except PermissionError as exc:
                raise HTTPException(status_code=403, detail=str(exc)) from exc

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
        inv_tel = (
            {
                "served_by": served_by,
                "model_id": entry["id"],
                "model_label": model_label,
                "status": status,
                "error": error,
                "oauth_consent_required": active_consent_card,
            }
            if invocation_id
            else None
        )
        auth_store.get_active_auth_store().upsert_session_metadata(
            session_id=session_id,
            user_id=user_id,
            title=user_text[:72],
            scope=scope,
            model_id=entry["id"],
            model_label=model_label,
            message_delta=2 if assistant_text else 1,
            append_attachments=saved_artifacts_meta,
            invocation_id=invocation_id,
            invocation_telemetry=inv_tel,
            updated_at=now_iso,
        )

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
        try:
            return set_gcp_connection_config(
                mode=payload.mode,
                organization_id=payload.organization_id,
                project_id=payload.project_id,
                location=payload.location,
                impersonated_service_account=payload.impersonated_service_account,
                access_token=payload.access_token,
                user_id=uid,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

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
