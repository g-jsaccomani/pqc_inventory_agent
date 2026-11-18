"""Unified transactional SQLAlchemy persistence for Phase 1 (OAuth/Sessions) and Phase 2 (Metadata/Credentials).

Eliminates process-local Python dictionaries, SQLite-on-GCS-FUSE, and authoritative local JSON files:
- ``pqc_schema_metadata``: schema revision metadata complementing ``alembic_version``.
- ``pqc_oauth_transactions``: server-side PKCE ``code_verifier``, OIDC ``nonce``, browser binding hash, initiating
  session/user ownership, strict expiration, and single-query atomic ``UPDATE ... WHERE consumed_at IS NULL``
  consumption (race-free under concurrent callbacks and across multiple Cloud Run instances).
- ``pqc_consumed_nonces``: primary-key-enforced single-use ledger for OIDC ``nonce`` claims and authorization codes.
- ``pqc_auth_sessions``: server-side session registry (keyed by ``jti`` and ``token_sha256``) supporting atomic
  cross-instance session revocation, fail-closed allowlist validation, and multi-account jar validation across restarts.
- ``pqc_tenant_users``: authoritative corporate user profiles with tenant domain isolation.
- ``pqc_session_metadata``: authoritative conversation metadata with strict foreign-key user ownership.
- ``pqc_user_connections``: per-user non-secret GCP connection settings (ADC / SA Impersonation / 3LO mode).
- ``pqc_oauth_client_configs``: administrator-managed OAuth 2.0 client configuration (with envelope-encrypted secret).
- ``pqc_calibration_events``: longitudinal Mosca calibration ledger scoped by organization/project and tenant.
- ``pqc_delegated_credentials``: KMS envelope-encrypted delegated OAuth credentials bound via AES-256-GCM AAD.

Production fails closed unless Cloud SQL / PostgreSQL (``postgresql+psycopg://`` and ``postgresql+asyncpg://``) is
configured and reachable. SQLite is permitted exclusively for explicitly configured local development and unit tests,
and is unconditionally rejected on ``/data`` (Cloud Storage FUSE) in all environments.
"""

from __future__ import annotations

import contextvars
import dataclasses
import datetime
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from typing import Any, Dict, List, Mapping, Optional
import uuid

from sqlalchemy import (
    Engine,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    delete,
    inspect as sa_inspect,
    or_,
    select,
    text,
    update,
)
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from pqc_agent import auth_guard

logger = logging.getLogger(__name__)

CURRENT_SCHEMA_VERSION = "20261117_0002"
EXPECTED_ALEMBIC_REVISION = CURRENT_SCHEMA_VERSION
MIN_OAUTH_TRANSACTION_TTL_SECONDS = 1
MAX_OAUTH_TRANSACTION_TTL_SECONDS = 600
REQUIRED_ADK_V1_TABLES: frozenset[str] = frozenset(
    {
        "adk_internal_metadata",
        "app_states",
        "user_states",
        "sessions",
        "events",
    }
)


def extract_tenant_domain(user_id_or_email: Optional[str]) -> str:
    """Extracts the normalized corporate tenant domain from a user identifier or email."""
    clean = str(user_id_or_email or "").strip().lower()
    if clean.startswith("accounts.google.com:"):
        clean = clean.split(":", 1)[1].strip()
    if "@" in clean:
        domain = clean.rsplit("@", 1)[1].strip()
        if domain:
            return domain
    return (os.getenv("GCP_ORGANIZATION_NAME") or "local.internal").strip().lower()


class PqcPersistenceBase(DeclarativeBase):
    """Shared SQLAlchemy 2.0 declarative base for all PQC Portal transactional tables."""


class SchemaVersionRecord(PqcPersistenceBase):
    """Tracks application schema version metadata alongside Alembic revisions."""

    __tablename__ = "pqc_schema_metadata"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)


class OAuthTransactionRecord(PqcPersistenceBase):
    """Temporary server-side OAuth 2.0 + PKCE transaction keyed by an opaque random ``state_id``."""

    __tablename__ = "pqc_oauth_transactions"

    state_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    flow_mode: Mapped[str] = mapped_column(String(32), nullable=False)  # "signin" | "3lo"
    client_type: Mapped[str] = mapped_column(String(32), nullable=False, default="public")  # "public" | "confidential"
    code_verifier: Mapped[str] = mapped_column(String(256), nullable=False)
    oidc_nonce: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    browser_binding_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    initiating_user_id: Mapped[Optional[str]] = mapped_column(String(320), nullable=True, index=True)
    initiating_session_jti: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    app_session_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    target_scope: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    redirect_uri: Mapped[str] = mapped_column(String(1024), nullable=False)
    region: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    timezone: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[float] = mapped_column(Float, nullable=False)
    expires_at: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    consumed_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)


class ConsumedNonceRecord(PqcPersistenceBase):
    """Single-use replay-prevention record for OIDC ID-token nonces and authorization codes."""

    __tablename__ = "pqc_consumed_nonces"

    nonce_key: Mapped[str] = mapped_column(String(160), primary_key=True)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[float] = mapped_column(Float, nullable=False)
    expires_at: Mapped[float] = mapped_column(Float, nullable=False, index=True)


class AuthSessionRecord(PqcPersistenceBase):
    """Authoritative server-side session lifecycle and revocation record shared across instances."""

    __tablename__ = "pqc_auth_sessions"

    jti: Mapped[str] = mapped_column(String(128), primary_key=True)
    token_sha256: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    user_id: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    region: Mapped[str] = mapped_column(String(64), nullable=False, default="NorthAm")
    auth_method: Mapped[str] = mapped_column(String(64), nullable=False, default="google_workspace_signin")
    issued_at: Mapped[float] = mapped_column(Float, nullable=False)
    expires_at: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    revoked_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    revocation_reason: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    __table_args__ = (
        Index("ix_pqc_auth_sessions_user_active", "user_id", "revoked_at", "expires_at"),
    )


class TenantUserRecord(PqcPersistenceBase):
    """Authoritative user profile record with tenant domain isolation (replaces pqc_tenant_users.json)."""

    __tablename__ = "pqc_tenant_users"

    user_id: Mapped[str] = mapped_column(String(320), primary_key=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    tenant_domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    region: Mapped[str] = mapped_column(String(64), nullable=False, default="NorthAm")
    timezone: Mapped[str] = mapped_column(String(128), nullable=False, default="UTC")
    auth_method: Mapped[str] = mapped_column(String(64), nullable=False, default="google_workspace_signin")
    picture: Mapped[str] = mapped_column(String(2048), nullable=False, default="")
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    last_login_at: Mapped[str] = mapped_column(String(64), nullable=False, index=True)


class SessionMetadataRecord(PqcPersistenceBase):
    """Authoritative session metadata record enforcing FK user ownership (replaces pqc_session_metadata.json)."""

    __tablename__ = "pqc_session_metadata"

    session_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(320),
        ForeignKey("pqc_tenant_users.user_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tenant_domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    scope: Mapped[str] = mapped_column(String(512), nullable=False)
    model_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    model_label: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    message_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    attachments_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    turn_telemetry_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    fallback_messages_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    __table_args__ = (
        Index("ix_pqc_session_meta_owner_updated", "user_id", "updated_at"),
    )


class UserConnectionRecord(PqcPersistenceBase):
    """Per-user non-secret GCP connection settings (replaces pqc_user_connections.json)."""

    __tablename__ = "pqc_user_connections"

    user_id: Mapped[str] = mapped_column(String(320), primary_key=True)
    tenant_domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="adc")
    organization_id: Mapped[str] = mapped_column(String(128), nullable=False)
    project_id: Mapped[str] = mapped_column(String(255), nullable=False)
    location: Mapped[str] = mapped_column(String(128), nullable=False, default="all")
    impersonated_service_account: Mapped[str] = mapped_column(String(320), nullable=False, default="")
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)


class OAuthClientConfigRecord(PqcPersistenceBase):
    """Administrator-managed OAuth 2.0 client configuration (replaces pqc_oauth_config.json)."""

    __tablename__ = "pqc_oauth_client_configs"

    config_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    encrypted_client_secret: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(320), nullable=True)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)


class CalibrationEventRecord(PqcPersistenceBase):
    """Transactional Mosca calibration history record (replaces /data/calibration-history.jsonl)."""

    __tablename__ = "pqc_calibration_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_uuid: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    scope: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    tenant_domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    industry_sector: Mapped[str] = mapped_column(String(64), nullable=False)
    sector_label: Mapped[str] = mapped_column(String(255), nullable=False)
    confidentiality_years_x: Mapped[float] = mapped_column(Float, nullable=False)
    migration_years_y: Mapped[float] = mapped_column(Float, nullable=False)
    crqc_horizon_years_z: Mapped[float] = mapped_column(Float, nullable=False)
    gateway_header_limit_kb: Mapped[int] = mapped_column(Integer, nullable=False)
    entry_json: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp_utc: Mapped[str] = mapped_column(String(64), nullable=False, index=True)


class DelegatedCredentialRecord(PqcPersistenceBase):
    """Envelope-encrypted delegated GCP OAuth credentials bound to owner + tenant via AES-256-GCM AAD."""

    __tablename__ = "pqc_delegated_credentials"

    credential_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    app_name: Mapped[str] = mapped_column(String(128), nullable=False)
    tenant_domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    credential_key: Mapped[str] = mapped_column(String(128), nullable=False)
    kek_provider: Mapped[str] = mapped_column(String(32), nullable=False)
    kms_key_name: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    wrapped_dek_b64: Mapped[str] = mapped_column(Text, nullable=False)
    payload_nonce_b64: Mapped[str] = mapped_column(String(64), nullable=False)
    ciphertext_b64: Mapped[str] = mapped_column(Text, nullable=False)
    aad_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    has_refresh_token: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    issued_at: Mapped[float] = mapped_column(Float, nullable=False)
    expires_at: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    revoked_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    revocation_reason: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "app_name",
            "tenant_domain",
            "user_id",
            "credential_key",
            name="uq_pqc_delegated_cred_owner",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<DelegatedCredentialRecord(user_id={self.user_id!r}, tenant={self.tenant_domain!r}, "
            f"key={self.credential_key!r}, provider={self.kek_provider!r}, revoked={self.revoked_at is not None})>"
        )


@dataclasses.dataclass(frozen=True)
class OAuthTransactionData:
    """Immutable view of a server-side OAuth transaction."""

    state_id: str
    flow_mode: str
    client_type: str
    code_verifier: str
    oidc_nonce: str
    browser_binding_token: Optional[str]
    browser_binding_hash: str
    initiating_user_id: Optional[str]
    initiating_session_jti: Optional[str]
    app_session_id: Optional[str]
    target_scope: Optional[str]
    redirect_uri: str
    region: str
    timezone: str
    created_at: float
    expires_at: float
    consumed_at: Optional[float] = None


def sha256_hex(value: str) -> str:
    clean = str(value or "").strip()
    if clean.lower().startswith("bearer "):
        clean = clean[7:].strip()
    return hashlib.sha256(clean.encode("utf-8")).hexdigest()


def _read_secret_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def build_cloud_sql_url_from_env(*, async_driver: bool = False) -> Optional[str]:
    """Builds a PostgreSQL SQLAlchemy URL from discrete Cloud SQL / TCP environment variables if configured.

    Supported environment variables:
      - ``PQC_CLOUD_SQL_CONNECTION_NAME`` (``project:region:instance`` for ``/cloudsql/...`` Unix socket)
      - ``PQC_DB_HOST`` / ``PQC_DB_PORT`` (TCP host/port, e.g. Private IP ``10.x.x.x:5432``)
      - ``PQC_DB_NAME`` (default ``pqc_workspace``)
      - ``PQC_DB_USER`` (default ``pqc_app``)
      - ``PQC_DB_PASSWORD`` or ``PQC_DB_PASSWORD_FILE`` (Secret Manager secret)
      - ``PQC_DB_UNIX_SOCKET_DIR`` (default ``/cloudsql``)
    """
    conn_name = (os.getenv("PQC_CLOUD_SQL_CONNECTION_NAME") or "").strip()
    db_host = (os.getenv("PQC_DB_HOST") or "").strip()
    if not conn_name and not db_host:
        return None

    db_name = (os.getenv("PQC_DB_NAME") or "pqc_workspace").strip()
    db_user = (os.getenv("PQC_DB_USER") or "pqc_app").strip()
    db_pass = (os.getenv("PQC_DB_PASSWORD") or "").strip()
    if not db_pass:
        pass_file = (os.getenv("PQC_DB_PASSWORD_FILE") or "").strip()
        if pass_file:
            db_pass = _read_secret_file(pass_file)

    driver = "postgresql+asyncpg" if async_driver else "postgresql+psycopg"
    if conn_name:
        socket_root = (os.getenv("PQC_DB_UNIX_SOCKET_DIR") or "/cloudsql").strip().rstrip("/")
        socket_dir = f"{socket_root}/{conn_name}"
        url_obj = URL.create(
            drivername=driver,
            username=db_user or None,
            password=db_pass or None,
            database=db_name,
            query={"host": socket_dir},
        )
        return url_obj.render_as_string(hide_password=False)

    port_raw = (os.getenv("PQC_DB_PORT") or "5432").strip()
    try:
        db_port: Optional[int] = int(port_raw)
    except ValueError:
        db_port = 5432
    sslmode = (os.getenv("PQC_DB_SSLMODE") or "").strip()
    query: Dict[str, str] = {}
    if sslmode and not async_driver:
        query["sslmode"] = sslmode
    elif sslmode and async_driver and sslmode in ("require", "verify-ca", "verify-full"):
        query["ssl"] = sslmode
    url_obj = URL.create(
        drivername=driver,
        username=db_user or None,
        password=db_pass or None,
        host=db_host,
        port=db_port,
        database=db_name,
        query=query,
    )
    return url_obj.render_as_string(hide_password=False)


def normalize_async_db_url(raw_url: str) -> str:
    """Normalizes a database URL for ADK ``DatabaseSessionService`` (``postgresql+asyncpg://`` or ``sqlite+aiosqlite://``)."""
    url = (raw_url or "").strip()
    if url.startswith("postgres://"):
        url = "postgresql+asyncpg://" + url[len("postgres://") :]
    elif url.startswith("postgresql://"):
        url = "postgresql+asyncpg://" + url[len("postgresql://") :]
    elif url.startswith("postgresql+psycopg://"):
        url = "postgresql+asyncpg://" + url[len("postgresql+psycopg://") :]
    elif url.startswith("postgresql+psycopg2://"):
        url = "postgresql+asyncpg://" + url[len("postgresql+psycopg2://") :]
    elif url.startswith("sqlite://") and not url.startswith("sqlite+aiosqlite://"):
        url = "sqlite+aiosqlite://" + url[len("sqlite://") :]

    if url.startswith("sqlite+aiosqlite:///"):
        raw_path = url[len("sqlite+aiosqlite:///") :]
        if raw_path and raw_path != ":memory:":
            parent_dir = os.path.dirname(raw_path) if raw_path.startswith("/") else os.path.dirname(os.path.abspath(raw_path))
            if parent_dir:
                try:
                    os.makedirs(parent_dir, exist_ok=True)
                except OSError:
                    pass
    return url


def normalize_sync_db_url(raw_url: str) -> str:
    """Normalizes a database URL for synchronous transactional SQLAlchemy operations (``postgresql+psycopg://`` or ``sqlite://``)."""
    url = (raw_url or "").strip()
    if url.startswith("postgres://"):
        url = "postgresql+psycopg://" + url[len("postgres://") :]
    elif url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://") :]
    elif url.startswith("postgresql+asyncpg://"):
        url = "postgresql+psycopg://" + url[len("postgresql+asyncpg://") :]
    elif url.startswith("postgresql+psycopg2://"):
        url = "postgresql+psycopg://" + url[len("postgresql+psycopg2://") :]
    elif url.startswith("sqlite+aiosqlite://"):
        url = "sqlite://" + url[len("sqlite+aiosqlite://") :]

    if url.startswith("sqlite:///"):
        raw_path = url[len("sqlite:///") :]
        if raw_path and raw_path != ":memory:":
            parent_dir = os.path.dirname(raw_path) if raw_path.startswith("/") else os.path.dirname(os.path.abspath(raw_path))
            if parent_dir:
                try:
                    os.makedirs(parent_dir, exist_ok=True)
                except OSError:
                    pass
    return url


def redact_db_url(raw_url: Optional[str]) -> str:
    """Redacts credentials from a SQLAlchemy database URL before exposing in health output or logs."""
    if not raw_url:
        return ""
    try:
        parsed = make_url(raw_url)
        return parsed.render_as_string(hide_password=True)
    except Exception:
        if "@" in raw_url and "://" in raw_url:
            scheme, rest = raw_url.split("://", 1)
            _, host_part = rest.rsplit("@", 1)
            return f"{scheme}://***@{host_part}"
        return raw_url


def _is_gcs_fuse_sqlite_path(raw_url: str) -> bool:
    """Detects SQLite URLs targeting ``/data`` or legacy ``sqlite:///data/pqc_sessions.db`` (Cloud Storage FUSE)."""
    clean = (raw_url or "").strip()
    if not clean.lower().startswith("sqlite"):
        return False
    try:
        db_path = make_url(normalize_sync_db_url(clean)).database or ""
    except Exception:
        db_path = clean
    norm_path = db_path.strip().replace("\\", "/")
    return (
        norm_path == "/data"
        or norm_path.startswith("/data/")
        or norm_path == "data/pqc_sessions.db"
        or norm_path.endswith("/data/pqc_sessions.db")
    )


def validate_production_postgres_only(raw_url: str) -> None:
    """Enforces PostgreSQL-only persistence in production and prohibits GCS FUSE SQLite paths everywhere."""
    clean = (raw_url or "").strip()
    if not clean:
        raise RuntimeError(
            "Production persistence failure: PostgreSQL database URL is not configured "
            "(set DATABASE_URL, SESSION_DB_URL, or PQC_CLOUD_SQL_CONNECTION_NAME + PQC_DB_PASSWORD)."
        )
    if _is_gcs_fuse_sqlite_path(clean):
        raise RuntimeError(
            f"Persistence security failure: SQLite database on Cloud Storage FUSE path ({redact_db_url(clean)}) is prohibited."
        )
    if auth_guard.is_production_environment():
        try:
            backend = make_url(normalize_sync_db_url(clean)).get_backend_name()
        except Exception as exc:
            raise RuntimeError(
                f"Production persistence failure: malformed database URL '{redact_db_url(clean)}': {exc}"
            ) from exc
        if backend != "postgresql":
            raise RuntimeError(
                f"Production persistence failure: database backend '{backend}' is prohibited in production; "
                "Cloud SQL PostgreSQL is mandatory (silent fallback to SQLite is disabled)."
            )


def resolve_configured_database_url(
    explicit_url: Optional[str] = None,
    *,
    async_driver: bool = False,
) -> str:
    """Resolves and validates the configured SQLAlchemy database URL (failing closed in production)."""
    raw_url = (
        (explicit_url or "").strip()
        or os.getenv("DATABASE_URL", "").strip()
        or os.getenv("SESSION_DB_URL", "").strip()
        or build_cloud_sql_url_from_env(async_driver=async_driver)
        or ""
    )
    if not raw_url:
        if auth_guard.is_production_environment():
            raise RuntimeError(
                "Production persistence failure: DATABASE_URL / SESSION_DB_URL / PQC_CLOUD_SQL_CONNECTION_NAME is not configured. "
                "Refusing silent fallback to SQLite in production."
            )
        local_dir = (os.getenv("PQC_DATA_DIR") or "data").strip()
        if local_dir == "/data" or local_dir.startswith("/data/"):
            local_dir = "data"
        os.makedirs(local_dir, exist_ok=True)
        raw_url = f"sqlite:///{os.path.abspath(os.path.join(local_dir, 'pqc_local_dev.db'))}"

    validate_production_postgres_only(raw_url)
    return normalize_async_db_url(raw_url) if async_driver else normalize_sync_db_url(raw_url)


def build_sync_sqlalchemy_engine(raw_url: str) -> Engine:
    """Creates a transactional SQLAlchemy Engine with appropriate pooling and statement/connect timeouts."""
    sync_url = normalize_sync_db_url(raw_url)
    parsed = make_url(sync_url)
    backend = parsed.get_backend_name()

    if backend == "sqlite":
        connect_args: Dict[str, Any] = {"check_same_thread": False, "timeout": 30.0}
        engine = create_engine(sync_url, future=True, connect_args=connect_args, pool_pre_ping=True)
        import sqlalchemy.event

        @sqlalchemy.event.listens_for(engine, "connect")
        def _configure_local_sqlite(dbapi_conn: Any, _record: Any) -> None:
            try:
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA foreign_keys=ON;")
                cur.execute("PRAGMA busy_timeout=30000;")
                cur.close()
            except Exception:
                pass

        return engine

    pool_size = max(1, int(os.getenv("PQC_DB_POOL_SIZE", "5")))
    max_overflow = max(0, int(os.getenv("PQC_DB_MAX_OVERFLOW", "10")))
    pool_timeout = max(1.0, float(os.getenv("PQC_DB_POOL_TIMEOUT", "15")))
    pool_recycle = max(60, int(os.getenv("PQC_DB_POOL_RECYCLE", "1800")))
    connect_timeout = max(2, int(os.getenv("PQC_DB_CONNECT_TIMEOUT", "10")))
    stmt_timeout_ms = max(1000, int(os.getenv("PQC_DB_STATEMENT_TIMEOUT_MS", "30000")))

    pg_connect_args: Dict[str, Any] = {
        "connect_timeout": connect_timeout,
        "options": f"-c statement_timeout={stmt_timeout_ms}",
    }
    return create_engine(
        sync_url,
        future=True,
        pool_pre_ping=True,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_timeout=pool_timeout,
        pool_recycle=pool_recycle,
        connect_args=pg_connect_args,
    )


def build_async_engine_kwargs(raw_url: str) -> Dict[str, Any]:
    """Returns SQLAlchemy ``create_async_engine`` kwargs (pooling + timeouts) for ``DatabaseSessionService``."""
    async_url = normalize_async_db_url(raw_url)
    parsed = make_url(async_url)
    if parsed.get_backend_name() == "sqlite":
        return {"connect_args": {"timeout": 30.0}}

    pool_size = max(1, int(os.getenv("PQC_DB_POOL_SIZE", "5")))
    max_overflow = max(0, int(os.getenv("PQC_DB_MAX_OVERFLOW", "10")))
    pool_timeout = max(1.0, float(os.getenv("PQC_DB_POOL_TIMEOUT", "15")))
    pool_recycle = max(60, int(os.getenv("PQC_DB_POOL_RECYCLE", "1800")))
    connect_timeout = max(2.0, float(os.getenv("PQC_DB_CONNECT_TIMEOUT", "10")))
    cmd_timeout = max(5.0, float(os.getenv("PQC_DB_STATEMENT_TIMEOUT_MS", "30000")) / 1000.0)
    return {
        "pool_pre_ping": True,
        "pool_size": pool_size,
        "max_overflow": max_overflow,
        "pool_timeout": pool_timeout,
        "pool_recycle": pool_recycle,
        "connect_args": {
            "timeout": connect_timeout,
            "command_timeout": cmd_timeout,
        },
    }


def verify_alembic_schema_on_engine(
    engine: Engine,
    *,
    expected_revision: str = EXPECTED_ALEMBIC_REVISION,
) -> str:
    """Read-only verification that Alembic has applied ``expected_revision`` and all required tables exist."""
    with engine.connect() as conn:
        existing_tables = set(sa_inspect(conn).get_table_names())
        if "alembic_version" not in existing_tables:
            raise RuntimeError(
                "Production schema verification failed: 'alembic_version' table is missing. "
                "Database schema must be initialized exclusively via Alembic ('alembic upgrade head')."
            )
        revs = [
            str(r[0])
            for r in conn.execute(text("SELECT version_num FROM alembic_version")).fetchall()
            if r and r[0] is not None
        ]
        if len(revs) != 1 or revs[0] != expected_revision:
            raise RuntimeError(
                f"Production schema verification failed: expected Alembic revision {expected_revision!r}, "
                f"found {revs!r}. Run 'python scripts/run_db_migrations.py' before starting the application."
            )

        required_tables = set(PqcPersistenceBase.metadata.tables.keys()) | set(REQUIRED_ADK_V1_TABLES)
        missing_tables = sorted(required_tables - existing_tables)
        if missing_tables:
            raise RuntimeError(
                "Production schema verification failed: inconsistent database schema; "
                f"missing required tables: {', '.join(missing_tables)}."
            )

        pqc_ver = conn.execute(
            text("SELECT value FROM pqc_schema_metadata WHERE key = :k"),
            {"k": "schema_version"},
        ).scalar_one_or_none()
        if pqc_ver != expected_revision:
            raise RuntimeError(
                f"Production schema verification failed: pqc_schema_metadata 'schema_version' is {pqc_ver!r} "
                f"(expected {expected_revision!r})."
            )

        adk_ver = conn.execute(
            text("SELECT value FROM adk_internal_metadata WHERE key = :k"),
            {"k": "schema_version"},
        ).scalar_one_or_none()
        if str(adk_ver or "") != "1":
            raise RuntimeError(
                f"Production schema verification failed: adk_internal_metadata 'schema_version' is {adk_ver!r} "
                "(expected '1')."
            )
    return expected_revision


class DistributedAuthStore:
    """Transactional database store for auth, sessions, user/session metadata, connections, calibration & credentials."""

    def __init__(
        self,
        db_url: str,
        *,
        engine: Optional[Engine] = None,
        create_schema: Optional[bool] = None,
        verify_connectivity: Optional[bool] = None,
        verify_schema: Optional[bool] = None,
    ) -> None:
        validate_production_postgres_only(db_url)
        in_prod = auth_guard.is_production_environment()
        if in_prod and create_schema is True:
            raise RuntimeError(
                "Production schema failure: SQLAlchemy metadata.create_all() is prohibited in production; "
                "schema creation and upgrades are controlled exclusively by Alembic."
            )

        self.db_url = normalize_sync_db_url(db_url)
        self.backend = make_url(self.db_url).get_backend_name()
        self._owns_engine = engine is None
        self.engine: Engine = engine or build_sync_sqlalchemy_engine(self.db_url)
        self._session_factory = sessionmaker(bind=self.engine, expire_on_commit=False, future=True)

        must_ping = (
            (in_prod or self.backend == "postgresql")
            if verify_connectivity is None
            else bool(verify_connectivity)
        )
        if must_ping:
            try:
                self.ping()
            except Exception as exc:
                if self._owns_engine:
                    self.engine.dispose()
                raise RuntimeError(
                    f"Database connectivity verification failed for '{redact_db_url(self.db_url)}': {exc}"
                ) from exc

        try:
            if in_prod:
                self.verify_production_schema()
            else:
                dev_auto = os.getenv("PQC_DEV_AUTO_CREATE_SCHEMA", "true").strip().lower() not in (
                    "0",
                    "false",
                    "no",
                )
                should_create = dev_auto if create_schema is None else bool(create_schema)
                if should_create:
                    self.ensure_schema()
                elif verify_schema:
                    self.verify_production_schema()
        except Exception:
            if self._owns_engine:
                self.engine.dispose()
            raise

    def verify_production_schema(self, *, expected_revision: str = EXPECTED_ALEMBIC_REVISION) -> str:
        """Validates that the database schema matches ``expected_revision`` without creating or altering tables."""
        return verify_alembic_schema_on_engine(self.engine, expected_revision=expected_revision)

    def ensure_schema(self) -> None:
        """Convenience schema initializer strictly restricted to non-production local development and unit tests."""
        if auth_guard.is_production_environment():
            raise RuntimeError(
                "Production schema failure: SQLAlchemy metadata.create_all() is prohibited in production; "
                "schema creation and upgrades are controlled exclusively by Alembic."
            )
        PqcPersistenceBase.metadata.create_all(self.engine)
        now_iso = _utc_now_iso()
        with self._session_factory.begin() as db:
            meta = db.get(SchemaVersionRecord, "schema_version")
            if meta is None:
                db.add(SchemaVersionRecord(key="schema_version", value=CURRENT_SCHEMA_VERSION, updated_at=now_iso))
            elif meta.value != CURRENT_SCHEMA_VERSION:
                meta.value = CURRENT_SCHEMA_VERSION
                meta.updated_at = now_iso

    def get_schema_version(self) -> Optional[str]:
        with self._session_factory() as db:
            row = db.get(SchemaVersionRecord, "schema_version")
            return row.value if row is not None else None

    def ping(self) -> bool:
        with self.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True

    def close(self) -> None:
        if self._owns_engine:
            self.engine.dispose()

    # ------------------------------------------------------------------
    # OAuth 2.0 + PKCE Temporary Server-Side Transactions (AUTH-02 / AUTH-04)
    # ------------------------------------------------------------------
    def create_oauth_transaction(
        self,
        *,
        flow_mode: str,
        redirect_uri: str,
        client_type: str = "public",
        initiating_user_id: Optional[str] = None,
        initiating_session_jti: Optional[str] = None,
        app_session_id: Optional[str] = None,
        target_scope: Optional[str] = None,
        region: str = "",
        timezone: str = "",
        ttl_seconds: int = MAX_OAUTH_TRANSACTION_TTL_SECONDS,
    ) -> OAuthTransactionData:
        """Creates an opaque ``state`` and stores the PKCE ``code_verifier`` and OIDC ``nonce`` server-side only."""
        now = time.time()
        effective_ttl = max(
            MIN_OAUTH_TRANSACTION_TTL_SECONDS,
            min(int(ttl_seconds), MAX_OAUTH_TRANSACTION_TTL_SECONDS),
        )
        state_id = secrets.token_urlsafe(32)
        code_verifier = secrets.token_urlsafe(64)
        oidc_nonce = secrets.token_urlsafe(32)
        browser_binding_token = secrets.token_urlsafe(32)
        binding_hash = sha256_hex(browser_binding_token)
        expires_at = now + effective_ttl

        record = OAuthTransactionRecord(
            state_id=state_id,
            flow_mode=flow_mode,
            client_type=client_type,
            code_verifier=code_verifier,
            oidc_nonce=oidc_nonce,
            browser_binding_hash=binding_hash,
            initiating_user_id=initiating_user_id,
            initiating_session_jti=initiating_session_jti,
            app_session_id=app_session_id or None,
            target_scope=target_scope or None,
            redirect_uri=redirect_uri,
            region=region or "",
            timezone=timezone or "",
            created_at=now,
            expires_at=expires_at,
            consumed_at=None,
        )
        with self._session_factory.begin() as db:
            db.execute(
                delete(OAuthTransactionRecord).where(OAuthTransactionRecord.expires_at < (now - 3600))
            )
            db.add(record)

        return OAuthTransactionData(
            state_id=state_id,
            flow_mode=flow_mode,
            client_type=client_type,
            code_verifier=code_verifier,
            oidc_nonce=oidc_nonce,
            browser_binding_token=browser_binding_token,
            browser_binding_hash=binding_hash,
            initiating_user_id=initiating_user_id,
            initiating_session_jti=initiating_session_jti,
            app_session_id=app_session_id or None,
            target_scope=target_scope or None,
            redirect_uri=redirect_uri,
            region=region or "",
            timezone=timezone or "",
            created_at=now,
            expires_at=expires_at,
            consumed_at=None,
        )

    def peek_oauth_transaction_mode(self, state_id: Optional[str]) -> Optional[str]:
        """Returns ``flow_mode`` for UI error messaging without exposing credentials or consuming the transaction."""
        clean = (state_id or "").strip()
        if not clean:
            return None
        with self._session_factory() as db:
            row = db.get(OAuthTransactionRecord, clean)
            return row.flow_mode if row is not None else None

    def consume_oauth_transaction(
        self,
        *,
        state_id: Optional[str],
        browser_binding_token: Optional[str],
        expected_redirect_uri: str,
        now_override: Optional[float] = None,
    ) -> Optional[OAuthTransactionData]:
        """Atomically validates and consumes an OAuth transaction (single-use, race-free across instances)."""
        clean_state = (state_id or "").strip()
        clean_binding = (browser_binding_token or "").strip()
        if not clean_state or not clean_binding or not expected_redirect_uri:
            return None
        if "." in clean_state or len(clean_state) > 128:
            return None

        binding_hash = sha256_hex(clean_binding)
        now = float(now_override if now_override is not None else time.time())
        min_valid_created_at = now - float(MAX_OAUTH_TRANSACTION_TTL_SECONDS)

        with self._session_factory.begin() as db:
            stmt = (
                update(OAuthTransactionRecord)
                .where(
                    OAuthTransactionRecord.state_id == clean_state,
                    OAuthTransactionRecord.consumed_at.is_(None),
                    OAuthTransactionRecord.expires_at > now,
                    OAuthTransactionRecord.created_at > min_valid_created_at,
                    OAuthTransactionRecord.browser_binding_hash == binding_hash,
                    OAuthTransactionRecord.redirect_uri == expected_redirect_uri,
                )
                .values(consumed_at=now)
            )
            res = db.execute(stmt)
            if (res.rowcount or 0) != 1:
                return None
            row = db.get(OAuthTransactionRecord, clean_state)
            if row is None or not hmac.compare_digest(row.browser_binding_hash, binding_hash):
                return None
            return OAuthTransactionData(
                state_id=row.state_id,
                flow_mode=row.flow_mode,
                client_type=row.client_type,
                code_verifier=row.code_verifier,
                oidc_nonce=row.oidc_nonce,
                browser_binding_token=None,
                browser_binding_hash=row.browser_binding_hash,
                initiating_user_id=row.initiating_user_id,
                initiating_session_jti=row.initiating_session_jti,
                app_session_id=row.app_session_id,
                target_scope=row.target_scope,
                redirect_uri=row.redirect_uri,
                region=row.region or "",
                timezone=row.timezone or "",
                created_at=row.created_at,
                expires_at=row.expires_at,
                consumed_at=row.consumed_at,
            )

    # ------------------------------------------------------------------
    # Single-Use Nonce & Authorization Code Replay Ledger (AUTH-01 / AUTH-04)
    # ------------------------------------------------------------------
    def consume_replay_token(
        self,
        purpose: str,
        raw_value: Optional[str],
        *,
        ttl_seconds: int = 3600,
        now_override: Optional[float] = None,
    ) -> bool:
        """Atomically marks ``(purpose, raw_value)`` as consumed; returns False if replayed or empty."""
        clean = (raw_value or "").strip()
        if not clean:
            return False
        now = float(now_override if now_override is not None else time.time())
        key = f"{purpose}:{sha256_hex(clean)}"
        try:
            with self._session_factory.begin() as db:
                db.execute(delete(ConsumedNonceRecord).where(ConsumedNonceRecord.expires_at <= now))
                db.add(
                    ConsumedNonceRecord(
                        nonce_key=key,
                        purpose=purpose,
                        created_at=now,
                        expires_at=now + max(60, int(ttl_seconds)),
                    )
                )
            return True
        except IntegrityError:
            return False

    # ------------------------------------------------------------------
    # Distributed Session Registry & Revocation (AUTH-03 / AUTH-04)
    # ------------------------------------------------------------------
    def register_session(
        self,
        *,
        jti: str,
        raw_token: str,
        user_id: str,
        email: str,
        region: str,
        auth_method: str,
        issued_at: float,
        expires_at: float,
    ) -> None:
        tok_hash = sha256_hex(raw_token)
        with self._session_factory.begin() as db:
            existing = db.get(AuthSessionRecord, jti)
            if existing is None:
                db.add(
                    AuthSessionRecord(
                        jti=jti,
                        token_sha256=tok_hash,
                        user_id=user_id,
                        email=email,
                        region=region or "NorthAm",
                        auth_method=auth_method or "google_workspace_signin",
                        issued_at=float(issued_at),
                        expires_at=float(expires_at),
                        revoked_at=None,
                        revocation_reason=None,
                    )
                )
            else:
                existing.token_sha256 = tok_hash
                existing.user_id = user_id
                existing.email = email
                existing.region = region or existing.region
                existing.auth_method = auth_method or existing.auth_method
                existing.expires_at = float(expires_at)

    def revoke_session(
        self,
        *,
        jti: Optional[str] = None,
        raw_token: Optional[str] = None,
        user_id: Optional[str] = None,
        expires_at: Optional[float] = None,
        reason: str = "logout",
    ) -> int:
        """Atomically revokes a session across all instances by ``jti`` and/or ``raw_token`` hash."""
        clean_jti = (jti or "").strip()
        tok_hash = sha256_hex(raw_token) if raw_token else ""
        if not clean_jti and not tok_hash:
            return 0
        now = time.time()
        conditions = []
        if clean_jti:
            conditions.append(AuthSessionRecord.jti == clean_jti)
        if tok_hash:
            conditions.append(AuthSessionRecord.token_sha256 == tok_hash)

        with self._session_factory.begin() as db:
            stmt = (
                update(AuthSessionRecord)
                .where(or_(*conditions))
                .values(revoked_at=now, revocation_reason=reason)
            )
            res = db.execute(stmt)
            updated = int(res.rowcount or 0)
            if updated == 0:
                effective_jti = clean_jti or f"tombstone:{tok_hash[:32]}"
                effective_hash = tok_hash or sha256_hex(effective_jti)
                db.add(
                    AuthSessionRecord(
                        jti=effective_jti,
                        token_sha256=effective_hash,
                        user_id=user_id or "revoked",
                        email=user_id or "revoked",
                        region="NorthAm",
                        auth_method="revoked",
                        issued_at=now,
                        expires_at=float(expires_at or (now + 30 * 86400)),
                        revoked_at=now,
                        revocation_reason=reason,
                    )
                )
                updated = 1
            return updated

    def revoke_user_sessions(self, user_id: str, *, reason: str = "user_revocation") -> int:
        """Atomically revokes all active sessions belonging to ``user_id`` across all instances."""
        clean_uid = str(user_id or "").strip().lower()
        if not clean_uid:
            return 0
        now = time.time()
        with self._session_factory.begin() as db:
            stmt = (
                update(AuthSessionRecord)
                .where(AuthSessionRecord.user_id == clean_uid, AuthSessionRecord.revoked_at.is_(None))
                .values(revoked_at=now, revocation_reason=reason)
            )
            res = db.execute(stmt)
            return int(res.rowcount or 0)

    def is_session_revoked_or_expired(
        self,
        *,
        jti: Optional[str],
        raw_token: Optional[str],
        now_override: Optional[float] = None,
    ) -> bool:
        """Checks authoritative database state: True if unregistered, revoked, or expired (fail-closed)."""
        clean_jti = (jti or "").strip()
        tok_hash = sha256_hex(raw_token) if raw_token else ""
        if not clean_jti and not tok_hash:
            return True
        now = float(now_override if now_override is not None else time.time())
        conditions = []
        if clean_jti:
            conditions.append(AuthSessionRecord.jti == clean_jti)
        if tok_hash:
            conditions.append(AuthSessionRecord.token_sha256 == tok_hash)

        with self._session_factory() as db:
            rows = db.scalars(select(AuthSessionRecord).where(or_(*conditions))).all()
            if not rows:
                return True
            for row in rows:
                if row.revoked_at is not None or row.expires_at <= now:
                    return True
            return False

    def get_active_session_by_jti(
        self,
        jti: Optional[str],
        *,
        expected_user_id: Optional[str] = None,
        now_override: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        """Loads an unrevoked, unexpired session record by ``jti`` (used by the HttpOnly multi-account switcher)."""
        clean_jti = (jti or "").strip()
        if not clean_jti:
            return None
        now = float(now_override if now_override is not None else time.time())
        with self._session_factory() as db:
            row = db.get(AuthSessionRecord, clean_jti)
            if row is None or row.revoked_at is not None or row.expires_at <= now:
                return None
            if expected_user_id and row.user_id.lower() != expected_user_id.lower():
                return None
            return {
                "jti": row.jti,
                "user_id": row.user_id,
                "email": row.email,
                "region": row.region,
                "auth_method": row.auth_method,
                "issued_at": row.issued_at,
                "expires_at": row.expires_at,
            }

    # ------------------------------------------------------------------
    # Authoritative Tenant User Profiles (DB-03)
    # ------------------------------------------------------------------
    @staticmethod
    def _tenant_user_to_dict(row: TenantUserRecord) -> Dict[str, Any]:
        return {
            "user_id": row.user_id,
            "email": row.email,
            "domain": row.tenant_domain,
            "tenant_domain": row.tenant_domain,
            "name": row.name,
            "region": row.region,
            "timezone": row.timezone,
            "auth_method": row.auth_method,
            "picture": row.picture,
            "created_at": row.created_at,
            "last_login_at": row.last_login_at,
        }

    def upsert_tenant_user(
        self,
        *,
        user_id: str,
        email: str,
        name: Optional[str] = None,
        region: Optional[str] = None,
        timezone: Optional[str] = None,
        auth_method: Optional[str] = None,
        picture: Optional[str] = None,
        created_at: Optional[str] = None,
        last_login_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Atomically creates or updates a corporate user profile in ``pqc_tenant_users``."""
        clean_uid = str(user_id or email).strip().lower()
        clean_email = str(email or clean_uid).strip().lower()
        domain = extract_tenant_domain(clean_email)
        now_iso = _utc_now_iso()

        with self._session_factory.begin() as db:
            row = db.get(TenantUserRecord, clean_uid)
            if row is None:
                row = TenantUserRecord(
                    user_id=clean_uid,
                    email=clean_email,
                    tenant_domain=domain,
                    name=(name or clean_email.split("@", 1)[0]).strip(),
                    region=(region or "NorthAm").strip(),
                    timezone=(timezone or "UTC").strip(),
                    auth_method=(auth_method or "google_workspace_signin").strip(),
                    picture=(picture or "").strip(),
                    created_at=created_at or now_iso,
                    last_login_at=last_login_at or now_iso,
                )
                db.add(row)
            else:
                if name and str(name).strip():
                    row.name = str(name).strip()
                if region and str(region).strip():
                    row.region = str(region).strip()
                if timezone and str(timezone).strip():
                    row.timezone = str(timezone).strip()
                if auth_method and str(auth_method).strip():
                    row.auth_method = str(auth_method).strip()
                if picture is not None and str(picture).strip():
                    row.picture = str(picture).strip()
                row.tenant_domain = domain
                row.last_login_at = last_login_at or now_iso
            db.flush()
            return self._tenant_user_to_dict(row)

    def get_tenant_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        clean_uid = str(user_id or "").strip().lower()
        if not clean_uid:
            return None
        with self._session_factory() as db:
            row = db.get(TenantUserRecord, clean_uid)
            return self._tenant_user_to_dict(row) if row is not None else None

    def list_tenant_users(self, *, tenant_domain: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._session_factory() as db:
            stmt = select(TenantUserRecord)
            if tenant_domain:
                stmt = stmt.where(TenantUserRecord.tenant_domain == tenant_domain.strip().lower())
            stmt = stmt.order_by(TenantUserRecord.last_login_at.desc())
            rows = db.scalars(stmt).all()
            return [self._tenant_user_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Authoritative Session Metadata with Strict Ownership (DB-03)
    # ------------------------------------------------------------------
    @staticmethod
    def _session_metadata_to_dict(row: SessionMetadataRecord) -> Dict[str, Any]:
        try:
            attachments = json.loads(row.attachments_json or "[]")
        except Exception:
            attachments = []
        try:
            telemetry = json.loads(row.turn_telemetry_json or "{}")
        except Exception:
            telemetry = {}
        fallback_msgs = None
        if row.fallback_messages_json:
            try:
                fallback_msgs = json.loads(row.fallback_messages_json)
            except Exception:
                fallback_msgs = None
        result: Dict[str, Any] = {
            "session_id": row.session_id,
            "user_id": row.user_id,
            "tenant_domain": row.tenant_domain,
            "title": row.title,
            "scope": row.scope,
            "model_id": row.model_id,
            "model_label": row.model_label,
            "message_count": int(row.message_count or 0),
            "attachments_by_turn": attachments if isinstance(attachments, list) else [],
            "turn_telemetry": telemetry if isinstance(telemetry, dict) else {},
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }
        if fallback_msgs:
            result["fallback_messages"] = fallback_msgs
        return result

    def _ensure_parent_user_in_tx(self, db: Any, user_id: str) -> str:
        clean_uid = str(user_id).strip().lower()
        domain = extract_tenant_domain(clean_uid)
        if db.get(TenantUserRecord, clean_uid) is None:
            now_iso = _utc_now_iso()
            db.add(
                TenantUserRecord(
                    user_id=clean_uid,
                    email=clean_uid,
                    tenant_domain=domain,
                    name=clean_uid.split("@", 1)[0],
                    region="NorthAm",
                    timezone="UTC",
                    auth_method="session_owner",
                    picture="",
                    created_at=now_iso,
                    last_login_at=now_iso,
                )
            )
            db.flush()
        return domain

    def upsert_session_metadata(
        self,
        *,
        session_id: str,
        user_id: str,
        title: Optional[str] = None,
        scope: Optional[str] = None,
        model_id: Optional[str] = None,
        model_label: Optional[str] = None,
        message_count: Optional[int] = None,
        message_delta: int = 0,
        append_attachments: Optional[List[Dict[str, Any]]] = None,
        attachments_by_turn: Optional[List[Any]] = None,
        invocation_id: Optional[str] = None,
        invocation_telemetry: Optional[Dict[str, Any]] = None,
        turn_telemetry: Optional[Dict[str, Any]] = None,
        fallback_messages: Optional[List[Dict[str, Any]]] = None,
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Atomically creates or updates session metadata while enforcing strict ``user_id`` ownership."""
        clean_sid = str(session_id).strip()
        clean_uid = str(user_id).strip().lower()
        if not clean_sid or not clean_uid:
            raise ValueError("session_id and user_id are required.")
        now_iso = updated_at or _utc_now_iso()

        with self._session_factory.begin() as db:
            domain = self._ensure_parent_user_in_tx(db, clean_uid)
            row = db.get(SessionMetadataRecord, clean_sid)
            if row is None:
                init_att = list(attachments_by_turn) if attachments_by_turn is not None else []
                if append_attachments is not None:
                    init_att.append(append_attachments)
                init_tel = dict(turn_telemetry) if turn_telemetry is not None else {}
                if invocation_id and invocation_telemetry is not None:
                    init_tel[invocation_id] = invocation_telemetry
                init_count = int(message_count) if message_count is not None else max(0, int(message_delta))
                row = SessionMetadataRecord(
                    session_id=clean_sid,
                    user_id=clean_uid,
                    tenant_domain=domain,
                    title=(title or "New PQC Assessment")[:512],
                    scope=(scope or "organizations/31564119954")[:512],
                    model_id=model_id,
                    model_label=model_label,
                    message_count=init_count,
                    attachments_json=json.dumps(init_att, ensure_ascii=False),
                    turn_telemetry_json=json.dumps(init_tel, ensure_ascii=False, default=str),
                    fallback_messages_json=(
                        json.dumps(fallback_messages, ensure_ascii=False, default=str) if fallback_messages else None
                    ),
                    created_at=created_at or now_iso,
                    updated_at=now_iso,
                )
                db.add(row)
            else:
                if row.user_id.lower() != clean_uid:
                    raise PermissionError(
                        f"Forbidden: session '{clean_sid}' is owned by another user and cannot be modified by '{clean_uid}'."
                    )
                if title is not None and (row.title in ("", "New PQC Assessment") or message_delta == 0):
                    row.title = title[:512]
                if scope is not None:
                    row.scope = scope[:512]
                if model_id is not None:
                    row.model_id = model_id
                if model_label is not None:
                    row.model_label = model_label
                if message_count is not None:
                    row.message_count = int(message_count)
                elif message_delta:
                    row.message_count = int(row.message_count or 0) + int(message_delta)

                if attachments_by_turn is not None:
                    row.attachments_json = json.dumps(attachments_by_turn, ensure_ascii=False)
                elif append_attachments is not None:
                    try:
                        curr_att = json.loads(row.attachments_json or "[]")
                    except Exception:
                        curr_att = []
                    if not isinstance(curr_att, list):
                        curr_att = []
                    curr_att.append(append_attachments)
                    row.attachments_json = json.dumps(curr_att, ensure_ascii=False)

                if turn_telemetry is not None:
                    row.turn_telemetry_json = json.dumps(turn_telemetry, ensure_ascii=False, default=str)
                elif invocation_id and invocation_telemetry is not None:
                    try:
                        curr_tel = json.loads(row.turn_telemetry_json or "{}")
                    except Exception:
                        curr_tel = {}
                    if not isinstance(curr_tel, dict):
                        curr_tel = {}
                    curr_tel[invocation_id] = invocation_telemetry
                    row.turn_telemetry_json = json.dumps(curr_tel, ensure_ascii=False, default=str)

                if fallback_messages is not None:
                    row.fallback_messages_json = json.dumps(fallback_messages, ensure_ascii=False, default=str)
                row.updated_at = now_iso
            db.flush()
            return self._session_metadata_to_dict(row)

    def get_session_metadata(self, session_id: str, *, user_id: str) -> Optional[Dict[str, Any]]:
        """Loads session metadata strictly scoped to ``user_id`` (returns None if owned by someone else)."""
        clean_sid = str(session_id or "").strip()
        clean_uid = str(user_id or "").strip().lower()
        if not clean_sid or not clean_uid:
            return None
        with self._session_factory() as db:
            stmt = select(SessionMetadataRecord).where(
                SessionMetadataRecord.session_id == clean_sid,
                SessionMetadataRecord.user_id == clean_uid,
            )
            row = db.scalars(stmt).one_or_none()
            return self._session_metadata_to_dict(row) if row is not None else None

    def list_user_session_metadata(self, user_id: str) -> Dict[str, Dict[str, Any]]:
        """Returns ``{session_id: metadata_dict}`` owned exclusively by ``user_id``."""
        clean_uid = str(user_id or "").strip().lower()
        if not clean_uid:
            return {}
        with self._session_factory() as db:
            stmt = (
                select(SessionMetadataRecord)
                .where(SessionMetadataRecord.user_id == clean_uid)
                .order_by(SessionMetadataRecord.updated_at.desc())
            )
            rows = db.scalars(stmt).all()
            return {r.session_id: self._session_metadata_to_dict(r) for r in rows}

    def delete_session_metadata(self, session_id: str, *, user_id: str) -> bool:
        """Atomically deletes session metadata only if owned by ``user_id``."""
        clean_sid = str(session_id or "").strip()
        clean_uid = str(user_id or "").strip().lower()
        if not clean_sid or not clean_uid:
            return False
        with self._session_factory.begin() as db:
            res = db.execute(
                delete(SessionMetadataRecord).where(
                    SessionMetadataRecord.session_id == clean_sid,
                    SessionMetadataRecord.user_id == clean_uid,
                )
            )
            return int(res.rowcount or 0) > 0

    # ------------------------------------------------------------------
    # Authoritative Per-User Non-Secret GCP Connection Config (DB-03)
    # ------------------------------------------------------------------
    @staticmethod
    def _connection_to_dict(row: UserConnectionRecord) -> Dict[str, Any]:
        return {
            "user_id": row.user_id,
            "tenant_domain": row.tenant_domain,
            "mode": row.mode,
            "organization_id": row.organization_id,
            "project_id": row.project_id,
            "location": row.location,
            "impersonated_service_account": row.impersonated_service_account,
            "updated_at": row.updated_at,
        }

    def get_user_connection(self, user_id: str) -> Optional[Dict[str, Any]]:
        clean_uid = str(user_id or "").strip().lower()
        if not clean_uid:
            return None
        with self._session_factory() as db:
            row = db.get(UserConnectionRecord, clean_uid)
            return self._connection_to_dict(row) if row is not None else None

    def upsert_user_connection(
        self,
        *,
        user_id: str,
        mode: Optional[str] = None,
        organization_id: Optional[str] = None,
        project_id: Optional[str] = None,
        location: Optional[str] = None,
        impersonated_service_account: Optional[str] = None,
        updated_at: Optional[str] = None,
        defaults: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        clean_uid = str(user_id or "").strip().lower()
        domain = extract_tenant_domain(clean_uid)
        now_iso = updated_at or _utc_now_iso()
        defs = dict(defaults or {})

        with self._session_factory.begin() as db:
            row = db.get(UserConnectionRecord, clean_uid)
            if row is None:
                row = UserConnectionRecord(
                    user_id=clean_uid,
                    tenant_domain=domain,
                    mode=str(mode or defs.get("mode") or "adc"),
                    organization_id=str(organization_id or defs.get("organization_id") or "31564119954"),
                    project_id=str(project_id or defs.get("project_id") or "pqc-inventory-agent-cd06"),
                    location=str(location or defs.get("location") or "all"),
                    impersonated_service_account=str(
                        impersonated_service_account
                        if impersonated_service_account is not None
                        else (defs.get("impersonated_service_account") or "")
                    ),
                    updated_at=now_iso,
                )
                db.add(row)
            else:
                if mode is not None:
                    row.mode = str(mode)
                if organization_id is not None and str(organization_id).strip():
                    row.organization_id = str(organization_id).strip()
                if project_id is not None and str(project_id).strip():
                    row.project_id = str(project_id).strip()
                if location is not None and str(location).strip():
                    row.location = str(location).strip()
                if impersonated_service_account is not None:
                    row.impersonated_service_account = str(impersonated_service_account).strip()
                row.tenant_domain = domain
                row.updated_at = now_iso
            db.flush()
            return self._connection_to_dict(row)

    # ------------------------------------------------------------------
    # Administrator OAuth Client Configuration (DB-03)
    # ------------------------------------------------------------------
    def get_oauth_client_config_record(self, config_key: str = "global") -> Optional[Dict[str, Any]]:
        with self._session_factory() as db:
            row = db.get(OAuthClientConfigRecord, config_key)
            if row is None:
                return None
            return {
                "config_key": row.config_key,
                "client_id": row.client_id,
                "encrypted_client_secret": row.encrypted_client_secret,
                "updated_by": row.updated_by,
                "updated_at": row.updated_at,
            }

    def save_oauth_client_config_record(
        self,
        *,
        client_id: Optional[str] = None,
        encrypted_client_secret: Optional[str] = None,
        updated_by: Optional[str] = None,
        config_key: str = "global",
    ) -> Dict[str, Any]:
        now_iso = _utc_now_iso()
        with self._session_factory.begin() as db:
            row = db.get(OAuthClientConfigRecord, config_key)
            if row is None:
                row = OAuthClientConfigRecord(
                    config_key=config_key,
                    client_id=(client_id or "").strip(),
                    encrypted_client_secret=encrypted_client_secret,
                    updated_by=updated_by,
                    updated_at=now_iso,
                )
                db.add(row)
            else:
                if client_id is not None:
                    row.client_id = str(client_id).strip()
                if encrypted_client_secret is not None:
                    row.encrypted_client_secret = encrypted_client_secret
                if updated_by is not None:
                    row.updated_by = updated_by
                row.updated_at = now_iso
            db.flush()
            return {
                "config_key": row.config_key,
                "client_id": row.client_id,
                "encrypted_client_secret": row.encrypted_client_secret,
                "updated_by": row.updated_by,
                "updated_at": row.updated_at,
            }

    # ------------------------------------------------------------------
    # Longitudinal Mosca Calibration Ledger (DB-03)
    # ------------------------------------------------------------------
    def append_calibration_event(
        self,
        *,
        scope: str,
        user_id: str,
        entry: Mapping[str, Any],
        event_uuid: Optional[str] = None,
    ) -> Dict[str, Any]:
        clean_uid = str(user_id or "sec-architect").strip().lower()
        domain = extract_tenant_domain(clean_uid)
        mosca = entry.get("mosca") or {}
        ts_utc = str(entry.get("timestamp_utc") or _utc_now_iso())
        ev_uuid = event_uuid or str(uuid.uuid4())
        entry_copy = dict(entry)
        entry_copy.setdefault("event_uuid", ev_uuid)

        with self._session_factory.begin() as db:
            existing = db.scalars(
                select(CalibrationEventRecord).where(CalibrationEventRecord.event_uuid == ev_uuid)
            ).one_or_none()
            if existing is None:
                db.add(
                    CalibrationEventRecord(
                        event_uuid=ev_uuid,
                        scope=str(scope).strip(),
                        user_id=clean_uid,
                        tenant_domain=domain,
                        industry_sector=str(entry.get("industry_sector") or "ENTERPRISE_DEFAULT"),
                        sector_label=str(entry.get("sector_label") or ""),
                        confidentiality_years_x=float(mosca.get("confidentiality_years_x", 10.0)),
                        migration_years_y=float(mosca.get("migration_years_y", 2.0)),
                        crqc_horizon_years_z=float(mosca.get("crqc_horizon_years_z", 8.5)),
                        gateway_header_limit_kb=int(entry.get("gateway_header_limit_kb", 8)),
                        entry_json=json.dumps(entry_copy, ensure_ascii=False, separators=(",", ":")),
                        timestamp_utc=ts_utc,
                    )
                )
        return entry_copy

    def list_calibration_events(
        self,
        *,
        scope: str,
        tenant_domain: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        with self._session_factory() as db:
            stmt = select(CalibrationEventRecord).where(CalibrationEventRecord.scope == str(scope).strip())
            if tenant_domain:
                stmt = stmt.where(CalibrationEventRecord.tenant_domain == tenant_domain.strip().lower())
            stmt = stmt.order_by(CalibrationEventRecord.id.asc())
            rows = db.scalars(stmt).all()
            out: List[Dict[str, Any]] = []
            for r in rows:
                try:
                    out.append(json.loads(r.entry_json))
                except Exception:
                    continue
            return out

    # ------------------------------------------------------------------
    # Envelope-Encrypted Delegated Credentials Persistence (ID-01)
    # ------------------------------------------------------------------
    def upsert_encrypted_credential(
        self,
        *,
        credential_id: str,
        app_name: str,
        tenant_domain: str,
        user_id: str,
        credential_key: str,
        kek_provider: str,
        kms_key_name: Optional[str],
        wrapped_dek_b64: str,
        payload_nonce_b64: str,
        ciphertext_b64: str,
        aad_sha256: str,
        has_refresh_token: bool,
        issued_at: float,
        expires_at: float,
    ) -> None:
        clean_uid = str(user_id).strip().lower()
        clean_tenant = str(tenant_domain).strip().lower()
        with self._session_factory.begin() as db:
            row = db.get(DelegatedCredentialRecord, credential_id)
            if row is None:
                db.add(
                    DelegatedCredentialRecord(
                        credential_id=credential_id,
                        app_name=app_name,
                        tenant_domain=clean_tenant,
                        user_id=clean_uid,
                        credential_key=credential_key,
                        kek_provider=kek_provider,
                        kms_key_name=kms_key_name,
                        wrapped_dek_b64=wrapped_dek_b64,
                        payload_nonce_b64=payload_nonce_b64,
                        ciphertext_b64=ciphertext_b64,
                        aad_sha256=aad_sha256,
                        has_refresh_token=1 if has_refresh_token else 0,
                        issued_at=float(issued_at),
                        expires_at=float(expires_at),
                        revoked_at=None,
                        revocation_reason=None,
                    )
                )
            else:
                if row.user_id != clean_uid or row.tenant_domain != clean_tenant:
                    raise PermissionError("Cross-user or cross-tenant credential overwrite rejected.")
                row.kek_provider = kek_provider
                row.kms_key_name = kms_key_name
                row.wrapped_dek_b64 = wrapped_dek_b64
                row.payload_nonce_b64 = payload_nonce_b64
                row.ciphertext_b64 = ciphertext_b64
                row.aad_sha256 = aad_sha256
                row.has_refresh_token = 1 if has_refresh_token else 0
                row.issued_at = float(issued_at)
                row.expires_at = float(expires_at)
                row.revoked_at = None
                row.revocation_reason = None

    def get_encrypted_credential_row(
        self,
        *,
        credential_id: str,
        expected_user_id: str,
        expected_tenant_domain: str,
    ) -> Optional[Dict[str, Any]]:
        clean_uid = str(expected_user_id).strip().lower()
        clean_tenant = str(expected_tenant_domain).strip().lower()
        with self._session_factory() as db:
            row = db.get(DelegatedCredentialRecord, credential_id)
            if row is None:
                return None
            if row.user_id != clean_uid or row.tenant_domain != clean_tenant:
                raise PermissionError("Cross-user or cross-tenant credential access rejected.")
            return {
                "credential_id": row.credential_id,
                "app_name": row.app_name,
                "tenant_domain": row.tenant_domain,
                "user_id": row.user_id,
                "credential_key": row.credential_key,
                "kek_provider": row.kek_provider,
                "kms_key_name": row.kms_key_name,
                "wrapped_dek_b64": row.wrapped_dek_b64,
                "payload_nonce_b64": row.payload_nonce_b64,
                "ciphertext_b64": row.ciphertext_b64,
                "aad_sha256": row.aad_sha256,
                "has_refresh_token": bool(row.has_refresh_token),
                "issued_at": row.issued_at,
                "expires_at": row.expires_at,
                "revoked_at": row.revoked_at,
                "revocation_reason": row.revocation_reason,
            }

    def revoke_encrypted_credentials(
        self,
        *,
        user_id: str,
        tenant_domain: Optional[str] = None,
        credential_key: Optional[str] = None,
        reason: str = "revoked",
    ) -> int:
        """Atomically revokes and wipes ciphertext for a user's delegated credentials across all instances."""
        clean_uid = str(user_id or "").strip().lower()
        if not clean_uid:
            return 0
        now = time.time()
        with self._session_factory.begin() as db:
            stmt = update(DelegatedCredentialRecord).where(DelegatedCredentialRecord.user_id == clean_uid)
            if tenant_domain:
                stmt = stmt.where(DelegatedCredentialRecord.tenant_domain == tenant_domain.strip().lower())
            if credential_key:
                stmt = stmt.where(DelegatedCredentialRecord.credential_key == credential_key)
            stmt = stmt.values(
                revoked_at=now,
                revocation_reason=reason,
                ciphertext_b64="",
                wrapped_dek_b64="",
                payload_nonce_b64="",
            )
            res = db.execute(stmt)
            return int(res.rowcount or 0)

    # ------------------------------------------------------------------
    # Non-Authoritative JSON Backup / Export Snapshot (DB-03)
    # ------------------------------------------------------------------
    def export_workspace_backup_snapshot(self, *, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Exports a non-authoritative, secret-redacted JSON snapshot for backup/portability."""
        clean_uid = str(user_id).strip().lower() if user_id else None
        with self._session_factory() as db:
            u_stmt = select(TenantUserRecord)
            s_stmt = select(SessionMetadataRecord)
            c_stmt = select(UserConnectionRecord)
            cal_stmt = select(CalibrationEventRecord)
            if clean_uid:
                u_stmt = u_stmt.where(TenantUserRecord.user_id == clean_uid)
                s_stmt = s_stmt.where(SessionMetadataRecord.user_id == clean_uid)
                c_stmt = c_stmt.where(UserConnectionRecord.user_id == clean_uid)
                cal_stmt = cal_stmt.where(CalibrationEventRecord.user_id == clean_uid)
            return {
                "format": "pqc_workspace_backup_v1",
                "authoritative": False,
                "exported_at": _utc_now_iso(),
                "schema_version": CURRENT_SCHEMA_VERSION,
                "tenant_users": [self._tenant_user_to_dict(r) for r in db.scalars(u_stmt).all()],
                "session_metadata": [self._session_metadata_to_dict(r) for r in db.scalars(s_stmt).all()],
                "user_connections": [self._connection_to_dict(r) for r in db.scalars(c_stmt).all()],
                "calibration_events": [json.loads(r.entry_json) for r in db.scalars(cal_stmt).all()],
            }


_CURRENT_AUTH_STORE: contextvars.ContextVar[Optional[DistributedAuthStore]] = contextvars.ContextVar(
    "pqc_current_auth_store", default=None
)
_FALLBACK_STORES_LOCK = threading.Lock()
_FALLBACK_STORES_BY_URL: Dict[str, DistributedAuthStore] = {}


def set_active_auth_store(store: Optional[DistributedAuthStore]) -> contextvars.Token[Optional[DistributedAuthStore]]:
    return _CURRENT_AUTH_STORE.set(store)


def reset_active_auth_store(token: contextvars.Token[Optional[DistributedAuthStore]]) -> None:
    _CURRENT_AUTH_STORE.reset(token)


def get_active_auth_store(default_db_url: Optional[str] = None) -> DistributedAuthStore:
    """Returns the request-bound instance ``DistributedAuthStore``, or resolves one for direct helper calls."""
    bound = _CURRENT_AUTH_STORE.get()
    if bound is not None:
        return bound

    norm_url = resolve_configured_database_url(default_db_url, async_driver=False)
    with _FALLBACK_STORES_LOCK:
        store = _FALLBACK_STORES_BY_URL.get(norm_url)
        if store is None:
            store = DistributedAuthStore(norm_url)
            _FALLBACK_STORES_BY_URL[norm_url] = store
        return store


def clear_fallback_auth_stores() -> None:
    """Disposes cached fallback stores (used by test teardown to ensure zero cross-test state)."""
    with _FALLBACK_STORES_LOCK:
        for store in _FALLBACK_STORES_BY_URL.values():
            try:
                store.close()
            except Exception:
                pass
        _FALLBACK_STORES_BY_URL.clear()
