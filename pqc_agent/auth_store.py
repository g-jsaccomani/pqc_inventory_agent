"""Distributed SQLAlchemy persistence for OAuth 2.0 PKCE transactions, replay nonces, and session revocation.

Eliminates process-local Python dictionaries and local JSON files as authoritative authentication state:
- ``pqc_oauth_transactions``: server-side PKCE ``code_verifier``, OIDC ``nonce``, browser binding hash, initiating
  session/user ownership, strict expiration, and single-query atomic ``UPDATE ... WHERE consumed_at IS NULL``
  consumption (race-free under concurrent callbacks and across multiple Cloud Run instances).
- ``pqc_consumed_nonces``: primary-key-enforced single-use ledger for OIDC ``nonce`` claims and authorization codes.
- ``pqc_auth_sessions``: server-side session registry (keyed by ``jti`` and ``token_sha256``) supporting atomic
  cross-instance session revocation, expiration enforcement, and multi-account jar validation across restarts.

Supports Cloud SQL PostgreSQL (``postgresql+psycopg://`` / ``postgresql+asyncpg://``) in production and SQLite
exclusively for local development and isolated unit tests.
"""

from __future__ import annotations

import contextvars
import dataclasses
import hashlib
import hmac
import logging
import os
import secrets
import threading
import time
from typing import Any, Dict, Optional
from urllib.parse import quote_plus

from sqlalchemy import Engine, Float, Index, String, create_engine, delete, or_, select, text, update
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from pqc_agent import auth_guard

logger = logging.getLogger(__name__)


class PqcPersistenceBase(DeclarativeBase):
    """Shared SQLAlchemy 2.0 declarative base for all PQC Portal transactional tables."""


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
            parent_dir = os.path.dirname(os.path.abspath(raw_path.lstrip("/") if not raw_path.startswith("/") else raw_path))
            if raw_path.startswith("/"):
                parent_dir = os.path.dirname(raw_path)
            else:
                parent_dir = os.path.dirname(os.path.abspath(raw_path))
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
                if parsed.database and parsed.database != ":memory:":
                    cur.execute("PRAGMA journal_mode=WAL;")
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


class DistributedAuthStore:
    """Transactional database store for OAuth PKCE state, single-use nonces, and cross-instance session revocation."""

    def __init__(self, db_url: str, *, engine: Optional[Engine] = None, create_schema: bool = True) -> None:
        self.db_url = normalize_sync_db_url(db_url)
        self._owns_engine = engine is None
        self.engine: Engine = engine or build_sync_sqlalchemy_engine(self.db_url)
        self._session_factory = sessionmaker(bind=self.engine, expire_on_commit=False, future=True)
        if create_schema:
            self.ensure_schema()

    def ensure_schema(self) -> None:
        PqcPersistenceBase.metadata.create_all(self.engine)

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
        ttl_seconds: int = 600,
    ) -> OAuthTransactionData:
        """Creates an opaque ``state`` and stores the PKCE ``code_verifier`` and OIDC ``nonce`` server-side only."""
        now = time.time()
        effective_ttl = max(1, min(int(ttl_seconds), 1800))
        state_id = secrets.token_urlsafe(32)
        # RFC 7636 §4.1: high-entropy cryptographic random string between 43 and 128 chars
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
        # Reject non-opaque legacy signed states immediately
        if "." in clean_state or len(clean_state) > 128:
            return None

        binding_hash = sha256_hex(clean_binding)
        now = float(now_override if now_override is not None else time.time())

        with self._session_factory.begin() as db:
            stmt = (
                update(OAuthTransactionRecord)
                .where(
                    OAuthTransactionRecord.state_id == clean_state,
                    OAuthTransactionRecord.consumed_at.is_(None),
                    OAuthTransactionRecord.expires_at > now,
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
                # Tombstone an unregistered token (e.g. minted before restart or by peer) so it is blocked everywhere
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

    raw_url = (
        default_db_url
        or os.getenv("DATABASE_URL", "").strip()
        or os.getenv("SESSION_DB_URL", "").strip()
        or build_cloud_sql_url_from_env(async_driver=False)
        or ""
    )
    if not raw_url:
        if auth_guard.is_production_environment():
            raise RuntimeError(
                "Production persistence failure: DATABASE_URL / SESSION_DB_URL / PQC_CLOUD_SQL_CONNECTION_NAME is not configured."
            )
        data_dir = (os.getenv("PQC_DATA_DIR") or "data").strip()
        os.makedirs(data_dir, exist_ok=True)
        raw_url = f"sqlite:///{os.path.join(data_dir, 'pqc_sessions.db')}"

    norm_url = normalize_sync_db_url(raw_url)
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
