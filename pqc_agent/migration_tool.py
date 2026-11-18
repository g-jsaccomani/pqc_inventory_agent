"""Safe, idempotent, non-destructive migration from legacy SQLite + JSON/JSONL to PostgreSQL (DB-04).

Capabilities:
1. Migrates legacy JSON/JSONL persistence (``pqc_tenant_users.json``, ``tenants/*/profile.json``,
   ``pqc_session_metadata.json``, ``tenants/*/sessions/*.json``, ``pqc_user_connections.json``,
   ``tenants/*/connection.json``, ``pqc_oauth_config.json``, ``calibration-history.jsonl``) into the
   authoritative relational schema (``PqcPersistenceBase``).
2. Migrates legacy Google ADK SQLite tables (``adk_internal_metadata``, ``app_states``, ``user_states``,
   ``sessions``, ``events``) and ``pqc_auth_sessions`` into the target database while preserving user
   identities, session IDs, ownership relationships, and original timestamps.
3. Enforces strict idempotency (deterministic UUIDv5 for legacy calibration JSONL lines; primary-key
   reconciliation for users, sessions, connections, and ADK events).
4. Detects duplicates, cross-user ownership conflicts, malformed JSON rows, orphan records, and legacy
   plaintext tokens (stripping plaintext tokens rather than importing unverified secrets).
5. Validates post-migration record counts, SQL referential integrity, and SHA-256 source-file immutability
   (never deletes or modifies source files).
6. Supports ``dry_run=True`` and emits both JSON and Markdown migration audit reports.
"""

from __future__ import annotations

import dataclasses
import datetime
import glob
import hashlib
import json
import logging
import os
import sqlite3
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple
import uuid

from alembic import command as alembic_command
from alembic.config import Config as AlembicConfig
from sqlalchemy import inspect as sa_inspect, select, text

from pqc_agent import auth_guard, auth_store, credential_service

logger = logging.getLogger(__name__)

MIGRATION_NAMESPACE = uuid.UUID("7b65d912-8a42-4d7c-9c74-51a9c0de2026")


@dataclasses.dataclass
class EntityCountSummary:
    source_records_seen: int = 0
    valid_unique_source: int = 0
    inserted: int = 0
    already_present_or_updated: int = 0
    skipped_invalid_or_conflict: int = 0
    target_total_after: int = 0

    def to_dict(self) -> Dict[str, int]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class MigrationReport:
    migration_id: str
    started_at_utc: str
    completed_at_utc: str
    dry_run: bool
    source_sqlite_path: Optional[str]
    source_data_dir: Optional[str]
    target_db_redacted: str
    target_backend: str
    schema_version: Optional[str]
    status: str  # "SUCCESS" | "DRY_RUN_OK" | "FAILED_VALIDATION"
    counts: Dict[str, Dict[str, int]]
    referential_integrity: Dict[str, Any]
    anomalies: List[Dict[str, Any]]
    source_files_untouched: bool
    source_file_checksums: Dict[str, str]

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    def to_markdown(self) -> str:
        lines = [
            "# PQC Inventory Agent — Persistence Migration Report",
            "",
            f"- **Migration ID:** `{self.migration_id}`",
            f"- **Status:** `{self.status}`",
            f"- **Dry Run:** `{self.dry_run}`",
            f"- **Started (UTC):** `{self.started_at_utc}`",
            f"- **Completed (UTC):** `{self.completed_at_utc}`",
            f"- **Source SQLite:** `{self.source_sqlite_path or 'N/A'}`",
            f"- **Source Data Directory:** `{self.source_data_dir or 'N/A'}`",
            f"- **Target Database:** `{self.target_db_redacted}` (`{self.target_backend}`)",
            f"- **Target Schema Version:** `{self.schema_version}`",
            f"- **Source Files Untouched (SHA-256 Verified):** `{self.source_files_untouched}`",
            "",
            "## Entity Record Counts",
            "",
            "| Entity | Source Seen | Valid Unique | Inserted | Idempotent / Existing | Skipped / Conflict | Target Total |",
            "| :--- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
        for entity, c in self.counts.items():
            lines.append(
                f"| `{entity}` | {c['source_records_seen']} | {c['valid_unique_source']} | "
                f"{c['inserted']} | {c['already_present_or_updated']} | "
                f"{c['skipped_invalid_or_conflict']} | {c['target_total_after']} |"
            )
        lines.extend(
            [
                "",
                "## Referential Integrity Checks",
                "",
                f"- **Passed:** `{self.referential_integrity.get('passed')}`",
                f"- **Orphan Session Metadata Rows:** `{self.referential_integrity.get('orphan_session_metadata', 0)}`",
                f"- **Orphan ADK Event Rows:** `{self.referential_integrity.get('orphan_adk_events', 0)}`",
                "",
                f"## Detected Anomalies & Security Warnings ({len(self.anomalies)})",
                "",
            ]
        )
        if not self.anomalies:
            lines.append("_No duplicates, conflicts, or malformed records detected._")
        else:
            for item in self.anomalies:
                lines.append(
                    f"- **[{item.get('severity', 'WARN')}] `{item.get('code')}`** "
                    f"(`{item.get('source', 'unknown')}`): {item.get('detail')}"
                )
        lines.append("")
        return "\n".join(lines)


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _normalize_uid(raw: Any) -> str:
    val = str(raw or "").strip().lower()
    if val.startswith("accounts.google.com:"):
        val = val.split(":", 1)[1].strip()
    return val


def _is_valid_email_uid(uid: str) -> bool:
    return bool(uid and "@" in uid and not uid.startswith("@") and not uid.endswith("@") and " " not in uid)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _collect_source_checksums(sqlite_path: Optional[str], data_dir: Optional[str]) -> Dict[str, str]:
    files: List[str] = []
    if sqlite_path and os.path.isfile(sqlite_path):
        files.append(os.path.abspath(sqlite_path))
    if data_dir and os.path.isdir(data_dir):
        for root, _dirs, filenames in os.walk(data_dir):
            for fname in filenames:
                if fname.endswith((".json", ".jsonl", ".db", ".sqlite", ".sqlite3")):
                    files.append(os.path.abspath(os.path.join(root, fname)))
    checksums: Dict[str, str] = {}
    for fpath in sorted(set(files)):
        if os.path.isfile(fpath):
            checksums[fpath] = _sha256_file(fpath)
    return checksums


ALEMBIC_MIGRATION_ADVISORY_LOCK_ID = 7081632026


def run_alembic_upgrade_head(
    target_db_url: str,
    *,
    require_postgres: bool = False,
) -> str:
    """Explicitly executes ``alembic upgrade head`` and verifies the resulting schema revision.

    - Never invokes ``metadata.create_all()``.
    - Acquires a PostgreSQL session advisory lock when targeting PostgreSQL so concurrent migration runs fail fast.
    - Verifies ``EXPECTED_ALEMBIC_REVISION`` and all required PQC + ADK v1 tables after migration completes.
    """
    sync_url = auth_store.normalize_sync_db_url(target_db_url)
    auth_store.validate_production_postgres_only(sync_url)
    backend = auth_store.make_url(sync_url).get_backend_name()
    if require_postgres and backend != "postgresql":
        raise RuntimeError(
            f"Explicit PostgreSQL target is required for schema migration; rejected backend '{backend}'."
        )

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    ini_path = os.path.join(repo_root, "alembic.ini")
    cfg = AlembicConfig(ini_path if os.path.isfile(ini_path) else None)
    cfg.set_main_option("script_location", os.path.join(repo_root, "migrations"))
    cfg.set_main_option("sqlalchemy.url", sync_url)

    lock_engine = auth_store.build_sync_sqlalchemy_engine(sync_url) if backend == "postgresql" else None
    lock_conn = None
    try:
        if lock_engine is not None:
            lock_conn = lock_engine.connect()
            acquired = bool(
                lock_conn.execute(
                    text("SELECT pg_try_advisory_lock(:lock_id)"),
                    {"lock_id": ALEMBIC_MIGRATION_ADVISORY_LOCK_ID},
                ).scalar()
            )
            if not acquired:
                raise RuntimeError(
                    "Concurrent Alembic migration detected (PostgreSQL advisory lock is already held). "
                    "Run database migrations from a single migration job only."
                )
        alembic_command.upgrade(cfg, "head")
    finally:
        if lock_conn is not None:
            try:
                lock_conn.execute(
                    text("SELECT pg_advisory_unlock(:lock_id)"),
                    {"lock_id": ALEMBIC_MIGRATION_ADVISORY_LOCK_ID},
                )
            except Exception:
                pass
            lock_conn.close()
        if lock_engine is not None:
            lock_engine.dispose()

    verify_engine = auth_store.build_sync_sqlalchemy_engine(sync_url)
    try:
        verified_rev = auth_store.verify_alembic_schema_on_engine(verify_engine)
    finally:
        verify_engine.dispose()
    return verified_rev


def _load_json_file_safe(path: str, anomalies: List[Dict[str, Any]]) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        anomalies.append(
            {
                "severity": "WARN",
                "code": "MALFORMED_JSON_FILE",
                "source": path,
                "detail": f"Failed to parse JSON file: {type(exc).__name__}: {exc}",
            }
        )
        return None


def _parse_datetime_maybe(val: Any) -> Any:
    """Converts SQLite string timestamps into timezone-aware/naive datetime objects when target column expects DateTime."""
    if val is None or isinstance(val, datetime.datetime):
        return val
    if isinstance(val, (int, float)):
        return datetime.datetime.fromtimestamp(float(val), tz=datetime.timezone.utc).replace(tzinfo=None)
    if isinstance(val, str):
        raw = val.strip()
        if not raw:
            return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            dt = datetime.datetime.fromisoformat(raw)
            return dt.astimezone(datetime.timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt
        except ValueError:
            for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
                try:
                    return datetime.datetime.strptime(raw, fmt)
                except ValueError:
                    continue
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def _parse_json_col_maybe(val: Any, default: Any) -> Any:
    if val is None:
        return default
    if isinstance(val, (dict, list)):
        return val
    if isinstance(val, (bytes, bytearray)):
        try:
            return json.loads(val.decode("utf-8"))
        except Exception:
            return default
    if isinstance(val, str):
        raw = val.strip()
        if not raw:
            return default
        try:
            return json.loads(raw)
        except Exception:
            return default
    return default


def migrate_legacy_persistence(
    *,
    target_db_url: str,
    source_sqlite_path: Optional[str] = None,
    source_data_dir: Optional[str] = None,
    dry_run: bool = False,
    allow_production_target: bool = False,
    report_json_path: Optional[str] = None,
    report_markdown_path: Optional[str] = None,
) -> MigrationReport:
    """Executes an idempotent, validated migration from legacy SQLite + JSON/JSONL to the target database."""
    if auth_guard.is_production_environment() and not allow_production_target:
        raise RuntimeError(
            "Refusing automatic migration execution while PQC production environment flags are active. "
            "Run against staging/disposable data first or pass allow_production_target=True explicitly."
        )

    started_at = _utc_now_iso()
    migration_id = f"mig-{uuid.uuid4().hex[:12]}"
    anomalies: List[Dict[str, Any]] = []

    if source_sqlite_path and os.path.exists(source_sqlite_path):
        abs_src_sqlite = os.path.abspath(source_sqlite_path)
    else:
        abs_src_sqlite = None
        if source_sqlite_path:
            anomalies.append(
                {
                    "severity": "INFO",
                    "code": "SOURCE_SQLITE_NOT_FOUND",
                    "source": source_sqlite_path,
                    "detail": "Source SQLite file does not exist; skipping SQLite table import.",
                }
            )

    abs_data_dir = os.path.abspath(source_data_dir) if (source_data_dir and os.path.isdir(source_data_dir)) else None
    checksums_before = _collect_source_checksums(abs_src_sqlite, abs_data_dir)

    sync_target_url = auth_store.normalize_sync_db_url(target_db_url)
    if abs_src_sqlite and sync_target_url.startswith("sqlite:///"):
        target_sqlite_file = os.path.abspath(sync_target_url[len("sqlite:///") :])
        if target_sqlite_file == abs_src_sqlite:
            raise ValueError("Target database URL must not point to the same file as source_sqlite_path.")

    # Initialize schema exclusively via Alembic (never metadata.create_all).
    run_alembic_upgrade_head(sync_target_url, require_postgres=auth_guard.is_production_environment())

    store = auth_store.DistributedAuthStore(
        sync_target_url,
        create_schema=False,
        verify_connectivity=True,
        verify_schema=True,
    )
    cred_svc = credential_service.EncryptedDatabaseCredentialService(store=store)

    counts: Dict[str, EntityCountSummary] = {
        "tenant_users": EntityCountSummary(),
        "session_metadata": EntityCountSummary(),
        "user_connections": EntityCountSummary(),
        "oauth_client_configs": EntityCountSummary(),
        "calibration_events": EntityCountSummary(),
        "auth_sessions": EntityCountSummary(),
        "adk_app_states": EntityCountSummary(),
        "adk_user_states": EntityCountSummary(),
        "adk_sessions": EntityCountSummary(),
        "adk_events": EntityCountSummary(),
    }

    try:
        # ------------------------------------------------------------------
        # Step 1: Collect & Reconcile Legacy JSON/JSONL Records in Memory
        # ------------------------------------------------------------------
        reconciled_users: Dict[str, Dict[str, Any]] = {}
        reconciled_sessions: Dict[str, Dict[str, Any]] = {}
        reconciled_connections: Dict[str, Dict[str, Any]] = {}
        oauth_cfg_candidate: Optional[Dict[str, Any]] = None
        reconciled_calibrations: Dict[str, Dict[str, Any]] = {}

        if abs_data_dir:
            # 1a. Tenant user profiles (global + partitioned)
            global_users_path = os.path.join(abs_data_dir, "pqc_tenant_users.json")
            if os.path.isfile(global_users_path):
                raw_users = _load_json_file_safe(global_users_path, anomalies)
                if isinstance(raw_users, dict):
                    for raw_k, prof in raw_users.items():
                        counts["tenant_users"].source_records_seen += 1
                        if not isinstance(prof, dict):
                            counts["tenant_users"].skipped_invalid_or_conflict += 1
                            anomalies.append(
                                {
                                    "severity": "WARN",
                                    "code": "INVALID_USER_RECORD",
                                    "source": global_users_path,
                                    "detail": f"Non-object profile under key '{raw_k}'.",
                                }
                            )
                            continue
                        uid = _normalize_uid(prof.get("email") or prof.get("user_id") or raw_k)
                        if not _is_valid_email_uid(uid):
                            counts["tenant_users"].skipped_invalid_or_conflict += 1
                            anomalies.append(
                                {
                                    "severity": "WARN",
                                    "code": "INVALID_USER_EMAIL",
                                    "source": global_users_path,
                                    "detail": f"Rejected malformed user identifier '{uid}'.",
                                }
                            )
                            continue
                        reconciled_users[uid] = dict(prof, user_id=uid, email=uid)

            for prof_path in sorted(glob.glob(os.path.join(abs_data_dir, "tenants", "*", "profile.json"))):
                counts["tenant_users"].source_records_seen += 1
                prof = _load_json_file_safe(prof_path, anomalies)
                folder_uid = _normalize_uid(os.path.basename(os.path.dirname(prof_path)))
                if not isinstance(prof, dict):
                    counts["tenant_users"].skipped_invalid_or_conflict += 1
                    continue
                uid = _normalize_uid(prof.get("email") or prof.get("user_id") or folder_uid)
                if folder_uid and uid and folder_uid != uid:
                    anomalies.append(
                        {
                            "severity": "WARN",
                            "code": "TENANT_DIR_EMAIL_MISMATCH",
                            "source": prof_path,
                            "detail": f"Partition directory '{folder_uid}' differs from profile email '{uid}'; using '{uid}'.",
                        }
                    )
                if not _is_valid_email_uid(uid):
                    counts["tenant_users"].skipped_invalid_or_conflict += 1
                    anomalies.append(
                        {
                            "severity": "WARN",
                            "code": "INVALID_USER_EMAIL",
                            "source": prof_path,
                            "detail": f"Rejected malformed user identifier '{uid}'.",
                        }
                    )
                    continue
                if uid in reconciled_users:
                    prev = reconciled_users[uid]
                    if prev.get("region") and prof.get("region") and prev.get("region") != prof.get("region"):
                        anomalies.append(
                            {
                                "severity": "INFO",
                                "code": "DUPLICATE_USER_PROFILE_MERGED",
                                "source": prof_path,
                                "detail": f"Merged conflicting region ('{prev.get('region')}' vs '{prof.get('region')}') for '{uid}' using latest login timestamp.",
                            }
                        )
                    earliest_created = min(
                        str(prev.get("created_at") or "9999"),
                        str(prof.get("created_at") or "9999"),
                    )
                    newer = prof if str(prof.get("last_login_at") or "") >= str(prev.get("last_login_at") or "") else prev
                    merged = dict(prev)
                    merged.update(newer)
                    if earliest_created != "9999":
                        merged["created_at"] = earliest_created
                    merged["user_id"] = uid
                    merged["email"] = uid
                    reconciled_users[uid] = merged
                else:
                    reconciled_users[uid] = dict(prof, user_id=uid, email=uid)

            # 1b. Session Metadata (global + partitioned)
            global_smeta_path = os.path.join(abs_data_dir, "pqc_session_metadata.json")
            if os.path.isfile(global_smeta_path):
                raw_smeta = _load_json_file_safe(global_smeta_path, anomalies)
                if isinstance(raw_smeta, dict):
                    for sid, meta in raw_smeta.items():
                        counts["session_metadata"].source_records_seen += 1
                        clean_sid = str(sid or "").strip()
                        if not clean_sid or not isinstance(meta, dict):
                            counts["session_metadata"].skipped_invalid_or_conflict += 1
                            continue
                        owner = _normalize_uid(meta.get("user_id"))
                        if not _is_valid_email_uid(owner):
                            counts["session_metadata"].skipped_invalid_or_conflict += 1
                            anomalies.append(
                                {
                                    "severity": "WARN",
                                    "code": "ORPHAN_SESSION_METADATA_NO_OWNER",
                                    "source": global_smeta_path,
                                    "detail": f"Session metadata '{clean_sid}' has missing/invalid owner '{owner}'; skipped.",
                                }
                            )
                            continue
                        reconciled_sessions[clean_sid] = dict(meta, session_id=clean_sid, user_id=owner)

            for smeta_path in sorted(glob.glob(os.path.join(abs_data_dir, "tenants", "*", "sessions", "*.json"))):
                counts["session_metadata"].source_records_seen += 1
                meta = _load_json_file_safe(smeta_path, anomalies)
                if not isinstance(meta, dict):
                    counts["session_metadata"].skipped_invalid_or_conflict += 1
                    continue
                parts = smeta_path.split(os.sep)
                tenants_idx = len(parts) - 4
                folder_uid = _normalize_uid(parts[tenants_idx + 1]) if tenants_idx >= 0 else ""
                file_sid = os.path.splitext(os.path.basename(smeta_path))[0].strip()
                clean_sid = str(meta.get("session_id") or file_sid).strip()
                owner = _normalize_uid(meta.get("user_id") or folder_uid)
                if folder_uid and owner and folder_uid != owner:
                    counts["session_metadata"].skipped_invalid_or_conflict += 1
                    anomalies.append(
                        {
                            "severity": "ERROR",
                            "code": "INCONSISTENT_SESSION_OWNER_PARTITION",
                            "source": smeta_path,
                            "detail": f"Session '{clean_sid}' partition '{folder_uid}' conflicts with payload user_id '{owner}'; skipped.",
                        }
                    )
                    continue
                if not clean_sid or not _is_valid_email_uid(owner):
                    counts["session_metadata"].skipped_invalid_or_conflict += 1
                    continue
                if clean_sid in reconciled_sessions:
                    existing_owner = reconciled_sessions[clean_sid]["user_id"]
                    if existing_owner != owner:
                        counts["session_metadata"].skipped_invalid_or_conflict += 1
                        anomalies.append(
                            {
                                "severity": "ERROR",
                                "code": "DUPLICATE_SESSION_ID_CROSS_USER_CONFLICT",
                                "source": smeta_path,
                                "detail": (
                                    f"Session '{clean_sid}' claimed by both '{existing_owner}' and '{owner}'; "
                                    f"preserving first owner '{existing_owner}' and rejecting conflicting duplicate."
                                ),
                            }
                        )
                        continue
                    # Same owner: merge keeping newest updated_at
                    prev_s = reconciled_sessions[clean_sid]
                    if str(meta.get("updated_at") or "") >= str(prev_s.get("updated_at") or ""):
                        merged_s = dict(prev_s)
                        merged_s.update(meta)
                        merged_s["session_id"] = clean_sid
                        merged_s["user_id"] = owner
                        reconciled_sessions[clean_sid] = merged_s
                else:
                    reconciled_sessions[clean_sid] = dict(meta, session_id=clean_sid, user_id=owner)

            # 1c. User GCP Connections (global + partitioned) — strip any legacy plaintext tokens!
            def _ingest_conn(uid_hint: str, raw_conn: Any, src_label: str) -> None:
                counts["user_connections"].source_records_seen += 1
                if not isinstance(raw_conn, dict):
                    counts["user_connections"].skipped_invalid_or_conflict += 1
                    return
                uid = _normalize_uid(raw_conn.get("user_id") or uid_hint)
                if not _is_valid_email_uid(uid):
                    counts["user_connections"].skipped_invalid_or_conflict += 1
                    anomalies.append(
                        {
                            "severity": "WARN",
                            "code": "INVALID_CONNECTION_USER",
                            "source": src_label,
                            "detail": f"Skipped connection config with invalid user_id '{uid}'.",
                        }
                    )
                    return
                cleaned = dict(raw_conn)
                for secret_field in ("access_token", "refresh_token", "token", "id_token", "client_secret"):
                    if cleaned.pop(secret_field, None):
                        anomalies.append(
                            {
                                "severity": "WARN",
                                "code": "LEGACY_PLAINTEXT_TOKEN_STRIPPED",
                                "source": src_label,
                                "detail": f"Stripped legacy plaintext '{secret_field}' for '{uid}'; user must re-authorize via PKCE.",
                            }
                        )
                mode = str(cleaned.get("mode") or "adc").strip().lower()
                if mode == "access_token":
                    mode = "adc"
                cleaned["user_id"] = uid
                cleaned["mode"] = mode
                prev_c = reconciled_connections.get(uid)
                if prev_c is None or str(cleaned.get("updated_at") or "") >= str(prev_c.get("updated_at") or ""):
                    reconciled_connections[uid] = cleaned

            global_conn_path = os.path.join(abs_data_dir, "pqc_user_connections.json")
            if os.path.isfile(global_conn_path):
                raw_conns = _load_json_file_safe(global_conn_path, anomalies)
                if isinstance(raw_conns, dict):
                    for k_uid, c_obj in raw_conns.items():
                        _ingest_conn(k_uid, c_obj, global_conn_path)

            for conn_path in sorted(glob.glob(os.path.join(abs_data_dir, "tenants", "*", "connection.json"))):
                folder_uid = _normalize_uid(os.path.basename(os.path.dirname(conn_path)))
                c_obj = _load_json_file_safe(conn_path, anomalies)
                _ingest_conn(folder_uid, c_obj, conn_path)

            # 1d. OAuth Client Config
            oauth_cfg_path = os.path.join(abs_data_dir, "pqc_oauth_config.json")
            if os.path.isfile(oauth_cfg_path):
                counts["oauth_client_configs"].source_records_seen += 1
                raw_ocfg = _load_json_file_safe(oauth_cfg_path, anomalies)
                if isinstance(raw_ocfg, dict) and (raw_ocfg.get("client_id") or raw_ocfg.get("client_secret")):
                    oauth_cfg_candidate = raw_ocfg
                else:
                    counts["oauth_client_configs"].skipped_invalid_or_conflict += 1

            # 1e. Calibration History JSONL
            cal_jsonl_path = os.path.join(abs_data_dir, "calibration-history.jsonl")
            if os.path.isfile(cal_jsonl_path):
                with open(cal_jsonl_path, "r", encoding="utf-8") as fh:
                    for line_no, raw_line in enumerate(fh, start=1):
                        stripped = raw_line.strip()
                        if not stripped:
                            continue
                        counts["calibration_events"].source_records_seen += 1
                        try:
                            entry = json.loads(stripped)
                        except Exception as exc:
                            counts["calibration_events"].skipped_invalid_or_conflict += 1
                            anomalies.append(
                                {
                                    "severity": "WARN",
                                    "code": "MALFORMED_CALIBRATION_JSONL_LINE",
                                    "source": f"{cal_jsonl_path}:{line_no}",
                                    "detail": f"Malformed JSONL line {line_no}: {exc}",
                                }
                            )
                            continue
                        if not isinstance(entry, dict):
                            counts["calibration_events"].skipped_invalid_or_conflict += 1
                            continue
                        canonical_fp = json.dumps(
                            {
                                "scope": entry.get("scope", "organizations/unspecified"),
                                "user_id": _normalize_uid(entry.get("user_id") or "legacy@google.com"),
                                "timestamp_utc": entry.get("timestamp_utc", ""),
                                "industry_sector": entry.get("industry_sector", "custom"),
                                "x": entry.get("confidentiality_years_x", 10.0),
                                "y": entry.get("migration_years_y", 3.0),
                                "z": entry.get("crqc_horizon_years_z", 10.0),
                            },
                            sort_keys=True,
                        )
                        ev_uuid = str(
                            entry.get("event_uuid") or uuid.uuid5(MIGRATION_NAMESPACE, canonical_fp)
                        )
                        if ev_uuid in reconciled_calibrations:
                            counts["calibration_events"].skipped_invalid_or_conflict += 1
                            anomalies.append(
                                {
                                    "severity": "INFO",
                                    "code": "DUPLICATE_CALIBRATION_EVENT_DEDUPED",
                                    "source": f"{cal_jsonl_path}:{line_no}",
                                    "detail": f"Deduplicated identical calibration event '{ev_uuid}'.",
                                }
                            )
                            continue
                        entry_copy = dict(entry, event_uuid=ev_uuid)
                        reconciled_calibrations[ev_uuid] = entry_copy

        # ------------------------------------------------------------------
        # Step 2: Inspect Legacy SQLite Database (ADK + Auth Sessions)
        # ------------------------------------------------------------------
        sqlite_adk_app_states: List[Dict[str, Any]] = []
        sqlite_adk_user_states: List[Dict[str, Any]] = []
        sqlite_adk_sessions: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        sqlite_adk_events: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
        sqlite_auth_sessions: Dict[str, Dict[str, Any]] = {}

        if abs_src_sqlite:
            ro_uri = f"file:{abs_src_sqlite}?mode=ro"
            conn_sq = sqlite3.connect(ro_uri, uri=True)
            conn_sq.row_factory = sqlite3.Row
            try:
                tables = {
                    r["name"]
                    for r in conn_sq.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                }
                if "app_states" in tables:
                    for r in conn_sq.execute("SELECT * FROM app_states").fetchall():
                        counts["adk_app_states"].source_records_seen += 1
                        sqlite_adk_app_states.append(dict(r))

                if "user_states" in tables:
                    for r in conn_sq.execute("SELECT * FROM user_states").fetchall():
                        counts["adk_user_states"].source_records_seen += 1
                        row_d = dict(r)
                        row_d["user_id"] = _normalize_uid(row_d.get("user_id"))
                        if not row_d["user_id"]:
                            counts["adk_user_states"].skipped_invalid_or_conflict += 1
                            continue
                        sqlite_adk_user_states.append(row_d)

                if "sessions" in tables:
                    for r in conn_sq.execute("SELECT * FROM sessions").fetchall():
                        counts["adk_sessions"].source_records_seen += 1
                        row_d = dict(r)
                        app_n = str(row_d.get("app_name") or "").strip()
                        uid = _normalize_uid(row_d.get("user_id"))
                        sid = str(row_d.get("id") or "").strip()
                        if not app_n or not uid or not sid:
                            counts["adk_sessions"].skipped_invalid_or_conflict += 1
                            anomalies.append(
                                {
                                    "severity": "WARN",
                                    "code": "INVALID_ADK_SESSION_PK",
                                    "source": f"{abs_src_sqlite}:sessions",
                                    "detail": f"Skipped ADK session with incomplete key ({app_n!r}, {uid!r}, {sid!r}).",
                                }
                            )
                            continue
                        row_d["user_id"] = uid
                        key = (app_n, uid, sid)
                        if key in sqlite_adk_sessions:
                            counts["adk_sessions"].skipped_invalid_or_conflict += 1
                            anomalies.append(
                                {
                                    "severity": "WARN",
                                    "code": "DUPLICATE_ADK_SESSION_KEY",
                                    "source": f"{abs_src_sqlite}:sessions",
                                    "detail": f"Duplicate normalized ADK session key {key}; keeping latest.",
                                }
                            )
                        sqlite_adk_sessions[key] = row_d
                        # Ensure parent tenant user exists if valid email
                        if _is_valid_email_uid(uid) and uid not in reconciled_users:
                            now_iso = _utc_now_iso()
                            reconciled_users[uid] = {
                                "user_id": uid,
                                "email": uid,
                                "name": uid.split("@", 1)[0],
                                "region": "NorthAm",
                                "timezone": "UTC",
                                "auth_method": "migrated_adk_session",
                                "picture": "",
                                "created_at": str(row_d.get("create_time") or now_iso),
                                "last_login_at": str(row_d.get("update_time") or now_iso),
                            }
                            anomalies.append(
                                {
                                    "severity": "INFO",
                                    "code": "SYNTHESIZED_MISSING_PARENT_USER",
                                    "source": f"{abs_src_sqlite}:sessions",
                                    "detail": f"Synthesized parent pqc_tenant_users record for ADK session owner '{uid}'.",
                                }
                            )

                if "events" in tables:
                    for r in conn_sq.execute("SELECT * FROM events").fetchall():
                        counts["adk_events"].source_records_seen += 1
                        row_d = dict(r)
                        ev_id = str(row_d.get("id") or "").strip()
                        app_n = str(row_d.get("app_name") or "").strip()
                        uid = _normalize_uid(row_d.get("user_id"))
                        sid = str(row_d.get("session_id") or "").strip()
                        if not ev_id or (app_n, uid, sid) not in sqlite_adk_sessions:
                            counts["adk_events"].skipped_invalid_or_conflict += 1
                            anomalies.append(
                                {
                                    "severity": "WARN",
                                    "code": "ORPHAN_ADK_EVENT_SKIPPED",
                                    "source": f"{abs_src_sqlite}:events",
                                    "detail": f"Skipped orphan ADK event '{ev_id}' referencing missing session ({app_n!r}, {uid!r}, {sid!r}).",
                                }
                            )
                            continue
                        row_d["user_id"] = uid
                        sqlite_adk_events[(ev_id, app_n, uid, sid)] = row_d

                if "pqc_auth_sessions" in tables:
                    for r in conn_sq.execute("SELECT * FROM pqc_auth_sessions").fetchall():
                        counts["auth_sessions"].source_records_seen += 1
                        row_d = dict(r)
                        jti = str(row_d.get("jti") or "").strip()
                        if not jti:
                            counts["auth_sessions"].skipped_invalid_or_conflict += 1
                            continue
                        sqlite_auth_sessions[jti] = row_d
            finally:
                conn_sq.close()

        # Also synthesize parent users for session_metadata owners missing a profile.json
        for sid, smeta in list(reconciled_sessions.items()):
            owner = smeta["user_id"]
            if owner not in reconciled_users:
                now_iso = _utc_now_iso()
                reconciled_users[owner] = {
                    "user_id": owner,
                    "email": owner,
                    "name": owner.split("@", 1)[0],
                    "region": "NorthAm",
                    "timezone": "UTC",
                    "auth_method": "migrated_session_owner",
                    "picture": "",
                    "created_at": str(smeta.get("created_at") or now_iso),
                    "last_login_at": str(smeta.get("updated_at") or now_iso),
                }
                anomalies.append(
                    {
                        "severity": "INFO",
                        "code": "SYNTHESIZED_MISSING_PARENT_USER",
                        "source": f"session_metadata:{sid}",
                        "detail": f"Synthesized parent pqc_tenant_users record for session '{sid}' owner '{owner}'.",
                    }
                )

        counts["tenant_users"].valid_unique_source = len(reconciled_users)
        counts["session_metadata"].valid_unique_source = len(reconciled_sessions)
        counts["user_connections"].valid_unique_source = len(reconciled_connections)
        counts["oauth_client_configs"].valid_unique_source = 1 if oauth_cfg_candidate else 0
        counts["calibration_events"].valid_unique_source = len(reconciled_calibrations)
        counts["auth_sessions"].valid_unique_source = len(sqlite_auth_sessions)
        counts["adk_app_states"].valid_unique_source = len(sqlite_adk_app_states)
        counts["adk_user_states"].valid_unique_source = len(sqlite_adk_user_states)
        counts["adk_sessions"].valid_unique_source = len(sqlite_adk_sessions)
        counts["adk_events"].valid_unique_source = len(sqlite_adk_events)

        # ADK v1 tables are created by Alembic revision 20261117_0002 via run_alembic_upgrade_head above.
        has_adk_source = bool(
            sqlite_adk_app_states or sqlite_adk_user_states or sqlite_adk_sessions or sqlite_adk_events
        )
        from google.adk.sessions.schemas import v1 as adk_schema_v1

        # ------------------------------------------------------------------
        # Step 3: Execute Transactional Upserts (Committed or Rolled Back on dry_run)
        # ------------------------------------------------------------------
        with store.engine.connect() as conn:
            trans = conn.begin()
            try:
                db = store._session_factory(bind=conn)
                try:
                    # 3a. Tenant users
                    for uid, prof in sorted(reconciled_users.items()):
                        existing_u = db.get(auth_store.TenantUserRecord, uid)
                        domain = auth_store.extract_tenant_domain(uid)
                        now_iso = _utc_now_iso()
                        if existing_u is None:
                            db.add(
                                auth_store.TenantUserRecord(
                                    user_id=uid,
                                    email=uid,
                                    tenant_domain=domain,
                                    name=str(prof.get("name") or uid.split("@", 1)[0])[:255],
                                    region=str(prof.get("region") or "NorthAm")[:64],
                                    timezone=str(prof.get("timezone") or "UTC")[:128],
                                    auth_method=str(prof.get("auth_method") or "google_workspace_signin")[:64],
                                    picture=str(prof.get("picture") or "")[:2048],
                                    created_at=str(prof.get("created_at") or now_iso),
                                    last_login_at=str(prof.get("last_login_at") or now_iso),
                                )
                            )
                            counts["tenant_users"].inserted += 1
                        else:
                            counts["tenant_users"].already_present_or_updated += 1
                    db.flush()

                    # 3b. Session metadata
                    for sid, smeta in sorted(reconciled_sessions.items()):
                        existing_s = db.get(auth_store.SessionMetadataRecord, sid)
                        owner = smeta["user_id"]
                        domain = auth_store.extract_tenant_domain(owner)
                        now_iso = _utc_now_iso()
                        if existing_s is None:
                            att = smeta.get("attachments_by_turn")
                            tel = smeta.get("turn_telemetry")
                            fb = smeta.get("fallback_messages")
                            db.add(
                                auth_store.SessionMetadataRecord(
                                    session_id=sid,
                                    user_id=owner,
                                    tenant_domain=domain,
                                    title=str(smeta.get("title") or "Migrated PQC Assessment")[:512],
                                    scope=str(smeta.get("scope") or "organizations/31564119954")[:512],
                                    model_id=smeta.get("model_id"),
                                    model_label=smeta.get("model_label"),
                                    message_count=int(smeta.get("message_count") or 0),
                                    attachments_json=json.dumps(att if isinstance(att, list) else [], ensure_ascii=False),
                                    turn_telemetry_json=json.dumps(
                                        tel if isinstance(tel, dict) else {}, ensure_ascii=False, default=str
                                    ),
                                    fallback_messages_json=(
                                        json.dumps(fb, ensure_ascii=False, default=str) if fb else None
                                    ),
                                    created_at=str(smeta.get("created_at") or now_iso),
                                    updated_at=str(smeta.get("updated_at") or now_iso),
                                )
                            )
                            counts["session_metadata"].inserted += 1
                        else:
                            if existing_s.user_id.lower() != owner:
                                counts["session_metadata"].skipped_invalid_or_conflict += 1
                                anomalies.append(
                                    {
                                        "severity": "ERROR",
                                        "code": "TARGET_SESSION_OWNER_CONFLICT",
                                        "source": f"session_metadata:{sid}",
                                        "detail": (
                                            f"Target DB already has session '{sid}' owned by '{existing_s.user_id}'; "
                                            f"refusing overwrite by '{owner}'."
                                        ),
                                    }
                                )
                            else:
                                counts["session_metadata"].already_present_or_updated += 1
                    db.flush()

                    # 3c. User connections
                    for uid, c_obj in sorted(reconciled_connections.items()):
                        existing_c = db.get(auth_store.UserConnectionRecord, uid)
                        domain = auth_store.extract_tenant_domain(uid)
                        now_iso = _utc_now_iso()
                        sa_val = str(c_obj.get("impersonated_service_account") or "").strip()
                        if sa_val and not sa_val.endswith(".iam.gserviceaccount.com"):
                            anomalies.append(
                                {
                                    "severity": "WARN",
                                    "code": "INVALID_IMPERSONATED_SA_CLEARED",
                                    "source": f"user_connections:{uid}",
                                    "detail": f"Cleared malformed service account '{sa_val}' during migration.",
                                }
                            )
                            sa_val = ""
                        if existing_c is None:
                            db.add(
                                auth_store.UserConnectionRecord(
                                    user_id=uid,
                                    tenant_domain=domain,
                                    mode=str(c_obj.get("mode") or "adc")[:32],
                                    organization_id=str(c_obj.get("organization_id") or "31564119954")[:128],
                                    project_id=str(c_obj.get("project_id") or "pqc-inventory-agent-cd06")[:255],
                                    location=str(c_obj.get("location") or "all")[:128],
                                    impersonated_service_account=sa_val[:320],
                                    updated_at=str(c_obj.get("updated_at") or now_iso),
                                )
                            )
                            counts["user_connections"].inserted += 1
                        else:
                            counts["user_connections"].already_present_or_updated += 1
                    db.flush()

                    # 3d. OAuth Client Config (envelope-encrypt secret!)
                    if oauth_cfg_candidate:
                        existing_ocfg = db.get(auth_store.OAuthClientConfigRecord, "global")
                        if existing_ocfg is None:
                            raw_sec = str(oauth_cfg_candidate.get("client_secret") or "").strip()
                            enc_sec = cred_svc.encrypt_config_secret(raw_sec, config_key="global") if raw_sec else None
                            db.add(
                                auth_store.OAuthClientConfigRecord(
                                    config_key="global",
                                    client_id=str(oauth_cfg_candidate.get("client_id") or "").strip(),
                                    encrypted_client_secret=enc_sec,
                                    updated_by="migration_tool",
                                    updated_at=str(oauth_cfg_candidate.get("updated_at") or _utc_now_iso()),
                                )
                            )
                            counts["oauth_client_configs"].inserted += 1
                        else:
                            counts["oauth_client_configs"].already_present_or_updated += 1
                    db.flush()

                    # 3e. Calibration events (idempotent on event_uuid)
                    for ev_uuid, entry in reconciled_calibrations.items():
                        existing_ev = db.scalars(
                            select(auth_store.CalibrationEventRecord).where(
                                auth_store.CalibrationEventRecord.event_uuid == ev_uuid
                            )
                        ).one_or_none()
                        if existing_ev is None:
                            uid = _normalize_uid(entry.get("user_id") or "legacy@google.com")
                            db.add(
                                auth_store.CalibrationEventRecord(
                                    event_uuid=ev_uuid,
                                    scope=str(entry.get("scope") or "organizations/unspecified")[:512],
                                    user_id=uid[:320],
                                    tenant_domain=auth_store.extract_tenant_domain(uid),
                                    industry_sector=str(entry.get("industry_sector") or "custom")[:64],
                                    sector_label=str(entry.get("sector_label") or "Custom")[:255],
                                    confidentiality_years_x=float(entry.get("confidentiality_years_x") or 10.0),
                                    migration_years_y=float(entry.get("migration_years_y") or 3.0),
                                    crqc_horizon_years_z=float(entry.get("crqc_horizon_years_z") or 10.0),
                                    gateway_header_limit_kb=int(entry.get("gateway_header_limit_kb") or 8),
                                    entry_json=json.dumps(entry, ensure_ascii=False, default=str),
                                    timestamp_utc=str(entry.get("timestamp_utc") or _utc_now_iso()),
                                )
                            )
                            counts["calibration_events"].inserted += 1
                        else:
                            counts["calibration_events"].already_present_or_updated += 1
                    db.flush()

                    # 3f. Auth sessions
                    for jti, srow in sqlite_auth_sessions.items():
                        existing_as = db.get(auth_store.AuthSessionRecord, jti)
                        if existing_as is None:
                            db.add(
                                auth_store.AuthSessionRecord(
                                    jti=jti,
                                    token_sha256=str(srow["token_sha256"]),
                                    user_id=_normalize_uid(srow["user_id"]),
                                    email=_normalize_uid(srow["email"]),
                                    region=str(srow.get("region") or "NorthAm"),
                                    auth_method=str(srow.get("auth_method") or "google_workspace_signin"),
                                    issued_at=float(srow["issued_at"]),
                                    expires_at=float(srow["expires_at"]),
                                    revoked_at=float(srow["revoked_at"]) if srow.get("revoked_at") is not None else None,
                                    revocation_reason=srow.get("revocation_reason"),
                                )
                            )
                            counts["auth_sessions"].inserted += 1
                        else:
                            counts["auth_sessions"].already_present_or_updated += 1
                    db.flush()

                    # 3g. Google ADK tables (v1 schema)
                    if has_adk_source:
                        from google.adk.sessions.migration import _schema_check_utils

                        meta_row = db.get(adk_schema_v1.StorageMetadata, _schema_check_utils.SCHEMA_VERSION_KEY)
                        if meta_row is None:
                            db.add(
                                adk_schema_v1.StorageMetadata(
                                    key=_schema_check_utils.SCHEMA_VERSION_KEY,
                                    value=_schema_check_utils.LATEST_SCHEMA_VERSION,
                                )
                            )
                        for arow in sqlite_adk_app_states:
                            app_n = str(arow["app_name"])
                            if db.get(adk_schema_v1.StorageAppState, app_n) is None:
                                db.add(
                                    adk_schema_v1.StorageAppState(
                                        app_name=app_n,
                                        state=_parse_json_col_maybe(arow.get("state"), {}),
                                        update_time=_parse_datetime_maybe(arow.get("update_time")),
                                    )
                                )
                                counts["adk_app_states"].inserted += 1
                            else:
                                counts["adk_app_states"].already_present_or_updated += 1

                        for urow in sqlite_adk_user_states:
                            pk_u = (str(urow["app_name"]), str(urow["user_id"]))
                            if db.get(adk_schema_v1.StorageUserState, pk_u) is None:
                                db.add(
                                    adk_schema_v1.StorageUserState(
                                        app_name=pk_u[0],
                                        user_id=pk_u[1],
                                        state=_parse_json_col_maybe(urow.get("state"), {}),
                                        update_time=_parse_datetime_maybe(urow.get("update_time")),
                                    )
                                )
                                counts["adk_user_states"].inserted += 1
                            else:
                                counts["adk_user_states"].already_present_or_updated += 1
                        db.flush()

                        for pk_s, s_adk in sqlite_adk_sessions.items():
                            if db.get(adk_schema_v1.StorageSession, pk_s) is None:
                                db.add(
                                    adk_schema_v1.StorageSession(
                                        app_name=pk_s[0],
                                        user_id=pk_s[1],
                                        id=pk_s[2],
                                        state=_parse_json_col_maybe(s_adk.get("state"), {}),
                                        create_time=_parse_datetime_maybe(s_adk.get("create_time")),
                                        update_time=_parse_datetime_maybe(s_adk.get("update_time")),
                                    )
                                )
                                counts["adk_sessions"].inserted += 1
                            else:
                                counts["adk_sessions"].already_present_or_updated += 1
                        db.flush()

                        for pk_e, ev_adk in sqlite_adk_events.items():
                            if db.get(adk_schema_v1.StorageEvent, pk_e) is None:
                                event_data = _parse_json_col_maybe(ev_adk.get("event_data"), None)
                                if event_data is None:
                                    # Legacy ADK v0 columns fallback -> synthesize minimal event_data envelope
                                    event_data = {
                                        "id": pk_e[0],
                                        "author": ev_adk.get("author") or "user",
                                        "invocation_id": ev_adk.get("invocation_id") or "",
                                        "content": _parse_json_col_maybe(ev_adk.get("content"), None),
                                    }
                                db.add(
                                    adk_schema_v1.StorageEvent(
                                        id=pk_e[0],
                                        app_name=pk_e[1],
                                        user_id=pk_e[2],
                                        session_id=pk_e[3],
                                        invocation_id=str(ev_adk.get("invocation_id") or ""),
                                        timestamp=_parse_datetime_maybe(ev_adk.get("timestamp")),
                                        event_data=event_data,
                                    )
                                )
                                counts["adk_events"].inserted += 1
                            else:
                                counts["adk_events"].already_present_or_updated += 1
                        db.flush()

                    # ------------------------------------------------------------------
                    # Step 4: Validate Target Record Counts & Referential Integrity
                    # ------------------------------------------------------------------
                    table_map: Sequence[Tuple[str, str]] = [
                        ("tenant_users", "pqc_tenant_users"),
                        ("session_metadata", "pqc_session_metadata"),
                        ("user_connections", "pqc_user_connections"),
                        ("oauth_client_configs", "pqc_oauth_client_configs"),
                        ("calibration_events", "pqc_calibration_events"),
                        ("auth_sessions", "pqc_auth_sessions"),
                    ]
                    inspector = sa_inspect(conn)
                    existing_tables = set(inspector.get_table_names())
                    for key_name, tbl_name in table_map:
                        if tbl_name in existing_tables:
                            counts[key_name].target_total_after = int(
                                conn.execute(text(f"SELECT COUNT(*) FROM {tbl_name}")).scalar_one()
                            )

                    for key_name, tbl_name in [
                        ("adk_app_states", "app_states"),
                        ("adk_user_states", "user_states"),
                        ("adk_sessions", "sessions"),
                        ("adk_events", "events"),
                    ]:
                        if tbl_name in existing_tables:
                            counts[key_name].target_total_after = int(
                                conn.execute(text(f"SELECT COUNT(*) FROM {tbl_name}")).scalar_one()
                            )

                    orphan_smeta = int(
                        conn.execute(
                            text(
                                "SELECT COUNT(*) FROM pqc_session_metadata sm "
                                "LEFT JOIN pqc_tenant_users tu ON sm.user_id = tu.user_id "
                                "WHERE tu.user_id IS NULL"
                            )
                        ).scalar_one()
                    )
                    orphan_events = 0
                    if "events" in existing_tables and "sessions" in existing_tables:
                        orphan_events = int(
                            conn.execute(
                                text(
                                    "SELECT COUNT(*) FROM events e "
                                    "LEFT JOIN sessions s "
                                    "ON e.app_name = s.app_name AND e.user_id = s.user_id AND e.session_id = s.id "
                                    "WHERE s.id IS NULL"
                                )
                            ).scalar_one()
                        )

                    count_checks_passed = all(
                        c.target_total_after >= c.valid_unique_source
                        and (c.inserted + c.already_present_or_updated + c.skipped_invalid_or_conflict)
                        >= c.valid_unique_source
                        for c in counts.values()
                    )
                    fk_passed = orphan_smeta == 0 and orphan_events == 0
                    referential_integrity = {
                        "passed": bool(fk_passed and count_checks_passed),
                        "orphan_session_metadata": orphan_smeta,
                        "orphan_adk_events": orphan_events,
                        "count_reconciliation_passed": count_checks_passed,
                    }

                    schema_ver_row = db.get(auth_store.SchemaVersionRecord, "schema_version")
                    schema_ver = schema_ver_row.value if schema_ver_row is not None else None
                finally:
                    db.close()

                if dry_run or not referential_integrity["passed"]:
                    trans.rollback()
                else:
                    trans.commit()
            except Exception:
                if trans.is_active:
                    trans.rollback()
                raise

        checksums_after = _collect_source_checksums(abs_src_sqlite, abs_data_dir)
        files_untouched = checksums_before == checksums_after

        if not files_untouched:
            status = "FAILED_VALIDATION"
        elif not referential_integrity["passed"]:
            status = "FAILED_VALIDATION"
        elif dry_run:
            status = "DRY_RUN_OK"
        else:
            status = "SUCCESS"

        report = MigrationReport(
            migration_id=migration_id,
            started_at_utc=started_at,
            completed_at_utc=_utc_now_iso(),
            dry_run=dry_run,
            source_sqlite_path=abs_src_sqlite,
            source_data_dir=abs_data_dir,
            target_db_redacted=auth_store.redact_db_url(sync_target_url),
            target_backend=store.backend,
            schema_version=schema_ver,
            status=status,
            counts={k: v.to_dict() for k, v in counts.items()},
            referential_integrity=referential_integrity,
            anomalies=anomalies,
            source_files_untouched=files_untouched,
            source_file_checksums=checksums_after,
        )

        if report_json_path:
            os.makedirs(os.path.dirname(os.path.abspath(report_json_path)), exist_ok=True)
            with open(report_json_path, "w", encoding="utf-8") as fj:
                json.dump(report.to_dict(), fj, ensure_ascii=False, indent=2)
        if report_markdown_path:
            os.makedirs(os.path.dirname(os.path.abspath(report_markdown_path)), exist_ok=True)
            with open(report_markdown_path, "w", encoding="utf-8") as fm:
                fm.write(report.to_markdown())

        return report
    finally:
        store.close()
