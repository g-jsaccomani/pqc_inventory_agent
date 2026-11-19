"""Mosca-parameter calibration ledger and uploaded-artifact reader for Google Cloud PQC assessments.

- `calibrate_assessment_context` RECORDS Mosca parameters (X, Y, Z) provided by stakeholders or extracted by the
  agent from documents, and computes the Mosca inequality arithmetic. Values not provided are filled from a
  clearly labeled sector baseline and reported as such.
- `get_historical_calibration_profile` returns ONLY the calibration recorded for the requested scope (never
  another scope's values); when none exists it returns the labeled default baseline.
- `read_uploaded_artifact` returns the raw extracted content of a file attached to the conversation so the Gemini
  agent can read and interpret it. No keyword/regex parameter extraction is performed here.

The calibration ledger is persisted transactionally in PostgreSQL (`pqc_calibration_events` table).
"""

from __future__ import annotations

from collections import OrderedDict
import csv
import datetime
import io
import json
import os
import threading
import time
from typing import Any, Dict, List, Optional

from pqc_agent import upload_validator

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAX_ARTIFACT_CHARS = int(os.getenv("PQC_MAX_ARTIFACT_CHARS", "60000"))

DEFAULT_UPLOAD_CACHE_MAX_ENTRIES = 128
DEFAULT_UPLOAD_CACHE_MAX_BYTES = 32 * 1024 * 1024  # 32 MiB extracted text budget
DEFAULT_UPLOAD_CACHE_TTL_SECONDS = 3600.0

# Tenant- and session-scoped bounded LRU cache of extracted uploaded artifact text.
_UPLOAD_CACHE_LOCK = threading.RLock()
_UPLOADED_ARTIFACT_CACHE: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
_UPLOADED_ARTIFACT_LATEST: Dict[str, str] = {}
_UPLOADED_ARTIFACT_CACHE_BYTES: int = 0

# Default sector baselines. These are ASSUMPTIONS that must be validated with stakeholders.
SECTOR_CALIBRATION_PROFILES: Dict[str, Dict[str, Any]] = {
    "BFSI_BANKING": {
        "sector_label": "Banking, Financial Services & Capital Markets (BFSI)",
        "default_confidentiality_years_x": 15.0,
        "default_migration_years_y": 3.0,
        "default_crqc_horizon_years_z": 8.5,
        "gateway_header_limit_kb_default": 8,
    },
    "HEALTHCARE_GENOMICS": {
        "sector_label": "Healthcare, Life Sciences, Biopharma & Genomics",
        "default_confidentiality_years_x": 35.0,
        "default_migration_years_y": 5.0,
        "default_crqc_horizon_years_z": 8.5,
        "gateway_header_limit_kb_default": 8,
    },
    "PUBLIC_SECTOR_DEFENSE": {
        "sector_label": "Public Sector, Government, Defense & Critical National Infrastructure",
        "default_confidentiality_years_x": 30.0,
        "default_migration_years_y": 4.0,
        "default_crqc_horizon_years_z": 7.5,
        "gateway_header_limit_kb_default": 16,
    },
    "TELECOM_5G_CLOUD": {
        "sector_label": "Telecommunications, 5G Core, ISP & Cloud Service Providers",
        "default_confidentiality_years_x": 10.0,
        "default_migration_years_y": 3.0,
        "default_crqc_horizon_years_z": 8.5,
        "gateway_header_limit_kb_default": 16,
    },
    "ENERGY_OT_INDUSTRIAL": {
        "sector_label": "Energy, Utilities, Industrial OT (SCADA/ICS), Automotive & Retail",
        "default_confidentiality_years_x": 12.0,
        "default_migration_years_y": 7.0,
        "default_crqc_horizon_years_z": 8.5,
        "gateway_header_limit_kb_default": 8,
    },
    "ENTERPRISE_DEFAULT": {
        "sector_label": "Standard Enterprise Cloud Footprint (Multi-Industry Baseline)",
        "default_confidentiality_years_x": 10.0,
        "default_migration_years_y": 2.0,
        "default_crqc_horizon_years_z": 8.5,
        "gateway_header_limit_kb_default": 8,
    },
}
BASELINE_NOTICE = "Sector baseline values are default assumptions and must be validated with the customer's stakeholders."


def _infer_sector_key(raw_text: str) -> str:
    """Normalizes a sector key or short sector description to one of the canonical profile keys."""
    if not raw_text:
        return "ENTERPRISE_DEFAULT"
    upper = raw_text.strip().upper()
    if upper in SECTOR_CALIBRATION_PROFILES:
        return upper
    low = raw_text.lower()
    if any(k in low for k in ("bank", "bfsi", "financ", "capital market", "payment", "pci", "dora", "bacen")):
        return "BFSI_BANKING"
    if any(k in low for k in ("health", "genom", "medical", "pharma", "hipaa", "biotech", "hospital")):
        return "HEALTHCARE_GENOMICS"
    if any(k in low for k in ("gov", "defense", "public sector", "federal", "military", "sovereign")):
        return "PUBLIC_SECTOR_DEFENSE"
    if any(k in low for k in ("telecom", "5g", "isp", "carrier", "telco")):
        return "TELECOM_5G_CLOUD"
    if any(k in low for k in ("energy", "utilit", "scada", "ics", "industrial", "automotive")):
        return "ENERGY_OT_INDUSTRIAL"
    return "ENTERPRISE_DEFAULT"


def _load_calibration_ledger(scope: Optional[str] = None) -> List[Dict[str, Any]]:
    from pqc_agent import auth_store

    if scope:
        return auth_store.get_active_auth_store().list_calibration_events(scope=scope)
    return []


def _mosca(x: float, y: float, z: float) -> Dict[str, Any]:
    total = round(x + y, 2)
    margin = round(z - total, 2)
    return {
        "confidentiality_years_x": x,
        "migration_years_y": y,
        "x_plus_y": total,
        "crqc_horizon_years_z": z,
        "margin_z_minus_x_plus_y": margin,
        "inequality_x_plus_y_greater_than_z": total > z,
    }


def calibrate_assessment_context(
    scope: str = "organizations/default",
    industry_sector: str = "ENTERPRISE_DEFAULT",
    confidentiality_years_x: Optional[float] = None,
    migration_years_y: Optional[float] = None,
    crqc_horizon_years_z: Optional[float] = None,
    gateway_header_limit_kb: Optional[int] = None,
    parameter_source_note: str = "",
) -> str:
    """Records Mosca parameters for a scope in ``pqc_calibration_events`` and computes the Mosca inequality (X + Y > Z)."""
    from pqc_agent import auth_store
    from tools.gcloud_bridge import get_current_tenant_user

    sector_key = _infer_sector_key(industry_sector)
    base = SECTOR_CALIBRATION_PROFILES[sector_key]
    provided = {
        "confidentiality_years_x": confidentiality_years_x is not None,
        "migration_years_y": migration_years_y is not None,
        "crqc_horizon_years_z": crqc_horizon_years_z is not None,
        "gateway_header_limit_kb": gateway_header_limit_kb is not None,
    }
    x = float(confidentiality_years_x) if provided["confidentiality_years_x"] else base["default_confidentiality_years_x"]
    y = float(migration_years_y) if provided["migration_years_y"] else base["default_migration_years_y"]
    z = float(crqc_horizon_years_z) if provided["crqc_horizon_years_z"] else base["default_crqc_horizon_years_z"]
    header_kb = int(gateway_header_limit_kb) if provided["gateway_header_limit_kb"] else base["gateway_header_limit_kb_default"]

    active_uid = get_current_tenant_user()
    entry = {
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "scope": scope,
        "user_id": active_uid,
        "industry_sector": sector_key,
        "sector_label": base["sector_label"],
        "mosca": _mosca(x, y, z),
        "gateway_header_limit_kb": header_kb,
        "parameter_sources": {k: ("provided" if v else "sector_baseline_default") for k, v in provided.items()},
        "parameter_source_note": parameter_source_note,
    }
    store = auth_store.get_active_auth_store()
    saved_entry = store.append_calibration_event(scope=scope, user_id=active_uid, entry=entry)
    scope_events = store.list_calibration_events(scope=scope)
    return json.dumps(
        {
            "status": "CALIBRATION_RECORDED",
            "store_backend": "database:pqc_calibration_events",
            "scope_calibration_events": len(scope_events),
            "recorded_entry": saved_entry,
            "baseline_notice": BASELINE_NOTICE if not all(provided.values()) else None,
        },
        separators=(",", ":"),
        ensure_ascii=False,
    )


def get_historical_calibration_profile(scope: str = "organizations/default") -> str:
    """Returns the Mosca calibration recorded in ``pqc_calibration_events`` for this exact scope, or default baseline."""
    scope_records = _load_calibration_ledger(scope=scope)
    if scope_records:
        return json.dumps(
            {
                "calibration_mode": "CALIBRATED_FOR_SCOPE",
                "scope": scope,
                "scope_calibration_events": len(scope_records),
                "active_profile": scope_records[-1],
                "recent_calibration_trail": scope_records[-5:],
                "available_sector_baselines": list(SECTOR_CALIBRATION_PROFILES.keys()),
            },
            separators=(",", ":"),
            ensure_ascii=False,
        )

    base = SECTOR_CALIBRATION_PROFILES["ENTERPRISE_DEFAULT"]
    return json.dumps(
        {
            "calibration_mode": "DEFAULT_BASELINE_NOT_CALIBRATED",
            "scope": scope,
            "scope_calibration_events": 0,
            "active_profile": {
                "industry_sector": "ENTERPRISE_DEFAULT",
                "sector_label": base["sector_label"],
                "mosca": _mosca(
                    base["default_confidentiality_years_x"],
                    base["default_migration_years_y"],
                    base["default_crqc_horizon_years_z"],
                ),
                "gateway_header_limit_kb": base["gateway_header_limit_kb_default"],
            },
            "baseline_notice": BASELINE_NOTICE,
            "available_sector_baselines": list(SECTOR_CALIBRATION_PROFILES.keys()),
        },
        separators=(",", ":"),
        ensure_ascii=False,
    )


# ---------------------------------------------------------------------------
# Uploaded artifacts: validated extraction & tenant-isolated bounded LRU cache
# ---------------------------------------------------------------------------


def _upload_cache_max_entries() -> int:
    raw = (os.getenv("PQC_UPLOAD_CACHE_MAX_ENTRIES") or "").strip()
    try:
        return max(1, int(raw)) if raw else DEFAULT_UPLOAD_CACHE_MAX_ENTRIES
    except ValueError:
        return DEFAULT_UPLOAD_CACHE_MAX_ENTRIES


def _upload_cache_max_bytes() -> int:
    raw = (os.getenv("PQC_UPLOAD_CACHE_MAX_BYTES") or "").strip()
    try:
        return max(1024, int(raw)) if raw else DEFAULT_UPLOAD_CACHE_MAX_BYTES
    except ValueError:
        return DEFAULT_UPLOAD_CACHE_MAX_BYTES


def _upload_cache_ttl_seconds() -> float:
    raw = (os.getenv("PQC_UPLOAD_CACHE_TTL_SECONDS") or "").strip()
    try:
        return max(1.0, float(raw)) if raw else DEFAULT_UPLOAD_CACHE_TTL_SECONDS
    except ValueError:
        return DEFAULT_UPLOAD_CACHE_TTL_SECONDS


def _resolve_cache_tenant_user(user_id: Optional[str] = None) -> str:
    from tools.gcloud_bridge import get_current_tenant_user, normalize_user_id

    return normalize_user_id(user_id or get_current_tenant_user())


def _evict_cache_key_unlocked(cache_key: str) -> None:
    global _UPLOADED_ARTIFACT_CACHE_BYTES
    removed = _UPLOADED_ARTIFACT_CACHE.pop(cache_key, None)
    if removed is not None:
        _UPLOADED_ARTIFACT_CACHE_BYTES = max(
            0, _UPLOADED_ARTIFACT_CACHE_BYTES - int(removed.get("_cached_text_bytes", 0))
        )
        latest_scope = f"{removed.get('user_id', '')}:{removed.get('session_id', '')}"
        if _UPLOADED_ARTIFACT_LATEST.get(latest_scope) == cache_key:
            _UPLOADED_ARTIFACT_LATEST.pop(latest_scope, None)


def _prune_upload_cache_unlocked(now_monotonic: Optional[float] = None) -> None:
    now = now_monotonic if now_monotonic is not None else time.monotonic()
    ttl = _upload_cache_ttl_seconds()
    expired_keys = [
        k for k, rec in _UPLOADED_ARTIFACT_CACHE.items() if (now - float(rec.get("_stored_at_monotonic", 0.0))) > ttl
    ]
    for k in expired_keys:
        _evict_cache_key_unlocked(k)

    max_entries = _upload_cache_max_entries()
    max_bytes = _upload_cache_max_bytes()
    while len(_UPLOADED_ARTIFACT_CACHE) > max_entries or (
        _UPLOADED_ARTIFACT_CACHE_BYTES > max_bytes and len(_UPLOADED_ARTIFACT_CACHE) > 0
    ):
        oldest_key = next(iter(_UPLOADED_ARTIFACT_CACHE))
        _evict_cache_key_unlocked(oldest_key)


def clear_uploaded_artifact_cache() -> None:
    """Clears all cached uploaded artifact text entries (used in tests and cleanup)."""
    global _UPLOADED_ARTIFACT_CACHE_BYTES
    with _UPLOAD_CACHE_LOCK:
        _UPLOADED_ARTIFACT_CACHE.clear()
        _UPLOADED_ARTIFACT_LATEST.clear()
        _UPLOADED_ARTIFACT_CACHE_BYTES = 0


def extract_text_from_uploaded_bytes(filename: str, raw_bytes: bytes, mime_type: str = "") -> str:
    """Validates magic bytes/structure and extracts bounded text or X.509 metadata (zero latin-1 fallback)."""
    validated = upload_validator.validate_and_extract_upload(
        filename=filename,
        raw_bytes=raw_bytes,
        declared_mime=mime_type,
        enforce_size_limit=True,
    )
    return validated.extracted_text


def register_uploaded_artifact_for_analysis(
    filename: str,
    raw_bytes: bytes,
    mime_type: str = "application/octet-stream",
    session_id: str = "default",
    *,
    user_id: Optional[str] = None,
    extracted_text: Optional[str] = None,
) -> Dict[str, Any]:
    """Caches validated uploaded artifact text partitioned strictly by `(user_id, session_id, sanitized_filename)`."""
    global _UPLOADED_ARTIFACT_CACHE_BYTES

    uid = _resolve_cache_tenant_user(user_id)
    safe_session = str(session_id or "default").strip() or "default"

    if extracted_text is None:
        validated = upload_validator.validate_and_extract_upload(
            filename=filename,
            raw_bytes=raw_bytes,
            declared_mime=mime_type,
            enforce_size_limit=True,
        )
        safe_name = validated.sanitized_filename
        resolved_mime = validated.canonical_mime
        text_val = validated.extracted_text
    else:
        safe_name = upload_validator.sanitize_upload_filename(filename, require_allowed_extension=True)
        resolved_mime = mime_type
        text_val = str(extracted_text)[: upload_validator.max_extracted_text_chars()]

    text_bytes_len = len(text_val.encode("utf-8", errors="ignore"))
    cache_key = f"{uid}:{safe_session}:{safe_name}"
    latest_scope = f"{uid}:{safe_session}"
    now_mono = time.monotonic()

    record = {
        "user_id": uid,
        "filename": safe_name,
        "mime_type": resolved_mime,
        "size_bytes": len(raw_bytes),
        "session_id": safe_session,
        "extracted_text": text_val,
        "uploaded_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "_stored_at_monotonic": now_mono,
        "_cached_text_bytes": text_bytes_len,
    }

    with _UPLOAD_CACHE_LOCK:
        _prune_upload_cache_unlocked(now_mono)
        if cache_key in _UPLOADED_ARTIFACT_CACHE:
            _evict_cache_key_unlocked(cache_key)
        _UPLOADED_ARTIFACT_CACHE[cache_key] = record
        _UPLOADED_ARTIFACT_CACHE.move_to_end(cache_key)
        _UPLOADED_ARTIFACT_CACHE_BYTES += text_bytes_len
        _UPLOADED_ARTIFACT_LATEST[latest_scope] = cache_key
        _prune_upload_cache_unlocked(now_mono)

    return {
        "user_id": uid,
        "filename": safe_name,
        "mime_type": resolved_mime,
        "size_bytes": len(raw_bytes),
        "session_id": safe_session,
        "extracted_text": text_val,
        "uploaded_at_utc": record["uploaded_at_utc"],
    }


def _lookup_cached_artifact(user_id: str, session_id: str, artifact_name: str = "") -> Optional[Dict[str, Any]]:
    now_mono = time.monotonic()
    with _UPLOAD_CACHE_LOCK:
        _prune_upload_cache_unlocked(now_mono)
        if artifact_name:
            try:
                safe_name = upload_validator.sanitize_upload_filename(artifact_name, require_allowed_extension=False)
            except upload_validator.UploadValidationError:
                return None
            cache_key = f"{user_id}:{session_id}:{safe_name}"
        else:
            cache_key = _UPLOADED_ARTIFACT_LATEST.get(f"{user_id}:{session_id}", "")
        if not cache_key:
            return None
        rec = _UPLOADED_ARTIFACT_CACHE.get(cache_key)
        if rec is None:
            return None
        _UPLOADED_ARTIFACT_CACHE.move_to_end(cache_key)
        return dict(rec)


def _csv_preview(text: str, max_rows: int = 50) -> Optional[Dict[str, Any]]:
    first_line = text.splitlines()[0] if text.strip() else ""
    if "," not in first_line:
        return None
    try:
        reader = csv.DictReader(io.StringIO(text))
        rows = []
        for idx, row in enumerate(reader):
            if idx >= max_rows:
                break
            rows.append({str(k).strip(): str(v).strip() for k, v in row.items() if k is not None})
        return {"columns": reader.fieldnames or [], "rows": rows, "rows_shown": len(rows)}
    except Exception:
        return None


async def read_uploaded_artifact(artifact_name: str = "", tool_context: Any = None) -> str:
    """Reads a file the user attached to this conversation and returns its raw extracted content.

    Supports PDF, DOCX, CSV, JSON, Markdown, text and PEM/CRT certificates (X.509 metadata). The agent must read and
    interpret the content itself (for example, extract Mosca parameters and then call calibrate_assessment_context).

    Args:
        artifact_name: File name as attached by the user. Leave empty to read the most recent attachment.

    Returns:
        JSON with `artifact_name`, `extracted_text` (truncated if very large), optional `csv_preview` and `source`.
    """
    session_id = "default"
    ctx_user_id: Optional[str] = None
    if tool_context is not None:
        try:
            session_id = str(getattr(getattr(tool_context, "session", None), "id", None) or "default")
        except Exception:
            session_id = "default"
        try:
            inv_ctx = getattr(tool_context, "_invocation_context", None)
            ctx_user_id = (
                getattr(inv_ctx, "user_id", None)
                or getattr(tool_context, "user_id", None)
                or getattr(getattr(tool_context, "session", None), "user_id", None)
            )
        except Exception:
            ctx_user_id = None

    uid = _resolve_cache_tenant_user(ctx_user_id)
    name = (artifact_name or "").strip()
    if name:
        try:
            name = upload_validator.sanitize_upload_filename(name, require_allowed_extension=False)
        except upload_validator.UploadValidationError:
            name = ""
    text: Optional[str] = None
    source = None

    if tool_context is not None:
        try:
            if not name:
                names = await tool_context.list_artifacts()
                name = names[-1] if names else ""
            if name:
                part = await tool_context.load_artifact(name)
                if part is not None:
                    if getattr(part, "inline_data", None) and part.inline_data.data:
                        text = extract_text_from_uploaded_bytes(name, part.inline_data.data, part.inline_data.mime_type or "")
                    elif getattr(part, "text", None):
                        text = part.text
                    source = "session_artifact_service"
        except Exception:
            text = None

    if text is None:
        cached = _lookup_cached_artifact(uid, session_id, name)
        if cached:
            name = cached["filename"]
            text = cached["extracted_text"]
            source = "upload_text_cache"

    if text is None:
        return json.dumps(
            {
                "status": "NO_ARTIFACT_FOUND",
                "artifact_name": name or None,
                "message": "No attached file with that name was found in this conversation.",
            },
            ensure_ascii=False,
        )

    truncated = len(text) > MAX_ARTIFACT_CHARS
    return json.dumps(
        {
            "status": "OK",
            "artifact_name": name,
            "source": source,
            "character_count": len(text),
            "truncated": truncated,
            "extracted_text": text[:MAX_ARTIFACT_CHARS],
            "csv_preview": _csv_preview(text) if name.lower().endswith(".csv") else None,
        },
        ensure_ascii=False,
    )
