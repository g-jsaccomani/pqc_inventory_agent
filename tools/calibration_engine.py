"""Mosca-parameter calibration ledger and uploaded-artifact reader for Google Cloud PQC assessments.

- `calibrate_assessment_context` RECORDS Mosca parameters (X, Y, Z) provided by stakeholders or extracted by the
  agent from documents, and computes the Mosca inequality arithmetic. Values not provided are filled from a
  clearly labeled sector baseline and reported as such.
- `get_historical_calibration_profile` returns ONLY the calibration recorded for the requested scope (never
  another scope's values); when none exists it returns the labeled default baseline.
- `read_uploaded_artifact` returns the raw extracted content of a file attached to the conversation so the Gemini
  agent can read and interpret it. No keyword/regex parameter extraction is performed here.

The ledger is persisted as JSONL (`/data/calibration-history.jsonl` on Cloud Run, `data/` locally).
"""

from __future__ import annotations

import csv
import datetime
import io
import json
import os
from typing import Any, Dict, List, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAX_ARTIFACT_CHARS = int(os.getenv("PQC_MAX_ARTIFACT_CHARS", "60000"))


def _resolve_default_calibration_path() -> str:
    env_override = os.getenv("PQC_CALIBRATION_STORE_PATH", "").strip()
    if env_override:
        return env_override
    if os.path.isdir("/data") and os.access("/data", os.W_OK):
        return "/data/calibration-history.jsonl"
    data_dir = os.path.join(PROJECT_ROOT, "data")
    try:
        os.makedirs(data_dir, exist_ok=True)
        return os.path.join(data_dir, "calibration-history.jsonl")
    except OSError:
        return os.path.join(PROJECT_ROOT, "exports", "calibration_history.jsonl")


DEFAULT_CALIBRATION_PATH = _resolve_default_calibration_path()

# Session-scoped cache of text extracted from uploaded files (filled by the portal upload endpoint).
_UPLOADED_ARTIFACT_CACHE: Dict[str, Dict[str, Any]] = {}

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


def _load_calibration_ledger(store_path: Optional[str] = None) -> List[Dict[str, Any]]:
    path = store_path or DEFAULT_CALIBRATION_PATH
    if not os.path.exists(path):
        return []
    records: List[Dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    records.append(json.loads(line))
    except Exception:
        return []
    return records


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
    """Records Mosca parameters for a scope and computes the Mosca inequality (X + Y > Z).

    Use this when stakeholders (or a document the user uploaded) state data shelf-life (X), migration time (Y) or the
    assumed quantum threat horizon (Z). Missing values are filled from the sector baseline and flagged as defaults.

    Args:
        scope: Target scope (e.g. 'organizations/<id>' or 'projects/<id>').
        industry_sector: Sector key or short description (normalized to a baseline profile).
        confidentiality_years_x: Mosca X — years the protected data must stay confidential.
        migration_years_y: Mosca Y — years needed to migrate to post-quantum cryptography.
        crqc_horizon_years_z: Mosca Z — assumed years until a cryptographically relevant quantum computer.
        gateway_header_limit_kb: Current HTTP header buffer limit on gateways/proxies, if known.
        parameter_source_note: Where the values came from (stakeholder interview, questionnaire section, file name).

    Returns:
        JSON with the recorded entry, which parameters were provided vs. defaulted, and the Mosca arithmetic.
    """
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

    entry = {
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "scope": scope,
        "industry_sector": sector_key,
        "sector_label": base["sector_label"],
        "mosca": _mosca(x, y, z),
        "gateway_header_limit_kb": header_kb,
        "parameter_sources": {k: ("provided" if v else "sector_baseline_default") for k, v in provided.items()},
        "parameter_source_note": parameter_source_note,
    }
    try:
        os.makedirs(os.path.dirname(os.path.abspath(DEFAULT_CALIBRATION_PATH)), exist_ok=True)
        with open(DEFAULT_CALIBRATION_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        persisted = True
    except OSError:
        persisted = False

    scope_events = [r for r in _load_calibration_ledger() if r.get("scope") == scope]
    return json.dumps(
        {
            "status": "CALIBRATION_RECORDED" if persisted else "CALIBRATION_COMPUTED_NOT_PERSISTED",
            "store_path": DEFAULT_CALIBRATION_PATH,
            "scope_calibration_events": len(scope_events),
            "recorded_entry": entry,
            "baseline_notice": BASELINE_NOTICE if not all(provided.values()) else None,
        },
        separators=(",", ":"),
        ensure_ascii=False,
    )


def get_historical_calibration_profile(scope: str = "organizations/default") -> str:
    """Returns the Mosca calibration recorded for this exact scope, or the labeled default baseline if none exists.

    Args:
        scope: Target scope (e.g. 'organizations/<id>' or 'projects/<id>').

    Returns:
        JSON with `calibration_mode` (CALIBRATED_FOR_SCOPE or DEFAULT_BASELINE_NOT_CALIBRATED), the active profile,
        the recent calibration trail for this scope and the available sector baselines.
    """
    scope_records = [r for r in _load_calibration_ledger() if r.get("scope") == scope]
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
# Uploaded artifacts: raw extraction only (the agent interprets the content)
# ---------------------------------------------------------------------------


def extract_text_from_uploaded_bytes(filename: str, raw_bytes: bytes, mime_type: str = "") -> str:
    """Extracts human-readable text or X.509 metadata from PDF, DOCX, PEM/CRT, CSV, JSON, MD or TXT bytes."""
    ext = os.path.splitext(filename or "")[1].lower()

    if ext == ".pdf" or mime_type == "application/pdf":
        try:
            from pypdf import PdfReader

            reader = PdfReader(io.BytesIO(raw_bytes))
            extracted = "\n".join(page.extract_text() or "" for page in reader.pages).strip()
            if extracted:
                return extracted
        except Exception:
            pass

    if ext == ".docx" or "officedocument.wordprocessingml" in (mime_type or ""):
        try:
            import docx

            document = docx.Document(io.BytesIO(raw_bytes))
            parts: List[str] = [p.text for p in document.paragraphs if p.text.strip()]
            for table in document.tables:
                for row in table.rows:
                    cells = [c.text.strip() for c in row.cells if c.text.strip()]
                    if cells:
                        parts.append(" | ".join(cells))
            extracted = "\n".join(parts).strip()
            if extracted:
                return extracted
        except Exception:
            pass

    if ext in (".pem", ".crt", ".cer") or b"-----BEGIN CERTIFICATE-----" in raw_bytes:
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa

            cert = x509.load_pem_x509_certificate(raw_bytes)
            pub = cert.public_key()
            if isinstance(pub, rsa.RSAPublicKey):
                algo_desc = f"RSA_{pub.key_size}"
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                algo_desc = f"ECDSA_{pub.curve.name.upper()}"
            elif isinstance(pub, ed25519.Ed25519PublicKey):
                algo_desc = "ED25519"
            elif isinstance(pub, dsa.DSAPublicKey):
                algo_desc = f"DSA_{pub.key_size}"
            else:
                algo_desc = type(pub).__name__
            return (
                "X509_CERTIFICATE_METADATA:\n"
                f"subject={cert.subject.rfc4514_string()}\n"
                f"issuer={cert.issuer.rfc4514_string()}\n"
                f"public_key_algorithm={algo_desc}\n"
                f"signature_algorithm={cert.signature_algorithm_oid._name}\n"
                f"not_valid_before={cert.not_valid_before_utc.isoformat()}\n"
                f"not_valid_after={cert.not_valid_after_utc.isoformat()}\n"
            )
        except Exception:
            pass

    try:
        return raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return raw_bytes.decode("latin-1", errors="replace")


def register_uploaded_artifact_for_analysis(
    filename: str,
    raw_bytes: bytes,
    mime_type: str = "application/octet-stream",
    session_id: str = "default",
) -> Dict[str, Any]:
    """Caches the text extracted from an uploaded file, scoped to the conversation session."""
    record = {
        "filename": filename,
        "mime_type": mime_type,
        "size_bytes": len(raw_bytes),
        "session_id": session_id,
        "extracted_text": extract_text_from_uploaded_bytes(filename, raw_bytes, mime_type),
        "uploaded_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    _UPLOADED_ARTIFACT_CACHE[f"{session_id}:{filename}"] = record
    _UPLOADED_ARTIFACT_CACHE[f"{session_id}:latest"] = record
    return record


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
    if tool_context is not None:
        try:
            session_id = tool_context.session.id
        except Exception:
            session_id = "default"

    name = (artifact_name or "").strip()
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
        cached = _UPLOADED_ARTIFACT_CACHE.get(f"{session_id}:{name or 'latest'}")
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
