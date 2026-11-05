"""Adaptive Self-Calibration, Artifact Ingestion & Historical Learning Engine for Google Cloud PQC Assessments.

Connects the structured stakeholder inputs from `PQC_Discovery_Questionnaire`, uploaded artifacts
(PDF, DOCX, CSV, JSON, PEM/CRT, MD, TXT), and interactive consultant calibration prompts directly
to the deterministic Mosca Inequality (X + Y > Z) and Monte Carlo Quantum Value-at-Risk (Q-VaR 95%)
simulation engines.

Every calibration update is persisted to a longitudinal JSONL ledger (`/data/calibration-history.jsonl`
on Cloud Run GCS Volume Mounts and `exports/calibration_history.jsonl` locally) so the agent
automatically learns from historical interactions across container restarts and scale-to-zero events.
"""

from __future__ import annotations

import csv
import datetime
import io
import json
import os
import re
from typing import Any, Dict, List, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _resolve_default_calibration_path() -> str:
    """Resolves the primary calibration ledger path, preferring `/data/calibration-history.jsonl` when mounted."""
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
SECONDARY_CALIBRATION_PATH = os.path.join(PROJECT_ROOT, "exports", "calibration_history.jsonl")

# Registry of recently uploaded session artifacts for deterministic tool inspection
_UPLOADED_ARTIFACT_CACHE: Dict[str, Dict[str, Any]] = {}

# Pre-calibrated Industry Vertical Profiles aligned with PQC_Discovery_Questionnaire Section 2
SECTOR_CALIBRATION_PROFILES: Dict[str, Dict[str, Any]] = {
    "BFSI_BANKING": {
        "sector_label": "Banking, Financial Services & Capital Markets (BFSI)",
        "default_confidentiality_years_x": 15.0,
        "default_migration_years_y": 3.0,
        "default_crqc_horizon_years_z": 8.5,
        "regulatory_frameworks": [
            "NIST FIPS 203/204/205",
            "NIST IR 8547 (Final)",
            "PCI-DSS v4.0 (Req 4.2.1)",
            "EU DORA (Art. 9)",
            "BACEN / Fed / ECB Operational Resilience",
        ],
        "qvar_sector_multiplier": 1.35,
        "gateway_header_limit_kb_default": 8,
        "calibration_rationale": (
            "High HNDL exposure on inter-bank mTLS settlement, ISO 20022 wire payloads, and long-term credit/ledger "
            "archives (X=15 yrs), combined with complex HSM/PKCS#11 and mainframe refactoring dependencies (Y=3 yrs)."
        ),
    },
    "HEALTHCARE_GENOMICS": {
        "sector_label": "Healthcare, Life Sciences, Biopharma & Genomics",
        "default_confidentiality_years_x": 35.0,
        "default_migration_years_y": 5.0,
        "default_crqc_horizon_years_z": 8.5,
        "regulatory_frameworks": [
            "NIST FIPS 203/204/205",
            "HIPAA Security Rule",
            "FDA Premarket Medical Device Cybersecurity",
            "GDPR / LGPD Biometric & Genomic Data Protection",
        ],
        "qvar_sector_multiplier": 1.50,
        "gateway_header_limit_kb_default": 8,
        "calibration_rationale": (
            "Permanent non-revocable privacy requirement for Electronic Health Records (EHR/PHI) and genomic IP "
            "(X=35+ yrs) coupled with long hardware replacement cycles on connected medical devices (Y=5 yrs)."
        ),
    },
    "PUBLIC_SECTOR_DEFENSE": {
        "sector_label": "Public Sector, Government, Defense & Critical National Infrastructure",
        "default_confidentiality_years_x": 30.0,
        "default_migration_years_y": 4.0,
        "default_crqc_horizon_years_z": 7.5,
        "regulatory_frameworks": [
            "White House EO 14412 (Dec 31, 2030 KEM / Dec 31, 2031 Signatures)",
            "OMB M-26-15 & NSM-10",
            "NSA CNSA 2.0",
            "NIST IR 8547 (Final)",
            "UK NCSC (2028/2031/2035)",
        ],
        "qvar_sector_multiplier": 1.60,
        "gateway_header_limit_kb_default": 16,
        "calibration_rationale": (
            "Sovereign identity registries and state-level secrets face active nation-state HNDL collection (X=30 yrs) "
            "under mandatory statutory deadlines (EO 14412 & CNSA 2.0)."
        ),
    },
    "TELECOM_5G_CLOUD": {
        "sector_label": "Telecommunications, 5G Core, ISP & Cloud Service Providers",
        "default_confidentiality_years_x": 10.0,
        "default_migration_years_y": 3.0,
        "default_crqc_horizon_years_z": 8.5,
        "regulatory_frameworks": [
            "NIST FIPS 203/204/205",
            "3GPP SA3 Post-Quantum 5G Security",
            "IETF TLS 1.3 Hybrid Key Exchange (X25519MLKEM768)",
            "ETSI Cyber / Quantum-Safe Cryptography",
        ],
        "qvar_sector_multiplier": 1.25,
        "gateway_header_limit_kb_default": 16,
        "calibration_rationale": (
            "Massive-scale TLS termination, SIM/eSIM provisioning roots, and IPsec backbone trunks sensitive to "
            "TCP MSS packet fragmentation and 3,309-byte ML-DSA-65 signature expansion."
        ),
    },
    "ENERGY_OT_INDUSTRIAL": {
        "sector_label": "Energy, Utilities, Industrial OT (SCADA/ICS), Automotive & Retail",
        "default_confidentiality_years_x": 12.0,
        "default_migration_years_y": 7.0,
        "default_crqc_horizon_years_z": 8.5,
        "regulatory_frameworks": [
            "NIST FIPS 203/204/205 (including SLH-DSA FIPS 205 for Firmware)",
            "NERC CIP / IEC 62443",
            "ISO/SAE 21434 (Automotive Cybersecurity)",
            "PCI-DSS v4.0",
        ],
        "qvar_sector_multiplier": 1.30,
        "gateway_header_limit_kb_default": 8,
        "calibration_rationale": (
            "Long-lived embedded field devices, smart meters, and vehicle ECUs require extended firmware migration "
            "windows (Y=7 yrs) and hash-based/lattice code-signing continuity."
        ),
    },
    "ENTERPRISE_DEFAULT": {
        "sector_label": "Standard Enterprise Cloud Footprint (Multi-Industry Baseline)",
        "default_confidentiality_years_x": 10.0,
        "default_migration_years_y": 2.0,
        "default_crqc_horizon_years_z": 8.5,
        "regulatory_frameworks": [
            "NIST FIPS 203/204/205",
            "NIST IR 8547 (Final, Oct 2026)",
            "Executive Order 14412",
            "NSA CNSA 2.0",
        ],
        "qvar_sector_multiplier": 1.0,
        "gateway_header_limit_kb_default": 8,
        "calibration_rationale": (
            "Default PSO consultative baseline assuming a 10-year regulated data shelf-life (X=10 yrs) and a "
            "2-year enterprise cryptographic refactoring timeline (Y=2 yrs)."
        ),
    },
}


def _load_calibration_ledger(store_path: str = DEFAULT_CALIBRATION_PATH) -> List[Dict[str, Any]]:
    candidate_paths = [store_path]
    if SECONDARY_CALIBRATION_PATH not in candidate_paths:
        candidate_paths.append(SECONDARY_CALIBRATION_PATH)

    for path in candidate_paths:
        if os.path.exists(path):
            records: List[Dict[str, Any]] = []
            try:
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line_s = line.strip()
                        if line_s:
                            records.append(json.loads(line_s))
                if records:
                    return records
            except Exception:
                continue
    return []


def calibrate_assessment_context(
    scope: str = "organizations/default",
    industry_sector: str = "ENTERPRISE_DEFAULT",
    confidentiality_years_x: Optional[float] = None,
    migration_years_y: Optional[float] = None,
    crqc_horizon_years_z: Optional[float] = None,
    gateway_header_limit_kb: Optional[int] = None,
    compensating_controls_note: str = "",
    project_tier_overrides: str = "",
) -> str:
    """Persists stakeholder discovery inputs and consultant calibration overrides into the agent's historical memory.

    Args:
        scope: Target GCP Organization, Folder, or Project identifier (e.g., 'organizations/<ORG_ID>').
        industry_sector: Sector key ('BFSI_BANKING', 'HEALTHCARE_GENOMICS', 'PUBLIC_SECTOR_DEFENSE',
            'TELECOM_5G_CLOUD', 'ENERGY_OT_INDUSTRIAL', or 'ENTERPRISE_DEFAULT').
        confidentiality_years_x: Mosca X parameter — required data confidentiality shelf-life in years.
        migration_years_y: Mosca Y parameter — estimated engineering & infrastructure refactoring time in years.
        crqc_horizon_years_z: Mosca Z parameter — expected CRQC threat horizon in years.
        gateway_header_limit_kb: Current API Gateway / Envoy / NGINX HTTP header buffer limit in KB.
        compensating_controls_note: Validated compensating controls (e.g., VPC-SC perimeter, scheduled key retirement).
        project_tier_overrides: JSON or comma-separated mapping of specific projects to custom criticality tiers.

    Returns:
        JSON string confirming the newly recorded calibration state and cumulative historical learning profile.
    """
    sector_key = _infer_sector_key(industry_sector)
    base_prof = SECTOR_CALIBRATION_PROFILES[sector_key]

    eff_x = float(confidentiality_years_x) if confidentiality_years_x is not None else base_prof["default_confidentiality_years_x"]
    eff_y = float(migration_years_y) if migration_years_y is not None else base_prof["default_migration_years_y"]
    eff_z = float(crqc_horizon_years_z) if crqc_horizon_years_z is not None else base_prof["default_crqc_horizon_years_z"]
    eff_hdr_kb = int(gateway_header_limit_kb) if gateway_header_limit_kb is not None else base_prof["gateway_header_limit_kb_default"]

    mosca_total = round(eff_x + eff_y, 2)
    mosca_margin = round(eff_z - mosca_total, 2)
    hndl_breach_active = mosca_total > eff_z

    entry = {
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "scope": scope,
        "industry_sector": sector_key,
        "sector_label": base_prof["sector_label"],
        "mosca_parameters": {
            "confidentiality_years_x": eff_x,
            "migration_years_y": eff_y,
            "total_protection_required_x_plus_y": mosca_total,
            "crqc_horizon_years_z": eff_z,
            "mosca_safety_margin_z_minus_xy": mosca_margin,
            "active_hndl_breach_window": hndl_breach_active,
            "mosca_verdict": (
                f"CRITICAL_ACTIVE_HNDL_WINDOW (X+Y={mosca_total} yrs > Z={eff_z} yrs; deficit={abs(mosca_margin)} yrs)"
                if hndl_breach_active
                else f"WITHIN_MIGRATION_MARGIN (X+Y={mosca_total} yrs <= Z={eff_z} yrs; buffer={mosca_margin} yrs)"
            ),
        },
        "gateway_header_limit_kb": eff_hdr_kb,
        "ml_dsa_65_header_overflow_risk": eff_hdr_kb < 16,
        "qvar_sector_multiplier": base_prof["qvar_sector_multiplier"],
        "regulatory_frameworks": base_prof["regulatory_frameworks"],
        "compensating_controls_note": compensating_controls_note,
        "project_tier_overrides": project_tier_overrides,
    }

    target_paths = {DEFAULT_CALIBRATION_PATH, SECONDARY_CALIBRATION_PATH}
    for path in target_paths:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            pass

    history = _load_calibration_ledger(DEFAULT_CALIBRATION_PATH)
    scope_history = [r for r in history if r.get("scope") == scope] or history

    return json.dumps(
        {
            "calibration_status": "CALIBRATION_RECORDED_AND_ACTIVE",
            "store_path": DEFAULT_CALIBRATION_PATH,
            "total_historical_calibration_events": len(history),
            "scope_calibration_events": len(scope_history),
            "active_calibrated_profile": entry,
            "self_learning_summary": (
                f"Agent calibrated for {base_prof['sector_label']} on scope '{scope}'. "
                f"Mosca inequality configured to X={eff_x}y + Y={eff_y}y = {mosca_total}y vs. Z={eff_z}y "
                f"({'ACTIVE HNDL EXPOSURE' if hndl_breach_active else 'SAFE MARGIN'}). "
                f"All subsequent readiness scans, Q-VaR simulations, and remediation runbooks will automatically "
                f"apply this historical calibration profile."
            ),
        },
        separators=(",", ":"),
        ensure_ascii=False,
    )


def get_historical_calibration_profile(scope: str = "organizations/default") -> str:
    """Retrieves the cumulative learned calibration profile and historical adjustments for the target scope.

    Args:
        scope: Target GCP Organization, Folder, or Project identifier.

    Returns:
        JSON string containing the active learned calibration parameters, historical audit trail,
        and available industry sector baselines.
    """
    history = _load_calibration_ledger(DEFAULT_CALIBRATION_PATH)
    scope_records = [r for r in history if r.get("scope") == scope]
    latest = scope_records[-1] if scope_records else (history[-1] if history else None)

    if latest is None:
        default_prof = SECTOR_CALIBRATION_PROFILES["ENTERPRISE_DEFAULT"]
        latest = {
            "scope": scope,
            "industry_sector": "ENTERPRISE_DEFAULT",
            "sector_label": default_prof["sector_label"],
            "mosca_parameters": {
                "confidentiality_years_x": default_prof["default_confidentiality_years_x"],
                "migration_years_y": default_prof["default_migration_years_y"],
                "total_protection_required_x_plus_y": 12.0,
                "crqc_horizon_years_z": default_prof["default_crqc_horizon_years_z"],
                "mosca_safety_margin_z_minus_xy": -3.5,
                "active_hndl_breach_window": True,
                "mosca_verdict": "CRITICAL_ACTIVE_HNDL_WINDOW (X+Y=12.0 yrs > Z=8.5 yrs; deficit=3.5 yrs)",
            },
            "gateway_header_limit_kb": default_prof["gateway_header_limit_kb_default"],
            "ml_dsa_65_header_overflow_risk": True,
            "qvar_sector_multiplier": default_prof["qvar_sector_multiplier"],
            "regulatory_frameworks": default_prof["regulatory_frameworks"],
            "compensating_controls_note": "None recorded yet — using default PSO baseline.",
            "project_tier_overrides": "",
        }

    return json.dumps(
        {
            "calibration_mode": "HISTORICAL_SELF_CALIBRATED" if history else "DEFAULT_BASELINE",
            "total_historical_events": len(history),
            "scope_historical_events": len(scope_records),
            "active_profile": latest,
            "recent_calibration_trail": (scope_records or history)[-5:],
            "available_sector_templates": list(SECTOR_CALIBRATION_PROFILES.keys()),
        },
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _infer_sector_key(raw_text: str) -> str:
    """Maps a sector keyword or description to one of the 6 canonical SECTOR_CALIBRATION_PROFILES keys."""
    if not raw_text:
        return "ENTERPRISE_DEFAULT"
    upper = raw_text.strip().upper()
    if upper in SECTOR_CALIBRATION_PROFILES:
        return upper
    low = raw_text.lower()
    if any(k in low for k in ("bank", "bfsi", "financ", "capital market", "payment", "pci", "dora", "bacen")):
        return "BFSI_BANKING"
    if any(k in low for k in ("health", "genom", "medical", "pharma", "hipaa", "biotech", "hospital", "ehr")):
        return "HEALTHCARE_GENOMICS"
    if any(k in low for k in ("gov", "defense", "public sector", "federal", "military", "cnsa", "sovereign")):
        return "PUBLIC_SECTOR_DEFENSE"
    if any(k in low for k in ("telecom", "5g", "isp", "carrier", "3gpp", "telco")):
        return "TELECOM_5G_CLOUD"
    if any(k in low for k in ("energy", "utilit", "scada", "ics", "industrial", "automotive", "nerc", "ot ")):
        return "ENERGY_OT_INDUSTRIAL"
    return "ENTERPRISE_DEFAULT"


def extract_text_from_uploaded_bytes(filename: str, raw_bytes: bytes, mime_type: str = "") -> str:
    """Extracts human-readable text or X.509 metadata from PDF, DOCX, PEM/CRT, CSV, JSON, MD, or TXT bytes."""
    ext = os.path.splitext(filename or "")[1].lower()

    # 1. PDF extraction via pypdf
    if ext == ".pdf" or mime_type == "application/pdf":
        try:
            from pypdf import PdfReader

            reader = PdfReader(io.BytesIO(raw_bytes))
            pages_text = [page.extract_text() or "" for page in reader.pages]
            extracted = "\n".join(pages_text).strip()
            if extracted:
                return extracted
        except Exception:
            pass

    # 2. DOCX extraction via python-docx
    if ext == ".docx" or "officedocument.wordprocessingml" in mime_type:
        try:
            import docx

            doc = docx.Document(io.BytesIO(raw_bytes))
            parts: List[str] = [p.text for p in doc.paragraphs if p.text.strip()]
            for table in doc.tables:
                for row in table.rows:
                    row_cells = [c.text.strip() for c in row.cells if c.text.strip()]
                    if row_cells:
                        parts.append(" | ".join(row_cells))
            extracted = "\n".join(parts).strip()
            if extracted:
                return extracted
        except Exception:
            pass

    # 3. X.509 Certificate (.pem, .crt, .cer) inspection via cryptography
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
            sig_algo = cert.signature_algorithm_oid._name
            return (
                f"X509_CERTIFICATE_METADATA:\n"
                f"subject={cert.subject.rfc4514_string()}\n"
                f"issuer={cert.issuer.rfc4514_string()}\n"
                f"public_key_algorithm={algo_desc}\n"
                f"signature_algorithm={sig_algo}\n"
                f"not_valid_before={cert.not_valid_before_utc.isoformat()}\n"
                f"not_valid_after={cert.not_valid_after_utc.isoformat()}\n"
                + raw_bytes.decode("utf-8", errors="ignore")
            )
        except Exception:
            pass

    # 4. Standard UTF-8 / Latin-1 text fallback (CSV, JSON, MD, TXT, PEM, YAML)
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
    """Caches an uploaded multimodal artifact's extracted text and metadata for `analyze_uploaded_pqc_artifact`."""
    extracted_text = extract_text_from_uploaded_bytes(filename, raw_bytes, mime_type)
    record = {
        "filename": filename,
        "mime_type": mime_type,
        "size_bytes": len(raw_bytes),
        "session_id": session_id,
        "extracted_text": extracted_text,
        "uploaded_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    _UPLOADED_ARTIFACT_CACHE[filename] = record
    _UPLOADED_ARTIFACT_CACHE["latest"] = record
    if session_id:
        _UPLOADED_ARTIFACT_CACHE[f"{session_id}:{filename}"] = record
        _UPLOADED_ARTIFACT_CACHE[f"{session_id}:latest"] = record
    return record


def analyze_uploaded_pqc_artifact(
    artifact_name: str = "",
    artifact_content: str = "",
    scope: str = "organizations/31564119954",
) -> str:
    """Analyzes an uploaded PQC Discovery Questionnaire, CSV/JSON cryptographic inventory, or certificate/config file, extracts Mosca/sector parameters, and auto-calibrates the assessment.

    Args:
        artifact_name: Filename of the uploaded file (e.g., 'PQC_Discovery_Questionnaire.md',
            'kms_inventory.csv', 'ingress_cert.pem'). Leave empty or pass 'latest' to analyze the most recently uploaded file.
        artifact_content: Optional raw text or JSON/CSV content of the uploaded artifact. If omitted,
            automatically loads the content extracted from the uploaded file in the current session.
        scope: Target GCP Organization or Project scope to calibrate (default: 'organizations/31564119954').

    Returns:
        JSON string with the detected artifact type, extracted cryptographic inventory or questionnaire parameters,
        vulnerability findings, and the resulting auto-calibration profile.
    """
    from tools.gcp_inventory import classify_crypto_key

    # Resolve content from cache if not explicitly provided
    resolved_name = (artifact_name or "latest").strip()
    cached = _UPLOADED_ARTIFACT_CACHE.get(resolved_name) or _UPLOADED_ARTIFACT_CACHE.get("latest")
    text = (artifact_content or "").strip()
    if not text and cached:
        text = cached.get("extracted_text", "")
        if resolved_name == "latest":
            resolved_name = cached.get("filename", "uploaded_artifact")

    if not text:
        return json.dumps(
            {
                "status": "NO_ARTIFACT_CONTENT_FOUND",
                "artifact_name": resolved_name,
                "message": (
                    "No uploaded artifact content was found in the current session. "
                    "Attach a Discovery Questionnaire (PDF/DOCX/MD/TXT), CSV/JSON inventory, or PEM/CRT certificate."
                ),
            },
            ensure_ascii=False,
        )

    ext = os.path.splitext(resolved_name)[1].lower()
    artifact_type = "DISCOVERY_QUESTIONNAIRE_OR_POLICY_DOC"
    inventory_findings: List[Dict[str, Any]] = []
    certificate_findings: List[Dict[str, Any]] = []

    # 1. Detect & parse CSV Cryptographic Inventory
    if ext == ".csv" or ("," in text.splitlines()[0] and len(text.splitlines()) >= 2 and "algorithm" in text.lower()):
        artifact_type = "CSV_CRYPTOGRAPHIC_INVENTORY"
        try:
            reader = csv.DictReader(io.StringIO(text))
            for idx, row in enumerate(reader, 1):
                norm_row = {str(k or "").strip().lower(): str(v or "").strip() for k, v in row.items()}
                key_name = (
                    norm_row.get("key_name")
                    or norm_row.get("key")
                    or norm_row.get("name")
                    or norm_row.get("asset")
                    or f"csv-key-{idx}"
                )
                key_ring = norm_row.get("key_ring") or norm_row.get("keyring") or "uploaded-csv-keyring"
                algo = (
                    norm_row.get("algorithm")
                    or norm_row.get("algo")
                    or norm_row.get("cipher")
                    or "RSA_DECRYPT_OAEP_2048_SHA256"
                ).upper()
                purpose = (norm_row.get("purpose") or "").upper()
                if not purpose:
                    if "SIGN" in algo or "ECDSA" in algo or "DSA" in algo:
                        purpose = "ASYMMETRIC_SIGN"
                    elif "DECRYPT" in algo or "OAEP" in algo or "KEM" in algo or "RSA" in algo:
                        purpose = "ASYMMETRIC_DECRYPT"
                    else:
                        purpose = "ENCRYPT_DECRYPT"
                rot_str = norm_row.get("rotation_period_days") or norm_row.get("rotation_days") or ""
                rot_days = int(rot_str) if rot_str.isdigit() else None
                classified = classify_crypto_key(
                    key_ring=key_ring,
                    key_name=key_name,
                    purpose=purpose,
                    algorithm=algo,
                    rotation_period_days=rot_days,
                )
                inventory_findings.append(classified)
        except Exception:
            pass

    # 2. Detect & parse JSON CBOM or Inventory
    elif ext == ".json" or (text.startswith("{") and text.endswith("}")):
        artifact_type = "JSON_CBOM_OR_INVENTORY"
        try:
            parsed_json = json.loads(text)
            components = (
                parsed_json.get("components")
                or parsed_json.get("keys")
                or parsed_json.get("inventory")
                or (parsed_json if isinstance(parsed_json, list) else [])
            )
            if isinstance(components, list):
                for idx, comp in enumerate(components, 1):
                    if not isinstance(comp, dict):
                        continue
                    key_name = comp.get("name") or comp.get("key_name") or f"json-key-{idx}"
                    algo = str(
                        comp.get("algorithm")
                        or comp.get("cryptoProperties", {}).get("algorithmProperties", {}).get("variant")
                        or "RSA_SIGN_PSS_2048_SHA256"
                    ).upper()
                    purpose = str(comp.get("purpose") or ("ASYMMETRIC_SIGN" if "SIGN" in algo else "ASYMMETRIC_DECRYPT")).upper()
                    classified = classify_crypto_key(
                        key_ring=str(comp.get("key_ring", "uploaded-json-cbom")),
                        key_name=str(key_name),
                        purpose=purpose,
                        algorithm=algo,
                    )
                    inventory_findings.append(classified)
        except Exception:
            pass

    # 3. Detect & parse Certificate / PEM / TLS Config
    if (
        ext in (".pem", ".crt", ".cer", ".key", ".conf")
        or "BEGIN CERTIFICATE" in text
        or "BEGIN PUBLIC KEY" in text
        or "X509_CERTIFICATE_METADATA:" in text
    ):
        artifact_type = "X509_CERTIFICATE_OR_TLS_CONFIG"
        is_rsa = bool(re.search(r"RSA[_\-\s]?(2048|3072|4096)|rsaEncryption", text, re.IGNORECASE))
        is_ecc = bool(re.search(r"ECDSA|secp256r1|prime256v1|secp384r1|P-256|P-384|ED25519", text, re.IGNORECASE))
        is_pqc = bool(re.search(r"ML-DSA|ML-KEM|XWING|X25519MLKEM768|SLH-DSA", text, re.IGNORECASE))
        certificate_findings.append(
            {
                "artifact_name": resolved_name,
                "quantum_vulnerability_status": (
                    "COMPLIANT_PQC_HYBRID"
                    if is_pqc
                    else ("VULNERABLE_SHOR_CLASSICAL_PKI" if (is_rsa or is_ecc) else "REQUIRES_PQC_UPGRADE")
                ),
                "detected_classical_rsa": is_rsa,
                "detected_classical_ecc": is_ecc,
                "detected_pqc_primitives": is_pqc,
                "recommended_target": (
                    "Migrate X.509 leaf/subordinate certificates to Google Cloud Certificate Authority Service (CAS) "
                    "with ML-DSA-65 / ML-DSA-87 signatures and enable TLS 1.3 RESTRICTED profile (X25519MLKEM768) on Cloud Load Balancing."
                ),
            }
        )

    # 4. Extract Mosca (X, Y, Z), Industry Sector, and Gateway Header Limit parameters from text
    inferred_sector = _infer_sector_key(text)
    base_prof = SECTOR_CALIBRATION_PROFILES[inferred_sector]

    x_match = re.search(
        r"(?:confidentiality|retention|shelf[\-\s]?life|secrecy|mosca\s*x)[^\d\n]{0,40}(\d+(?:\.\d+)?)\s*(?:years|yrs|y|anos)",
        text,
        re.IGNORECASE,
    )
    y_match = re.search(
        r"(?:migration|refactoring|upgrade\s*timeline|mosca\s*y)[^\d\n]{0,40}(\d+(?:\.\d+)?)\s*(?:years|yrs|y|anos)",
        text,
        re.IGNORECASE,
    )
    z_match = re.search(
        r"(?:crqc|quantum\s*horizon|threat\s*horizon|mosca\s*z)[^\d\n]{0,40}(\d+(?:\.\d+)?)\s*(?:years|yrs|y|anos)",
        text,
        re.IGNORECASE,
    )
    hdr_match = re.search(
        r"(?:header\s*(?:buffer|limit|size)|max_request_headers_kb|large_client_header_buffers)[^\d\n]{0,30}(\d+)\s*(?:kb|k\b)",
        text,
        re.IGNORECASE,
    )

    eff_x = float(x_match.group(1)) if x_match else base_prof["default_confidentiality_years_x"]
    eff_y = float(y_match.group(1)) if y_match else base_prof["default_migration_years_y"]
    eff_z = float(z_match.group(1)) if z_match else base_prof["default_crqc_horizon_years_z"]
    eff_hdr_kb = int(hdr_match.group(1)) if hdr_match else base_prof["gateway_header_limit_kb_default"]

    vuln_inv_count = sum(
        1 for item in inventory_findings if item.get("quantum_status") == "VULNERABLE_CLASSICAL_RSA_ECC"
    )
    pqc_inv_count = sum(1 for item in inventory_findings if item.get("quantum_status") == "APPROVED_PQC")

    calibration_raw = calibrate_assessment_context(
        scope=scope,
        industry_sector=inferred_sector,
        confidentiality_years_x=eff_x,
        migration_years_y=eff_y,
        crqc_horizon_years_z=eff_z,
        gateway_header_limit_kb=eff_hdr_kb,
        compensating_controls_note=(
            f"Auto-calibrated from uploaded artifact '{resolved_name}' ({artifact_type}); "
            f"parsed {len(inventory_findings)} inventory items ({vuln_inv_count} vulnerable classical, {pqc_inv_count} PQC-native) "
            f"and {len(certificate_findings)} certificate/TLS items."
        ),
    )
    calibration_result = json.loads(calibration_raw)

    return json.dumps(
        {
            "status": "ARTIFACT_ANALYZED_AND_AUTO_CALIBRATED",
            "artifact_name": resolved_name,
            "detected_artifact_type": artifact_type,
            "scope": scope,
            "extracted_parameters": {
                "industry_sector": inferred_sector,
                "sector_label": base_prof["sector_label"],
                "confidentiality_years_x": eff_x,
                "migration_years_y": eff_y,
                "crqc_horizon_years_z": eff_z,
                "gateway_header_limit_kb": eff_hdr_kb,
            },
            "inventory_analysis_summary": {
                "total_items_parsed": len(inventory_findings),
                "vulnerable_classical_rsa_ecc_count": vuln_inv_count,
                "approved_pqc_count": pqc_inv_count,
                "items": inventory_findings[:50],
            },
            "certificate_or_config_findings": certificate_findings,
            "auto_calibration_result": calibration_result,
        },
        separators=(",", ":"),
        ensure_ascii=False,
    )
