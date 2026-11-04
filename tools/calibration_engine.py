"""Adaptive Self-Calibration & Historical Learning Engine for Google Cloud PQC Assessments.

Connects the structured stakeholder inputs from `PQC_Discovery_Questionnaire` and interactive
consultant calibration prompts (`PQC_User_and_Consultant_Guide`) directly to the deterministic
Mosca Inequality (X + Y > Z) and Monte Carlo Quantum Value-at-Risk (Q-VaR 95%) simulation engines.

Every calibration update is persisted to a longitudinal JSONL ledger (`calibration_history.jsonl`)
so the agent automatically learns from historical interactions, refines sector-specific threat
parameters, and applies active calibration overrides across subsequent assessments.
"""

import datetime
import json
import os
from typing import Any, Dict, List, Optional

DEFAULT_CALIBRATION_PATH = os.getenv(
    "PQC_CALIBRATION_STORE_PATH",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "exports", "calibration_history.jsonl"),
)

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
    if not os.path.exists(store_path):
        return []
    records: List[Dict[str, Any]] = []
    try:
        with open(store_path, "r", encoding="utf-8") as f:
            for line in f:
                line_s = line.strip()
                if line_s:
                    records.append(json.loads(line_s))
    except Exception:
        return []
    return records


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
    sector_key = str(industry_sector or "ENTERPRISE_DEFAULT").strip().upper()
    if sector_key not in SECTOR_CALIBRATION_PROFILES:
        sector_key = "ENTERPRISE_DEFAULT"
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

    os.makedirs(os.path.dirname(DEFAULT_CALIBRATION_PATH), exist_ok=True)
    with open(DEFAULT_CALIBRATION_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

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
