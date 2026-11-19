"""Evidence collection and auditable calculations for the Google Cloud cryptographic inventory.

Design principle (LLM-first):
- These tools only COLLECT facts from Google Cloud APIs (Cloud KMS, Cloud Asset Inventory) and COMPUTE
  verifiable numbers (counts, ratios with explicit numerators/denominators).
- They never correlate workloads to keys heuristically, never prioritize, never recommend and never write
  narrative. That reasoning is performed by the Gemini agents on Vertex AI, which must cite this evidence.

Simulation policy:
- Demo data is returned ONLY when `PQC_SIMULATION_MODE=TRUE` or when the scope is an explicit demo identifier
  listed in `SIMULATION_PROJECT_IDS`. It is never a silent fallback for API errors. Every simulated payload is
  labeled `data_source=SIMULATED_DEMO_DATASET` and carries a `simulation_notice`.
"""

from __future__ import annotations

import concurrent.futures
import datetime
import json
import logging
import os
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

from google.cloud import asset_v1, kms_v1

from tools import mock_data

logger = logging.getLogger(__name__)

DEFAULT_ORGANIZATION_ID = os.getenv("GCP_ORGANIZATION_ID", "31564119954")
DEFAULT_ORGANIZATION_NAME = os.getenv("GCP_ORGANIZATION_NAME", "jsaccomani.altostrat.com")

LIVE_DATA_SOURCE = "LIVE_GCP_API"
SIMULATED_DATA_SOURCE = "SIMULATED_DEMO_DATASET"
SIMULATION_NOTICE = (
    "DEMO DATA: this payload comes from the built-in demo dataset, not from the customer's Google Cloud "
    "environment. It must never be presented as customer findings."
)
REQUIRED_READ_ROLES = [
    "roles/cloudkms.viewer",
    "roles/cloudasset.viewer",
    "roles/resourcemanager.organizationViewer",
]

# In-memory TTL cache so specialist agents can re-read the same evidence without repeating API calls.
_SCAN_CACHE: Dict[str, Tuple[float, str]] = {}
_CACHE_TTL_SECONDS = float(os.getenv("PQC_SCAN_CACHE_TTL_SECONDS", "1800"))

# Explicit demo identifiers. Requesting one of these scopes returns the demo dataset (clearly labeled).
SIMULATION_PROJECT_IDS = {
    "meu-projeto-gcp",
    "my-gcp-project",
    "demo-pqc-project",
    "test-project",
    "seu_projeto_conexao",
}

ORG_MODE_TOKENS = {
    "",
    "org",
    "organization",
    "organizacao",
    "organização",
    "org mode",
    "org-wide",
    "current",
    "default",
    "all",
    "*",
    DEFAULT_ORGANIZATION_ID.lower(),
    f"organizations/{DEFAULT_ORGANIZATION_ID}".lower(),
    DEFAULT_ORGANIZATION_NAME.lower(),
}

# Reference facts for NIST-standardized and Cloud KMS-supported post-quantum algorithms.
ALGORITHM_SPECIFICATIONS: Dict[str, Dict[str, Any]] = {
    "KEM_XWING": {
        "family": "HYBRID_PQC_KEM",
        "nist_standard": "NIST FIPS 203 (ML-KEM-768) + X25519 hybrid (X-Wing)",
        "nist_pqc_security_category": 3,
        "public_key_bytes": 1216,
        "ciphertext_or_signature_bytes": 1120,
    },
    "ML_KEM_768": {
        "family": "PQC_KEM",
        "nist_standard": "NIST FIPS 203 (ML-KEM-768)",
        "nist_pqc_security_category": 3,
        "public_key_bytes": 1184,
        "ciphertext_or_signature_bytes": 1088,
    },
    "ML_KEM_1024": {
        "family": "PQC_KEM",
        "nist_standard": "NIST FIPS 203 (ML-KEM-1024)",
        "nist_pqc_security_category": 5,
        "public_key_bytes": 1568,
        "ciphertext_or_signature_bytes": 1568,
    },
    "PQ_SIGN_ML_DSA_44": {
        "family": "PQC_SIGNATURE",
        "nist_standard": "NIST FIPS 204 (ML-DSA-44)",
        "nist_pqc_security_category": 2,
        "public_key_bytes": 1312,
        "ciphertext_or_signature_bytes": 2420,
    },
    "PQ_SIGN_ML_DSA_65": {
        "family": "PQC_SIGNATURE",
        "nist_standard": "NIST FIPS 204 (ML-DSA-65)",
        "nist_pqc_security_category": 3,
        "public_key_bytes": 1952,
        "ciphertext_or_signature_bytes": 3309,
    },
    "PQ_SIGN_ML_DSA_87": {
        "family": "PQC_SIGNATURE",
        "nist_standard": "NIST FIPS 204 (ML-DSA-87)",
        "nist_pqc_security_category": 5,
        "public_key_bytes": 2592,
        "ciphertext_or_signature_bytes": 4627,
    },
    "PQ_SIGN_SLH_DSA_SHA2_128S": {
        "family": "PQC_SIGNATURE",
        "nist_standard": "NIST FIPS 205 (SLH-DSA-SHA2-128s)",
        "nist_pqc_security_category": 1,
        "public_key_bytes": 32,
        "ciphertext_or_signature_bytes": 7856,
    },
    "PQ_SIGN_HASH_SLH_DSA_SHA2_128S_SHA256": {
        "family": "PQC_SIGNATURE",
        "nist_standard": "NIST FIPS 205 (HashSLH-DSA-SHA2-128s with SHA-256 pre-hash)",
        "nist_pqc_security_category": 1,
        "public_key_bytes": 32,
        "ciphertext_or_signature_bytes": 7856,
    },
}

# Reference facts for classical algorithms (classical security per NIST SP 800-57 Part 1).
CLASSICAL_ALGORITHM_FACTS: Dict[str, Dict[str, Any]] = {
    "RSA_2048": {"classical_security_bits": 112, "signature_or_ciphertext_bytes": 256},
    "RSA_3072": {"classical_security_bits": 128, "signature_or_ciphertext_bytes": 384},
    "RSA_4096": {"classical_security_bits": 140, "signature_or_ciphertext_bytes": 512},
    "EC_P256": {"classical_security_bits": 128, "signature_or_ciphertext_bytes": 64},
    "EC_P384": {"classical_security_bits": 192, "signature_or_ciphertext_bytes": 96},
    "ED25519": {"classical_security_bits": 128, "signature_or_ciphertext_bytes": 64},
    "SECP256K1": {"classical_security_bits": 128, "signature_or_ciphertext_bytes": 64},
}

QUANTUM_STATUS_RANK = {
    "QUANTUM_VULNERABLE_SHOR": 0,
    "UNKNOWN_REQUIRES_REVIEW": 1,
    "BELOW_PQ_SECURITY_TARGET": 2,
    "QUANTUM_RESISTANT_SYMMETRIC": 3,
    "QUANTUM_SAFE_PQC": 4,
}

ASYMMETRIC_FAMILIES = {"CLASSICAL_RSA", "CLASSICAL_ECC", "PQC_KEM", "HYBRID_PQC_KEM", "PQC_SIGNATURE"}
SYMMETRIC_FAMILIES = {"SYMMETRIC_AES_256", "SYMMETRIC_AES_128", "MAC_HMAC"}
ASYMMETRIC_PURPOSES = {"ASYMMETRIC_SIGN", "ASYMMETRIC_DECRYPT", "KEY_ENCAPSULATION"}
SYMMETRIC_PURPOSES = {"ENCRYPT_DECRYPT", "MAC", "RAW_ENCRYPT_DECRYPT"}

WORKLOAD_ASSET_TYPES = [
    "run.googleapis.com/Service",
    "compute.googleapis.com/Instance",
    "compute.googleapis.com/Disk",
    "container.googleapis.com/Cluster",
    "storage.googleapis.com/Bucket",
    "bigquery.googleapis.com/Dataset",
    "sqladmin.googleapis.com/Instance",
    "secretmanager.googleapis.com/Secret",
    "pubsub.googleapis.com/Topic",
    "artifactregistry.googleapis.com/Repository",
    "iam.googleapis.com/ServiceAccount",
]
MAX_WORKLOADS_RETURNED = int(os.getenv("PQC_MAX_WORKLOADS_RETURNED", "600"))


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def _compact_json(payload: Any) -> str:
    """Serializes tool output into compact JSON to reduce LLM input tokens."""
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False, default=str)


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def _get_client_kwargs() -> Dict[str, Any]:
    """Returns {'credentials': creds} for the active tenant connection, failing closed on PermissionError."""
    try:
        from tools.gcloud_bridge import get_active_gcp_credentials

        creds = get_active_gcp_credentials()
        if creds is not None:
            return {"credentials": creds}
    except PermissionError:
        raise
    except Exception:
        pass
    return {}


def _cache_scope_prefix() -> str:
    """Returns a cache key prefix isolating non-default credential modes per tenant user."""
    try:
        from tools.gcloud_bridge import get_gcp_connection_config

        cfg = get_gcp_connection_config(mask_token=True)
        mode = cfg.get("mode", "access_token")
        if mode == "impersonation":
            return f"imp:{cfg.get('user_id', '')}:{cfg.get('impersonated_service_account', '')}"
        if mode == "access_token":
            return f"tok:{cfg.get('user_id', '')}:{cfg.get('access_token_preview', '')}"
        if mode == "adc" and cfg.get("adc_authorized"):
            return f"adc:{cfg.get('user_id', '')}"
    except Exception:
        pass
    return "unconfigured"


def _cache_get(key: str) -> Optional[str]:
    scoped_key = f"{_cache_scope_prefix()}:{key}"
    cached = _SCAN_CACHE.get(scoped_key)
    if cached and (time.monotonic() - cached[0]) < _CACHE_TTL_SECONDS:
        return cached[1]
    return None


def _cache_put(key: str, value: str) -> str:
    scoped_key = f"{_cache_scope_prefix()}:{key}"
    _SCAN_CACHE[scoped_key] = (time.monotonic(), value)
    return value


def excluded_key_rings() -> Set[str]:
    """Key rings explicitly excluded by configuration (`PQC_EXCLUDED_KEY_RINGS`, comma-separated). Default: none."""
    raw = os.getenv("PQC_EXCLUDED_KEY_RINGS", "")
    return {token.strip() for token in raw.split(",") if token.strip()}


def simulation_requested(clean_id: str) -> bool:
    """True only for explicit simulation (`PQC_SIMULATION_MODE=TRUE`) or an explicit demo scope identifier."""
    if os.getenv("PQC_SIMULATION_MODE", "FALSE").strip().upper() == "TRUE":
        return True
    return (clean_id or "").strip().lower() in SIMULATION_PROJECT_IDS


def _is_internal_runtime_tenant_project(proj_id: str) -> bool:
    """Detects internal Google-managed Vertex AI Agent Engine runtime tenant projects (e.g. `*-tp`)."""
    clean = (proj_id or "").strip().lower()
    if not clean or clean in SIMULATION_PROJECT_IDS:
        return False
    if clean.endswith("-tp") or clean in ("vertex-ai-tenant", "agent-engine-tenant", "reasoning-engine-tenant"):
        return True
    return bool(re.match(r"^project-[0-9a-f]{6,}-[0-9a-f]{4}-", clean))


def _active_tenant_org_id() -> str:
    """Returns the active tenant user's configured Organization ID, falling back to DEFAULT_ORGANIZATION_ID."""
    try:
        from tools.gcloud_bridge import get_gcp_connection_config

        org = (get_gcp_connection_config(mask_token=True).get("organization_id") or "").strip()
        if org:
            return org.replace("organizations/", "")
    except Exception:
        pass
    return DEFAULT_ORGANIZATION_ID


def _resolve_scope(target: Optional[str] = None) -> Tuple[str, str, str]:
    """Resolves the requested scope into (mode, scope_uri, clean_id)."""
    raw = (target or "").strip()
    lower = raw.lower()
    active_org = _active_tenant_org_id()

    if lower in ORG_MODE_TOKENS:
        return ("ORG", f"organizations/{active_org}", active_org)
    if lower.startswith("organizations/"):
        org_id = raw.split("/", 1)[1].strip() or active_org
        return ("ORG", f"organizations/{org_id}", org_id)
    if raw.isdigit() and len(raw) >= 8:
        return ("ORG", f"organizations/{raw}", raw)
    if lower.startswith("folders/"):
        folder_id = raw.split("/", 1)[1].strip()
        return ("FOLDER", f"folders/{folder_id}", folder_id)

    proj_id = raw.split("/", 1)[1].strip() if lower.startswith("projects/") else raw
    if _is_internal_runtime_tenant_project(proj_id):
        logger.info("Redirecting internal runtime tenant project '%s' to the configured organization.", proj_id)
        return ("ORG", f"organizations/{active_org}", active_org)
    return ("PROJECT", f"projects/{proj_id}", proj_id)


def _project_from_cai_name(resource_name: str, fallback: str = "") -> str:
    parts = (resource_name or "").split("/")
    if len(parts) >= 5 and parts[3] == "projects":
        return parts[4]
    if "projects/" in (resource_name or ""):
        return resource_name.split("projects/", 1)[1].split("/", 1)[0]
    return (fallback or "").split("/")[-1]


def _ratio_metric(numerator: int, denominator: int, definition: str) -> Dict[str, Any]:
    value = round((numerator / denominator) * 100.0, 1) if denominator else None
    return {
        "value_pct": value,
        "numerator": numerator,
        "denominator": denominator,
        "definition": definition,
        "note": None if denominator else "Not applicable: denominator is zero in this scope.",
    }


# ---------------------------------------------------------------------------
# Factual algorithm classification
# ---------------------------------------------------------------------------


def _classical_fact_key(algo: str) -> Optional[str]:
    if algo.startswith("RSA_"):
        if "4096" in algo:
            return "RSA_4096"
        if "3072" in algo:
            return "RSA_3072"
        return "RSA_2048"
    if "P384" in algo:
        return "EC_P384"
    if "P256" in algo:
        return "EC_P256"
    if "ED25519" in algo:
        return "ED25519"
    if "SECP256K1" in algo:
        return "SECP256K1"
    return None


def _cloud_kms_pqc_alternatives(purpose: str, status: str, family: str) -> List[Dict[str, Any]]:
    """Factual list of Cloud KMS algorithms that provide post-quantum security for the same function."""
    def _opt(name: str, api_note: str) -> Dict[str, Any]:
        spec = ALGORITHM_SPECIFICATIONS.get(name, {})
        return {
            "algorithm": name,
            "nist_standard": spec.get("nist_standard"),
            "nist_pqc_security_category": spec.get("nist_pqc_security_category"),
            "public_key_bytes": spec.get("public_key_bytes"),
            "ciphertext_or_signature_bytes": spec.get("ciphertext_or_signature_bytes"),
            "cloud_kms_api_contract": api_note,
        }

    if status == "QUANTUM_VULNERABLE_SHOR" and ("DECRYPT" in purpose or family == "CLASSICAL_RSA" and "SIGN" not in purpose):
        note = (
            "KEY_ENCAPSULATION purpose: Encapsulate/Decapsulate a shared secret (KEM). "
            "AsymmetricDecrypt is not available on KEM keys."
        )
        return [_opt("KEM_XWING", note), _opt("ML_KEM_768", note), _opt("ML_KEM_1024", note)]
    if status == "QUANTUM_VULNERABLE_SHOR":
        ml_dsa_note = (
            "ASYMMETRIC_SIGN purpose: pure ML-DSA signs the message data (not a pre-computed digest); "
            "the *_EXTERNAL_MU variants accept a client-computed message representative."
        )
        slh_note = "ASYMMETRIC_SIGN purpose: stateless hash-based signature (large signatures, small public keys)."
        return [
            _opt("PQ_SIGN_ML_DSA_44", ml_dsa_note),
            _opt("PQ_SIGN_ML_DSA_65", ml_dsa_note),
            _opt("PQ_SIGN_ML_DSA_87", ml_dsa_note),
            _opt("PQ_SIGN_SLH_DSA_SHA2_128S", slh_note),
        ]
    if status == "BELOW_PQ_SECURITY_TARGET":
        return [
            {"algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION", "cloud_kms_api_contract": "ENCRYPT_DECRYPT (AES-256-GCM)"},
            {"algorithm": "HMAC_SHA256", "cloud_kms_api_contract": "MAC (MacSign/MacVerify)"},
        ]
    return []


def classify_algorithm(algorithm: str, purpose: str = "") -> Dict[str, Any]:
    """Returns factual classification of a Cloud KMS algorithm (no recommendations or prose).

    Unknown or unrecognized algorithms are classified as `UNKNOWN_REQUIRES_REVIEW` (fail-closed), never as safe.
    """
    algo = (algorithm or "").strip().upper()
    purp = (purpose or "").strip().upper()
    spec_key = algo.replace("_EXTERNAL_MU", "")
    flags: List[str] = []
    if "SHA1" in algo:
        flags.append("SHA1_DEPRECATED_HASH")
    if "RAW_PKCS1" in algo:
        flags.append("RAW_PKCS1_SIGNATURE_WITHOUT_HASH_ENCODING")

    pq_bits: Optional[int] = None
    nist_reference: Optional[str] = None
    if not algo or algo in ("UNKNOWN", "UNKNOWN_ALGORITHM", "CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED"):
        family, status, threat = "UNKNOWN", "UNKNOWN_REQUIRES_REVIEW", "UNKNOWN"
    elif any(t in algo for t in ("ML_KEM", "KEM_XWING", "XWING")):
        family = "HYBRID_PQC_KEM" if "XWING" in algo else "PQC_KEM"
        status, threat = "QUANTUM_SAFE_PQC", "NO_KNOWN_EFFICIENT_QUANTUM_ATTACK"
        nist_reference = "NIST FIPS 203"
    elif any(t in algo for t in ("ML_DSA", "SLH_DSA", "PQ_SIGN")):
        family, status, threat = "PQC_SIGNATURE", "QUANTUM_SAFE_PQC", "NO_KNOWN_EFFICIENT_QUANTUM_ATTACK"
        nist_reference = "NIST FIPS 205" if "SLH_DSA" in algo else "NIST FIPS 204"
    elif algo.startswith("RSA_"):
        family, status, threat = "CLASSICAL_RSA", "QUANTUM_VULNERABLE_SHOR", "SHOR_INTEGER_FACTORIZATION"
        pq_bits = 0
    elif algo.startswith("EC_SIGN") or "ED25519" in algo or "SECP256K1" in algo:
        family, status, threat = "CLASSICAL_ECC", "QUANTUM_VULNERABLE_SHOR", "SHOR_ELLIPTIC_CURVE_DISCRETE_LOG"
        pq_bits = 0
    elif algo == "GOOGLE_SYMMETRIC_ENCRYPTION" or algo.startswith("AES_256"):
        family, status, threat = "SYMMETRIC_AES_256", "QUANTUM_RESISTANT_SYMMETRIC", "GROVER_QUADRATIC_SPEEDUP"
        pq_bits = 128
    elif algo.startswith("AES_128"):
        family, status, threat = "SYMMETRIC_AES_128", "BELOW_PQ_SECURITY_TARGET", "GROVER_QUADRATIC_SPEEDUP"
        pq_bits = 64
    elif algo.startswith("HMAC_"):
        family, threat = "MAC_HMAC", "GROVER_QUADRATIC_SPEEDUP"
        key_bits = {"HMAC_SHA1": 160, "HMAC_SHA224": 224, "HMAC_SHA256": 256, "HMAC_SHA384": 384, "HMAC_SHA512": 512}
        bits = key_bits.get(algo)
        pq_bits = min(bits // 2, 256) if bits else None
        status = "QUANTUM_RESISTANT_SYMMETRIC" if (pq_bits or 0) >= 128 else "BELOW_PQ_SECURITY_TARGET"
        if bits is None:
            status = "UNKNOWN_REQUIRES_REVIEW"
    elif algo == "EXTERNAL_SYMMETRIC_ENCRYPTION":
        family, status, threat = "EXTERNAL_KEY_MANAGER", "UNKNOWN_REQUIRES_REVIEW", "DEPENDS_ON_EXTERNAL_KEY_MANAGER"
        flags.append("KEY_MATERIAL_MANAGED_OUTSIDE_GOOGLE_CLOUD")
    else:
        family, status, threat = "UNRECOGNIZED", "UNKNOWN_REQUIRES_REVIEW", "UNKNOWN"

    facts: Dict[str, Any] = {
        "algorithm": algo or "UNKNOWN",
        "algorithm_family": family,
        "quantum_status": status,
        "quantum_threat_model": threat,
        "estimated_post_quantum_security_bits": pq_bits,
        "nist_reference": nist_reference,
        "deprecated_primitive_flags": flags,
    }
    spec = ALGORITHM_SPECIFICATIONS.get(spec_key)
    if spec:
        facts["nist_reference"] = spec["nist_standard"]
        facts["nist_pqc_security_category"] = spec["nist_pqc_security_category"]
        facts["artifact_sizes_bytes"] = {
            "public_key": spec["public_key_bytes"],
            "ciphertext_or_signature": spec["ciphertext_or_signature_bytes"],
        }
    classical_key = _classical_fact_key(algo) if family in ("CLASSICAL_RSA", "CLASSICAL_ECC") else None
    if classical_key:
        cfacts = CLASSICAL_ALGORITHM_FACTS[classical_key]
        facts["classical_security_bits"] = cfacts["classical_security_bits"]
        facts["artifact_sizes_bytes"] = {"ciphertext_or_signature": cfacts["signature_or_ciphertext_bytes"]}
    facts["cloud_kms_pqc_alternatives"] = _cloud_kms_pqc_alternatives(purp, status, family)
    return facts


# ---------------------------------------------------------------------------
# Cloud KMS key records (facts only)
# ---------------------------------------------------------------------------


def build_key_record(
    *,
    project_id: str,
    location: str,
    key_ring: str,
    key_name: str,
    purpose: str,
    algorithm: str,
    protection_level: str = "SOFTWARE",
    rotation_period_days: Optional[int] = None,
    labels: Optional[Dict[str, str]] = None,
    primary_state: Optional[str] = "ENABLED",
    enabled_version_ids: Optional[List[str]] = None,
    enabled_version_algorithms: Optional[List[str]] = None,
    iam_bindings: Optional[List[Dict[str, Any]]] = None,
    next_rotation_time: Optional[str] = None,
    create_time: Optional[str] = None,
    versions_listing_error: Optional[str] = None,
    iam_listing_error: Optional[str] = None,
    data_source: str = LIVE_DATA_SOURCE,
) -> Dict[str, Any]:
    """Builds a factual Cloud KMS key record used by every downstream tool."""
    purpose_upper = (purpose or "UNKNOWN").upper()
    template_algo = (algorithm or "UNKNOWN").upper()
    version_algos = sorted({a.upper() for a in (enabled_version_algorithms or []) if a})
    primary = (primary_state or "NO_PRIMARY").upper()

    activity_assumed_due_to_version_error = False
    if versions_listing_error:
        # Version listing failed: asymmetric keys never populate `key.primary` (`NO_PRIMARY`).
        # Conservatively treat non-disabled/non-destroyed keys as active rather than silently dropping them.
        if primary in ("DESTROYED", "DESTROY_SCHEDULED", "DISABLED"):
            is_active = False
        elif primary == "ENABLED":
            is_active = True
        else:
            is_active = True
            activity_assumed_due_to_version_error = True
    else:
        is_active = bool(enabled_version_ids) and primary not in ("DESTROYED", "DESTROY_SCHEDULED", "DISABLED")

    # Classify the weakest algorithm among the template and enabled versions (downgrade-aware).
    candidates = [template_algo] + [a for a in version_algos if a != template_algo]
    classified = [classify_algorithm(a, purpose_upper) for a in candidates]
    effective = min(classified, key=lambda f: QUANTUM_STATUS_RANK.get(f["quantum_status"], 1))

    hygiene_flags: Dict[str, Any] = {}
    if effective["algorithm_family"] in SYMMETRIC_FAMILIES and purpose_upper == "ENCRYPT_DECRYPT":
        hygiene_flags = {
            "rotation_configured": rotation_period_days is not None,
            "rotation_period_days": rotation_period_days,
            "rotation_within_90_days": (rotation_period_days is not None and rotation_period_days <= 90),
        }

    record: Dict[str, Any] = {
        "project_id": project_id,
        "location": location,
        "key_ring": key_ring,
        "key_name": key_name,
        "resource_name": f"projects/{project_id}/locations/{location}/keyRings/{key_ring}/cryptoKeys/{key_name}",
        "purpose": purpose_upper,
        "template_algorithm": template_algo,
        "enabled_version_algorithms": version_algos,
        "version_algorithms_mismatch": len(set(candidates)) > 1 and bool(version_algos),
        "effective_algorithm": effective["algorithm"],
        "algorithm_facts": effective,
        "protection_level": (protection_level or "SOFTWARE").upper(),
        "primary_state": primary,
        "enabled_version_ids": list(enabled_version_ids or []),
        "is_active": is_active,
        "rotation_period_days": rotation_period_days,
        "next_rotation_time": next_rotation_time,
        "create_time": create_time,
        "hygiene_flags": hygiene_flags,
        "labels": dict(labels or {}),
        "iam_bindings": list(iam_bindings or []),
        "data_source": data_source,
    }
    if versions_listing_error:
        record["versions_listing_error"] = versions_listing_error
        record["activity_assumed_due_to_version_error"] = activity_assumed_due_to_version_error
    if iam_listing_error:
        record["iam_listing_error"] = iam_listing_error
    return record


def _ts_to_iso(ts: Any) -> Optional[str]:
    if not ts:
        return None
    try:
        return ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
    except Exception:
        return None


def _inspect_single_kms_key(
    client: kms_v1.KeyManagementServiceClient,
    project_id: str,
    location_id: str,
    kr_short_name: str,
    key: Any,
) -> Dict[str, Any]:
    """Reads one CryptoKey (template, versions, rotation, labels, IAM bindings) and returns a factual record."""
    purpose = key.purpose.name if hasattr(key.purpose, "name") else str(key.purpose)
    template = key.version_template
    template_algo = template.algorithm.name if template and hasattr(template.algorithm, "name") else "UNKNOWN_ALGORITHM"
    protection = template.protection_level.name if template and hasattr(template.protection_level, "name") else "UNKNOWN"

    rotation_days: Optional[int] = None
    if key.rotation_period:
        secs = (
            key.rotation_period.total_seconds()
            if hasattr(key.rotation_period, "total_seconds")
            else getattr(key.rotation_period, "seconds", 0)
        )
        if secs and secs > 0:
            rotation_days = int(secs // 86400)

    primary_state = key.primary.state.name if key.primary and hasattr(key.primary.state, "name") else "NO_PRIMARY"

    enabled_ids: List[str] = []
    enabled_algos: List[str] = []
    versions_error: Optional[str] = None
    try:
        for ver in client.list_crypto_key_versions(request={"parent": key.name}):
            state = ver.state.name if hasattr(ver.state, "name") else str(ver.state)
            if state == "ENABLED":
                enabled_ids.append(ver.name.split("/")[-1])
                algo = ver.algorithm.name if hasattr(ver.algorithm, "name") else str(ver.algorithm)
                if algo:
                    enabled_algos.append(algo)
    except Exception as exc:
        versions_error = f"{type(exc).__name__}: {str(exc)[:200]}"

    bindings: List[Dict[str, Any]] = []
    iam_error: Optional[str] = None
    try:
        policy = client.get_iam_policy(request={"resource": key.name})
        for binding in policy.bindings:
            members = list(binding.members)
            bindings.append({"role": binding.role, "members": members[:25], "member_count": len(members)})
    except Exception as exc:
        iam_error = f"{type(exc).__name__}: {str(exc)[:200]}"

    return build_key_record(
        project_id=project_id,
        location=location_id,
        key_ring=kr_short_name,
        key_name=key.name.split("/")[-1],
        purpose=purpose,
        algorithm=template_algo,
        protection_level=protection,
        rotation_period_days=rotation_days,
        labels=dict(key.labels) if key.labels else {},
        primary_state=primary_state,
        enabled_version_ids=enabled_ids,
        enabled_version_algorithms=enabled_algos,
        iam_bindings=bindings,
        next_rotation_time=_ts_to_iso(getattr(key, "next_rotation_time", None)),
        create_time=_ts_to_iso(getattr(key, "create_time", None)),
        versions_listing_error=versions_error,
        iam_listing_error=iam_error,
    )


def _scan_kms_location(
    client: kms_v1.KeyManagementServiceClient,
    project_id: str,
    location_id: str,
    skipped_key_rings: List[str],
) -> List[Dict[str, Any]]:
    """Lists every CryptoKey in a project/location and inspects them in parallel."""
    parent = f"projects/{project_id}/locations/{location_id}"
    excluded = excluded_key_rings()
    key_tasks: List[Tuple[str, Any]] = []
    for key_ring in client.list_key_rings(request={"parent": parent}):
        kr_short = key_ring.name.split("/")[-1]
        if kr_short in excluded:
            skipped_key_rings.append(f"{project_id}/{location_id}/{kr_short}")
            continue
        for key in client.list_crypto_keys(request={"parent": key_ring.name}):
            key_tasks.append((kr_short, key))

    if not key_tasks:
        return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(key_tasks))) as executor:
        futures = [
            executor.submit(_inspect_single_kms_key, client, project_id, location_id, kr, key)
            for kr, key in key_tasks
        ]
        return [f.result() for f in futures]


DEFAULT_FUNCTIONAL_LAB_FALLBACK_SCOPES: Tuple[str, ...] = (
    "folders/534285347409",
    "projects/pqc-inventory-agent-cd06",
    "projects/pqc-inventory-agent-dev",
)


def _cai_search_all_resources_with_fallback(
    cai_client: Any,
    scope_uri: str,
    asset_types: List[str],
    read_mask: Optional[str] = None,
    page_size: int = 500,
) -> List[Any]:
    """Queries Cloud Asset Inventory `search_all_resources` for `scope_uri`.
    When `scope_uri` is `organizations/31564119954` and the runtime service account is scoped to the Functional Lab
    folder (`folders/534285347409`) + host project (`projects/pqc-inventory-agent-cd06`), transparently falls back
    to querying those scopes and deduplicating resources by `name`."""
    req: Dict[str, Any] = {
        "scope": scope_uri,
        "asset_types": list(asset_types),
        "page_size": page_size,
    }
    if read_mask:
        req["read_mask"] = read_mask
    try:
        return list(cai_client.search_all_resources(request=req))
    except Exception as primary_exc:
        if scope_uri != f"organizations/{DEFAULT_ORGANIZATION_ID}":
            raise
        combined: List[Any] = []
        seen_names: Set[str] = set()
        any_succeeded = False
        for fb_scope in DEFAULT_FUNCTIONAL_LAB_FALLBACK_SCOPES:
            fb_req = dict(req, scope=fb_scope)
            try:
                for item in cai_client.search_all_resources(request=fb_req):
                    any_succeeded = True
                    item_name = getattr(item, "name", "")
                    if item_name and item_name in seen_names:
                        continue
                    if item_name:
                        seen_names.add(item_name)
                    combined.append(item)
            except Exception:
                continue
        if any_succeeded:
            return combined
        raise primary_exc


def _discover_kms_targets_via_cai(scope_uri: str, errors: List[str]) -> List[Tuple[str, str]]:
    """Discovers (project_id, location) pairs that contain KeyRings/CryptoKeys inside the scope."""
    targets: Set[Tuple[str, str]] = set()
    try:
        cai_client = asset_v1.AssetServiceClient(**_get_client_kwargs())
        response = _cai_search_all_resources_with_fallback(
            cai_client=cai_client,
            scope_uri=scope_uri,
            asset_types=["cloudkms.googleapis.com/KeyRing", "cloudkms.googleapis.com/CryptoKey"],
            page_size=500,
        )
        for resource in response:
            parts = resource.name.split("/")
            if len(parts) >= 7 and parts[3] == "projects" and parts[5] == "locations":
                targets.add((parts[4], parts[6]))
    except Exception as exc:
        errors.append(f"Cloud Asset Inventory KMS discovery failed for {scope_uri}: {type(exc).__name__}: {str(exc)[:200]}")
    if not targets and scope_uri.startswith("projects/"):
        targets.add((scope_uri.split("/", 1)[1], "global"))
    return sorted(targets)


def _attach_alternatives_reference(keys: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Replaces per-key `cloud_kms_pqc_alternatives` lists with a reference id into one shared table."""
    reference: Dict[str, Any] = {}
    compacted: List[Dict[str, Any]] = []
    for key in keys:
        facts = dict(key.get("algorithm_facts", {}))
        alternatives = facts.pop("cloud_kms_pqc_alternatives", None)
        if alternatives:
            ref_id = "+".join(sorted(a["algorithm"] for a in alternatives))
            reference.setdefault(ref_id, alternatives)
            facts["cloud_kms_pqc_alternatives_ref"] = ref_id
        compacted.append({**key, "algorithm_facts": facts})
    return compacted, reference


def _inventory_summary(keys: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_status: Dict[str, int] = {}
    by_project: Dict[str, int] = {}
    by_purpose: Dict[str, int] = {}
    active = 0
    for k in keys:
        if k.get("is_active"):
            active += 1
            status = k["algorithm_facts"]["quantum_status"]
            by_status[status] = by_status.get(status, 0) + 1
        by_project[k["project_id"]] = by_project.get(k["project_id"], 0) + 1
        by_purpose[k["purpose"]] = by_purpose.get(k["purpose"], 0) + 1
    return {
        "key_count": len(keys),
        "active_key_count": active,
        "inactive_key_count": len(keys) - active,
        "active_keys_by_quantum_status": by_status,
        "keys_by_project": by_project,
        "keys_by_purpose": by_purpose,
    }


def collect_kms_inventory(
    scope: str = f"organizations/{DEFAULT_ORGANIZATION_ID}",
    location: str = "all",
) -> str:
    """Collects the Cloud KMS key inventory for an organization, folder or project (facts only).

    Returns every CryptoKey with purpose, template and enabled-version algorithms, protection level, primary
    state, rotation settings, labels, IAM bindings (role -> members) and a factual algorithm classification
    (family, quantum threat model, NIST reference, artifact sizes, Cloud KMS post-quantum alternatives).
    It performs no correlation, prioritization or recommendation.

    Args:
        scope: 'organizations/<id>', 'folders/<id>', 'projects/<id>' or a bare project ID.
        location: Cloud KMS location filter, or 'all' to cover every location that has key rings.

    Returns:
        JSON with `data_source`, summary counts, `keys`, `collection_errors` and `excluded_key_rings`,
        or an `error` object with the IAM roles required when the inventory cannot be read.
    """
    mode, scope_uri, clean_id = _resolve_scope(scope)
    loc = (location or "all").strip()
    simulated = simulation_requested(clean_id)
    cache_key = f"kms:{scope_uri}:{loc.lower()}:{simulated}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    if simulated:
        keys = [
            build_key_record(project_id=clean_id, enabled_version_ids=["1"], data_source=SIMULATED_DATA_SOURCE, **raw)
            for raw in mock_data.get_simulated_kms_raw_keys(clean_id, loc)
        ]
        compact_keys, alternatives_reference = _attach_alternatives_reference(keys)
        payload = {
            "scope": scope_uri,
            "scope_mode": mode,
            "data_source": SIMULATED_DATA_SOURCE,
            "simulation_notice": SIMULATION_NOTICE,
            "generated_at": _now_iso(),
            **_inventory_summary(keys),
            "keys": compact_keys,
            "cloud_kms_pqc_alternatives_reference": alternatives_reference,
            "collection_errors": [],
            "excluded_key_rings": [],
        }
        return _cache_put(cache_key, _compact_json(payload))

    errors: List[str] = []
    skipped: List[str] = []
    keys: List[Dict[str, Any]] = []
    try:
        client = kms_v1.KeyManagementServiceClient(**_get_client_kwargs())
        targets = _discover_kms_targets_via_cai(scope_uri, errors)
        if loc.lower() not in ("all", "*", ""):
            if mode == "PROJECT":
                targets = [(clean_id, loc)]
            else:
                targets = [(p, l) for (p, l) in targets if l == loc]

        if targets:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(targets))) as executor:
                futures = {
                    executor.submit(_scan_kms_location, client, proj, l, skipped): (proj, l) for proj, l in targets
                }
                for fut in concurrent.futures.as_completed(futures):
                    proj, l = futures[fut]
                    try:
                        keys.extend(fut.result())
                    except Exception as exc:
                        errors.append(f"Cloud KMS listing failed for {proj}/{l}: {type(exc).__name__}: {str(exc)[:200]}")
    except Exception as exc:
        return _compact_json(
            {
                "scope": scope_uri,
                "scope_mode": mode,
                "data_source": LIVE_DATA_SOURCE,
                "error": f"Cloud KMS inventory could not be read: {type(exc).__name__}: {str(exc)[:300]}",
                "required_roles": REQUIRED_READ_ROLES,
            }
        )

    keys.sort(key=lambda k: (k["project_id"], k["location"], k["key_ring"], k["key_name"]))
    compact_keys, alternatives_reference = _attach_alternatives_reference(keys)
    payload = {
        "scope": scope_uri,
        "scope_mode": mode,
        "organization_domain": DEFAULT_ORGANIZATION_NAME if mode == "ORG" else None,
        "data_source": LIVE_DATA_SOURCE,
        "generated_at": _now_iso(),
        **_inventory_summary(keys),
        "keys": compact_keys,
        "cloud_kms_pqc_alternatives_reference": alternatives_reference,
        "collection_errors": errors,
        "excluded_key_rings": sorted(set(skipped)),
    }
    if not keys and errors:
        payload["error"] = "No keys could be read; see collection_errors."
        payload["required_roles"] = REQUIRED_READ_ROLES
    return _cache_put(cache_key, _compact_json(payload))


# ---------------------------------------------------------------------------
# Workload evidence (Cloud Asset Inventory) — raw facts for the correlation agent
# ---------------------------------------------------------------------------


def _normalize_kms_key_ref(k_ref: str) -> str:
    clean = (k_ref or "").split("/cryptoKeyVersions/")[0]
    idx = clean.find("projects/")
    return clean[idx:] if idx >= 0 else clean


def _build_workload_evidence_payload(
    mode: str, scope_uri: str, raw_workloads: List[Dict[str, Any]], data_source: str, errors: List[str]
) -> Dict[str, Any]:
    cmek_references: List[Dict[str, Any]] = []
    workloads: List[Dict[str, Any]] = []
    by_type: Dict[str, int] = {}
    for w in raw_workloads:
        refs = [_normalize_kms_key_ref(r) for r in (w.get("kms_keys") or []) if r]
        entry = {k: v for k, v in w.items() if k != "kms_keys"}
        entry["kms_key_references"] = refs
        workloads.append(entry)
        by_type[w["asset_type"]] = by_type.get(w["asset_type"], 0) + 1
        for ref in refs:
            cmek_references.append(
                {
                    "kms_key": ref,
                    "consumer_resource": w["name"],
                    "consumer_asset_type": w["asset_type"],
                    "consumer_project_id": w.get("project_id"),
                    "evidence_source": "Cloud Asset Inventory resource kmsKey/kmsKeys field",
                }
            )
    truncated = len(workloads) > MAX_WORKLOADS_RETURNED
    payload: Dict[str, Any] = {
        "scope": scope_uri,
        "scope_mode": mode,
        "data_source": data_source,
        "generated_at": _now_iso(),
        "cmek_reference_count": len(cmek_references),
        "cmek_references": cmek_references,
        "workload_count": len(workloads),
        "workloads_by_asset_type": by_type,
        "workloads": workloads[:MAX_WORKLOADS_RETURNED],
        "workloads_truncated": truncated,
        "collection_errors": errors,
    }
    if data_source == SIMULATED_DATA_SOURCE:
        payload["simulation_notice"] = SIMULATION_NOTICE
    return payload


def collect_workload_evidence(scope: str = f"organizations/{DEFAULT_ORGANIZATION_ID}") -> str:
    """Collects raw workload evidence from Cloud Asset Inventory for key-to-workload correlation (facts only).

    Returns workloads (Cloud Run, GKE, Compute, Storage, BigQuery, Cloud SQL, Secret Manager, Pub/Sub,
    Artifact Registry, service accounts) with labels and the exact Cloud KMS keys referenced by each resource
    (CMEK). It does not infer relationships; the correlation agent decides and cites evidence levels.

    Args:
        scope: 'organizations/<id>', 'folders/<id>', 'projects/<id>' or a bare project ID.

    Returns:
        JSON with `cmek_references` (exact key -> consumer resource), `workloads`, counts and `collection_errors`.
    """
    mode, scope_uri, clean_id = _resolve_scope(scope)
    simulated = simulation_requested(clean_id)
    cache_key = f"workloads:{scope_uri}:{simulated}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    if simulated:
        raw = mock_data.get_simulated_workload_evidence(clean_id)["workloads"]
        payload = _build_workload_evidence_payload(mode, scope_uri, raw, SIMULATED_DATA_SOURCE, [])
        return _cache_put(cache_key, _compact_json(payload))

    raw_workloads: List[Dict[str, Any]] = []
    try:
        cai_client = asset_v1.AssetServiceClient(**_get_client_kwargs())
        response = _cai_search_all_resources_with_fallback(
            cai_client=cai_client,
            scope_uri=scope_uri,
            asset_types=WORKLOAD_ASSET_TYPES,
            page_size=500,
        )
        for r in response:
            refs: List[str] = []
            if getattr(r, "kms_key", ""):
                refs.append(r.kms_key)
            for k_ref in getattr(r, "kms_keys", None) or []:
                if k_ref not in refs:
                    refs.append(k_ref)
            raw_workloads.append(
                {
                    "asset_type": r.asset_type,
                    "name": r.name,
                    "display_name": r.display_name or r.name.split("/")[-1],
                    "project_id": _project_from_cai_name(r.name, r.project),
                    "location": r.location or "global",
                    "labels": dict(r.labels) if r.labels else {},
                    "kms_keys": refs,
                }
            )
    except Exception as exc:
        return _compact_json(
            {
                "scope": scope_uri,
                "scope_mode": mode,
                "data_source": LIVE_DATA_SOURCE,
                "error": f"Cloud Asset Inventory workload search failed: {type(exc).__name__}: {str(exc)[:300]}",
                "required_roles": ["roles/cloudasset.viewer"],
            }
        )

    payload = _build_workload_evidence_payload(mode, scope_uri, raw_workloads, LIVE_DATA_SOURCE, [])
    return _cache_put(cache_key, _compact_json(payload))


# ---------------------------------------------------------------------------
# Crypto / PKI assets from Cloud Asset Inventory (raw attributes)
# ---------------------------------------------------------------------------

CRYPTO_ASSET_TYPES = [
    "compute.googleapis.com/SslCertificate",
    "certificatemanager.googleapis.com/Certificate",
    "privateca.googleapis.com/CertificateAuthority",
    "compute.googleapis.com/SslPolicy",
]
_CRYPTO_ATTRIBUTE_KEYS = (
    "type",
    "expireTime",
    "minTlsVersion",
    "profile",
    "customFeatures",
    "keySpec",
    "managed",
    "subjectAlternativeNames",
    "state",
)


def discover_all_crypto_assets(scope: str = f"organizations/{DEFAULT_ORGANIZATION_ID}") -> str:
    """Lists TLS certificates, Certificate Manager certificates, Private CA authorities and SSL policies (raw facts).

    Args:
        scope: 'organizations/<id>', 'folders/<id>', 'projects/<id>' or a bare project ID.

    Returns:
        JSON with `assets` (asset type, name, project, location, state, selected raw attributes, labels).
    """
    mode, scope_uri, clean_id = _resolve_scope(scope)
    simulated = simulation_requested(clean_id)
    cache_key = f"cai-crypto:{scope_uri}:{simulated}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    if simulated:
        payload = {
            "scope": scope_uri,
            "scope_mode": mode,
            "data_source": SIMULATED_DATA_SOURCE,
            "simulation_notice": SIMULATION_NOTICE,
            "generated_at": _now_iso(),
            "assets": mock_data.get_simulated_cai_crypto_assets(clean_id),
        }
        payload["asset_count"] = len(payload["assets"])
        return _cache_put(cache_key, _compact_json(payload))

    assets: List[Dict[str, Any]] = []
    try:
        cai_client = asset_v1.AssetServiceClient(**_get_client_kwargs())
        response = _cai_search_all_resources_with_fallback(
            cai_client=cai_client,
            scope_uri=scope_uri,
            asset_types=CRYPTO_ASSET_TYPES,
            read_mask="*",
            page_size=500,
        )
        for resource in response:
            attrs: Dict[str, Any] = {}
            if getattr(resource, "versioned_resources", None):
                try:
                    full = dict(resource.versioned_resources[0].resource)
                    attrs = {k: full[k] for k in _CRYPTO_ATTRIBUTE_KEYS if k in full}
                except Exception:
                    attrs = {}
            assets.append(
                {
                    "asset_type": resource.asset_type,
                    "name": resource.name,
                    "display_name": resource.display_name,
                    "project_id": _project_from_cai_name(resource.name, resource.project),
                    "location": resource.location,
                    "state": resource.state,
                    "attributes": attrs,
                    "labels": dict(resource.labels) if resource.labels else {},
                }
            )
    except Exception as exc:
        return _compact_json(
            {
                "scope": scope_uri,
                "scope_mode": mode,
                "data_source": LIVE_DATA_SOURCE,
                "error": f"Cloud Asset Inventory crypto asset search failed: {type(exc).__name__}: {str(exc)[:300]}",
                "required_roles": ["roles/cloudasset.viewer"],
            }
        )

    payload = {
        "scope": scope_uri,
        "scope_mode": mode,
        "data_source": LIVE_DATA_SOURCE,
        "generated_at": _now_iso(),
        "asset_count": len(assets),
        "assets": assets,
    }
    return _cache_put(cache_key, _compact_json(payload))


# ---------------------------------------------------------------------------
# Auditable scorecard (deterministic arithmetic with explicit numerators/denominators)
# ---------------------------------------------------------------------------

SCORECARD_WEIGHTS = {
    "asymmetric_pqc_migration": 0.60,
    "symmetric_quantum_resistance": 0.25,
    "symmetric_rotation_hygiene": 0.15,
}


def compute_scorecard_from_keys(keys: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Computes KMS posture KPIs from factual key records with exhaustive denominator partitioning.

    Every active key is partitioned into exactly one of:
    - `asym` (known asymmetric family, or unknown family with an asymmetric KMS purpose)
    - `sym` (known symmetric/MAC family, Cloud EKM `EXTERNAL_KEY_MANAGER`, or unknown family with symmetric purpose)
    - `uncategorized` (active keys whose algorithm family AND purpose are unrecognized; these penalize maturity so
      unreviewed keys can never be silently dropped to inflate maturity to 100.0%).
    """
    active = [k for k in keys if k.get("is_active")]

    def family(k: Dict[str, Any]) -> str:
        return str((k.get("algorithm_facts") or {}).get("algorithm_family") or "UNKNOWN").upper()

    def status(k: Dict[str, Any]) -> str:
        return str((k.get("algorithm_facts") or {}).get("quantum_status") or "UNKNOWN_REQUIRES_REVIEW").upper()

    def purpose(k: Dict[str, Any]) -> str:
        return str(k.get("purpose") or "UNKNOWN").upper()

    asym: List[Dict[str, Any]] = []
    sym: List[Dict[str, Any]] = []
    uncategorized: List[Dict[str, Any]] = []

    for k in active:
        fam = family(k)
        purp = purpose(k)
        if fam in ASYMMETRIC_FAMILIES:
            asym.append(k)
        elif fam in SYMMETRIC_FAMILIES or fam == "EXTERNAL_KEY_MANAGER":
            sym.append(k)
        elif purp in ASYMMETRIC_PURPOSES:
            asym.append(k)
        elif purp in SYMMETRIC_PURPOSES:
            sym.append(k)
        else:
            uncategorized.append(k)

    asym_pqc = [k for k in asym if status(k) == "QUANTUM_SAFE_PQC"]
    sym_resistant = [k for k in sym if status(k) == "QUANTUM_RESISTANT_SYMMETRIC"]
    ekm_keys = [k for k in sym if family(k) == "EXTERNAL_KEY_MANAGER"]
    # Cloud EKM keys rotate in the external key manager rather than via GCP KMS rotation_period;
    # all Google-managed ENCRYPT_DECRYPT keys (including unknown-algorithm ones) are included conservatively.
    sym_encrypt = [k for k in sym if purpose(k) == "ENCRYPT_DECRYPT" and family(k) != "EXTERNAL_KEY_MANAGER"]
    sym_rotated = [k for k in sym_encrypt if k.get("hygiene_flags", {}).get("rotation_within_90_days")]
    quantum_safe = [k for k in active if status(k) in ("QUANTUM_SAFE_PQC", "QUANTUM_RESISTANT_SYMMETRIC")]
    unknown = [k for k in active if status(k) == "UNKNOWN_REQUIRES_REVIEW"]
    assumed_active_err = [k for k in active if k.get("activity_assumed_due_to_version_error")]

    metrics = {
        "asymmetric_pqc_migration": _ratio_metric(
            len(asym_pqc),
            len(asym),
            "Active asymmetric keys using a post-quantum algorithm / all active asymmetric keys (including unreviewed asymmetric keys).",
        ),
        "symmetric_quantum_resistance": _ratio_metric(
            len(sym_resistant),
            len(sym),
            "Active symmetric/MAC keys with >= 128-bit post-quantum security / all active symmetric, MAC, and Cloud EKM keys.",
        ),
        "symmetric_rotation_hygiene": _ratio_metric(
            len(sym_rotated),
            len(sym_encrypt),
            "Active Google-managed ENCRYPT_DECRYPT symmetric keys with automatic rotation <= 90 days / all active Google-managed ENCRYPT_DECRYPT keys (Cloud EKM keys rotate externally and are tracked in counts.active_ekm_keys).",
        ),
        "algorithmic_quantum_safe": _ratio_metric(
            len(quantum_safe), len(active), "Active keys whose algorithm is post-quantum or quantum-resistant / all active keys."
        ),
    }

    available = {name: w for name, w in SCORECARD_WEIGHTS.items() if metrics[name]["denominator"]}
    weight_sum = sum(available.values())
    if weight_sum:
        raw_weighted = sum(metrics[n]["value_pct"] * w for n, w in available.items()) / weight_sum
        if uncategorized and active:
            classified_ratio = (len(active) - len(uncategorized)) / len(active)
            weighted_value: Optional[float] = round(raw_weighted * classified_ratio, 1)
        else:
            weighted_value = round(raw_weighted, 1)
    elif uncategorized:
        weighted_value = 0.0
    else:
        weighted_value = None

    metrics["weighted_kms_pqc_maturity"] = {
        "value_pct": weighted_value,
        "weights_used": {n: round(w / weight_sum, 3) for n, w in available.items()} if weight_sum else {},
        "uncategorized_penalty_applied": bool(uncategorized),
        "definition": (
            "Weighted average of the KMS KPIs above (methodology weights 60% asymmetric PQC migration, "
            "25% symmetric quantum resistance, 15% rotation hygiene), renormalized over applicable KPIs and "
            "penalized proportionally when active keys have unrecognized purpose and algorithm."
        ),
    }
    return {
        "metrics": metrics,
        "counts": {
            "active_keys": len(active),
            "inactive_keys": len(keys) - len(active),
            "active_asymmetric_keys": len(asym),
            "active_asymmetric_pqc_keys": len(asym_pqc),
            "active_shor_vulnerable_keys": len([k for k in asym if status(k) == "QUANTUM_VULNERABLE_SHOR"]),
            "active_symmetric_or_mac_keys": len(sym),
            "active_ekm_keys": len(ekm_keys),
            "active_uncategorized_keys": len(uncategorized),
            "active_symmetric_below_pq_target": len([k for k in sym if status(k) == "BELOW_PQ_SECURITY_TARGET"]),
            "active_symmetric_encrypt_keys_without_90d_rotation": len(sym_encrypt) - len(sym_rotated),
            "active_keys_unknown_requires_review": len(unknown),
            "active_keys_assumed_active_due_to_version_error": len(assumed_active_err),
            "partition_check_sum": len(asym) + len(sym) + len(uncategorized),
        },
    }


def compute_pqc_scorecard(
    scope: str = f"organizations/{DEFAULT_ORGANIZATION_ID}",
    location: str = "all",
    include_network_and_byok: bool = True,
) -> str:
    """Computes the auditable PQC posture scorecard (deterministic arithmetic, explicit numerators/denominators).

    KMS KPIs come from `collect_kms_inventory`. When `include_network_and_byok` is true it also computes the share
    of HTTPS/SSL target proxies that require TLS 1.3 (and explicitly tracks PQC-ready TLS 1.3 excluding `DEFERRED`)
    and the share of active KMS import jobs that use post-quantum HPKE wrapping. The tool does not interpret the
    numbers; the agent explains them.

    Args:
        scope: 'organizations/<id>', 'folders/<id>', 'projects/<id>' or a bare project ID.
        location: Cloud KMS location filter or 'all'.
        include_network_and_byok: Also compute TLS and BYOK import-job KPIs.

    Returns:
        JSON with `metrics` (value_pct, numerator, denominator, definition), `counts`, `completeness_status`,
        `inventory_complete`, and `data_sources`.
    """
    inventory = json.loads(collect_kms_inventory(scope=scope, location=location))
    if inventory.get("error") and not inventory.get("keys"):
        return _compact_json(
            {
                "scope": inventory.get("scope"),
                "error": inventory["error"],
                "inventory_complete": False,
                "completeness_status": "COLLECTION_FAILED",
                "required_roles": REQUIRED_READ_ROLES,
            }
        )

    result = compute_scorecard_from_keys(inventory.get("keys", []))
    result.update(
        {
            "scope": inventory.get("scope"),
            "generated_at": _now_iso(),
            "data_sources": {"kms_inventory": inventory.get("data_source")},
            "collection_errors": list(inventory.get("collection_errors", [])),
        }
    )
    if inventory.get("data_source") == SIMULATED_DATA_SOURCE:
        result["simulation_notice"] = SIMULATION_NOTICE

    if include_network_and_byok:
        from tools.pqc_detectors import collect_kms_import_jobs, collect_tls_policies

        tls = json.loads(collect_tls_policies(scope=scope))
        if tls.get("error"):
            result["collection_errors"].append(f"TLS policies: {tls['error']}")
        else:
            proxies = tls.get("target_proxies", [])
            tls13 = [p for p in proxies if p.get("effective_requires_tls_1_3")]
            tls13_pqc_ready = [
                p
                for p in proxies
                if p.get("effective_requires_tls_1_3") and not p.get("effective_post_quantum_key_exchange_deferred")
            ]
            tls13_deferred = [
                p
                for p in proxies
                if p.get("effective_requires_tls_1_3") and p.get("effective_post_quantum_key_exchange_deferred")
            ]
            result["metrics"]["https_proxies_requiring_tls_1_3"] = _ratio_metric(
                len(tls13), len(proxies), "HTTPS/SSL target proxies whose effective SSL policy requires TLS 1.3 / all target proxies."
            )
            result["metrics"]["https_proxies_pqc_ready_tls_1_3"] = _ratio_metric(
                len(tls13_pqc_ready),
                len(proxies),
                "HTTPS/SSL target proxies requiring TLS 1.3 without postQuantumKeyExchange=DEFERRED / all target proxies.",
            )
            result["counts"]["https_proxies_tls_1_3_with_pqc_deferred"] = len(tls13_deferred)
            result["data_sources"]["tls_policies"] = tls.get("data_source")

        ij = json.loads(collect_kms_import_jobs(scope=scope, location=location))
        if ij.get("error"):
            result["collection_errors"].append(f"KMS import jobs: {ij['error']}")
        else:
            active_jobs = [j for j in ij.get("import_jobs", []) if j.get("is_active")]
            pqc_jobs = [j for j in active_jobs if j.get("transport_quantum_status") == "QUANTUM_SAFE_PQC"]
            result["metrics"]["byok_import_jobs_using_pqc_wrapping"] = _ratio_metric(
                len(pqc_jobs), len(active_jobs), "Active KMS import jobs using post-quantum HPKE wrapping / all active import jobs."
            )
            result["data_sources"]["kms_import_jobs"] = ij.get("data_source")

    has_partial_errors = bool(result["collection_errors"]) or (
        result["counts"].get("active_keys_assumed_active_due_to_version_error", 0) > 0
    )
    if has_partial_errors:
        result["inventory_complete"] = False
        result["completeness_status"] = "PARTIAL_WITH_ERRORS"
    elif result["counts"]["active_keys"] == 0 and result["counts"]["inactive_keys"] == 0:
        result["inventory_complete"] = True
        result["completeness_status"] = "EMPTY_SCOPE"
    else:
        result["inventory_complete"] = True
        result["completeness_status"] = "COMPLETE"

    return _compact_json(result)


# ---------------------------------------------------------------------------
# OWASP CycloneDX v1.6 CBOM export (facts + agent-validated correlations)
# ---------------------------------------------------------------------------


def _cyclonedx_crypto_properties(key: Dict[str, Any]) -> Dict[str, Any]:
    """Maps a factual key record to CycloneDX v1.6 `cryptoProperties`."""
    algo = str(key.get("effective_algorithm", "UNKNOWN")).upper()
    purpose = str(key.get("purpose", "UNKNOWN")).upper()
    facts = key.get("algorithm_facts", {})

    if "KEM" in purpose or "KEM" in algo or "XWING" in algo:
        primitive, functions = "kem", ["encapsulate", "decapsulate"]
    elif "DECRYPT" in purpose and "ASYMMETRIC" in purpose:
        primitive, functions = "pke", ["encrypt", "decrypt"]
    elif "SIGN" in purpose:
        primitive, functions = "signature", ["sign", "verify"]
    elif "MAC" in purpose or algo.startswith("HMAC"):
        primitive, functions = "mac", ["tag", "verify"]
    else:
        primitive, functions = "ae", ["encrypt", "decrypt", "keygen"]

    table: List[Tuple[str, str, str, Optional[int], int]] = [
        # (match token, oid, parameterSetIdentifier, classicalSecurityLevel, nistQuantumSecurityLevel)
        ("XWING", "1.3.6.1.4.1.62253.25722", "X25519+ML-KEM-768", 192, 3),
        ("ML_KEM_768", "2.16.840.1.101.3.4.4.2", "768", 192, 3),
        ("ML_KEM_1024", "2.16.840.1.101.3.4.4.3", "1024", 256, 5),
        ("ML_DSA_44", "2.16.840.1.101.3.4.3.17", "44", 128, 2),
        ("ML_DSA_65", "2.16.840.1.101.3.4.3.18", "65", 192, 3),
        ("ML_DSA_87", "2.16.840.1.101.3.4.3.19", "87", 256, 5),
        ("SLH_DSA", "2.16.840.1.101.3.4.3.20", "128s", 128, 1),
        ("RSA_DECRYPT_OAEP", "1.2.840.113549.1.1.7", "", None, 0),
        ("RSA_SIGN_PSS", "1.2.840.113549.1.1.10", "", None, 0),
        ("RSA_SIGN", "1.2.840.113549.1.1.11", "", None, 0),
        ("EC_SIGN_P384", "1.2.840.10045.4.3.3", "P-384", 192, 0),
        ("EC_SIGN_P256", "1.2.840.10045.4.3.2", "P-256", 128, 0),
        ("ED25519", "1.3.101.112", "Ed25519", 128, 0),
        ("SECP256K1", "1.2.840.10045.4.3.2", "secp256k1", 128, 0),
        ("GOOGLE_SYMMETRIC_ENCRYPTION", "2.16.840.1.101.3.4.1.46", "256", 256, 5),
        ("AES_256", "2.16.840.1.101.3.4.1.46", "256", 256, 5),
        ("AES_128", "2.16.840.1.101.3.4.1.6", "128", 128, 1),
        ("HMAC_SHA512", "1.2.840.113549.2.11", "512", 512, 5),
        ("HMAC_SHA384", "1.2.840.113549.2.10", "384", 384, 5),
        ("HMAC_SHA256", "1.2.840.113549.2.9", "256", 256, 5),
        ("HMAC_SHA224", "1.2.840.113549.2.8", "224", 224, 3),
        ("HMAC_SHA1", "1.2.840.113549.2.7", "160", 160, 1),
    ]
    oid, param_set, classical_bits, nist_level = "unknown", "", facts.get("classical_security_bits"), 0
    for token, t_oid, t_param, t_classical, t_level in table:
        if token in algo:
            oid, param_set, nist_level = t_oid, t_param, t_level
            classical_bits = t_classical if t_classical is not None else facts.get("classical_security_bits")
            break
    if algo.startswith("RSA_"):
        param_set = "4096" if "4096" in algo else ("3072" if "3072" in algo else "2048")

    return {
        "assetType": "algorithm",
        "algorithmProperties": {
            "primitive": primitive,
            "parameterSetIdentifier": param_set,
            "executionEnvironment": "hardware-environment" if "HSM" in str(key.get("protection_level")) else "software-plain-ram",
            "implementationPlatform": "gcp-cloud-kms",
            "cryptoFunctions": functions,
            "classicalSecurityLevel": classical_bits,
            "nistQuantumSecurityLevel": nist_level,
        },
        "oid": oid,
    }


def export_cyclonedx_cbom(
    scope: str = f"organizations/{DEFAULT_ORGANIZATION_ID}",
    location: str = "all",
    validated_correlations_json: str = "",
) -> str:
    """Exports an OWASP CycloneDX v1.6 Cryptographic Bill of Materials (CBOM) for the Cloud KMS inventory.

    Cryptographic-asset components come from `collect_kms_inventory`. Application components and dependencies
    are included ONLY from `validated_correlations_json`, a JSON list produced by the correlation agent, e.g.
    [{"application_name": "...", "workload_resource": "//run.googleapis.com/...", "kms_key": "projects/.../cryptoKeys/k",
      "evidence_level": "STRONG|MEDIUM|WEAK", "evidence": "short citation"}]. Entries whose key is not in the inventory
    are rejected and reported.

    Args:
        scope: 'organizations/<id>', 'folders/<id>', 'projects/<id>' or a bare project ID.
        location: Cloud KMS location filter or 'all'.
        validated_correlations_json: Optional JSON list of agent-validated key-to-workload correlations.

    Returns:
        JSON CycloneDX v1.6 document plus `export_notes` (rejected correlations, data source).
    """
    inventory = json.loads(collect_kms_inventory(scope=scope, location=location))
    if inventory.get("error") and not inventory.get("keys"):
        return _compact_json({"scope": inventory.get("scope"), "error": inventory["error"]})

    keys = inventory.get("keys", [])
    scope_uri = inventory.get("scope", scope)
    root_ref = f"gcp-scope:{scope_uri}"
    components: List[Dict[str, Any]] = []
    refs_by_resource: Dict[str, str] = {}
    for k in keys:
        ref = f"crypto-key:{k['resource_name']}"
        refs_by_resource[k["resource_name"]] = ref
        facts = k["algorithm_facts"]
        components.append(
            {
                "type": "cryptographic-asset",
                "bom-ref": ref,
                "name": f"{k['key_ring']}/{k['key_name']}",
                "description": f"Cloud KMS CryptoKey {k['effective_algorithm']} in {k['project_id']}/{k['location']}",
                "cryptoProperties": _cyclonedx_crypto_properties(k),
                "properties": [
                    {"name": "gcp:resource_name", "value": k["resource_name"]},
                    {"name": "gcp:protection_level", "value": str(k.get("protection_level"))},
                    {"name": "gcp:is_active", "value": str(k.get("is_active")).lower()},
                    {"name": "pqc:quantum_status", "value": facts["quantum_status"]},
                    {"name": "pqc:quantum_threat_model", "value": facts["quantum_threat_model"]},
                    {"name": "pqc:data_source", "value": str(k.get("data_source"))},
                ],
            }
        )

    notes: Dict[str, Any] = {"data_source": inventory.get("data_source"), "rejected_correlations": []}
    app_refs: Dict[str, Dict[str, Any]] = {}
    app_deps: Dict[str, List[str]] = {}
    if validated_correlations_json and validated_correlations_json.strip():
        try:
            correlations = json.loads(validated_correlations_json)
            if not isinstance(correlations, list):
                raise ValueError("validated_correlations_json must be a JSON list")
        except Exception as exc:
            correlations = []
            notes["correlations_parse_error"] = str(exc)
        for c in correlations:
            key_ref = _normalize_kms_key_ref(str(c.get("kms_key", "")))
            crypto_ref = refs_by_resource.get(key_ref)
            if not crypto_ref:
                notes["rejected_correlations"].append({"entry": c, "reason": "kms_key not found in inventory"})
                continue
            app_name = str(c.get("application_name") or c.get("workload_resource") or "unnamed-workload")
            app_ref = f"application:{c.get('workload_resource') or app_name}"
            app_refs.setdefault(
                app_ref,
                {
                    "type": "application",
                    "bom-ref": app_ref,
                    "name": app_name,
                    "properties": [
                        {"name": "gcp:workload_resource", "value": str(c.get("workload_resource", ""))},
                        {"name": "pqc:evidence_level", "value": str(c.get("evidence_level", "UNSPECIFIED"))},
                        {"name": "pqc:evidence", "value": str(c.get("evidence", ""))[:300]},
                        {"name": "pqc:correlation_source", "value": "agent_validated_correlation"},
                    ],
                },
            )
            deps = app_deps.setdefault(app_ref, [])
            if crypto_ref not in deps:
                deps.append(crypto_ref)

    components.extend(app_refs.values())
    dependencies = [{"ref": root_ref, "dependsOn": list(app_refs.keys()) + list(refs_by_resource.values())}]
    dependencies.extend({"ref": a, "dependsOn": d} for a, d in app_deps.items())

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _now_iso(),
            "tools": {"components": [{"type": "application", "name": "agentic-pqc-workspace", "version": "4.0.0"}]},
            "component": {"type": "platform", "bom-ref": root_ref, "name": scope_uri},
        },
        "components": components,
        "dependencies": dependencies,
        "export_notes": notes,
    }
    if inventory.get("data_source") == SIMULATED_DATA_SOURCE:
        bom["export_notes"]["simulation_notice"] = SIMULATION_NOTICE
    return _compact_json(bom)
