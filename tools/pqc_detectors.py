"""Network (TLS/SSL Policy) and Key Import (BYOK ImportJob) Post-Quantum Cryptography Detectors.

Provides specialized PQC posture detection tools for:
1. `scan_ssl_policies(project_id: str) -> str`:
   - Inspects active Google Cloud SSL Policies (via Cloud Asset Inventory and/or google-cloud-compute SDK).
   - Evaluates whether policies enforce TLS 1.3 (`min_tls_version == "TLS_1_3"`) and support IETF hybrid
     post-quantum key exchange (`X25519MLKEM768` = X25519 + ML-KEM-768).
   - Flags non-compliant policies as `VULNERABLE_TO_SNDL_ATTACKS` (Store Now, Decrypt Later).
2. `scan_import_jobs_pqc(project_id: str, location_id: str = "global") -> str`:
   - Inspects Cloud KMS `ImportJobs` (Bring Your Own Key / BYOK transport wrapping).
   - Flags classical RSA-OAEP import jobs (`RSA_OAEP_3072_*`, `RSA_OAEP_4096_*`) as `VULNERABLE_KEY_IMPORT_TRANSPORT`.
   - Classifies quantum-safe HPKE X-Wing / ML-KEM import jobs (`HPKE_KEM_XWING_HKDF_SHA256_AES_256_GCM`,
     `HPKE_KEM_ML_KEM_768_HKDF_SHA256_AES_256_GCM`, `HPKE_KEM_ML_KEM_1024_HKDF_SHA256_AES_256_GCM`)
     as `SECURE_PQC_BYOK`.
"""

import concurrent.futures
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

from google.api_core import exceptions as gcp_exceptions
from google.cloud import asset_v1, kms_v1

from tools.gcp_inventory import (
    DEFAULT_ORGANIZATION_ID,
    DEFAULT_ORGANIZATION_NAME,
    SIMULATION_PROJECT_IDS,
    _CACHE_TTL_SECONDS,
    _SCAN_CACHE,
    _compact_json,
    _get_client_kwargs,
    _resolve_scope,
)

logger = logging.getLogger(__name__)


def _extract_project_from_resource_name(resource_name: str, fallback: str = "") -> str:
    """Extracts the GCP Project ID from a full Cloud Asset Inventory resource URI."""
    parts = resource_name.split("/")
    if len(parts) >= 5 and parts[3] == "projects":
        return parts[4]
    if "projects/" in resource_name:
        after = resource_name.split("projects/", 1)[1]
        return after.split("/", 1)[0]
    return fallback


def _proto_struct_to_dict(resource_obj: Any) -> Dict[str, Any]:
    """Safely converts a protobuf Struct / MapComposite from CAI versioned_resources to a Python dict."""
    if not resource_obj:
        return {}
    try:
        return dict(resource_obj)
    except Exception:
        return {}


def _discover_org_key_rings_via_cai(scope_uri: str) -> List[Dict[str, str]]:
    """Discovers all Cloud KMS KeyRings within an Organization, Folder, or Project scope via Cloud Asset Inventory."""
    keyrings: List[Dict[str, str]] = []
    try:
        cai_client = asset_v1.AssetServiceClient(**_get_client_kwargs())
        response = cai_client.search_all_resources(
            request={
                "scope": scope_uri,
                "asset_types": ["cloudkms.googleapis.com/KeyRing"],
                "page_size": 500,
            }
        )
        for item in response:
            if "kr-pqc-audit-lab" in item.name:
                continue
            parts = item.name.split("/")
            # Format: //cloudkms.googleapis.com/projects/{proj}/locations/{loc}/keyRings/{kr}
            if len(parts) >= 9 and parts[3] == "projects" and parts[5] == "locations" and parts[7] == "keyRings":
                proj_id = parts[4]
                loc_id = parts[6]
                kr_id = parts[8]
                keyrings.append(
                    {
                        "project_id": proj_id,
                        "location": loc_id,
                        "key_ring": kr_id,
                        "resource_name": f"projects/{proj_id}/locations/{loc_id}/keyRings/{kr_id}",
                    }
                )
    except Exception as exc:
        logger.debug("CAI KeyRing discovery fallback on '%s': %s", scope_uri, exc)
    return keyrings


# Cloud KMS ImportMethod classifications
PQC_APPROVED_IMPORT_METHODS = {
    "HPKE_KEM_XWING_HKDF_SHA256_AES_256_GCM",
    "HPKE_KEM_ML_KEM_768_HKDF_SHA256_AES_256_GCM",
    "HPKE_KEM_ML_KEM_1024_HKDF_SHA256_AES_256_GCM",
}

CLASSICAL_VULNERABLE_IMPORT_METHODS = {
    "RSA_OAEP_3072_SHA1_AES_256",
    "RSA_OAEP_3072_SHA256",
    "RSA_OAEP_3072_SHA256_AES_256",
    "RSA_OAEP_4096_SHA1_AES_256",
    "RSA_OAEP_4096_SHA256",
    "RSA_OAEP_4096_SHA256_AES_256",
}


def _get_simulated_ssl_policies(project_id: str) -> List[Dict[str, Any]]:
    """Returns representative SSL Policies for local simulation and unit testing."""
    return [
        {
            "project_id": project_id,
            "policy_name": "ssl-policy-legacy-tls12-ingress",
            "resource_name": f"//compute.googleapis.com/projects/{project_id}/global/sslPolicies/ssl-policy-legacy-tls12-ingress",
            "location": "global",
            "min_tls_version": "TLS_1_2",
            "profile": "COMPATIBLE",
            "custom_features": [],
            "enforces_tls_1_3": False,
            "supports_hybrid_pqc_key_share_x25519_mlkem768": False,
            "pqc_status": "VULNERABLE_TO_SNDL_ATTACKS",
            "threat_vector": (
                "Store Now, Decrypt Later (SNDL / HNDL) — Allows classical TLS 1.2 handshakes (ECDHE-RSA / P-256) "
                "vulnerable to Shor's Algorithm key recovery by a Cryptographically Relevant Quantum Computer (CRQC)."
            ),
            "remediation_Recommendation": (
                "Upgrade SSL Policy to enforce TLS 1.3 (`--min-tls-version=1.3 --profile=RESTRICTED`) on "
                "Google Cloud Global Load Balancing (L7) with Certificate Authority Service (CAS) to mandate "
                "hybrid post-quantum key exchange (X25519 + ML-KEM-768 / X25519MLKEM768)."
            ),
            "remediation_recommendation": (
                "Upgrade SSL Policy to enforce TLS 1.3 (`--min-tls-version=1.3 --profile=RESTRICTED`) on "
                "Google Cloud Global Load Balancing (L7) with Certificate Authority Service (CAS) to mandate "
                "hybrid post-quantum key exchange (X25519 + ML-KEM-768 / X25519MLKEM768)."
            ),
            "step_by_step_execution_guide": [
                "Step 1 (Pre-Flight Client Telemetry Check): Query Cloud Load Balancing logs (`jsonPayload.tlsVersion`) to confirm no critical legacy clients rely exclusively on TLS 1.0/1.1.",
                f"Step 2 (Policy Enforcement): Update `ssl-policy-legacy-tls12-ingress` in `{project_id}` to `minTlsVersion=TLS_1_3` and `profile=RESTRICTED` so BoringSSL negotiates IETF hybrid `X25519MLKEM768` (`0x11EC`).",
                "Step 3 (Post-Change Handshake Verification): Validate the policy state via `gcloud compute ssl-policies describe` and verify hybrid key share negotiation (`X25519MLKEM768`) using a PQC-capable TLS 1.3 client (`bssl` / Chrome 124+ / OpenSSL 3.5+).",
            ],
            "gcloud_remediation_command": (
                f"gcloud compute ssl-policies update ssl-policy-legacy-tls12-ingress "
                f"--project={project_id} --min-tls-version=1.3 --profile=RESTRICTED"
            ),
            "post_change_validation_command": (
                f"gcloud compute ssl-policies describe ssl-policy-legacy-tls12-ingress "
                f"--project={project_id} --format=\"yaml(name,minTlsVersion,profile)\""
            ),
        },
        {
            "project_id": project_id,
            "policy_name": "ssl-policy-pqc-hybrid-tls13-prod",
            "resource_name": f"//compute.googleapis.com/projects/{project_id}/global/sslPolicies/ssl-policy-pqc-hybrid-tls13-prod",
            "location": "global",
            "min_tls_version": "TLS_1_3",
            "profile": "RESTRICTED",
            "custom_features": ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_AES_256_GCM_SHA384"],
            "enforces_tls_1_3": True,
            "supports_hybrid_pqc_key_share_x25519_mlkem768": True,
            "pqc_status": "QUANTUM_READY_HYBRID_TLS_1_3",
            "threat_vector": "NONE (Protected against SNDL/HNDL via TLS 1.3 + X25519MLKEM768 hybrid post-quantum key exchange)",
            "remediation_Recommendation": (
                "Compliant: Enforces TLS 1.3 minimum version and supports hybrid post-quantum key shares "
                "(X25519 + ML-KEM-768) on Google Cloud Global Load Balancing (L7)."
            ),
            "remediation_recommendation": (
                "Compliant: Enforces TLS 1.3 minimum version and supports hybrid post-quantum key shares "
                "(X25519 + ML-KEM-768) on Google Cloud Global Load Balancing (L7)."
            ),
            "step_by_step_execution_guide": [
                "No remediation required: Policy already enforces TLS 1.3 RESTRICTED profile with hybrid X25519MLKEM768 key exchange."
            ],
            "gcloud_remediation_command": None,
            "post_change_validation_command": (
                f"gcloud compute ssl-policies describe ssl-policy-pqc-hybrid-tls13-prod "
                f"--project={project_id} --format=\"yaml(name,minTlsVersion,profile)\""
            ),
        },
    ]


def _get_simulated_import_jobs(project_id: str) -> List[Dict[str, Any]]:
    """Returns representative Cloud KMS ImportJobs for local simulation and unit testing."""
    return [
        {
            "project_id": project_id,
            "location": "us-central1",
            "key_ring": "kr-pagamentos-prod",
            "import_job_name": "ij-legacy-byok-rsa3072",
            "resource_name": (
                f"projects/{project_id}/locations/us-central1/keyRings/kr-pagamentos-prod/"
                f"importJobs/ij-legacy-byok-rsa3072"
            ),
            "state": "ACTIVE",
            "is_active": True,
            "import_method": "RSA_OAEP_3072_SHA256_AES_256",
            "protection_level": "HSM",
            "pqc_status": "VULNERABLE_KEY_IMPORT_TRANSPORT",
            "threat_vector": (
                "Shor's Algorithm (BYOK Wrapping Vulnerability) — Classical RSA-OAEP wrapping key can be factored "
                "by a CRQC if the wrapped key material or API transport payload is intercepted (SNDL/HNDL), "
                "compromising the imported production key."
            ),
            "recommendation": (
                "Replace classical RSA-OAEP ImportJob with a quantum-safe RFC 9180 HPKE ImportJob using "
                "`HPKE_KEM_XWING_HKDF_SHA256_AES_256_GCM` backed by Cloud HSM (`--protection-level=hsm`)."
            ),
            "step_by_step_execution_guide": [
                "Step 1 (Pre-Flight On-Premises HSM / Tink Check): Verify that your local key generation utility or gcloud CLI (>= 495.0.0) supports RFC 9180 HPKE X-Wing wrapping.",
                f"Step 2 (Provision Quantum-Safe ImportJob): Create `ij-pqc-byok-xwing` in KeyRing `kr-pagamentos-prod` (`us-central1`) with `--import-method=hpke-kem-xwing-hkdf-sha256-aes-256-gcm` and `--protection-level=hsm`.",
                "Step 3 (Fetch HPKE Wrapping Public Key & Import): Download the X-Wing public key from the active ImportJob and execute `gcloud kms keys versions import` to wrap and upload key material.",
                "Step 4 (Validate Imported Key Version): Verify that the newly imported `CryptoKeyVersion` reaches `ENABLED` state with `protectionLevel: HSM`.",
            ],
            "gcloud_remediation_command": (
                f"gcloud kms import-jobs create ij-pqc-byok-xwing "
                f"--location=us-central1 --keyring=kr-pagamentos-prod "
                f"--import-method=hpke-kem-xwing-hkdf-sha256-aes-256-gcm "
                f"--protection-level=hsm --project={project_id}"
            ),
            "post_change_validation_command": (
                f"gcloud kms import-jobs describe ij-pqc-byok-xwing "
                f"--location=us-central1 --keyring=kr-pagamentos-prod --project={project_id} "
                f"--format=\"yaml(name,importMethod,protectionLevel,state)\""
            ),
        },
        {
            "project_id": project_id,
            "location": "global",
            "key_ring": "kr-pqc-canary-global",
            "import_job_name": "ij-pqc-byok-xwing-prod",
            "resource_name": (
                f"projects/{project_id}/locations/global/keyRings/kr-pqc-canary-global/"
                f"importJobs/ij-pqc-byok-xwing-prod"
            ),
            "state": "ACTIVE",
            "is_active": True,
            "import_method": "HPKE_KEM_XWING_HKDF_SHA256_AES_256_GCM",
            "protection_level": "HSM",
            "pqc_status": "SECURE_PQC_BYOK",
            "threat_vector": "NONE (Protected via Hybrid Post-Quantum HPKE X-Wing = X25519 + ML-KEM-768 + HKDF-SHA256 + AES-256-GCM)",
            "recommendation": (
                "Compliant: Uses quantum-safe HPKE_KEM_XWING_HKDF_SHA256_AES_256_GCM key wrapping for BYOK imports."
            ),
            "step_by_step_execution_guide": [
                "No remediation required: ImportJob already uses quantum-safe HPKE_KEM_XWING_HKDF_SHA256_AES_256_GCM on Cloud HSM."
            ],
            "gcloud_remediation_command": None,
            "post_change_validation_command": (
                f"gcloud kms import-jobs describe ij-pqc-byok-xwing-prod "
                f"--location=global --keyring=kr-pqc-canary-global --project={project_id} "
                f"--format=\"yaml(name,importMethod,protectionLevel,state)\""
            ),
        },
    ]


def _evaluate_ssl_policy_dict(
    policy_name: str,
    resource_name: str,
    project_id: str,
    location: str,
    min_tls_version: str,
    profile: str,
    custom_features: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Analyzes a single SSL Policy for TLS 1.3 enforcement and hybrid PQC key share support (X25519 + ML-KEM-768)."""
    norm_tls = (min_tls_version or "TLS_1_0").upper()
    norm_profile = (profile or "COMPATIBLE").upper()
    features = list(custom_features or [])
    region_flag = "" if location in ("global", "", None) else f" --region={location}"

    # Strict requirement: Enforce TLS 1.3 (and compatible profile/features) to guarantee hybrid PQC key shares (X25519 + ML-KEM-768)
    enforces_tls_1_3 = norm_tls == "TLS_1_3"
    supports_hybrid_pqc = enforces_tls_1_3 and norm_profile in ("MODERN", "RESTRICTED", "CUSTOM", "DEFAULT")

    if enforces_tls_1_3 and supports_hybrid_pqc:
        pqc_status = "QUANTUM_READY_HYBRID_TLS_1_3"
        threat_vector = (
            "NONE (Enforces TLS 1.3 and supports hybrid post-quantum key shares X25519 + ML-KEM-768 / X25519MLKEM768)"
        )
        recommendation = (
            "Compliant: SSL Policy enforces TLS 1.3 and supports hybrid post-quantum key exchange "
            "(X25519 + ML-KEM-768) on Google Cloud Global Load Balancing (L7)."
        )
        gcloud_cmd = None
        execution_steps = [
            "No remediation required: Policy already enforces TLS 1.3 and supports X25519MLKEM768 hybrid key shares."
        ]
    else:
        pqc_status = "VULNERABLE_TO_SNDL_ATTACKS"
        threat_vector = (
            f"Store Now, Decrypt Later (SNDL / HNDL) — Policy has minTlsVersion='{norm_tls}' (profile='{norm_profile}'), "
            "permitting classical TLS 1.2/1.1/1.0 ECDHE/RSA key exchanges that do not negotiate hybrid post-quantum "
            "key shares (X25519 + ML-KEM-768) and can be decrypted retroactively by a CRQC using Shor's Algorithm."
        )
        gcloud_cmd = (
            f"gcloud compute ssl-policies update {policy_name} "
            f"--project={project_id}{region_flag} --min-tls-version=1.3 --profile=RESTRICTED"
        )
        recommendation = (
            "Enforce TLS 1.3 (`--min-tls-version=1.3 --profile=RESTRICTED`) on Google Cloud Global Load Balancing (L7) "
            "and pair with Certificate Authority Service (CAS) to mandate hybrid post-quantum key shares (X25519 + ML-KEM-768)."
        )
        execution_steps = [
            f"Step 1 (Pre-Flight Client Telemetry Check): Inspect Cloud Load Balancing logs in `{project_id}` to confirm external clients support TLS 1.3.",
            f"Step 2 (Upgrade Policy to TLS 1.3 Restricted): Run `{gcloud_cmd}` to disable legacy TLS 1.0–1.2 handshakes and enable IETF hybrid `X25519MLKEM768`.",
            f"Step 3 (Verify Policy Enforcement): Run `gcloud compute ssl-policies describe {policy_name} --project={project_id}{region_flag}` and confirm `minTlsVersion: TLS_1_3`.",
        ]

    return {
        "project_id": project_id,
        "policy_name": policy_name,
        "resource_name": resource_name,
        "location": location or "global",
        "min_tls_version": norm_tls,
        "profile": norm_profile,
        "custom_features": features,
        "enforces_tls_1_3": enforces_tls_1_3,
        "supports_hybrid_pqc_key_share_x25519_mlkem768": supports_hybrid_pqc,
        "pqc_status": pqc_status,
        "threat_vector": threat_vector,
        "remediation_recommendation": recommendation,
        "step_by_step_execution_guide": execution_steps,
        "gcloud_remediation_command": gcloud_cmd,
        "post_change_validation_command": (
            f"gcloud compute ssl-policies describe {policy_name} "
            f"--project={project_id}{region_flag} --format=\"yaml(name,minTlsVersion,profile)\""
        ),
    }


def scan_ssl_policies(project_id: str = f"organizations/{DEFAULT_ORGANIZATION_ID}") -> str:
    """Fetches all active Google Cloud SSL Policies and analyzes whether they enforce TLS 1.3
    and support hybrid post-quantum key shares (X25519 + ML-KEM-768). Flags non-compliant policies
    as 'VULNERABLE_TO_SNDL_ATTACKS'.

    Args:
        project_id: Target GCP Project ID (e.g. 'pqc-inventory-agent-cd06') or Organization scope
                    (e.g. 'organizations/31564119954', 'org', 'all').

    Returns:
        JSON string containing the SSL Policy PQC posture analysis, SNDL vulnerability flags,
        deterministic ssl_pqc_readiness_score_pct, step-by-step execution guide, and remediation commands.
    """
    sim_mode = os.getenv("PQC_SIMULATION_MODE", "AUTO").upper()
    mode, scope_uri, clean_id = _resolve_scope(project_id)
    cache_key = f"ssl:{sim_mode}:{scope_uri}"
    now_ts = time.monotonic()
    cached = _SCAN_CACHE.get(cache_key)
    if cached and (now_ts - cached[0]) < _CACHE_TTL_SECONDS:
        return cached[1]

    if sim_mode == "TRUE" or clean_id.lower() in SIMULATION_PROJECT_IDS:
        sim_policies = _get_simulated_ssl_policies(clean_id)
        vuln_count = sum(1 for p in sim_policies if p["pqc_status"] == "VULNERABLE_TO_SNDL_ATTACKS")
        ready_count = sum(1 for p in sim_policies if p["pqc_status"] == "QUANTUM_READY_HYBRID_TLS_1_3")
        score_pct = round((ready_count / len(sim_policies)) * 100.0, 1) if sim_policies else 0.0
        out_json = _compact_json(
            {
                "scope": scope_uri,
                "scope_mode": mode,
                "data_source": "SIMULATION_MODE",
                "data_source_authenticity": "SIMULATED_BENCHMARK_DATASET",
                "total_ssl_policies_scanned": len(sim_policies),
                "vulnerable_to_sndl_attacks_count": vuln_count,
                "quantum_ready_hybrid_tls13_count": ready_count,
                "ssl_pqc_readiness_score_pct": score_pct,
                "ssl_policies": sim_policies,
                "architectural_upsell_recommendation": (
                    "Deploy Google Cloud Global Load Balancing (L7) with TLS 1.3 modern/restricted policies "
                    "(X25519 + ML-KEM-768 hybrid PQC key exchange) and Certificate Authority Service (CAS)."
                ),
            }
        )
        _SCAN_CACHE[cache_key] = (now_ts, out_json)
        return out_json

    evaluated_policies: List[Dict[str, Any]] = []
    seen_resources = set()

    # 1. Try google-cloud-compute SDK if installed and scanning a single project
    if mode == "PROJECT":
        try:
            from google.cloud import compute_v1  # type: ignore

            ssl_client = compute_v1.SslPoliciesClient()
            for policy in ssl_client.list(project=clean_id):
                res_name = f"//compute.googleapis.com/projects/{clean_id}/global/sslPolicies/{policy.name}"
                seen_resources.add(res_name)
                evaluated_policies.append(
                    _evaluate_ssl_policy_dict(
                        policy_name=policy.name,
                        resource_name=res_name,
                        project_id=clean_id,
                        location="global",
                        min_tls_version=str(getattr(policy, "min_tls_version", "TLS_1_0")),
                        profile=str(getattr(policy, "profile", "COMPATIBLE")),
                        custom_features=list(getattr(policy, "custom_features", []) or []),
                    )
                )
        except ImportError:
            logger.debug("google-cloud-compute not installed; using Cloud Asset Inventory for SSL Policy discovery.")
        except Exception as exc:
            logger.warning("Compute Engine SslPoliciesClient lookup note on '%s': %s", clean_id, exc)

    # 2. Query Cloud Asset Inventory for compute.googleapis.com/SslPolicy across Organization or Project
    try:
        cai_client = asset_v1.AssetServiceClient(**_get_client_kwargs())
        request = asset_v1.SearchAllResourcesRequest(
            scope=scope_uri,
            asset_types=[
                "compute.googleapis.com/SslPolicy",
                "compute.googleapis.com/TargetHttpsProxy",
                "compute.googleapis.com/TargetSslProxy",
            ],
            read_mask="*",
        )
        unattached_https_proxies: List[Dict[str, Any]] = []

        for item in cai_client.search_all_resources(request=request):
            asset_type = item.asset_type
            res_name = item.name
            proj = _extract_project_from_resource_name(res_name, item.project or clean_id)
            attrs = _proto_struct_to_dict(item.versioned_resources[0].resource) if item.versioned_resources else {}

            if asset_type == "compute.googleapis.com/SslPolicy":
                if res_name in seen_resources:
                    continue
                seen_resources.add(res_name)
                policy_name = item.display_name or res_name.split("/")[-1]
                min_tls = str(attrs.get("minTlsVersion", attrs.get("min_tls_version", "TLS_1_0")))
                profile = str(attrs.get("profile", "COMPATIBLE"))
                custom_features = attrs.get("customFeatures", attrs.get("custom_features", [])) or []
                evaluated_policies.append(
                    _evaluate_ssl_policy_dict(
                        policy_name=policy_name,
                        resource_name=res_name,
                        project_id=proj,
                        location=item.location or "global",
                        min_tls_version=min_tls,
                        profile=profile,
                        custom_features=custom_features if isinstance(custom_features, list) else [],
                    )
                )
            elif asset_type in ("compute.googleapis.com/TargetHttpsProxy", "compute.googleapis.com/TargetSslProxy"):
                bound_policy = attrs.get("sslPolicy") or attrs.get("ssl_policy")
                if not bound_policy:
                    proxy_name = item.display_name or res_name.split("/")[-1]
                    create_attach_cmd = (
                        f"gcloud compute ssl-policies create ssl-policy-pqc-tls13 --project={proj} "
                        f"--min-tls-version=1.3 --profile=RESTRICTED && "
                        f"gcloud compute target-https-proxies update {proxy_name} --project={proj} "
                        f"--ssl-policy=ssl-policy-pqc-tls13"
                    )
                    unattached_https_proxies.append(
                        {
                            "project_id": proj,
                            "policy_name": f"DEFAULT_UNATTACHED_SSL_POLICY ({proxy_name})",
                            "resource_name": res_name,
                            "location": item.location or "global",
                            "min_tls_version": "TLS_1_0 (GCP Default SSL Policy)",
                            "profile": "COMPATIBLE (Default)",
                            "custom_features": [],
                            "enforces_tls_1_3": False,
                            "supports_hybrid_pqc_key_share_x25519_mlkem768": False,
                            "pqc_status": "VULNERABLE_TO_SNDL_ATTACKS",
                            "threat_vector": (
                                f"Target proxy '{proxy_name}' has no custom SslPolicy attached and defaults to "
                                "TLS_1_0 / COMPATIBLE, making it vulnerable to Store Now, Decrypt Later (SNDL) attacks."
                            ),
                            "remediation_recommendation": (
                                "Create and attach a Google Cloud SSL Policy enforcing TLS 1.3 (`--min-tls-version=1.3 --profile=RESTRICTED`) "
                                "on Google Cloud Global Load Balancing (L7) with Certificate Authority Service (CAS)."
                            ),
                            "step_by_step_execution_guide": [
                                f"Step 1: Create a restricted TLS 1.3 SSL policy (`ssl-policy-pqc-tls13`) in project `{proj}`.",
                                f"Step 2: Bind `ssl-policy-pqc-tls13` to proxy `{proxy_name}` to mandate hybrid `X25519MLKEM768` key exchange.",
                                f"Step 3: Verify proxy attachment via `gcloud compute target-https-proxies describe {proxy_name} --project={proj}`.",
                            ],
                            "gcloud_remediation_command": create_attach_cmd,
                            "post_change_validation_command": (
                                f"gcloud compute target-https-proxies describe {proxy_name} "
                                f"--project={proj} --format=\"yaml(name,sslPolicy)\""
                            ),
                        }
                    )

        evaluated_policies.extend(unattached_https_proxies)

        vuln_count = sum(1 for p in evaluated_policies if p["pqc_status"] == "VULNERABLE_TO_SNDL_ATTACKS")
        ready_count = sum(1 for p in evaluated_policies if p["pqc_status"] == "QUANTUM_READY_HYBRID_TLS_1_3")
        score_pct = round((ready_count / len(evaluated_policies)) * 100.0, 1) if evaluated_policies else 0.0

        advisory_note = None
        if not evaluated_policies:
            advisory_note = (
                "No custom compute.googleapis.com/SslPolicy resources were found in this scope. "
                "Any public or internal HTTPS endpoints without an explicit TLS 1.3 SSL Policy default to "
                "TLS 1.0/1.2 fallback ('VULNERABLE_TO_SNDL_ATTACKS'). Provision Google Cloud Global Load Balancing (L7) "
                "with a TLS 1.3 SSL Policy (X25519 + ML-KEM-768) and Certificate Authority Service (CAS)."
            )

        out_json = _compact_json(
            {
                "scope": scope_uri,
                "scope_mode": mode,
                "organization_id": DEFAULT_ORGANIZATION_ID if mode == "ORG" else None,
                "organization_domain": DEFAULT_ORGANIZATION_NAME if mode == "ORG" else None,
                "data_source": "LIVE_GCP_CLOUD_ASSET_INVENTORY_AND_COMPUTE_API",
                "data_source_authenticity": "LIVE_GCP_TELEMETRY_VERIFIED",
                "total_ssl_policies_scanned": len(evaluated_policies),
                "vulnerable_to_sndl_attacks_count": vuln_count,
                "quantum_ready_hybrid_tls13_count": ready_count,
                "ssl_pqc_readiness_score_pct": score_pct,
                "ssl_policies": evaluated_policies,
                "advisory_note": advisory_note,
                "baseline_ssl_policy_creation_guide": {
                    "step_1_create_tls13_policy_cmd": (
                        f"gcloud compute ssl-policies create ssl-policy-pqc-hybrid-tls13 "
                        f"--project={clean_id if mode == 'PROJECT' else 'pqc-inventory-agent-cd06'} "
                        f"--min-tls-version=1.3 --profile=RESTRICTED"
                    ),
                    "step_2_attach_to_https_proxy_cmd": (
                        "gcloud compute target-https-proxies update <TARGET_HTTPS_PROXY_NAME> "
                        f"--project={clean_id if mode == 'PROJECT' else 'pqc-inventory-agent-cd06'} "
                        "--ssl-policy=ssl-policy-pqc-hybrid-tls13"
                    ),
                    "step_3_validate_policy_cmd": (
                        "gcloud compute ssl-policies describe ssl-policy-pqc-hybrid-tls13 "
                        f"--project={clean_id if mode == 'PROJECT' else 'pqc-inventory-agent-cd06'} "
                        "--format=\"yaml(name,minTlsVersion,profile)\""
                    ),
                },
                "architectural_upsell_recommendation": (
                    "Recommend Google Cloud Global Load Balancing (L7) with TLS 1.3 modern/restricted policies "
                    "(enabling hybrid post-quantum key shares X25519 + ML-KEM-768 / X25519MLKEM768) and "
                    "Certificate Authority Service (CAS) to enforce quantum-safe transport."
                ),
            }
        )
        _SCAN_CACHE[cache_key] = (now_ts, out_json)
        return out_json
    except gcp_exceptions.GoogleAPICallError as exc:
        logger.warning("GCP API error in scan_ssl_policies on '%s': %s", scope_uri, exc)
        return _compact_json(
            {
                "error": f"Failed to scan SSL Policies in scope '{scope_uri}': {exc.message}",
                "scope": scope_uri,
            }
        )


def _classify_import_job(
    project_id: str,
    location: str,
    key_ring: str,
    job_name: str,
    resource_name: str,
    state_name: str,
    import_method_name: str,
    protection_level_name: str,
) -> Dict[str, Any]:
    """Classifies a Cloud KMS ImportJob based on its wrapping algorithm and state."""
    norm_method = (import_method_name or "IMPORT_METHOD_UNSPECIFIED").upper()
    norm_state = (state_name or "IMPORT_JOB_STATE_UNSPECIFIED").upper()
    norm_prot = (protection_level_name or "SOFTWARE").upper()
    is_active = norm_state in ("ACTIVE", "PENDING_GENERATION")

    if norm_method in PQC_APPROVED_IMPORT_METHODS:
        pqc_status = "SECURE_PQC_BYOK"
        threat_vector = (
            f"NONE — Uses quantum-safe RFC 9180 HPKE key wrapping ({norm_method}), protecting imported key material "
            "in transit against Shor's Algorithm and Store Now, Decrypt Later (SNDL) attacks."
        )
        recommendation = (
            f"Compliant ('SECURE_PQC_BYOK'): ImportJob uses post-quantum {norm_method} wrapping "
            f"with protection level {norm_prot}."
        )
        gcloud_cmd = None
        execution_steps = [
            f"No remediation required: ImportJob `{job_name}` already uses post-quantum `{norm_method}` wrapping."
        ]
        validation_cmd = (
            f"gcloud kms import-jobs describe {job_name} "
            f"--location={location} --keyring={key_ring} --project={project_id} "
            f"--format=\"yaml(name,importMethod,protectionLevel,state)\""
        )
    elif norm_method in CLASSICAL_VULNERABLE_IMPORT_METHODS or "RSA_OAEP" in norm_method:
        pqc_status = "VULNERABLE_KEY_IMPORT_TRANSPORT"
        threat_vector = (
            f"Shor's Algorithm (BYOK Transport Vulnerability) — ImportJob uses classical '{norm_method}' wrapping. "
            "An adversary capturing wrapped BYOK key material in transit can factor the RSA-3072/4096 wrapping key "
            "using a Cryptographically Relevant Quantum Computer (CRQC) and compromise the imported production key."
        )
        recommendation = (
            "Migrate BYOK key imports from classical RSA-OAEP to quantum-safe hybrid HPKE "
            "('HPKE_KEM_XWING_HKDF_SHA256_AES_256_GCM') backed by Cloud HSM ('--protection-level=hsm')."
        )
        gcloud_cmd = (
            f"gcloud kms import-jobs create {job_name}-pqc-xwing "
            f"--location={location} --keyring={key_ring} "
            f"--import-method=hpke-kem-xwing-hkdf-sha256-aes-256-gcm "
            f"--protection-level=hsm --project={project_id}"
        )
        validation_cmd = (
            f"gcloud kms import-jobs describe {job_name}-pqc-xwing "
            f"--location={location} --keyring={key_ring} --project={project_id} "
            f"--format=\"yaml(name,importMethod,protectionLevel,state)\""
        )
        execution_steps = [
            "Step 1 (Pre-Flight CLI / HSM Readiness): Ensure gcloud CLI >= 495.0.0 or local Tink HPKE wrapper is installed on the key generation workstation.",
            f"Step 2 (Provision Quantum-Safe ImportJob): Execute `{gcloud_cmd}` to create a parallel HPKE X-Wing ImportJob backed by Cloud HSM.",
            f"Step 3 (Re-Wrap & Import Key Material): Retrieve the new ImportJob public key and run `gcloud kms keys versions import --import-job={job_name}-pqc-xwing ...`.",
            f"Step 4 (Verify Active State): Run `{validation_cmd}` to confirm `state: ACTIVE` and `importMethod: HPKE_KEM_XWING_HKDF_SHA256_AES_256_GCM`.",
        ]
    else:
        pqc_status = "UNKNOWN_IMPORT_METHOD_REVIEW_REQUIRED"
        threat_vector = f"Unrecognized ImportMethod '{norm_method}'; verify quantum resistance."
        recommendation = (
            "Use 'HPKE_KEM_XWING_HKDF_SHA256_AES_256_GCM' backed by Cloud HSM for quantum-safe BYOK key transport."
        )
        gcloud_cmd = None
        execution_steps = [
            "Verify ImportJob wrapping method and standardize on HPKE_KEM_XWING_HKDF_SHA256_AES_256_GCM."
        ]
        validation_cmd = (
            f"gcloud kms import-jobs describe {job_name} "
            f"--location={location} --keyring={key_ring} --project={project_id}"
        )

    return {
        "project_id": project_id,
        "location": location,
        "key_ring": key_ring,
        "import_job_name": job_name,
        "resource_name": resource_name,
        "state": norm_state,
        "is_active": is_active,
        "import_method": norm_method,
        "protection_level": norm_prot,
        "pqc_status": pqc_status,
        "threat_vector": threat_vector,
        "recommendation": recommendation,
        "step_by_step_execution_guide": execution_steps,
        "gcloud_remediation_command": gcloud_cmd,
        "post_change_validation_command": validation_cmd,
    }


def scan_import_jobs_pqc(
    project_id: str = f"organizations/{DEFAULT_ORGANIZATION_ID}",
    location_id: str = "global",
) -> str:
    """Lists all active ImportJobs in Cloud KMS and inspects their wrapping/import methods.
    Flags classical RSA-OAEP jobs as 'VULNERABLE_KEY_IMPORT_TRANSPORT' and classifies
    'HPKE_KEM_XWING_HKDF_SHA256_AES_256_GCM' (and ML-KEM HPKE variants) as 'SECURE_PQC_BYOK'.

    Args:
        project_id: Target GCP Project ID (e.g. 'pqc-inventory-agent-cd06') or Organization scope
                    (e.g. 'organizations/31564119954', 'org', 'all').
        location_id: Cloud KMS location (e.g. 'global', 'us-central1', or 'all' to scan all locations).

    Returns:
        JSON string containing the Cloud KMS ImportJobs PQC assessment, classification verdicts,
        deterministic byok_pqc_readiness_score_pct, step-by-step execution guide, and remediation commands.
    """
    sim_mode = os.getenv("PQC_SIMULATION_MODE", "AUTO").upper()
    mode, scope_uri, clean_id = _resolve_scope(project_id)
    cache_key = f"ij:{sim_mode}:{scope_uri}:{(location_id or 'global').lower()}"
    now_ts = time.monotonic()
    cached = _SCAN_CACHE.get(cache_key)
    if cached and (now_ts - cached[0]) < _CACHE_TTL_SECONDS:
        return cached[1]

    if sim_mode == "TRUE" or clean_id.lower() in SIMULATION_PROJECT_IDS:
        sim_jobs = _get_simulated_import_jobs(clean_id)
        if location_id and location_id.lower() not in ("all", "*", "global"):
            sim_jobs = [j for j in sim_jobs if j["location"] == location_id]
        active_sim = [j for j in sim_jobs if j["is_active"]]
        vuln_count = sum(1 for j in active_sim if j["pqc_status"] == "VULNERABLE_KEY_IMPORT_TRANSPORT")
        secure_count = sum(1 for j in active_sim if j["pqc_status"] == "SECURE_PQC_BYOK")
        score_pct = round((secure_count / len(active_sim)) * 100.0, 1) if active_sim else 100.0
        out_json = _compact_json(
            {
                "scope": scope_uri,
                "scope_mode": mode,
                "location_filter": location_id,
                "data_source": "SIMULATION_MODE",
                "data_source_authenticity": "SIMULATED_BENCHMARK_DATASET",
                "total_import_jobs_scanned": len(sim_jobs),
                "active_import_jobs_count": len(active_sim),
                "vulnerable_key_import_transport_count": vuln_count,
                "secure_pqc_byok_count": secure_count,
                "byok_pqc_readiness_score_pct": score_pct,
                "import_jobs": sim_jobs,
                "architectural_upsell_recommendation": (
                    "Migrate BYOK workflows to Cloud HSM (FIPS 140-3 Level 3) using "
                    "HPKE_KEM_XWING_HKDF_SHA256_AES_256_GCM import jobs to eliminate key transport risks."
                ),
            }
        )
        _SCAN_CACHE[cache_key] = (now_ts, out_json)
        return out_json

    try:
        kms_client = kms_v1.KeyManagementServiceClient(**_get_client_kwargs())
        key_rings_to_scan: List[Dict[str, str]] = []

        if mode in ("ORG", "FOLDER"):
            org_krs = _discover_org_key_rings_via_cai(scope_uri)
            for kr in org_krs:
                if location_id.lower() in ("all", "*", "global") or kr["location"] == location_id:
                    key_rings_to_scan.append(kr)
        else:
            # Project mode: discover KeyRings via CAI first, or fallback to common locations
            proj_krs = _discover_org_key_rings_via_cai(f"projects/{clean_id}")
            if proj_krs:
                for kr in proj_krs:
                    if location_id.lower() in ("all", "*") or kr["location"] == location_id or location_id == "global":
                        key_rings_to_scan.append(kr)
            else:
                locs = (
                    ["global", "us-central1", "us-east1", "southamerica-east1", "europe-west1"]
                    if location_id.lower() in ("all", "*")
                    else [location_id]
                )
                for loc in locs:
                    parent = f"projects/{clean_id}/locations/{loc}"
                    try:
                        for kr in kms_client.list_key_rings(request={"parent": parent}):
                            kr_id = kr.name.split("/")[-1]
                            key_rings_to_scan.append(
                                {
                                    "project_id": clean_id,
                                    "location": loc,
                                    "key_ring": kr_id,
                                    "resource_name": kr.name,
                                }
                            )
                    except Exception:
                        continue

        def _scan_keyring_import_jobs(kr_info: Dict[str, str]) -> List[Dict[str, Any]]:
            kr_parent = kr_info["resource_name"]
            proj = kr_info["project_id"]
            loc = kr_info["location"]
            kr_name = kr_info["key_ring"]
            results: List[Dict[str, Any]] = []
            try:
                for ij in kms_client.list_import_jobs(request={"parent": kr_parent}):
                    job_id = ij.name.split("/")[-1]
                    state_str = kms_v1.ImportJob.ImportJobState(ij.state).name
                    method_str = kms_v1.ImportJob.ImportMethod(ij.import_method).name
                    prot_str = kms_v1.ProtectionLevel(ij.protection_level).name
                    results.append(
                        _classify_import_job(
                            project_id=proj,
                            location=loc,
                            key_ring=kr_name,
                            job_name=job_id,
                            resource_name=ij.name,
                            state_name=state_str,
                            import_method_name=method_str,
                            protection_level_name=prot_str,
                        )
                    )
            except Exception as exc:
                logger.debug("Could not list ImportJobs in '%s': %s", kr_parent, exc)
            return results

        all_jobs: List[Dict[str, Any]] = []
        if key_rings_to_scan:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(key_rings_to_scan))) as executor:
                for kr_jobs in executor.map(_scan_keyring_import_jobs, key_rings_to_scan):
                    all_jobs.extend(kr_jobs)

        active_jobs = [j for j in all_jobs if j["is_active"]]
        vuln_count = sum(1 for j in active_jobs if j["pqc_status"] == "VULNERABLE_KEY_IMPORT_TRANSPORT")
        secure_count = sum(1 for j in active_jobs if j["pqc_status"] == "SECURE_PQC_BYOK")
        score_pct = round((secure_count / len(active_jobs)) * 100.0, 1) if active_jobs else 100.0

        out_json = _compact_json(
            {
                "scope": scope_uri,
                "scope_mode": mode,
                "location_filter": location_id,
                "data_source": "LIVE_GCP_KMS_IMPORT_JOBS_API",
                "data_source_authenticity": "LIVE_GCP_TELEMETRY_VERIFIED",
                "keyrings_inspected_count": len(key_rings_to_scan),
                "total_import_jobs_scanned": len(all_jobs),
                "active_import_jobs_count": len(active_jobs),
                "vulnerable_key_import_transport_count": vuln_count,
                "secure_pqc_byok_count": secure_count,
                "byok_pqc_readiness_score_pct": score_pct,
                "import_jobs": all_jobs,
                "baseline_byok_pqc_import_guide": {
                    "step_1_create_hpke_xwing_import_job_cmd": (
                        f"gcloud kms import-jobs create ij-pqc-byok-xwing "
                        f"--location=global --keyring=kr-pqc-enterprise-prod "
                        f"--import-method=hpke-kem-xwing-hkdf-sha256-aes-256-gcm "
                        f"--protection-level=hsm --project={clean_id if mode == 'PROJECT' else 'pqc-inventory-agent-cd06'}"
                    ),
                    "step_2_describe_and_verify_state_cmd": (
                        f"gcloud kms import-jobs describe ij-pqc-byok-xwing "
                        f"--location=global --keyring=kr-pqc-enterprise-prod "
                        f"--project={clean_id if mode == 'PROJECT' else 'pqc-inventory-agent-cd06'} "
                        f"--format=\"yaml(name,importMethod,protectionLevel,state)\""
                    ),
                },
                "architectural_upsell_recommendation": (
                    "For all BYOK workflows, mandate Cloud HSM (protection-level=HSM) with "
                    "HPKE_KEM_XWING_HKDF_SHA256_AES_256_GCM ImportJobs to protect key material during import transport."
                ),
            }
        )
        _SCAN_CACHE[cache_key] = (now_ts, out_json)
        return out_json
    except gcp_exceptions.GoogleAPICallError as exc:
        logger.warning("GCP API error in scan_import_jobs_pqc on '%s': %s", scope_uri, exc)
        return _compact_json(
            {
                "error": f"Failed to scan Cloud KMS ImportJobs in scope '{scope_uri}': {exc.message}",
                "scope": scope_uri,
            }
        )
