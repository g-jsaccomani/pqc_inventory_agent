"""Explicit demo datasets for local development and unit tests.

These records are returned ONLY when `PQC_SIMULATION_MODE=TRUE` or when the requested scope is one of the
explicit demo identifiers in `tools.gcp_inventory.SIMULATION_PROJECT_IDS`. They are never used as a silent
fallback for live API errors, and every payload built from them is labeled `SIMULATED_DEMO_DATASET`.
"""

from typing import Any, Dict, List


def get_simulated_kms_raw_keys(project_id: str, location_id: str = "all") -> List[Dict[str, Any]]:
    """Returns demo Cloud KMS keys (raw facts only, no classification or recommendations)."""
    all_keys: List[Dict[str, Any]] = [
        {
            "key_ring": "kr-core-banking-prod",
            "key_name": "cmek-pix-envelope-rsa",
            "location": "southamerica-east1",
            "purpose": "ASYMMETRIC_DECRYPT",
            "algorithm": "RSA_DECRYPT_OAEP_2048_SHA256",
            "protection_level": "HSM",
            "rotation_period_days": None,
            "labels": {"env": "prod", "system": "pix-settlement", "data_classification": "confidential"},
        },
        {
            "key_ring": "kr-core-banking-prod",
            "key_name": "jwt-auth-signing-ecdsa",
            "location": "southamerica-east1",
            "purpose": "ASYMMETRIC_SIGN",
            "algorithm": "EC_SIGN_P256_SHA256",
            "protection_level": "HSM",
            "rotation_period_days": None,
            "labels": {"env": "prod", "system": "iam-federation", "data_classification": "restricted"},
        },
        {
            "key_ring": "kr-digital-signature-global",
            "key_name": "doc-legal-signing-rsa4096",
            "location": "global",
            "purpose": "ASYMMETRIC_SIGN",
            "algorithm": "RSA_SIGN_PSS_4096_SHA256",
            "protection_level": "SOFTWARE",
            "rotation_period_days": None,
            "labels": {"env": "prod", "system": "contracts-pki", "retention": "10y"},
        },
        {
            "key_ring": "kr-data-lake-encryption",
            "key_name": "bq-customer-pii-cmek",
            "location": "us-central1",
            "purpose": "ENCRYPT_DECRYPT",
            "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
            "protection_level": "SOFTWARE",
            "rotation_period_days": 90,
            "labels": {"env": "prod", "system": "bigquery-dwh", "data_classification": "pii"},
        },
        {
            "key_ring": "kr-data-lake-encryption",
            "key_name": "gcs-archive-cmek",
            "location": "us-central1",
            "purpose": "ENCRYPT_DECRYPT",
            "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
            "protection_level": "SOFTWARE",
            "rotation_period_days": None,
            "labels": {"env": "prod", "system": "archive"},
        },
        {
            "key_ring": "kr-api-gateway-mac",
            "key_name": "webhook-hmac-sha256",
            "location": "us-central1",
            "purpose": "MAC",
            "algorithm": "HMAC_SHA256",
            "protection_level": "HSM",
            "rotation_period_days": None,
            "labels": {"env": "prod", "system": "open-finance-gateway"},
        },
        {
            "key_ring": "kr-pqc-pilot-2026",
            "key_name": "kem-xwing-vault-transit",
            "location": "global",
            "purpose": "KEY_ENCAPSULATION",
            "algorithm": "KEM_XWING",
            "protection_level": "SOFTWARE",
            "rotation_period_days": None,
            "labels": {"env": "pilot", "system": "pqc-zero-trust"},
        },
        {
            "key_ring": "kr-pqc-pilot-2026",
            "key_name": "mldsa65-artifact-attestation",
            "location": "global",
            "purpose": "ASYMMETRIC_SIGN",
            "algorithm": "PQ_SIGN_ML_DSA_65",
            "protection_level": "SOFTWARE",
            "rotation_period_days": None,
            "labels": {"env": "pilot", "system": "binary-authorization"},
        },
    ]

    loc = (location_id or "all").strip().lower()
    if loc in ("all", "*", ""):
        return all_keys
    return [k for k in all_keys if k["location"].lower() == loc]


def get_simulated_cai_crypto_assets(project_id: str) -> List[Dict[str, Any]]:
    """Returns demo Cloud Asset Inventory crypto/PKI assets with raw attributes only."""
    return [
        {
            "asset_type": "compute.googleapis.com/SslCertificate",
            "name": f"//compute.googleapis.com/projects/{project_id}/global/sslCertificates/cert-openbanking-rsa2048",
            "project_id": project_id,
            "location": "global",
            "display_name": "cert-openbanking-rsa2048",
            "state": "ACTIVE",
            "attributes": {"type": "SELF_MANAGED", "expireTime": "2027-03-31T00:00:00Z"},
            "labels": {},
        },
        {
            "asset_type": "privateca.googleapis.com/CertificateAuthority",
            "name": (
                f"//privateca.googleapis.com/projects/{project_id}/locations/southamerica-east1/"
                "caPools/corp-pki/certificateAuthorities/sub-ca-ecdsa-p384"
            ),
            "project_id": project_id,
            "location": "southamerica-east1",
            "display_name": "sub-ca-ecdsa-p384",
            "state": "ENABLED",
            "attributes": {"type": "SUBORDINATE", "keySpec": {"algorithm": "EC_P384_SHA384"}},
            "labels": {},
        },
    ]


def get_simulated_workload_evidence(project_id: str) -> Dict[str, Any]:
    """Returns demo Cloud Asset Inventory workload evidence (resources and their CMEK key references)."""
    key_prefix = f"projects/{project_id}/locations/us-central1/keyRings/kr-data-lake-encryption/cryptoKeys"
    workloads = [
        {
            "asset_type": "bigquery.googleapis.com/Dataset",
            "name": f"//bigquery.googleapis.com/projects/{project_id}/datasets/customer_pii",
            "display_name": "customer_pii",
            "project_id": project_id,
            "location": "us-central1",
            "labels": {"system": "bigquery-dwh"},
            "kms_keys": [f"{key_prefix}/bq-customer-pii-cmek"],
        },
        {
            "asset_type": "storage.googleapis.com/Bucket",
            "name": f"//storage.googleapis.com/{project_id}-archive",
            "display_name": f"{project_id}-archive",
            "project_id": project_id,
            "location": "us-central1",
            "labels": {"system": "archive"},
            "kms_keys": [f"{key_prefix}/gcs-archive-cmek"],
        },
        {
            "asset_type": "run.googleapis.com/Service",
            "name": f"//run.googleapis.com/projects/{project_id}/locations/southamerica-east1/services/pix-settlement-api",
            "display_name": "pix-settlement-api",
            "project_id": project_id,
            "location": "southamerica-east1",
            "labels": {"system": "pix-settlement"},
            "kms_keys": [],
        },
        {
            "asset_type": "iam.googleapis.com/ServiceAccount",
            "name": f"//iam.googleapis.com/projects/{project_id}/serviceAccounts/sa-pix-settlement@{project_id}.iam.gserviceaccount.com",
            "display_name": "sa-pix-settlement",
            "project_id": project_id,
            "location": "global",
            "labels": {},
            "kms_keys": [],
        },
    ]
    return {"workloads": workloads}


def get_simulated_tls_evidence(project_id: str) -> Dict[str, Any]:
    """Returns demo SSL policies and target proxies (raw configuration only)."""
    policies = [
        {
            "policy_name": "ssl-policy-legacy-tls12-ingress",
            "resource_name": f"//compute.googleapis.com/projects/{project_id}/global/sslPolicies/ssl-policy-legacy-tls12-ingress",
            "project_id": project_id,
            "location": "global",
            "min_tls_version": "TLS_1_2",
            "profile": "COMPATIBLE",
            "custom_features": [],
        },
        {
            "policy_name": "ssl-policy-tls13-restricted",
            "resource_name": f"//compute.googleapis.com/projects/{project_id}/global/sslPolicies/ssl-policy-tls13-restricted",
            "project_id": project_id,
            "location": "global",
            "min_tls_version": "TLS_1_3",
            "profile": "RESTRICTED",
            "custom_features": [],
        },
    ]
    proxies = [
        {
            "proxy_name": "openbanking-https-proxy",
            "resource_name": f"//compute.googleapis.com/projects/{project_id}/global/targetHttpsProxies/openbanking-https-proxy",
            "project_id": project_id,
            "proxy_type": "compute.googleapis.com/TargetHttpsProxy",
            "attached_ssl_policy": "ssl-policy-legacy-tls12-ingress",
        },
        {
            "proxy_name": "internal-admin-https-proxy",
            "resource_name": f"//compute.googleapis.com/projects/{project_id}/global/targetHttpsProxies/internal-admin-https-proxy",
            "project_id": project_id,
            "proxy_type": "compute.googleapis.com/TargetHttpsProxy",
            "attached_ssl_policy": None,
        },
    ]
    return {"policies": policies, "proxies": proxies}


def get_simulated_import_jobs(project_id: str) -> List[Dict[str, Any]]:
    """Returns demo Cloud KMS ImportJobs (raw configuration only)."""
    return [
        {
            "project_id": project_id,
            "location": "southamerica-east1",
            "key_ring": "kr-core-banking-prod",
            "import_job_name": "ij-byok-legacy-rsa3072",
            "resource_name": (
                f"projects/{project_id}/locations/southamerica-east1/keyRings/kr-core-banking-prod/"
                "importJobs/ij-byok-legacy-rsa3072"
            ),
            "state": "ACTIVE",
            "import_method": "RSA_OAEP_3072_SHA256_AES_256",
            "protection_level": "HSM",
        },
        {
            "project_id": project_id,
            "location": "global",
            "key_ring": "kr-pqc-pilot-2026",
            "import_job_name": "ij-byok-hpke-xwing",
            "resource_name": f"projects/{project_id}/locations/global/keyRings/kr-pqc-pilot-2026/importJobs/ij-byok-hpke-xwing",
            "state": "ACTIVE",
            "import_method": "HPKE_KEM_XWING_HKDF_SHA256_AES_256_GCM",
            "protection_level": "HSM",
        },
    ]
